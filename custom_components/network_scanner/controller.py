from __future__ import annotations
from typing import Any, Dict, List, Optional
import asyncio
import json
import logging
import re
from datetime import datetime, timezone

import nmap
from aiohttp import ClientError, ClientTimeout, BasicAuth
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN,
    DEFAULT_NMAP_ARGS,
    DEFAULT_SCAN_INTERVAL,
    CONF_ARP_PROVIDER,
    ARP_PROVIDER_NONE,
    ARP_PROVIDER_OPNSENSE,
)

_LOGGER = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_mac(s: Optional[str]) -> str:
    return (s or "").upper()


_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


def _valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def _clean_mac(s: Optional[str]) -> str:
    """
    Normalize and discard bogus/incomplete MACs often seen in ARP tables.
    """
    m = _norm_mac(s)
    if not m or m == "*" or m.replace(":", "") == "000000000000":
        return ""
    if m.lower() in ("(incomplete)", "incomplete"):
        return ""
    return m if _valid_mac(m) else ""


def _ip_sort_key(ip_str: str) -> List[int]:
    try:
        return [int(p) for p in ip_str.split(".")]
    except Exception:
        return [999, 999, 999, 999]


def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(obj, dict):
        return out
    block = obj.get("data", obj)
    if not isinstance(block, dict):
        return out
    for k, v in block.items():
        mk = _clean_mac(k)
        if not mk:
            continue
        if isinstance(v, dict):
            out[mk] = {"name": str(v.get("name", "")), "desc": str(v.get("desc", ""))}
        else:
            out[mk] = {"name": str(v), "desc": ""}
    return out


class ScanController:
    """
    Unifies all sources (nmap + optional ARP) into a single, consistent
    device list and applies directory enrichment by MAC.
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry
        self.nm = nmap.PortScanner()

        # live state
        self._devices: List[Dict[str, Any]] = []
        self._device_count: int = 0
        self._status: str = "idle"
        self._last_scan_started: Optional[str] = None
        self._last_scan_finished: Optional[str] = None
        self._is_scanning: bool = False

        # config-derived
        self._cidrs: List[str] = []
        self._nmap_args: str = DEFAULT_NMAP_ARGS
        self._scan_interval: int = DEFAULT_SCAN_INTERVAL  # seconds
        self._arp_provider: str = ARP_PROVIDER_NONE

        # opnsense
        self._opn_url: str = ""
        self._opn_key: str = ""
        self._opn_sec: str = ""
        self._opn_iface: str = ""
        self._opn_timeout = ClientTimeout(total=10)

        self.apply_entry(entry)

    # ---------------- public properties ----------------

    @property
    def devices(self) -> List[Dict[str, Any]]:
        return self._devices

    @property
    def device_count(self) -> int:
        return self._device_count

    @property
    def status(self) -> str:
        return self._status

    @property
    def last_scan_started(self) -> Optional[str]:
        return self._last_scan_started

    @property
    def last_scan_finished(self) -> Optional[str]:
        return self._last_scan_finished

    @property
    def cidrs(self) -> List[str]:
        return self._cidrs

    @property
    def nmap_args(self) -> str:
        return self._nmap_args

    @property
    def scan_interval(self) -> int:
        return self._scan_interval

    # ---------------- config handling ----------------

    def apply_entry(self, entry: ConfigEntry) -> None:
        self._entry = entry
        data = entry.data or {}
        opts = entry.options or {}

        raw = (opts.get("ip_range") or data.get("ip_range") or "").strip()
        self._cidrs = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]

        self._nmap_args = (opts.get("nmap_args") or data.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        self._scan_interval = int(opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL)))
        self._arp_provider = (opts.get(CONF_ARP_PROVIDER) or data.get(CONF_ARP_PROVIDER) or ARP_PROVIDER_NONE).strip()

        self._opn_url = (opts.get("opnsense_url") or data.get("opnsense_url") or "").strip().rstrip("/")
        self._opn_key = (opts.get("opnsense_key") or data.get("opnsense_key") or "").strip()
        self._opn_sec = (opts.get("opnsense_secret") or data.get("opnsense_secret") or "").strip()
        self._opn_iface = (opts.get("opnsense_interface") or data.get("opnsense_interface") or "").strip()

    # ---------------- scheduling ----------------

    async def maybe_auto_scan(self) -> None:
        if self._is_scanning or self._scan_interval <= 0:
            return
        # HA calls us often; gate by interval using last finished timestamp
        if self._last_scan_finished:
            try:
                last = datetime.fromisoformat(self._last_scan_finished.replace("Z", "+00:00")).timestamp()
            except Exception:
                last = 0.0
        else:
            last = 0.0
        now = datetime.now(timezone.utc).timestamp()
        if now - last < self._scan_interval:
            return
        await self.scan_now()

    async def scan_now(self) -> None:
        if self._is_scanning:
            return
        self._is_scanning = True
        self._status = "scanning"
        self._last_scan_started = _now_iso()
        try:
            devices = await self._do_full_scan()
            devices.sort(key=lambda d: _ip_sort_key(d.get("ip", "")))
            self._devices = devices
            self._device_count = len(devices)
            self._status = "ok"
        except Exception as exc:
            _LOGGER.exception("Scan failed: %s", exc)
            self._status = "error"
        finally:
            self._last_scan_finished = _now_iso()
            self._is_scanning = False

    # ---------------- pipeline ----------------

    async def _do_full_scan(self) -> List[Dict[str, Any]]:
        directory = await self._build_effective_directory()

        # nmap per CIDR
        nmap_map: Dict[str, Dict[str, Any]] = {}
        for cidr in self._cidrs:
            chunk = await self.hass.async_add_executor_job(self._scan_cidr_nmap, cidr, self._nmap_args)
            for ip, dev in chunk.items():
                if ip not in nmap_map:
                    nmap_map[ip] = dev

        # ARP
        arp_map: Dict[str, str] = {}
        if self._arp_provider == ARP_PROVIDER_OPNSENSE and self._opn_url and self._opn_key and self._opn_sec:
            try:
                arp_map = await self._fetch_arp_table_opnsense()
            except Exception as exc:
                _LOGGER.warning("OPNsense ARP fetch failed: %s", exc)

        merged = self._merge_nmap_arp(nmap_map, arp_map)

        # enrichment
        self._apply_directory_overrides(merged, directory)

        return list(merged.values())

    # ---------------- nmap ----------------

    def _scan_cidr_nmap(self, cidr: str, nmap_args: str) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        self.nm.scan(hosts=cidr, arguments=nmap_args)
        for host in self.nm.all_hosts():
            try:
                node = self.nm[host]
                addrs = node.get("addresses", {})
                ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
                if not ip:
                    continue
                mac = _clean_mac(addrs.get("mac") or "")
                vendor = "Unknown"
                ven_map = node.get("vendor", {})
                if isinstance(ven_map, dict) and mac:
                    for k, v in ven_map.items():
                        if _clean_mac(k) == mac:
                            vendor = v
                            break
                hostname = node.hostname() or ""
                out[ip] = {
                    "ip": ip,
                    "mac": mac,             # cleaned; may be ""
                    "vendor": vendor,
                    "hostname": hostname,
                    "source": ["nmap"],
                    "name": "",
                    "type": "",
                }
            except Exception as exc:
                _LOGGER.debug("nmap parse skip host %s: %s", host, exc)
        return out

    # ---------------- ARP (OPNsense) ----------------

    async def _fetch_arp_table_opnsense(self) -> Dict[str, str]:
            """
            POST /api/diagnostics/interface/search_arp (or trailing slash)
            data: current=1&rowCount=9999&searchPhrase=&interface=<iface>
            Auth: Basic <key:secret>
            returns { ip -> MAC } (cleaned)
            """
            session = async_get_clientsession(self.hass)
            auth = BasicAuth(self._opn_key, self._opn_sec)
            base = f"{self._opn_url}/api/diagnostics/interface"
            payload = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
            if self._opn_iface:
                payload["interface"] = self._opn_iface
    
            headers = {
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            }
    
            urls = [f"{base}/search_arp", f"{base}/search_arp/"]
            last_err: Optional[Exception] = None
    
            for url in urls:
                try:
                    async with session.post(
                        url,
                        auth=auth,
                        data=payload,
                        timeout=self._opn_timeout,
                        ssl=False,  # self-signed default on OPNsense
                        headers=headers,
                    ) as resp:
                        txt = await resp.text()
                        if resp.status >= 400:
                            raise RuntimeError(f"HTTP {resp.status}: {txt[:200]!r}")
    
                        # Try to parse JSON from text (even if content-type is odd)
                        try:
                            data = json.loads(txt)
                        except Exception:
                            short = txt[:180].replace("\n", " ")
                            _LOGGER.warning(
                                "OPNsense returned non-JSON from %s, first bytes=%r",
                                url, short
                            )
                            return {}
                        return self._parse_opnsense_arp(data)
    
                except Exception as exc:
                    last_err = exc
    
            if last_err:
                # Don’t crash the whole scan; log once and continue without ARP data
                _LOGGER.warning("OPNsense ARP fetch failed: %s", last_err)
            return {}

    def _parse_opnsense_arp(self, data: Any) -> Dict[str, str]:
        """
        Expect {"rows":[{"ip":"10.0.3.12","mac":"aa:bb:..."}]}
        Returns {ip: MAC} with cleaned MACs (invalid -> skip).
        """
        def pick(rows: List[dict]) -> Dict[str, str]:
            out: Dict[str, str] = {}
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rip = r.get("ip") or r.get("address") or r.get("inet") or r.get("Addr")
                rmac = r.get("mac") or r.get("lladdr") or r.get("hwaddr") or r.get("MAC")
                mac = _clean_mac(rmac)
                if rip and mac:
                    out[str(rip)] = mac
            return out

        if isinstance(data, dict):
            if isinstance(data.get("rows"), list):
                return pick(data["rows"])
            for v in data.values():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    got = pick(v)
                    if got:
                        return got
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return pick(data)
        return {}

    # ---------------- merge + enrichment ----------------

    def _merge_nmap_arp(
        self,
        nmap_map: Dict[str, Dict[str, Any]],
        arp_map: Dict[str, str],
    ) -> Dict[str, Dict[str, Any]]:
        """
        - Union of IPs from both sources.
        - Fill missing/invalid MACs from ARP (only if valid).
        - For ARP-only IPs, create a minimal device entry (no 'cidr').
        """
        out: Dict[str, Dict[str, Any]] = {}
        all_ips = set(nmap_map.keys()) | set(arp_map.keys())

        for ip in all_ips:
            base = nmap_map.get(ip)
            mac_from_arp = _clean_mac(arp_map.get(ip, ""))
            if base:
                dev = dict(base)
                cur_mac = _clean_mac(dev.get("mac", ""))
                if not cur_mac and mac_from_arp:
                    dev["mac"] = mac_from_arp
                elif cur_mac and not _valid_mac(cur_mac):
                    dev["mac"] = mac_from_arp or ""
                # mark sources
                src = set(dev.get("source", []))
                if mac_from_arp:
                    src.add("arp")
                dev["source"] = sorted(src)
            else:
                dev = {
                    "ip": ip,
                    "mac": mac_from_arp or "",
                    "vendor": "Unknown",
                    "hostname": "",
                    "source": ["arp"] if mac_from_arp else ["arp"],
                    "name": "",
                    "type": "",
                }
            out[ip] = dev
        return out

    def _apply_directory_overrides(self, by_ip: Dict[str, Dict[str, Any]], directory: Dict[str, Dict[str, str]]) -> None:
        for dev in by_ip.values():
            mac = _clean_mac(dev.get("mac", ""))
            override = directory.get(mac, {}) if mac else {}
            dev["name"] = override.get("name") or dev.get("name") or "Unknown Device"
            dev["type"] = override.get("desc") or dev.get("type") or "Unknown Device"

    # ---------------- directory building ----------------

    async def _build_effective_directory(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = dict(self._entry.data.get("mac_directory", {}))
        # keys may not be cleaned yet
        out = { _clean_mac(k): {"name": v.get("name",""), "desc": v.get("desc","")} for k, v in out.items() if _clean_mac(k) }

        opts = self._entry.options or {}
        jtxt = (opts.get("mac_directory_json_text") or "").strip()
        if jtxt:
            try:
                out.update(_parse_dir_obj(json.loads(jtxt)))
            except Exception as exc:
                _LOGGER.warning("Invalid directory JSON (options): %s", exc)

        url = (opts.get("mac_directory_json_url") or self._entry.data.get("mac_directory_json_url") or "").strip()
        if url:
            try:
                session = async_get_clientsession(self.hass)
                async with session.get(url, timeout=10) as resp:
                    resp.raise_for_status()
                    out.update(_parse_dir_obj(json.loads(await resp.text())))
            except (ClientError, Exception) as exc:
                _LOGGER.warning("Failed to fetch directory URL %s: %s", url, exc)
        return out
