from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import asyncio
import json
import logging
import ipaddress
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


def _ip_sort_key(ip_str: str) -> List[int]:
    try:
        return [int(p) for p in ip_str.split(".")]
    except Exception:
        return [999, 999, 999, 999]


def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
    """
    Accept either:
      { "AA:BB:..": {"name":"..","desc":".."}, ... }
    or:
      { "data": { "AA:BB:..": ... } }
    Returns uppercase MAC keys.
    """
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(obj, dict):
        return out
    block = obj.get("data", obj)
    if not isinstance(block, dict):
        return out
    for k, v in block.items():
        mk = _norm_mac(k)
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
        self._last_scan_epoch: float = 0.0
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

    # ---------------- public properties (used by sensors) ----------------

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
        """Re-read options/data into runtime config."""
        self._entry = entry
        data = entry.data or {}
        opts = entry.options or {}

        # multi-CIDR (space/comma separated) kept as a *string* in ip_range
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
        """Called from sensors' async_update. Respects scan_interval."""
        if self._is_scanning:
            return
        if self._scan_interval <= 0:
            return  # manual-only
        # HA calls async_update on its own cadence; we gate by our interval.
        if self._last_scan_finished:
            # parse iso -> epoch seconds
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
        """Manual trigger (button platform calls this)."""
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

    # ---------------- core scan pipeline ----------------

    async def _do_full_scan(self) -> List[Dict[str, Any]]:
        # 1) Build effective directory (data + options JSON text + URL)
        directory = await self._build_effective_directory()

        # 2) Run nmap across all CIDRs (in executor)
        nmap_map: Dict[str, Dict[str, Any]] = {}
        for cidr in self._cidrs:
            chunk = await self.hass.async_add_executor_job(self._scan_cidr_nmap, cidr, self._nmap_args)
            # chunk is {ip -> device}
            for ip, dev in chunk.items():
                # prefer first seen per IP
                if ip not in nmap_map:
                    nmap_map[ip] = dev

        # 3) (optional) Fetch ARP mapping from provider
        arp_map: Dict[str, str] = {}
        if self._arp_provider == ARP_PROVIDER_OPNSENSE and self._opn_url and self._opn_key and self._opn_sec:
            try:
                arp_map = await self._fetch_arp_table_opnsense()
            except Exception as exc:
                _LOGGER.warning("OPNsense ARP fetch failed: %s", exc)

        # 4) Merge: union of IPs; fill missing MACs from ARP; then apply directory overrides by MAC
        merged = self._merge_nmap_arp(nmap_map, arp_map, self._cidrs)

        # 5) Enrich with directory (name/desc by MAC) uniformly
        self._apply_directory_overrides(merged, directory)

        # 6) Return as a list
        return list(merged.values())

    # ---------------- nmap ----------------

    def _scan_cidr_nmap(self, cidr: str, nmap_args: str) -> Dict[str, Dict[str, Any]]:
        """Return { ip -> base_device } for a CIDR from nmap."""
        out: Dict[str, Dict[str, Any]] = {}
        self.nm.scan(hosts=cidr, arguments=nmap_args)
        for host in self.nm.all_hosts():
            try:
                node = self.nm[host]
                addrs = node.get("addresses", {})
                ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
                if not ip:
                    continue
                mac = addrs.get("mac") or ""
                vendor = "Unknown"
                ven_map = node.get("vendor", {})
                if isinstance(ven_map, dict):
                    for k, v in ven_map.items():
                        if _norm_mac(k) == _norm_mac(mac):
                            vendor = v
                            break
                hostname = node.hostname() or ""
                out[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "cidr": cidr,
                    "source": ["nmap"],
                    # enrichment placeholders; filled later
                    "name": "",
                    "type": "",
                }
            except Exception as exc:
                _LOGGER.debug("nmap parse skip host %s: %s", host, exc)
        return out

    # ---------------- ARP (OPNsense) ----------------

    async def _fetch_arp_table_opnsense(self) -> Dict[str, str]:
        """
        POST /api/diagnostics/interface/search_arp (or with trailing slash)
        Body: current=1&rowCount=9999&searchPhrase=&interface=<iface>
        Auth: Basic <key:secret>
        Returns a JSON with rows containing IP/MAC pairs.
        """
        if not self._opn_url:
            return {}

        session = async_get_clientsession(self.hass)
        auth = BasicAuth(self._opn_key, self._opn_sec)
        base = f"{self._opn_url}/api/diagnostics/interface"
        payload = {
            "current": 1,
            "rowCount": 9999,
            "searchPhrase": "",
        }
        if self._opn_iface:
            payload["interface"] = self._opn_iface

        # Try both with and without trailing slash (some versions differ)
        urls = [f"{base}/search_arp", f"{base}/search_arp/"]
        last_err: Optional[Exception] = None
        for url in urls:
            try:
                async with session.post(url, auth=auth, data=payload, timeout=self._opn_timeout, ssl=False) as resp:
                    # OPNsense may respond 302 if wrong path; follow manually by trying both.
                    if resp.status >= 400:
                        txt = await resp.text()
                        raise RuntimeError(f"HTTP {resp.status}: {txt[:200]}")
                    data = await resp.json(content_type=None)
                    return self._parse_opnsense_arp(data)
            except Exception as exc:
                last_err = exc
        if last_err:
            raise last_err
        return {}

    def _parse_opnsense_arp(self, data: Any) -> Dict[str, str]:
        """
        Expect {"rows":[{"ip":"10.0.3.12","mac":"aa:bb:...","...}, ...], ...}
        Fallback: search for the first list of dicts with (ip|address) and (mac|lladdr).
        """
        def pick(rows: List[dict]) -> Dict[str, str]:
            out: Dict[str, str] = {}
            for r in rows:
                if not isinstance(r, dict):
                    continue
                # a bunch of tolerant key names
                rip = r.get("ip") or r.get("address") or r.get("inet") or r.get("Addr")
                rmac = r.get("mac") or r.get("lladdr") or r.get("hwaddr") or r.get("MAC")
                if rip and rmac:
                    out[str(rip)] = _norm_mac(str(rmac))
            return out

        if isinstance(data, dict):
            if isinstance(data.get("rows"), list):
                return pick(data["rows"])
            # fallback: find first list-of-dicts
            for v in data.values():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    got = pick(v)  # possibly empty
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
        cidrs: List[str],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Normalize into { ip -> device } with consistent keys.
        - Union IPs from both sources.
        - Fill missing MACs from ARP.
        - If IP appears only in ARP, create a placeholder device.
        """
        out: Dict[str, Dict[str, Any]] = {}

        # helper to find a CIDR that contains ip (for ARP-only IPs)
        nets: List[Tuple[str, ipaddress._BaseNetwork]] = []
        for c in cidrs:
            try:
                nets.append((c, ipaddress.ip_network(c, strict=False)))
            except Exception:
                pass

        all_ips = set(nmap_map.keys()) | set(arp_map.keys())

        for ip in all_ips:
            base = nmap_map.get(ip)
            mac_from_arp = arp_map.get(ip, "")
            if base:
                dev = dict(base)
                if not dev.get("mac") and mac_from_arp:
                    dev["mac"] = mac_from_arp
                if "arp" not in dev.get("source", []):
                    if mac_from_arp:
                        dev["source"] = list(set(dev["source"] + ["arp"]))
            else:
                # ARP-only entry (no nmap record)
                cidr = ""
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    for c, net in nets:
                        if ip_obj in net:
                            cidr = c
                            break
                except Exception:
                    pass
                dev = {
                    "ip": ip,
                    "mac": mac_from_arp or "",
                    "vendor": "Unknown",
                    "hostname": "",
                    "cidr": cidr,
                    "source": ["arp"],
                    "name": "",
                    "type": "",
                }
            out[ip] = dev

        return out

    def _apply_directory_overrides(self, by_ip: Dict[str, Dict[str, Any]], directory: Dict[str, Dict[str, str]]) -> None:
        """Apply name/desc by MAC uniformly (after merge)."""
        for dev in by_ip.values():
            mac = _norm_mac(dev.get("mac", ""))
            override = directory.get(mac, {}) if mac else {}
            # name/type finalization
            dev["name"] = override.get("name") or dev.get("name") or "Unknown Device"
            dev["type"] = override.get("desc") or dev.get("type") or "Unknown Device"

    # ---------------- directory building ----------------

    async def _build_effective_directory(self) -> Dict[str, Dict[str, str]]:
        """
        Combine:
          - entry.data.mac_directory (already normalized dict),
          - options mac_directory_json_text (highest precedence),
          - URL (options or data).
        """
        out: Dict[str, Dict[str, str]] = dict(self._entry.data.get("mac_directory", {}))
        opts = self._entry.options or {}

        # JSON pasted in options
        jtxt = (opts.get("mac_directory_json_text") or "").strip()
        if jtxt:
            try:
                out.update(_parse_dir_obj(json.loads(jtxt)))
            except Exception as exc:
                _LOGGER.warning("Invalid directory JSON (options): %s", exc)

        # URL (prefer options; fallback to data)
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
