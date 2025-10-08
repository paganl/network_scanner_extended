# custom_components/network_scanner/controller.py
from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import json
import logging
import re
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

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

# ---------------- small helpers ----------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _norm(s: Optional[str]) -> str:
    return (s or "").strip()

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

def _split_list(s: str) -> List[str]:
    return [p.strip() for p in (s or "").replace(",", " ").split() if p.strip()]

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

# ---------------- controller ----------------

class ScanController:
    """
    Unifies all sources (nmap + optional OPNsense ARP) into one consistent list,
    filters strictly to configured CIDRs, and applies directory enrichment by MAC.
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

        # rollups
        self._counts_by_segment: Dict[str, int] = {}
        self._counts_by_source: Dict[str, int] = {}

        # config-derived
        self._cidrs: List[str] = []
        self._networks: List = []  # ip_network objects
        self._nmap_args: str = DEFAULT_NMAP_ARGS
        self._scan_interval: int = DEFAULT_SCAN_INTERVAL  # seconds
        self._arp_provider: str = ARP_PROVIDER_NONE

        # opnsense
        self._opn_url: str = ""
        self._opn_key: str = ""
        self._opn_sec: str = ""
        self._opn_ifaces: List[str] = []
        self._opn_timeout = ClientTimeout(total=15)

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

    @property
    def counts_by_segment(self) -> Dict[str, int]:
        return self._counts_by_segment

    @property
    def counts_by_source(self) -> Dict[str, int]:
        return self._counts_by_source

    # ---------------- config handling ----------------

    def apply_entry(self, entry: ConfigEntry) -> None:
        self._entry = entry
        data = entry.data or {}
        opts = entry.options or {}

        raw = (opts.get("ip_range") or data.get("ip_range") or "").strip()
        self._cidrs = _split_list(raw)
        self._networks = []
        for c in self._cidrs:
            try:
                self._networks.append(ip_network(c, strict=False))
            except Exception:
                _LOGGER.warning("Ignoring invalid CIDR in ip_range: %s", c)

        self._nmap_args = (opts.get("nmap_args") or data.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        self._scan_interval = int(opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL)))
        self._arp_provider = (opts.get(CONF_ARP_PROVIDER) or data.get(CONF_ARP_PROVIDER) or ARP_PROVIDER_NONE).strip()

        self._opn_url = _norm((opts.get("opnsense_url") or data.get("opnsense_url") or "")).rstrip("/")
        self._opn_key = _norm(opts.get("opnsense_key") or data.get("opnsense_key") or "")
        self._opn_sec = _norm(opts.get("opnsense_secret") or data.get("opnsense_secret") or "")
        self._opn_ifaces = _split_list(opts.get("opnsense_interface") or data.get("opnsense_interface") or "")

    # ---------------- scheduling ----------------

    async def maybe_auto_scan(self) -> None:
        if self._is_scanning or self._scan_interval <= 0:
            return
        # gate by interval using last finished timestamp
        last = 0.0
        if self._last_scan_finished:
            try:
                last = datetime.fromisoformat(self._last_scan_finished.replace("Z", "+00:00")).timestamp()
            except Exception:
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
            self._recompute_rollups()
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

        # nmap per CIDR (inside executor)
        nmap_map: Dict[str, Dict[str, Any]] = {}
        for cidr in self._cidrs:
            chunk = await self.hass.async_add_executor_job(self._scan_cidr_nmap, cidr, self._nmap_args)
            for ip, dev in chunk.items():
                if self._ip_in_scope(ip) and ip not in nmap_map:
                    nmap_map[ip] = dev

        # ARP (OPNsense)
        arp_map: Dict[str, Dict[str, Any]] = {}
        if self._arp_provider == ARP_PROVIDER_OPNSENSE and self._opn_url and self._opn_key and self._opn_sec:
            try:
                arp_map = await self._fetch_arp_table_opnsense()
                # filter ARP strictly to scope (and optional interfaces if provided)
                arp_map = self._filter_arp_scope(arp_map)
            except Exception as exc:
                _LOGGER.warning("OPNsense ARP fetch failed: %s", exc)

        merged = self._merge_nmap_arp(nmap_map, arp_map)

        # enrichment by MAC
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
                    "mac": mac,             # may be ""
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

    async def _fetch_arp_table_opnsense(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns dict: { ip: { mac, intf, intf_description, expired, expires, permanent, arp_type, manufacturer, hostname } }
        Uses /api/diagnostics/interface/search_arp (with optional ?interface=IFACE via POST form).
        """
        session = async_get_clientsession(self.hass)
        auth = BasicAuth(self._opn_key, self._opn_sec)
        base = f"{self._opn_url}/api/diagnostics/interface"
        headers = {
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }

        rows: List[dict] = []

        if self._opn_ifaces:
            # Query per interface to keep payloads small
            for iface in self._opn_ifaces:
                payload = {"current": 1, "rowCount": 9999, "searchPhrase": "", "interface": iface}
                for path in ("search_arp", "search_arp/"):
                    url = f"{base}/{path}"
                    try:
                        async with session.post(url, auth=auth, data=payload, timeout=self._opn_timeout, ssl=False, headers=headers) as resp:
                            txt = await resp.text()
                            if resp.status >= 400:
                                raise RuntimeError(f"HTTP {resp.status}: {txt[:200]!r}")
                            data = json.loads(txt)
                            part = self._extract_rows_from_arp_json(data)
                            if part:
                                rows.extend(part)
                                break
                    except Exception as exc:
                        _LOGGER.debug("OPNsense ARP iface %s via %s failed: %s", iface, url, exc)
        else:
            # Single fetch (all interfaces), then we filter locally
            payload = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
            for path in ("search_arp", "search_arp/"):
                url = f"{base}/{path}"
                try:
                    async with session.post(url, auth=auth, data=payload, timeout=self._opn_timeout, ssl=False, headers=headers) as resp:
                        txt = await resp.text()
                        if resp.status >= 400:
                            raise RuntimeError(f"HTTP {resp.status}: {txt[:200]!r}")
                        data = json.loads(txt)
                        rows = self._extract_rows_from_arp_json(data)
                        break
                except Exception as exc:
                    _LOGGER.debug("OPNsense ARP fetch via %s failed: %s", url, exc)

        out: Dict[str, Dict[str, Any]] = {}
        for r in rows or []:
            ip = _norm(r.get("ip") or r.get("address") or r.get("inet") or r.get("Addr"))
            mac = _clean_mac(r.get("mac") or r.get("lladdr") or r.get("hwaddr") or r.get("MAC"))
            if not ip:
                continue
            out[ip] = {
                "mac": mac,
                "intf": r.get("intf") or "",
                "intf_description": r.get("intf_description") or "",
                "expired": bool(r.get("expired", False)),
                "expires": r.get("expires"),
                "permanent": bool(r.get("permanent", False)),
                "arp_type": r.get("type") or "",
                "manufacturer": r.get("manufacturer") or "",
                "hostname": r.get("hostname") or "",
            }
        return out

    @staticmethod
    def _extract_rows_from_arp_json(data: Any) -> List[dict]:
        if isinstance(data, dict) and isinstance(data.get("rows"), list):
            return data["rows"]
        # fallback tolerant shapes
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    return v
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data
        return []

    # ---------------- filtering ----------------

    def _ip_in_scope(self, ip_str: str) -> bool:
        if not self._networks:
            return False
        try:
            ip_obj = ip_address(ip_str)
        except Exception:
            return False
        return any(ip_obj in net for net in self._networks)

    def _filter_arp_scope(self, arp_map: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        if not arp_map:
            return {}
        # First filter by CIDRs
        scoped = {ip: r for ip, r in arp_map.items() if self._ip_in_scope(ip)}
        if not self._opn_ifaces:
            return scoped
        allowed = set(self._opn_ifaces)
        return {ip: r for ip, r in scoped.items() if _norm(r.get("intf")) in allowed}

    # ---------------- merge + enrichment ----------------

    def _merge_nmap_arp(
        self,
        nmap_map: Dict[str, Dict[str, Any]],
        arp_map: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        - Union of IPs from both sources, **then filter by scope**.
        - Fill missing/invalid MACs from ARP (only if valid).
        - For ARP-only IPs (still within scope), create an entry.
        - Add ARP interface/segment/manufacturer/hostname where helpful.
        """
        all_ips = set(nmap_map.keys()) | set(arp_map.keys())
        out: Dict[str, Dict[str, Any]] = {}

        for ip in all_ips:
            if not self._ip_in_scope(ip):
                continue

            n = nmap_map.get(ip)
            a = arp_map.get(ip)

            if n:
                dev = dict(n)
                cur_mac = _clean_mac(dev.get("mac", ""))
                mac_from_arp = _clean_mac(a.get("mac") if a else "")
                if not cur_mac and mac_from_arp:
                    dev["mac"] = mac_from_arp
                elif cur_mac and not _valid_mac(cur_mac):
                    dev["mac"] = mac_from_arp or ""

                # prefer existing vendor/hostname; fill from ARP if missing
                if a:
                    if dev.get("vendor", "Unknown") == "Unknown":
                        mfr = _norm(a.get("manufacturer"))
                        if mfr:
                            dev["vendor"] = mfr
                    if not _norm(dev.get("hostname")):
                        ahost = _norm(a.get("hostname"))
                        if ahost:
                            dev["hostname"] = ahost

                    # capture interface/segment and ARP meta
                    dev["interface"] = a.get("intf") or dev.get("interface", "")
                    dev["segment"] = a.get("intf_description") or dev.get("segment", "")
                    dev["arp_meta"] = {
                        "expired": a.get("expired", False),
                        "expires": a.get("expires"),
                        "permanent": a.get("permanent", False),
                        "arp_type": a.get("arp_type") or "",
                    }

                src = set(dev.get("source", []))
                src.add("nmap")
                if a:
                    src.add("arp")
                dev["source"] = sorted(src)

            else:
                # ARP-only (still in-scope)
                mac_from_arp = _clean_mac(a.get("mac") if a else "")
                dev = {
                    "ip": ip,
                    "mac": mac_from_arp or "",
                    "vendor": (a.get("manufacturer") or "Unknown") if a else "Unknown",
                    "hostname": a.get("hostname") or "" if a else "",
                    "source": ["arp"],
                    "name": "",
                    "type": "",
                }
                if a:
                    dev["interface"] = a.get("intf") or ""
                    dev["segment"] = a.get("intf_description") or ""
                    dev["arp_meta"] = {
                        "expired": a.get("expired", False),
                        "expires": a.get("expires"),
                        "permanent": a.get("permanent", False),
                        "arp_type": a.get("arp_type") or "",
                    }

            out[ip] = dev

        return out

    def _apply_directory_overrides(self, by_ip: Dict[str, Dict[str, Any]], directory: Dict[str, Dict[str, str]]) -> None:
        for dev in by_ip.values():
            mac = _clean_mac(dev.get("mac", ""))
            override = directory.get(mac, {}) if mac else {}
            dev["name"] = override.get("name") or dev.get("name") or "Unknown Device"
            dev["type"] = override.get("desc") or dev.get("type") or "Unknown Device"

    def _recompute_rollups(self) -> None:
        by_seg: Dict[str, int] = {}
        by_src: Dict[str, int] = {"nmap": 0, "arp": 0, "both": 0}
        for d in self._devices:
            seg = _norm(d.get("segment") or "Unsegmented")
            by_seg[seg] = by_seg.get(seg, 0) + 1
            src = d.get("source") or []
            key = "both" if ("nmap" in src and "arp" in src) else ("nmap" if "nmap" in src else "arp")
            by_src[key] = by_src.get(key, 0) + 1
        self._counts_by_segment = dict(sorted(by_seg.items()))
        self._counts_by_source = by_src

    # ---------------- directory building ----------------

    async def _build_effective_directory(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}
        # entry data (pre-parsed on save)
        base = self._entry.data.get("mac_directory", {})
        if isinstance(base, dict):
            for k, v in base.items():
                mk = _clean_mac(k)
                if not mk:
                    continue
                if isinstance(v, dict):
                    out[mk] = {"name": _norm(v.get("name")), "desc": _norm(v.get("desc"))}
                else:
                    out[mk] = {"name": str(v), "desc": ""}

        # options JSON text (highest precedence)
        opts = self._entry.options or {}
        jtxt = _norm(opts.get("mac_directory_json_text"))
        if jtxt:
            try:
                out.update(_parse_dir_obj(json.loads(jtxt)))
            except Exception as exc:
                _LOGGER.warning("Invalid directory JSON (options): %s", exc)

        # JSON URL
        url = _norm(opts.get("mac_directory_json_url") or self._entry.data.get("mac_directory_json_url"))
        if url:
            try:
                session = async_get_clientsession(self.hass)
                async with session.get(url, timeout=10) as resp:
                    resp.raise_for_status()
                    out.update(_parse_dir_obj(json.loads(await resp.text())))
            except (ClientError, Exception) as exc:
                _LOGGER.warning("Failed to fetch directory URL %s: %s", url, exc)

        return out
