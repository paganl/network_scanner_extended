# custom_components/network_scanner/controller.py
from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from ipaddress import ip_network, ip_address

import nmap
from aiohttp import ClientError, ClientTimeout, BasicAuth
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import (
    DOMAIN,
    DEFAULT_NMAP_ARGS,
    DEFAULT_SCAN_INTERVAL,
    CONF_ARP_PROVIDER,
    ARP_PROVIDER_NONE,
    ARP_PROVIDER_OPNSENSE,
    DEFAULT_OPNSENSE_URL,
    OPNSENSE_ARP_PATH,
    CONF_ARP_VERIFY_TLS,
    # status/phase + signal
    STATUS_IDLE, STATUS_SCANNING, STATUS_ENRICHING, STATUS_OK, STATUS_ERROR,
    PHASE_IDLE, PHASE_ARP, PHASE_NMAP,
    SIGNAL_NSX_UPDATED,
)

_LOGGER = logging.getLogger(__name__)

# -------------------- small helpers --------------------

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
        ip = ip_address(ip_str)
        return [0 if ip.version == 4 else 1, int(ip)]
    except Exception:
        return [2, 0]

def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
    """
    Accepts either:
      { "AA:BB:CC:...": "Name", ... }
    or  { "AA:BB:...": {"name":"..","desc":".."}, ... }
    or  { "data": { ... as above ... } }
    Returns { MAC -> {name, desc} } with cleaned MAC keys.
    """
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

def _ip_in_any(ip_str: str, nets: List[Tuple[str, object]]) -> bool:
    """
    nets is list of (cidr_string, ip_network)
    """
    try:
        ip = ip_address(ip_str)
    except Exception:
        return False
    for _, net in nets:
        try:
            if ip in net:
                return True
        except Exception:
            continue
    return False

# -------------------- controller --------------------

class ScanController:
    """
    Two-phase scanner:
      Phase 1: ARP (OPNsense) -> filter to IP ranges -> enrich -> publish immediately (status='enriching').
      Phase 2: Nmap (optional) -> merge with ARP -> enrich -> publish final (status='ok').

    Public properties used by sensors/buttons:
      devices, device_count, status, last_scan_started, last_scan_finished,
      cidrs, nmap_args, scan_interval, phase
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry

        # live state
        self._devices: List[Dict[str, Any]] = []
        self._device_count: int = 0
        self._status: str = STATUS_IDLE
        self._phase: str = PHASE_IDLE
        self._last_scan_started: Optional[str] = None
        self._last_scan_finished: Optional[str] = None
        self._is_scanning: bool = False
        self._scan_gen: int = 0             # guard against stale results

        # config-derived
        self._cidr_strings: List[str] = []
        self._cidr_nets: List[Tuple[str, object]] = []  # (string, ip_network)
        self._nmap_args: str = DEFAULT_NMAP_ARGS
        self._scan_interval: int = DEFAULT_SCAN_INTERVAL  # seconds
        self._arp_provider: str = ARP_PROVIDER_NONE

        # opnsense
        self._opn_url: str = ""
        self._opn_key: str = ""
        self._opn_sec: str = ""
        self._opn_iface: str = ""
        self._opn_verify_tls: bool = False
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
        return self._cidr_strings

    @property
    def nmap_args(self) -> str:
        return self._nmap_args

    @property
    def scan_interval(self) -> int:
        return self._scan_interval

    @property
    def phase(self) -> str:
        # idle | arp | nmap
        return self._phase

    # ---------------- config handling ----------------

    def apply_entry(self, entry: ConfigEntry) -> None:
        self._entry = entry
        data = entry.data or {}
        opts = entry.options or {}

        raw = _norm(opts.get("ip_range") or data.get("ip_range"))
        self._cidr_strings = [p for p in raw.replace(",", " ").split() if p] if raw else []
        self._cidr_nets = []
        for c in self._cidr_strings:
            try:
                self._cidr_nets.append((c, ip_network(c, strict=False)))
            except Exception:
                _LOGGER.warning("Invalid CIDR in config: %s", c)

        self._nmap_args = _norm(opts.get("nmap_args") or data.get("nmap_args") or DEFAULT_NMAP_ARGS)
        self._scan_interval = int(opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL)))
        self._arp_provider = _norm(opts.get(CONF_ARP_PROVIDER) or data.get(CONF_ARP_PROVIDER) or ARP_PROVIDER_NONE)

        self._opn_url = _norm(opts.get("opnsense_url") or data.get("opnsense_url")).rstrip("/")
        self._opn_key = _norm(opts.get("opnsense_key") or data.get("opnsense_key"))
        self._opn_sec = _norm(opts.get("opnsense_secret") or data.get("opnsense_secret"))
        self._opn_iface = _norm(opts.get("opnsense_interface") or data.get("opnsense_interface"))
        self._opn_verify_tls = bool(opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, False)))

    # ---------------- scheduling ----------------

    async def maybe_auto_scan(self) -> None:
        if self._is_scanning or self._scan_interval <= 0:
            return
        # gate by interval using last finished timestamp
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
        self._status = STATUS_SCANNING
        self._phase = PHASE_ARP
        self._last_scan_started = _now_iso()
        self._scan_gen += 1
        my_gen = self._scan_gen

        try:
            # -------- Phase 1: ARP (publish immediately if we got anything) --------
            arp_map: Dict[str, Dict[str, Any]] = {}
            if (
                self._arp_provider == ARP_PROVIDER_OPNSENSE
                and self._opn_url
                and self._opn_key
                and self._opn_sec
            ):
                try:
                    arp_pairs = await self._fetch_arp_table_opnsense()  # {ip: mac}
                    arp_map = self._arp_pairs_to_devices(arp_pairs)
                    # filter to configured ranges
                    if self._cidr_nets:
                        arp_map = {ip: dev for ip, dev in arp_map.items() if _ip_in_any(ip, self._cidr_nets)}
                except Exception as exc:
                    _LOGGER.warning("OPNsense ARP fetch failed: %s", exc)

            if arp_map:
                # Enrich + publish partial results
                directory = await self._build_effective_directory()
                self._apply_directory_overrides(arp_map, directory)
                if my_gen == self._scan_gen:
                    self._devices = sorted(arp_map.values(), key=lambda d: _ip_sort_key(d.get("ip", "")))
                    self._device_count = len(self._devices)
                    self._status = STATUS_ENRICHING
                    self._phase = PHASE_ARP
                    self.hass.async_add_job(async_dispatcher_send, self.hass, SIGNAL_NSX_UPDATED)

            # -------- Phase 2: Nmap (optional) --------
            if self._nmap_args:
                nmap_map: Dict[str, Dict[str, Any]] = {}
                for cidr in self._cidr_strings:
                    chunk = await self.hass.async_add_executor_job(self._scan_cidr_nmap, cidr, self._nmap_args)
                    for ip, dev in chunk.items():
                        if ip not in nmap_map:
                            nmap_map[ip] = dev

                merged = self._merge_nmap_with_existing(nmap_map, arp_map)
                # final enrichment on the union
                directory = await self._build_effective_directory()
                self._apply_directory_overrides(merged, directory)

                if my_gen == self._scan_gen:
                    final_list = sorted(merged.values(), key=lambda d: _ip_sort_key(d.get("ip", "")))
                    self._devices = final_list
                    self._device_count = len(final_list)
                    self._status = STATUS_OK
                    self._phase = PHASE_NMAP
                    self.hass.async_add_job(async_dispatcher_send, self.hass, SIGNAL_NSX_UPDATED)
            else:
                # ARP-only path
                if my_gen == self._scan_gen:
                    self._status = STATUS_OK if arp_map else STATUS_ERROR
                    self._phase = PHASE_IDLE
                    self.hass.async_add_job(async_dispatcher_send, self.hass, SIGNAL_NSX_UPDATED)

        except Exception as exc:
            _LOGGER.exception("Scan failed: %s", exc)
            if my_gen == self._scan_gen:
                self._status = STATUS_ERROR
                self._phase = PHASE_IDLE
                self.hass.async_add_job(async_dispatcher_send, self.hass, SIGNAL_NSX_UPDATED)
        finally:
            if my_gen == self._scan_gen:
                self._last_scan_finished = _now_iso()
                self._is_scanning = False

    # ---------------- nmap ----------------

    def _scan_cidr_nmap(self, cidr: str, nmap_args: str) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=cidr, arguments=nmap_args)
        except Exception as exc:
            _LOGGER.warning("nmap scan failed for %s: %s", cidr, exc)
            return out

        for host in nm.all_hosts():
            try:
                node = nm[host]
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
        POST {base}/api/diagnostics/interface/search_arp (or trailing slash)
        form-data: current=1, rowCount=9999, searchPhrase="", [interface=<iface>]
        Basic auth: key:secret
        Returns { ip -> MAC } (cleaned).
        """
        session = async_get_clientsession(self.hass)
        auth = BasicAuth(self._opn_key, self._opn_sec)
        base = f"{self._opn_url}/api/diagnostics/interface".rstrip("/")
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
                    data=payload,               # OPNsense expects form-encoded
                    timeout=self._opn_timeout,
                    ssl=self._opn_verify_tls,   # respect TLS verify setting
                    headers=headers,
                ) as resp:
                    txt = await resp.text()
                    if resp.status >= 400:
                        raise RuntimeError(f"HTTP {resp.status}: {txt[:200]!r}")

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
            raise last_err
        return {}

    def _parse_opnsense_arp(self, data: Any) -> Dict[str, str]:
        """
        Accepts the rich structure you pasted (with manufacturer, hostname, etc.)
        but returns a simple {ip: MAC} map for merging. We keep only *valid* MACs.
        """
        def pick(rows: List[dict]) -> Dict[str, str]:
            out: Dict[str, str] = {}
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rip = r.get("ip") or r.get("address") or r.get("inet")
                rmac = r.get("mac") or r.get("lladdr") or r.get("hwaddr")
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

    def _arp_pairs_to_devices(self, pairs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """
        Convert {ip: mac} to device dicts (ARP-only). We leave vendor/hostname blank
        here—those may be filled by directory overrides or later by nmap.
        """
        out: Dict[str, Dict[str, Any]] = {}
        for ip, mac in pairs.items():
            out[ip] = {
                "ip": ip,
                "mac": _clean_mac(mac),
                "vendor": "Unknown",
                "hostname": "",
                "source": ["arp"],
                "name": "",
                "type": "",
            }
        return out

    # ---------------- merge + enrichment ----------------

    def _merge_nmap_with_existing(
        self,
        nmap_map: Dict[str, Dict[str, Any]],
        arp_map: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Merge union of IPs; prefer filled MACs; keep union of sources.
        NB: If devices changed IPs between phases, this is IP-keyed and may
        duplicate by MAC—dedup by MAC can be added later if desired.
        """
        out: Dict[str, Dict[str, Any]] = {}
        all_ips = set(nmap_map.keys()) | set(arp_map.keys())

        for ip in all_ips:
            n = nmap_map.get(ip)
            a = arp_map.get(ip)
            if n and a:
                # merge fields
                mac_n = _clean_mac(n.get("mac"))
                mac_a = _clean_mac(a.get("mac"))
                mac = mac_n or mac_a

                vendor = n.get("vendor") or a.get("vendor") or "Unknown"
                hostname = n.get("hostname") or a.get("hostname") or ""
                name = n.get("name") or a.get("name") or ""
                typ = n.get("type") or a.get("type") or ""

                src = sorted(set(n.get("source", [])) | set(a.get("source", [])))

                out[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "source": src,
                    "name": name,
                    "type": typ,
                }
            elif n:
                out[ip] = dict(n)
            elif a:
                out[ip] = dict(a)
        return out

    def _apply_directory_overrides(
        self,
        by_ip: Dict[str, Dict[str, Any]],
        directory: Dict[str, Dict[str, str]],
    ) -> None:
        for dev in by_ip.values():
            mac = _clean_mac(dev.get("mac", ""))
            override = directory.get(mac, {}) if mac else {}
            # Only apply provided overrides; don't force "Unknown Device"
            if override:
                if override.get("name"):
                    dev["name"] = override["name"]
                if override.get("desc"):
                    dev["type"] = override["desc"]

    # ---------------- directory building ----------------

    async def _build_effective_directory(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}

        # base from config entry data (already normalized on save)
        base = self._entry.data.get("mac_directory", {})
        if isinstance(base, dict):
            for k, v in base.items():
                mk = _clean_mac(k)
                if not mk:
                    continue
                if isinstance(v, dict):
                    out[mk] = {"name": str(v.get("name", "")), "desc": str(v.get("desc", ""))}
                else:
                    out[mk] = {"name": str(v), "desc": ""}

        # overrides from options JSON text
        opts = self._entry.options or {}
        jtxt = _norm(opts.get("mac_directory_json_text"))
        if jtxt:
            try:
                out.update(_parse_dir_obj(json.loads(jtxt)))
            except Exception as exc:
                _LOGGER.warning("Invalid directory JSON (options): %s", exc)

        # optional URL
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
