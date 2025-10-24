# custom_components/network_scanner/controller.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import json
import logging
import re
from datetime import datetime, timezone
from ipaddress import ip_network, ip_address

import nmap
from aiohttp import ClientError, ClientTimeout
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import (
    DEFAULT_NMAP_ARGS,
    DEFAULT_SCAN_INTERVAL,
    # Providers
    CONF_ARP_PROVIDER,
    ARP_PROVIDER_NONE,
    ARP_PROVIDER_OPNSENSE,
    ARP_PROVIDER_ADGUARD,
    CONF_ARP_VERIFY_TLS,
    # Status / phase / dispatcher signal
    STATUS_IDLE,
    STATUS_SCANNING,
    STATUS_ENRICHING,
    STATUS_OK,
    STATUS_ERROR,
    PHASE_IDLE,
    PHASE_ARP,
    PHASE_NMAP,
    SIGNAL_NSX_UPDATED,
    # AdGuard creds
    CONF_ADG_URL,
    CONF_ADG_USER,
    CONF_ADG_PASS,
)

from .opnsense import OPNsenseARPClient
from .adguard import AdGuardDHCPClient

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
    Normalise and discard bogus/incomplete MACs often seen in ARP tables.
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
        # Sort v4 before v6; then by numeric value
        return [0 if ip.version == 4 else 1, int(ip)]
    except Exception:
        return [2, 0]

def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
    """
    Accept either:
      { "AA:BB:...": "Name", ... }
      { "AA:BB:...": {"name":"..","desc":".."}, ... }
      { "data": { ... as above ... } }
    Return { MAC -> {name, desc} } with cleaned MAC keys.
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
      Phase 1: ARP (OPNsense / AdGuard) -> filter to CIDRs -> enrich -> publish immediately (status='enriching').
      Phase 2: nmap (optional) -> merge -> enrich -> publish final (status='ok').
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry

        # Live state
        self._devices: List[Dict[str, Any]] = []
        self._device_count: int = 0
        self._status: str = STATUS_IDLE
        self._phase: str = PHASE_IDLE
        self._last_scan_started: Optional[str] = None
        self._last_scan_finished: Optional[str] = None
        self._is_scanning: bool = False
        self._scan_gen: int = 0

        # Config-derived
        self._cidr_strings: List[str] = []
        self._cidr_nets: List[Tuple[str, object]] = []
        self._nmap_args: str = DEFAULT_NMAP_ARGS
        self._scan_interval: int = DEFAULT_SCAN_INTERVAL
        self._arp_provider: str = ARP_PROVIDER_NONE

        # OPNsense
        self._opn_url: str = ""
        self._opn_key: str = ""
        self._opn_sec: str = ""
        self._opn_iface: str = ""

        # AdGuard
        self._adg_url: str = ""
        self._adg_user: str = ""
        self._adg_pass: str = ""

        # TLS verify flag (used for both HTTP providers)
        self._verify_tls: bool = False

        # HTTP timeout for directory JSON fetch
        self._http_timeout = ClientTimeout(total=10)

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

    # ---------------- internal helpers ----------------

    def _emit_update(self) -> None:
        """Notify sensors on the HA loop (thread-safe)."""
        self.hass.loop.call_soon_threadsafe(async_dispatcher_send, self.hass, SIGNAL_NSX_UPDATED)

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

        # OPNsense
        self._opn_url = _norm(opts.get("opnsense_url") or data.get("opnsense_url")).rstrip("/")
        self._opn_key = _norm(opts.get("opnsense_key") or data.get("opnsense_key"))
        self._opn_sec = _norm(opts.get("opnsense_secret") or data.get("opnsense_secret"))
        self._opn_iface = _norm(opts.get("opnsense_interface") or data.get("opnsense_interface"))

        # AdGuard
        self._adg_url = _norm(opts.get(CONF_ADG_URL) or data.get(CONF_ADG_URL))
        self._adg_user = _norm(opts.get(CONF_ADG_USER) or data.get(CONF_ADG_USER))
        self._adg_pass = _norm(opts.get(CONF_ADG_PASS) or data.get(CONF_ADG_PASS))

        # TLS verify
        self._verify_tls = bool(opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, False)))

    # ---------------- scheduling ----------------

    async def maybe_auto_scan(self) -> None:
        if self._is_scanning or self._scan_interval <= 0:
            return
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
        self._status = STATUS_SCANNING
        self._phase = PHASE_ARP
        self._last_scan_started = _now_iso()
        self._scan_gen += 1
        my_gen = self._scan_gen
        self._emit_update()

        try:
            # -------- Phase 1: ARP provider --------
            arp_map: Dict[str, Dict[str, Any]] = {}
            try:
                if self._arp_provider == ARP_PROVIDER_OPNSENSE and self._opn_url and self._opn_key and self._opn_sec:
                    client = OPNsenseARPClient(
                        base_url=self._opn_url,
                        key=self._opn_key,
                        secret=self._opn_sec,
                        verify_tls=self._verify_tls,
                        timeout=10,
                    )
                    arp_pairs = await client.fetch_map(self.hass)  # { ip: MAC }
                    arp_map = self._arp_pairs_to_devices(arp_pairs)
                elif self._arp_provider == ARP_PROVIDER_ADGUARD and self._adg_url and self._adg_user and self._adg_pass:
                    adg = AdGuardDHCPClient(self._adg_url, self._adg_user, self._adg_pass, verify_tls=self._verify_tls)
                    arp_pairs = await adg.fetch_map(self.hass)  # { ip: MAC }
                    arp_map = self._arp_pairs_to_devices(arp_pairs)
            except Exception as exc:
                _LOGGER.warning("ARP provider fetch failed: %s", exc)

            # Filter to configured ranges
            if arp_map and self._cidr_nets:
                arp_map = {ip: dev for ip, dev in arp_map.items() if _ip_in_any(ip, self._cidr_nets)}

            if arp_map:
                directory = await self._build_effective_directory()
                self._apply_directory_overrides(arp_map, directory)
                if my_gen == self._scan_gen:
                    self._devices = sorted(arp_map.values(), key=lambda d: _ip_sort_key(d.get("ip", "")))
                    self._device_count = len(self._devices)
                    self._status = STATUS_ENRICHING
                    self._phase = PHASE_ARP
                    self._emit_update()

            # -------- Phase 2: nmap (optional) --------
            if self._nmap_args:
                nmap_map: Dict[str, Dict[str, Any]] = await self.hass.async_add_executor_job(
                    self._nmap_scan_ranges, self._cidr_strings, self._nmap_args
                )
                merged = self._merge_nmap_with_existing(nmap_map, arp_map)
                directory = await self._build_effective_directory()
                self._apply_directory_overrides(merged, directory)

                if my_gen == self._scan_gen:
                    final_list = sorted(merged.values(), key=lambda d: _ip_sort_key(d.get("ip", "")))
                    self._devices = final_list
                    self._device_count = len(final_list)
                    self._status = STATUS_OK
                    self._phase = PHASE_NMAP
                    self._emit_update()
            else:
                if my_gen == self._scan_gen:
                    self._status = STATUS_OK if arp_map else STATUS_ERROR
                    self._phase = PHASE_IDLE
                    self._emit_update()

        except Exception as exc:
            _LOGGER.exception("Scan failed: %s", exc)
            if my_gen == self._scan_gen:
                self._status = STATUS_ERROR
                self._phase = PHASE_IDLE
                self._emit_update()
        finally:
            if my_gen == self._scan_gen:
                self._last_scan_finished = _now_iso()
                self._is_scanning = False
                self._emit_update()

    # ---------------- nmap (executor) ----------------

    def _nmap_scan_ranges(self, cidrs: List[str], nmap_args: str) -> Dict[str, Dict[str, Any]]:
        """
        Sweep multiple CIDRs sequentially using a single PortScanner instance.
        Runs inside an executor; OK to block here.
        """
        out: Dict[str, Dict[str, Any]] = {}
        try:
            nm = nmap.PortScanner()
        except Exception as exc:
            _LOGGER.warning("nmap init failed: %s", exc)
            return out

        for cidr in cidrs:
            try:
                nm.scan(hosts=cidr, arguments=nmap_args)
            except Exception as exc:
                _LOGGER.warning("nmap scan failed for %s: %s", cidr, exc)
                continue

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
                    # Only keep the first sighting per IP across ranges
                    if ip not in out:
                        out[ip] = {
                            "ip": ip,
                            "mac": mac,
                            "vendor": vendor,
                            "hostname": hostname,
                            "source": ["nmap"],
                            "name": "",
                            "type": "",
                        }
                except Exception as exc:
                    _LOGGER.debug("nmap parse skip host %s: %s", host, exc)
        return out

    # ---------------- ARP helpers ----------------

    def _arp_pairs_to_devices(self, pairs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Transform {ip: mac} -> device dicts (ARP-only)."""
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
        Merge by IP: prefer nmap MAC if present; union the sources.
        """
        out: Dict[str, Dict[str, Any]] = {}
        all_ips = set(nmap_map.keys()) | set(arp_map.keys())

        for ip in all_ips:
            n = nmap_map.get(ip)
            a = arp_map.get(ip)
            if n and a:
                mac = _clean_mac(n.get("mac")) or _clean_mac(a.get("mac"))
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
            if override:
                if override.get("name"):
                    dev["name"] = override["name"]
                if override.get("desc"):
                    dev["type"] = override["desc"]

    # ---------------- directory ----------------

    async def _build_effective_directory(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}

        # Base from config entry data (already normalised on save)
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

        # Overrides from options JSON text
        opts = self._entry.options or {}
        jtxt = _norm(opts.get("mac_directory_json_text"))
        if jtxt:
            try:
                out.update(_parse_dir_obj(json.loads(jtxt)))
            except Exception as exc:
                _LOGGER.warning("Invalid directory JSON (options): %s", exc)

        # Optional URL
        url = _norm(opts.get("mac_directory_json_url") or self._entry.data.get("mac_directory_json_url"))
        if url:
            try:
                session = async_get_clientsession(self.hass)
                async with session.get(url, timeout=self._http_timeout) as resp:
                    resp.raise_for_status()
                    out.update(_parse_dir_obj(json.loads(await resp.text())))
            except (ClientError, Exception) as exc:
                _LOGGER.warning("Failed to fetch directory URL %s: %s", url, exc)
        return out
