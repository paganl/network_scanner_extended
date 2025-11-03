# custom_components/network_scanner/controller.py
from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
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
    DEFAULT_NMAP_ARGS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_IP_RANGE,
    CONF_ARP_PROVIDER,
    ARP_PROVIDER_NONE,
    ARP_PROVIDER_OPNSENSE,
    ARP_PROVIDER_ADGUARD,
    ARP_PROVIDER_UNIFI,
    CONF_ARP_VERIFY_TLS,
    # status/phase + signal
    STATUS_IDLE, STATUS_SCANNING, STATUS_ENRICHING, STATUS_OK, STATUS_ERROR,
    PHASE_IDLE, PHASE_ARP, PHASE_NMAP,
    SIGNAL_NSX_UPDATED,
    # AdGuard
    CONF_ADG_URL, CONF_ADG_USER, CONF_ADG_PASS,
)
from .opnsense import OPNsenseARPClient
from .adguard import AdGuardDHCPClient
from .unifi import UniFiClient

_LOGGER = logging.getLogger(__name__)

# ---------------- helpers ----------------

def _emit_update(hass) -> None:
    # Fire dispatcher safely from any thread
    hass.loop.call_soon_threadsafe(async_dispatcher_send, hass, SIGNAL_NSX_UPDATED)

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

# --------- normalisation to unified schema (per provider) ---------

def _make_base(ip: str = "", mac: str = "") -> dict:
    return {
        "ip": ip, "mac": _clean_mac(mac),
        "name": "", "hostname": "", "vendor": "Unknown",
        "wired": None, "ssid": "", "vlan": None, "network": "",
        "ap": {"mac": "", "name": ""},
        "switch": {"mac": "", "name": "", "port": None, "port_name": "", "poe": None},
        "signal": {"rssi": None, "snr": None},
        "bytes": {"tx": 0, "rx": 0},
        "dhcp": {"server": "", "lease_ip": "", "reservation_ip": ""},
        "first_seen": "", "last_seen": "",
        "source": [], "type": "",
    }

def norm_from_arp(ip: str, mac: str) -> dict:
    d = _make_base(ip, mac)
    d["source"] = ["arp"]
    return d

def norm_from_adguard(lease: dict) -> dict:
    ip = str(lease.get("ip", "") or lease.get("address", ""))
    mac = _clean_mac(lease.get("mac", lease.get("mac_address", "")))
    d = _make_base(ip, mac)
    d["dhcp"]["server"] = "adguard"
    d["dhcp"]["lease_ip"] = ip
    d["source"] = ["adguard"]
    # optionally carry hostname
    host = lease.get("hostname") or lease.get("name") or ""
    d["hostname"] = host or d["hostname"]
    return d

def norm_from_unifi_client(c: dict, ap_name_by_mac: dict[str, str]) -> dict:
    ip = str(c.get("ip", "") or "")
    mac = _clean_mac(c.get("mac", ""))
    d = _make_base(ip, mac)
    d["hostname"] = c.get("hostname", "") or d["hostname"]
    d["vendor"] = c.get("oui", "") or d["vendor"]
    d["wired"] = bool(c.get("is_wired")) if c.get("is_wired") is not None else None
    d["ssid"] = c.get("essid", "") or d["ssid"]
    if isinstance(c.get("vlan"), int):
        d["vlan"] = c.get("vlan")
    # AP + switch context if present
    ap_mac = _clean_mac(c.get("ap_mac", ""))
    if ap_mac:
        d["ap"]["mac"] = ap_mac
        d["ap"]["name"] = ap_name_by_mac.get(ap_mac, "")
    sw_mac = _clean_mac(c.get("sw_mac", ""))
    if sw_mac:
        d["switch"]["mac"] = sw_mac
        d["switch"]["port"] = c.get("sw_port")
    # signal/bytes
    if isinstance(c.get("rssi"), int): d["signal"]["rssi"] = c["rssi"]
    if isinstance(c.get("snr"), int):  d["signal"]["snr"] = c["snr"]
    d["bytes"]["tx"] = int(c.get("tx_bytes", 0) or 0)
    d["bytes"]["rx"] = int(c.get("rx_bytes", 0) or 0)
    # timestamps
    def _iso(v):
        try:
            return datetime.fromtimestamp(int(v), tz=timezone.utc).isoformat()
        except Exception:
            return ""
    if c.get("first_seen"): d["first_seen"] = _iso(c["first_seen"])
    if c.get("last_seen"):  d["last_seen"]  = _iso(c["last_seen"])
    d["source"] = ["unifi"]
    return d

def norm_from_nmap(ip: str, mac: str, vendor: str, hostname: str) -> dict:
    d = _make_base(ip, mac)
    d["vendor"] = vendor or d["vendor"]
    d["hostname"] = hostname or d["hostname"]
    d["source"] = ["nmap"]
    return d

# --------- merge helpers (MAC-first) ---------

def _merge_device(dst: dict, src: dict) -> dict:
    """Adopt non-empty values, coalesce arrays, keep union of sources."""
    def take(path: list[str], prefer_existing: bool = False):
        # Navigate nested dicts and set if src has a useful value
        d = dst; s = src
        for p in path[:-1]:
            d = d.setdefault(p, {})
            s = s.get(p, {}) if isinstance(s.get(p, {}), dict) else {}
        key = path[-1]
        val = s.get(key)
        if val is None or val == "" or (isinstance(val, (list, dict)) and not val):
            return
        if prefer_existing and d.get(key):
            return
        d[key] = val

    # identity & labels
    take(["ip"], prefer_existing=True)
    take(["mac"])
    for p in (["name"], ["hostname"], ["vendor"], ["type"]): take(p)
    # connectivity/topology
    for p in (["wired"], ["ssid"], ["vlan"], ["network"]): take(p)
    for p in (["ap","mac"], ["ap","name"], ["switch","mac"], ["switch","name"],
              ["switch","port"], ["switch","port_name"], ["switch","poe"]): take(p)
    for p in (["signal","rssi"], ["signal","snr"]): take(p)
    for p in (["bytes","tx"], ["bytes","rx"]): take(p)
    for p in (["dhcp","server"], ["dhcp","lease_ip"], ["dhcp","reservation_ip"]): take(p)
    for p in (["first_seen"], ["last_seen"]): take(p)

    # sources union
    dst["source"] = sorted(set((dst.get("source") or []) + (src.get("source") or [])))
    return dst

# ---------------- controller ----------------

class ScanController:
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
        self._scan_gen: int = 0

        # config-derived
        self._cidr_strings: List[str] = []
        self._cidr_nets: List[Tuple[str, object]] = []
        self._nmap_args: str = DEFAULT_NMAP_ARGS
        self._scan_interval_minutes: int = DEFAULT_SCAN_INTERVAL_MINUTES
        self._arp_provider: str = ARP_PROVIDER_NONE

        # providers config
        # OPNsense
        self._opn_url: str = ""
        self._opn_key: str = ""
        self._opn_sec: str = ""
        self._opn_iface: str = ""
        self._opn_timeout = ClientTimeout(total=10)

        # AdGuard
        self._adg_url: str = ""
        self._adg_user: str = ""
        self._adg_pass: str = ""

        # UniFi
        self._unifi_url: str = ""
        self._unifi_user: str = ""
        self._unifi_pass: str = ""
        self._unifi_site: str = "default"

        # TLS verify for HTTP providers
        self._verify_tls: bool = False

        self.apply_entry(entry)

    # properties consumed by entities
    @property
    def devices(self) -> List[Dict[str, Any]]: return self._devices
    @property
    def device_count(self) -> int: return self._device_count
    @property
    def status(self) -> str: return self._status
    @property
    def last_scan_started(self) -> Optional[str]: return self._last_scan_started
    @property
    def last_scan_finished(self) -> Optional[str]: return self._last_scan_finished
    @property
    def cidrs(self) -> List[str]: return self._cidr_strings
    @property
    def nmap_args(self) -> str: return self._nmap_args
    @property
    def scan_interval_minutes(self) -> int: return self._scan_interval_minutes
    @property
    def phase(self) -> str: return self._phase

    # config
    def apply_entry(self, entry: ConfigEntry) -> None:
        self._entry = entry
        data = entry.data or {}
        opts = entry.options or {}

        raw = _norm(opts.get("ip_range") or data.get("ip_range") or DEFAULT_IP_RANGE)
        self._cidr_strings = [p for p in raw.replace(",", " ").split() if p] if raw else []
        self._cidr_nets = []
        for c in self._cidr_strings:
            try:
                self._cidr_nets.append((c, ip_network(c, strict=False)))
            except Exception:
                _LOGGER.warning("Invalid CIDR in config: %s", c)

        self._nmap_args = _norm(opts.get("nmap_args") or data.get("nmap_args") or DEFAULT_NMAP_ARGS)
        self._scan_interval_minutes = int(opts.get("scan_interval_minutes", data.get("scan_interval_minutes", DEFAULT_SCAN_INTERVAL_MINUTES)))
        self._arp_provider = _norm(opts.get(CONF_ARP_PROVIDER) or data.get(CONF_ARP_PROVIDER) or ARP_PROVIDER_NONE)

        # OPNsense
        self._opn_url = _norm(opts.get("opnsense_url") or data.get("opnsense_url")).rstrip("/")
        self._opn_key = _norm(opts.get("opnsense_key") or data.get("opnsense_key"))
        self._opn_sec = _norm(opts.get("opnsense_secret") or data.get("opnsense_secret"))
        self._opn_iface = _norm(opts.get("opnsense_interface") or data.get("opnsense_interface"))

        # AdGuard
        self._adg_url  = _norm(opts.get(CONF_ADG_URL)  or data.get(CONF_ADG_URL))
        self._adg_user = _norm(opts.get(CONF_ADG_USER) or data.get(CONF_ADG_USER))
        self._adg_pass = _norm(opts.get(CONF_ADG_PASS) or data.get(CONF_ADG_PASS))

        # UniFi
        from .const import CONF_UNIFI_URL, CONF_UNIFI_USER, CONF_UNIFI_PASS, CONF_UNIFI_SITE
        self._unifi_url  = _norm(opts.get(CONF_UNIFI_URL)  or data.get(CONF_UNIFI_URL))
        self._unifi_user = _norm(opts.get(CONF_UNIFI_USER) or data.get(CONF_UNIFI_USER))
        self._unifi_pass = _norm(opts.get(CONF_UNIFI_PASS) or data.get(CONF_UNIFI_PASS))
        self._unifi_site = _norm(opts.get(CONF_UNIFI_SITE) or data.get(CONF_UNIFI_SITE) or "default")

        # TLS verify
        self._verify_tls = bool(opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, False)))

    # scheduling
    async def maybe_auto_scan(self) -> None:
        if self._is_scanning or self._scan_interval_minutes <= 0:
            return
        last = 0.0
        if self._last_scan_finished:
            try:
                last = datetime.fromisoformat(self._last_scan_finished.replace("Z", "+00:00")).timestamp()
            except Exception:
                last = 0.0
        now = datetime.now(timezone.utc).timestamp()
        interval_secs = max(0, int(self._scan_interval_minutes) * 60)
        
        if now - last < interval_secs
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
        _emit_update(self.hass)

        try:
            # -------- Phase 1: Providers (ARP/DHCP/UniFi) --------
            by_mac: Dict[str, dict] = {}
            by_ip_fallback: Dict[str, dict] = {}

            # OPNsense (ARP)
            if self._arp_provider == ARP_PROVIDER_OPNSENSE and self._opn_url and self._opn_key and self._opn_sec:
                try:
                    pairs = await self._fetch_arp_table_opnsense()
                    for ip, mac in pairs.items():
                        d = norm_from_arp(ip, mac)
                        if self._cidr_nets and not _ip_in_any(ip, self._cidr_nets):
                            continue
                        key = d["mac"] or ip
                        if d["mac"]:
                            by_mac[key] = _merge_device(by_mac.get(key, _make_base()), d)
                        else:
                            by_ip_fallback[key] = _merge_device(by_ip_fallback.get(key, _make_base()), d)
                except Exception as exc:
                    _LOGGER.warning("OPNsense ARP fetch failed: %s", exc)

            # AdGuard (DHCP)
            if self._arp_provider == ARP_PROVIDER_ADGUARD and self._adg_url and self._adg_user and self._adg_pass:
                try:
                    ag = AdGuardDHCPClient(self._adg_url, self._adg_user, self._adg_pass, verify_tls=self._verify_tls)
                    mapping = await ag.fetch_map(self.hass)  # {ip: mac}
                    # we can also try fetch_status to get lease list with names; keep map path for now
                    for ip, mac in mapping.items():
                        d = norm_from_adguard({"ip": ip, "mac": mac})
                        if self._cidr_nets and not _ip_in_any(ip, self._cidr_nets):
                            continue
                        key = d["mac"] or ip
                        if d["mac"]:
                            by_mac[key] = _merge_device(by_mac.get(key, _make_base()), d)
                        else:
                            by_ip_fallback[key] = _merge_device(by_ip_fallback.get(key, _make_base()), d)
                except Exception as exc:
                    _LOGGER.warning("AdGuard DHCP fetch failed: %s", exc)

            # UniFi (rich client inventory)
            if self._arp_provider == ARP_PROVIDER_UNIFI and self._unifi_url and self._unifi_user and self._unifi_pass:
                try:
                    uc = UniFiClient(self._unifi_url, self._unifi_user, self._unifi_pass,
                                     site=self._unifi_site, verify_tls=self._verify_tls)
                    clients = await uc.fetch_clients(self.hass)
                    devices = await uc.fetch_devices(self.hass)
                    ap_name = {}
                    for dev in devices or []:
                        if dev.get("type") == "uap" or "ap" in str(dev.get("type", "")).lower():
                            mac = _clean_mac(dev.get("mac"))
                            if mac:
                                ap_name[mac] = dev.get("name", dev.get("model", "")) or ""
                    for c in clients or []:
                        d = norm_from_unifi_client(c, ap_name)
                        ip = d.get("ip", "")
                        if ip and self._cidr_nets and not _ip_in_any(ip, self._cidr_nets):
                            continue
                        key = d["mac"] or ip
                        if d["mac"]:
                            by_mac[key] = _merge_device(by_mac.get(key, _make_base()), d)
                        else:
                            by_ip_fallback[key] = _merge_device(by_ip_fallback.get(key, _make_base()), d)
                except Exception as exc:
                    _LOGGER.warning("UniFi fetch failed: %s", exc)

            # Publish partial (ARP/DHCP/UniFi)
            if my_gen == self._scan_gen:
                # prefer MAC-keyed; add IP-only records at end
                union = list(by_mac.values()) + [v for k, v in by_ip_fallback.items() if k not in by_mac]
                # directory overrides before publishing
                directory = await self._build_effective_directory()
                self._apply_directory_overrides(union, directory)
                self._devices = sorted(union, key=lambda d: _ip_sort_key(d.get("ip", "")))
                self._device_count = len(self._devices)
                self._status = STATUS_ENRICHING
                self._phase = PHASE_ARP
                _emit_update(self.hass)
                
            _LOGGER.debug(
                "Phase1 complete: provider=%s devices=%d (mac-keyed=%d, ip-only=%d)",
                self._arp_provider, len(by_mac) + len(by_ip_fallback), len(by_mac), len(by_ip_fallback)
            )

            # -------- Phase 2: nmap (optional) --------
            if self._cidr_strings:  # only if ranges are set
                def _scan_ranges(cidrs: List[str], args: str) -> Dict[str, dict]:
                    out: Dict[str, dict] = {}
                    try:
                        nm = nmap.PortScanner()
                    except Exception as exc:
                        _LOGGER.warning("nmap init failed: %s", exc)
                        return out
                    for cidr in cidrs:
                        try:
                            nm.scan(hosts=cidr, arguments=args)
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
                                            vendor = v; break
                                hostname = node.hostname() or ""
                                out[ip] = norm_from_nmap(ip, mac, vendor, hostname)
                            except Exception as exc:
                                _LOGGER.debug("nmap parse skip host %s: %s", host, exc)
                    return out

                nmap_map: Dict[str, dict] = await self.hass.async_add_executor_job(
                    _scan_ranges, self._cidr_strings, self._nmap_args
                )

                # merge nmap into existing union
                union_by_mac: Dict[str, dict] = {d.get("mac",""): d for d in self._devices if d.get("mac")}
                ip_only: Dict[str, dict] = {d.get("ip",""): d for d in self._devices if not d.get("mac") and d.get("ip")}

                for ip, nd in nmap_map.items():
                    mac = nd.get("mac","")
                    if mac:
                        union_by_mac[mac] = _merge_device(union_by_mac.get(mac, _make_base()), nd)
                    else:
                        ip_only[ip] = _merge_device(ip_only.get(ip, _make_base()), nd)

                final = list(union_by_mac.values()) + [v for k,v in ip_only.items() if k not in union_by_mac]

                # directory overrides before final publish
                directory = await self._build_effective_directory()
                self._apply_directory_overrides(final, directory)

                if my_gen == self._scan_gen:
                    self._devices = sorted(final, key=lambda d: _ip_sort_key(d.get("ip","")))
                    self._device_count = len(self._devices)
                    self._status = STATUS_OK
                    self._phase = PHASE_NMAP
                    _emit_update(self.hass)
            else:
                # ARP/DHCP/UniFi only
                if my_gen == self._scan_gen:
                    self._status = STATUS_OK if self._devices else STATUS_ERROR
                    self._phase = PHASE_IDLE
                    _emit_update(self.hass)

        except Exception as exc:
            _LOGGER.exception("Scan failed: %s", exc)
            if my_gen == self._scan_gen:
                self._status = STATUS_ERROR
                self._phase = PHASE_IDLE
                _emit_update(self.hass)
        finally:
            if my_gen == self._scan_gen:
                self._last_scan_finished = _now_iso()
                self._is_scanning = False
                _emit_update(self.hass)

    # ------------- provider impls -------------

    async def _fetch_arp_table_opnsense(self) -> Dict[str, str]:
        """
        POST {base}/api/diagnostics/interface/search_arp (and with '/')
        form-data: current=1, rowCount=9999, searchPhrase="", [interface=<iface>]
        Basic auth: key:secret
        Returns { ip -> MAC } (cleaned).
        """
        if not (self._opn_url and self._opn_key and self._opn_sec):
            return {}

        session = async_get_clientsession(self.hass, verify_ssl=self._verify_tls)
        auth = BasicAuth(self._opn_key, self._opn_sec)
        base = f"{self._opn_url.rstrip('/')}/api/diagnostics/interface"
        payload = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
        if self._opn_iface:
            payload["interface"] = self._opn_iface
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}

        for path in ("search_arp", "search_arp/"):
            url = f"{base}/{path}"
            try:
                async with session.post(url, auth=auth, data=payload, headers=headers, timeout=self._opn_timeout) as resp:
                    txt = await resp.text()
                    if resp.status >= 400:
                        continue
                    data = json.loads(txt)
                    mapping = self._parse_opnsense_arp(data)
                    if mapping:
                        return mapping
            except Exception as exc:
                _LOGGER.debug("OPNsense probe %s failed: %s", path, exc)

        _LOGGER.warning("OPNsense ARP: no usable endpoint at %s", self._opn_url)
        return {}

    def _parse_opnsense_arp(self, data: Any) -> Dict[str, str]:
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

    # directory build + overlay

    async def _build_effective_directory(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}
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

        opts = self._entry.options or {}
        jtxt = _norm(opts.get("mac_directory_json_text"))
        if jtxt:
            try:
                out.update(_parse_dir_obj(json.loads(jtxt)))
            except Exception as exc:
                _LOGGER.warning("Invalid directory JSON (options): %s", exc)

        url = _norm(opts.get("mac_directory_json_url") or self._entry.data.get("mac_directory_json_url"))
        if url:
            try:
                session = async_get_clientsession(self.hass, verify_ssl=self._verify_tls)
                async with session.get(url, timeout=10) as resp:
                    resp.raise_for_status()
                    out.update(_parse_dir_obj(json.loads(await resp.text())))
            except (ClientError, Exception) as exc:
                _LOGGER.warning("Failed to fetch directory URL %s: %s", url, exc)
        return out

    def _apply_directory_overrides(self, devices: List[dict], directory: Dict[str, Dict[str, str]]) -> None:
        for dev in devices:
            mac = _clean_mac(dev.get("mac", ""))
            if not mac:
                continue
            override = directory.get(mac)
            if not override:
                continue
            name = override.get("name")
            desc = override.get("desc")
            if name:
                dev["name"] = name
            if desc:
                # Keep 'type' for real device type; store free-text into 'notes'
                dev.setdefault("notes", desc)
