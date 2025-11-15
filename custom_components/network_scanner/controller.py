"""Data controller for the Network Scanner integration (nmap-free)."""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import json
import logging
import re
from datetime import datetime, timezone
from ipaddress import ip_network, ip_address

from aiohttp import ClientError, ClientTimeout, BasicAuth
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import (
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_IP_RANGE,
    CONF_ARP_PROVIDER,
    ARP_PROVIDER_NONE,
    ARP_PROVIDER_OPNSENSE,
    ARP_PROVIDER_ADGUARD,
    CONF_ARP_VERIFY_TLS,
    # status/phase + signal
    STATUS_IDLE, STATUS_SCANNING, STATUS_ENRICHING, STATUS_OK, STATUS_ERROR,
    PHASE_IDLE, PHASE_ARP,
    SIGNAL_NSX_UPDATED,
    # AdGuard
    CONF_ADG_URL, CONF_ADG_USER, CONF_ADG_PASS,
    # UniFi
    CONF_UNIFI_ENABLED, CONF_UNIFI_URL, CONF_UNIFI_USER, CONF_UNIFI_PASS, CONF_UNIFI_SITE,
)

from .adguard import AdGuardDHCPClient
from .unifi import UniFiClient

_LOGGER = logging.getLogger(__name__)

# ---------------- helpers ----------------

def _emit_update(hass) -> None:
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

# --------- unified device model ---------

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
    d = _make_base(ip, mac); d["source"] = ["arp"]; return d

def norm_from_adguard(lease: dict) -> dict:
    ip = str(lease.get("ip", "") or lease.get("address", ""))
    mac = _clean_mac(lease.get("mac", lease.get("mac_address", "")))
    d = _make_base(ip, mac)
    d["dhcp"]["server"] = "adguard"
    d["dhcp"]["lease_ip"] = ip
    d["source"] = ["adguard"]
    host = lease.get("hostname") or lease.get("name") or ""
    if host: d["hostname"] = host
    return d

def norm_from_unifi_client(c: dict, ap_name_by_mac: dict[str, str]) -> dict:
    ip = str(c.get("ip", "") or "")
    mac = _clean_mac(c.get("mac", ""))
    d = _make_base(ip, mac)
    if c.get("hostname"): d["hostname"] = c["hostname"]
    if c.get("oui"): d["vendor"] = c["oui"]
    if c.get("is_wired") is not None: d["wired"] = bool(c["is_wired"])
    if c.get("essid"): d["ssid"] = c["essid"]
    if isinstance(c.get("vlan"), int): d["vlan"] = c["vlan"]
    ap_mac = _clean_mac(c.get("ap_mac", "")); 
    if ap_mac: d["ap"]["mac"] = ap_mac; d["ap"]["name"] = ap_name_by_mac.get(ap_mac, "")
    sw_mac = _clean_mac(c.get("sw_mac", "")); 
    if sw_mac: d["switch"]["mac"] = sw_mac; d["switch"]["port"] = c.get("sw_port")
    if isinstance(c.get("rssi"), int): d["signal"]["rssi"] = c["rssi"]
    if isinstance(c.get("snr"), int):  d["signal"]["snr"] = c["snr"]
    d["bytes"]["tx"] = int(c.get("tx_bytes", 0) or 0)
    d["bytes"]["rx"] = int(c.get("rx_bytes", 0) or 0)
    def _iso(v):
        try: return datetime.fromtimestamp(int(v), tz=timezone.utc).isoformat()
        except Exception: return ""
    if c.get("first_seen"): d["first_seen"] = _iso(c["first_seen"])
    if c.get("last_seen"):  d["last_seen"]  = _iso(c["last_seen"])
    d["source"] = ["unifi"]
    return d

def _merge_device(dst: dict, src: dict) -> dict:
    def take(path: list[str], prefer_existing: bool = False):
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

    # Keep first decent identity/name/vendor
    take(["ip"])
    take(["mac"])
    take(["name"], prefer_existing=True)
    take(["hostname"], prefer_existing=True)
    take(["vendor"], prefer_existing=True)
    take(["type"], prefer_existing=False)

    # network-ish
    take(["wired"])
    take(["ssid"], prefer_existing=True)
    take(["vlan"])
    take(["network"], prefer_existing=True)

    # infra
    for p in (["ap","mac"], ["ap","name"], ["switch","mac"], ["switch","name"], ["switch","port"], ["switch","port_name"], ["switch","poe"]):
        take(p)

    # signal/bytes
    for p in (["signal","rssi"], ["signal","snr"]): take(p)
    for p in (["bytes","tx"], ["bytes","rx"]): take(p)

    # DHCP
    for p in (["dhcp","server"], ["dhcp","lease_ip"], ["dhcp","reservation_ip"]): take(p)

    # timestamps: keep the newer last_seen, older first_seen
    for key in ("first_seen", "last_seen"):
        src_v = src.get(key)
        dst_v = dst.get(key)
        if not src_v:
            continue
        if not dst_v:
            dst[key] = src_v
        else:
            try:
                src_ts = datetime.fromisoformat(src_v.replace("Z", "+00:00")).timestamp()
                dst_ts = datetime.fromisoformat(dst_v.replace("Z", "+00:00")).timestamp()
                if (key == "first_seen" and src_ts < dst_ts) or (key == "last_seen" and src_ts > dst_ts):
                    dst[key] = src_v
            except Exception:
                pass

    dst["source"] = sorted(set((dst.get("source") or []) + (src.get("source") or [])))
    return dst

# ---------------- controller ----------------

class ScanController:
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry

        self._devices: List[Dict[str, Any]] = []
        self._device_count: int = 0
        self._status: str = STATUS_IDLE
        self._phase: str = PHASE_IDLE
        self._last_scan_started: Optional[str] = None
        self._last_scan_finished: Optional[str] = None
        self._is_scanning: bool = False
        self._scan_gen: int = 0

        self._cidr_strings: List[str] = []
        self._cidr_nets: List[Tuple[str, object]] = []
        self._scan_interval_minutes: int = DEFAULT_SCAN_INTERVAL_MINUTES
        self._arp_provider: str = ARP_PROVIDER_NONE

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

        # UniFi (independent enrichment)
        self._unifi_enabled: bool = False
        self._unifi_url: str = ""
        self._unifi_user: str = ""
        self._unifi_pass: str = ""
        self._unifi_site: str = "default"

        self._verify_tls: bool = False

        self.apply_entry(entry)

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
    def scan_interval_minutes(self) -> int: return self._scan_interval_minutes
    @property
    def phase(self) -> str: return self._phase

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
        self._unifi_enabled = bool(opts.get(CONF_UNIFI_ENABLED, data.get(CONF_UNIFI_ENABLED, False)))
        self._unifi_url  = _norm(opts.get(CONF_UNIFI_URL)  or data.get(CONF_UNIFI_URL))
        self._unifi_user = _norm(opts.get(CONF_UNIFI_USER) or data.get(CONF_UNIFI_USER))
        self._unifi_pass = _norm(opts.get(CONF_UNIFI_PASS) or data.get(CONF_UNIFI_PASS))
        self._unifi_site = _norm(opts.get(CONF_UNIFI_SITE) or data.get(CONF_UNIFI_SITE) or "default")

        self._verify_tls = bool(opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, False)))

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
        if now - last < self._scan_interval_minutes * 60:
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

        start_ts = datetime.now(timezone.utc)
        _LOGGER.debug(
            "Scan start gen=%d provider=%s cidrs=%s unifi_enabled=%s",
            my_gen, self._arp_provider, self._cidr_strings, self._unifi_enabled
        )

        try:
            by_mac: Dict[str, dict] = {}
            by_ip_fallback: Dict[str, dict] = {}

            # ---------- ARP/DHCP ----------
            if self._arp_provider == ARP_PROVIDER_OPNSENSE and self._opn_url and self._opn_key and self._opn_sec:
                try:
                    pairs = await self._fetch_arp_table_opnsense()
                    for ip, mac in pairs.items():
                        if self._cidr_nets and not _ip_in_any(ip, self._cidr_nets):
                            continue
                        d = norm_from_arp(ip, mac)
                        key = d["mac"] or ip
                        target = by_mac if d["mac"] else by_ip_fallback
                        target[key] = _merge_device(target.get(key, _make_base()), d)
                except Exception as exc:
                    _LOGGER.warning("OPNsense ARP fetch failed: %s", exc)

            if self._arp_provider == ARP_PROVIDER_ADGUARD and self._adg_url and self._adg_user and self._adg_pass:
                try:
                    ag = AdGuardDHCPClient(self._adg_url, self._adg_user, self._adg_pass, verify_tls=self._verify_tls)
                    mapping = await ag.fetch_map(self.hass)  # {ip: mac}
                    for ip, mac in mapping.items():
                        if self._cidr_nets and not _ip_in_any(ip, self._cidr_nets):
                            continue
                        d = norm_from_adguard({"ip": ip, "mac": mac})
                        key = d["mac"] or ip
                        target = by_mac if d["mac"] else by_ip_fallback
                        target[key] = _merge_device(target.get(key, _make_base()), d)
                except Exception as exc:
                    _LOGGER.warning("AdGuard DHCP fetch failed: %s", exc)

            _LOGGER.debug("ARP/DHCP unique MAC=%d IP-only=%d", len(by_mac), len(by_ip_fallback))

            # ---------- UniFi enrichment (independent) ----------
            if self._unifi_enabled and self._unifi_url and self._unifi_user and self._unifi_pass:
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
                    _LOGGER.debug("UniFi: clients=%d devices=%d", len(clients or []), len(devices or []))
                    for c in clients or []:
                        d = norm_from_unifi_client(c, ap_name)
                        ip = d.get("ip", "")
                        if ip and self._cidr_nets and not _ip_in_any(ip, self._cidr_nets):
                            continue
                        key = d["mac"] or ip
                        target = by_mac if d["mac"] else by_ip_fallback
                        target[key] = _merge_device(target.get(key, _make_base()), d)
                except Exception as exc:
                    _LOGGER.warning("UniFi fetch failed: %s", exc)

            # Publish final (no nmap phase)
            if my_gen == self._scan_gen:
                union = list(by_mac.values()) + [v for k, v in by_ip_fallback.items() if k not in by_mac]
                directory = await self._build_effective_directory()
                self._apply_directory_overrides(union, directory)

                self._devices = sorted(union, key=lambda d: _ip_sort_key(d.get("ip", "")))
                self._device_count = len(self._devices)
                # Briefly surface "enriching" before OK to keep UI signals consistent
                self._status = STATUS_ENRICHING
                self._phase = PHASE_ARP
                _emit_update(self.hass)

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
                _LOGGER.debug(
                    "Scan finish gen=%d status=%s phase=%s devices=%d",
                    my_gen, self._status, self._phase, self._device_count
                )

    # ------------- provider impls -------------

    async def _fetch_arp_table_opnsense(self) -> Dict[str, str]:
        if not (self._opn_url and self._opn_key and self._opn_sec):
            return {}
        session = async_get_clientsession(self.hass, verify_ssl=self._verify_tls)
        auth = BasicAuth(self._opn_key, self._opn_sec)
        base = f"{self._opn_url.rstrip('/')}/api/diagnostics/interface"
        payload = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
        if self._opn_iface:
            payload["interface"] = self._opn_iface
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}

        async def _looks_like_html(ct: str | None, body: str) -> bool:
            ct = (ct or "").lower()
            if "text/html" in ct:
                return True
            t = body.lstrip().lower()
            return t.startswith("<!doctype") or t.startswith("<html")

        for path in ("search_arp", "search_arp/"):
            url = f"{base}/{path}"
            try:
                async with session.post(url, auth=auth, data=payload, headers=headers, timeout=self._opn_timeout) as resp:
                    txt = await resp.text()
                    if resp.status >= 400:
                        _LOGGER.debug("OPNsense %s HTTP %s: %.200s", url, resp.status, txt)
                        continue
                    if _looks_like_html(resp.headers.get("Content-Type"), txt):
                        _LOGGER.debug("OPNsense %s returned HTML (likely login page).", url)
                        continue
                    try:
                        data = await resp.json(content_type=None)
                    except Exception:
                        try:
                            data = json.loads(txt)
                        except Exception:
                            _LOGGER.debug("OPNsense %s non-JSON body: %.200s", url, txt)
                            continue
                    mapping = self._parse_opnsense_arp(data)
                    if mapping:
                        return mapping
            except Exception as exc:
                _LOGGER.debug("OPNsense probe %s failed: %s", url, exc)

        _LOGGER.warning("OPNsense ARP: no usable endpoint at %s (check API key/secret, interface, TLS)", self._opn_url)
        return {}

    def _parse_opnsense_arp(self, data: Any) -> Dict[str, str]:
        def pick(rows: List[dict]) -> Dict[str, str]:
            out: Dict[str, str] = {}
            for r in rows:
                if not isinstance(r, dict): continue
                rip = r.get("ip") or r.get("address") or r.get("inet")
                rmac = r.get("mac") or r.get("lladdr") or r.get("hwaddr")
                mac = _clean_mac(rmac)
                if rip and mac: out[str(rip)] = mac
            return out
        if isinstance(data, dict):
            if isinstance(data.get("rows"), list):
                return pick(data["rows"])
            for v in data.values():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    got = pick(v)
                    if got: return got
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return pick(data)
        return {}

    # ------------- directory overlay -------------

    async def _build_effective_directory(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}
        base = self._entry.data.get("mac_directory", {})
        if isinstance(base, dict):
            for k, v in base.items():
                mk = _clean_mac(k)
                if not mk: continue
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
            if override.get("name"):
                dev["name"] = override["name"]
            if override.get("desc"):
                dev["type"] = override["desc"]
