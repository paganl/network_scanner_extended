from __future__ import annotations
import json, logging
from datetime import timedelta, datetime
from typing import Any, Dict, List, Optional
import nmap
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import Entity
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from .const import DOMAIN

SCAN_INTERVAL = timedelta(minutes=15)
_LOGGER = logging.getLogger(__name__)

def _norm_mac(mac: Optional[str]) -> str:
    return (mac or "").upper()

def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
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

async def _fetch_dir_from_url(hass: HomeAssistant, url: str) -> Dict[str, Dict[str, str]]:
    if not url:
        return {}
    try:
        session = async_get_clientsession(hass)
        async with session.get(url, timeout=10) as resp:
            resp.raise_for_status()
            data = json.loads(await resp.text())
        return _parse_dir_obj(data)
    except Exception as exc:
        _LOGGER.warning("Failed to fetch directory from %s: %s", url, exc)
        return {}

class NetworkScanner(Entity):
    _attr_name = "Network Scanner Extended"
    _attr_unit_of_measurement = "Devices"
    _attr_should_poll = True

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.ip_range: str = entry.data.get("ip_range", "")
        self._state: Optional[int] = None
        self._devices: List[Dict[str, Any]] = []
        # status diagnostics
        self._status: str = "idle"  # idle|scanning|ok|error
        self._last_scan_started: Optional[str] = None
        self._last_scan_duration_ms: Optional[int] = None
        self._last_error: Optional[str] = None
        self.nm = nmap.PortScanner()
        _LOGGER.info("Network Scanner Extended initialised for %s", self.ip_range)

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self.ip_range}"

    @property
    def icon(self) -> str:
        return "mdi:lan-pending" if self._status == "scanning" else "mdi:lan"

    @property
    def state(self) -> Optional[int]:
        return self._state

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            "devices": self._devices,
            "status": self._status,
            "last_scan_started": self._last_scan_started,
            "last_scan_duration_ms": self._last_scan_duration_ms,
            "last_error": self._last_error,
        }

    async def async_update(self) -> None:
        try:
            directory: Dict[str, Dict[str, str]] = dict(self.entry.data.get("mac_directory", {}))
            opts = self.entry.options or {}
            opt_text = (opts.get("mac_directory_json_text") or "").strip()
            if opt_text:
                try:
                    directory.update(_parse_dir_obj(json.loads(opt_text)))
                except Exception as exc:
                    _LOGGER.warning("Options JSON invalid; ignoring: %s", exc)
            opt_url = (opts.get("mac_directory_json_url") or "").strip()
            data_url = (self.entry.data.get("mac_directory_json_url") or "").strip()
            url_to_use = opt_url or data_url
            if url_to_use:
                directory.update(await _fetch_dir_from_url(self.hass, url_to_use) or {})

            # mark scanning and push to UI
            self._status = "scanning"
            self._last_error = None
            start = datetime.utcnow()
            self._last_scan_started = start.isoformat(timespec="seconds") + "Z"
            self.async_write_ha_state()

            devices = await self.hass.async_add_executor_job(self._scan_network, directory)
            self._devices = devices
            self._state = len(devices)
            self._last_scan_duration_ms = int((datetime.utcnow() - start).total_seconds() * 1000)
            self._status = "ok"
        except Exception as e:
            _LOGGER.error("Error updating network scanner: %s", e)
            self._status = "error"
            self._last_error = str(e)

    def _lookup_override(self, directory: Dict[str, Dict[str, str]], mac: str) -> Dict[str, str]:
        return directory.get(_norm_mac(mac), {})

    def _scan_network(self, directory: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
        self.nm.scan(hosts=self.ip_range, arguments="-sn")
        devices: List[Dict[str, Any]] = []
        for host in self.nm.all_hosts():
            try:
                addrs = self.nm[host].get("addresses", {})
                mac = addrs.get("mac")
                ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
                if not mac or not ip:
                    continue
                vendor = "Unknown"
                ven_map = self.nm[host].get("vendor", {})
                if isinstance(ven_map, dict):
                    for k, v in ven_map.items():
                        if _norm_mac(k) == _norm_mac(mac):
                            vendor = v
                            break
                hostname = self.nm[host].hostname() or ""
                override = self._lookup_override(directory, mac)
                device_name = override.get("name") or "Unknown Device"
                device_type = override.get("desc") or "Unknown Device"
                devices.append({
                    "ip": ip, "mac": mac, "name": device_name, "type": device_type,
                    "vendor": vendor, "hostname": hostname
                })
            except Exception as exc:
                _LOGGER.debug("Skipping host %s: %s", host, exc)
        def _ip_key(ip_str: str) -> List[int]:
            try: return [int(part) for part in ip_str.split(".")]
            except Exception: return [999, 999, 999, 999]
        devices.sort(key=lambda x: _ip_key(x.get("ip", "")))
        return devices

async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities) -> None:
    ip_range = config_entry.data.get("ip_range")
    if not ip_range:
        _LOGGER.error("No ip_range configured; aborting setup")
        return
    _LOGGER.debug("Setting up Network Scanner Extended for %s", ip_range)
    # IMPORTANT: don't block on first update
    async_add_entities([NetworkScanner(hass, config_entry)], False)
