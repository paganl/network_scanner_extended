from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import nmap
from aiohttp import ClientError
from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Default discovery args work across subnets better than ARP-only
DEFAULT_NMAP_ARGS = "-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4"

def _norm_mac(s: Optional[str]) -> str:
    return (s or "").upper()

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

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _ip_key(ip_str: str) -> List[int]:
    try:
        return [int(p) for p in ip_str.split(".")]
    except Exception:
        return [999, 999, 999, 999]

class NetworkScannerExtended(SensorEntity):
    _attr_name = "Network Scanner Extended"
    _attr_native_unit_of_measurement = "Devices"
    _attr_should_poll = True

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        # Support 1+ CIDRs, comma/space separated
        self._cidrs = self._parse_cidrs(entry)
        self._nmap_args = self._get_nmap_args(entry)
        self._state: Optional[int] = None
        self._devices: List[Dict[str, Any]] = []
        self._status: str = "idle"
        self._last_scan_started: Optional[str] = None
        self._last_scan_finished: Optional[str] = None
        self.nm = nmap.PortScanner()

    @staticmethod
    def _parse_cidrs(entry: ConfigEntry) -> List[str]:
        # Prefer options.ip_range; allow multiple, split by comma/space
        raw = entry.options.get("ip_range", entry.data.get("ip_range", "")).strip()
        parts = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
        return parts

    @staticmethod
    def _get_nmap_args(entry: ConfigEntry) -> str:
        return (entry.options.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()


    @property
    def unique_id(self) -> str:
        # use the config entry id to guarantee uniqueness across entries
        return f"{DOMAIN}_{self.entry.entry_id}"

    @property
    def native_value(self) -> Optional[int]:
        return self._state

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            "status": self._status,
            "ip_ranges": self._cidrs,
            "nmap_args": self._nmap_args,
            "last_scan_started": self._last_scan_started,
            "last_scan_finished": self._last_scan_finished,
            "devices": self._devices,
        }

    async def async_update(self) -> None:
        # Build effective directory (entry.data + options text/url)
        try:
            self._status = "scanning"
            self._last_scan_started = _now_iso()

            directory: Dict[str, Dict[str, str]] = dict(self.entry.data.get("mac_directory", {}))
            opts = self.entry.options or {}

            # JSON pasted in options (highest precedence)
            jtxt = (opts.get("mac_directory_json_text") or "").strip()
            if jtxt:
                try:
                    directory.update(_parse_dir_obj(json.loads(jtxt)))
                except Exception as exc:
                    _LOGGER.warning("Invalid options JSON: %s", exc)

            # Optional URL
            url = (opts.get("mac_directory_json_url") or self.entry.data.get("mac_directory_json_url") or "").strip()
            if url:
                try:
                    session = async_get_clientsession(self.hass)
                    async with session.get(url, timeout=10) as resp:
                        resp.raise_for_status()
                        directory.update(_parse_dir_obj(json.loads(await resp.text())))
                except (ClientError, Exception) as exc:
                    _LOGGER.warning("Failed to fetch directory URL %s: %s", url, exc)

            # Scan each CIDR; merge results
            all_devices: List[Dict[str, Any]] = []
            for cidr in self._cidrs:
                chunk = await self.hass.async_add_executor_job(self._scan_cidr, cidr, directory, self._nmap_args)
                all_devices.extend(chunk)

            # Deduplicate by MAC (keep first seen)
            dedup: Dict[str, Dict[str, Any]] = {}
            for d in all_devices:
                mk = _norm_mac(d.get("mac"))
                if mk and mk not in dedup:
                    dedup[mk] = d

            devices = list(dedup.values())
            devices.sort(key=lambda d: _ip_key(d.get("ip", "")))

            self._devices = devices
            self._state = len(devices)
            self._status = "ok"
        except Exception as exc:
            self._status = "error"
            _LOGGER.error("Network scan failed: %s", exc)
        finally:
            self._last_scan_finished = _now_iso()

    def _scan_cidr(self, cidr: str, directory: Dict[str, Dict[str, str]], nmap_args: str) -> List[Dict[str, Any]]:
        res: List[Dict[str, Any]] = []
        # nmap_args e.g. "-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4"
        self.nm.scan(hosts=cidr, arguments=nmap_args)
        for host in self.nm.all_hosts():
            try:
                node = self.nm[host]
                addrs = node.get("addresses", {})
                mac = addrs.get("mac")
                ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
                if not ip:  # keep entries even if MAC missing for visibility?
                    continue

                vendor = "Unknown"
                ven_map = node.get("vendor", {})
                if isinstance(ven_map, dict):
                    for k, v in ven_map.items():
                        if _norm_mac(k) == _norm_mac(mac):
                            vendor = v
                            break

                hostname = node.hostname() or ""
                override = directory.get(_norm_mac(mac), {}) if mac else {}
                name = override.get("name") or "Unknown Device"
                desc = override.get("desc") or "Unknown Device"

                res.append({
                    "ip": ip,
                    "mac": mac or "",
                    "name": name,
                    "type": desc,
                    "vendor": vendor,
                    "hostname": hostname,
                    "cidr": cidr,
                })
            except Exception as exc:
                _LOGGER.debug("Skipping host %s: %s", host, exc)
        return res

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    # Require at least one CIDR
    raw = entry.options.get("ip_range", entry.data.get("ip_range", "")).strip()
    if not raw:
        _LOGGER.error("network_scanner: ip_range missing; not creating entity")
        return
    async_add_entities([NetworkScannerExtended(hass, entry)], False)
