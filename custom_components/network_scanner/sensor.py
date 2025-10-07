from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import nmap
from aiohttp import ClientError
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Default discovery args that work across subnets (not just ARP on local LAN)
DEFAULT_NMAP_ARGS = "-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4"


# ---------- small helpers ----------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_mac(s: Optional[str]) -> str:
    return (s or "").upper()


def _ip_key(ip_str: str) -> List[int]:
    """Sort key for IPv4 addresses; pushes non-IPv4 to the bottom."""
    try:
        return [int(p) for p in ip_str.split(".")]
    except Exception:
        return [999, 999, 999, 999]


def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
    """
    Accept either:
      { "AA:BB:...": {"name":"..","desc":".."}, ... }
    or:
      { "data": { "AA:BB:...": {"name":"..","desc":".."}, ... } }
    Returns UPPERCASE MAC keys.
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


def _split_cidrs(raw: str) -> List[str]:
    """Split comma/space separated list into distinct non-empty CIDR strings."""
    return [p.strip() for p in re.split(r"[,\s]+", (raw or "").strip()) if p.strip()]


# ---------- main sensor ----------

class NetworkScannerExtended(SensorEntity):
    """Counts discovered devices; exposes details in attributes."""

    _attr_name = "Network Scanner Extended"
    _attr_native_unit_of_measurement = "Devices"
    _attr_should_poll = True

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry

        # Support multiple CIDRs from options first, then data
        self._cidrs: List[str] = _split_cidrs(
            entry.options.get("ip_range", entry.data.get("ip_range", ""))
        )
        self._nmap_args: str = (
            entry.options.get("nmap_args")
            or entry.data.get("nmap_args")
            or DEFAULT_NMAP_ARGS
        ).strip()

        self._state: Optional[int] = None
        self._devices: List[Dict[str, Any]] = []
        self._status: str = "idle"
        self._last_scan_started: Optional[str] = None
        self._last_scan_finished: Optional[str] = None

        self._nm = nmap.PortScanner()

        # Link a sibling status entity (set in async_setup_entry)
        self._status_entity: Optional[NetworkScannerExtendedStatus] = None

    # Allow the setup to inject the status entity so we can nudge updates
    def attach_status_entity(self, status_entity: "NetworkScannerExtendedStatus") -> None:
        self._status_entity = status_entity

    @property
    def unique_id(self) -> str:
        # Use the config entry id to guarantee uniqueness per entry
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
        """Run a scan across all configured CIDRs, merge and dedupe results."""
        self._status = "scanning"
        self._last_scan_started = _now_iso()
        if self._status_entity:
            self._status_entity.async_write_ha_state()

        try:
            # Build effective override directory: entry.data + options text/url
            directory: Dict[str, Dict[str, str]] = dict(
                self.entry.data.get("mac_directory", {})
            )
            opts = self.entry.options or {}

            # JSON pasted into options (highest precedence)
            jtxt = (opts.get("mac_directory_json_text") or "").strip()
            if jtxt:
                try:
                    directory.update(_parse_dir_obj(json.loads(jtxt)))
                except Exception as exc:
                    _LOGGER.warning("Invalid options JSON, ignoring: %s", exc)

            # Optional directory URL (options takes precedence, fallback to data)
            url = (
                opts.get("mac_directory_json_url")
                or self.entry.data.get("mac_directory_json_url")
                or ""
            ).strip()
            if url:
                try:
                    session = async_get_clientsession(self.hass)
                    async with session.get(url, timeout=10) as resp:
                        resp.raise_for_status()
                        directory.update(_parse_dir_obj(json.loads(await resp.text())))
                except (ClientError, Exception) as exc:
                    _LOGGER.warning("Failed to fetch directory URL %s: %s", url, exc)

            # Scan each CIDR; gather results
            all_devices: List[Dict[str, Any]] = []
            for cidr in self._cidrs:
                chunk = await self.hass.async_add_executor_job(
                    self._scan_cidr, cidr, directory, self._nmap_args
                )
                all_devices.extend(chunk)

            # Deduplicate by MAC (keep first seen), then sort by IP
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
            _LOGGER.error("Network scan failed: %s", exc)
            self._status = "error"
        finally:
            self._last_scan_finished = _now_iso()
            if self._status_entity:
                self._status_entity.async_write_ha_state()

    # ---------- internal ----------

    def _scan_cidr(
        self,
        cidr: str,
        directory: Dict[str, Dict[str, str]],
        nmap_args: str,
    ) -> List[Dict[str, Any]]:
        """Blocking scan for a single CIDR (runs in executor)."""
        res: List[Dict[str, Any]] = []
        self._nm.scan(hosts=cidr, arguments=nmap_args)

        for host in self._nm.all_hosts():
            try:
                node = self._nm[host]
                addrs = node.get("addresses", {})
                mac = addrs.get("mac")
                ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
                if not ip:
                    # If there's no IP we can't place it meaningfully—skip
                    continue

                # Vendor (case-insensitive match on MAC)
                vendor = "Unknown"
                ven_map = node.get("vendor", {})
                if isinstance(ven_map, dict) and ven_map:
                    for k, v in ven_map.items():
                        if _norm_mac(k) == _norm_mac(mac):
                            vendor = v
                            break

                hostname = node.hostname() or ""

                override = directory.get(_norm_mac(mac), {}) if mac else {}
                name = override.get("name") or "Unknown Device"
                desc = override.get("desc") or "Unknown Device"

                res.append(
                    {
                        "ip": ip,
                        "mac": mac or "",
                        "name": name,
                        "type": desc,
                        "vendor": vendor,
                        "hostname": hostname,
                        "cidr": cidr,
                    }
                )
            except Exception as exc:
                _LOGGER.debug("Skipping host %s due to parse error: %s", host, exc)

        return res


# ---------- separate status sensor (optional but useful) ----------

class NetworkScannerExtendedStatus(SensorEntity):
    """
    Simple text sensor reflecting the main scanner's state: idle/scanning/ok/error,
    with the same timestamps/ranges as attributes.
    """

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["idle", "scanning", "ok", "error"]
    _attr_should_poll = False

    def __init__(self, parent: NetworkScannerExtended) -> None:
        self._parent = parent
        self._attr_name = "Network Scanner Extended Status"
        self._attr_unique_id = f"{DOMAIN}_{parent.entry.entry_id}_status"

    @property
    def native_value(self) -> str | None:
        return getattr(self._parent, "_status", None)

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            "last_scan_started": getattr(self._parent, "_last_scan_started", None),
            "last_scan_finished": getattr(self._parent, "_last_scan_finished", None),
            "ip_ranges": getattr(self._parent, "_cidrs", []),
            "nmap_args": getattr(self._parent, "_nmap_args", None),
        }


# ---------- setup ----------

async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
) -> None:
    """
    Create one main counter sensor and one status sensor per config entry.
    We do NOT add with initial update=True; nmap can be slow. HA will poll.
    """
    raw = (entry.options.get("ip_range") or entry.data.get("ip_range") or "").strip()
    if not raw:
        _LOGGER.error("network_scanner_extended: ip_range missing; not creating entities")
        return

    main = NetworkScannerExtended(hass, entry)
    status = NetworkScannerExtendedStatus(main)
    main.attach_status_entity(status)

    async_add_entities([main, status], False)
