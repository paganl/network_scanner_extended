from __future__ import annotations
from typing import Any, Dict, Optional

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN
from .controller import ScanController


class NetworkScannerExtendedSensor(SensorEntity):
    """Device count + device list."""

    _attr_name = "Network Scanner Extended"
    _attr_native_unit_of_measurement = "Devices"
    _attr_should_poll = True

    def __init__(self, controller: ScanController, entry: ConfigEntry) -> None:
        self._ctl = controller
        self._entry = entry

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry.entry_id}"

    @property
    def native_value(self) -> Optional[int]:
        return self._ctl.device_count

    @property
    def icon(self) -> str:
        st = (self._ctl.status or "idle").lower()
        if st == "scanning":
            return "mdi:radar"
        if st == "error":
            return "mdi:alert-circle-outline"
        if st == "ok":
            return "mdi:access-point-network"
        return "mdi:lan"

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            "status": self._ctl.status,
            "ip_ranges": self._ctl.cidrs,
            "nmap_args": self._ctl.nmap_args,
            "scan_interval": self._ctl.scan_interval,
            "last_scan_started": self._ctl.last_scan_started,
            "last_scan_finished": self._ctl.last_scan_finished,
            "devices": self._ctl.devices,
        }

    async def async_update(self) -> None:
        # Controller decides whether to auto-scan based on scan_interval (0 = manual).
        await self._ctl.maybe_auto_scan()


class NetworkScannerExtendedStatus(SensorEntity):
    """Status-only mirror: idle/scanning/ok/error."""

    _attr_name = "Network Scanner Extended Status"
    _attr_should_poll = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, controller: ScanController, entry: ConfigEntry) -> None:
        self._ctl = controller
        self._entry = entry

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry.entry_id}_status"

    @property
    def native_value(self) -> Optional[str]:
        return self._ctl.status

    @property
    def icon(self) -> str:
        st = (self._ctl.status or "idle").lower()
        if st == "scanning":
            return "mdi:radar"
        if st == "error":
            return "mdi:alert-circle-outline"
        if st == "ok":
            return "mdi:lan-check"
        return "mdi:lan"

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            "last_scan_started": self._ctl.last_scan_started,
            "last_scan_finished": self._ctl.last_scan_finished,
            "scan_interval": self._ctl.scan_interval,
            "ip_ranges": self._ctl.cidrs,
            "nmap_args": self._ctl.nmap_args,
            "device_count": self._ctl.device_count,
        }

    async def async_update(self) -> None:
        # Just reflects controller state; do not trigger scans here.
        return


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    controller: ScanController = hass.data[DOMAIN][entry.entry_id]["controller"]
    async_add_entities(
        [
            NetworkScannerExtendedSensor(controller, entry),
            NetworkScannerExtendedStatus(controller, entry),
        ],
        False,  # no immediate update; controller handles refresh/timing
    )
