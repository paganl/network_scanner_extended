# custom_components/network_scanner_extended/sensor.py
from __future__ import annotations

from typing import Any, Dict, Optional

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN
from .controller import ScanController


def _get_phase(ctl: ScanController) -> str:
    # Prefer public property if present, otherwise peek the private field.
    return getattr(ctl, "phase", getattr(ctl, "_phase", "idle")) or "idle"


class NetworkScannerExtendedSensor(SensorEntity):
    """Primary entity: device count + full device list / metrics."""

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
        ph = _get_phase(self._ctl).lower()
        if st == "scanning":
            # show 'enriching' distinctly if we're in the slow pass
            return "mdi:progress-clock" if ph == "nmap" else "mdi:radar"
        if st == "error":
            return "mdi:alert-circle-outline"
        if st == "ok":
            return "mdi:access-point-network"
        return "mdi:lan"

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        # Safe getattr fallbacks so sensor doesn't explode if controller evolves.
        return {
            "status": self._ctl.status,
            "phase": _get_phase(self._ctl),  # idle | arp | nmap
            "ip_ranges": list(getattr(self._ctl, "cidrs", [])),
            "nmap_args": getattr(self._ctl, "nmap_args", ""),
            "scan_interval": getattr(self._ctl, "scan_interval", 0),
            "last_scan_started": getattr(self._ctl, "last_scan_started", None),
            "last_scan_finished": getattr(self._ctl, "last_scan_finished", None),
            "devices": list(getattr(self._ctl, "devices", [])),
            "counts_by_segment": dict(getattr(self._ctl, "counts_by_segment", {})),
            "counts_by_source": dict(getattr(self._ctl, "counts_by_source", {})),
        }

    async def async_update(self) -> None:
        # Controller decides whether to auto-scan based on scan_interval (0 = manual)
        await self._ctl.maybe_auto_scan()


class NetworkScannerExtendedStatus(SensorEntity):
    """Secondary entity: status-only mirror + timing/metrics."""

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
        ph = _get_phase(self._ctl).lower()
        if st == "scanning":
            return "mdi:progress-clock" if ph == "nmap" else "mdi:radar"
        if st == "error":
            return "mdi:alert-circle-outline"
        if st == "ok":
            return "mdi:lan-check"
        return "mdi:lan"

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            "phase": _get_phase(self._ctl),
            "last_scan_started": getattr(self._ctl, "last_scan_started", None),
            "last_scan_finished": getattr(self._ctl, "last_scan_finished", None),
            "scan_interval": getattr(self._ctl, "scan_interval", 0),
            "ip_ranges": list(getattr(self._ctl, "cidrs", [])),
            "nmap_args": getattr(self._ctl, "nmap_args", ""),
            "device_count": getattr(self._ctl, "device_count", 0),
            "counts_by_segment": dict(getattr(self._ctl, "counts_by_segment", {})),
            "counts_by_source": dict(getattr(self._ctl, "counts_by_source", {})),
        }

    async def async_update(self) -> None:
        # Reflects controller state; do not trigger scans here
        return


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
) -> None:
    controller: ScanController = hass.data[DOMAIN][entry.entry_id]["controller"]
    async_add_entities(
        [
            NetworkScannerExtendedSensor(controller, entry),
            NetworkScannerExtendedStatus(controller, entry),
        ],
        False,  # controller handles refresh / timing
    )
