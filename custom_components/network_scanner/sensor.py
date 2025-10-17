# custom_components/network_scanner/sensor.py
from __future__ import annotations

from typing import Any, Dict, Optional, Callable

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory

from .const import (
    DOMAIN,
    # status/phase constants
    STATUS_SCANNING, STATUS_ERROR, STATUS_OK,
    PHASE_NMAP,
    # dispatcher signal
    SIGNAL_NSX_UPDATED,
)
from .controller import ScanController


def _icon_for(status: str | None, phase: str | None) -> str:
    st = (status or "").lower()
    ph = (phase or "").lower()
    if st == STATUS_SCANNING:
        # show a different icon during the slower nmap phase
        return "mdi:progress-clock" if ph == PHASE_NMAP else "mdi:radar"
    if st == STATUS_ERROR:
        return "mdi:alert-circle-outline"
    if st == STATUS_OK:
        return "mdi:access-point-network"
    return "mdi:lan"


class NetworkScannerExtendedSensor(SensorEntity):
    """Primary entity: device count + full device list / metrics."""

    _attr_name = "Network Scanner Extended"
    _attr_native_unit_of_measurement = "Devices"
    _attr_should_poll = False  # dispatcher-driven

    def __init__(self, controller: ScanController, entry: ConfigEntry) -> None:
        self._ctl = controller
        self._entry = entry
        self._unsub_dispatcher: Optional[Callable[[], None]] = None

    async def async_added_to_hass(self) -> None:
        # Subscribe to controller publishes
        self._unsub_dispatcher = async_dispatcher_connect(
            self.hass, SIGNAL_NSX_UPDATED, self._handle_push_update
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub_dispatcher:
            self._unsub_dispatcher()
            self._unsub_dispatcher = None

    def _handle_push_update(self) -> None:
        self.async_write_ha_state()

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry.entry_id}"

    @property
    def native_value(self) -> Optional[int]:
        # Always an int
        return int(getattr(self._ctl, "device_count", 0) or 0)

    @property
    def icon(self) -> str:
        return _icon_for(getattr(self._ctl, "status", ""), getattr(self._ctl, "phase", ""))

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        # Concrete, safe defaults for all attrs (avoid None in templates)
        devices = list(getattr(self._ctl, "devices", [])) or []
        attrs: Dict[str, Any] = {
            "status": getattr(self._ctl, "status", "") or "idle",
            "phase": getattr(self._ctl, "phase", "") or "idle",  # idle | arp | nmap
            "ip_ranges": list(getattr(self._ctl, "cidrs", [])) or [],
            "nmap_args": getattr(self._ctl, "nmap_args", "") or "",
            "scan_interval": int(getattr(self._ctl, "scan_interval", 0) or 0),
            "last_scan_started": getattr(self._ctl, "last_scan_started", None),
            "last_scan_finished": getattr(self._ctl, "last_scan_finished", None),
            "devices": devices,
            # Back-compat shims expected by existing templates
            "device_count_raw": int(getattr(self._ctl, "device_count", 0) or 0),
            # Optional metrics (controller may not provide these yet)
            "counts_by_segment": dict(getattr(self._ctl, "counts_by_segment", {}) or {}),
            "counts_by_source": dict(getattr(self._ctl, "counts_by_source", {}) or {}),
        }
        return attrs


class NetworkScannerExtendedStatus(SensorEntity):
    """Secondary entity: status-only mirror + timing/metrics."""

    _attr_name = "Network Scanner Extended Status"
    _attr_should_poll = False  # dispatcher-driven
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, controller: ScanController, entry: ConfigEntry) -> None:
        self._ctl = controller
        self._entry = entry
        self._unsub_dispatcher: Optional[Callable[[], None]] = None

    async def async_added_to_hass(self) -> None:
        self._unsub_dispatcher = async_dispatcher_connect(
            self.hass, SIGNAL_NSX_UPDATED, self._handle_push_update
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub_dispatcher:
            self._unsub_dispatcher()
            self._unsub_dispatcher = None

    def _handle_push_update(self) -> None:
        self.async_write_ha_state()

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry.entry_id}_status"

    @property
    def native_value(self) -> Optional[str]:
        return getattr(self._ctl, "status", "") or "idle"

    @property
    def icon(self) -> str:
        return _icon_for(getattr(self._ctl, "status", ""), getattr(self._ctl, "phase", ""))

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return {
            "phase": getattr(self._ctl, "phase", "") or "idle",
            "last_scan_started": getattr(self._ctl, "last_scan_started", None),
            "last_scan_finished": getattr(self._ctl, "last_scan_finished", None),
            "scan_interval": int(getattr(self._ctl, "scan_interval", 0) or 0),
            "ip_ranges": list(getattr(self._ctl, "cidrs", [])) or [],
            "nmap_args": getattr(self._ctl, "nmap_args", "") or "",
            "device_count": int(getattr(self._ctl, "device_count", 0) or 0),
            # Back-compat shim (some dashboards read it from the status entity)
            "device_count_raw": int(getattr(self._ctl, "device_count", 0) or 0),
            "counts_by_segment": dict(getattr(self._ctl, "counts_by_segment", {}) or {}),
            "counts_by_source": dict(getattr(self._ctl, "counts_by_source", {}) or {}),
        }


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
) -> None:
    controller: ScanController = hass.data[DOMAIN][entry.entry_id]["controller"]
    async_add_entities(
        [
            NetworkScannerExtendedSensor(controller, entry),
            NetworkScannerExtendedStatus(controller, entry),
        ],
        True,  # write initial state immediately
    )
