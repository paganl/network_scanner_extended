# custom_components/network_scanner/sensor.py
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities([NetworkScannerSummarySensor(coordinator, entry)], True)


class NetworkScannerSummarySensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Summary"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:lan"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}:summary"

    @property
    def native_value(self) -> int:
        data = self.coordinator.data or {}
        return int(data.get("device_count_total", 0))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Keep attributes SMALL — this is what fixes the 16KB warning."""
        d = self.coordinator.data or {}
        return {
            "status": d.get("status", "unknown"),
            "presence_provider": d.get("presence_provider", ""),
            "unifi_enabled": bool(d.get("unifi_enabled", False)),
            "device_count_total": int(d.get("device_count_total", 0)),
            "device_count_new": int(d.get("device_count_new", 0)),
            "device_count_random_mac": int(d.get("device_count_random_mac", 0)),
            "device_count_stale": int(d.get("device_count_stale", 0)),
            "last_scan_started": d.get("last_scan_started"),
            "last_scan_finished": d.get("last_scan_finished"),
            "duration_ms": int(d.get("duration_ms", 0)),
            "error_count": int(d.get("error_count", 0)),
            "last_error": d.get("last_error", ""),
        }
