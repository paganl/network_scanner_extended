"""Sensor platform for the Network Scanner integration."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.const import UnitOfNone

from .const import DOMAIN

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([NetworkScannerSensor(coordinator, entry)], update_before_add=True)

class NetworkScannerSensor(CoordinatorEntity, SensorEntity):
    _attr_icon = "mdi:devices"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry
        # Friendly name varies per entry (e.g. “Network Scanner (opnsense)”)
        title = entry.title or "Network Scanner"
        self._attr_name = f"{title} Devices"
        # Stable unique_id so multiple entries can coexist
        self._attr_unique_id = f"{entry.entry_id}_devices"

    @property
    def native_value(self):
        """Sensor state = device count."""
        data = self.coordinator.data or {}
        return int(data.get("count") or 0)

    @property
    def extra_state_attributes(self):
        """
        Expose all coordinator data (devices, flat, index, summary, last_refresh_utc, count).
        These are plain dict/list/str/int types — safe for HA.
        """
        return self.coordinator.data or {}

    @property
    def should_poll(self) -> bool:
        return False
