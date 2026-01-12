from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    blob = hass.data[DOMAIN][entry.entry_id]
    coordinator = blob["coordinator"] if isinstance(blob, dict) else blob
    async_add_entities([NetworkScannerSensor(coordinator, entry)], True)


class NetworkScannerSensor(CoordinatorEntity, SensorEntity):
    _attr_icon = "mdi:lan"
    _attr_has_entity_name = True
    _attr_name = "Network Scanner"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}:summary"

    @property
    def native_value(self):
        meta = (self.coordinator.data or {}).get("meta") or {}
        return int(meta.get("count") or 0)

    @property
    def extra_state_attributes(self):
        meta = (self.coordinator.data or {}).get("meta") or {}
        # keep it SMALL
        return {
            "new_count": int(meta.get("new_count") or 0),
            "random_count": int(meta.get("random_count") or 0),
            "stale_count": int(meta.get("stale_count") or 0),
            "last_refresh_utc": meta.get("last_refresh_utc"),
            "providers": meta.get("providers") or [],
            "errors": meta.get("errors") or {},
        }
