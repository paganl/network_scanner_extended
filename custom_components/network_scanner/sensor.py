"""Sensor platform for Network Scanner (diagnostic + summary)."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities,
) -> None:
    """Set up sensors from a config entry."""
    blob = hass.data[DOMAIN].get(entry.entry_id)

    # Support both styles: stored as coordinator or as {"coordinator": coordinator, ...}
    coordinator = blob.get("coordinator") if isinstance(blob, dict) else blob

    if coordinator is None:
        _LOGGER.error("Sensor setup: no coordinator found for entry %s", entry.entry_id)
        return

    # Log what we actually have at setup time
    keys = list((coordinator.data or {}).keys()) if getattr(coordinator, "data", None) else []
    _LOGGER.debug("Sensor setup: coordinator.data keys at setup = %s", keys)

    async_add_entities(
        [
            NetworkScannerDeviceCountSensor(coordinator, entry),
        ],
        update_before_add=True,
    )


class NetworkScannerDeviceCountSensor(CoordinatorEntity, SensorEntity):
    """Shows the number of merged devices (proves coordinator -> entity path)."""

    _attr_icon = "mdi:lan"

    def __init__(self, coordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_name = "Network Scanner Devices"
        self._attr_unique_id = f"{entry.entry_id}:device_count"

    @property
    def native_value(self) -> int:
        data = self.coordinator.data or {}
        # Your coordinator returns "count"
        return int(data.get("count") or 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self.coordinator.data or {}
        summary = data.get("summary") or {}
        return {
            "last_refresh_utc": data.get("last_refresh_utc"),
            "vendors": summary.get("vendors"),
            "vlans": summary.get("vlans"),
            "sample": (data.get("flat") or [])[:10],  # first 10 rows for quick sanity
        }
