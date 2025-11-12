
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import NetworkScannerCoordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coord: NetworkScannerCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([NetworkScannerSensor(coord)], True)


class NetworkScannerSensor(SensorEntity):
    _attr_name = "Network Scanner Devices"
    _attr_icon = "mdi:lan"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator: NetworkScannerCoordinator) -> None:
        self.coordinator = coordinator
        self._attr_unique_id = f"{coordinator.entry.entry_id}_devices"

    @property
    def available(self) -> bool:
        return True

    @property
    def native_value(self) -> int | None:
        data = self.coordinator.data or {}
        return data.get("count")

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        data = self.coordinator.data or {}
        return {"devices": data.get("devices", [])}

    async def async_update(self) -> None:
        await self.coordinator.async_request_refresh()
