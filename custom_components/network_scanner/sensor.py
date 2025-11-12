"""Sensor platform for the Network Scanner integration."""

from __future__ import annotations

from typing import Any, Dict, List

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import NetworkScannerCoordinator


async def async_setup_entry(hass, entry, async_add_entities) -> None:
    """Set up the network scanner sensor from a config entry."""
    coordinator: NetworkScannerCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([NetworkScannerDevicesSensor(coordinator)])


class NetworkScannerDevicesSensor(CoordinatorEntity[NetworkScannerCoordinator], SensorEntity):
    """Sensor representing the count of network devices."""

    def __init__(self, coordinator: NetworkScannerCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_name = "Network Scanner Devices"
        self._attr_icon = "mdi:devices"

    @property
    def native_value(self) -> int:
        """Return the number of devices detected."""
        data = self.coordinator.data or []
        return len(data)

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        """Return additional attributes with the raw device list."""
        data: List[Dict[str, Any]] = self.coordinator.data or []
        return {"devices": data}