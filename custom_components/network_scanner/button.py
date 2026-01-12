# custom_components/network_scanner/button.py
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN


class NetworkScannerScanNow(ButtonEntity):
    _attr_name = "Network Scanner: Scan Now"
    _attr_icon = "mdi:radar"
    _attr_has_entity_name = True

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry
        self._attr_unique_id = f"{DOMAIN}_{entry.entry_id}_scan_now"

    async def async_press(self) -> None:
        coordinator = self.hass.data[DOMAIN][self._entry.entry_id]
        await coordinator.async_request_refresh()


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    async_add_entities([NetworkScannerScanNow(hass, entry)], True)
