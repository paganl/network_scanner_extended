from __future__ import annotations
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .controller import ScanController

class NetworkScannerRunScanButton(ButtonEntity):
    _attr_name = "Network Scanner Extended: Run Scan"
    _attr_icon = "mdi:play-circle"

    def __init__(self, controller: ScanController, entry: ConfigEntry) -> None:
        self._ctl = controller
        self._entry = entry

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry.entry_id}_run_scan"

    async def async_press(self) -> None:
        await self._ctl.run_scan(force=True)
        # Entities will show the new state on next poll; proactively poke them:
        self.async_write_ha_state()

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    controller: ScanController = hass.data[DOMAIN][entry.entry_id]["controller"]
    async_add_entities([NetworkScannerRunScanButton(controller, entry)], False)
