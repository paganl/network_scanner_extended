# custom_components/network_scanner/button.py
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .controller import ScanController

class NetworkScannerScanNow(ButtonEntity):
    _attr_name = "Network Scanner Extended: Scan Now"
    _attr_icon = "mdi:radar"

    def __init__(self, controller: ScanController, entry: ConfigEntry) -> None:
        self._ctl = controller
        self._entry = entry
        self._attr_unique_id = f"{DOMAIN}_{entry.entry_id}_scan_now"

    async def async_press(self) -> None:
        await self._ctl.scan_now()   # <-- await the coroutine

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    controller: ScanController = hass.data[DOMAIN][entry.entry_id]["controller"]
    async_add_entities([NetworkScannerScanNow(controller, entry)], True)
