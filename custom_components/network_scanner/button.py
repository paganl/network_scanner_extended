# custom_components/network_scanner_extended/button.py
from __future__ import annotations
import inspect
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN
from .controller import ScanController


class NetworkScannerRunScanButton(ButtonEntity):
    _attr_name = "Network Scanner: Run Scan Now"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:radar"

    def __init__(self, controller: ScanController, entry: ConfigEntry) -> None:
        self._ctl = controller
        self._entry = entry

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._entry.entry_id}_run_scan"

    async def async_press(self) -> None:
        # Supports both async and sync controller.scan_now()
        if hasattr(self._ctl, "scan_now"):
            if inspect.iscoroutinefunction(self._ctl.scan_now):
                await self._ctl.scan_now()
            else:
                await self.hass.async_add_executor_job(self._ctl.scan_now)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    controller: ScanController = hass.data[DOMAIN][entry.entry_id]["controller"]
    async_add_entities([NetworkScannerRunScanButton(controller, entry)], False)
