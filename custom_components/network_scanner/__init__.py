from __future__ import annotations
from typing import Final
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry

from .const import DOMAIN
from .controller import ScanController

PLATFORMS: Final = ["sensor", "button"]

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    controller = ScanController(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = {"controller": controller}

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Reconfigure controller on options change
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True

async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    hass.data[DOMAIN][entry.entry_id]["controller"].apply_entry(entry)
    await hass.config_entries.async_reload(entry.entry_id)

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
