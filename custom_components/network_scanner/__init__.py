# custom_components/network_scanner/__init__.py
from __future__ import annotations
from typing import Final
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.event import async_track_time_interval

from .const import DOMAIN
from .controller import ScanController

PLATFORMS: Final = ["sensor", "button"]

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    controller = ScanController(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = {
        "controller": controller,
        "entry": entry,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # SAFE interval tick on HA loop, no async_create_task, no threads
    async def _tick(now) -> None:
        await controller.maybe_auto_scan()

    # Run a quick tick every 30s; controller gates internally by scan_interval
    unsub = async_track_time_interval(hass, _tick, timedelta(seconds=30))
    entry.async_on_unload(unsub)

    # Options change -> reload entry
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True

async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
