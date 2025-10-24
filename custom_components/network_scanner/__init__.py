# custom_components/network_scanner/__init__.py
from __future__ import annotations
from typing import Final
from datetime import timedelta

from homeassistant.core import HomeAssistant, callback
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
        "unsub_timer": None,
    }

    # schedule periodic auto-scan checks
    def _schedule():
        data = hass.data[DOMAIN][entry.entry_id]
        if data["unsub_timer"]:
            data["unsub_timer"]()
            data["unsub_timer"] = None
        # run check every 30s; controller enforces its own interval
        data["unsub_timer"] = async_track_time_interval(
            hass, lambda now: hass.async_create_task(controller.maybe_auto_scan()),
            timedelta(seconds=30),
        )

    _schedule()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    @callback
    def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
        # controller will read new options; reschedule timer
        controller.apply_entry(entry)
        _schedule()
        # reload platforms if you prefer; not strictly necessary now
        # hass.async_create_task(hass.config_entries.async_reload(entry.entry_id))

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = hass.data[DOMAIN].get(entry.entry_id)
    if data and data.get("unsub_timer"):
        data["unsub_timer"]()
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
