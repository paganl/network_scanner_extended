# custom_components/network_scanner/__init__.py
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import async_track_time_interval

from .const import DOMAIN
from .controller import ScanController

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BUTTON]
SCAN_TICK = timedelta(seconds=30)  # check interval; controller self-gates by scan_interval


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    # YAML setup not used; just ensure domain bucket exists.
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    controller = ScanController(hass, entry)

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "controller": controller,
        "unsub_tick": None,
        "update_unsub": None,
    }

    # Forward to platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Periodic tick: async, runs on HA loop, no thread hops, no async_create_task-from-thread
    async def _tick(now) -> None:
        await controller.maybe_auto_scan()

    unsub_tick = async_track_time_interval(hass, _tick, SCAN_TICK)
    hass.data[DOMAIN][entry.entry_id]["unsub_tick"] = unsub_tick
    entry.async_on_unload(unsub_tick)

    # Apply changed options without full reload
    async def _on_options_updated(hass_: HomeAssistant, updated: ConfigEntry) -> None:
        controller.apply_entry(updated)
        _LOGGER.debug("network_scanner: options applied to controller")

    update_unsub = entry.add_update_listener(_on_options_updated)
    hass.data[DOMAIN][entry.entry_id]["update_unsub"] = update_unsub
    entry.async_on_unload(update_unsub)

    _LOGGER.debug("network_scanner: setup complete for %s", entry.entry_id)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
        if data:
            # entry.async_on_unload already cleans these up; this is belt-and-braces
            if data.get("unsub_tick"):
                try:
                    data["unsub_tick"]()
                except Exception:
                    pass
            if data.get("update_unsub"):
                try:
                    data["update_unsub"]()
                except Exception:
                    pass
        if not hass.data.get(DOMAIN):
            hass.data.pop(DOMAIN, None)
    return ok
