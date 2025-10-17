# custom_components/network_scanner/__init__.py
from __future__ import annotations

from datetime import timedelta
from typing import Final, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import async_track_time_interval

from .const import DOMAIN
from .controller import ScanController

PLATFORMS: Final[list[Platform]] = [Platform.SENSOR, Platform.BUTTON]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    controller = ScanController(hass, entry)

    # Set up a lightweight scheduler to trigger auto-scans
    def _tick(_now) -> None:
        # Fire-and-forget; controller handles gating and concurrency
        hass.async_create_task(controller.maybe_auto_scan())

    unsub_interval: Callable[[], None] = async_track_time_interval(
        hass, _tick, timedelta(minutes=1)
    )

    # Kick once shortly after startup so first results appear without waiting a full interval
    hass.loop.call_soon_threadsafe(lambda: hass.async_create_task(controller.maybe_auto_scan()))

    # Keep references for unload
    hass.data[DOMAIN][entry.entry_id] = {
        "controller": controller,
        "entry": entry,
        "unsub_interval": unsub_interval,
    }

    # Forward to platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Reload on options change (recreates controller cleanly)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    stored = hass.data[DOMAIN].get(entry.entry_id, {})
    # Stop the interval ticker first
    unsub = stored.get("unsub_interval")
    if callable(unsub):
        unsub()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
