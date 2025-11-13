"""Set up the Network Scanner integration.

This module initialises the data coordinator and registers services
when Home Assistant loads a config entry for the integration.  It
also handles unloading and reloading entries in response to option
changes.  The logic here relies on the ``NetworkScannerCoordinator``
defined in ``coordinator.py`` to perform periodic updates.
"""

from __future__ import annotations
import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.const import Platform

from .const import DOMAIN
from .coordinator import async_setup_coordinator, async_unload_coordinator

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.SENSOR]

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    await async_setup_coordinator(hass, entry)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    ok = await async_unload_coordinator(hass, entry) and ok
    return ok

async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
