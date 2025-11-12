
from __future__ import annotations

import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN
from .coordinator import async_setup_coordinator, async_unload_coordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.debug("Setting up %s entry %s", DOMAIN, entry.entry_id)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    await async_setup_coordinator(hass, entry)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.debug("Unloading %s entry %s", DOMAIN, entry.entry_id)
    ok = await async_unload_coordinator(hass, entry)
    return ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    _LOGGER.debug("Reloading %s entry %s", DOMAIN, entry.entry_id)
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
