"""Set up the Network Scanner integration.

This module initialises the data coordinator and registers services
when Home Assistant loads a config entry for the integration.  It
also handles unloading and reloading entries in response to option
changes.  The logic here relies on the ``NetworkScannerCoordinator``
defined in ``coordinator.py`` to perform periodic updates.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import NetworkScannerCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[str] = ["sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Network Scanner from a config entry."""
    coordinator = NetworkScannerCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    # Expose a service to trigger a manual refresh
    async def _handle_refresh_service(call: Any) -> None:
        await coordinator.async_request_refresh()

    hass.services.async_register(DOMAIN, "refresh", _handle_refresh_service)

    # Forward the entry to platform(s)
    await hass.config_entries.async_forward_entry_setup(entry, "sensor")

    # Listen for option changes and reload the entry when they occur
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Remove coordinator
    coordinator: NetworkScannerCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
    await coordinator.async_remove()
    # Unload the platform(s)
    return await hass.config_entries.async_forward_entry_unload(entry, "sensor")


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry when options change."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)