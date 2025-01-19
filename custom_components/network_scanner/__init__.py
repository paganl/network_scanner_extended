"""The Network Scanner integration."""
from __future__ import annotations

import logging
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform, ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import (
    DOMAIN,
    SERVICE_START_SCAN,
    EVENT_SCAN_STARTED,
    EVENT_SCAN_COMPLETED,
)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]

_LOGGER = logging.getLogger(__name__)

SERVICE_SCHEMA = vol.Schema({
    vol.Optional(ATTR_ENTITY_ID): cv.entity_id,
})

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema({
            vol.Optional("ip_range"): cv.string,
        })
    },
    extra=vol.ALLOW_EXTRA,
)

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the Network Scanner component."""
    _LOGGER.debug("Setting up Network Scanner integration")
    hass.data.setdefault(DOMAIN, {})

    if DOMAIN in config:
        hass.data[DOMAIN].update(config[DOMAIN])

    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Network Scanner from a config entry."""
    _LOGGER.debug("Setting up Network Scanner config entry")
    
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {}
    hass.data[DOMAIN]["entities"] = []

    async def handle_start_scan(call: ServiceCall) -> None:
        """Handle the manual scan service call."""
        try:
            entity_id = call.data.get(ATTR_ENTITY_ID)
            hass.bus.async_fire(EVENT_SCAN_STARTED)
            
            if entity_id:
                await hass.services.async_call(
                    "homeassistant",
                    "update_entity",
                    {ATTR_ENTITY_ID: entity_id}
                )
            else:
                entities = hass.data[DOMAIN].get("entities", [])
                for entity in entities:
                    await entity.async_update()
                    
            hass.bus.async_fire(EVENT_SCAN_COMPLETED)
            
        except Exception as err:
            _LOGGER.error("Error during manual scan: %s", str(err))
            hass.bus.async_fire(EVENT_SCAN_COMPLETED)

    hass.services.async_register(
        DOMAIN,
        SERVICE_START_SCAN,
        handle_start_scan,
        schema=SERVICE_SCHEMA,
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(
        entry.add_update_listener(async_reload_entry)
    )

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.debug("Unloading Network Scanner config entry")
    
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        if "entities" in hass.data[DOMAIN]:
            hass.data[DOMAIN].pop("entities")
        
        if not hass.data[DOMAIN]:
            hass.data.pop(DOMAIN)

    return unload_ok

async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
