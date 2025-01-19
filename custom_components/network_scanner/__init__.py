"""The Network Scanner integration."""
import logging
import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv
from homeassistant.const import ATTR_ENTITY_ID

from .const import (
    DOMAIN,
    SERVICE_START_SCAN,
    EVENT_SCAN_STARTED,
    EVENT_SCAN_COMPLETED,
)

_LOGGER = logging.getLogger(__name__)

SERVICE_SCHEMA = vol.Schema({
    vol.Optional(ATTR_ENTITY_ID): cv.entity_id,
})

async def async_setup(hass: HomeAssistant, config):
    """Set up the Network Scanner component from YAML."""
    hass.data[DOMAIN] = config.get(DOMAIN, {})
    return True

async def async_setup_entry(hass: HomeAssistant, config_entry):
    """Set up Network Scanner from a config entry."""
    # Register service
    async def handle_start_scan(call: ServiceCall):
        """Handle the manual scan service call."""
        entity_id = call.data.get(ATTR_ENTITY_ID)
        
        # Fire scan started event
        hass.bus.async_fire(EVENT_SCAN_STARTED)
        
        if entity_id:
            # Trigger update for specific entity
            await hass.services.async_call(
                "homeassistant",
                "update_entity",
                {ATTR_ENTITY_ID: entity_id}
            )
        else:
            # Find all network scanner entities and update them
            entities = hass.data.get(DOMAIN, {}).get("entities", [])
            for entity in entities:
                await entity.async_update()
        
        # Fire scan completed event
        hass.bus.async_fire(EVENT_SCAN_COMPLETED)

    hass.services.async_register(
        DOMAIN,
        SERVICE_START_SCAN,
        handle_start_scan,
        schema=SERVICE_SCHEMA,
    )

    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(
        config_entry, ["sensor", "binary_sensor"]
    )
    
    # Initialize entities list in domain data
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    hass.data[DOMAIN]["entities"] = []
    
    return True

async def async_unload_entry(hass: HomeAssistant, config_entry):
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(
        config_entry, ["sensor", "binary_sensor"]
    )
    
    if unload_ok:
        if DOMAIN in hass.data:
            hass.data[DOMAIN].pop("entities", None)
    
    return unload_ok
