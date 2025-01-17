from .const import DOMAIN

async def async_setup(hass, config):
    """Set up the Network Scanner component from YAML (if any)."""
    hass.data[DOMAIN] = config.get(DOMAIN, {})
    return True

async def async_setup_entry(hass, config_entry):
    """Set up Network Scanner from a config entry."""
    # Forward this config entry to the sensor and binary_sensor platforms
    await hass.config_entries.async_forward_entry_setups(config_entry, ["sensor", "binary_sensor"])
    return True

async def async_unload_entry(hass, config_entry):
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_forward_entry_unload(config_entry, "sensor")
    unload_ok = unload_ok and await hass.config_entries.async_forward_entry_unload(config_entry, "binary_sensor")
    return unload_ok
