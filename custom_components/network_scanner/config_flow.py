"""Config and options flow for the Network Scanner integration."""

from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback

from .const import (
    DOMAIN,
    CONF_PROVIDER,
    CONF_URL,
    CONF_API_KEY,
    CONF_API_SECRET,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_VERIFY_SSL,
    CONF_INTERVAL,
    PROVIDERS,
    DEFAULT_INTERVAL,
)


class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Network Scanner."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, str] | None = None):  # type: ignore[type-arg]
        """Handle the initial step of a user initiated flow."""
        if user_input is not None:
            # Create the config entry immediately.  Home Assistant will
            # subsequently call async_setup_entry in __init__.py.
            return self.async_create_entry(title=user_input[CONF_PROVIDER], data=user_input)

        # Build the form schema.  We provide defaults only for simple
        # values to avoid persisting stale credentials on re-runs.
        data_schema = vol.Schema(
            {
                vol.Required(CONF_PROVIDER, default=PROVIDERS[0]): vol.In(PROVIDERS),
                vol.Required(CONF_URL): str,
                vol.Optional(CONF_API_KEY): str,
                vol.Optional(CONF_API_SECRET): str,
                vol.Optional(CONF_USERNAME): str,
                vol.Optional(CONF_PASSWORD): str,
                vol.Optional(CONF_VERIFY_SSL, default=False): bool,
                vol.Optional(CONF_INTERVAL, default=DEFAULT_INTERVAL): vol.Coerce(int),
            }
        )
        return self.async_show_form(step_id="user", data_schema=data_schema)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        """Return the options flow handler."""
        return NetworkScannerOptionsFlow(config_entry)


class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    """Handle an options flow for Network Scanner."""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self.config_entry = entry

    async def async_step_init(self, user_input: dict[str, str] | None = None):  # type: ignore[type-arg]
        """Manage the network scanner options."""
        if user_input is not None:
            # Update the config entry options with user selections
            return self.async_create_entry(title="", data=user_input)

        # Merge current data and options to provide defaults
        current = {**self.config_entry.data, **(self.config_entry.options or {})}

        # Build the options schema with current values as defaults
        options_schema = vol.Schema(
            {
                vol.Required(CONF_PROVIDER, default=current.get(CONF_PROVIDER, PROVIDERS[0])): vol.In(PROVIDERS),
                vol.Required(CONF_URL, default=current.get(CONF_URL, "")): str,
                vol.Optional(CONF_API_KEY, default=current.get(CONF_API_KEY, "")): str,
                vol.Optional(CONF_API_SECRET, default=current.get(CONF_API_SECRET, "")): str,
                vol.Optional(CONF_USERNAME, default=current.get(CONF_USERNAME, "")): str,
                vol.Optional(CONF_PASSWORD, default=current.get(CONF_PASSWORD, "")): str,
                vol.Optional(CONF_VERIFY_SSL, default=current.get(CONF_VERIFY_SSL, False)): bool,
                vol.Optional(CONF_INTERVAL, default=current.get(CONF_INTERVAL, DEFAULT_INTERVAL)): vol.Coerce(int),
            }
        )
        return self.async_show_form(step_id="init", data_schema=options_schema)