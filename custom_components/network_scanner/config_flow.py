"""Config flow for Network Scanner."""
import logging
import voluptuous as vol
from typing import Any, Dict, Optional

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, CONF_PRIVILEGED

_LOGGER = logging.getLogger(__name__)

class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Network Scanner."""

    VERSION = 1

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        """Handle the initial step."""
        errors: Dict[str, str] = {}

        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        if user_input is not None:
            try:
                # Clean up the input by removing empty MAC mappings
                cleaned_input = {k: v for k, v in user_input.items() if v not in (None, "")}
                return self.async_create_entry(
                    title="Network Scanner",
                    data=cleaned_input
                )
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.error("Unexpected exception: %s", err)
                errors["base"] = "unknown"

        # Prepare the schema
        data_schema = vol.Schema({
            vol.Required("ip_range", default="192.168.1.0/24"): str,
            vol.Optional(CONF_PRIVILEGED, default=False): bool,
        })

        # Add MAC mapping fields
        schema_dict = {}
        schema_dict[vol.Required("ip_range", default="192.168.1.0/24")] = str
        schema_dict[vol.Optional(CONF_PRIVILEGED, default=False)] = bool

        for i in range(1, 26):  # Start with 25 mapping fields
            schema_dict[vol.Optional(f"mac_mapping_{i}", default="")] = str

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(schema_dict),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for the Network Scanner integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Manage options."""
        errors: Dict[str, str] = {}

        if user_input is not None:
            # Clean up the input by removing empty MAC mappings
            cleaned_input = {k: v for k, v in user_input.items() if v not in (None, "")}
            return self.async_create_entry(title="", data=cleaned_input)

        # Prepare schema with current values
        options_schema = {}
        
        options_schema[vol.Required(
            "ip_range",
            default=self.config_entry.data.get("ip_range", "192.168.1.0/24")
        )] = str
        
        options_schema[vol.Optional(
            CONF_PRIVILEGED,
            default=self.config_entry.data.get(CONF_PRIVILEGED, False)
        )] = bool

        # Add MAC mapping fields with current values
        current_mappings = {
            k: v for k, v in self.config_entry.data.items()
            if k.startswith("mac_mapping_")
        }

        # Add existing mappings
        for key, value in current_mappings.items():
            options_schema[vol.Optional(key, default=value)] = str

        # Add a few extra empty mapping fields
        max_mapping = max(
            [int(k.split("_")[2]) for k in current_mappings.keys()]
            if current_mappings else [0]
        )
        
        for i in range(max_mapping + 1, max_mapping + 6):
            options_schema[vol.Optional(f"mac_mapping_{i}", default="")] = str

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(options_schema),
            errors=errors,
        )
