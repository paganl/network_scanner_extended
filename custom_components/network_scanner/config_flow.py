"""Config flow for Network Scanner."""
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.const import CONF_IP_ADDRESS
from .const import DOMAIN, CONF_PRIVILEGED

import logging

_LOGGER = logging.getLogger(__name__)

class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Network Scanner."""

    VERSION = 1
    
    async def async_step_user(self, user_input=None):
        """Manage the configurations from the user interface."""
        return await self.async_step_config(user_input)

    async def async_step_config(self, user_input=None):
        """Handle the configuration step."""
        errors = {}

        # Load data from configuration.yaml
        yaml_config = self.hass.data.get(DOMAIN, {})
        _LOGGER.debug("YAML Config: %s", yaml_config)

        # If this is a reconfiguration, get the existing entry
        existing_entry = None
        if self.context.get("source") == config_entries.SOURCE_REAUTH:
            existing_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        elif self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        if user_input is not None:
            # Clean up the input by removing empty MAC mappings
            cleaned_input = {k: v for k, v in user_input.items() if v not in (None, "")}
            
            if existing_entry:
                self.hass.config_entries.async_update_entry(
                    existing_entry,
                    data=cleaned_input
                )
                return self.async_abort(reason="reauth_successful")
            
            return self.async_create_entry(title="Network Scanner", data=cleaned_input)

        # Build the data schema
        data_schema_dict = {
            vol.Required(
                "ip_range",
                default=(existing_entry.data.get("ip_range", "") if existing_entry 
                        else yaml_config.get("ip_range", "192.168.1.0/24")),
                description={"suggested_value": yaml_config.get("ip_range", "192.168.1.0/24")}
            ): vol.Schema({
                "type": str,
                "description": "IP Range",
                "name": "IP Range"
            }),
            vol.Optional(
                CONF_PRIVILEGED,
                default=(existing_entry.data.get(CONF_PRIVILEGED, False) if existing_entry 
                        else yaml_config.get(CONF_PRIVILEGED, False)),
                description={"suggested_value": yaml_config.get(CONF_PRIVILEGED, False)}
            ): vol.Schema({
                "type": bool,
                "description": "Privileged mode (for use in Docker)",
                "name": "Privileged mode (for use in Docker)"
            }),
        }

        # Add MAC mappings with values from existing entry or YAML
        for i in range(1, 26):  # Ensure at least 25 entries
            key = f"mac_mapping_{i}"
            
            # Try to get existing value first, then YAML value
            if existing_entry and key in existing_entry.data:
                suggested_value = existing_entry.data[key]
            else:
                suggested_value = yaml_config.get(key, "")
            
            data_schema_dict[vol.Optional(
                key,
                description={
                    "suggested_value": suggested_value,
                    "name": f"MAC Mapping {i}",
                    "description": "Format: MAC;Name;Type"
                }
            )] = str

        # Continue to add more mappings if available in existing entry or YAML
        i = 26
        while True:
            key = f"mac_mapping_{i}"
            has_existing = existing_entry and key in existing_entry.data
            has_yaml = key in yaml_config
            
            if not has_existing and not has_yaml:
                break
                
            suggested_value = ""
            if has_existing:
                suggested_value = existing_entry.data[key]
            elif has_yaml:
                suggested_value = yaml_config[key]
                
            data_schema_dict[vol.Optional(
                key,
                description={
                    "suggested_value": suggested_value,
                    "name": f"MAC Mapping {i}",
                    "description": "Format: MAC;Name;Type"
                }
            )] = str
            i += 1

        return self.async_show_form(
            step_id="config",
            data_schema=vol.Schema(data_schema_dict),
            errors=errors,
            description_placeholders={
                "description": "Configure network scanner settings and MAC mappings"
            }
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for the network scanner."""

    def __init__(self, config_entry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Manage options."""
        if user_input is not None:
            cleaned_input = {k: v for k, v in user_input.items() if v not in (None, "")}
            return self.async_create_entry(title="", data=cleaned_input)

        # Build options schema using current values
        options_schema = {
            vol.Required(
                "ip_range",
                default=self.config_entry.data.get("ip_range", "192.168.1.0/24")
            ): vol.Schema({
                "type": str,
                "description": "IP Range",
                "name": "IP Range"
            }),
            vol.Optional(
                CONF_PRIVILEGED,
                default=self.config_entry.data.get(CONF_PRIVILEGED, False)
            ): vol.Schema({
                "type": bool,
                "description": "Privileged mode (for use in Docker)",
                "name": "Privileged mode (for use in Docker)"
            }),
        }

        # Add MAC mapping fields with current values
        for key, value in self.config_entry.data.items():
            if key.startswith("mac_mapping_"):
                mapping_num = key.split("_")[2]
                options_schema[vol.Optional(
                    key,
                    default=value,
                    description={
                        "name": f"MAC Mapping {mapping_num}",
                        "description": "Format: MAC;Name;Type"
                    }
                )] = str

        # Add a few empty MAC mapping fields for new entries
        current_max = max(
            [int(k.split("_")[2]) for k in self.config_entry.data.keys() 
             if k.startswith("mac_mapping_")] + [0]
        )
        
        for i in range(current_max + 1, current_max + 6):
            options_schema[vol.Optional(
                f"mac_mapping_{i}",
                description={
                    "name": f"MAC Mapping {i}",
                    "description": "Format: MAC;Name;Type"
                }
            )] = str

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(options_schema),
            description_placeholders={
                "description": "Modify network scanner settings and MAC mappings"
            }
        )
