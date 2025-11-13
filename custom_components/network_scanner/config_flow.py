"""Config and options flow for the Network Scanner integration."""

from __future__ import annotations
from typing import Any, Dict, Optional
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import (
    DOMAIN, DEFAULT_OPTIONS,
    CONF_PROVIDER, CONF_URL, CONF_OPNSENSE_URL, CONF_UNIFI_URL,
    CONF_KEY, CONF_SECRET, CONF_NAME, CONF_PASSWORD, CONF_TOKEN,
    CONF_VERIFY_SSL, CONF_INTERVAL_MIN,
)

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        if user_input is not None:
            prov = user_input.get(CONF_PROVIDER, "opnsense")
            # Build a stable unique_id so you can add multiple entries
            if prov == "opnsense_unifi":
                uid = f"{prov}:{(user_input.get(CONF_OPNSENSE_URL,'') or user_input.get(CONF_URL,'')).rstrip('/')}" \
                      f"|{(user_input.get(CONF_UNIFI_URL,'') or user_input.get(CONF_URL,'')).rstrip('/')}"
            else:
                uid = f"{prov}:{(user_input.get(CONF_URL,'') or user_input.get(CONF_OPNSENSE_URL,'') or user_input.get(CONF_UNIFI_URL,'')).rstrip('/')}"
            if uid:
                await self.async_set_unique_id(uid)
                self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=f"Network Scanner ({prov})",
                data={}, options=user_input,
            )

        o = DEFAULT_OPTIONS
        schema = vol.Schema({
            vol.Required(CONF_PROVIDER, default=o[CONF_PROVIDER]): vol.In(["opnsense","unifi","adguard","opnsense_unifi"]),
            # Generic URL remains for backward-compat; specialised URLs for the combo provider
            vol.Optional(CONF_URL, default=o[CONF_URL]): str,
            vol.Optional(CONF_OPNSENSE_URL, default=o[CONF_OPNSENSE_URL]): str,
            vol.Optional(CONF_UNIFI_URL, default=o[CONF_UNIFI_URL]): str,

            vol.Optional(CONF_KEY, default=o[CONF_KEY]): str,
            vol.Optional(CONF_SECRET, default=o[CONF_SECRET]): str,
            vol.Optional(CONF_NAME, default=o[CONF_NAME]): str,
            vol.Optional(CONF_PASSWORD, default=o[CONF_PASSWORD]): str,
            vol.Optional(CONF_TOKEN, default=o[CONF_TOKEN]): str,

            vol.Required(CONF_VERIFY_SSL, default=o[CONF_VERIFY_SSL]): bool,
            vol.Required(CONF_INTERVAL_MIN, default=o[CONF_INTERVAL_MIN]): int,
        })
        return self.async_show_form(step_id="user", data_schema=schema)

    @staticmethod
    def async_get_options_flow(config_entry):
        return OptionsFlowHandler(config_entry)

class OptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, entry): self.entry = entry

    async def async_step_init(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        o = {**DEFAULT_OPTIONS, **self.entry.options}
        schema = vol.Schema({
            vol.Required(CONF_PROVIDER, default=o.get(CONF_PROVIDER,"opnsense")): vol.In(["opnsense","unifi","adguard","opnsense_unifi"]),
            vol.Optional(CONF_URL, default=o.get(CONF_URL,"")): str,
            vol.Optional(CONF_OPNSENSE_URL, default=o.get(CONF_OPNSENSE_URL,"")): str,
            vol.Optional(CONF_UNIFI_URL, default=o.get(CONF_UNIFI_URL,"")): str,

            vol.Optional(CONF_KEY, default=o.get(CONF_KEY,"")): str,
            vol.Optional(CONF_SECRET, default=o.get(CONF_SECRET,"")): str,
            vol.Optional(CONF_NAME, default=o.get(CONF_NAME,"")): str,
            vol.Optional(CONF_PASSWORD, default=o.get(CONF_PASSWORD,"")): str,
            vol.Optional(CONF_TOKEN, default=o.get(CONF_TOKEN,"")): str,

            vol.Required(CONF_VERIFY_SSL, default=o.get(CONF_VERIFY_SSL, False)): bool,
            vol.Required(CONF_INTERVAL_MIN, default=o.get(CONF_INTERVAL_MIN, 3)): int,
        })
        return self.async_show_form(step_id="init", data_schema=schema)
