
from __future__ import annotations

from typing import Any, Dict, Optional

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import (
    DOMAIN,
    DEFAULT_OPTIONS,
    CONF_PROVIDER,
    CONF_URL,
    CONF_KEY,
    CONF_SECRET,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_CIDRS,
    CONF_INTERVAL_MIN,
    CONF_USE_NMAP,
    CONF_NMAP_ARGS,
    CONF_MAC_DIRECTORY,
)


def _cidrs_default(opts) -> str:
    val = opts.get(CONF_CIDRS, [])
    if isinstance(val, str):
        return val  # already a CSV string
    try:
        return ",".join(val)
    except Exception:
        return ""


def _cidrs_to_list(s: str) -> list[str]:
    if not s:
        return []
    return [c.strip() for c in s.split(",") if c.strip()]


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        if user_input is not None:
            await self.async_set_unique_id(DOMAIN)
            self._abort_if_unique_id_configured()
            user_input[CONF_CIDRS] = _cidrs_to_list(user_input.get(CONF_CIDRS, ""))
            return self.async_create_entry(title="Network Scanner", data={}, options=user_input)

        opts = DEFAULT_OPTIONS
        schema = vol.Schema({
            vol.Required(CONF_PROVIDER, default=opts[CONF_PROVIDER]): vol.In(["opnsense", "adguard"]),
            vol.Optional(CONF_URL, default=opts[CONF_URL]): str,
            vol.Optional(CONF_KEY, default=opts[CONF_KEY]): str,
            vol.Optional(CONF_SECRET, default=opts[CONF_SECRET]): str,
            vol.Optional(CONF_NAME, default=opts[CONF_NAME]): str,
            vol.Optional(CONF_PASSWORD, default=opts[CONF_PASSWORD]): str,
            vol.Required(CONF_CIDRS, default=_cidrs_default(opts)): str,
            vol.Required(CONF_INTERVAL_MIN, default=opts[CONF_INTERVAL_MIN]): int,
            vol.Required(CONF_USE_NMAP, default=opts[CONF_USE_NMAP]): bool,
            vol.Optional(CONF_NMAP_ARGS, default=opts[CONF_NMAP_ARGS]): str,
            vol.Optional(CONF_MAC_DIRECTORY, default=opts[CONF_MAC_DIRECTORY]): str,
        })
        return self.async_show_form(step_id="user", data_schema=schema)

    @staticmethod
    def async_get_options_flow(config_entry):
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, entry):
        self.entry = entry

    async def async_step_init(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        if user_input is not None:
            user_input[CONF_CIDRS] = _cidrs_to_list(user_input.get(CONF_CIDRS, ""))
            return self.async_create_entry(title="", data=user_input)

        opts = {**DEFAULT_OPTIONS, **self.entry.options}
        schema = vol.Schema({
            vol.Required(CONF_PROVIDER, default=opts[CONF_PROVIDER]): vol.In(["opnsense", "adguard"]),
            vol.Optional(CONF_URL, default=opts.get(CONF_URL, "")): str,
            vol.Optional(CONF_KEY, default=opts.get(CONF_KEY, "")): str,
            vol.Optional(CONF_SECRET, default=opts.get(CONF_SECRET, "")): str,
            vol.Optional(CONF_NAME, default=opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=opts.get(CONF_PASSWORD, "")): str,
            vol.Required(CONF_CIDRS, default=_cidrs_default(opts)): str,
            vol.Required(CONF_INTERVAL_MIN, default=opts.get(CONF_INTERVAL_MIN, 3)): int,
            vol.Required(CONF_USE_NMAP, default=opts.get(CONF_USE_NMAP, False)): bool,
            vol.Optional(CONF_NMAP_ARGS, default=opts.get(CONF_NMAP_ARGS, "-sn --max-retries 1 --host-timeout 5s")): str,
            vol.Optional(CONF_MAC_DIRECTORY, default=opts.get(CONF_MAC_DIRECTORY, "")): str,
        })
        return self.async_show_form(step_id="init", data_schema=schema)
