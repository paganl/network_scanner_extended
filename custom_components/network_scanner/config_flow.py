# custom_components/network_scanner/config_flow.py
from __future__ import annotations
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from .const import (
    DOMAIN, DEFAULT_OPTIONS,
    CONF_PROVIDER, CONF_VERIFY_SSL, CONF_INTERVAL_MIN,
    CONF_OPNSENSE_URL, CONF_UNIFI_URL, CONF_ADGUARD_URL,
    CONF_KEY, CONF_SECRET,
    CONF_NAME, CONF_PASSWORD, CONF_TOKEN,
    CONF_AUTH_MODE, AUTH_MODE_TOKEN, AUTH_MODE_USERPASS,
)

PROVIDERS = ["opnsense", "unifi", "adguard", "opnsense_unifi"]

class NetworkScannerFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(
                title="Network Scanner",
                data={},
                options={**DEFAULT_OPTIONS, **user_input},
            )
        schema = vol.Schema({
            vol.Required(CONF_PROVIDER, default=DEFAULT_OPTIONS[CONF_PROVIDER]): vol.In(PROVIDERS),
            vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_OPTIONS[CONF_VERIFY_SSL]): bool,
            vol.Optional(CONF_INTERVAL_MIN, default=DEFAULT_OPTIONS[CONF_INTERVAL_MIN]): int,
        })
        return self.async_show_form(step_id="user", data_schema=schema)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return NetworkScannerOptionsFlow(config_entry)

class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self.entry = entry
        self._opts = {**DEFAULT_OPTIONS, **dict(entry.options)}

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            self._opts.update(user_input)
            prov = self._opts.get(CONF_PROVIDER, "opnsense")
            if prov == "opnsense":       return await self.async_step_opnsense()
            if prov == "unifi":          return await self.async_step_unifi()
            if prov == "adguard":        return await self.async_step_adguard()
            if prov == "opnsense_unifi": return await self.async_step_both()
            return await self._finish()

        schema = vol.Schema({
            vol.Required(CONF_PROVIDER, default=self._opts.get(CONF_PROVIDER, "opnsense")): vol.In(PROVIDERS),
            vol.Optional(CONF_VERIFY_SSL, default=self._opts.get(CONF_VERIFY_SSL, False)): bool,
            vol.Optional(CONF_INTERVAL_MIN, default=self._opts.get(CONF_INTERVAL_MIN, 3)): int,
        })
        return self.async_show_form(step_id="init", data_schema=schema)

    async def async_step_opnsense(self, user_input=None):
        if user_input is not None:
            self._opts.update(user_input)
            return await self._finish()
        schema = vol.Schema({
            vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
            vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
            vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
        })
        return self.async_show_form(step_id="opnsense", data_schema=schema)

    async def async_step_unifi(self, user_input=None):
        if user_input is not None:
            self._opts.update(user_input)
            if self._opts.get(CONF_AUTH_MODE, AUTH_MODE_USERPASS) == AUTH_MODE_TOKEN:
                self._opts.pop(CONF_NAME, None)
                self._opts.pop(CONF_PASSWORD, None)
            else:
                self._opts.pop(CONF_TOKEN, None)
            return await self._finish()
        schema = vol.Schema({
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Required(CONF_AUTH_MODE, default=self._opts.get(CONF_AUTH_MODE, AUTH_MODE_USERPASS)): vol.In([AUTH_MODE_TOKEN, AUTH_MODE_USERPASS]),
            vol.Optional(CONF_TOKEN, default=self._opts.get(CONF_TOKEN, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        })
        return self.async_show_form(step_id="unifi", data_schema=schema)

    async def async_step_adguard(self, user_input=None):
        if user_input is not None:
            self._opts.update(user_input)
            return await self._finish()
        schema = vol.Schema({
            vol.Required(CONF_ADGUARD_URL, default=self._opts.get(CONF_ADGUARD_URL, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        })
        return self.async_show_form(step_id="adguard", data_schema=schema)

    async def async_step_both(self, user_input=None):
        nxt = self._opts.pop("_both_next", "opnsense")
        if nxt == "opnsense":
            self._opts["_both_next"] = "unifi"
            return await self.async_step_opnsense()
        self._opts.pop("_both_next", None)
        return await self.async_step_unifi()

    async def _finish(self):
        return self.async_create_entry(title="", data=self._opts)
