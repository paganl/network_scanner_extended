# custom_components/network_scanner/config_flow.py
from __future__ import annotations

from typing import Any, Dict
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

from .const import (
    DOMAIN,
    # provider & URLs
    CONF_PROVIDER,
    PROVIDER_OPNSENSE,
    PROVIDER_UNIFI,
    PROVIDER_ADGUARD,
    PROVIDER_OPNSENSE_UNIFI,
    CONF_OPNSENSE_URL,
    CONF_UNIFI_URL,
    CONF_ADGUARD_URL,
    # auth + creds
    CONF_AUTH_MODE,
    AUTH_MODE_PASSWORD,
    AUTH_MODE_TOKEN,
    CONF_KEY,
    CONF_SECRET,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_TOKEN,
    # common
    CONF_VERIFY_SSL,
    CONF_INTERVAL_MIN,
    DEFAULT_OPTIONS,
)

PROVIDER_CHOICES = [
    PROVIDER_OPNSENSE,
    PROVIDER_UNIFI,
    PROVIDER_ADGUARD,
    PROVIDER_OPNSENSE_UNIFI,
]

AUTH_MODE_CHOICES = [AUTH_MODE_PASSWORD, AUTH_MODE_TOKEN]


class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Network Scanner."""

    VERSION = 1

    def __init__(self) -> None:
        self._opts: Dict[str, Any] = dict(DEFAULT_OPTIONS)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return NetworkScannerOptionsFlow(config_entry)

    async def async_step_user(self, user_input: Dict[str, Any] | None = None):
        """Step 1: choose provider + common options."""
        if user_input is not None:
            self._opts[CONF_PROVIDER] = user_input[CONF_PROVIDER]
            self._opts[CONF_VERIFY_SSL] = user_input.get(CONF_VERIFY_SSL, False)
            self._opts[CONF_INTERVAL_MIN] = max(1, int(user_input.get(CONF_INTERVAL_MIN, 3)))

            prov = self._opts[CONF_PROVIDER]
            if prov == PROVIDER_OPNSENSE:
                return await self.async_step_opnsense()
            if prov == PROVIDER_UNIFI:
                return await self.async_step_unifi()
            if prov == PROVIDER_ADGUARD:
                return await self.async_step_adguard()
            if prov == PROVIDER_OPNSENSE_UNIFI:
                return await self.async_step_opnsense_unifi()

        schema = vol.Schema({
            vol.Required(CONF_PROVIDER, default=self._opts.get(CONF_PROVIDER, PROVIDER_OPNSENSE)):
                vol.In(PROVIDER_CHOICES),
            vol.Optional(CONF_VERIFY_SSL, default=self._opts.get(CONF_VERIFY_SSL, False)): bool,
            vol.Optional(CONF_INTERVAL_MIN, default=self._opts.get(CONF_INTERVAL_MIN, 3)): int,
        })
        return self.async_show_form(step_id="user", data_schema=schema)

    # ----- Provider-specific steps -----

    async def async_step_opnsense(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_OPNSENSE_URL] = user_input[CONF_OPNSENSE_URL].rstrip("/")
            self._opts[CONF_KEY] = user_input.get(CONF_KEY, "")
            self._opts[CONF_SECRET] = user_input.get(CONF_SECRET, "")
            return await self._finish()

        schema = vol.Schema({
            vol.Required(CONF_OPNSENSE_URL): str,
            vol.Required(CONF_KEY): str,
            vol.Required(CONF_SECRET): str,
        })
        return self.async_show_form(step_id="opnsense", data_schema=schema)

    async def async_step_unifi(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_UNIFI_URL] = user_input[CONF_UNIFI_URL].rstrip("/")
            self._opts[CONF_AUTH_MODE] = user_input[CONF_AUTH_MODE]
            if self._opts[CONF_AUTH_MODE] == AUTH_MODE_TOKEN:
                self._opts[CONF_TOKEN] = user_input.get(CONF_TOKEN, "")
                self._opts[CONF_NAME] = ""
                self._opts[CONF_PASSWORD] = ""
            else:
                self._opts[CONF_NAME] = user_input.get(CONF_NAME, "")
                self._opts[CONF_PASSWORD] = user_input.get(CONF_PASSWORD, "")
                self._opts[CONF_TOKEN] = ""
            return await self._finish()

        # present both variants; we’ll validate minimal requirements
        schema = vol.Schema({
            vol.Required(CONF_UNIFI_URL): str,
            vol.Required(CONF_AUTH_MODE, default=AUTH_MODE_TOKEN): vol.In(AUTH_MODE_CHOICES),
            vol.Optional(CONF_TOKEN, default=""): str,
            vol.Optional(CONF_NAME, default=""): str,
            vol.Optional(CONF_PASSWORD, default=""): str,
        })
        return self.async_show_form(step_id="unifi", data_schema=schema)

    async def async_step_adguard(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_ADGUARD_URL] = user_input[CONF_ADGUARD_URL].rstrip("/")
            self._opts[CONF_NAME] = user_input.get(CONF_NAME, "admin")
            self._opts[CONF_PASSWORD] = user_input.get(CONF_PASSWORD, "")
            return await self._finish()

        schema = vol.Schema({
            vol.Required(CONF_ADGUARD_URL): str,
            vol.Optional(CONF_NAME, default="admin"): str,
            vol.Optional(CONF_PASSWORD, default=""): str,
        })
        return self.async_show_form(step_id="adguard", data_schema=schema)

    async def async_step_opnsense_unifi(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            # OPNsense
            self._opts[CONF_OPNSENSE_URL] = user_input[CONF_OPNSENSE_URL].rstrip("/")
            self._opts[CONF_KEY] = user_input.get(CONF_KEY, "")
            self._opts[CONF_SECRET] = user_input.get(CONF_SECRET, "")
            # UniFi
            self._opts[CONF_UNIFI_URL] = user_input[CONF_UNIFI_URL].rstrip("/")
            self._opts[CONF_AUTH_MODE] = user_input[CONF_AUTH_MODE]
            if self._opts[CONF_AUTH_MODE] == AUTH_MODE_TOKEN:
                self._opts[CONF_TOKEN] = user_input.get(CONF_TOKEN, "")
                self._opts[CONF_NAME] = ""
                self._opts[CONF_PASSWORD] = ""
            else:
                self._opts[CONF_NAME] = user_input.get(CONF_NAME, "")
                self._opts[CONF_PASSWORD] = user_input.get(CONF_PASSWORD, "")
                self._opts[CONF_TOKEN] = ""
            return await self._finish()

        schema = vol.Schema({
            # OPNsense
            vol.Required(CONF_OPNSENSE_URL): str,
            vol.Required(CONF_KEY): str,
            vol.Required(CONF_SECRET): str,
            # UniFi
            vol.Required(CONF_UNIFI_URL): str,
            vol.Required(CONF_AUTH_MODE, default=AUTH_MODE_TOKEN): vol.In(AUTH_MODE_CHOICES),
            vol.Optional(CONF_TOKEN, default=""): str,
            vol.Optional(CONF_NAME, default=""): str,
            vol.Optional(CONF_PASSWORD, default=""): str,
        })
        return self.async_show_form(step_id="opnsense_unifi", data_schema=schema)

    async def _finish(self):
        # Single entry; make re-adding idempotent
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title="Network Scanner", data={}, options=self._opts)


class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    """Options flow mirrors initial setup."""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry = entry
        self._opts: Dict[str, Any] = dict(entry.options or DEFAULT_OPTIONS)

    async def async_step_init(self, user_input: Dict[str, Any] | None = None):
        """Entry point for options."""
        return await self.async_step_user(user_input)

    async def async_step_user(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_PROVIDER] = user_input[CONF_PROVIDER]
            self._opts[CONF_VERIFY_SSL] = user_input.get(CONF_VERIFY_SSL, False)
            self._opts[CONF_INTERVAL_MIN] = max(1, int(user_input.get(CONF_INTERVAL_MIN, 3)))
            prov = self._opts[CONF_PROVIDER]
            if prov == PROVIDER_OPNSENSE:
                return await self.async_step_opnsense()
            if prov == PROVIDER_UNIFI:
                return await self.async_step_unifi()
            if prov == PROVIDER_ADGUARD:
                return await self.async_step_adguard()
            if prov == PROVIDER_OPNSENSE_UNIFI:
                return await self.async_step_opnsense_unifi()

        schema = vol.Schema({
            vol.Required(CONF_PROVIDER, default=self._opts.get(CONF_PROVIDER, PROVIDER_OPNSENSE)):
                vol.In(PROVIDER_CHOICES),
            vol.Optional(CONF_VERIFY_SSL, default=self._opts.get(CONF_VERIFY_SSL, False)): bool,
            vol.Optional(CONF_INTERVAL_MIN, default=self._opts.get(CONF_INTERVAL_MIN, 3)): int,
        })
        return self.async_show_form(step_id="user", data_schema=schema)

    async def async_step_opnsense(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_OPNSENSE_URL] = user_input[CONF_OPNSENSE_URL].rstrip("/")
            self._opts[CONF_KEY] = user_input.get(CONF_KEY, "")
            self._opts[CONF_SECRET] = user_input.get(CONF_SECRET, "")
            return await self._finish()
        schema = vol.Schema({
            vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
            vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
            vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
        })
        return self.async_show_form(step_id="opnsense", data_schema=schema)

    async def async_step_unifi(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_UNIFI_URL] = user_input[CONF_UNIFI_URL].rstrip("/")
            self._opts[CONF_AUTH_MODE] = user_input[CONF_AUTH_MODE]
            if self._opts[CONF_AUTH_MODE] == AUTH_MODE_TOKEN:
                self._opts[CONF_TOKEN] = user_input.get(CONF_TOKEN, "")
                self._opts[CONF_NAME] = ""
                self._opts[CONF_PASSWORD] = ""
            else:
                self._opts[CONF_NAME] = user_input.get(CONF_NAME, "")
                self._opts[CONF_PASSWORD] = user_input.get(CONF_PASSWORD, "")
                self._opts[CONF_TOKEN] = ""
            return await self._finish()

        schema = vol.Schema({
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Required(CONF_AUTH_MODE, default=self._opts.get(CONF_AUTH_MODE, AUTH_MODE_TOKEN)):
                vol.In(AUTH_MODE_CHOICES),
            vol.Optional(CONF_TOKEN, default=self._opts.get(CONF_TOKEN, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        })
        return self.async_show_form(step_id="unifi", data_schema=schema)

    async def async_step_adguard(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_ADGUARD_URL] = user_input[CONF_ADGUARD_URL].rstrip("/")
            self._opts[CONF_NAME] = user_input.get(CONF_NAME, "admin")
            self._opts[CONF_PASSWORD] = user_input.get(CONF_PASSWORD, "")
            return await self._finish()

        schema = vol.Schema({
            vol.Required(CONF_ADGUARD_URL, default=self._opts.get(CONF_ADGUARD_URL, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "admin")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        })
        return self.async_show_form(step_id="adguard", data_schema=schema)

    async def async_step_opnsense_unifi(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            # OPNsense
            self._opts[CONF_OPNSENSE_URL] = user_input[CONF_OPNSENSE_URL].rstrip("/")
            self._opts[CONF_KEY] = user_input.get(CONF_KEY, "")
            self._opts[CONF_SECRET] = user_input.get(CONF_SECRET, "")
            # UniFi
            self._opts[CONF_UNIFI_URL] = user_input[CONF_UNIFI_URL].rstrip("/")
            self._opts[CONF_AUTH_MODE] = user_input[CONF_AUTH_MODE]
            if self._opts[CONF_AUTH_MODE] == AUTH_MODE_TOKEN:
                self._opts[CONF_TOKEN] = user_input.get(CONF_TOKEN, "")
                self._opts[CONF_NAME] = ""
                self._opts[CONF_PASSWORD] = ""
            else:
                self._opts[CONF_NAME] = user_input.get(CONF_NAME, "")
                self._opts[CONF_PASSWORD] = user_input.get(CONF_PASSWORD, "")
                self._opts[CONF_TOKEN] = ""
            return await self._finish()

        schema = vol.Schema({
            # OPNsense
            vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
            vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
            vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
            # UniFi
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Required(CONF_AUTH_MODE, default=self._opts.get(CONF_AUTH_MODE, AUTH_MODE_TOKEN)):
                vol.In(AUTH_MODE_CHOICES),
            vol.Optional(CONF_TOKEN, default=self._opts.get(CONF_TOKEN, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        })
        return self.async_show_form(step_id="opnsense_unifi", data_schema=schema)

    async def _finish(self):
        return self.async_create_entry(title="Network Scanner", data={}, options=self._opts)
