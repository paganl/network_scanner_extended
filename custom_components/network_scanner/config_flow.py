from __future__ import annotations

from typing import Any, Dict, List, Optional

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv

from .const import (
    DOMAIN,
    DEFAULT_OPTIONS,
    CONF_PROVIDERS,
    CONF_VERIFY_SSL,
    CONF_INTERVAL_MIN,
    PROVIDER_OPTIONS,
    PROVIDER_OPNSENSE,
    PROVIDER_UNIFI,
    PROVIDER_ADGUARD,
    # OPNsense
    CONF_OPNSENSE_URL, CONF_KEY, CONF_SECRET,
    # UniFi
    CONF_UNIFI_URL, CONF_UNIFI_TOKEN, CONF_UNIFI_USER, CONF_UNIFI_PASS, CONF_UNIFI_SITE,
    # AdGuard
    CONF_ADGUARD_URL, CONF_ADGUARD_USER, CONF_ADGUARD_PASS,
    # Directory
    CONF_MAC_DIRECTORY_JSON_URL, CONF_MAC_DIRECTORY_JSON_TEXT,
)


def _rstrip_url(v: Optional[str]) -> str:
    return (v or "").strip().rstrip("/")


class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._opts: Dict[str, Any] = dict(DEFAULT_OPTIONS)
        self._todo: List[str] = []

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return NetworkScannerOptionsFlow(config_entry)

    async def async_step_user(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}

        if user_input is not None:
            providers = user_input.get(CONF_PROVIDERS) or []
            providers = list(providers) if isinstance(providers, (list, set, tuple)) else [providers]
            providers = [p for p in providers if p in PROVIDER_OPTIONS]

            if not providers:
                errors["base"] = "no_provider_selected"
            else:
                self._opts[CONF_PROVIDERS] = providers
                self._opts[CONF_VERIFY_SSL] = bool(user_input.get(CONF_VERIFY_SSL, True))
                self._opts[CONF_INTERVAL_MIN] = max(1, int(user_input.get(CONF_INTERVAL_MIN, 3)))
                self._opts[CONF_MAC_DIRECTORY_JSON_URL] = (user_input.get(CONF_MAC_DIRECTORY_JSON_URL) or "").strip()
                self._opts[CONF_MAC_DIRECTORY_JSON_TEXT] = (user_input.get(CONF_MAC_DIRECTORY_JSON_TEXT) or "").strip()

                self._todo = providers[:]
                return await self._next_step()

        schema = vol.Schema({
            vol.Required(CONF_PROVIDERS, default=self._opts[CONF_PROVIDERS]): cv.multi_select({p: p for p in PROVIDER_OPTIONS}),
            vol.Optional(CONF_VERIFY_SSL, default=self._opts[CONF_VERIFY_SSL]): bool,
            vol.Optional(CONF_INTERVAL_MIN, default=self._opts[CONF_INTERVAL_MIN]): int,
            vol.Optional(CONF_MAC_DIRECTORY_JSON_URL, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_URL, "")): str,
            vol.Optional(CONF_MAC_DIRECTORY_JSON_TEXT, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_TEXT, "")): str,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def _next_step(self):
        if not self._todo:
            return await self._finish()

        prov = self._todo.pop(0)
        if prov == PROVIDER_OPNSENSE:
            return await self.async_step_opnsense()
        if prov == PROVIDER_UNIFI:
            return await self.async_step_unifi()
        if prov == PROVIDER_ADGUARD:
            return await self.async_step_adguard()

        return await self._next_step()

    async def async_step_opnsense(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            url = _rstrip_url(user_input.get(CONF_OPNSENSE_URL))
            key = (user_input.get(CONF_KEY) or "").strip()
            sec = (user_input.get(CONF_SECRET) or "").strip()
            if not url:
                errors["base"] = "opnsense_url_required"
            elif not key or not sec:
                errors["base"] = "opnsense_creds_required"
            else:
                self._opts[CONF_OPNSENSE_URL] = url
                self._opts[CONF_KEY] = key
                self._opts[CONF_SECRET] = sec
                return await self._next_step()

        schema = vol.Schema({
            vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
            vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
            vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
        })
        return self.async_show_form(step_id="opnsense", data_schema=schema, errors=errors)

    async def async_step_unifi(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            url = _rstrip_url(user_input.get(CONF_UNIFI_URL))
            token = (user_input.get(CONF_UNIFI_TOKEN) or "").strip()
            user = (user_input.get(CONF_UNIFI_USER) or "").strip()
            pwd = (user_input.get(CONF_UNIFI_PASS) or "").strip()
            site = (user_input.get(CONF_UNIFI_SITE) or "default").strip()

            if not url:
                errors["base"] = "unifi_url_required"
            elif not token and (not user or not pwd):
                errors["base"] = "unifi_auth_required"
            else:
                self._opts[CONF_UNIFI_URL] = url
                self._opts[CONF_UNIFI_TOKEN] = token
                self._opts[CONF_UNIFI_USER] = "" if token else user
                self._opts[CONF_UNIFI_PASS] = "" if token else pwd
                self._opts[CONF_UNIFI_SITE] = site or "default"
                return await self._next_step()

        schema = vol.Schema({
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Optional(CONF_UNIFI_TOKEN, default=self._opts.get(CONF_UNIFI_TOKEN, "")): str,
            vol.Optional(CONF_UNIFI_USER, default=self._opts.get(CONF_UNIFI_USER, "")): str,
            vol.Optional(CONF_UNIFI_PASS, default=self._opts.get(CONF_UNIFI_PASS, "")): str,
            vol.Optional(CONF_UNIFI_SITE, default=self._opts.get(CONF_UNIFI_SITE, "default")): str,
        })
        return self.async_show_form(step_id="unifi", data_schema=schema, errors=errors)

    async def async_step_adguard(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            url = _rstrip_url(user_input.get(CONF_ADGUARD_URL))
            user = (user_input.get(CONF_ADGUARD_USER) or "admin").strip()
            pwd = (user_input.get(CONF_ADGUARD_PASS) or "").strip()
            if not url:
                errors["base"] = "adguard_url_required"
            else:
                self._opts[CONF_ADGUARD_URL] = url
                self._opts[CONF_ADGUARD_USER] = user
                self._opts[CONF_ADGUARD_PASS] = pwd
                return await self._next_step()

        schema = vol.Schema({
            vol.Required(CONF_ADGUARD_URL, default=self._opts.get(CONF_ADGUARD_URL, "")): str,
            vol.Optional(CONF_ADGUARD_USER, default=self._opts.get(CONF_ADGUARD_USER, "admin")): str,
            vol.Optional(CONF_ADGUARD_PASS, default=self._opts.get(CONF_ADGUARD_PASS, "")): str,
        })
        return self.async_show_form(step_id="adguard", data_schema=schema, errors=errors)

    async def _finish(self):
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title="Network Scanner", data={}, options=self._opts)


class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry = entry
        self._opts: Dict[str, Any] = {**DEFAULT_OPTIONS, **(entry.options or {})}
        self._todo: List[str] = []

    async def async_step_init(self, user_input: Dict[str, Any] | None = None):
        return await self.async_step_user(user_input)

    async def async_step_user(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            providers = user_input.get(CONF_PROVIDERS) or []
            providers = list(providers) if isinstance(providers, (list, set, tuple)) else [providers]
            providers = [p for p in providers if p in PROVIDER_OPTIONS]
            if not providers:
                errors["base"] = "no_provider_selected"
            else:
                self._opts[CONF_PROVIDERS] = providers
                self._opts[CONF_VERIFY_SSL] = bool(user_input.get(CONF_VERIFY_SSL, True))
                self._opts[CONF_INTERVAL_MIN] = max(1, int(user_input.get(CONF_INTERVAL_MIN, 3)))
                self._opts[CONF_MAC_DIRECTORY_JSON_URL] = (user_input.get(CONF_MAC_DIRECTORY_JSON_URL) or "").strip()
                self._opts[CONF_MAC_DIRECTORY_JSON_TEXT] = (user_input.get(CONF_MAC_DIRECTORY_JSON_TEXT) or "").strip()

                self._todo = providers[:]
                return await self._next_step()

        schema = vol.Schema({
            vol.Required(CONF_PROVIDERS, default=self._opts[CONF_PROVIDERS]): cv.multi_select({p: p for p in PROVIDER_OPTIONS}),
            vol.Optional(CONF_VERIFY_SSL, default=self._opts[CONF_VERIFY_SSL]): bool,
            vol.Optional(CONF_INTERVAL_MIN, default=self._opts[CONF_INTERVAL_MIN]): int,
            vol.Optional(CONF_MAC_DIRECTORY_JSON_URL, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_URL, "")): str,
            vol.Optional(CONF_MAC_DIRECTORY_JSON_TEXT, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_TEXT, "")): str,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def _next_step(self):
        if not self._todo:
            return self.async_create_entry(title="", data=self._opts)

        prov = self._todo.pop(0)
        if prov == PROVIDER_OPNSENSE:
            return await self.async_step_opnsense()
        if prov == PROVIDER_UNIFI:
            return await self.async_step_unifi()
        if prov == PROVIDER_ADGUARD:
            return await self.async_step_adguard()
        return await self._next_step()

    async def async_step_opnsense(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_OPNSENSE_URL] = _rstrip_url(user_input.get(CONF_OPNSENSE_URL))
            self._opts[CONF_KEY] = (user_input.get(CONF_KEY) or "").strip()
            self._opts[CONF_SECRET] = (user_input.get(CONF_SECRET) or "").strip()
            return await self._next_step()

        schema = vol.Schema({
            vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
            vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
            vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
        })
        return self.async_show_form(step_id="opnsense", data_schema=schema)

    async def async_step_unifi(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_UNIFI_URL] = _rstrip_url(user_input.get(CONF_UNIFI_URL))
            self._opts[CONF_UNIFI_TOKEN] = (user_input.get(CONF_UNIFI_TOKEN) or "").strip()
            if self._opts[CONF_UNIFI_TOKEN]:
                self._opts[CONF_UNIFI_USER] = ""
                self._opts[CONF_UNIFI_PASS] = ""
            else:
                self._opts[CONF_UNIFI_USER] = (user_input.get(CONF_UNIFI_USER) or "").strip()
                self._opts[CONF_UNIFI_PASS] = (user_input.get(CONF_UNIFI_PASS) or "").strip()
            self._opts[CONF_UNIFI_SITE] = (user_input.get(CONF_UNIFI_SITE) or "default").strip()
            return await self._next_step()

        schema = vol.Schema({
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Optional(CONF_UNIFI_TOKEN, default=self._opts.get(CONF_UNIFI_TOKEN, "")): str,
            vol.Optional(CONF_UNIFI_USER, default=self._opts.get(CONF_UNIFI_USER, "")): str,
            vol.Optional(CONF_UNIFI_PASS, default=self._opts.get(CONF_UNIFI_PASS, "")): str,
            vol.Optional(CONF_UNIFI_SITE, default=self._opts.get(CONF_UNIFI_SITE, "default")): str,
        })
        return self.async_show_form(step_id="unifi", data_schema=schema)

    async def async_step_adguard(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_ADGUARD_URL] = _rstrip_url(user_input.get(CONF_ADGUARD_URL))
            self._opts[CONF_ADGUARD_USER] = (user_input.get(CONF_ADGUARD_USER) or "admin").strip()
            self._opts[CONF_ADGUARD_PASS] = (user_input.get(CONF_ADGUARD_PASS) or "").strip()
            return await self._next_step()

        schema = vol.Schema({
            vol.Required(CONF_ADGUARD_URL, default=self._opts.get(CONF_ADGUARD_URL, "")): str,
            vol.Optional(CONF_ADGUARD_USER, default=self._opts.get(CONF_ADGUARD_USER, "admin")): str,
            vol.Optional(CONF_ADGUARD_PASS, default=self._opts.get(CONF_ADGUARD_PASS, "")): str,
        })
        return self.async_show_form(step_id="adguard", data_schema=schema)
