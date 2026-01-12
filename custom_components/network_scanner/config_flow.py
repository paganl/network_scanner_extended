# custom_components/network_scanner/config_flow.py
from __future__ import annotations

from typing import Any, Dict, Optional

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback

from .const import (
    DOMAIN,
    DEFAULT_OPTIONS,
    # common
    CONF_SCAN_INTERVAL_MIN,
    CONF_VERIFY_SSL,
    CONF_PRESENCE_PROVIDER,
    PRESENCE_PROVIDER_OPTIONS,
    # opnsense
    CONF_OPNSENSE_URL,
    CONF_OPNSENSE_KEY,
    CONF_OPNSENSE_SECRET,
    CONF_OPNSENSE_INTERFACE,
    # adguard
    CONF_ADGUARD_URL,
    CONF_ADGUARD_USERNAME,
    CONF_ADGUARD_PASSWORD,
    # unifi
    CONF_UNIFI_ENABLED,
    CONF_UNIFI_URL,
    CONF_UNIFI_TOKEN,
    CONF_UNIFI_USERNAME,
    CONF_UNIFI_PASSWORD,
    CONF_UNIFI_SITE,
    # directory overlay
    CONF_MAC_DIRECTORY_JSON_URL,
    CONF_MAC_DIRECTORY_JSON_TEXT,
)


def _rstrip_url(v: Optional[str]) -> str:
    return (v or "").strip().rstrip("/")


class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._opts: Dict[str, Any] = dict(DEFAULT_OPTIONS)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return NetworkScannerOptionsFlow(config_entry)

    async def async_step_user(self, user_input: Dict[str, Any] | None = None):
        """Common step: interval + TLS + presence provider + optional UniFi + directory."""
        if user_input is not None:
            self._opts[CONF_SCAN_INTERVAL_MIN] = max(1, int(user_input.get(CONF_SCAN_INTERVAL_MIN, 3)))
            self._opts[CONF_VERIFY_SSL] = bool(user_input.get(CONF_VERIFY_SSL, False))
            self._opts[CONF_PRESENCE_PROVIDER] = user_input[CONF_PRESENCE_PROVIDER]

            self._opts[CONF_UNIFI_ENABLED] = bool(user_input.get(CONF_UNIFI_ENABLED, False))

            self._opts[CONF_MAC_DIRECTORY_JSON_URL] = (user_input.get(CONF_MAC_DIRECTORY_JSON_URL) or "").strip()
            self._opts[CONF_MAC_DIRECTORY_JSON_TEXT] = (user_input.get(CONF_MAC_DIRECTORY_JSON_TEXT) or "").strip()

            if self._opts[CONF_PRESENCE_PROVIDER] == "opnsense":
                return await self.async_step_opnsense()
            return await self.async_step_adguard()

        schema = vol.Schema(
            {
                vol.Optional(CONF_SCAN_INTERVAL_MIN, default=self._opts[CONF_SCAN_INTERVAL_MIN]): int,
                vol.Optional(CONF_VERIFY_SSL, default=self._opts[CONF_VERIFY_SSL]): bool,
                vol.Required(CONF_PRESENCE_PROVIDER, default=self._opts[CONF_PRESENCE_PROVIDER]): vol.In(PRESENCE_PROVIDER_OPTIONS),
                vol.Optional(CONF_UNIFI_ENABLED, default=self._opts[CONF_UNIFI_ENABLED]): bool,
                vol.Optional(CONF_MAC_DIRECTORY_JSON_URL, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_URL, "")): str,
                vol.Optional(CONF_MAC_DIRECTORY_JSON_TEXT, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_TEXT, "")): str,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema)

    async def async_step_opnsense(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            url = _rstrip_url(user_input.get(CONF_OPNSENSE_URL))
            key = (user_input.get(CONF_OPNSENSE_KEY) or "").strip()
            sec = (user_input.get(CONF_OPNSENSE_SECRET) or "").strip()
            iface = (user_input.get(CONF_OPNSENSE_INTERFACE) or "").strip()

            if not url:
                errors["base"] = "opnsense_url_required"
            elif not key or not sec:
                errors["base"] = "opnsense_creds_required"
            else:
                self._opts[CONF_OPNSENSE_URL] = url
                self._opts[CONF_OPNSENSE_KEY] = key
                self._opts[CONF_OPNSENSE_SECRET] = sec
                self._opts[CONF_OPNSENSE_INTERFACE] = iface

                if self._opts.get(CONF_UNIFI_ENABLED):
                    return await self.async_step_unifi()
                return await self._finish()

        schema = vol.Schema(
            {
                vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
                vol.Required(CONF_OPNSENSE_KEY, default=self._opts.get(CONF_OPNSENSE_KEY, "")): str,
                vol.Required(CONF_OPNSENSE_SECRET, default=self._opts.get(CONF_OPNSENSE_SECRET, "")): str,
                vol.Optional(CONF_OPNSENSE_INTERFACE, default=self._opts.get(CONF_OPNSENSE_INTERFACE, "")): str,
            }
        )
        return self.async_show_form(step_id="opnsense", data_schema=schema, errors=errors)

    async def async_step_adguard(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            url = _rstrip_url(user_input.get(CONF_ADGUARD_URL))
            user = (user_input.get(CONF_ADGUARD_USERNAME) or "").strip()
            pwd = (user_input.get(CONF_ADGUARD_PASSWORD) or "").strip()

            if not url:
                errors["base"] = "adguard_url_required"
            else:
                self._opts[CONF_ADGUARD_URL] = url
                self._opts[CONF_ADGUARD_USERNAME] = user
                self._opts[CONF_ADGUARD_PASSWORD] = pwd

                if self._opts.get(CONF_UNIFI_ENABLED):
                    return await self.async_step_unifi()
                return await self._finish()

        schema = vol.Schema(
            {
                vol.Required(CONF_ADGUARD_URL, default=self._opts.get(CONF_ADGUARD_URL, "")): str,
                vol.Optional(CONF_ADGUARD_USERNAME, default=self._opts.get(CONF_ADGUARD_USERNAME, "")): str,
                vol.Optional(CONF_ADGUARD_PASSWORD, default=self._opts.get(CONF_ADGUARD_PASSWORD, "")): str,
            }
        )
        return self.async_show_form(step_id="adguard", data_schema=schema, errors=errors)

    async def async_step_unifi(self, user_input: Dict[str, Any] | None = None):
        """UniFi enrichment step (token OR username+password)."""
        errors: Dict[str, str] = {}
        if user_input is not None:
            url = _rstrip_url(user_input.get(CONF_UNIFI_URL))
            token = (user_input.get(CONF_UNIFI_TOKEN) or "").strip()
            user = (user_input.get(CONF_UNIFI_USERNAME) or "").strip()
            pwd = (user_input.get(CONF_UNIFI_PASSWORD) or "").strip()
            site = (user_input.get(CONF_UNIFI_SITE) or "default").strip()

            if not url:
                errors["base"] = "unifi_url_required"
            elif not token and (not user or not pwd):
                errors["base"] = "unifi_auth_required"
            else:
                self._opts[CONF_UNIFI_URL] = url
                self._opts[CONF_UNIFI_TOKEN] = token
                self._opts[CONF_UNIFI_USERNAME] = "" if token else user
                self._opts[CONF_UNIFI_PASSWORD] = "" if token else pwd
                self._opts[CONF_UNIFI_SITE] = site
                return await self._finish()

        schema = vol.Schema(
            {
                vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
                vol.Optional(CONF_UNIFI_TOKEN, default=self._opts.get(CONF_UNIFI_TOKEN, "")): str,
                vol.Optional(CONF_UNIFI_USERNAME, default=self._opts.get(CONF_UNIFI_USERNAME, "")): str,
                vol.Optional(CONF_UNIFI_PASSWORD, default=self._opts.get(CONF_UNIFI_PASSWORD, "")): str,
                vol.Optional(CONF_UNIFI_SITE, default=self._opts.get(CONF_UNIFI_SITE, "default")): str,
            }
        )
        return self.async_show_form(step_id="unifi", data_schema=schema, errors=errors)

    async def _finish(self):
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title="Network Scanner", data=self._opts)


class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry = entry
        base = dict(entry.options or entry.data or {})
        self._opts: Dict[str, Any] = {**DEFAULT_OPTIONS, **base}

    async def async_step_init(self, user_input: Dict[str, Any] | None = None):
        return await self.async_step_user(user_input)

    async def async_step_user(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_SCAN_INTERVAL_MIN] = max(1, int(user_input.get(CONF_SCAN_INTERVAL_MIN, 3)))
            self._opts[CONF_VERIFY_SSL] = bool(user_input.get(CONF_VERIFY_SSL, False))
            self._opts[CONF_PRESENCE_PROVIDER] = user_input[CONF_PRESENCE_PROVIDER]
            self._opts[CONF_UNIFI_ENABLED] = bool(user_input.get(CONF_UNIFI_ENABLED, False))
            self._opts[CONF_MAC_DIRECTORY_JSON_URL] = (user_input.get(CONF_MAC_DIRECTORY_JSON_URL) or "").strip()
            self._opts[CONF_MAC_DIRECTORY_JSON_TEXT] = (user_input.get(CONF_MAC_DIRECTORY_JSON_TEXT) or "").strip()

            if self._opts[CONF_PRESENCE_PROVIDER] == "opnsense":
                return await self.async_step_opnsense()
            return await self.async_step_adguard()

        schema = vol.Schema(
            {
                vol.Optional(CONF_SCAN_INTERVAL_MIN, default=self._opts[CONF_SCAN_INTERVAL_MIN]): int,
                vol.Optional(CONF_VERIFY_SSL, default=self._opts[CONF_VERIFY_SSL]): bool,
                vol.Required(CONF_PRESENCE_PROVIDER, default=self._opts[CONF_PRESENCE_PROVIDER]): vol.In(PRESENCE_PROVIDER_OPTIONS),
                vol.Optional(CONF_UNIFI_ENABLED, default=self._opts[CONF_UNIFI_ENABLED]): bool,
                vol.Optional(CONF_MAC_DIRECTORY_JSON_URL, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_URL, "")): str,
                vol.Optional(CONF_MAC_DIRECTORY_JSON_TEXT, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_TEXT, "")): str,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema)

    async def async_step_opnsense(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_OPNSENSE_URL] = _rstrip_url(user_input.get(CONF_OPNSENSE_URL))
            self._opts[CONF_OPNSENSE_KEY] = (user_input.get(CONF_OPNSENSE_KEY) or "").strip()
            self._opts[CONF_OPNSENSE_SECRET] = (user_input.get(CONF_OPNSENSE_SECRET) or "").strip()
            self._opts[CONF_OPNSENSE_INTERFACE] = (user_input.get(CONF_OPNSENSE_INTERFACE) or "").strip()

            if self._opts.get(CONF_UNIFI_ENABLED):
                return await self.async_step_unifi()
            return self.async_create_entry(title="", data=self._opts)

        schema = vol.Schema(
            {
                vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
                vol.Required(CONF_OPNSENSE_KEY, default=self._opts.get(CONF_OPNSENSE_KEY, "")): str,
                vol.Required(CONF_OPNSENSE_SECRET, default=self._opts.get(CONF_OPNSENSE_SECRET, "")): str,
                vol.Optional(CONF_OPNSENSE_INTERFACE, default=self._opts.get(CONF_OPNSENSE_INTERFACE, "")): str,
            }
        )
        return self.async_show_form(step_id="opnsense", data_schema=schema)

    async def async_step_adguard(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_ADGUARD_URL] = _rstrip_url(user_input.get(CONF_ADGUARD_URL))
            self._opts[CONF_ADGUARD_USERNAME] = (user_input.get(CONF_ADGUARD_USERNAME) or "").strip()
            self._opts[CONF_ADGUARD_PASSWORD] = (user_input.get(CONF_ADGUARD_PASSWORD) or "").strip()

            if self._opts.get(CONF_UNIFI_ENABLED):
                return await self.async_step_unifi()
            return self.async_create_entry(title="", data=self._opts)

        schema = vol.Schema(
            {
                vol.Required(CONF_ADGUARD_URL, default=self._opts.get(CONF_ADGUARD_URL, "")): str,
                vol.Optional(CONF_ADGUARD_USERNAME, default=self._opts.get(CONF_ADGUARD_USERNAME, "")): str,
                vol.Optional(CONF_ADGUARD_PASSWORD, default=self._opts.get(CONF_ADGUARD_PASSWORD, "")): str,
            }
        )
        return self.async_show_form(step_id="adguard", data_schema=schema)

    async def async_step_unifi(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_UNIFI_URL] = _rstrip_url(user_input.get(CONF_UNIFI_URL))
            self._opts[CONF_UNIFI_TOKEN] = (user_input.get(CONF_UNIFI_TOKEN) or "").strip()

            if self._opts[CONF_UNIFI_TOKEN]:
                self._opts[CONF_UNIFI_USERNAME] = ""
                self._opts[CONF_UNIFI_PASSWORD] = ""
            else:
                self._opts[CONF_UNIFI_USERNAME] = (user_input.get(CONF_UNIFI_USERNAME) or "").strip()
                self._opts[CONF_UNIFI_PASSWORD] = (user_input.get(CONF_UNIFI_PASSWORD) or "").strip()

            self._opts[CONF_UNIFI_SITE] = (user_input.get(CONF_UNIFI_SITE) or "default").strip()
            return self.async_create_entry(title="", data=self._opts)

        schema = vol.Schema(
            {
                vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
                vol.Optional(CONF_UNIFI_TOKEN, default=self._opts.get(CONF_UNIFI_TOKEN, "")): str,
                vol.Optional(CONF_UNIFI_USERNAME, default=self._opts.get(CONF_UNIFI_USERNAME, "")): str,
                vol.Optional(CONF_UNIFI_PASSWORD, default=self._opts.get(CONF_UNIFI_PASSWORD, "")): str,
                vol.Optional(CONF_UNIFI_SITE, default=self._opts.get(CONF_UNIFI_SITE, "default")): str,
            }
        )
        return self.async_show_form(step_id="unifi", data_schema=schema)
