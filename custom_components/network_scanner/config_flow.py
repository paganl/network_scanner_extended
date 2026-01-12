# custom_components/network_scanner/config_flow.py
from __future__ import annotations

from typing import Any, Dict, Optional
import voluptuous as vol
import logging
_LOGGER = logging.getLogger(__name__)

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
    # creds / tokens
    CONF_KEY,
    CONF_SECRET,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_UNIFI_TOKEN,
    # common
    CONF_VERIFY_SSL,
    CONF_INTERVAL_MIN,
    DEFAULT_OPTIONS,
    # optional (if you have it in const.py; otherwise remove these two lines)
    CONF_UNIFI_SITE,
    CONF_MAC_DIRECTORY_JSON_URL,
    CONF_MAC_DIRECTORY_JSON_TEXT,
)

PROVIDER_CHOICES = [
    PROVIDER_OPNSENSE,
    PROVIDER_UNIFI,
    PROVIDER_ADGUARD,
    PROVIDER_OPNSENSE_UNIFI,
]


def _rstrip_url(v: Optional[str]) -> str:
    return (v or "").strip().rstrip("/")


class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Network Scanner."""

    VERSION = 1

    def __init__(self) -> None:
        # No entry here – this is the initial config flow
        self._entry: config_entries.ConfigEntry | None = None
        # Start from defaults; we’ll fill this as we go through the steps
        self._opts: Dict[str, Any] = dict(DEFAULT_OPTIONS)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return NetworkScannerOptionsFlow(config_entry)

    # ------------------- initial step -------------------

    async def async_step_user(self, user_input: Dict[str, Any] | None = None):
        """Step 1: choose provider + common options."""
        if user_input is not None:
            self._opts[CONF_PROVIDER] = user_input[CONF_PROVIDER]
            self._opts[CONF_VERIFY_SSL] = bool(user_input.get(CONF_VERIFY_SSL, False))
            self._opts[CONF_INTERVAL_MIN] = max(1, int(user_input.get(CONF_INTERVAL_MIN, 3)))
            self._opts[CONF_MAC_DIRECTORY_JSON_URL] = (user_input.get(CONF_MAC_DIRECTORY_JSON_URL) or "").strip()
            self._opts[CONF_MAC_DIRECTORY_JSON_TEXT] = (user_input.get(CONF_MAC_DIRECTORY_JSON_TEXT) or "").strip()


            prov = self._opts[CONF_PROVIDER]
            if prov == PROVIDER_OPNSENSE:
                return await self.async_step_opnsense()
            if prov == PROVIDER_UNIFI:
                return await self.async_step_unifi()
            if prov == PROVIDER_ADGUARD:
                return await self.async_step_adguard()
            if prov == PROVIDER_OPNSENSE_UNIFI:
                return await self.async_step_opnsense_unifi()

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_PROVIDER,
                    default=self._opts.get(CONF_PROVIDER, PROVIDER_OPNSENSE),
                ): vol.In(PROVIDER_CHOICES),
                vol.Optional(CONF_VERIFY_SSL, default=self._opts.get(CONF_VERIFY_SSL, False)): bool,
                vol.Optional(CONF_INTERVAL_MIN, default=self._opts.get(CONF_INTERVAL_MIN, 3)): int,
                vol.Optional(CONF_MAC_DIRECTORY_JSON_URL, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_URL, "")): str,
                vol.Optional(CONF_MAC_DIRECTORY_JSON_TEXT, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_TEXT, "")): str,

            }
        )
        _LOGGER.debug(
            "Showing step_user. Defaults: url='%s' text_len=%d provider=%s",
            self._opts.get(CONF_MAC_DIRECTORY_JSON_URL, ""),
            len(self._opts.get(CONF_MAC_DIRECTORY_JSON_TEXT, "") or ""),
            self._opts.get(CONF_PROVIDER),
        )

        return self.async_show_form(step_id="user", data_schema=schema)

    # ------------------- provider steps -------------------

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
                return await self._finish()

        schema = vol.Schema(
            {
                vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
                vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
                vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
            }
        )
        return self.async_show_form(step_id="opnsense", data_schema=schema, errors=errors)

    async def async_step_unifi(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            url = _rstrip_url(user_input.get(CONF_UNIFI_URL))
            token = (user_input.get(CONF_UNIFI_TOKEN) or "").strip()
            name = (user_input.get(CONF_NAME) or "").strip()
            pwd = (user_input.get(CONF_PASSWORD) or "").strip()
            site = (user_input.get(CONF_UNIFI_SITE) or "default").strip() if "CONF_UNIFI_SITE" in globals() else "default"

            if not url:
                errors["base"] = "unifi_url_required"
            elif not token and (not name or not pwd):
                errors["base"] = "unifi_auth_required"  # token OR (user & pass)
            else:
                self._opts[CONF_UNIFI_URL] = url
                self._opts[CONF_UNIFI_TOKEN] = token
                self._opts[CONF_NAME] = "" if token else name
                self._opts[CONF_PASSWORD] = "" if token else pwd
                if "CONF_UNIFI_SITE" in globals():
                    self._opts[CONF_UNIFI_SITE] = site
                return await self._finish()

        schema = {
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Optional(CONF_UNIFI_TOKEN, default=self._opts.get(CONF_UNIFI_TOKEN, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        }
        if "CONF_UNIFI_SITE" in globals():
            schema[vol.Optional(CONF_UNIFI_SITE, default=self._opts.get(CONF_UNIFI_SITE, "default"))] = str
        return self.async_show_form(step_id="unifi", data_schema=vol.Schema(schema), errors=errors)

    async def async_step_adguard(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            url = _rstrip_url(user_input.get(CONF_ADGUARD_URL))
            name = (user_input.get(CONF_NAME) or "admin").strip()
            pwd = (user_input.get(CONF_PASSWORD) or "").strip()
            if not url:
                errors["base"] = "adguard_url_required"
            else:
                self._opts[CONF_ADGUARD_URL] = url
                self._opts[CONF_NAME] = name
                self._opts[CONF_PASSWORD] = pwd
                return await self._finish()

        schema = vol.Schema(
            {
                vol.Required(CONF_ADGUARD_URL, default=self._opts.get(CONF_ADGUARD_URL, "")): str,
                vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "admin")): str,
                vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
            }
        )
        return self.async_show_form(step_id="adguard", data_schema=schema, errors=errors)

    async def async_step_opnsense_unifi(self, user_input: Dict[str, Any] | None = None):
        errors: Dict[str, str] = {}
        if user_input is not None:
            # OPNsense
            url_opn = _rstrip_url(user_input.get(CONF_OPNSENSE_URL))
            key = (user_input.get(CONF_KEY) or "").strip()
            sec = (user_input.get(CONF_SECRET) or "").strip()
            # UniFi
            url_uni = _rstrip_url(user_input.get(CONF_UNIFI_URL))
            token = (user_input.get(CONF_UNIFI_TOKEN) or "").strip()
            name = (user_input.get(CONF_NAME) or "").strip()
            pwd = (user_input.get(CONF_PASSWORD) or "").strip()
            site = (user_input.get(CONF_UNIFI_SITE) or "default").strip() if "CONF_UNIFI_SITE" in globals() else "default"

            if not url_opn or not key or not sec:
                errors["base"] = "opnsense_unifi_opnsense_required"
            elif not url_uni:
                errors["base"] = "opnsense_unifi_unifi_url_required"
            elif not token and (not name or not pwd):
                errors["base"] = "opnsense_unifi_unifi_auth_required"
            else:
                self._opts[CONF_OPNSENSE_URL] = url_opn
                self._opts[CONF_KEY] = key
                self._opts[CONF_SECRET] = sec

                self._opts[CONF_UNIFI_URL] = url_uni
                self._opts[CONF_UNIFI_TOKEN] = token
                self._opts[CONF_NAME] = "" if token else name
                self._opts[CONF_PASSWORD] = "" if token else pwd
                if "CONF_UNIFI_SITE" in globals():
                    self._opts[CONF_UNIFI_SITE] = site

                return await self._finish()

        schema_dict: Dict[Any, Any] = {
            # OPNsense
            vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
            vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
            vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
            # UniFi
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Optional(CONF_UNIFI_TOKEN, default=self._opts.get(CONF_UNIFI_TOKEN, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        }
        if "CONF_UNIFI_SITE" in globals():
            schema_dict[vol.Optional(CONF_UNIFI_SITE, default=self._opts.get(CONF_UNIFI_SITE, "default"))] = str

        return self.async_show_form(
            step_id="opnsense_unifi",
            data_schema=vol.Schema(schema_dict),
            errors=errors,
        )

    # ------------------- finish -------------------

    async def _finish(self):
        # Single entry; make re-adding idempotent
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        # Store initial settings in data (not options) for HA versions
        # that don't support options= in async_create_entry
        return self.async_create_entry(
            title="Network Scanner",
            data=self._opts,
        )



class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    """Options flow mirrors initial setup."""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry = entry
        base = dict(entry.options or entry.data or {})
        self._opts: Dict[str, Any] = {**DEFAULT_OPTIONS, **base}
    
    async def _finish(self):
        # In an OptionsFlow, async_create_entry(data=...) becomes entry.options
        return self.async_create_entry(title="", data=self._opts)
    
    async def async_step_init(self, user_input: Dict[str, Any] | None = None):
        return await self.async_step_user(user_input)

    async def async_step_user(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_PROVIDER] = user_input[CONF_PROVIDER]
            self._opts[CONF_VERIFY_SSL] = bool(user_input.get(CONF_VERIFY_SSL, False))
            self._opts[CONF_INTERVAL_MIN] = max(1, int(user_input.get(CONF_INTERVAL_MIN, 3)))
            self._opts[CONF_MAC_DIRECTORY_JSON_URL] = (user_input.get(CONF_MAC_DIRECTORY_JSON_URL) or "").strip()
            self._opts[CONF_MAC_DIRECTORY_JSON_TEXT] = (user_input.get(CONF_MAC_DIRECTORY_JSON_TEXT) or "").strip()


            prov = self._opts[CONF_PROVIDER]
            if prov == PROVIDER_OPNSENSE:
                return await self.async_step_opnsense()
            if prov == PROVIDER_UNIFI:
                return await self.async_step_unifi()
            if prov == PROVIDER_ADGUARD:
                return await self.async_step_adguard()
            if prov == PROVIDER_OPNSENSE_UNIFI:
                return await self.async_step_opnsense_unifi()

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_PROVIDER,
                    default=self._opts.get(CONF_PROVIDER, PROVIDER_OPNSENSE),
                ): vol.In(PROVIDER_CHOICES),
                vol.Optional(CONF_VERIFY_SSL, default=self._opts.get(CONF_VERIFY_SSL, False)): bool,
                vol.Optional(CONF_INTERVAL_MIN, default=self._opts.get(CONF_INTERVAL_MIN, 3)): int,
                vol.Optional(CONF_MAC_DIRECTORY_JSON_URL, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_URL, "")): str,
                vol.Optional(CONF_MAC_DIRECTORY_JSON_TEXT, default=self._opts.get(CONF_MAC_DIRECTORY_JSON_TEXT, "")): str,

            }
        )
        _LOGGER.debug(
            "Showing step_user. Defaults: url='%s' text_len=%d provider=%s",
            self._opts.get(CONF_MAC_DIRECTORY_JSON_URL, ""),
            len(self._opts.get(CONF_MAC_DIRECTORY_JSON_TEXT, "") or ""),
            self._opts.get(CONF_PROVIDER),
        )

        return self.async_show_form(step_id="user", data_schema=schema)

    async def async_step_opnsense(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_OPNSENSE_URL] = _rstrip_url(user_input.get(CONF_OPNSENSE_URL))
            self._opts[CONF_KEY] = (user_input.get(CONF_KEY) or "").strip()
            self._opts[CONF_SECRET] = (user_input.get(CONF_SECRET) or "").strip()
            return await self._finish()

        schema = vol.Schema(
            {
                vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
                vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
                vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
            }
        )
        return self.async_show_form(step_id="opnsense", data_schema=schema)

    async def async_step_unifi(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_UNIFI_URL] = _rstrip_url(user_input.get(CONF_UNIFI_URL))
            self._opts[CONF_UNIFI_TOKEN] = (user_input.get(CONF_UNIFI_TOKEN) or "").strip()
            if self._opts[CONF_UNIFI_TOKEN]:
                # token path -> blank out user/pass
                self._opts[CONF_NAME] = ""
                self._opts[CONF_PASSWORD] = ""
            else:
                self._opts[CONF_NAME] = (user_input.get(CONF_NAME) or "").strip()
                self._opts[CONF_PASSWORD] = (user_input.get(CONF_PASSWORD) or "").strip()
            if "CONF_UNIFI_SITE" in globals():
                self._opts[CONF_UNIFI_SITE] = (user_input.get(CONF_UNIFI_SITE) or "default").strip()
            return await self._finish()

        schema_dict: Dict[Any, Any] = {
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Optional(CONF_UNIFI_TOKEN, default=self._opts.get(CONF_UNIFI_TOKEN, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        }
        if "CONF_UNIFI_SITE" in globals():
            schema_dict[vol.Optional(CONF_UNIFI_SITE, default=self._opts.get(CONF_UNIFI_SITE, "default"))] = str

        return self.async_show_form(step_id="unifi", data_schema=vol.Schema(schema_dict))

    async def async_step_adguard(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            self._opts[CONF_ADGUARD_URL] = _rstrip_url(user_input.get(CONF_ADGUARD_URL))
            self._opts[CONF_NAME] = (user_input.get(CONF_NAME) or "admin").strip()
            self._opts[CONF_PASSWORD] = (user_input.get(CONF_PASSWORD) or "").strip()
            return await self._finish()

        schema = vol.Schema(
            {
                vol.Required(CONF_ADGUARD_URL, default=self._opts.get(CONF_ADGUARD_URL, "")): str,
                vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "admin")): str,
                vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
            }
        )
        return self.async_show_form(step_id="adguard", data_schema=schema)

    async def async_step_opnsense_unifi(self, user_input: Dict[str, Any] | None = None):
        if user_input is not None:
            # OPNsense
            self._opts[CONF_OPNSENSE_URL] = _rstrip_url(user_input.get(CONF_OPNSENSE_URL))
            self._opts[CONF_KEY] = (user_input.get(CONF_KEY) or "").strip()
            self._opts[CONF_SECRET] = (user_input.get(CONF_SECRET) or "").strip()
            # UniFi
            self._opts[CONF_UNIFI_URL] = _rstrip_url(user_input.get(CONF_UNIFI_URL))
            self._opts[CONF_UNIFI_TOKEN] = (user_input.get(CONF_UNIFI_TOKEN) or "").strip()
            if self._opts[CONF_UNIFI_TOKEN]:
                self._opts[CONF_NAME] = ""
                self._opts[CONF_PASSWORD] = ""
            else:
                self._opts[CONF_NAME] = (user_input.get(CONF_NAME) or "").strip()
                self._opts[CONF_PASSWORD] = (user_input.get(CONF_PASSWORD) or "").strip()
            if "CONF_UNIFI_SITE" in globals():
                self._opts[CONF_UNIFI_SITE] = (user_input.get(CONF_UNIFI_SITE) or "default").strip()
            return await self._finish()

        schema_dict: Dict[Any, Any] = {
            # OPNsense
            vol.Required(CONF_OPNSENSE_URL, default=self._opts.get(CONF_OPNSENSE_URL, "")): str,
            vol.Required(CONF_KEY, default=self._opts.get(CONF_KEY, "")): str,
            vol.Required(CONF_SECRET, default=self._opts.get(CONF_SECRET, "")): str,
            # UniFi
            vol.Required(CONF_UNIFI_URL, default=self._opts.get(CONF_UNIFI_URL, "")): str,
            vol.Optional(CONF_UNIFI_TOKEN, default=self._opts.get(CONF_UNIFI_TOKEN, "")): str,
            vol.Optional(CONF_NAME, default=self._opts.get(CONF_NAME, "")): str,
            vol.Optional(CONF_PASSWORD, default=self._opts.get(CONF_PASSWORD, "")): str,
        }
        if "CONF_UNIFI_SITE" in globals():
            schema_dict[vol.Optional(CONF_UNIFI_SITE, default=self._opts.get(CONF_UNIFI_SITE, "default"))] = str

        return self.async_show_form(step_id="opnsense_unifi", data_schema=vol.Schema(schema_dict))

