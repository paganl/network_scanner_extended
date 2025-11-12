from __future__ import annotations

import json
import logging
import re
from ipaddress import ip_network
from typing import Any, Dict

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, OptionsFlow, ConfigEntry

from .const import (
    DOMAIN,
    DEFAULT_IP_RANGE,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_NMAP_ARGS,
    # ARP provider
    CONF_ARP_PROVIDER, ARP_PROVIDERS, DEFAULT_ARP_PROVIDER,
    CONF_ARP_VERIFY_TLS,
    # OPNsense
    DEFAULT_OPNSENSE_URL, DEFAULT_OPNSENSE_IFACE,
    # AdGuard
    DEFAULT_ADGUARD_URL, CONF_ADG_URL, CONF_ADG_USER, CONF_ADG_PASS,
    # UniFi (independent enrichment)
    DEFAULT_UNIFI_URL, DEFAULT_UNIFI_SITE,
    CONF_UNIFI_ENABLED, CONF_UNIFI_URL, CONF_UNIFI_USER, CONF_UNIFI_PASS, CONF_UNIFI_SITE,
)

_LOGGER = logging.getLogger(__name__)

_FORBIDDEN_NMAP_CHARS = re.compile(r"[;&|`$><]")

def _coerce_minutes(val, default_mins: int) -> int:
    try:
        if val in (None, ""):
            return default_mins
        m = int(round(float(val)))
        if m < 0: m = 0
        if m > 1440: m = 1440
        return m
    except Exception:
        return default_mins

def _split_cidrs(s: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\s]+", s or "") if p.strip()]

def _cidr_bad(c: str) -> bool:
    try:
        ip_network(c, strict=False)
        return False
    except Exception:
        return True

def _is_dir_json(txt: str) -> bool:
    try:
        parsed = json.loads(txt)
        block = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
        return isinstance(block, dict)
    except Exception:
        return False

def _build_dir(txt: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not txt:
        return out
    parsed = json.loads(txt)
    block = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
    if isinstance(block, dict):
        for k, v in block.items():
            mk = (k or "").upper()
            if not mk:
                continue
            if isinstance(v, dict):
                out[mk] = {"name": str(v.get("name", "")), "desc": str(v.get("desc", ""))}
            else:
                out[mk] = {"name": str(v), "desc": ""}
    return out

def _nmap_args_invalid(s: str) -> bool:
    return bool(s and _FORBIDDEN_NMAP_CHARS.search(s))

# Selectors (guarded so tests don’t explode)
try:
    from homeassistant.helpers.selector import selector as ha_selector
    def TextSelector():
        return ha_selector({"text": {"multiline": True}})
    def MinutesNumberSelector():
        return ha_selector({"number": {"min": 0, "max": 1440, "step": 1, "mode": "box", "unit_of_measurement": "min"}})
except Exception:
    def TextSelector(): return str
    def MinutesNumberSelector(): return int

# =============================== Config Flow (v2) ===============================

class NetworkScannerConfigFlow(ConfigFlow, domain=DOMAIN):
    """
    V2 schema (minutes):
      - Choose one ARP provider (none/opnsense/adguard)
      - Optional UniFi enrichment is independent of ARP provider
    """
    VERSION = 2
    _common: Dict[str, Any] | None = None

    async def async_step_user(self, user_input=None):
        suggested_mins = DEFAULT_SCAN_INTERVAL_MINUTES

        schema = vol.Schema({
            vol.Optional("ip_range", description={"suggested_value": DEFAULT_IP_RANGE}): str,
            vol.Optional("nmap_args", description={"suggested_value": DEFAULT_NMAP_ARGS}): str,
            vol.Optional("scan_interval_minutes", description={"suggested_value": suggested_mins}): MinutesNumberSelector(),

            vol.Required(CONF_ARP_PROVIDER, description={"suggested_value": DEFAULT_ARP_PROVIDER}): vol.In(ARP_PROVIDERS),
            vol.Optional(CONF_ARP_VERIFY_TLS, description={"suggested_value": False}): bool,

            vol.Optional("mac_directory_json_text", description={"suggested_value": ""}): TextSelector(),
            vol.Optional("mac_directory_json_url", description={"suggested_value": ""}): str,

            # UniFi enrichment (independent)
            vol.Optional(CONF_UNIFI_ENABLED, description={"suggested_value": False}): bool,
            vol.Optional(CONF_UNIFI_URL,     description={"suggested_value": DEFAULT_UNIFI_URL}): str,
            vol.Optional(CONF_UNIFI_USER,    description={"suggested_value": ""}): str,
            vol.Optional(CONF_UNIFI_PASS,    description={"suggested_value": ""}): str,
            vol.Optional(CONF_UNIFI_SITE,    description={"suggested_value": DEFAULT_UNIFI_SITE}): str,
        })

        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=schema, errors={})

        errors: Dict[str, str] = {}

        ipr = (user_input.get("ip_range") or "").strip()
        cidrs = _split_cidrs(ipr)
        if any(_cidr_bad(c) for c in cidrs):
            errors["ip_range"] = "invalid_ip_range"

        mins = _coerce_minutes(user_input.get("scan_interval_minutes"), suggested_mins)

        nmap_args = (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        if _nmap_args_invalid(nmap_args):
            errors["nmap_args"] = "invalid_nmap_args"

        jtxt = (user_input.get("mac_directory_json_text") or "").strip()
        if jtxt and not _is_dir_json(jtxt):
            errors["mac_directory_json_text"] = "invalid_json"

        # Basic UniFi URL shape only if enabled
        if bool(user_input.get(CONF_UNIFI_ENABLED, False)):
            u_url = (user_input.get(CONF_UNIFI_URL) or "").strip()
            if u_url and not u_url.startswith(("http://", "https://")):
                errors[CONF_UNIFI_URL] = "invalid_url"

        if errors:
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        self._common = {
            "ip_range": ipr,
            "nmap_args": nmap_args,
            "scan_interval_minutes": mins,
            "mac_directory": _build_dir(jtxt),
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            CONF_ARP_PROVIDER: user_input.get(CONF_ARP_PROVIDER, DEFAULT_ARP_PROVIDER),
            CONF_ARP_VERIFY_TLS: bool(user_input.get(CONF_ARP_VERIFY_TLS, False)),
            # UniFi enrichment block
            CONF_UNIFI_ENABLED: bool(user_input.get(CONF_UNIFI_ENABLED, False)),
            CONF_UNIFI_URL:  (user_input.get(CONF_UNIFI_URL)  or "").strip(),
            CONF_UNIFI_USER: (user_input.get(CONF_UNIFI_USER) or "").strip(),
            CONF_UNIFI_PASS: (user_input.get(CONF_UNIFI_PASS) or "").strip(),
            CONF_UNIFI_SITE: (user_input.get(CONF_UNIFI_SITE) or DEFAULT_UNIFI_SITE).strip(),
        }

        provider = self._common[CONF_ARP_PROVIDER]
        if provider == "opnsense":
            return await self.async_step_opnsense()
        if provider == "adguard":
            return await self.async_step_adguard()
        # none -> create now
        return self.async_create_entry(title="Network Scanner Extended", data=self._common)

    async def async_step_opnsense(self, user_input=None):
        schema = vol.Schema({
            vol.Required("opnsense_url", description={"suggested_value": DEFAULT_OPNSENSE_URL}): str,
            vol.Optional("opnsense_key", description={"suggested_value": ""}): str,
            vol.Optional("opnsense_secret", description={"suggested_value": ""}): str,
            vol.Optional("opnsense_interface", description={"suggested_value": DEFAULT_OPNSENSE_IFACE}): str,
        })
        if user_input is None:
            return self.async_show_form(step_id="opnsense", data_schema=schema, errors={})

        errors: Dict[str, str] = {}
        url = (user_input.get("opnsense_url") or "").strip()
        if url and not url.startswith(("http://", "https://")):
            errors["opnsense_url"] = "invalid_url"
        key = (user_input.get("opnsense_key") or "").strip()
        sec = (user_input.get("opnsense_secret") or "").strip()
        if (key and not sec) or (sec and not key):
            errors["opnsense_key"] = "incomplete_credentials"

        if errors:
            return self.async_show_form(step_id="opnsense", data_schema=schema, errors=errors)

        data = dict(self._common or {})
        data.update({
            "opnsense_url": url,
            "opnsense_key": key,
            "opnsense_secret": sec,
            "opnsense_interface": (user_input.get("opnsense_interface") or "").strip(),
        })
        return self.async_create_entry(title="Network Scanner Extended", data=data)

    async def async_step_adguard(self, user_input=None):
        schema = vol.Schema({
            vol.Required(CONF_ADG_URL,  description={"suggested_value": DEFAULT_ADGUARD_URL}): str,
            vol.Required(CONF_ADG_USER, description={"suggested_value": ""}): str,
            vol.Required(CONF_ADG_PASS, description={"suggested_value": ""}): str,
        })
        if user_input is None:
            return self.async_show_form(step_id="adguard", data_schema=schema, errors={})

        errors: Dict[str, str] = {}
        url = (user_input.get(CONF_ADG_URL) or "").strip()
        if url and not url.startswith(("http://", "https://")):
            errors[CONF_ADG_URL] = "invalid_url"
        user = (user_input.get(CONF_ADG_USER) or "").strip()
        pwd  = (user_input.get(CONF_ADG_PASS) or "").strip()
        if not (user and pwd):
            errors[CONF_ADG_USER] = "incomplete_credentials"

        if errors:
            return self.async_show_form(step_id="adguard", data_schema=schema, errors=errors)

        data = dict(self._common or {})
        data.update({
            CONF_ADG_URL: url,
            CONF_ADG_USER: user,
            CONF_ADG_PASS: pwd,
        })
        return self.async_create_entry(title="Network Scanner Extended", data=data)

# =============================== Options Flow ===============================

class NetworkScannerOptionsFlow(OptionsFlow):
    def __init__(self, entry: ConfigEntry) -> None:
        self.entry = entry

    async def async_step_init(self, user_input=None):
        data = self.entry.data or {}
        opts = self.entry.options or {}

        saved_mins = opts.get("scan_interval_minutes", data.get("scan_interval_minutes", DEFAULT_SCAN_INTERVAL_MINUTES))
        prov = opts.get(CONF_ARP_PROVIDER, data.get(CONF_ARP_PROVIDER, DEFAULT_ARP_PROVIDER))

        schema_dict: Dict[Any, Any] = {
            vol.Optional("ip_range", description={"suggested_value": opts.get("ip_range", data.get("ip_range", DEFAULT_IP_RANGE))}): str,
            vol.Optional("nmap_args", description={"suggested_value": opts.get("nmap_args", data.get("nmap_args", DEFAULT_NMAP_ARGS))}): str,
            vol.Optional("scan_interval_minutes", description={"suggested_value": saved_mins}): MinutesNumberSelector(),

            vol.Required(CONF_ARP_PROVIDER, description={"suggested_value": prov}): vol.In(ARP_PROVIDERS),
            vol.Optional(CONF_ARP_VERIFY_TLS, description={"suggested_value": opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, False))}): bool,

            vol.Optional("mac_directory_json_text", description={"suggested_value": opts.get("mac_directory_json_text", "")}): TextSelector(),
            vol.Optional("mac_directory_json_url",  description={"suggested_value": opts.get("mac_directory_json_url", data.get("mac_directory_json_url", ""))}): str,

            # UniFi enrichment (always visible)
            vol.Optional(CONF_UNIFI_ENABLED, description={"suggested_value": opts.get(CONF_UNIFI_ENABLED, data.get(CONF_UNIFI_ENABLED, False))}): bool,
            vol.Optional(CONF_UNIFI_URL,     description={"suggested_value": opts.get(CONF_UNIFI_URL, data.get(CONF_UNIFI_URL, DEFAULT_UNIFI_URL))}): str,
            vol.Optional(CONF_UNIFI_USER,    description={"suggested_value": "********" if (opts.get(CONF_UNIFI_USER) or data.get(CONF_UNIFI_USER)) else ""}): str,
            vol.Optional(CONF_UNIFI_PASS,    description={"suggested_value": "********" if (opts.get(CONF_UNIFI_PASS) or data.get(CONF_UNIFI_PASS)) else ""}): str,
            vol.Optional(CONF_UNIFI_SITE,    description={"suggested_value": opts.get(CONF_UNIFI_SITE, data.get(CONF_UNIFI_SITE, DEFAULT_UNIFI_SITE))}): str,
        }

        # Provider-specific block
        if prov == "opnsense":
            schema_dict.update({
                vol.Optional("opnsense_url", description={"suggested_value": opts.get("opnsense_url", data.get("opnsense_url", DEFAULT_OPNSENSE_URL))}): str,
                vol.Optional("opnsense_key", description={"suggested_value": "********" if (opts.get("opnsense_key") or data.get("opnsense_key")) else ""}): str,
                vol.Optional("opnsense_secret", description={"suggested_value": "********" if (opts.get("opnsense_secret") or data.get("opnsense_secret")) else ""}): str,
                vol.Optional("opnsense_interface", description={"suggested_value": opts.get("opnsense_interface", data.get("opnsense_interface", DEFAULT_OPNSENSE_IFACE))}): str,
            })
        elif prov == "adguard":
            schema_dict.update({
                vol.Optional(CONF_ADG_URL,  description={"suggested_value": opts.get(CONF_ADG_URL, data.get(CONF_ADG_URL, DEFAULT_ADGUARD_URL))}): str,
                vol.Optional(CONF_ADG_USER, description={"suggested_value": "********" if (opts.get(CONF_ADG_USER) or data.get(CONF_ADG_USER)) else ""}): str,
                vol.Optional(CONF_ADG_PASS, description={"suggested_value": "********" if (opts.get(CONF_ADG_PASS) or data.get(CONF_ADG_PASS)) else ""}): str,
            })

        schema = vol.Schema(schema_dict)

        if user_input is None:
            return self.async_show_form(step_id="init", data_schema=schema, errors={})

        errors: Dict[str, str] = {}

        ipr = (user_input.get("ip_range") or "").strip()
        cidrs = _split_cidrs(ipr)
        if any(_cidr_bad(c) for c in cidrs):
            errors["ip_range"] = "invalid_ip_range"

        mins = _coerce_minutes(user_input.get("scan_interval_minutes", saved_mins), saved_mins)

        nmap_args = (user_input.get("nmap_args") or opts.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        if _nmap_args_invalid(nmap_args):
            errors["nmap_args"] = "invalid_nmap_args"

        prov = user_input.get(CONF_ARP_PROVIDER, prov)

        def _url_ok(field: str):
            v = (user_input.get(field) or "").strip()
            if v and not v.startswith(("http://", "https://")):
                errors[field] = "invalid_url"
            return v

        if prov == "opnsense":
            _url_ok("opnsense_url")
            key_in = (user_input.get("opnsense_key") or "").strip()
            sec_in = (user_input.get("opnsense_secret") or "").strip()
            if key_in == "********":
                key_in = opts.get("opnsense_key") or data.get("opnsense_key", "")
            if sec_in == "********":
                sec_in = opts.get("opnsense_secret") or data.get("opnsense_secret", "")
            if (key_in and not sec_in) or (sec_in and not key_in):
                errors["opnsense_key"] = "incomplete_credentials"

        if prov == "adguard":
            _url_ok(CONF_ADG_URL)
            k = (user_input.get(CONF_ADG_USER) or "").strip()
            s = (user_input.get(CONF_ADG_PASS) or "").strip()
            if k == "********":
                k = opts.get(CONF_ADG_USER) or data.get(CONF_ADG_USER, "")
            if s == "********":
                s = opts.get(CONF_ADG_PASS) or data.get(CONF_ADG_PASS, "")
            if (k and not s) or (s and not k):
                errors[CONF_ADG_USER] = "incomplete_credentials"

        # UniFi check only if enabled
        unifi_enabled = bool(user_input.get(CONF_UNIFI_ENABLED, opts.get(CONF_UNIFI_ENABLED, data.get(CONF_UNIFI_ENABLED, False))))
        if unifi_enabled:
            _url_ok(CONF_UNIFI_URL)
            u = (user_input.get(CONF_UNIFI_USER) or "").strip()
            p = (user_input.get(CONF_UNIFI_PASS) or "").strip()
            if (u and not p) or (p and not u):
                errors[CONF_UNIFI_USER] = "incomplete_credentials"

        jtxt = (user_input.get("mac_directory_json_text") or "").strip()
        if jtxt and not _is_dir_json(jtxt):
            errors["mac_directory_json_text"] = "invalid_json"

        if errors:
            return self.async_show_form(step_id="init", data_schema=schema, errors=errors)

        out = {
            "ip_range": ipr,
            "nmap_args": nmap_args,
            "scan_interval_minutes": mins,
            CONF_ARP_PROVIDER: prov,
            CONF_ARP_VERIFY_TLS: bool(user_input.get(CONF_ARP_VERIFY_TLS, opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, False)))),
            "mac_directory_json_text": jtxt,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            # UniFi persisted regardless of provider
            CONF_UNIFI_ENABLED: unifi_enabled,
            CONF_UNIFI_URL:  (user_input.get(CONF_UNIFI_URL)  or opts.get(CONF_UNIFI_URL)  or data.get(CONF_UNIFI_URL, "")).strip(),
            CONF_UNIFI_USER: ((user_input.get(CONF_UNIFI_USER) or "").strip().replace("********", "")
                              or opts.get(CONF_UNIFI_USER) or data.get(CONF_UNIFI_USER, "")),
            CONF_UNIFI_PASS: ((user_input.get(CONF_UNIFI_PASS) or "").strip().replace("********", "")
                              or opts.get(CONF_UNIFI_PASS) or data.get(CONF_UNIFI_PASS, "")),
            CONF_UNIFI_SITE: (user_input.get(CONF_UNIFI_SITE) or opts.get(CONF_UNIFI_SITE)
                              or data.get(CONF_UNIFI_SITE, DEFAULT_UNIFI_SITE)).strip(),
        }

        if prov == "opnsense":
            out["opnsense_url"] = (user_input.get("opnsense_url") or opts.get("opnsense_url") or data.get("opnsense_url", "")).strip()
            out["opnsense_key"] = ((user_input.get("opnsense_key") or "").strip().replace("********", "")
                                   or opts.get("opnsense_key") or data.get("opnsense_key", ""))
            out["opnsense_secret"] = ((user_input.get("opnsense_secret") or "").strip().replace("********", "")
                                      or opts.get("opnsense_secret") or data.get("opnsense_secret", ""))
            out["opnsense_interface"] = (user_input.get("opnsense_interface") or opts.get("opnsense_interface")
                                         or data.get("opnsense_interface", "")).strip()

        if prov == "adguard":
            out[CONF_ADG_URL]  = (user_input.get(CONF_ADG_URL)  or opts.get(CONF_ADG_URL)  or data.get(CONF_ADG_URL, "")).strip()
            out[CONF_ADG_USER] = ((user_input.get(CONF_ADG_USER) or "").strip().replace("********", "")
                                  or opts.get(CONF_ADG_USER) or data.get(CONF_ADG_USER, ""))
            out[CONF_ADG_PASS] = ((user_input.get(CONF_ADG_PASS) or "").strip().replace("********", "")
                                  or opts.get(CONF_ADG_PASS) or data.get(CONF_ADG_PASS, ""))

        return self.async_create_entry(title="", data=out)

async def async_get_options_flow(config_entry: ConfigEntry):
    return NetworkScannerOptionsFlow(config_entry)
