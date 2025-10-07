# custom_components/network_scanner_extended/config_flow.py
from __future__ import annotations
import json
import logging
import re
from ipaddress import ip_network
from typing import Any, Dict

import voluptuous as vol
from homeassistant import config_entries

from .const import (
    DOMAIN,
    DEFAULT_IP_RANGE,
    DEFAULT_SCAN_INTERVAL,   # seconds
    DEFAULT_NMAP_ARGS,
    # NEW:
    CONF_ARP_PROVIDER, CONF_ARP_BASE_URL, CONF_ARP_KEY, CONF_ARP_SECRET, CONF_ARP_VERIFY_TLS,
    ARP_PROVIDER_NONE, ARP_PROVIDER_OPNSENSE,
)

_LOGGER = logging.getLogger(__name__)

# Selectors (multiline text, select, password if available)
try:
    from homeassistant.helpers.selector import selector as ha_selector

    def TextSelector():
        return ha_selector({"text": {"multiline": True}})

    def SelectProvider(default_val: str):
        return ha_selector({"select": {
            "options": [
                {"label": "None", "value": ARP_PROVIDER_NONE},
                {"label": "OPNsense", "value": ARP_PROVIDER_OPNSENSE},
            ],
            "mode": "dropdown",
            "translation_key": "arp_provider",
        }})

    def PasswordSelector():
        # HA text selector supports type=password
        return ha_selector({"text": {"type": "password"}})

    def BoolSelector(default: bool):
        return ha_selector({"boolean": {}})
except Exception:
    def TextSelector():
        return str
    def SelectProvider(_v: str):
        return str
    def PasswordSelector():
        return str
    def BoolSelector(_b: bool):
        return bool

def _split_cidrs(s: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\s]+", s or "") if p.strip()]

def _normalise_mac_key(mac: str) -> str:
    return mac.upper() if isinstance(mac, str) else ""

class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        yaml_defaults = self.hass.data.get(DOMAIN, {}) or {}

        schema = vol.Schema({
            vol.Required(
                "ip_range",
                description={"suggested_value": yaml_defaults.get("ip_range", DEFAULT_IP_RANGE)},
            ): str,
            vol.Optional(
                "nmap_args",
                description={"suggested_value": DEFAULT_NMAP_ARGS},
            ): str,
            vol.Optional(
                "scan_interval",
                description={"suggested_value": DEFAULT_SCAN_INTERVAL},  # seconds; 0 disables
            ): int,
            # Directory JSON (optional)
            vol.Optional("mac_directory_json_text", description={"suggested_value": ""}): TextSelector(),
            vol.Optional("mac_directory_json_url",  description={"suggested_value": ""}): str,

            # NEW: ARP enrichment (optional)
            vol.Optional(CONF_ARP_PROVIDER, description={"suggested_value": ARP_PROVIDER_NONE}): SelectProvider(ARP_PROVIDER_NONE),
            vol.Optional(CONF_ARP_BASE_URL, description={"suggested_value": ""}): str,
            vol.Optional(CONF_ARP_KEY, description={"suggested_value": ""}): str,
            vol.Optional(CONF_ARP_SECRET, description={"suggested_value": ""}): PasswordSelector(),
            vol.Optional(CONF_ARP_VERIFY_TLS, description={"suggested_value": True}): BoolSelector(True),
        })

        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=schema, errors={})

        errors: Dict[str, str] = {}

        # Validate multi-CIDR
        ipr = (user_input.get("ip_range") or "").strip()
        cidrs = _split_cidrs(ipr)
        if not cidrs:
            errors["ip_range"] = "invalid_ip_range"
        else:
            for c in cidrs:
                try:
                    ip_network(c, strict=False)
                except Exception:
                    errors["ip_range"] = "invalid_ip_range"
                    break

        # Validate scan interval (seconds; allow 0 to disable)
        try:
            scan_interval = int(user_input.get("scan_interval", DEFAULT_SCAN_INTERVAL))
        except Exception:
            scan_interval = DEFAULT_SCAN_INTERVAL
        if scan_interval < 0 or scan_interval > 24 * 3600:
            errors["scan_interval"] = "invalid_scan_interval"

        # Light validation of JSON text
        jtxt = (user_input.get("mac_directory_json_text") or "").strip()
        if jtxt:
            try:
                parsed = json.loads(jtxt)
                block = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
                if not isinstance(block, dict):
                    errors["mac_directory_json_text"] = "invalid_json"
            except Exception:
                errors["mac_directory_json_text"] = "invalid_json"

        # ARP validation
        provider = (user_input.get(CONF_ARP_PROVIDER) or ARP_PROVIDER_NONE).strip().lower()
        if provider == ARP_PROVIDER_OPNSENSE:
            if not (user_input.get(CONF_ARP_BASE_URL) and user_input.get(CONF_ARP_KEY) and user_input.get(CONF_ARP_SECRET)):
                errors[CONF_ARP_BASE_URL] = "required"
                errors[CONF_ARP_KEY] = "required"
                errors[CONF_ARP_SECRET] = "required"

        if errors:
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        # Normalise directory now so the sensor can use it directly
        directory: Dict[str, Dict[str, str]] = {}
        if jtxt:
            raw = json.loads(jtxt)
            block = raw.get("data", raw) if isinstance(raw, dict) else {}
            if isinstance(block, dict):
                for k, v in block.items():
                    mk = _normalise_mac_key(k)
                    if not mk:
                        continue
                    if isinstance(v, dict):
                        directory[mk] = {"name": str(v.get("name", "")), "desc": str(v.get("desc", ""))}
                    else:
                        directory[mk] = {"name": str(v), "desc": ""}

        data = {
            "ip_range": ipr,
            "nmap_args": (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip(),
            "scan_interval": scan_interval,  # seconds; 0 = manual only
            "mac_directory": directory,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            # ARP enrichment
            CONF_ARP_PROVIDER:   provider,
            CONF_ARP_BASE_URL:   (user_input.get(CONF_ARP_BASE_URL) or "").strip(),
            CONF_ARP_KEY:        (user_input.get(CONF_ARP_KEY) or "").strip(),
            CONF_ARP_SECRET:     (user_input.get(CONF_ARP_SECRET) or "").strip(),
            CONF_ARP_VERIFY_TLS: bool(user_input.get(CONF_ARP_VERIFY_TLS, True)),
        }
        return self.async_create_entry(title="Network Scanner Extended", data=data)

# ---- Options Flow mirrors the same fields ----

class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self.entry = entry

    async def async_step_init(self, user_input=None):
        return await self.async_step_user(user_input)

    async def async_step_user(self, user_input=None):
        data = self.entry.data or {}
        opts = self.entry.options or {}

        schema = vol.Schema({
            vol.Required("ip_range", description={"suggested_value": opts.get("ip_range", data.get("ip_range", DEFAULT_IP_RANGE))}): str,
            vol.Optional("nmap_args", description={"suggested_value": opts.get("nmap_args", data.get("nmap_args", DEFAULT_NMAP_ARGS))}): str,
            vol.Optional("scan_interval", description={"suggested_value": opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL))}): int,
            vol.Optional("mac_directory_json_text", description={"suggested_value": opts.get("mac_directory_json_text", "")}): TextSelector(),
            vol.Optional("mac_directory_json_url",  description={"suggested_value": opts.get("mac_directory_json_url", data.get("mac_directory_json_url",""))}): str,
            # ARP enrichment
            vol.Optional(CONF_ARP_PROVIDER,   description={"suggested_value": opts.get(CONF_ARP_PROVIDER,   data.get(CONF_ARP_PROVIDER, ARP_PROVIDER_NONE))}): SelectProvider(ARP_PROVIDER_NONE),
            vol.Optional(CONF_ARP_BASE_URL,   description={"suggested_value": opts.get(CONF_ARP_BASE_URL,   data.get(CONF_ARP_BASE_URL, ""))}): str,
            vol.Optional(CONF_ARP_KEY,        description={"suggested_value": opts.get(CONF_ARP_KEY,        data.get(CONF_ARP_KEY, ""))}): str,
            vol.Optional(CONF_ARP_SECRET,     description={"suggested_value": opts.get(CONF_ARP_SECRET,     data.get(CONF_ARP_SECRET, ""))}): PasswordSelector(),
            vol.Optional(CONF_ARP_VERIFY_TLS, description={"suggested_value": opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, True))}): BoolSelector(True),
        })

        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=schema, errors={})

        errors: Dict[str, str] = {}

        # CIDRs
        ipr = (user_input.get("ip_range") or "").strip()
        cidrs = _split_cidrs(ipr)
        if not cidrs:
            errors["ip_range"] = "invalid_ip_range"
        else:
            for c in cidrs:
                try:
                    ip_network(c, strict=False)
                except Exception:
                    errors["ip_range"] = "invalid_ip_range"
                    break

        # scan interval
        try:
            scan_interval = int(user_input.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL)))
        except Exception:
            scan_interval = DEFAULT_SCAN_INTERVAL
        if scan_interval < 0 or scan_interval > 24 * 3600:
            errors["scan_interval"] = "invalid_scan_interval"

        # JSON text validation
        jtxt = (user_input.get("mac_directory_json_text") or "").strip()
        if jtxt:
            try:
                parsed = json.loads(jtxt)
                block = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
                if not isinstance(block, dict):
                    errors["mac_directory_json_text"] = "invalid_json"
            except Exception:
                errors["mac_directory_json_text"] = "invalid_json"

        # ARP validation
        provider = (user_input.get(CONF_ARP_PROVIDER) or ARP_PROVIDER_NONE).strip().lower()
        if provider == ARP_PROVIDER_OPNSENSE:
            if not (user_input.get(CONF_ARP_BASE_URL) and user_input.get(CONF_ARP_KEY) and user_input.get(CONF_ARP_SECRET)):
                errors[CONF_ARP_BASE_URL] = "required"
                errors[CONF_ARP_KEY] = "required"
                errors[CONF_ARP_SECRET] = "required"

        if errors:
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        return self.async_create_entry(title="", data={
            "ip_range": ipr,
            "nmap_args": (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip(),
            "scan_interval": scan_interval,
            "mac_directory_json_text": jtxt,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            # ARP enrichment
            CONF_ARP_PROVIDER:   provider,
            CONF_ARP_BASE_URL:   (user_input.get(CONF_ARP_BASE_URL) or "").strip(),
            CONF_ARP_KEY:        (user_input.get(CONF_ARP_KEY) or "").strip(),
            CONF_ARP_SECRET:     (user_input.get(CONF_ARP_SECRET) or "").strip(),
            CONF_ARP_VERIFY_TLS: bool(user_input.get(CONF_ARP_VERIFY_TLS, True)),
        })

async def async_get_options_flow(config_entry: config_entries.ConfigEntry):
    return NetworkScannerOptionsFlow(config_entry)
