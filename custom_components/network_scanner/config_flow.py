from __future__ import annotations
import json
import logging
import re
from ipaddress import ip_network
from typing import Any, Dict
from .const import DEFAULT_SCAN_INTERVAL

import voluptuous as vol
from homeassistant import config_entries

# Text selector (multiline) when available
try:
    from homeassistant.helpers.selector import selector as ha_selector
    def TextSelector():
        return ha_selector({"text": {"multiline": True}})
except Exception:
    def TextSelector():
        return str

from .const import DOMAIN, DEFAULT_IP_RANGE, DEFAULT_SCAN_INTERVAL, DEFAULT_NMAP_ARGS

_LOGGER = logging.getLogger(__name__)

def _split_cidrs(s: str) -> list[str]:
    # split on commas or whitespace
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
                "scan_interval",
                description={"suggested_value": DEFAULT_SCAN_INTERVAL},
            ): int,
            vol.Optional(
                "nmap_args",
                description={"suggested_value": DEFAULT_NMAP_ARGS},
            ): str,
            vol.Optional("mac_directory_json_text", description={"suggested_value": ""}): TextSelector(),
            vol.Optional("mac_directory_json_url",  description={"suggested_value": ""}): str,
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
            bad = []
            for c in cidrs:
                try:
                    ip_network(c, strict=False)
                except Exception:
                    bad.append(c)
            if bad:
                errors["ip_range"] = "invalid_ip_range"

        # Validate scan interval
        scan_interval = int(user_input.get("scan_interval") or DEFAULT_SCAN_INTERVAL)
        if scan_interval < 30 or scan_interval > 3600:
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

        if errors:
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        # Normalise directory now so the sensor can use it directly
        directory = {}
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
            "ip_range": ipr,  # NOTE: we keep the raw string "10.0.0.0/24,10.0.3.0/24"
            "mac_directory": directory,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            "nmap_args": (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip(),
            "scan_interval": int(user_input.get("scan_interval", DEFAULT_SCAN_INTERVAL))
        }
        return self.async_create_entry(title="Network Scanner Extended", data=data)

# ---- Options Flow ----

class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self.entry = entry

    async def async_step_init(self, user_input=None):
        return await self.async_step_user(user_input)

    async def async_step_user(self, user_input=None):
        data = self.entry.data or {}
        opts = self.entry.options or {}

        schema = vol.Schema({
            vol.Required(
                "ip_range",
                description={"suggested_value": opts.get("ip_range", data.get("ip_range", DEFAULT_IP_RANGE))},
            ): str,
            vol.Optional(
                "scan_interval",
                description={"suggested_value": opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL))},
            ): int,
            vol.Optional(
                "nmap_args",
                description={"suggested_value": opts.get("nmap_args", data.get("nmap_args", DEFAULT_NMAP_ARGS))},
            ): str,
            vol.Optional(
                "mac_directory_json_text",
                description={"suggested_value": opts.get("mac_directory_json_text", "")},
            ): TextSelector(),
            vol.Optional(
                "mac_directory_json_url",
                description={"suggested_value": opts.get("mac_directory_json_url", data.get("mac_directory_json_url", ""))},
            ): str,
        })

        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=schema, errors={})

        errors: Dict[str, str] = {}

        # Validate multi-CIDR again
        ipr = (user_input.get("ip_range") or "").strip()
        cidrs = _split_cidrs(ipr)
        if not cidrs:
            errors["ip_range"] = "invalid_ip_range"
        else:
            bad = []
            for c in cidrs:
                try:
                    ip_network(c, strict=False)
                except Exception:
                    bad.append(c)
            if bad:
                errors["ip_range"] = "invalid_ip_range"

        # Validate scan interval
        scan_interval = int(user_input.get("scan_interval") or DEFAULT_SCAN_INTERVAL)
        if scan_interval < 0 or scan_interval > 3600:
            errors["scan_interval"] = "invalid_scan_interval"

        # Validate JSON text
        jtxt = (user_input.get("mac_directory_json_text") or "").strip()
        if jtxt:
            try:
                parsed = json.loads(jtxt)
                block = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
                if not isinstance(block, dict):
                    errors["mac_directory_json_text"] = "invalid_json"
            except Exception:
                errors["mac_directory_json_text"] = "invalid_json"

        if errors:
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        return self.async_create_entry(title="", data={
            "ip_range": ipr,
            "scan_interval": scan_interval,
            "nmap_args": (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip(),
            "mac_directory_json_text": jtxt,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
        })

async def async_get_options_flow(config_entry: config_entries.ConfigEntry):
    return NetworkScannerOptionsFlow(config_entry)
