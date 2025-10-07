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
)

_LOGGER = logging.getLogger(__name__)

# ---------- helpers ----------

def _secs_to_minutes(secs: int | None) -> int:
    if not isinstance(secs, int) or secs < 0:
        return 0
    # Return an int; 0 means disabled in minutes UI as well
    return max(0, int(round(secs / 60)))

def _minutes_to_secs(mins: int | None, default_secs: int) -> int:
    if not isinstance(mins, int) or mins < 0:
        return default_secs
    return 0 if mins == 0 else mins * 60

def _split_cidrs(s: str) -> list[str]:
    # split on commas or whitespace
    return [p.strip() for p in re.split(r"[,\s]+", s or "") if p.strip()]

def _normalise_mac_key(mac: str) -> str:
    return mac.upper() if isinstance(mac, str) else ""

# Multiline text selector when available (safe fallback to str)
try:
    from homeassistant.helpers.selector import selector as ha_selector
    def TextSelector():
        return ha_selector({"text": {"multiline": True}})
except Exception:
    def TextSelector():
        return str

# ---------- Config Flow ----------

class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        yaml_defaults = self.hass.data.get(DOMAIN, {}) or {}
        current_secs = int(yaml_defaults.get("scan_interval", DEFAULT_SCAN_INTERVAL))
        current_mins = _secs_to_minutes(current_secs)

        schema = vol.Schema({
            vol.Required(
                "ip_range",
                default=yaml_defaults.get("ip_range", DEFAULT_IP_RANGE),
            ): str,
            vol.Optional(
                "nmap_args",
                default=DEFAULT_NMAP_ARGS,
            ): str,
            # minutes in UI, stored as seconds internally
            vol.Optional(
                "scan_interval_minutes",
                default=current_mins,
            ): int,
            vol.Optional(
                "mac_directory_json_text",
                description={"suggested_value": ""},
            ): TextSelector(),
            vol.Optional(
                "mac_directory_json_url",
                default="",
            ): str,
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

        # Validate minutes (0..1440, where 0 disables auto-scan)
        try:
            mins = int(user_input.get("scan_interval_minutes", current_mins))
        except Exception:
            mins = current_mins
        if mins < 0 or mins > 1440:
            errors["scan_interval_minutes"] = "invalid_scan_interval"

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

        # Normalise directory now so the sensor/controller can use it directly
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
                        directory[mk] = {
                            "name": str(v.get("name", "")),
                            "desc": str(v.get("desc", "")),
                        }
                    else:
                        directory[mk] = {"name": str(v), "desc": ""}

        # Store seconds internally
        scan_secs = _minutes_to_secs(mins, DEFAULT_SCAN_INTERVAL)

        data = {
            "ip_range": ipr,  # raw string e.g. "10.0.0.0/24,10.0.3.0/24"
            "nmap_args": (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip(),
            "scan_interval": scan_secs,   # SECONDS (0 = disabled)
            "mac_directory": directory,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
        }
        return self.async_create_entry(title="Network Scanner Extended", data=data)

# ---------- Options Flow ----------

class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self.entry = entry

    async def async_step_init(self, user_input=None):
        return await self.async_step_user(user_input)

    async def async_step_user(self, user_input=None):
        data = self.entry.data or {}
        opts = self.entry.options or {}

        saved_secs = int(opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL)))
        saved_mins = _secs_to_minutes(saved_secs)

        schema = vol.Schema({
            vol.Required(
                "ip_range",
                default=opts.get("ip_range", data.get("ip_range", DEFAULT_IP_RANGE)),
            ): str,
            vol.Optional(
                "nmap_args",
                default=opts.get("nmap_args", data.get("nmap_args", DEFAULT_NMAP_ARGS)),
            ): str,
            vol.Optional(
                "scan_interval_minutes",
                default=saved_mins,
            ): int,
            vol.Optional(
                "mac_directory_json_text",
                description={"suggested_value": opts.get("mac_directory_json_text", "")},
            ): TextSelector(),
            vol.Optional(
                "mac_directory_json_url",
                default=opts.get("mac_directory_json_url", data.get("mac_directory_json_url", "")),
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

        # Validate minutes 0..1440
        try:
            mins = int(user_input.get("scan_interval_minutes", saved_mins))
        except Exception:
            mins = saved_mins
        if mins < 0 or mins > 1440:
            errors["scan_interval_minutes"] = "invalid_scan_interval"

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

        # Store seconds in OPTIONS (so Configure overrides take effect)
        scan_secs = _minutes_to_secs(mins, DEFAULT_SCAN_INTERVAL)

        return self.async_create_entry(
            title="",
            data={
                "ip_range": ipr,
                "nmap_args": (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip(),
                "scan_interval": scan_secs,  # SECONDS; 0 disables auto-scan
                "mac_directory_json_text": jtxt,
                "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            },
        )

async def async_get_options_flow(config_entry: config_entries.ConfigEntry):
    return NetworkScannerOptionsFlow(config_entry)
