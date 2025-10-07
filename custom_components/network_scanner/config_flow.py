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
    DEFAULT_OPNSENSE_URL,
    DEFAULT_OPNSENSE_IFACE,
)

_LOGGER = logging.getLogger(__name__)

def _secs_to_minutes(secs: int | None) -> int:
    if not isinstance(secs, int) or secs < 0:
        return 0
    return max(0, round(secs / 60))

def _minutes_to_secs(mins: int | None, default_secs: int) -> int:
    if not isinstance(mins, int) or mins < 0:
        return default_secs
    return 0 if mins == 0 else mins * 60

def _split_cidrs(s: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\s]+", s or "") if p.strip()]

def _normalise_mac_key(mac: str) -> str:
    return mac.upper() if isinstance(mac, str) else ""

# Selectors
try:
    from homeassistant.helpers.selector import selector as ha_selector

    def TextSelector():
        return ha_selector({"text": {"multiline": True}})

    def NumberMinutesSelector(default_val: int):
        return ha_selector({
            "number": {
                "min": 0, "max": 1440, "step": 1, "mode": "box",
                "unit_of_measurement": "min",
                "value": default_val,
            }
        })
except Exception:
    def TextSelector():
        return str
    def NumberMinutesSelector(_default_val: int):
        return int


class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        yaml_defaults = self.hass.data.get(DOMAIN, {}) or {}

        current_secs = yaml_defaults.get("scan_interval", DEFAULT_SCAN_INTERVAL)
        current_mins = _secs_to_minutes(current_secs)

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
                "scan_interval_minutes",
                description={"suggested_value": current_mins},
            ): NumberMinutesSelector(current_mins),

            # OPNsense (optional)
            vol.Optional("opnsense_url",
                description={"suggested_value": DEFAULT_OPNSENSE_URL}): str,
            vol.Optional("opnsense_key",
                description={"suggested_value": ""}): str,
            vol.Optional("opnsense_secret",
                description={"suggested_value": ""}): str,
            vol.Optional("opnsense_interface",
                description={"suggested_value": DEFAULT_OPNSENSE_IFACE}): str,

            # Directory
            vol.Optional("mac_directory_json_text",
                         description={"suggested_value": ""}): TextSelector(),
            vol.Optional("mac_directory_json_url",
                         description={"suggested_value": ""}): str,
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
            bad = [c for c in cidrs if _cidr_bad(c)]
            if bad:
                errors["ip_range"] = "invalid_ip_range"

        # Minutes 0..1440
        mins = _get_int(user_input, "scan_interval_minutes", current_mins)
        if mins < 0 or mins > 1440:
            errors["scan_interval_minutes"] = "invalid_scan_interval"

        # OPNsense URL consistency
        opn_url = (user_input.get("opnsense_url") or "").strip()
        opn_key = (user_input.get("opnsense_key") or "").strip()
        opn_sec = (user_input.get("opnsense_secret") or "").strip()
        if opn_url and not opn_url.startswith(("http://", "https://")):
            errors["opnsense_url"] = "invalid_url"
        if (opn_key and not opn_sec) or (opn_sec and not opn_key):
            errors["opnsense_key"] = "incomplete_credentials"

        # JSON text
        jtxt = (user_input.get("mac_directory_json_text") or "").strip()
        if jtxt and not _is_dir_json(jtxt):
            errors["mac_directory_json_text"] = "invalid_json"

        if errors:
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        directory = _build_dir(jtxt)

        scan_secs = _minutes_to_secs(mins, DEFAULT_SCAN_INTERVAL)
        data = {
            "ip_range": ipr,
            "nmap_args": (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip(),
            "scan_interval": scan_secs,  # seconds (0 disables auto)
            "mac_directory": directory,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            # OPNsense
            "opnsense_url": opn_url,
            "opnsense_key": opn_key,
            "opnsense_secret": opn_sec,
            "opnsense_interface": (user_input.get("opnsense_interface") or "").strip(),
        }
        return self.async_create_entry(title="Network Scanner Extended", data=data)


class NetworkScannerOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self.entry = entry

    async def async_step_init(self, user_input=None):
        return await self.async_step_user(user_input)

    async def async_step_user(self, user_input=None):
        data = self.entry.data or {}
        opts = self.entry.options or {}

        saved_secs = opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL))
        saved_mins = _secs_to_minutes(saved_secs)

        schema = vol.Schema({
            vol.Required(
                "ip_range",
                description={"suggested_value": opts.get("ip_range", data.get("ip_range", DEFAULT_IP_RANGE))},
            ): str,
            vol.Optional(
                "nmap_args",
                description={"suggested_value": opts.get("nmap_args", data.get("nmap_args", DEFAULT_NMAP_ARGS))},
            ): str,
            vol.Optional(
                "scan_interval_minutes",
                description={"suggested_value": saved_mins},
            ): NumberMinutesSelector(saved_mins),

            # OPNsense
            vol.Optional("opnsense_url",
                description={"suggested_value": opts.get("opnsense_url", data.get("opnsense_url", DEFAULT_OPNSENSE_URL))}): str,
            vol.Optional("opnsense_key",
                description={"suggested_value": "********" if (opts.get('opnsense_key') or data.get('opnsense_key')) else ""}): str,
            vol.Optional("opnsense_secret",
                description={"suggested_value": "********" if (opts.get('opnsense_secret') or data.get('opnsense_secret')) else ""}): str,
            vol.Optional("opnsense_interface",
                description={"suggested_value": opts.get("opnsense_interface", data.get("opnsense_interface", DEFAULT_OPNSENSE_IFACE))}): str,

            # Directory
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

        ipr = (user_input.get("ip_range") or "").strip()
        cidrs = _split_cidrs(ipr)
        if not cidrs or any(_cidr_bad(c) for c in cidrs):
            errors["ip_range"] = "invalid_ip_range"

        mins = _get_int(user_input, "scan_interval_minutes", saved_mins)
        if mins < 0 or mins > 1440:
            errors["scan_interval_minutes"] = "invalid_scan_interval"

        opn_url = (user_input.get("opnsense_url") or "").strip()
        opn_key = (user_input.get("opnsense_key") or "").strip()
        opn_sec = (user_input.get("opnsense_secret") or "").strip()
        if opn_url and not opn_url.startswith(("http://", "https://")):
            errors["opnsense_url"] = "invalid_url"
        if (opn_key and not opn_sec) or (opn_sec and not opn_key):
            errors["opnsense_key"] = "incomplete_credentials"

        jtxt = (user_input.get("mac_directory_json_text") or "").strip()
        if jtxt and not _is_dir_json(jtxt):
            errors["mac_directory_json_text"] = "invalid_json"

        if errors:
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        scan_secs = _minutes_to_secs(mins, DEFAULT_SCAN_INTERVAL)
        return self.async_create_entry(title="", data={
            "ip_range": ipr,
            "nmap_args": (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip(),
            "scan_interval": scan_secs,
            "mac_directory_json_text": jtxt,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            "opnsense_url": opn_url,
            "opnsense_key": opn_key,
            "opnsense_secret": opn_sec,
            "opnsense_interface": (user_input.get("opnsense_interface") or "").strip(),
        })


# ---- helpers (private) ----

def _cidr_bad(c: str) -> bool:
    try:
        ip_network(c, strict=False)
        return False
    except Exception:
        return True

def _get_int(src: dict, key: str, default_val: int) -> int:
    try:
        return int(src.get(key, default_val))
    except Exception:
        return default_val

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
            mk = _normalise_mac_key(k)
            if not mk:
                continue
            if isinstance(v, dict):
                out[mk] = {"name": str(v.get("name", "")), "desc": str(v.get("desc", ""))}
            else:
                out[mk] = {"name": str(v), "desc": ""}
    return out

async def async_get_options_flow(config_entry: config_entries.ConfigEntry):
    return NetworkScannerOptionsFlow(config_entry)
