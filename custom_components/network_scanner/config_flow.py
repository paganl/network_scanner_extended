# custom_components/network_scanner/config_flow.py
from __future__ import annotations

import json
import logging
import re
from ipaddress import ip_network
from typing import Dict

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, OptionsFlow, ConfigEntry

from .const import (
    DOMAIN,
    DEFAULT_IP_RANGE,
    DEFAULT_SCAN_INTERVAL,   # seconds
    DEFAULT_NMAP_ARGS,
    # ARP provider bits
    CONF_ARP_PROVIDER,
    ARP_PROVIDERS,
    DEFAULT_ARP_PROVIDER,
    # OPNsense
    DEFAULT_OPNSENSE_URL,
    DEFAULT_OPNSENSE_IFACE,
    CONF_ARP_VERIFY_TLS,
)

_LOGGER = logging.getLogger(__name__)

# ---------- helpers ----------

_FORBIDDEN_NMAP_CHARS = re.compile(r"[;&|`$><]")

def _secs_to_minutes(secs: int | None) -> int:
    if not isinstance(secs, int) or secs < 0:
        return 0
    return max(0, round(secs / 60))

def _minutes_to_secs(mins: int | None, default_secs: int) -> int:
    if not isinstance(mins, int) or mins < 0:
        return default_secs
    return 0 if mins == 0 else mins * 60

def _split_cidrs(s: str) -> list[str]:
    # split on commas or whitespace
    return [p.strip() for p in re.split(r"[,\s]+", s or "") if p.strip()]

def _normalise_mac_key(mac: str) -> str:
    return mac.upper() if isinstance(mac, str) else ""

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

def _nmap_args_invalid(s: str) -> bool:
    if not s:
        return False
    return bool(_FORBIDDEN_NMAP_CHARS.search(s))

# ---------- selectors (safe) ----------

try:
    from homeassistant.helpers.selector import selector as ha_selector

    def TextSelector():
        # Only constraints; defaults/suggested values go in schema.description
        return ha_selector({"text": {"multiline": True}})

    def MinutesNumberSelector():
        # Constraints only—no unsupported keys like "value"
        return ha_selector({
            "number": {
                "min": 0,
                "max": 1440,
                "step": 1,
                "mode": "box",
                "unit_of_measurement": "min",
            }
        })
except Exception:
    # Fallbacks for older cores
    def TextSelector():
        return str
    def MinutesNumberSelector():
        return int

# ---------- Config Flow ----------

class NetworkScannerConfigFlow(ConfigFlow, domain=DOMAIN):
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
            ): MinutesNumberSelector(),

            # ARP provider (none/opnsense)
            vol.Optional(
                CONF_ARP_PROVIDER,
                description={"suggested_value": DEFAULT_ARP_PROVIDER},
            ): vol.In(ARP_PROVIDERS),

            # OPNsense (optional)
            vol.Optional("opnsense_url",
                description={"suggested_value": DEFAULT_OPNSENSE_URL}): str,
            vol.Optional("opnsense_key",
                description={"suggested_value": ""}): str,
            vol.Optional("opnsense_secret",
                description={"suggested_value": ""}): str,
            vol.Optional("opnsense_interface",
                description={"suggested_value": DEFAULT_OPNSENSE_IFACE}): str,
            vol.Optional(CONF_ARP_VERIFY_TLS,
                description={"suggested_value": False}): bool,

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

        # nmap args sanity
        nmap_args = (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        if _nmap_args_invalid(nmap_args):
            errors["nmap_args"] = "invalid_nmap_args"

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
            "nmap_args": nmap_args,
            "scan_interval": scan_secs,  # seconds (0 disables auto)
            "mac_directory": directory,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),

            # ARP provider
            CONF_ARP_PROVIDER: user_input.get(CONF_ARP_PROVIDER, DEFAULT_ARP_PROVIDER),

            # OPNsense
            "opnsense_url": opn_url,
            "opnsense_key": opn_key,
            "opnsense_secret": opn_sec,
            "opnsense_interface": (user_input.get("opnsense_interface") or "").strip(),
            CONF_ARP_VERIFY_TLS: bool(user_input.get(CONF_ARP_VERIFY_TLS, False)),
        }
        return self.async_create_entry(title="Network Scanner Extended", data=data)

# ---------- Options Flow ----------

class NetworkScannerOptionsFlow(OptionsFlow):
    def __init__(self, entry: ConfigEntry) -> None:
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
            ): MinutesNumberSelector(),

            # ARP provider (ensure it appears in options too)
            vol.Optional(
                CONF_ARP_PROVIDER,
                description={"suggested_value": opts.get(CONF_ARP_PROVIDER, data.get(CONF_ARP_PROVIDER, DEFAULT_ARP_PROVIDER))},
            ): vol.In(ARP_PROVIDERS),

            # OPNsense
            vol.Optional("opnsense_url",
                description={"suggested_value": opts.get("opnsense_url", data.get("opnsense_url", DEFAULT_OPNSENSE_URL))}): str,
            vol.Optional("opnsense_key",
                description={"suggested_value": "********" if (opts.get('opnsense_key') or data.get('opnsense_key')) else ""}): str,
            vol.Optional("opnsense_secret",
                description={"suggested_value": "********" if (opts.get('opnsense_secret') or data.get('opnsense_secret')) else ""}): str,
            vol.Optional("opnsense_interface",
                description={"suggested_value": opts.get("opnsense_interface", data.get("opnsense_interface", DEFAULT_OPNSENSE_IFACE))}): str,
            vol.Optional(CONF_ARP_VERIFY_TLS,
                description={"suggested_value": opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, False))}): bool,

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

        # nmap args sanity
        nmap_args = (user_input.get("nmap_args") or opts.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        if _nmap_args_invalid(nmap_args):
            errors["nmap_args"] = "invalid_nmap_args"

        # Handle OPNsense URL + placeholder secrets
        prev_key = opts.get("opnsense_key") or data.get("opnsense_key", "")
        prev_sec = opts.get("opnsense_secret") or data.get("opnsense_secret", "")

        opn_url = (user_input.get("opnsense_url") or "").strip()
        key_in  = (user_input.get("opnsense_key") or "").strip()
        sec_in  = (user_input.get("opnsense_secret") or "").strip()
        opn_key = prev_key if key_in == "********" else key_in
        opn_sec = prev_sec if sec_in == "********" else sec_in

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
            "nmap_args": nmap_args,
            "scan_interval": scan_secs,  # seconds; 0 disables auto-scan
            # persist provider in OPTIONS too
            CONF_ARP_PROVIDER: user_input.get(
                CONF_ARP_PROVIDER,
                opts.get(CONF_ARP_PROVIDER, data.get(CONF_ARP_PROVIDER, DEFAULT_ARP_PROVIDER)),
            ),
            "mac_directory_json_text": jtxt,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            "opnsense_url": opn_url,
            "opnsense_key": opn_key,
            "opnsense_secret": opn_sec,
            "opnsense_interface": (user_input.get("opnsense_interface") or "").strip(),
            CONF_ARP_VERIFY_TLS: bool(user_input.get(CONF_ARP_VERIFY_TLS, opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, False)))),
        })

async def async_get_options_flow(config_entry: ConfigEntry):
    return NetworkScannerOptionsFlow(config_entry)
