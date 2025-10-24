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
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_NMAP_ARGS,
    # Providers
    CONF_ARP_PROVIDER, ARP_PROVIDERS, DEFAULT_ARP_PROVIDER,
    # OPNsense
    DEFAULT_OPNSENSE_URL, DEFAULT_OPNSENSE_IFACE,
    # AdGuard
    DEFAULT_ADGUARD_URL,
    CONF_ADG_URL, CONF_ADG_USER, CONF_ADG_PASS,   # <-- keep as constants
    # TLS verify
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
    return bool(s and _FORBIDDEN_NMAP_CHARS.search(s))

# ---------- selectors ----------

try:
    from homeassistant.helpers.selector import selector as ha_selector
    def TextSelector():
        return ha_selector({"text": {"multiline": True}})
    def MinutesNumberSelector():
        return ha_selector({
            "number": {"min": 0, "max": 1440, "step": 1, "mode": "box", "unit_of_measurement": "min"}
        })
except Exception:
    def TextSelector(): return str
    def MinutesNumberSelector(): return int

# ---------- Config Flow ----------

class NetworkScannerConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        yaml_defaults = self.hass.data.get(DOMAIN, {}) or {}
        current_secs = yaml_defaults.get("scan_interval", DEFAULT_SCAN_INTERVAL)
        current_mins = _secs_to_minutes(current_secs)

        schema = vol.Schema({
            vol.Required("ip_range",
                description={"suggested_value": yaml_defaults.get("ip_range", DEFAULT_IP_RANGE)}): str,
            vol.Optional("nmap_args",
                description={"suggested_value": DEFAULT_NMAP_ARGS}): str,
            vol.Optional("scan_interval_minutes",
                description={"suggested_value": current_mins}): MinutesNumberSelector(),

            # Provider choice
            vol.Optional(CONF_ARP_PROVIDER,
                description={"suggested_value": DEFAULT_ARP_PROVIDER}): vol.In(ARP_PROVIDERS),

            # OPNsense
            vol.Optional("opnsense_url",
                description={"suggested_value": DEFAULT_OPNSENSE_URL}): str,
            vol.Optional("opnsense_key",    description={"suggested_value": ""}): str,
            vol.Optional("opnsense_secret", description={"suggested_value": ""}): str,
            vol.Optional("opnsense_interface",
                description={"suggested_value": DEFAULT_OPNSENSE_IFACE}): str,

            # AdGuard (use constant keys for storage later)
            vol.Optional(CONF_ADG_URL,
                description={"suggested_value": DEFAULT_ADGUARD_URL}): str,
            vol.Optional(CONF_ADG_USER,    description={"suggested_value": ""}): str,
            vol.Optional(CONF_ADG_PASS,    description={"suggested_value": ""}): str,

            # TLS verify (applies to HTTP providers)
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
        if not cidrs or any(_cidr_bad(c) for c in cidrs):
            errors["ip_range"] = "invalid_ip_range"

        # Minutes 0..1440
        mins = _get_int(user_input, "scan_interval_minutes", current_mins)
        if mins < 0 or mins > 1440:
            errors["scan_interval_minutes"] = "invalid_scan_interval"

        # nmap args sanity
        nmap_args = (user_input.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        if _nmap_args_invalid(nmap_args):
            errors["nmap_args"] = "invalid_nmap_args"

        provider = user_input.get(CONF_ARP_PROVIDER, DEFAULT_ARP_PROVIDER)

        # Provider-aware URL/creds validation
        def _chk_url_val(val: str) -> bool:
            return bool(val.startswith(("http://", "https://")))

        # OPNsense only if chosen
        opn_url = (user_input.get("opnsense_url") or "").strip()
        opn_key = (user_input.get("opnsense_key") or "").strip()
        opn_sec = (user_input.get("opnsense_secret") or "").strip()
        opn_iface = (user_input.get("opnsense_interface") or "").strip()
        if provider == "opnsense":
            if opn_url and not _chk_url_val(opn_url):
                errors["opnsense_url"] = "invalid_url"
            if (opn_key and not opn_sec) or (opn_sec and not opn_key):
                errors["opnsense_key"] = "incomplete_credentials"

        # AdGuard only if chosen (use constant keys)
        ag_url = (user_input.get(CONF_ADG_URL) or "").strip()
        ag_user = (user_input.get(CONF_ADG_USER) or "").strip()
        ag_pass = (user_input.get(CONF_ADG_PASS) or "").strip()
        if provider == "adguard":
            if ag_url and not _chk_url_val(ag_url):
                errors[CONF_ADG_URL] = "invalid_url"
            if (ag_user and not ag_pass) or (ag_pass and not ag_user):
                errors[CONF_ADG_USER] = "incomplete_credentials"

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
            "scan_interval": scan_secs,
            "mac_directory": directory,
            "mac_directory_json_url": (user_input.get("mac_directory_json_url") or "").strip(),
            CONF_ARP_PROVIDER: provider,
            CONF_ARP_VERIFY_TLS: bool(user_input.get(CONF_ARP_VERIFY_TLS, False)),
        }

        # Store only the chosen provider’s fields
        if provider == "opnsense":
            data.update({
                "opnsense_url": opn_url,
                "opnsense_key": opn_key,
                "opnsense_secret": opn_sec,
                "opnsense_interface": opn_iface,
            })
        elif provider == "adguard":
            data.update({
                CONF_ADG_URL: ag_url,
                CONF_ADG_USER: ag_user,
                CONF_ADG_PASS: ag_pass,
            })

        return self.async_create_entry(title="Network Scanner Extended", data=data)

# ---------- Options Flow ----------

class NetworkScannerOptionsFlow(OptionsFlow):
    def __init__(self, entry: ConfigEntry) -> None:
        self.entry = entry

    a
