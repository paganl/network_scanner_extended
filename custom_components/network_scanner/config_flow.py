from __future__ import annotations
import json
import logging
import re
from ipaddress import ip_network
from typing import Dict

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

# ---------- helpers ----------

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

# ---------- selectors (safe) ----------

try:
    from homeassistant.helpers.selector import selector as ha_selector
    def TextSelector():
        # Only constraints; defaults/suggested values go in schema.description
        return ha_selector({"text": {"multiline": True}})
    def MinutesNumberSelector():
        # No non-standard keys; just constraints.
        return ha_selector({"number": {
            "min": 0, "max": 1440, "step": 1, "mode": "box",
            "unit_of_measurement": "min"
        }})
except Exception:
    # Fallbacks for older cores
    def TextSelector():
        return str
    def MinutesNumberSelector():
        return int

# ---------- Config Flow ----------

class NetworkScannerConfigF
