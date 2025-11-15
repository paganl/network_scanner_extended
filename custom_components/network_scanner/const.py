# custom_components/network_scanner/const.py
from __future__ import annotations
from typing import Final, Dict, Any

DOMAIN: Final = "network_scanner"
INTEGRATION_NAME: Final = "Network Scanner Extended (Lean)"
VERSION: Final = "0.14.4"

# Provider + URLs
CONF_PROVIDER: Final = "provider"
CONF_URL: Final = "url"  # legacy catch-all (migration only)
CONF_OPNSENSE_URL: Final = "opnsense_url"
CONF_UNIFI_URL: Final = "unifi_url"
CONF_ADGUARD_URL: Final = "adguard_url"

# Auth fields
CONF_KEY: Final = "key"            # OPNsense API key
CONF_SECRET: Final = "secret"      # OPNsense API secret
CONF_NAME: Final = "name"          # Username (UniFi/AdGuard)
CONF_PASSWORD: Final = "password"
CONF_TOKEN: Final = "token"        # UniFi API token

# Misc options
CONF_VERIFY_SSL: Final = "verify_ssl"
CONF_INTERVAL_MIN: Final = "interval_min"

# Defaults used by coordinator
DEFAULT_OPTIONS: Dict[str, Any] = {
    CONF_PROVIDER: "opnsense",       # "opnsense" | "unifi" | "adguard" | "opnsense_unifi"
    CONF_VERIFY_SSL: False,
    CONF_INTERVAL_MIN: 3,
}

# Heuristic constant (kept for potential use)
ASSUMED_ARP_TTL_S: Final = 1200
