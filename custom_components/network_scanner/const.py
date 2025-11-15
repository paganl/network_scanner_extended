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

# Auth mode (used by config_flow)
CONF_AUTH_MODE: Final = "auth_mode"
AUTH_MODE_PASSWORD: Final = "password"
AUTH_MODE_TOKEN: Final = "token"

# Misc options
CONF_VERIFY_SSL: Final = "verify_ssl"
CONF_INTERVAL_MIN: Final = "interval_min"

# Defaults used by coordinator
DEFAULT_OPTIONS: Dict[str, Any] = {
    CONF_PROVIDER: "opnsense",       # "opnsense" | "unifi" | "adguard" | "opnsense_unifi"
    CONF_VERIFY_SSL: False,
    CONF_INTERVAL_MIN: 3,
}

# Heuristic constant
ASSUMED_ARP_TTL_S: Final = 1200

# Optional helper tuples your config_flow may import
PROVIDERS: tuple[str, ...] = ("opnsense", "unifi", "adguard", "opnsense_unifi")
AUTH_MODES: tuple[str, ...] = (AUTH_MODE_PASSWORD, AUTH_MODE_TOKEN)
