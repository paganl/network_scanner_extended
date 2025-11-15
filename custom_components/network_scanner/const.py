# custom_components/network_scanner/const.py
from __future__ import annotations

DOMAIN = "network_scanner"

# Provider selection
CONF_PROVIDER = "provider"
PROVIDER_OPNSENSE = "opnsense"
PROVIDER_UNIFI = "unifi"
PROVIDER_ADGUARD = "adguard"
PROVIDER_OPNSENSE_UNIFI = "opnsense_unifi"

# Per-provider URLs
CONF_OPNSENSE_URL = "opnsense_url"
CONF_UNIFI_URL = "unifi_url"
CONF_ADGUARD_URL = "adguard_url"

# Auth + creds
CONF_AUTH_MODE = "auth_mode"        # how we authenticate to UniFi
AUTH_MODE_PASSWORD = "password"     # preferred name
AUTH_MODE_TOKEN = "token"

# ---- Backward-compat shims (legacy names some flows still import) ----
AUTH_MODE_USERPASS = AUTH_MODE_PASSWORD   # legacy alias -> keep imports working

# Credentials/keys
CONF_KEY = "key"            # OPNsense API key
CONF_SECRET = "secret"      # OPNsense API secret
CONF_NAME = "username"      # UniFi / AdGuard username
CONF_PASSWORD = "password"  # UniFi / AdGuard password
CONF_TOKEN = "token"        # UniFi API token

# Common options
CONF_VERIFY_SSL = "verify_ssl"
CONF_INTERVAL_MIN = "interval_minutes"

DEFAULT_OPTIONS = {
    CONF_PROVIDER: PROVIDER_OPNSENSE,
    CONF_VERIFY_SSL: False,
    CONF_INTERVAL_MIN: 3,
}
