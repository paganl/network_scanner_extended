"""Constants for the Network Scanner integration (coordinator-only)."""

from __future__ import annotations

DOMAIN = "network_scanner"
INTEGRATION_VERSION = "0.30.0"

# ---- Config keys ----
CONF_PROVIDERS = "providers"          # list[str]
CONF_VERIFY_SSL = "verify_ssl"
CONF_INTERVAL_MIN = "interval_min"

# Provider enablement
PROVIDER_OPNSENSE = "opnsense"
PROVIDER_UNIFI = "unifi"
PROVIDER_ADGUARD = "adguard"

PROVIDER_OPTIONS = [PROVIDER_OPNSENSE, PROVIDER_UNIFI, PROVIDER_ADGUARD]

# OPNsense
CONF_OPNSENSE_URL = "opnsense_url"
CONF_KEY = "key"
CONF_SECRET = "secret"

# UniFi
CONF_UNIFI_URL = "unifi_url"
CONF_UNIFI_TOKEN = "token"
CONF_UNIFI_USER = "username"
CONF_UNIFI_PASS = "password"
CONF_UNIFI_SITE = "site"

# AdGuard
CONF_ADGUARD_URL = "adguard_url"
CONF_ADGUARD_USER = "username"
CONF_ADGUARD_PASS = "password"

# Directory overlay
CONF_MAC_DIRECTORY_JSON_URL = "mac_directory_json_url"
CONF_MAC_DIRECTORY_JSON_TEXT = "mac_directory_json_text"

DEFAULT_OPTIONS = {
    CONF_PROVIDERS: [PROVIDER_OPNSENSE],
    CONF_VERIFY_SSL: True,
    CONF_INTERVAL_MIN: 3,
    CONF_UNIFI_SITE: "default",
    CONF_MAC_DIRECTORY_JSON_URL: "",
    CONF_MAC_DIRECTORY_JSON_TEXT: "",
}

# ---- Events / services ----
EVENT_RANDOM_MAC_DETECTED = f"{DOMAIN}_random_mac_detected"
EVENT_NEW_DEVICE_DETECTED = f"{DOMAIN}_new_device_detected"

SERVICE_RESCan = "rescan"
SERVICE_CLEANUP = "cleanup_entities"

# ---- Internal ----
STORE_VERSION = 1
STALE_HOURS = 24
