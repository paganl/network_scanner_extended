# custom_components/network_scanner/const.py
"""Constants for Network Scanner (summary sensor + device_trackers)."""

from __future__ import annotations

DOMAIN = "network_scanner"
INTEGRATION_VERSION = "0.21.0"

PLATFORMS: list[str] = ["sensor", "device_tracker"]

# ---- Config keys ----
CONF_SCAN_INTERVAL_MIN = "scan_interval_min"
CONF_VERIFY_SSL = "verify_ssl"

# Presence provider (pick ONE)
CONF_PRESENCE_PROVIDER = "presence_provider"
PRESENCE_OPNSENSE = "opnsense"
PRESENCE_ADGUARD = "adguard"
PRESENCE_PROVIDER_OPTIONS = [PRESENCE_OPNSENSE, PRESENCE_ADGUARD]

# Optional UniFi enrichment
CONF_UNIFI_ENABLED = "unifi_enabled"
CONF_UNIFI_URL = "unifi_url"
CONF_UNIFI_TOKEN = "unifi_token"
CONF_UNIFI_USERNAME = "unifi_username"
CONF_UNIFI_PASSWORD = "unifi_password"
CONF_UNIFI_SITE = "unifi_site"

# OPNsense creds
CONF_OPNSENSE_URL = "opnsense_url"
CONF_OPNSENSE_KEY = "opnsense_key"
CONF_OPNSENSE_SECRET = "opnsense_secret"
CONF_OPNSENSE_INTERFACE = "opnsense_interface"

# AdGuard creds
CONF_ADGUARD_URL = "adguard_url"
CONF_ADGUARD_USERNAME = "adguard_username"
CONF_ADGUARD_PASSWORD = "adguard_password"

# Directory overlay
CONF_MAC_DIRECTORY_JSON_URL = "mac_directory_json_url"
CONF_MAC_DIRECTORY_JSON_TEXT = "mac_directory_json_text"

DEFAULT_OPTIONS = {
    CONF_SCAN_INTERVAL_MIN: 3,
    CONF_VERIFY_SSL: False,
    CONF_PRESENCE_PROVIDER: PRESENCE_OPNSENSE,
    CONF_UNIFI_ENABLED: False,
    CONF_UNIFI_SITE: "default",
    CONF_OPNSENSE_INTERFACE: "",
    CONF_MAC_DIRECTORY_JSON_URL: "",
    CONF_MAC_DIRECTORY_JSON_TEXT: "",
}

# ---- Services ----
SERVICE_SCAN_NOW = "scan_now"
SERVICE_CLEANUP = "cleanup"

ATTR_MODE = "mode"
ATTR_OLDER_THAN_DAYS = "older_than_days"

CLEANUP_MODE_ALL = "all"
CLEANUP_MODE_RANDOM_ONLY = "random_only"
CLEANUP_MODE_STALE_ONLY = "stale_only"

DEFAULT_CLEANUP_OLDER_THAN_DAYS = 14

# ---- Events ----
EVENT_DEVICE_NEW = "network_scanner_device_new"
EVENT_DEVICE_NEW_RANDOM = "network_scanner_device_new_random_mac"
EVENT_SCAN_ERROR = "network_scanner_scan_error"
