# custom_components/network_scanner/const.py
"""Constants for the Network Scanner integration."""

from __future__ import annotations

# -------- Integration id/version --------
DOMAIN = "network_scanner"
INTEGRATION_VERSION = "0.15.0"

# -------- High-level provider modes (used by config_flow/coordinator) --------
PROVIDER_OPNSENSE = "opnsense"
PROVIDER_UNIFI = "unifi"
PROVIDER_ADGUARD = "adguard"
PROVIDER_OPNSENSE_UNIFI = "opnsense_unifi"
CONF_MAC_DIRECTORY_JSON_URL = "mac_directory.json"

PROVIDER_OPTIONS = [
    PROVIDER_OPNSENSE,
    PROVIDER_UNIFI,
    PROVIDER_ADGUARD,
    PROVIDER_OPNSENSE_UNIFI,
]

# -------- Generic options (coordinator/config_flow) --------
CONF_PROVIDER     = "provider"
CONF_VERIFY_SSL   = "verify_ssl"     # TLS verify toggle
CONF_INTERVAL_MIN = "interval_min"   # minutes between refreshes
CONF_SITE         = "site"           # UniFi site (default: "default")

# OPNsense (key/secret user)
CONF_OPNSENSE_URL = "opnsense_url"
CONF_KEY          = "key"
CONF_SECRET       = "secret"

# UniFi (prefer token; else username/password)
CONF_UNIFI_URL    = "unifi_url"
CONF_UNIFI_TOKEN  = "token"
CONF_UNIFI_SITE   = CONF_SITE    # backward-compat 
CONF_TOKEN        = CONF_UNIFI_TOKEN # backwards-compat alias for coordinator
CONF_NAME         = "username"   # generic username (kept for b/w compat)
CONF_PASSWORD     = "password"   # generic password (kept for b/w compat)

# AdGuard (username/password)
CONF_ADGUARD_URL = "adguard_url"
# Some modules use short names — keep aliases pointing to same keys
CONF_ADG_URL  = CONF_ADGUARD_URL
CONF_ADG_USER = CONF_NAME       # "username"
CONF_ADG_PASS = CONF_PASSWORD   # "password"

# UniFi short-form keys used by ScanController
CONF_UNIFI_ENABLED = "unifi_enabled"
CONF_UNIFI_USER    = "unifi_username"
CONF_UNIFI_PASS    = "unifi_password"
CONF_UNIFI_SITE    = "unifi_site"

# -------- ARP provider (used by ScanController) --------
CONF_ARP_PROVIDER   = "arp_provider"
ARP_PROVIDER_NONE    = "none"
ARP_PROVIDER_OPNSENSE = "opnsense"
ARP_PROVIDER_ADGUARD  = "adguard"
CONF_ARP_VERIFY_TLS  = "verify_tls"   # TLS verify for ARP/DHCP fetches

# -------- Scan defaults (used by ScanController) --------
DEFAULT_IP_RANGE                 = ""                 # empty = no active sweep
DEFAULT_NMAP_ARGS                = "-sn -PE -n"      # harmless defaults if enabled
DEFAULT_SCAN_INTERVAL_MINUTES    = 10

# -------- Controller status/phase (used by ScanController & UI) --------
STATUS_IDLE       = "idle"        # not doing anything
STATUS_SCANNING   = "scanning"    # actively collecting data
STATUS_ENRICHING  = "enriching"   # merging/applying directory overlays
STATUS_OK         = "ok"          # last run completed successfully
STATUS_ERROR      = "error"       # last run failed

PHASE_IDLE        = "idle"
PHASE_ARP         = "arp"         # ARP/DHCP/UniFi stage
PHASE_NMAP        = "nmap"        # optional (safe to keep even if nmap disabled)

# -------- Dispatcher signal (for UI/cards to subscribe) --------
SIGNAL_NSX_UPDATED = f"{DOMAIN}_updated"

# -------- Defaults for coordinator-based path (kept for compatibility) --------
DEFAULT_OPTIONS = {
    CONF_PROVIDER: PROVIDER_OPNSENSE,
    CONF_VERIFY_SSL: False,
    CONF_INTERVAL_MIN: 3,
    CONF_SITE: "default",
}

__all__ = [
    "DOMAIN", "INTEGRATION_VERSION",
    "PROVIDER_OPNSENSE", "PROVIDER_UNIFI", "PROVIDER_ADGUARD", "PROVIDER_OPNSENSE_UNIFI",
    "PROVIDER_OPTIONS",
    "CONF_PROVIDER", "CONF_VERIFY_SSL", "CONF_INTERVAL_MIN", "CONF_SITE",
    "CONF_OPNSENSE_URL", "CONF_KEY", "CONF_SECRET",
    "CONF_UNIFI_URL", "CONF_TOKEN", "CONF_NAME", "CONF_PASSWORD",
    "CONF_ADGUARD_URL", "CONF_ADG_URL", "CONF_ADG_USER", "CONF_ADG_PASS",
    "CONF_UNIFI_ENABLED", "CONF_UNIFI_USER", "CONF_UNIFI_PASS", "CONF_UNIFI_SITE",
    "CONF_ARP_PROVIDER", "ARP_PROVIDER_NONE", "ARP_PROVIDER_OPNSENSE", "ARP_PROVIDER_ADGUARD",
    "CONF_ARP_VERIFY_TLS",
    "DEFAULT_IP_RANGE", "DEFAULT_NMAP_ARGS", "DEFAULT_SCAN_INTERVAL_MINUTES",
    "STATUS_IDLE", "STATUS_SCANNING", "STATUS_ENRICHING", "STATUS_OK", "STATUS_ERROR",
    "PHASE_IDLE", "PHASE_ARP", "PHASE_NMAP",
    "SIGNAL_NSX_UPDATED",
    "DEFAULT_OPTIONS",
]
