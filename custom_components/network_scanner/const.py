# custom_components/network_scanner/const.py
from __future__ import annotations

DOMAIN: str = "network_scanner"

# --- Defaults ---
DEFAULT_IP_RANGE = ""  # empty -> skip nmap entirely
DEFAULT_NMAP_ARGS = "-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4"
DEFAULT_SCAN_INTERVAL_MINUTES = 4  # minutes

# --- Providers ---
CONF_ARP_PROVIDER = "arp_provider"
ARP_PROVIDER_NONE = "none"
ARP_PROVIDER_OPNSENSE = "opnsense"
ARP_PROVIDER_ADGUARD = "adguard"
ARP_PROVIDER_UNIFI = "unifi"
ARP_PROVIDERS = [
    ARP_PROVIDER_NONE,
    ARP_PROVIDER_OPNSENSE,
    ARP_PROVIDER_ADGUARD,
    ARP_PROVIDER_UNIFI,
]
DEFAULT_ARP_PROVIDER = ARP_PROVIDER_NONE

# TLS verify toggle for HTTP providers
CONF_ARP_VERIFY_TLS = "arp_verify_tls"

# --- OPNsense ---
DEFAULT_OPNSENSE_URL = "https://10.0.0.2"
DEFAULT_OPNSENSE_IFACE = ""  # e.g., "lan"
# We probe endpoints dynamically; leaving paths here for clarity
OPNSENSE_ARP_PATH = "/api/diagnostics/interface/search_arp"

# --- AdGuard Home (running in HA or external) ---
DEFAULT_ADGUARD_URL = "http://127.0.0.1:3000"
CONF_ADG_URL = "adguard_url"
CONF_ADG_USER = "adguard_key"      # keep legacy naming to match your flow
CONF_ADG_PASS = "adguard_secret"

# --- UniFi Network ---
CONF_UNIFI_ENABLED = "unifi_enabled"
DEFAULT_UNIFI_URL = "https://unifi.local"
DEFAULT_UNIFI_SITE = "default"
CONF_UNIFI_URL = "unifi_url"
CONF_UNIFI_USER = "unifi_username"
CONF_UNIFI_PASS = "unifi_password"
CONF_UNIFI_SITE = "unifi_site"

# Card-friendly status strings
STATUS_IDLE = "idle"
STATUS_SCANNING = "scanning"
STATUS_ENRICHING = "enriching"
STATUS_OK = "ok"
STATUS_ERROR = "error"

# Phases
PHASE_IDLE = "idle"
PHASE_ARP = "arp"
PHASE_NMAP = "nmap"

# Dispatcher signal so sensors can update immediately on publish
SIGNAL_NSX_UPDATED = "network_scanner_extended_updated"

# Internal schema version (not stored) to track templates/docs
SCHEMA_VERSION = 2
