# custom_components/network_scanner/const.py

DEFAULT_SCAN_INTERVAL_MINUTES = 5
DEFAULT_IP_RANGE = "10.0.0.0/24"

CONF_ARP_PROVIDER   = "arp_provider"
ARP_PROVIDER_NONE   = "none"
ARP_PROVIDER_OPNSENSE = "opnsense"
ARP_PROVIDER_ADGUARD  = "adguard"

CONF_ARP_VERIFY_TLS = "arp_verify_tls"

# Status & phase (for UI)
STATUS_IDLE = "idle"
STATUS_SCANNING = "scanning"
STATUS_ENRICHING = "enriching"
STATUS_OK = "ok"
STATUS_ERROR = "error"

PHASE_IDLE = "idle"
PHASE_ARP = "arp"

# Dispatcher signal
SIGNAL_NSX_UPDATED = "nsx_updated"

# AdGuard
CONF_ADG_URL  = "adguard_url"
CONF_ADG_USER = "adguard_user"
CONF_ADG_PASS = "adguard_pass"

# UniFi
CONF_UNIFI_ENABLED = "unifi_enabled"
CONF_UNIFI_URL  = "unifi_url"
CONF_UNIFI_USER = "unifi_user"
CONF_UNIFI_PASS = "unifi_pass"
CONF_UNIFI_SITE = "unifi_site"
