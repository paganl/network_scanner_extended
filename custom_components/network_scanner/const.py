from __future__ import annotations

DOMAIN = "network_scanner"

# ---------------- Defaults (schema v2 uses minutes) ----------------
DEFAULT_IP_RANGE = ""
DEFAULT_SCAN_INTERVAL_MINUTES = 5          # minutes
DEFAULT_NMAP_ARGS = "-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4"                  # host discovery only; empty string disables nmap
DEFAULT_OPNSENSE_URL = "https://10.0.0.2"
DEFAULT_OPNSENSE_IFACE = ""                # optional filter
DEFAULT_ADGUARD_URL = "http://10.0.0.1:3000"

# UniFi defaults
DEFAULT_UNIFI_URL = "https://10.0.0.3"     # set port if you run behind non-standard proxy, e.g. :4334
DEFAULT_UNIFI_SITE = "default"

# ---------------- Providers ----------------
CONF_ARP_PROVIDER = "arp_provider"
ARP_PROVIDER_NONE = "none"
ARP_PROVIDER_OPNSENSE = "opnsense"
ARP_PROVIDER_ADGUARD = "adguard"
ARP_PROVIDER_UNIFI = "unifi"  # retained for backwards compat (not used as a selector now)
ARP_PROVIDERS = [ARP_PROVIDER_NONE, ARP_PROVIDER_OPNSENSE, ARP_PROVIDER_ADGUARD]
DEFAULT_ARP_PROVIDER = ARP_PROVIDER_OPNSENSE

# TLS verify toggle for HTTP providers
CONF_ARP_VERIFY_TLS = "arp_verify_tls"

# AdGuard
CONF_ADG_URL  = "adguard_url"
CONF_ADG_USER = "adguard_user"
CONF_ADG_PASS = "adguard_pass"

# UniFi enrichment (independent of ARP provider)
CONF_UNIFI_ENABLED = "unifi_enabled"
CONF_UNIFI_URL  = "unifi_url"
CONF_UNIFI_USER = "unifi_user"
CONF_UNIFI_PASS = "unifi_pass"
CONF_UNIFI_SITE = "unifi_site"

# ---------------- Status / Phase / Signals ----------------
STATUS_IDLE = "idle"
STATUS_SCANNING = "scanning"
STATUS_ENRICHING = "enriching"
STATUS_OK = "ok"
STATUS_ERROR = "error"

PHASE_IDLE = "idle"
PHASE_ARP = "arp"
PHASE_NMAP = "nmap"

SIGNAL_NSX_UPDATED = "network_scanner_updated"
