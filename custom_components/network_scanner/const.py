# custom_components/network_scanner/const.py
from __future__ import annotations

DOMAIN: str = "network_scanner"

# Default UI values
DEFAULT_IP_RANGE = "192.168.1.0/24"

# Default nmap args that work across routed networks (not just ARP)
DEFAULT_NMAP_ARGS = "-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4"

# Default scan interval in seconds
DEFAULT_SCAN_INTERVAL = 240

# ARP enrichment settings
CONF_ARP_PROVIDER   = "arp_provider"
CONF_ARP_BASE_URL   = "arp_base_url"   # reserved
CONF_ARP_KEY        = "arp_key"
CONF_ARP_SECRET     = "arp_secret"
CONF_ARP_VERIFY_TLS = "arp_verify_tls"

# Providers
ARP_PROVIDER_NONE      = "none"
ARP_PROVIDER_OPNSENSE  = "opnsense"
ARP_PROVIDER_ADGUARD   = "adguard"     # NEW
ARP_PROVIDERS = [ARP_PROVIDER_NONE, ARP_PROVIDER_OPNSENSE, ARP_PROVIDER_ADGUARD]

# OPNsense defaults
DEFAULT_OPNSENSE_URL   = "http://10.0.0.2"
DEFAULT_OPNSENSE_IFACE = ""            # optional (e.g. "lan", "vlan30")
OPNSENSE_ARP_PATH      = "/api/diagnostics/interface/search_arp/"

# AdGuard defaults
DEFAULT_ADGUARD_URL    = "http://127.0.0.1:3000"  # change to your AGH host/port

# Card-friendly status strings
STATUS_IDLE = "idle"
STATUS_SCANNING = "scanning"
STATUS_ENRICHING = "enriching"
STATUS_OK = "ok"
STATUS_ERROR = "error"

# Phases
PHASE_IDLE = "idle"
PHASE_ARP  = "arp"
PHASE_NMAP = "nmap"

# Dispatcher signal so sensors can update immediately on publish
SIGNAL_NSX_UPDATED = "network_scanner_extended_updated"
