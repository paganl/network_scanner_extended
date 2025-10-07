from __future__ import annotations

DOMAIN: str = "network_scanner"

# Default UI values
DEFAULT_IP_RANGE = "192.168.1.0/24"

# Default nmap args that work across routed networks (not just ARP)
DEFAULT_NMAP_ARGS = "-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4"

# Default scan interval in seconds (make it generous if your scans take minutes)
DEFAULT_SCAN_INTERVAL = 240

# ARP enrichment settings 
CONF_ARP_PROVIDER   = "arp_provider"
CONF_ARP_BASE_URL   = "arp_base_url"
CONF_ARP_KEY        = "arp_key"
CONF_ARP_SECRET     = "arp_secret"
CONF_ARP_VERIFY_TLS = "arp_verify_tls"

ARP_PROVIDER_NONE     = "none"
ARP_PROVIDER_OPNSENSE = "opnsense"

DEFAULT_OPNSENSE_URL = "http://10.0.0.2"
DEFAULT_OPNSENSE_IFACE = ""      # optional (e.g. "lan", "vlan30")
OPNSENSE_ARP_PATH = "/api/diagnostics/interface/search_arp/"

# Card-friendly status strings
STATUS_IDLE = "idle"
STATUS_SCANNING = "scanning"
STATUS_OK = "ok"
STATUS_ERROR = "error"
