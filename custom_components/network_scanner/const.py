DOMAIN = "network_scanner"

# Default UI values
DEFAULT_IP_RANGE = "192.168.1.0/24"

# Default nmap args that work across routed networks (not just ARP)
DEFAULT_NMAP_ARGS = "-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4"

# Default scan interval in seconds (make it generous if your scans take minutes)
DEFAULT_SCAN_INTERVAL = 240

# Card-friendly status strings
STATUS_IDLE = "idle"
STATUS_SCANNING = "scanning"
STATUS_OK = "ok"
STATUS_ERROR = "error"
