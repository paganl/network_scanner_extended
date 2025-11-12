
from __future__ import annotations

DOMAIN = "network_scanner"

CONF_PROVIDER = "provider"
CONF_URL = "url"
CONF_KEY = "key"
CONF_SECRET = "secret"
CONF_NAME = "name"
CONF_PASSWORD = "password"
CONF_CIDRS = "cidrs"
CONF_INTERVAL_MIN = "interval_min"
CONF_USE_NMAP = "use_nmap"
CONF_NMAP_ARGS = "nmap_args"
CONF_MAC_DIRECTORY = "mac_directory"

DEFAULT_OPTIONS = {
    CONF_PROVIDER: "opnsense",         # or "adguard"
    CONF_URL: "",
    CONF_KEY: "",
    CONF_SECRET: "",
    CONF_NAME: "",
    CONF_PASSWORD: "",
    CONF_CIDRS: ["192.168.1.0/24"],
    CONF_INTERVAL_MIN: 3,
    CONF_USE_NMAP: False,
    CONF_NMAP_ARGS: "-sn --max-retries 1 --host-timeout 5s",
    CONF_MAC_DIRECTORY: "",
}
