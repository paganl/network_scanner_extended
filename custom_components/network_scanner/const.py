from __future__ import annotations

DOMAIN = "network_scanner"

CONF_OPNSENSE_URL = "opnsense_url"
CONF_UNIFI_URL    = "unifi_url"
CONF_ADGUARD_URL = 'adguard url" 

CONF_KEY        = "key"         # OPNsense
CONF_SECRET     = "secret"      # OPNsense
CONF_NAME       = "name"        # username (AdGuard/UniFi)
CONF_PASSWORD   = "password"    # password (AdGuard/UniFi)
CONF_TOKEN      = "token"       # UniFi API token (optional)
CONF_VERIFY_SSL = "verify_ssl"
CONF_INTERVAL_MIN = "interval_min"
CONF_PROVIDER   = "provider"    # "opnsense" | "unifi" | "adguard" | "opnsense_unifi"

DEFAULT_OPTIONS = {
    CONF_PROVIDER: "opnsense",
    CONF_VERIFY_SSL: False,
    CONF_INTERVAL_MIN: 3,
}
