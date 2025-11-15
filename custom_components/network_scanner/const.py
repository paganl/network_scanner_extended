# custom_components/network_scanner/const.py
DOMAIN = "network_scanner"

# Options / config keys
CONF_PROVIDER       = "provider"           # "opnsense" | "unifi" | "adguard" | "opnsense_unifi"
CONF_VERIFY_SSL     = "verify_ssl"
CONF_INTERVAL_MIN   = "interval_min"

CONF_OPNSENSE_URL   = "opnsense_url"
CONF_KEY            = "key"
CONF_SECRET         = "secret"

CONF_UNIFI_URL      = "unifi_url"
CONF_NAME           = "username"
CONF_PASSWORD       = "password"
CONF_TOKEN          = "token"              # optional (preferred if provided)
CONF_SITE           = "site"               # defaults "default"

CONF_ADGUARD_URL    = "adguard_url"

DEFAULT_OPTIONS = {
    CONF_PROVIDER: "opnsense",
    CONF_VERIFY_SSL: False,
    CONF_INTERVAL_MIN: 3,
}
