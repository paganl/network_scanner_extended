"""Constants for the Network Scanner integration.

These values centralise configuration keys and defaults used across
multiple modules of the component.  Updating a key here will
automatically propagate to the config flow, coordinator and sensor.
"""

DOMAIN: str = "network_scanner"

# Configuration and option keys
CONF_PROVIDER: str = "provider"
CONF_URL: str = "url"
CONF_API_KEY: str = "api_key"
CONF_API_SECRET: str = "api_secret"
CONF_USERNAME: str = "username"
CONF_PASSWORD: str = "password"
CONF_VERIFY_SSL: str = "verify_ssl"
CONF_INTERVAL: str = "interval_min"

# Supported providers for device discovery.  Additional providers can be
# added here and referenced in both the config flow and coordinator.
PROVIDERS: list[str] = ["opnsense"]

# Default polling interval in minutes.  Used if no value is
# explicitly configured via the options flow.
DEFAULT_INTERVAL: int = 2