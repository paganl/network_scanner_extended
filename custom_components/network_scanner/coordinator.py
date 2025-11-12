"""Data coordinator for the Network Scanner integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict, List

from aiohttp import ClientSession
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_PROVIDER,
    CONF_URL,
    CONF_API_KEY,
    CONF_API_SECRET,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_VERIFY_SSL,
    CONF_INTERVAL,
    DOMAIN,
    DEFAULT_INTERVAL,
)

from .provider import opnsense as opnsense_provider

_LOGGER = logging.getLogger(__name__)


class NetworkScannerCoordinator(DataUpdateCoordinator[List[Dict[str, Any]]]):
    """Class to manage fetching network devices from a provider."""

    def __init__(self, hass: HomeAssistant, entry) -> None:
        self.hass = hass
        self.entry = entry
        interval_min = entry.options.get(CONF_INTERVAL, entry.data.get(CONF_INTERVAL, DEFAULT_INTERVAL))
        update_interval = timedelta(minutes=max(int(interval_min), 1))

        super().__init__(
            hass,
            _LOGGER,
            name="Network Scanner coordinator",
            update_interval=update_interval,
        )

    async def _async_update_data(self) -> List[Dict[str, Any]]:
        """Fetch network devices from the configured provider."""
        opts = {**self.entry.data, **(self.entry.options or {})}
        provider = opts.get(CONF_PROVIDER)
        url = opts.get(CONF_URL)
        verify_ssl = bool(opts.get(CONF_VERIFY_SSL, False))
        api_key = opts.get(CONF_API_KEY, "")
        api_secret = opts.get(CONF_API_SECRET, "")
        username = opts.get(CONF_USERNAME, "")
        password = opts.get(CONF_PASSWORD, "")

        session: ClientSession = async_get_clientsession(self.hass)

        try:
            if provider == "opnsense":
                # Only call the opnsense provider for now; other providers
                # could be added via elif blocks.
                devices = await opnsense_provider.async_get_devices(
                    session,
                    url,
                    api_key,
                    api_secret,
                    verify_ssl=verify_ssl,
                    timeout_s=5,
                )
                return devices
            else:
                _LOGGER.warning("Unknown provider: %s", provider)
                return []
        except Exception as err:
            # Propagate errors to the coordinator framework
            raise UpdateFailed(f"Error fetching devices: {err}") from err