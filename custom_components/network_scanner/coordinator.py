"""Data coordinator for the Network Scanner integration."""

from __future__ import annotations
import logging
from datetime import timedelta
from typing import Any, Dict, List

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN, DEFAULT_OPTIONS,
    CONF_PROVIDER, CONF_URL, CONF_KEY, CONF_SECRET,
    CONF_NAME, CONF_PASSWORD, CONF_TOKEN,
    CONF_VERIFY_SSL, CONF_INTERVAL_MIN,
)
from .provider import opnsense, unifi, adguard

_LOGGER = logging.getLogger(__name__)

async def async_setup_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> None:
    hass.data.setdefault(DOMAIN, {})
    coordinator = NetworkScannerCoordinator(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    hass.async_create_task(coordinator.async_request_refresh())

    async def _svc_refresh(call):
        await coordinator.async_request_refresh()

    hass.services.async_register(DOMAIN, "refresh", _svc_refresh)

async def async_unload_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, ["sensor"])
    try:
        hass.services.async_remove(DOMAIN, "refresh")
    except Exception:
        pass
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return ok

class NetworkScannerCoordinator(DataUpdateCoordinator[Dict[str, Any]]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.options = {**DEFAULT_OPTIONS, **dict(entry.options)}
        self.session = async_get_clientsession(hass)

        interval_min = max(1, int(self.options.get(CONF_INTERVAL_MIN, 3)))
        update_interval = timedelta(minutes=interval_min)

        super().__init__(
            hass, _LOGGER, name="network_scanner_coordinator",
            update_method=self._async_update_data, update_interval=update_interval,
        )

    async def _async_update_data(self) -> Dict[str, Any]:
        try:
            devices = await self._gather_devices()
            return {"devices": devices, "count": len(devices)}
        except Exception as exc:
            raise UpdateFailed(str(exc)) from exc

    async def _gather_devices(self) -> List[Dict[str, Any]]:
        prov   = self.options.get(CONF_PROVIDER, "opnsense")
        url    = (self.options.get(CONF_URL) or "").rstrip("/")
        verify = bool(self.options.get(CONF_VERIFY_SSL, False))
        name   = self.options.get(CONF_NAME, "")
        pwd    = self.options.get(CONF_PASSWORD, "")
        key    = self.options.get(CONF_KEY, "")
        sec    = self.options.get(CONF_SECRET, "")
        token  = self.options.get(CONF_TOKEN, "")

        if prov == "opnsense":
            return await opnsense.async_get_devices(self.session, url, key, sec, verify_ssl=verify)
        if prov == "unifi":
            return await unifi.async_get_devices(self.session, url, username=name, password=pwd, token=token, verify_ssl=verify)
        if prov == "adguard":
            return await adguard.async_get_devices(self.session, url, username=name, password=pwd, verify_ssl=verify)

        _LOGGER.warning("Unknown provider %s", prov)
        return []
