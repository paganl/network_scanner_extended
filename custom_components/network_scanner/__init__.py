# custom_components/network_scanner/__init__.py
"""Network Scanner integration (summary sensor + per-device device_trackers)."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    DOMAIN,
    PLATFORMS,
    SERVICE_SCAN_NOW,
    SERVICE_CLEANUP,
    ATTR_MODE,
    ATTR_OLDER_THAN_DAYS,
    CLEANUP_MODE_ALL,
    CLEANUP_MODE_RANDOM_ONLY,
    CLEANUP_MODE_STALE_ONLY,
    DEFAULT_CLEANUP_OLDER_THAN_DAYS,
)

_LOGGER = logging.getLogger(__name__)
_LOGGER.warning("network_scanner LOADED FROM custom_components (v0.21.0) - marker A")


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    from .coordinator import NetworkScannerCoordinator

    hass.data.setdefault(DOMAIN, {})
    coordinator = NetworkScannerCoordinator(hass, entry)

    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception as exc:
        raise ConfigEntryNotReady(str(exc)) from exc

    hass.data[DOMAIN][entry.entry_id] = {"coordinator": coordinator}

    # Services (registered once globally)
    _ensure_services_registered(hass)

    # Reload on options change
    entry.async_on_unload(entry.add_update_listener(_async_entry_updated))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Startup cleanup: default to stale-only (safe)
    hass.async_create_task(coordinator.async_cleanup_entities(
        mode=CLEANUP_MODE_STALE_ONLY,
        older_than_days=DEFAULT_CLEANUP_OLDER_THAN_DAYS,
        startup=True,
    ))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    return ok


async def _async_entry_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


@callback
def _ensure_services_registered(hass: HomeAssistant) -> None:
    if hass.data.setdefault(DOMAIN, {}).get("_services_registered"):
        return

    async def _svc_scan_now(call: ServiceCall) -> None:
        entry_id = call.data.get("config_entry_id")
        if not entry_id:
            _LOGGER.warning("scan_now requires config_entry_id")
            return
        block = hass.data.get(DOMAIN, {}).get(entry_id)
        if not block:
            _LOGGER.warning("scan_now: unknown config_entry_id=%s", entry_id)
            return
        coordinator = block["coordinator"]
        await coordinator.async_request_refresh()

    async def _svc_cleanup(call: ServiceCall) -> None:
        entry_id = call.data.get("config_entry_id")
        if not entry_id:
            _LOGGER.warning("cleanup requires config_entry_id")
            return
        block = hass.data.get(DOMAIN, {}).get(entry_id)
        if not block:
            _LOGGER.warning("cleanup: unknown config_entry_id=%s", entry_id)
            return
        coordinator = block["coordinator"]

        mode = call.data.get(ATTR_MODE, CLEANUP_MODE_STALE_ONLY)
        older = int(call.data.get(ATTR_OLDER_THAN_DAYS, DEFAULT_CLEANUP_OLDER_THAN_DAYS))

        if mode not in (CLEANUP_MODE_ALL, CLEANUP_MODE_RANDOM_ONLY, CLEANUP_MODE_STALE_ONLY):
            _LOGGER.warning("cleanup: invalid mode=%s", mode)
            return

        await coordinator.async_cleanup_entities(mode=mode, older_than_days=older, startup=False)

    hass.services.async_register(DOMAIN, SERVICE_SCAN_NOW, _svc_scan_now)
    hass.services.async_register(DOMAIN, SERVICE_CLEANUP, _svc_cleanup)

    hass.data[DOMAIN]["_services_registered"] = True
