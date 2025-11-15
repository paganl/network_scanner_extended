# custom_components/network_scanner/__init__.py
"""Set up the Network Scanner integration.

This module initialises the data coordinator and registers services
when Home Assistant loads a config entry for the integration. It
also handles unloading and reloading entries in response to option
changes. The logic here relies on the ``NetworkScannerCoordinator``
defined in ``coordinator.py`` to perform periodic updates.
"""

from __future__ import annotations
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    DOMAIN,
    CONF_PROVIDER, CONF_OPNSENSE_URL, CONF_UNIFI_URL, CONF_ADGUARD_URL,
)

from .coordinator import async_setup_coordinator, async_unload_coordinator

PLATFORMS: list[str] = ["sensor"]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    await _maybe_migrate_legacy_url(hass, entry)
    await async_setup_coordinator(hass, entry)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        await async_unload_coordinator(hass, entry)
    return ok

async def _maybe_migrate_legacy_url(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """One-time migration for old installs that still stored a `url`."""
    opts = dict(entry.options or {})
    legacy = (opts.pop("url", "") or "").strip()   # <- remove if present
    if not legacy:
        return

    prov = opts.get(CONF_PROVIDER, "opnsense")
    changed = False

    if prov in ("opnsense", "opnsense_unifi") and not (opts.get(CONF_OPNSENSE_URL) or "").strip():
        opts[CONF_OPNSENSE_URL] = legacy; changed = True
    if prov in ("unifi", "opnsense_unifi") and not (opts.get(CONF_UNIFI_URL) or "").strip():
        opts[CONF_UNIFI_URL] = legacy; changed = True
    if prov == "adguard" and not (opts.get(CONF_ADGUARD_URL) or "").strip():
        opts[CONF_ADGUARD_URL] = legacy; changed = True

    if changed:
        hass.config_entries.async_update_entry(entry, options=opts)

