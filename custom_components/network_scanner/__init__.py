"""Network Scanner integration (coordinator-only)."""

from __future__ import annotations

import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import entity_registry as er

from .const import (
    DOMAIN,
    SERVICE_RESCAN,
    SERVICE_CLEANUP,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[str] = ["sensor", "device_tracker"]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    from .coordinator import NetworkScannerCoordinator

    hass.data.setdefault(DOMAIN, {})
    coordinator = NetworkScannerCoordinator(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "known_tracker_ids": set(),   # used by device_tracker platform
    }

    # First refresh so we have devices before cleanup / platform add
    await coordinator.async_config_entry_first_refresh()

    # Forward platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Cleanup orphaned trackers on startup (after first refresh)
    await _cleanup_orphaned_trackers(hass, entry)

    # Register services once per HA instance
    if not hass.services.has_service(DOMAIN, SERVICE_RESCAN):
        hass.services.async_register(DOMAIN, SERVICE_RESCAN, _svc_rescan)
    if not hass.services.has_service(DOMAIN, SERVICE_CLEANUP):
        hass.services.async_register(DOMAIN, SERVICE_CLEANUP, _svc_cleanup)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    return ok


async def _svc_rescan(call: ServiceCall) -> None:
    hass: HomeAssistant = call.hass
    # rescan all entries
    for entry_id, blob in (hass.data.get(DOMAIN) or {}).items():
        coord = blob.get("coordinator")
        if coord:
            await coord.async_request_refresh()


async def _svc_cleanup(call: ServiceCall) -> None:
    hass: HomeAssistant = call.hass
    for entry in hass.config_entries.async_entries(DOMAIN):
        await _cleanup_orphaned_trackers(hass, entry)


async def _cleanup_orphaned_trackers(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove device_tracker entities from the entity registry if no longer present."""
    blob = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if not blob:
        return
    coordinator = blob["coordinator"]
    present = set(coordinator.device_uids())

    ent_reg = er.async_get(hass)
    removed = 0

    for ent in list(er.async_entries_for_config_entry(ent_reg, entry.entry_id)):
        if ent.domain != "device_tracker":
            continue
        # our unique_id format: "<entry_id>:<uid>"
        if not (ent.unique_id or "").startswith(f"{entry.entry_id}:"):
            continue
        uid = (ent.unique_id or "").split(":", 1)[1] if ":" in (ent.unique_id or "") else ""
        if uid and uid not in present:
            ent_reg.async_remove(ent.entity_id)
            removed += 1

    if removed:
        _LOGGER.warning("Cleanup: removed %d orphaned device_tracker entities", removed)
    else:
        _LOGGER.debug("Cleanup: no orphaned device_tracker entities found")
