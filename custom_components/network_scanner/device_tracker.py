from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.components.device_tracker.const import SourceType
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    blob = hass.data[DOMAIN][entry.entry_id]
    coordinator = blob["coordinator"]
    known = blob["known_tracker_ids"]

    @callback
    def _add_new_entities() -> None:
        devs = (coordinator.data or {}).get("devices") or []
        new_ents = []
        for d in devs:
            uid = d.get("uid")
            if not uid or uid in known:
                continue
            known.add(uid)
            new_ents.append(NetworkScannerTracker(coordinator, entry, uid))
        if new_ents:
            async_add_entities(new_ents)

    # initial add
    _add_new_entities()
    # add on updates
    coordinator.async_add_listener(_add_new_entities)


class NetworkScannerTracker(CoordinatorEntity, TrackerEntity):
    _attr_has_entity_name = True
    _attr_icon = "mdi:access-point-network"

    def __init__(self, coordinator, entry: ConfigEntry, uid: str) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._uid = uid
        self._attr_unique_id = f"{entry.entry_id}:{uid}"

    def _dev(self) -> Optional[Dict[str, Any]]:
        devs = (self.coordinator.data or {}).get("devices") or []
        for d in devs:
            if d.get("uid") == self._uid:
                return d
        return None

    @property
    def name(self) -> str:
        d = self._dev() or {}
        return d.get("name") or d.get("hostname") or (d.get("mac") or d.get("ip") or self._uid)

    @property
    def source_type(self) -> SourceType:
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        d = self._dev() or {}
        return not bool(d.get("derived", {}).get("stale"))

    @property
    def ip_address(self) -> Optional[str]:
        d = self._dev() or {}
        ip = d.get("ip") or ""
        return ip or None

    @property
    def mac_address(self) -> Optional[str]:
        d = self._dev() or {}
        mac = d.get("mac") or ""
        return mac or None

    @property
    def extra_state_attributes(self):
        d = self._dev() or {}
        deriv = d.get("derived") or {}
        # Extended attributes live here (device_tracker can handle large attrs; recorder stores state, not attrs).
        # Still, keep it sensible.
        return {
            "uid": d.get("uid"),
            "ip": d.get("ip"),
            "hostname": d.get("hostname"),
            "vendor": d.get("vendor"),
            "sources": d.get("sources") or [],
            "name_override": d.get("name") or "",
            "description": d.get("description") or "",
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
            "new_device": bool(deriv.get("new_device")),
            "stale": bool(deriv.get("stale")),
            "random_mac": bool(deriv.get("random_mac")),
            # provider blocks (only if present)
            "opnsense": d.get("opnsense") or {},
            "unifi": d.get("unifi") or {},
            "adguard": d.get("adguard") or {},
        }
