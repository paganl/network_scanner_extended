# custom_components/network_scanner/device_tracker.py
from __future__ import annotations

import logging
from typing import Any, Dict

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import TrackerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
):
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    added: set[str] = set()

    def _current_keys():
        return list((coordinator.devices_by_key or {}).keys())

    # Add existing right away (after first refresh)
    entities = []
    for key in _current_keys():
        entities.append(NetworkScannerDeviceTracker(coordinator, entry, key))
        added.add(key)

    async_add_entities(entities, True)

    # Add new entities dynamically when new devices appear
    @callback
    def _handle_update():
        keys = set(_current_keys())
        new_keys = keys - added
        if not new_keys:
            return
        new_entities = [NetworkScannerDeviceTracker(coordinator, entry, k) for k in sorted(new_keys)]
        for k in new_keys:
            added.add(k)
        async_add_entities(new_entities, True)

    coordinator.async_add_listener(_handle_update)


class NetworkScannerDeviceTracker(CoordinatorEntity, TrackerEntity):
    """One device_tracker per discovered device."""

    def __init__(self, coordinator, entry: ConfigEntry, key: str) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._key = key
        self._attr_unique_id = f"{entry.entry_id}:{key}"
        # Friendly name can still be overridden by entity_registry
        self._attr_name = key

    @property
    def source_type(self) -> SourceType:
        return SourceType.ROUTER

    def _dev(self) -> Dict[str, Any]:
        return (self.coordinator.devices_by_key or {}).get(self._key, {})

    @property
    def mac_address(self) -> str | None:
        mac = self._dev().get("mac")
        return mac or None

    @property
    def ip_address(self) -> str | None:
        ip = self._dev().get("ip")
        return ip or None

    @property
    def hostname(self) -> str | None:
        d = self._dev()
        return (d.get("name") or d.get("hostname") or d.get("ip") or self._key) or None

    @property
    def is_connected(self) -> bool:
        # Treat "stale" as not connected; otherwise connected when present in latest scan.
        d = self._dev()
        if not d:
            return False
        return not bool((d.get("derived") or {}).get("stale", False))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        d = self._dev()
        if not d:
            return {}

        # Keep attributes useful but not insane (avoid huge provider raw dumps).
        derived = d.get("derived") or {}
        return {
            "key": self._key,
            "ip": d.get("ip", ""),
            "mac": d.get("mac", ""),
            "hostname": d.get("hostname", ""),
            "name": d.get("name", ""),
            "desc": d.get("desc", ""),
            "vendor": d.get("vendor", ""),
            "device_type": d.get("device_type", "unknown"),
            "wired": d.get("wired"),
            "ssid": d.get("ssid", ""),
            "vlan_id": d.get("vlan_id"),
            "network_role": d.get("network_role", ""),
            "interface": d.get("interface", ""),
            "ap": d.get("ap", {}),
            "switch": d.get("switch", {}),
            "signal": d.get("signal", {}),
            "bytes": d.get("bytes", {}),
            "dhcp": d.get("dhcp", {}),
            "sources": d.get("sources", []),
            "first_seen": d.get("first_seen", ""),
            "last_seen": d.get("last_seen", ""),
            "new_device": bool(derived.get("new_device", False)),
            "random_mac": bool(derived.get("random_mac", False)),
            "stale": bool(derived.get("stale", False)),
        }
