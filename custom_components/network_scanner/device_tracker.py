"""Device tracker platform for Network Scanner."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

# Try new-style TrackerEntity first, fall back for older cores
try:
    from homeassistant.components.device_tracker.config_entry import TrackerEntity
    from homeassistant.components.device_tracker import SourceType
except Exception:  # pragma: no cover
    from homeassistant.components.device_tracker import DeviceTrackerEntity as TrackerEntity  # type: ignore
    from homeassistant.components.device_tracker import SourceType  # type: ignore

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities,
) -> None:
    """Set up device trackers from a config entry."""
    blob = hass.data[DOMAIN].get(entry.entry_id)

    # Support both styles: stored as coordinator or as {"coordinator": coordinator, ...}
    coordinator = blob.get("coordinator") if isinstance(blob, dict) else blob
    if coordinator is None:
        _LOGGER.error("Device tracker setup: no coordinator found for entry %s", entry.entry_id)
        return

    # Create/ensure a hub device so client devices can use via_device=(DOMAIN, entry.entry_id)
    dev_reg = dr.async_get(hass)
    dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.entry_id)},
        name="Network Scanner",
        manufacturer="Network Scanner Extended",
        model="Coordinator",
    )

    devices = (coordinator.data or {}).get("devices") or []
    _LOGGER.debug("Device tracker setup: creating %d trackers", len(devices))

    entities: list[NetworkScannerTracker] = []
    for dev in devices:
        uid = (dev.get("mac") or "").upper() or (f"IP:{dev['ips'][0]}" if dev.get("ips") else "")
        if not uid:
            continue
        entities.append(NetworkScannerTracker(coordinator, entry, uid))

    async_add_entities(entities, update_before_add=True)


class NetworkScannerTracker(CoordinatorEntity, TrackerEntity):
    """Presence-style tracker based on last_seen TTL."""

    _attr_should_poll = False
    _attr_source_type = SourceType.ROUTER

    CONNECTED_TTL = timedelta(minutes=5)

    def __init__(self, coordinator, entry: ConfigEntry, uid: str) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._uid = uid
        self._attr_unique_id = f"{entry.entry_id}:{uid}"
        self._attr_name = f"NS {uid}"

    def _find_device(self) -> dict[str, Any] | None:
        data = self.coordinator.data or {}
        for dev in data.get("devices", []) or []:
            mac = (dev.get("mac") or "").upper()
            uid = mac or (f"IP:{dev['ips'][0]}" if dev.get("ips") else "")
            if uid == self._uid:
                return dev
        return None

    @property
    def device_info(self) -> DeviceInfo | None:
        """Register/link a HA Device so entities group like Netgear does."""
        dev = self._find_device() or {}
        deriv = dev.get("derived") or {}
        mac = (dev.get("mac") or "").upper()

        # Only create a device if we have a MAC; IP-only entries cannot reliably link across integrations
        if not mac:
            return None

        vendor = (dev.get("vendor") or "").strip() or "Unknown"
        name = (deriv.get("directory_name") or dev.get("hostname") or f"Device {mac}").strip()

        return DeviceInfo(
            identifiers={(DOMAIN, mac)},
            name=name,
            manufacturer=vendor,
            connections={(dr.CONNECTION_NETWORK_MAC, mac)},
            via_device=(DOMAIN, self._entry.entry_id),
        )

    @property
    def is_connected(self) -> bool:
        """Connected if last_seen is within CONNECTED_TTL."""
        dev = self._find_device() or {}
        last_seen = dev.get("last_seen")
        if not last_seen:
            return False

        dt = dt_util.parse_datetime(last_seen)
        if dt is None:
            return False

        dt = dt_util.as_utc(dt)
        return (dt_util.utcnow() - dt) <= self.CONNECTED_TTL

    @property
    def state(self) -> str:
        return "home" if self.is_connected else "not_home"

    @property
    def hostname(self) -> str | None:
        dev = self._find_device() or {}
        v = (dev.get("hostname") or "").strip()
        return v or None

    @property
    def ip_address(self) -> str | None:
        dev = self._find_device() or {}
        return dev.get("ip") or (dev.get("ips") or [None])[0]

    @property
    def mac_address(self) -> str | None:
        return self._uid if ":" in self._uid and not self._uid.startswith("IP:") else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        dev = self._find_device() or {}
        deriv = dev.get("derived") or {}
        return {
            "vendor": dev.get("vendor"),
            "device_type": dev.get("device_type"),
            "network_role": dev.get("network_role"),
            "vlan_id": dev.get("vlan_id"),
            "sources": dev.get("sources"),
            "first_seen": dev.get("first_seen"),
            "last_seen": dev.get("last_seen"),
            "derived": deriv,
            "directory_name": deriv.get("directory_name"),
            "directory_desc": deriv.get("directory_desc"),
        }

    @property
    def name(self) -> str:
        dev = self._find_device() or {}
        deriv = dev.get("derived") or {}

        dir_name = (deriv.get("directory_name") or "").strip()
        if dir_name:
            return f"NS {dir_name}"

        host = (dev.get("hostname") or "").strip()
        if host:
            return f"NS {host}"

        return self._attr_name
