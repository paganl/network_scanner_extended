"""Device tracker platform for Network Scanner."""

from __future__ import annotations
from datetime import timedelta
from homeassistant.util import dt as dt_util

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo

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
    for d in devices:
        uid = (d.get("mac") or "").upper() or (f"IP:{d['ips'][0]}" if d.get("ips") else "")
        if not uid:
            continue
        entities.append(NetworkScannerTracker(coordinator, entry, uid))

    async_add_entities(entities, update_before_add=True)


class NetworkScannerTracker(CoordinatorEntity, TrackerEntity):
    """A simple presence tracker for a network device."""

    _attr_should_poll = False
    _attr_source_type = SourceType.ROUTER

    def __init__(self, coordinator, entry: ConfigEntry, uid: str) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._uid = uid

        # Keep unique_id stable: entry-scoped + uid (MAC preferred; IP fallback)
        self._attr_unique_id = f"{entry.entry_id}:{uid}"

        # Default name; we'll override via name property when hostname is available
        self._attr_name = f"NS {uid}"

    def _find_device(self) -> dict[str, Any] | None:
        data = self.coordinator.data or {}
        for d in data.get("devices", []) or []:
            mac = (d.get("mac") or "").upper()
            uid = mac or (f"IP:{d['ips'][0]}" if d.get("ips") else "")
            if uid == self._uid:
                return d
        return None

    @property
    def device_info(self) -> DeviceInfo | None:
        """Register/link a HA Device so entities group like Netgear does."""
        d = self._find_device() or {}
        mac = (d.get("mac") or "").upper()

        # Only create a device if we have a MAC; IP-only entries cannot reliably link across integrations
        if not mac:
            return None

        hostname = (d.get("hostname") or "").strip()
        vendor = (d.get("vendor") or "").strip() or "Unknown"

        return DeviceInfo(
            # identifiers tie the device to THIS integration/config entry
            identifiers={(DOMAIN, mac)},
            name=hostname or f"Device {mac}",
            manufacturer=vendor,

            # connections let HA link other integrations that also publish the same MAC
            connections={(dr.CONNECTION_NETWORK_MAC, mac)},

            # Show the client as "behind" the Network Scanner hub
            via_device=(DOMAIN, self._entry.entry_id),
        )
    
    CONNECTED_TTL = timedelta(minutes=5)  # tweak to taste
    
    @property
    def is_connected(self) -> bool:
        """Connected if last_seen is within CONNECTED_TTL."""
        d = self._find_device() or {}

    last_seen = d.get("last_seen")
    if not last_seen:
        return False

    dt = dt_util.parse_datetime(last_seen)
    if dt is None:
        return False

    dt = dt_util.as_utc(dt)
    return (dt_util.utcnow() - dt) <= CONNECTED_TTL

    @property
    def state(self) -> str:
        return "home" if self.is_connected else "not_home"
    
    @property
    def hostname(self) -> str | None:
        d = self._find_device() or {}
        v = (d.get("hostname") or "").strip()
        return v or None

    @property
    def ip_address(self) -> str | None:
        d = self._find_device() or {}
        return (d.get("ip") or (d.get("ips") or [None])[0])

    @property
    def mac_address(self) -> str | None:
        # Only return a MAC if this UID is a MAC
        return self._uid if ":" in self._uid and not self._uid.startswith("IP:") else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        d = self._find_device() or {}
        return {
            "vendor": d.get("vendor"),
            "device_type": d.get("device_type"),
            "network_role": d.get("network_role"),
            "vlan_id": d.get("vlan_id"),
            "sources": d.get("sources"),
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
            "derived": d.get("derived"),
        }

    @property
    def name(self) -> str:
        """Prefer hostname when available."""
        host = self.hostname
        if host:
            return f"NS {host}"
        return self._attr_name
