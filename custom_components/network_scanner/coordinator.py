"""Data coordinator for the Network Scanner integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict, List, Tuple, Set

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN, DEFAULT_OPTIONS,
    CONF_PROVIDER, CONF_URL, CONF_OPNSENSE_URL, CONF_UNIFI_URL,
    CONF_KEY, CONF_SECRET, CONF_NAME, CONF_PASSWORD, CONF_TOKEN,
    CONF_VERIFY_SSL, CONF_INTERVAL_MIN,
)
from .provider import opnsense, unifi, adguard

_LOGGER = logging.getLogger(__name__)
STORE_VERSION = 1
STORE_KEY = f"{DOMAIN}_inventory"

async def async_setup_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> None:
    hass.data.setdefault(DOMAIN, {})
    coordinator = NetworkScannerCoordinator(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    hass.async_create_task(coordinator.async_request_refresh())

async def async_unload_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, ["sensor"])
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

        self._store: Store = Store(hass, STORE_VERSION, STORE_KEY)
        self._inventory: Dict[str, Dict[str, Any]] | None = None  # key -> stored record

    async def _ensure_inventory_loaded(self) -> None:
        if self._inventory is None:
            data = await self._store.async_load()
            self._inventory = data if isinstance(data, dict) else {}

    async def _async_update_data(self) -> Dict[str, Any]:
        try:
            await self._ensure_inventory_loaded()
            now_iso = dt_util.utcnow().isoformat()

            raw_devices = await self._collect_raw_devices()
            merged = self._merge_and_enrich(raw_devices)

            # persist first_seen/last_seen + keep annotations
            changed = False
            for d in merged:
                key = d["mac"] or (f"IP:{d['ips'][0]}" if d.get("ips") else None)
                if not key:
                    continue
                stored = self._inventory.get(key, {})
                if "first_seen" not in stored:
                    stored["first_seen"] = now_iso
                    changed = True
                stored["last_seen"] = now_iso
                # carry forward user annotations if present
                for k in ("owner", "room", "notes", "tags_user"):
                    if k in stored and k not in d.get("derived", {}):
                        d.setdefault("derived", {})[k] = stored[k]
                # save back minimal record
                self._inventory[key] = {
                    "first_seen": stored["first_seen"],
                    "last_seen": stored["last_seen"],
                    # keep space for annotations
                    **{k: stored.get(k) for k in ("owner","room","notes","tags_user") if stored.get(k) is not None},
                }

            if changed:
                await self._store.async_save(self._inventory)

            return {"devices": merged, "count": len(merged)}
        except Exception as exc:
            raise UpdateFailed(str(exc)) from exc

    async def _collect_raw_devices(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect lists from providers; keys are provider names."""
        prov = self.options.get(CONF_PROVIDER, "opnsense")
        verify = bool(self.options.get(CONF_VERIFY_SSL, False))

        # Helper: resolve URLs
        def _u(kind: str) -> str:
            if kind == "opnsense":
                return (self.options.get(CONF_OPNSENSE_URL) or self.options.get(CONF_URL) or "").rstrip("/")
            if kind == "unifi":
                return (self.options.get(CONF_UNIFI_URL) or self.options.get(CONF_URL) or "").rstrip("/")
            return (self.options.get(CONF_URL) or "").rstrip("/")

        out: Dict[str, List[Dict[str, Any]]] = {}

        if prov == "opnsense":
            out["opnsense"] = await opnsense.async_get_devices(
                session=self.session,
                base_url=_u("opnsense"),
                key=self.options.get(CONF_KEY, ""),
                secret=self.options.get(CONF_SECRET, ""),
                verify_ssl=verify,
            )
        elif prov == "unifi":
            out["unifi"] = await unifi.async_get_devices(
                session=self.session,
                base_url=_u("unifi"),
                username=self.options.get(CONF_NAME, ""),
                password=self.options.get(CONF_PASSWORD, ""),
                token=self.options.get(CONF_TOKEN, ""),
                verify_ssl=verify,
            )
        elif prov == "adguard":
            out["adguard"] = await adguard.async_get_devices(
                session=self.session,
                base_url=_u("adguard"),
                username=self.options.get(CONF_NAME, ""),
                password=self.options.get(CONF_PASSWORD, ""),
                verify_ssl=verify,
            )
        elif prov == "opnsense_unifi":
            out["opnsense"] = await opnsense.async_get_devices(
                session=self.session,
                base_url=_u("opnsense"),
                key=self.options.get(CONF_KEY, ""),
                secret=self.options.get(CONF_SECRET, ""),
                verify_ssl=verify,
            )
            out["unifi"] = await unifi.async_get_devices(
                session=self.session,
                base_url=_u("unifi"),
                username=self.options.get(CONF_NAME, ""),
                password=self.options.get(CONF_PASSWORD, ""),
                token=self.options.get(CONF_TOKEN, ""),
                verify_ssl=verify,
            )
        else:
            _LOGGER.warning("Unknown provider %s", prov)

        return out

    # ---------------- merge + derive ----------------

    def _merge_and_enrich(self, src: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        by_key: Dict[str, Dict[str, Any]] = {}
        sources_seen: Dict[str, Set[str]] = {}

        def key_of(d: Dict[str, Any]) -> str | None:
            mac = (d.get("mac") or "").upper()
            if mac:
                return mac
            ip = d.get("ip")
            return f"IP:{ip}" if ip else None

        def add(d: Dict[str, Any], source: str):
            k = key_of(d)
            if not k:
                return
            cur = by_key.get(k, {
                "mac": (d.get("mac") or "").upper(),
                "ips": [],
                "hostname": "",
                "vendor": "",
                "device_type": "unknown",
                "vlan_id": None,
                "network_role": "",
                "interface": "",
                "site": None,
                "tags": [],
                "sources": [],
            })
            # union IPs
            ips = set(cur.get("ips") or [])
            ip = d.get("ip")
            if ip: ips.add(str(ip))
            cur["ips"] = sorted(ips)

            # prefer non-empty hostname/vendor
            cur["hostname"] = cur["hostname"] or d.get("hostname") or ""
            cur["vendor"]   = cur["vendor"]   or d.get("vendor")   or ""

            # attach provider blocks if present
            for block in ("opnsense","unifi","adguard"):
                if block in d and block not in cur:
                    cur[block] = d[block]

            # quick device_type + interface from provider blocks
            if "unifi" in d:
                cur["device_type"] = "wired" if d["unifi"].get("is_wired") else "wifi"
                cur["site"] = d["unifi"].get("site") or cur["site"]
            if "opnsense" in d:
                cur["interface"] = d["opnsense"].get("intf") or cur["interface"]
                nr = d["opnsense"].get("intf_description")
                if nr: cur["network_role"] = nr

            # capture sources/tags
            sources = set(cur.get("sources") or [])
            sources.add(source)
            cur["sources"] = sorted(sources)
            tags = set(cur.get("tags") or [])
            tags.add(source)
            cur["tags"] = sorted(tags)

            by_key[k] = cur
            sources_seen.setdefault(k, set()).add(source)

        # ingest all
        for src_name, items in (src or {}).items():
            for d in items or []:
                add(d, src_name)

        # derive vlan_id, role, risk, timestamps placeholders
        out: List[Dict[str, Any]] = []
        for k, dev in by_key.items():
            vlan_id = self._derive_vlan_id(dev)
            dev["vlan_id"] = vlan_id

            derived = dev.setdefault("derived", {})
            derived["new_device"] = False  # will be set from store on next cycle
            derived["stale"] = False
            derived["risk_score"] = self._risk_score(dev)

            out.append(dev)

        # sort for stable UI (hostname, then MAC/IP)
        out.sort(key=lambda d: (d.get("hostname") or "", d.get("mac") or d["ips"][0] if d.get("ips") else ""))
        return out

    @staticmethod
    def _derive_vlan_id(dev: Dict[str, Any]) -> int | None:
        # from UniFi if present
        uni = dev.get("unifi") or {}
        if "vlan" in uni and isinstance(uni["vlan"], int):
            return uni["vlan"]
        # parse from interface like 'vlan0.2'
        intf = dev.get("interface") or ""
        if ". " in intf:  # guard against typo
            intf = intf.replace(". ", ".")
        if "vlan" in intf and "." in intf:
            try:
                return int(intf.split(".")[-1])
            except Exception:
                return None
        return None

    @staticmethod
    def _risk_score(dev: Dict[str, Any]) -> int:
        score = 0
        if not dev.get("vendor"): score += 30
        if dev.get("device_type") == "wifi" and (dev.get("network_role") or "").lower() not in ("iot","guest","media"):
            score += 20
        if "new_device" in dev.get("derived", {}) and dev["derived"]["new_device"]:
            score += 10
        if dev.get("network_role","").lower() == "guest":
            score += 5
        return max(0, min(100, score))
