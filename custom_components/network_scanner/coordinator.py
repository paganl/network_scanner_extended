# custom_components/network_scanner/coordinator.py
"""Coordinator: one scan engine, summary-only coordinator.data, per-device map stored on coordinator."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from aiohttp import ClientError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.entity_registry import async_get as async_get_entity_registry
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    DEFAULT_OPTIONS,
    # common
    CONF_SCAN_INTERVAL_MIN,
    CONF_VERIFY_SSL,
    # providers
    CONF_PRESENCE_PROVIDER,
    PRESENCE_OPNSENSE,
    PRESENCE_ADGUARD,
    CONF_OPNSENSE_URL,
    CONF_OPNSENSE_KEY,
    CONF_OPNSENSE_SECRET,
    CONF_OPNSENSE_INTERFACE,
    CONF_ADGUARD_URL,
    CONF_ADGUARD_USERNAME,
    CONF_ADGUARD_PASSWORD,
    # unifi
    CONF_UNIFI_ENABLED,
    CONF_UNIFI_URL,
    CONF_UNIFI_TOKEN,
    CONF_UNIFI_USERNAME,
    CONF_UNIFI_PASSWORD,
    CONF_UNIFI_SITE,
    # directory
    CONF_MAC_DIRECTORY_JSON_URL,
    CONF_MAC_DIRECTORY_JSON_TEXT,
    # events
    EVENT_DEVICE_NEW,
    EVENT_DEVICE_NEW_RANDOM,
    EVENT_SCAN_ERROR,
    # cleanup
    CLEANUP_MODE_ALL,
    CLEANUP_MODE_RANDOM_ONLY,
    CLEANUP_MODE_STALE_ONLY,
)

# Your existing provider modules (keep them as-is)
from .provider import opnsense, adguard, unifi  # type: ignore

_LOGGER = logging.getLogger(__name__)

STORE_VERSION = 1
STORE_KEY_FMT = f"{DOMAIN}_inventory_{{entry_id}}"
STALE_HOURS_DEFAULT = 24

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


def _clean_mac(s: Optional[str]) -> str:
    m = (s or "").strip().upper()
    if not m:
        return ""
    if m in ("*", "(INCOMPLETE)", "INCOMPLETE"):
        return ""
    if m.replace(":", "") == "000000000000":
        return ""
    return m if _MAC_RE.match(m) else ""


def _is_locally_administered(mac: str) -> bool:
    """Detect private/random MACs (locally administered bit)."""
    mac = _clean_mac(mac)
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return (first_octet & 0b00000010) != 0
    except Exception:
        return False


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _now_iso() -> str:
    return dt_util.utcnow().isoformat()


def _norm(s: Optional[str]) -> str:
    return (s or "").strip()


def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(obj, dict):
        return out
    block = obj.get("data", obj)
    if not isinstance(block, dict):
        return out
    for k, v in block.items():
        mk = _clean_mac(str(k))
        if not mk:
            continue
        if isinstance(v, dict):
            out[mk] = {"name": str(v.get("name", "")), "desc": str(v.get("desc", ""))}
        else:
            out[mk] = {"name": str(v), "desc": ""}
    return out


class NetworkScannerCoordinator(DataUpdateCoordinator[Dict[str, Any]]):
    """Coordinator that returns summary data only; devices are kept on the coordinator."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry

        raw = dict(entry.options or entry.data or {})
        self.options: Dict[str, Any] = {**DEFAULT_OPTIONS, **raw}

        interval_min = max(1, int(self.options.get(CONF_SCAN_INTERVAL_MIN, 3)))
        update_interval = timedelta(minutes=interval_min)

        super().__init__(
            hass,
            _LOGGER,
            name="network_scanner_coordinator",
            update_method=self._async_update_data,
            update_interval=update_interval,
        )

        self.session = async_get_clientsession(hass, verify_ssl=bool(self.options.get(CONF_VERIFY_SSL, False)))

        self._store = Store(hass, STORE_VERSION, STORE_KEY_FMT.format(entry_id=entry.entry_id))
        self._inventory: Dict[str, Dict[str, Any]] | None = None

        # Public-ish: current device map keyed by MAC or IP:...
        self.devices_by_key: Dict[str, Dict[str, Any]] = {}

        # Summary / operational fields
        self.last_scan_started: Optional[str] = None
        self.last_scan_finished: Optional[str] = None
        self.last_error: str = ""
        self.error_count: int = 0
        self.warning_count: int = 0

    async def _ensure_inventory_loaded(self) -> None:
        if self._inventory is None:
            data = await self._store.async_load()
            self._inventory = data if isinstance(data, dict) else {}

    def _key_of(self, mac: str, ip: str) -> str:
        mac = _clean_mac(mac)
        if mac:
            return mac
        ip = (ip or "").strip()
        return f"IP:{ip}" if ip else ""

    async def _collect_presence(self) -> List[Dict[str, Any]]:
        prov = self.options.get(CONF_PRESENCE_PROVIDER, PRESENCE_OPNSENSE)
        verify_ssl = bool(self.options.get(CONF_VERIFY_SSL, False))

        if prov == PRESENCE_OPNSENSE:
            return await opnsense.async_get_devices(
                session=self.session,
                base_url=(self.options.get(CONF_OPNSENSE_URL) or "").rstrip("/"),
                key=self.options.get(CONF_OPNSENSE_KEY, ""),
                secret=self.options.get(CONF_OPNSENSE_SECRET, ""),
                verify_ssl=verify_ssl,
                interface=(self.options.get(CONF_OPNSENSE_INTERFACE) or "").strip(),
            )
        if prov == PRESENCE_ADGUARD:
            return await adguard.async_get_devices(
                session=self.session,
                base_url=(self.options.get(CONF_ADGUARD_URL) or "").rstrip("/"),
                username=self.options.get(CONF_ADGUARD_USERNAME, ""),
                password=self.options.get(CONF_ADGUARD_PASSWORD, ""),
                verify_ssl=verify_ssl,
            )

        _LOGGER.warning("Unknown presence_provider=%s", prov)
        return []

    async def _collect_unifi(self) -> List[Dict[str, Any]]:
        if not bool(self.options.get(CONF_UNIFI_ENABLED, False)):
            return []

        verify_ssl = bool(self.options.get(CONF_VERIFY_SSL, False))
        return await unifi.async_get_devices(
            session=self.session,
            base_url=(self.options.get(CONF_UNIFI_URL) or "").rstrip("/"),
            token=self.options.get(CONF_UNIFI_TOKEN, ""),
            username=self.options.get(CONF_UNIFI_USERNAME, ""),
            password=self.options.get(CONF_UNIFI_PASSWORD, ""),
            site=self.options.get(CONF_UNIFI_SITE, "default"),
            verify_ssl=verify_ssl,
        )

    async def _build_directory(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}

        # text
        jtxt = _norm(self.options.get(CONF_MAC_DIRECTORY_JSON_TEXT))
        if jtxt:
            try:
                out.update(_parse_dir_obj(json.loads(jtxt)))
            except Exception as exc:
                _LOGGER.warning("Invalid directory JSON text: %s", exc)

        # url
        url = _norm(self.options.get(CONF_MAC_DIRECTORY_JSON_URL))
        if url:
            try:
                async with self.session.get(url, timeout=10) as resp:
                    body = await resp.text()
                    if resp.status >= 400:
                        _LOGGER.warning("Directory URL HTTP %s: %.200s", resp.status, body)
                    else:
                        try:
                            out.update(_parse_dir_obj(json.loads(body)))
                        except Exception as exc:
                            _LOGGER.warning("Directory URL invalid JSON: %s %.200s", exc, body)
            except (ClientError, Exception) as exc:
                _LOGGER.warning("Directory URL fetch failed: %s", exc)

        return out

    def _merge_device(self, dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
        """Merge with sensible precedence (keep existing good identity, fill gaps)."""

        def take(key: str, prefer_existing: bool = False):
            v = src.get(key)
            if v is None or v == "" or (isinstance(v, (list, dict)) and not v):
                return
            if prefer_existing and dst.get(key):
                return
            dst[key] = v

        # identity + common
        take("mac", prefer_existing=True)
        take("ip", prefer_existing=True)
        take("hostname", prefer_existing=True)
        take("vendor", prefer_existing=True)

        # richer fields
        for k in ("name", "desc", "device_type", "wired", "ssid", "vlan_id", "network_role", "interface"):
            take(k, prefer_existing=True)

        # nested common blocks
        for block in ("opnsense", "adguard", "unifi", "ap", "switch", "signal", "bytes", "dhcp"):
            if block in src and block not in dst:
                dst[block] = src[block]

        # sources
        s = set(dst.get("sources") or [])
        for x in (src.get("sources") or []):
            if x:
                s.add(str(x))
        dst["sources"] = sorted(s)

        return dst

    def _apply_directory(self, dev: Dict[str, Any], directory: Dict[str, Dict[str, str]]) -> None:
        mac = _clean_mac(dev.get("mac", ""))
        if not mac:
            return
        ov = directory.get(mac)
        if not ov:
            return
        if ov.get("name"):
            dev["name"] = ov["name"]
        if ov.get("desc"):
            dev["desc"] = ov["desc"]

    async def _async_update_data(self) -> Dict[str, Any]:
        await self._ensure_inventory_loaded()
        assert self._inventory is not None

        self.last_scan_started = _now_iso()
        started = dt_util.utcnow()

        try:
            presence = await self._collect_presence()
            unifi_list = await self._collect_unifi()
            directory = await self._build_directory()

            # Index + merge by MAC preferred, else IP
            by_key: Dict[str, Dict[str, Any]] = {}

            def ingest(items: List[Dict[str, Any]], source: str):
                for d in items or []:
                    mac = _clean_mac(d.get("mac", ""))
                    ip = (d.get("ip") or "").strip()
                    k = self._key_of(mac, ip)
                    if not k:
                        continue

                    cur = by_key.get(k) or {
                        "mac": mac,
                        "ip": ip,
                        "hostname": "",
                        "vendor": "",
                        "name": "",
                        "desc": "",
                        "device_type": "unknown",
                        "wired": None,
                        "ssid": "",
                        "vlan_id": None,
                        "network_role": "",
                        "interface": "",
                        "ap": {"mac": "", "name": ""},
                        "switch": {"mac": "", "name": "", "port": None, "port_name": "", "poe": None},
                        "signal": {"rssi": None, "snr": None},
                        "bytes": {"tx": 0, "rx": 0},
                        "dhcp": {"server": "", "lease_ip": "", "reservation_ip": ""},
                        "sources": [],
                        "derived": {},
                        "first_seen": "",
                        "last_seen": "",
                    }

                    # Normalise a couple of common fields from provider payloads if present
                    nd = dict(d)
                    nd["mac"] = mac
                    nd["ip"] = ip

                    # Ensure sources list
                    nd["sources"] = sorted(set((cur.get("sources") or []) + [source]))

                    by_key[k] = self._merge_device(cur, nd)

            # Presence first (base truth)
            prov = self.options.get(CONF_PRESENCE_PROVIDER, PRESENCE_OPNSENSE)
            ingest(presence, prov)

            # UniFi enrichment (may introduce devices that presence didn’t see)
            ingest(unifi_list, "unifi")

            # Apply directory overrides
            for dev in by_key.values():
                self._apply_directory(dev, directory)

            # Inventory merge (first_seen/last_seen + new/random/stale)
            now = dt_util.utcnow()
            now_ts = now.timestamp()
            stale_hours = STALE_HOURS_DEFAULT

            new_count = 0
            random_count = 0
            stale_count = 0

            def _parse_iso(s: str | None):
                try:
                    return dt_util.parse_datetime(s) if s else None
                except Exception:
                    return None

            for k, dev in by_key.items():
                mac = _clean_mac(dev.get("mac", ""))
                ip = (dev.get("ip") or "").strip()

                # derive random/private
                is_random = _is_locally_administered(mac)
                if is_random:
                    random_count += 1

                prev = self._inventory.get(k, {})
                was_known = bool(prev)
                if not was_known:
                    new_count += 1

                prev_last = _parse_iso(prev.get("last_seen"))
                is_stale = bool(prev_last and (now - prev_last) > timedelta(hours=stale_hours))
                if is_stale:
                    stale_count += 1

                # last_seen: prefer unifi timestamp if present, else "now"
                last_seen_ts = None
                uni = dev.get("unifi") or {}
                u_ts = uni.get("last_seen_ts") or uni.get("last_seen")  # accept either if your provider sets it
                if isinstance(u_ts, (int, float)) and u_ts > 0:
                    last_seen_ts = float(u_ts)
                if last_seen_ts is None:
                    last_seen_ts = now_ts

                stored = {
                    "first_seen": prev.get("first_seen") or now.isoformat(),
                    "last_seen": dt_util.utc_from_timestamp(last_seen_ts).isoformat(),
                }
                if stored != prev:
                    self._inventory[k] = stored

                dev["first_seen"] = stored["first_seen"]
                dev["last_seen"] = stored["last_seen"]

                dev.setdefault("derived", {})
                dev["derived"]["new_device"] = not was_known
                dev["derived"]["random_mac"] = is_random
                dev["derived"]["stale"] = is_stale

                # Fire events for new devices
                if not was_known:
                    payload = {
                        "key": k,
                        "mac": mac,
                        "ip": ip,
                        "hostname": dev.get("hostname") or "",
                        "vendor": dev.get("vendor") or "",
                        "sources": dev.get("sources") or [],
                        "random_mac": is_random,
                    }
                    self.hass.bus.async_fire(EVENT_DEVICE_NEW, payload)
                    if is_random:
                        self.hass.bus.async_fire(EVENT_DEVICE_NEW_RANDOM, payload)

            await self._store.async_save(self._inventory)

            # Publish device map
            self.devices_by_key = by_key

            self.last_scan_finished = _now_iso()
            finished = dt_util.utcnow()
            dur_ms = int((finished - started).total_seconds() * 1000)

            # Summary only (keep small!)
            return {
                "status": "ok",
                "presence_provider": self.options.get(CONF_PRESENCE_PROVIDER, ""),
                "unifi_enabled": bool(self.options.get(CONF_UNIFI_ENABLED, False)),
                "device_count_total": len(by_key),
                "device_count_new": new_count,
                "device_count_random_mac": random_count,
                "device_count_stale": stale_count,
                "last_scan_started": self.last_scan_started,
                "last_scan_finished": self.last_scan_finished,
                "duration_ms": dur_ms,
                "error_count": self.error_count,
                "last_error": self.last_error or "",
            }

        except Exception as exc:
            self.error_count += 1
            self.last_error = str(exc)
            self.last_scan_finished = _now_iso()

            self.hass.bus.async_fire(EVENT_SCAN_ERROR, {"error": str(exc)})

            raise UpdateFailed(str(exc)) from exc

    async def async_cleanup_entities(self, mode: str, older_than_days: int, startup: bool) -> None:
        """Remove device_tracker entities based on mode."""
        ent_reg = async_get_entity_registry(self.hass)
        cutoff = dt_util.utcnow() - timedelta(days=max(1, int(older_than_days)))

        # Ensure inventory loaded (for stale decisions)
        await self._ensure_inventory_loaded()
        inv = self._inventory or {}

        removed: list[str] = []
        inspected = 0

        for entity_id, ent in list(ent_reg.entities.items()):
            if ent.config_entry_id != self.entry.entry_id:
                continue
            if ent.domain != "device_tracker":
                continue
            inspected += 1

            # unique_id format: "{entry_id}:{key}"
            unique_id = ent.unique_id or ""
            if ":" not in unique_id:
                continue
            _, key = unique_id.split(":", 1)

            mac = _clean_mac(key) if not key.startswith("IP:") else ""
            is_random = _is_locally_administered(mac) if mac else False

            # stale check uses inventory last_seen if available
            last_seen_iso = (inv.get(key) or {}).get("last_seen")
            last_seen_dt = None
            try:
                last_seen_dt = dt_util.parse_datetime(last_seen_iso) if last_seen_iso else None
            except Exception:
                last_seen_dt = None
            is_stale = bool(last_seen_dt and last_seen_dt < cutoff)

            should_remove = False
            if mode == CLEANUP_MODE_ALL:
                should_remove = True
            elif mode == CLEANUP_MODE_RANDOM_ONLY:
                should_remove = is_random
            elif mode == CLEANUP_MODE_STALE_ONLY:
                should_remove = is_stale

            if should_remove:
                ent_reg.async_remove(entity_id)
                removed.append(entity_id)

        if removed:
            _LOGGER.warning(
                "Cleanup (%s): removed=%d inspected=%d older_than_days=%d startup=%s",
                mode, len(removed), inspected, older_than_days, startup
            )
        else:
            _LOGGER.debug(
                "Cleanup (%s): removed=0 inspected=%d older_than_days=%d startup=%s",
                mode, inspected, older_than_days, startup
            )
