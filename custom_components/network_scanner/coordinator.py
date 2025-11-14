"""Data coordinator for the Network Scanner integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict, List

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
STALE_HOURS = 24  # mark devices stale after this many hours

async def async_setup_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> None:
    hass.data.setdefault(DOMAIN, {})
    coordinator = NetworkScannerCoordinator(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = coordinator
    # DO NOT forward platforms here (done in __init__.py)
    hass.async_create_task(coordinator.async_request_refresh())

async def async_unload_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    # DO NOT unload platforms here (done in __init__.py)
    hass.data[DOMAIN].pop(entry.entry_id, None)
    return True

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

        self._store = Store(hass, STORE_VERSION, f"{DOMAIN}_inventory_{entry.entry_id}")
        self._inventory: Dict[str, Dict[str, Any]] | None = None  # key -> stored record
        
    def _build_views(self, merged: list[dict]) -> dict:
        flat = []
        idx_mac: dict[str, int] = {}
        idx_ip: dict[str, int] = {}
        vendors: dict[str, int] = {}
        vlans: dict[str, int] = {}
    
        for i, d in enumerate(merged):
            ip = d.get("ip") or (d.get("ips", [None])[0] if d.get("ips") else None)
            mac = (d.get("mac") or "").upper()
            role = d.get("network_role") or ""
            vlan_id = d.get("vlan_id")
            v = d.get("vendor") or "Unknown"
    
            flat.append({
                "hostname": d.get("hostname") or "",
                "ip": ip or "",
                "mac": mac,
                "vendor": v,
                "role": role,
                "vlan_id": vlan_id,
                "type": d.get("device_type") or "unknown",
                "site": d.get("site") or "",
                "new": bool((d.get("derived") or {}).get("new_device")),
                "risk": (d.get("derived") or {}).get("risk_score", 0),
                "first_seen": d.get("first_seen") or "",
                "last_seen": d.get("last_seen") or "",
                "source_str": ",".join(d.get("sources", [])) if d.get("sources") else (d.get("source") or ""),
            })
    
            if mac:
                idx_mac[mac] = i
            if ip:
                idx_ip[ip] = i
    
            vendors[v] = vendors.get(v, 0) + 1
            key_vlan = str(vlan_id) if vlan_id is not None else "None"
            vlans[key_vlan] = vlans.get(key_vlan, 0) + 1
    
        return {
            "flat": flat,
            "index": {"mac": idx_mac, "ip": idx_ip},
            "summary": {"vendors": vendors, "vlans": vlans},
        }

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

            now = dt_util.utcnow()
            now_ts = now.timestamp()
            
            def _epoch_to_iso(v):
                try:
                    return dt_util.utc_from_timestamp(float(v)).isoformat()
                except Exception:
                    return None

            def _parse_iso(dt_str: str | None):
                try:
                    return dt_util.parse_datetime(dt_str) if dt_str else None
                except Exception:
                    return None
            
            def _best_seen_iso_for_device(dev: Dict[str, Any], prev_last_iso: str | None) -> str:
                """
                Choose the best last_seen time we can infer from provider signals.
                Priority:
                  1) UniFi 'last_seen' (epoch seconds)
                  2) OPNsense ARP 'expires' (approximate: now - (TTL - expires))
                  3) Previous stored last_seen (don’t regress)
                  4) now() as a last resort
                """
                candidates_ts: list[float] = []
            
                # UniFi: prefer true 'last_seen' if provider supplies it
                uni = dev.get("unifi") or {}
                uni_last_seen = uni.get("last_seen_ts")  # <-- you'll add this in the UniFi provider (see step 2)
                if isinstance(uni_last_seen, (int, float)) and uni_last_seen > 0:
                    candidates_ts.append(float(uni_last_seen))
            
                # OPNsense: approximate from ARP 'expires' counter
                op = dev.get("opnsense") or {}
                exp = op.get("arp_expires_s")
                perm = op.get("arp_permanent")
                if isinstance(exp, (int, float)) and exp >= 0 and not perm:
                    # If TTL is 1200 and expires==1190, we "saw" it ~10s ago.
                    seen_ts = now_ts - max(0.0, float(ASSUMED_ARP_TTL_S) - float(exp))
                    candidates_ts.append(seen_ts)
            
                # Previous store value, if present (avoid regressions)
                if prev_last_iso:
                    prev_dt = dt_util.parse_datetime(prev_last_iso)
                    if prev_dt:
                        candidates_ts.append(prev_dt.timestamp())
            
                # Fallback: we did see the device in this scan, so 'now'
                if not candidates_ts:
                    candidates_ts.append(now_ts)
            
                best_ts = max(candidates_ts)
                return dt_util.utc_from_timestamp(best_ts).isoformat()

            
            for d in merged:
                key = d["mac"] or (f"IP:{d['ips'][0]}" if d.get("ips") else None)
                if not key:
                    continue
            
                prev = self._inventory.get(key, {})
                was_known = bool(prev)
                prev_last_dt = _parse_iso(prev.get("last_seen"))
            
                deriv = d.setdefault("derived", {})
                deriv["new_device"] = not was_known
                deriv["stale"] = bool(prev_last_dt and (now - prev_last_dt) > timedelta(hours=STALE_HOURS))
            
                # carry forward user annotations if present
                for k in ("owner", "room", "notes", "tags_user"):
                    if k in prev and k not in deriv:
                        deriv[k] = prev[k]
            
                # --- build a "best_seen" by source ---
                # UniFi: if you can add last_seen_ts in provider, prefer it
                uni = d.get("unifi") or {}
                best_seen_iso = _epoch_to_iso(uni.get("last_seen_ts"))  # may be None
            
                # OPNsense: if the ARP entry is present and not expired/permanent -> seen now
                opn = d.get("opnsense") or {}
                if not best_seen_iso:
                    if opn.get("arp_permanent") is True:
                        best_seen_iso = now.isoformat()
                    elif opn.get("arp_expired") is False:
                        best_seen_iso = now.isoformat()
            
                # Fallback: if device is present this cycle, we can treat as seen now
                if not best_seen_iso:
                    best_seen_iso = now.isoformat()
            
                # choose the newer of previous vs current (compare as datetimes)
                best_seen_dt = _parse_iso(best_seen_iso)
                if prev_last_dt and best_seen_dt and prev_last_dt > best_seen_dt:
                    final_last_seen_iso = prev.get("last_seen")
                else:
                    final_last_seen_iso = best_seen_iso
            
                stored = {
                    "first_seen": prev.get("first_seen") or now.isoformat(),
                    "last_seen": final_last_seen_iso,
                    **{k: prev.get(k) for k in ("owner", "room", "notes", "tags_user") if prev.get(k) is not None},
                }
            
                if stored != prev:
                    self._inventory[key] = stored
                    changed = True
            
                # Surface timestamps for UI/templates
                d["first_seen"] = stored["first_seen"]
                d["last_seen"]  = stored["last_seen"]
            
                # recompute risk AFTER flags are set
                deriv["risk_score"] = self._risk_score(d)

            
            if changed:
                await self._store.async_save(self._inventory)

                
            views = self._build_views(merged)
            
            return {
                "devices": merged,
                "count": len(merged),
                "last_refresh_utc": now_iso,
                **views,   # flat, index, summary
            }              
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
                iw = d["unifi"].get("is_wired")
                if iw is True:
                    cur["device_type"] = "wired"
                elif iw is False:
                    cur["device_type"] = "wifi"
                # else leave whatever it was (default "unknown")
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

        # ingest all
        for src_name, items in (src or {}).items():
            for d in items or []:
                add(d, src_name)

        # derive vlan_id, role, risk, timestamps placeholders
        out: List[Dict[str, Any]] = []
        for k, dev in by_key.items():
            vlan_id = self._derive_vlan_id(dev)
            dev["vlan_id"] = vlan_id

            dev.setdefault("derived", {})  # flags filled later after store merge

            out.append(dev)

        # sort for stable UI (hostname, then MAC/IP)
        out.sort(key=lambda d: (d.get("hostname") or "", d.get("mac") or d["ips"][0] if d.get("ips") else ""))
        return out

    @staticmethod
    def _derive_vlan_id(dev: Dict[str, Any]) -> int | None:
        # Prefer UniFi VLAN if present
        uni = dev.get("unifi") or {}
        try:
            if "vlan" in uni and uni["vlan"] is not None:
                return int(uni["vlan"])
        except (TypeError, ValueError):
            pass
    
        # Fallback: parse from interface like 'vlan0.2'
        intf = (dev.get("interface") or "").replace(". ", ".")
        if intf.startswith("vlan") and "." in intf:
            try:
                return int(intf.split(".")[-1])
            except (TypeError, ValueError):
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
