"""Data coordinator for the Network Scanner integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict, List
import json
import re
from aiohttp import ClientError

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    DEFAULT_OPTIONS,
    CONF_PROVIDERS,
    CONF_VERIFY_SSL,
    CONF_INTERVAL_MIN,
    # OPNsense
    CONF_OPNSENSE_URL, CONF_KEY, CONF_SECRET,
    # UniFi
    CONF_UNIFI_URL, CONF_UNIFI_TOKEN, CONF_UNIFI_USER, CONF_UNIFI_PASS, CONF_UNIFI_SITE,
    # AdGuard
    CONF_ADGUARD_URL, CONF_ADGUARD_USER, CONF_ADGUARD_PASS,
    CONF_MAC_DIRECTORY_JSON_URL, CONF_MAC_DIRECTORY_JSON_TEXT,

)


from .provider import opnsense, unifi, adguard

_LOGGER = logging.getLogger(__name__)

STORE_VERSION = 1
STALE_HOURS = 24  # mark devices stale after this many hours
ASSUMED_FALLBACK_ARP_TTL_S = 1200.0  # typical OPNsense ARP TTL if we can't infer it


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
    
_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", re.IGNORECASE)

def _norm_mac(v: str | None) -> str:
    m = (v or "").strip().upper()
    return m if _MAC_RE.match(m) else ""


class NetworkScannerCoordinator(DataUpdateCoordinator[Dict[str, Any]]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self._mac_dir: dict[str, dict[str, Any]] = {}
        self._mac_dir_loaded_utc: str | None = None

        raw = dict(entry.options or entry.data or {})
        self.options = {**DEFAULT_OPTIONS, **raw}

        self.session = async_get_clientsession(hass)

        interval_min = max(1, int(self.options.get(CONF_INTERVAL_MIN, 3)))
        update_interval = timedelta(minutes=interval_min)

        super().__init__(
            hass,
            _LOGGER,
            name="network_scanner_coordinator",
            update_method=self._async_update_data,
            update_interval=update_interval,
        )

        self._store = Store(hass, STORE_VERSION, f"{DOMAIN}_inventory_{entry.entry_id}")
        self._inventory: Dict[str, Dict[str, Any]] | None = None  # key -> stored record

    def device_uids(self) -> list[str]:
        """Return stable IDs for devices currently present (used for cleanup)."""
        devices = (self.data or {}).get("devices", [])
        out: list[str] = []
        for d in devices:
            mac = (d.get("mac") or "").upper()
            if mac:
                out.append(mac)
            elif d.get("ips"):
                out.append(f"IP:{d['ips'][0]}")
        return out
    
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
            now = dt_util.utcnow()
            now_iso = now.isoformat()
            now_ts = now.timestamp()

            raw_devices = await self._collect_raw_devices()
            merged = self._merge_and_enrich(raw_devices)
            
            # Load MAC directory overlay (optional)
            mac_dir = await self._load_mac_directory()
            
            # Apply directory overlay to merged devices (by MAC)
            if mac_dir:
                for d in merged:
                    mac = _norm_mac(d.get("mac"))
                    if not mac:
                        continue
                    meta = mac_dir.get(mac)
                    if not meta:
                        continue
            
                    deriv = d.setdefault("derived", {})
                    deriv["directory_name"] = (meta.get("name") or meta.get("display_name") or "").strip()
                    deriv["directory_desc"] = (meta.get("desc") or meta.get("description") or "").strip()
            
                    # Optional: if hostname empty, use directory name
                    if deriv["directory_name"] and not (d.get("hostname") or "").strip():
                        d["hostname"] = deriv["directory_name"]
            
            # --- Estimate ARP TTL from this sample (max expires of non-permanent entries) ---
            op_ttl_guess_s: float | None = None
            for d in merged:
                op = d.get("opnsense") or {}
                exp = op.get("arp_expires_s")
                perm = op.get("arp_permanent")
                if isinstance(exp, (int, float)) and exp >= 0 and not perm:
                    op_ttl_guess_s = max(op_ttl_guess_s or 0.0, float(exp))
            
            if op_ttl_guess_s is None:
                op_ttl_guess_s = ASSUMED_FALLBACK_ARP_TTL_S
            
            _LOGGER.debug("Network Scanner: inferred ARP TTL ~ %.0fs", op_ttl_guess_s)
               
            changed = False

            def _parse_iso(dt_str: str | None):
                try:
                    return dt_util.parse_datetime(dt_str) if dt_str else None
                except Exception:
                    return None

            for d in merged:
                key = d.get("mac") or (f"IP:{d['ips'][0]}" if d.get("ips") else None)
                if not key:
                    continue

                prev = self._inventory.get(key, {})
                was_known = bool(prev)
                prev_last_iso = prev.get("last_seen")
                prev_last_dt = _parse_iso(prev_last_iso)

                deriv = d.setdefault("derived", {})
                deriv["new_device"] = not was_known
                deriv["stale"] = bool(prev_last_dt and (now - prev_last_dt) > timedelta(hours=STALE_HOURS))

                # carry forward user annotations if present
                for k in ("owner", "room", "notes", "tags_user"):
                    if k in prev and k not in deriv:
                        deriv[k] = prev[k]

                # ---- Build a best "last_seen" by source ----
                cand_ts: list[float] = []
                last_seen_source = "fallback"

                # 1) UniFi 'last_seen_ts' if provider exposes it
                uni = d.get("unifi") or {}
                u_ts = uni.get("last_seen_ts")
                if isinstance(u_ts, (int, float)) and u_ts > 0:
                    cand_ts.append(float(u_ts))
                    last_seen_source = "unifi"

                # 2) OPNsense ARP-based approximation
                opn = d.get("opnsense") or {}
                exp = opn.get("arp_expires_s")
                perm = opn.get("arp_permanent")
                if isinstance(exp, (int, float)) and exp >= 0:
                    # Permanent entries don’t age -> we treat them as seen "now"
                    if perm is True:
                        cand_ts.append(now_ts)
                        last_seen_source = "opnsense"
                    else:
                        seen_ts = now_ts - max(0.0, float(op_ttl_guess_s) - float(exp))
                        cand_ts.append(seen_ts)
                        last_seen_source = "opnsense"

                # 3) AdGuard "clients" is the only real "active-ish" signal when using AdGuard only
                adg = d.get("adguard") or {}
                if adg.get("from") == "clients":
                    cand_ts.append(now_ts)
                    last_seen_source = "adguard"

                # 4) Keep previous store to avoid regressions
                if prev_last_dt:
                    cand_ts.append(prev_last_dt.timestamp())

                # 5) Absolute fallback: if we have no signal at all, don't invent recency
                # (If you *do* want everything to look online, you can append now_ts here – but it lies.)
                if not cand_ts:
                    cand_ts.append(now_ts)
                    last_seen_source = "fallback"
                    
                final_last_seen_iso = dt_util.utc_from_timestamp(max(cand_ts)).isoformat()
                deriv["last_seen_source"] = last_seen_source

                stored = {
                    "first_seen": prev.get("first_seen") or now_iso,
                    "last_seen": final_last_seen_iso,
                    **{k: prev.get(k) for k in ("owner", "room", "notes", "tags_user") if prev.get(k) is not None},
                }

                if stored != prev:
                    self._inventory[key] = stored
                    changed = True

                # Surface timestamps for UI/templates
                d["first_seen"] = stored["first_seen"]
                d["last_seen"] = stored["last_seen"]

                # recompute risk AFTER flags are set
                deriv["risk_score"] = self._risk_score(d)

            if changed:
                await self._store.async_save(self._inventory)

            views = self._build_views(merged)

            return {
                "devices": merged,
                "count": len(merged),
                "last_refresh_utc": now_iso,
                **views,  # flat, index, summary
            }
        except Exception as exc:
            raise UpdateFailed(str(exc)) from exc

    async def _collect_raw_devices(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect device lists from enabled providers; keys are provider names."""
        providers = self.options.get(CONF_PROVIDERS) or []
        providers = list(providers) if isinstance(providers, (list, set, tuple)) else [providers]
    
        verify = bool(self.options.get(CONF_VERIFY_SSL, True))
    
        def _rstrip(v: str) -> str:
            return (v or "").strip().rstrip("/")
    
        out: Dict[str, List[Dict[str, Any]]] = {}
    
        if "opnsense" in providers:
            out["opnsense"] = await opnsense.async_get_devices(
                session=self.session,
                base_url=_rstrip(self.options.get(CONF_OPNSENSE_URL, "")),
                key=(self.options.get(CONF_KEY) or "").strip(),
                secret=(self.options.get(CONF_SECRET) or "").strip(),
                verify_ssl=verify,
            )
    
        if "unifi" in providers:
            out["unifi"] = await unifi.async_get_devices(
                session=self.session,
                base_url=_rstrip(self.options.get(CONF_UNIFI_URL, "")),
                token=(self.options.get(CONF_UNIFI_TOKEN) or "").strip(),
                username=(self.options.get(CONF_UNIFI_USER) or "").strip(),
                password=(self.options.get(CONF_UNIFI_PASS) or "").strip(),
                site=(self.options.get(CONF_UNIFI_SITE) or "default").strip(),
                verify_ssl=verify,
            )
    
        if "adguard" in providers:
            out["adguard"] = await adguard.async_get_devices(
                session=self.session,
                base_url=_rstrip(self.options.get(CONF_ADGUARD_URL, "")),
                username=(self.options.get(CONF_ADGUARD_USER) or "").strip(),
                password=(self.options.get(CONF_ADGUARD_PASS) or "").strip(),
                verify_ssl=verify,
            )
    
        return out

    async def _load_mac_directory(self) -> dict[str, dict[str, Any]]:
        """Load directory overlay from JSON text or URL. Returns dict keyed by MAC."""
        # Prefer inline text if provided
        raw_text = (self.options.get(CONF_MAC_DIRECTORY_JSON_TEXT) or "").strip()
        url = (self.options.get(CONF_MAC_DIRECTORY_JSON_URL) or "").strip()

        data: Any = None
    
        if raw_text:
            try:
                data = json.loads(raw_text)
            except Exception as exc:
                _LOGGER.warning("MAC directory JSON text is invalid: %s", exc)
                return {}
    
        elif url:
            try:
                async with self.session.get(url, ssl=bool(self.options.get("verify_ssl", True))) as r:
                    if r.status != 200:
                        _LOGGER.warning("MAC directory URL returned HTTP %s", r.status)
                        return {}
                    data = await r.json(content_type=None)
            except (ClientError, Exception) as exc:
                _LOGGER.warning("MAC directory URL fetch failed: %s", exc)
                return {}
    
        else:
            return {}
    
        out: dict[str, dict[str, Any]] = {}
    
        # Support either:
        # 1) {"AA:BB:...": {"name": "...", "desc": "..."}}
        # 2) [{"mac":"AA:BB:...","name":"...","desc":"..."}]
        if isinstance(data, dict):
            for mac, meta in data.items():
                m = _norm_mac(str(mac))
                if not m or not isinstance(meta, dict):
                    continue
                out[m] = meta
    
        elif isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                m = _norm_mac(row.get("mac"))
                if not m:
                    continue
                out[m] = row
    
        _LOGGER.debug("MAC directory loaded: %d entries", len(out))
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
            if ip:
                ips.add(str(ip))
            cur["ips"] = sorted(ips)

            # prefer non-empty hostname/vendor
            cur["hostname"] = cur["hostname"] or d.get("hostname") or ""
            cur["vendor"] = cur["vendor"] or d.get("vendor") or ""

            # attach provider blocks if present
            for block in ("opnsense", "unifi", "adguard"):
                if block in d and block not in cur:
                    cur[block] = d[block]

            # quick device_type + interface from provider blocks
            if "unifi" in d:
                iw = d["unifi"].get("is_wired")
                if iw is True:
                    cur["device_type"] = "wired"
                elif iw is False:
                    cur["device_type"] = "wifi"
                cur["site"] = d["unifi"].get("site") or cur["site"]

            if "opnsense" in d:
                cur["interface"] = d["opnsense"].get("intf") or cur["interface"]
                nr = d["opnsense"].get("intf_description")
                if nr:
                    cur["network_role"] = nr

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

        # derive vlan_id, timestamps placeholders (risk later)
        out: List[Dict[str, Any]] = []
        for dev in by_key.values():
            vlan_id = self._derive_vlan_id(dev)
            dev["vlan_id"] = vlan_id
            dev.setdefault("derived", {})  # flags filled later after store merge
            out.append(dev)

        # sort for stable UI (hostname, then MAC/IP)
        out.sort(key=lambda d: (d.get("hostname") or "", d.get("mac") or (d["ips"][0] if d.get("ips") else "")))
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
        if not dev.get("vendor"):
            score += 30
        if dev.get("device_type") == "wifi" and (dev.get("network_role") or "").lower() not in ("iot", "guest", "media"):
            score += 20
        if dev.get("derived", {}).get("new_device"):
            score += 10
        if (dev.get("network_role") or "").lower() == "guest":
            score += 5
        return max(0, min(100, score))
