# custom_components/network_scanner_extended/controller.py
from __future__ import annotations
from typing import Any, Dict, List, Optional
import json
import logging
from datetime import datetime, timezone

import nmap
from aiohttp import ClientError
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN, DEFAULT_NMAP_ARGS, DEFAULT_SCAN_INTERVAL,
    CONF_ARP_PROVIDER, CONF_ARP_BASE_URL, CONF_ARP_KEY, CONF_ARP_SECRET, CONF_ARP_VERIFY_TLS,
    ARP_PROVIDER_NONE, ARP_PROVIDER_OPNSENSE,
)
from .opnsense import OPNsenseARPClient

_LOGGER = logging.getLogger(__name__)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _norm_mac(s: Optional[str]) -> str:
    return (s or "").upper()

def _ip_key(ip: str) -> List[int]:
    try: return [int(p) for p in ip.split(".")]
    except Exception: return [999,999,999,999]

def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(obj, dict): return out
    block = obj.get("data", obj)
    if not isinstance(block, dict): return out
    for k, v in block.items():
        mk = _norm_mac(k)
        if not mk and isinstance(k, str) and k.count(".") == 3:
            # allow IP keys in directory
            mk = k.strip()  # keep as IP
        if not mk: continue
        if isinstance(v, dict):
            out[mk] = {"name": str(v.get("name","")), "desc": str(v.get("desc",""))}
        else:
            out[mk] = {"name": str(v), "desc": ""}
    return out

class ScanController:
    """Holds config, runs scans, merges ARP, exposes state."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.nm = nmap.PortScanner()
        self.devices: List[Dict[str, Any]] = []
        self.device_count: Optional[int] = None
        self.status: str = "idle"
        self.last_scan_started: Optional[str] = None
        self.last_scan_finished: Optional[str] = None

        # populated by apply_entry
        self.cidrs: List[str] = []
        self.nmap_args: str = DEFAULT_NMAP_ARGS
        self.scan_interval: int = DEFAULT_SCAN_INTERVAL

        # ARP enrichment
        self._arp_provider: str = ARP_PROVIDER_NONE
        self._arp: Optional[OPNsenseARPClient] = None

        self.apply_entry(entry)

    def apply_entry(self, entry: ConfigEntry) -> None:
        data = entry.data or {}
        opts = entry.options or {}
        raw_ranges = (opts.get("ip_range") or data.get("ip_range") or "").strip()
        self.cidrs = [p.strip() for p in raw_ranges.replace(",", " ").split() if p.strip()]
        self.nmap_args = (opts.get("nmap_args") or data.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        self.scan_interval = int(opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL)))

        # ARP provider config
        prov = (opts.get(CONF_ARP_PROVIDER, data.get(CONF_ARP_PROVIDER, ARP_PROVIDER_NONE)) or "").lower()
        base = opts.get(CONF_ARP_BASE_URL,   data.get(CONF_ARP_BASE_URL,   ""))
        key  = opts.get(CONF_ARP_KEY,        data.get(CONF_ARP_KEY,        ""))
        sec  = opts.get(CONF_ARP_SECRET,     data.get(CONF_ARP_SECRET,     ""))
        vfy  = bool(opts.get(CONF_ARP_VERIFY_TLS, data.get(CONF_ARP_VERIFY_TLS, True)))

        self._arp_provider = prov
        self._arp = None
        if prov == ARP_PROVIDER_OPNSENSE and base and key and sec:
            self._arp = OPNsenseARPClient(base, key, sec, verify_tls=vfy)

    async def maybe_auto_scan(self) -> None:
        """Run a scan if auto-scan is enabled (scan_interval > 0)."""
        if self.scan_interval == 0:
            return
        await self.run_scan()

    async def run_scan(self) -> None:
        try:
            self.status = "scanning"
            self.last_scan_started = _now_iso()

            # Build effective directory: entry data + options JSON/URL already parsed by your flow
            directory: Dict[str, Dict[str, str]] = {}
            entry = self._get_entry()
            directory.update(entry.data.get("mac_directory", {}))
            jtxt = (entry.options.get("mac_directory_json_text") or "")
            if jtxt:
                try:
                    directory.update(_parse_dir_obj(json.loads(jtxt)))
                except Exception as exc:
                    _LOGGER.debug("Directory JSON invalid: %s", exc)
            url = entry.options.get("mac_directory_json_url") or entry.data.get("mac_directory_json_url")
            if url:
                try:
                    session = async_get_clientsession(self.hass)
                    async with session.get(url, timeout=10) as resp:
                        resp.raise_for_status()
                        directory.update(_parse_dir_obj(json.loads(await resp.text())))
                except (ClientError, Exception) as exc:
                    _LOGGER.debug("Directory URL fetch failed: %s", exc)

            # ARP enrichment from OPNsense (optional)
            arp_map: Dict[str, str] = {}
            if self._arp:
                try:
                    arp_map = await self._arp.fetch_map(self.hass)
                except Exception as exc:
                    _LOGGER.debug("OPNsense ARP fetch failed: %s", exc)

            # Scan each CIDR
            all_devices: List[Dict[str, Any]] = []
            for cidr in self.cidrs:
                all_devices.extend(await self.hass.async_add_executor_job(self._scan_cidr, cidr, directory, arp_map, self.nmap_args))

            # Deduplicate: prefer MAC, fallback to IP
            dedup: Dict[str, Dict[str, Any]] = {}
            for d in all_devices:
                key = _norm_mac(d.get("mac")) or f"IP:{d.get('ip','')}"
                if key and key not in dedup:
                    dedup[key] = d

            devices = list(dedup.values())
            devices.sort(key=lambda d: _ip_key(d.get("ip", "")))

            self.devices = devices
            self.device_count = len(devices)
            self.status = "ok"
        except Exception as exc:
            self.status = "error"
            _LOGGER.error("Network scan failed: %s", exc)
        finally:
            self.last_scan_finished = _now_iso()

    # -------- internals --------

    def _get_entry(self) -> ConfigEntry:
        # Helper to find the current entry via hass.data
        for entry_id, blob in self.hass.data.get(DOMAIN, {}).items():
            if blob.get("controller") is self:
                # @ts-ignore - we don’t need the actual type here
                return blob["entry"] if "entry" in blob else blob.get("config_entry") or blob.get("entry_obj")
        # Fallback: not strictly needed if you pass entry in hass.data
        raise RuntimeError("controller: config entry not found in hass.data")

    def _scan_cidr(self, cidr: str, directory: Dict[str, Dict[str, str]], arp_map: Dict[str, str], nmap_args: str) -> List[Dict[str, Any]]:
        res: List[Dict[str, Any]] = []
        self.nm.scan(hosts=cidr, arguments=nmap_args)
        for host in self.nm.all_hosts():
            try:
                node = self.nm[host]
                addrs = node.get("addresses", {})
                ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
                mac = addrs.get("mac") or ""

                # Enrich MAC from router ARP map if missing (typical across VLANs)
                if not mac and ip and ip in arp_map:
                    mac = arp_map[ip]

                # Vendor
                vendor = "Unknown"
                ven_map = node.get("vendor", {})
                if isinstance(ven_map, dict):
                    for k, v in ven_map.items():
                        if _norm_mac(k) == _norm_mac(mac):
                            vendor = v
                            break

                # Hostname (nmap) – you can also add reverse DNS here if you like
                hostname = node.hostname() or ""

                # Directory override by MAC first, then IP key
                override = {}
                if mac:
                    override = directory.get(_norm_mac(mac), {})
                if not override and ip:
                    override = directory.get(ip, {})

                name = override.get("name") or "Unknown Device"
                desc = override.get("desc") or "Unknown Device"

                if ip:
                    res.append({
                        "ip": ip,
                        "mac": mac,
                        "name": name,
                        "type": desc,
                        "vendor": vendor,
                        "hostname": hostname,
                        "cidr": cidr,
                    })
            except Exception as exc:
                _LOGGER.debug("Skip host %s: %s", host, exc)
        return res
