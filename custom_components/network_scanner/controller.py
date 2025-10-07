# custom_components/network_scanner_extended/controller.py
from __future__ import annotations
import json
import logging
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional

import nmap
from aiohttp import BasicAuth, ClientError
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DEFAULT_NMAP_ARGS,
    DEFAULT_SCAN_INTERVAL,
    OPNSENSE_ARP_PATH,
)

_LOGGER = logging.getLogger(__name__)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _norm_mac(s: Optional[str]) -> str:
    return (s or "").upper()

def _ip_key(ip_str: str) -> List[int]:
    try:
        return [int(p) for p in ip_str.split(".")]
    except Exception:
        return [999, 999, 999, 999]

def _in_any_cidr(ip_str: str, cidrs: List[str]) -> bool:
    try:
        ip = ip_address(ip_str)
        for c in cidrs:
            if ip in ip_network(c, strict=False):
                return True
    except Exception:
        pass
    return False

def _parse_dir_obj(obj: Any) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(obj, dict):
        return out
    block = obj.get("data", obj)
    if not isinstance(block, dict):
        return out
    for k, v in block.items():
        mk = _norm_mac(k)
        if not mk:
            continue
        if isinstance(v, dict):
            out[mk] = {"name": str(v.get("name", "")), "desc": str(v.get("desc", ""))}
        else:
            out[mk] = {"name": str(v), "desc": ""}
    return out


class ScanController:
    """Holds config, runs scans, exposes state to entities and button."""

    def __init__(self, hass: HomeAssistant, entry) -> None:
        self.hass = hass
        self.entry = entry
        self.status: str = "idle"
        self.last_scan_started: Optional[str] = None
        self.last_scan_finished: Optional[str] = None

        self._devices: List[Dict[str, Any]] = []
        self._nm = nmap.PortScanner()
        self._manual_requested = False
        self._last_run: Optional[datetime] = None

        self.cidrs: List[str] = []
        self.nmap_args: str = DEFAULT_NMAP_ARGS
        self.scan_interval: int = DEFAULT_SCAN_INTERVAL  # seconds

        # OPNsense settings
        self.opn_url: str = ""
        self.opn_key: str = ""
        self.opn_secret: str = ""
        self.opn_interface: str = ""

        self.apply_entry(entry)

    # --- public properties used by entities ---
    @property
    def devices(self) -> List[Dict[str, Any]]:
        return self._devices

    @property
    def device_count(self) -> int:
        return len(self._devices)

    # --- lifecycle/config ---
    def apply_entry(self, entry) -> None:
        self.entry = entry
        data = entry.data or {}
        opts = entry.options or {}

        raw = (opts.get("ip_range") or data.get("ip_range") or "").strip()
        self.cidrs = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
        self.nmap_args = (opts.get("nmap_args") or data.get("nmap_args") or DEFAULT_NMAP_ARGS).strip()
        self.scan_interval = int(opts.get("scan_interval", data.get("scan_interval", DEFAULT_SCAN_INTERVAL)))

        # OPNsense
        self.opn_url = (opts.get("opnsense_url", data.get("opnsense_url", "")) or "").strip().rstrip("/")
        self.opn_key = (opts.get("opnsense_key", data.get("opnsense_key", "")) or "").strip()
        self.opn_secret = (opts.get("opnsense_secret", data.get("opnsense_secret", "")) or "").strip()
        self.opn_interface = (opts.get("opnsense_interface", data.get("opnsense_interface", "")) or "").strip()

    # --- called by button entity ---
    def request_manual_scan(self) -> None:
        self._manual_requested = True

    # --- called by sensors on update ---
    async def maybe_auto_scan(self) -> None:
        # Manual?
        if self._manual_requested:
            self._manual_requested = False
            await self._do_scan()
            return

        # Auto disabled?
        if self.scan_interval == 0:
            return

        # Run if never ran or enough time elapsed
        now = datetime.now(timezone.utc)
        if not self._last_run or (now - self._last_run) >= timedelta(seconds=self.scan_interval):
            await self._do_scan()

    # --- core scan ---
    async def _do_scan(self) -> None:
        try:
            self.status = "scanning"
            self.last_scan_started = _now_iso()

            # effective directory (data + options)
            directory: Dict[str, Dict[str, str]] = dict(self.entry.data.get("mac_directory", {}))
            opts = self.entry.options or {}

            # options JSON text
            jtxt = (opts.get("mac_directory_json_text") or "").strip()
            if jtxt:
                try:
                    directory.update(_parse_dir_obj(json.loads(jtxt)))
                except Exception as exc:
                    _LOGGER.warning("Invalid options JSON, ignoring: %s", exc)

            # options/data URL (optional)
            url = (opts.get("mac_directory_json_url") or self.entry.data.get("mac_directory_json_url") or "").strip()
            if url:
                try:
                    session = async_get_clientsession(self.hass)
                    async with session.get(url, timeout=10) as resp:
                        resp.raise_for_status()
                        directory.update(_parse_dir_obj(json.loads(await resp.text())))
                except (ClientError, Exception) as exc:
                    _LOGGER.warning("Failed to fetch directory URL %s: %s", url, exc)

            # 1) nmap across all CIDRs (executor)
            all_devices: List[Dict[str, Any]] = []
            for cidr in self.cidrs:
                chunk = await self.hass.async_add_executor_job(self._scan_cidr, cidr, directory, self.nmap_args)
                all_devices.extend(chunk)

            # 2) OPNsense ARP fallback (optional)
            ip_to_mac: Dict[str, str] = {}
            if self.opn_url and self.opn_key and self.opn_secret:
                try:
                    ip_to_mac = await self._fetch_opnsense_arp()
                except Exception as exc:
                    _LOGGER.warning("OPNsense ARP fetch failed: %s", exc)

            # Fill missing MACs from ARP
            ip_seen = set()
            for d in all_devices:
                ip_seen.add(d.get("ip", ""))
                if not d.get("mac"):
                    mac = _norm_mac(ip_to_mac.get(d.get("ip", "")))
                    if mac:
                        d["mac"] = mac
                        # apply directory override if present
                        ov = directory.get(mac, {})
                        if ov:
                            d["name"] = ov.get("name") or d["name"]
                            d["type"] = ov.get("desc") or d["type"]

            # Add ARP-only devices (within our CIDRs)
            for ip, mac in ip_to_mac.items():
                if ip in ip_seen or not _in_any_cidr(ip, self.cidrs):
                    continue
                mm = directory.get(_norm_mac(mac), {})
                all_devices.append({
                    "ip": ip,
                    "mac": mac,
                    "name": mm.get("name") or "Unknown Device",
                    "type": mm.get("desc") or "Unknown Device",
                    "vendor": "Unknown",
                    "hostname": "",
                    "cidr": self._cidr_for_ip(ip),
                    "source": "arp"
                })

            # Dedup by MAC (prefer nmap over ARP-only)
            dedup: Dict[str, Dict[str, Any]] = {}
            for d in all_devices:
                mk = _norm_mac(d.get("mac"))
                key = mk or f"IP:{d.get('ip','')}"
                if key not in dedup:
                    dedup[key] = d

            devices = list(dedup.values())
            devices.sort(key=lambda d: _ip_key(d.get("ip", "")))

            self._devices = devices
            self.status = "ok"
        except Exception as exc:
            self.status = "error"
            _LOGGER.exception("Network scan failed: %s", exc)
        finally:
            self._last_run = datetime.now(timezone.utc)
            self.last_scan_finished = _now_iso()

    def _cidr_for_ip(self, ip_str: str) -> str:
        try:
            ip = ip_address(ip_str)
            for c in self.cidrs:
                if ip in ip_network(c, strict=False):
                    return c
        except Exception:
            pass
        return ""

    def _scan_cidr(self, cidr: str, directory: Dict[str, Dict[str, str]], nmap_args: str) -> List[Dict[str, Any]]:
        res: List[Dict[str, Any]] = []
        self._nm.scan(hosts=cidr, arguments=nmap_args)
        for host in self._nm.all_hosts():
            try:
                node = self._nm[host]
                addrs = node.get("addresses", {})
                mac = addrs.get("mac")
                ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
                if not ip:
                    continue
                vendor = "Unknown"
                ven_map = node.get("vendor", {})
                if isinstance(ven_map, dict):
                    for k, v in ven_map.items():
                        if _norm_mac(k) == _norm_mac(mac):
                            vendor = v
                            break
                hostname = node.hostname() or ""
                ov = directory.get(_norm_mac(mac), {}) if mac else {}
                name = ov.get("name") or "Unknown Device"
                desc = ov.get("desc") or "Unknown Device"
                res.append({
                    "ip": ip,
                    "mac": mac or "",
                    "name": name,
                    "type": desc,
                    "vendor": vendor,
                    "hostname": hostname,
                    "cidr": cidr,
                    "source": "nmap",
                })
            except Exception as exc:
                _LOGGER.debug("Skipping host %s: %s", host, exc)
        return res

    async def _fetch_opnsense_arp(self) -> Dict[str, str]:
        """Return mapping {ip: mac} from OPNsense ARP table."""
        base = self.opn_url
        if not base:
            return {}
        session = async_get_clientsession(self.hass)
        auth = BasicAuth(self.opn_key, self.opn_secret)
        payload: Dict[str, Any] = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
        if self.opn_interface:
            payload["interface"] = self.opn_interface

        url = f"{base}{OPNSENSE_ARP_PATH}"
        try:
            async with session.post(url, json=payload, auth=auth, ssl=False, timeout=15) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
        except ClientError as exc:
            raise RuntimeError(f"HTTP error from OPNsense: {exc}") from exc

        rows = []
        if isinstance(data, dict):
            if isinstance(data.get("rows"), list):
                rows = data["rows"]
            elif isinstance(data.get("data"), list):
                rows = data["data"]

        out: Dict[str, str] = {}
        for r in rows:
            ip = str(r.get("ip") or r.get("IPAddress") or r.get("address") or "").strip()
            mac = _norm_mac(str(r.get("mac") or r.get("macaddr") or r.get("ether") or "").strip())
            if ip and mac:
                out[ip] = mac
        _LOGGER.debug("OPNsense ARP entries: %d", len(out))
        return out
