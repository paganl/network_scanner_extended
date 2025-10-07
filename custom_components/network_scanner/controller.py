from __future__ import annotations
import json
import time
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import nmap
from aiohttp import ClientError
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import DEFAULT_NMAP_ARGS, DEFAULT_SCAN_INTERVAL, DOMAIN

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

def _split_cidrs(raw: str) -> List[str]:
    import re
    return [p.strip() for p in re.split(r"[,\s]+", raw or "") if p.strip()]

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
    """Holds scan config + state; performs nmap run when asked."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry

        self._cidrs: List[str] = []
        self._nmap_args: str = DEFAULT_NMAP_ARGS
        self._scan_interval: int = DEFAULT_SCAN_INTERVAL

        # state
        self.status: str = "idle"           # idle|scanning|ok|error
        self.last_scan_started: Optional[str] = None
        self.last_scan_finished: Optional[str] = None
        self.devices: List[Dict[str, Any]] = []
        self.device_count: Optional[int] = None

        self._next_allowed = 0.0
        self._nm = nmap.PortScanner()

        self.apply_entry(entry)

    # -------- config application --------
    def apply_entry(self, entry: ConfigEntry) -> None:
        self.entry = entry
        raw_ip = (entry.options.get("ip_range") or entry.data.get("ip_range") or "").strip()
        self._cidrs = _split_cidrs(raw_ip)

        self._nmap_args = (entry.options.get("nmap_args")
                           or entry.data.get("nmap_args")
                           or DEFAULT_NMAP_ARGS).strip()

        try:
            self._scan_interval = int(entry.options.get("scan_interval")
                                      or entry.data.get("scan_interval")
                                      or DEFAULT_SCAN_INTERVAL)
        except Exception:
            self._scan_interval = DEFAULT_SCAN_INTERVAL

        # force immediate eligibility after config changes
        self._next_allowed = 0.0

    # -------- public read-only props for entities --------
    @property
    def cidrs(self) -> List[str]:
        return self._cidrs

    @property
    def nmap_args(self) -> str:
        return self._nmap_args

    @property
    def scan_interval(self) -> int:
        return self._scan_interval

    # -------- scanning --------
    async def maybe_auto_scan(self) -> None:
        """Run a scan when interval elapsed; no-op if interval=0 (manual mode)."""
        if self._scan_interval <= 0:
            return
        now = time.monotonic()
        if now >= self._next_allowed:
            await self.run_scan(force=True)

    async def run_scan(self, force: bool = True) -> None:
        """Always perform a scan (manual button or auto); ‘force’ ignored here for clarity."""
        self.status = "scanning"
        self.last_scan_started = _now_iso()
        try:
            directory: Dict[str, Dict[str, str]] = dict(self.entry.data.get("mac_directory", {}))
            opts = self.entry.options or {}

            # merge JSON text (highest precedence)
            jtxt = (opts.get("mac_directory_json_text") or "").strip()
            if jtxt:
                try:
                    directory.update(_parse_dir_obj(json.loads(jtxt)))
                except Exception as exc:
                    _LOGGER.warning("Invalid options JSON: %s", exc)

            # optional URL
            url = (opts.get("mac_directory_json_url")
                   or self.entry.data.get("mac_directory_json_url")
                   or "").strip()
            if url:
                try:
                    session = async_get_clientsession(self.hass)
                    async with session.get(url, timeout=10) as resp:
                        resp.raise_for_status()
                        directory.update(_parse_dir_obj(json.loads(await resp.text())))
                except (ClientError, Exception) as exc:
                    _LOGGER.warning("Failed to fetch directory URL %s: %s", url, exc)

            # scan each cidr
            all_devices: List[Dict[str, Any]] = []
            for cidr in self._cidrs:
                chunk = await self.hass.async_add_executor_job(
                    self._scan_cidr, cidr, directory, self._nmap_args
                )
                all_devices.extend(chunk)

            # dedup by MAC
            dedup: Dict[str, Dict[str, Any]] = {}
            for d in all_devices:
                mk = _norm_mac(d.get("mac"))
                if mk and mk not in dedup:
                    dedup[mk] = d

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
            # schedule next auto run (or never if manual mode)
            if self._scan_interval <= 0:
                self._next_allowed = float("inf")
            else:
                self._next_allowed = time.monotonic() + max(30, self._scan_interval)

    # -------- sync helper --------
    def _scan_cidr(self, cidr: str, directory: Dict[str, Dict[str, str]], nmap_args: str) -> List[Dict[str, Any]]:
        res: List[Dict[str, Any]] = []
        self._nm.scan(hosts=cidr, arguments=nmap_args)
        for host in self._nm.all_hosts():
            try:
                node = self._nm[host]
                addrs = node.get("addresses", {})
                ip = addrs.get("ipv4") or addrs.get("ipv6") or ""
                if not ip:
                    continue

                mac = addrs.get("mac") or ""
                vendor = "Unknown"
                ven_map = node.get("vendor", {})
                if isinstance(ven_map, dict):
                    for k, v in ven_map.items():
                        if _norm_mac(k) == _norm_mac(mac):
                            vendor = v
                            break

                hostname = node.hostname() or ""
                override = directory.get(_norm_mac(mac), {}) if mac else {}
                name = override.get("name") or "Unknown Device"
                desc = override.get("desc") or "Unknown Device"

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
                _LOGGER.debug("Skipping host %s: %s", host, exc)
        return res
