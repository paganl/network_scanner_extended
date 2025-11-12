
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any, Dict, List

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN,
    DEFAULT_OPTIONS,
    CONF_PROVIDER,
    CONF_URL,
    CONF_KEY,
    CONF_SECRET,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_CIDRS,
    CONF_INTERVAL_MIN,
    CONF_USE_NMAP,
    CONF_NMAP_ARGS,
    CONF_MAC_DIRECTORY,
)

from .provider.opnsense import OPNsenseARPClient
from .provider.adguard import AdGuardDHCPClient

_LOGGER = logging.getLogger(__name__)

NMAP_LOCK = asyncio.Lock()


async def async_setup_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> None:
    hass.data.setdefault(DOMAIN, {})

    coordinator = NetworkScannerCoordinator(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Load platforms first; refresh in background to avoid blocking UI
    await hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    hass.async_create_task(coordinator.async_request_refresh())

    async def _svc_refresh(call):
        await coordinator.async_request_refresh()

    async def _svc_run_nmap(call):
        await coordinator.async_run_nmap_enrich()

    hass.services.async_register(DOMAIN, "refresh", _svc_refresh)
    hass.services.async_register(DOMAIN, "run_nmap", _svc_run_nmap)


async def async_unload_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, ["sensor"])
    coord: NetworkScannerCoordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
    if coord:
        await coord.async_shutdown()
    try:
        hass.services.async_remove(DOMAIN, "refresh")
        hass.services.async_remove(DOMAIN, "run_nmap")
    except Exception:
        pass
    return ok


async def async_reload_coordinator(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await async_unload_coordinator(hass, entry)
    await async_setup_coordinator(hass, entry)


class NetworkScannerCoordinator(DataUpdateCoordinator[Dict[str, Any]]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.options = {**DEFAULT_OPTIONS, **dict(entry.options)}
        self.session = async_get_clientsession(hass)

        self._opnsense = None
        self._adguard = None
        prov = self.options[CONF_PROVIDER]
        base = self.options.get(CONF_URL, "")
        if prov == "opnsense" and base:
            self._opnsense = OPNsenseARPClient(self.session, base, self.options.get(CONF_KEY, ""), self.options.get(CONF_SECRET, ""))
        if prov == "adguard" and base:
            self._adguard = AdGuardDHCPClient(self.session, base, self.options.get(CONF_NAME, ""), self.options.get(CONF_PASSWORD, ""))

        interval_min = max(0, int(self.options.get(CONF_INTERVAL_MIN, 3)))
        update_interval = timedelta(minutes=interval_min) if interval_min > 0 else None

        super().__init__(
            hass,
            _LOGGER,
            name="network_scanner_coordinator",
            update_method=self._async_update_data,
            update_interval=update_interval,
        )

        self._tasks: List[asyncio.Task] = []

    async def _async_update_data(self) -> Dict[str, Any]:
        try:
            devices = await self._gather_devices()
            payload = {"devices": devices, "count": len(devices)}
            if not devices:
                self.logger.warning("Network Scanner found 0 devices from provider=%s url=%s. Enable debug logs for details.", self.options.get("provider"), self.options.get("url"))
            return payload
        except Exception as exc:
            raise UpdateFailed(str(exc)) from exc

    async def _gather_devices(self) -> List[Dict[str, Any]]:
        prov = self.options[CONF_PROVIDER]
        results: List[Dict[str, Any]] = []
        if prov == "opnsense" and self._opnsense:
            results = await self._opnsense.async_get_arp()
        elif prov == "adguard" and self._adguard:
            results = await self._adguard.async_get_clients()
        else:
            _LOGGER.warning("No provider configured or URL missing")
        dedup: Dict[str, Dict[str, Any]] = {}
        for item in results:
            mac = (item.get("mac") or "").upper()
            ip = item.get("ip")
            host = item.get("hostname") or ""
            if not mac and ip:
                mac = f"IP:{ip}"
            if mac:
                dedup[mac] = {
                    "mac": mac,
                    "ip": ip,
                    "hostname": host,
                    "vendor": item.get("vendor") or "",
                    "source": item.get("source") or prov,
                    "first_seen": item.get("first_seen") or "",
                    "last_seen": item.get("last_seen") or "",
                }
        return list(dedup.values())

    async def async_run_nmap_enrich(self) -> None:
        use_nmap = bool(self.options.get(CONF_USE_NMAP, False))
        if not use_nmap:
            return
        cidrs = self.options.get(CONF_CIDRS) or []
        args = self.options.get(CONF_NMAP_ARGS, "-sn --max-retries 1 --host-timeout 5s")
        try:
            await self._async_run_nmap_once(cidrs, args)
            await self.async_request_refresh()
        except Exception as exc:
            _LOGGER.warning("nmap enrichment failed: %s", exc)

    async def _async_run_nmap_once(self, cidrs: List[str], args: str, timeout_s: int = 25) -> None:
        if not cidrs:
            return
        import shlex, asyncio
        cmd = ["nmap"] + shlex.split(args) + cidrs
        async with NMAP_LOCK:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
            except asyncio.TimeoutError:
                proc.kill()
                raise
            if proc.returncode != 0:
                raise RuntimeError((err or b"").decode(errors="ignore"))

    async def async_shutdown(self) -> None:
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
