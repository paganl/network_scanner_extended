# custom_components/network_scanner/unifi.py
from __future__ import annotations
from typing import Dict, Any, Iterable
import json
import logging

from aiohttp import ClientError, ClientTimeout
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

class UniFiClient:
    """
    Minimal UniFi Network client (UDM/Network App 7.x/8.x tolerant):
      - Login with username/password (cookie-based)
      - Fetch connected clients: /proxy/network/api/s/{site}/stat/sta
      - Fetch devices (for AP names): /proxy/network/api/s/{site}/stat/device

    Notes:
      * Controller bases often vary; we accept http(s)://host[:port]
      * Uses the same aiohttp session as HA; respects verify_ssl toggle
    """

    def __init__(self, base_url: str, username: str, password: str, site: str = "default",
                 verify_tls: bool = True, timeout: int = 10) -> None:
        self.base = (base_url or "").rstrip("/")
        self.user = username or ""
        self.passwd = password or ""
        self.site = site or "default"
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)
        self._cookie_jar = None

    async def _session(self, hass):
        return async_get_clientsession(hass, verify_ssl=self.verify_tls)

    async def _login(self, hass) -> bool:
        """
        Modern controllers: POST /api/login
        Legacy: POST /api/auth/login
        We try both.
        """
        sess = await self._session(hass)
        payload = {"username": self.user, "password": self.passwd}
        for path in ("/api/login", "/api/auth/login"):
            try:
                async with sess.post(self.base + path, json=payload, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        _LOGGER.debug("UniFi login ok via %s", path)
                        return True
            except ClientError as exc:
                _LOGGER.debug("UniFi login path %s failed: %s", path, exc)
        _LOGGER.warning("UniFi login failed at %s", self.base)
        return False

    async def _get_json(self, hass, path: str) -> Any:
        sess = await self._session(hass)
        async with sess.get(self.base + path, timeout=self.timeout) as resp:
            txt = await resp.text()
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}: {txt[:200]!r}")
            try:
                return json.loads(txt)
            except Exception:
                raise RuntimeError(f"Non-JSON at {path}: {txt[:120]!r}")

    async def fetch_clients(self, hass) -> list[dict]:
        if not (self.base and self.user and self.passwd):
            return []
        ok = await self._login(hass)
        if not ok:
            return []
        path = f"/proxy/network/api/s/{self.site}/stat/sta"
        try:
            data = await self._get_json(hass, path)
            return data.get("data", []) if isinstance(data, dict) else []
        except Exception as exc:
            _LOGGER.warning("UniFi fetch clients failed: %s", exc)
            return []

    async def fetch_devices(self, hass) -> list[dict]:
        if not (self.base and self.user and self.passwd):
            return []
        # Do not re-login; cookies still in session
        path = f"/proxy/network/api/s/{self.site}/stat/device"
        try:
            data = await self._get_json(hass, path)
            return data.get("data", []) if isinstance(data, dict) else []
        except Exception as exc:
            _LOGGER.debug("UniFi fetch devices failed: %s", exc)
            return []
