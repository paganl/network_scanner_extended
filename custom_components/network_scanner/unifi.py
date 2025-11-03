# custom_components/network_scanner/unifi.py
from __future__ import annotations
from typing import Any, List
import json
import logging

from aiohttp import ClientError, ClientTimeout
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

class UniFiClient:
    """
    Works with both UniFi OS (UDM/UDR/CK Gen2) and stand-alone Network app:
      - Tries UniFi OS first:    /api/auth/login  + /proxy/network/api/...
      - Falls back to legacy:    :8443/api/login + /api/...
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        site: str = "default",
        verify_tls: bool = True,
        timeout: int = 10,
    ) -> None:
        self.base = (base_url or "").rstrip("/")
        self.user = username or ""
        self.passwd = password or ""
        self.site = site or "default"
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)

        # chosen mode after detection
        self._use_proxy = True   # assume UniFi OS first
        self._login_path = "/api/auth/login"  # UniFi OS; fallback to /api/login

    async def _session(self, hass):
        return async_get_clientsession(hass, verify_ssl=self.verify_tls)

    async def _try_login(self, hass) -> bool:
        """
        Try UniFi OS style, then legacy. Sets _use_proxy and _login_path accordingly.
        """
        sess = await self._session(hass)
        payload = {"username": self.user, "password": self.passwd}

        # 1) UniFi OS
        try:
            async with sess.post(self.base + "/api/auth/login", json=payload, timeout=self.timeout) as resp:
                if resp.status == 200:
                    self._use_proxy = True
                    self._login_path = "/api/auth/login"
                    _LOGGER.debug("UniFi: logged in via /api/auth/login (UniFi OS)")
                    return True
        except ClientError:
            pass

        # 2) Legacy
        try:
            async with sess.post(self.base + "/api/login", json=payload, timeout=self.timeout) as resp:
                if resp.status == 200:
                    self._use_proxy = False
                    self._login_path = "/api/login"
                    _LOGGER.debug("UniFi: logged in via /api/login (stand-alone)")
                    return True
        except ClientError:
            pass

        _LOGGER.warning("UniFi: login failed at %s", self.base)
        return False

    def _path(self, core: str) -> str:
        """
        Build the right path depending on proxy mode.
        core is the 'api/.../s/{site}/...' tail without leading slash.
        """
        if self._use_proxy:
            return f"/proxy/network/{core}"
        return f"/{core}"  # legacy

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
        if not await self._try_login(hass):
            return []
        path = self._path(f"api/s/{self.site}/stat/sta")
        try:
            data = await self._get_json(hass, path)
            return data.get("data", []) if isinstance(data, dict) else []
        except Exception as exc:
            _LOGGER.warning("UniFi fetch clients failed: %s", exc)
            return []

    async def fetch_devices(self, hass) -> list[dict]:
        if not (self.base and self.user and self.passwd):
            return []
        # Reuse cookies/session established by _try_login
        path = self._path(f"api/s/{self.site}/stat/device")
        try:
            data = await self._get_json(hass, path)
            return data.get("data", []) if isinstance(data, dict) else []
        except Exception as exc:
            _LOGGER.debug("UniFi fetch devices failed: %s", exc)
            return []
