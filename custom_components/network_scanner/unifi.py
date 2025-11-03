# custom_components/network_scanner/unifi.py
from __future__ import annotations
from typing import Any
import json
import logging

from aiohttp import ClientError, ClientTimeout
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

class UniFiClient:
    """
    Minimal UniFi client that copes with both UniFi OS (UDM/UDR/CloudKey Gen2)
    and legacy/stand-alone Network Application.

    Strategy:
      1) Try UniFi OS login:   POST /api/auth/login
      2) Fallback legacy:      POST /api/login
      3) After a successful login, PROBE which API root responds:
           - UniFi OS:   GET /proxy/network/api/self/sites
           - Legacy:     GET /api/self/sites
         Then lock onto that root for subsequent calls.

    NOTE:
      - Base URL should include scheme, host, and (if non-standard) port.
        e.g. https://10.0.0.3:4334
      - 'verify_tls' controls certificate verification (self-signed -> False).
      - We do not persist cookies manually; we rely on HA's shared session.
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

        # Will be set after login + probe
        self._use_proxy = True   # assume UniFi OS until proven otherwise

    async def _session(self, hass):
        # Reuse HA's session; honour TLS verify toggle
        return async_get_clientsession(hass, verify_ssl=self.verify_tls)

    async def _post_json(self, hass, path: str, payload: Any) -> tuple[int, str]:
        sess = await self._session(hass)
        async with sess.post(self.base + path, json=payload, timeout=self.timeout) as resp:
            txt = await resp.text()
            _LOGGER.debug("UniFi POST %s -> %s, body[0:200]=%r", path, resp.status, txt[:200])
            return resp.status, txt

    async def _get_json_text(self, hass, path: str) -> tuple[int, str]:
        sess = await self._session(hass)
        async with sess.get(self.base + path, timeout=self.timeout) as resp:
            txt = await resp.text()
            _LOGGER.debug("UniFi GET %s -> %s, body[0:200]=%r", path, resp.status, txt[:200])
            return resp.status, txt

    async def _login(self, hass) -> bool:
        """
        Attempt UniFi OS login first, then legacy.
        Returns True if any succeeds.
        """
        payload = {"username": self.user, "password": self.passwd}

        # 1) UniFi OS (UDM/UDR/CK Gen2)
        try:
            status, body = await self._post_json(hass, "/api/auth/login", payload)
            if status == 200:
                _LOGGER.debug("UniFi: logged in via /api/auth/login")
                return True
            _LOGGER.debug("UniFi: /api/auth/login failed with %s", status)
        except ClientError as exc:
            _LOGGER.debug("UniFi: /api/auth/login client error: %s", exc)

        # 2) Legacy / Stand-alone
        try:
            status, body = await self._post_json(hass, "/api/login", payload)
            if status == 200:
                _LOGGER.debug("UniFi: logged in via /api/login")
                return True
            _LOGGER.debug("UniFi: /api/login failed with %s", status)
        except ClientError as exc:
            _LOGGER.debug("UniFi: /api/login client error: %s", exc)

        _LOGGER.warning("UniFi: login failed at %s", self.base)
        return False

    async def _probe_api_root(self, hass) -> bool:
        """
        After login, decide whether we need the '/proxy/network' prefix.
        Returns True if we could determine a working root.
        """
        # Probe UniFi OS path
        try:
            status, txt = await self._get_json_text(hass, "/proxy/network/api/self/sites")
            if status == 200:
                # Should be {"meta":{"rc":"ok"}, "data":[ ... ]}
                try:
                    data = json.loads(txt)
                    if isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok":
                        self._use_proxy = True
                        _LOGGER.debug("UniFi: using UniFi OS proxy root (/proxy/network)")
                        return True
                except Exception:
                    pass
        except ClientError as exc:
            _LOGGER.debug("UniFi: probe proxy root failed: %s", exc)

        # Probe legacy path
        try:
            status, txt = await self._get_json_text(hass, "/api/self/sites")
            if status == 200:
                try:
                    data = json.loads(txt)
                    if isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok":
                        self._use_proxy = False
                        _LOGGER.debug("UniFi: using legacy root (/api)")
                        return True
                except Exception:
                    pass
        except ClientError as exc:
            _LOGGER.debug("UniFi: probe legacy root failed: %s", exc)

        _LOGGER.warning("UniFi: could not determine API root after login (proxy vs legacy).")
        return False

    def _path(self, tail: str) -> str:
        """
        Build the request path given an API 'tail' that starts with 'api/...'.
        Example tail: 'api/s/{site}/stat/sta'
        """
        if self._use_proxy:
            return f"/proxy/network/{tail}"
        return f"/{tail}"

    async def _get_json_obj(self, hass, path: str) -> Any:
        status, txt = await self._get_json_text(hass, path)
        if status >= 400:
            raise RuntimeError(f"HTTP {status}: {txt[:200]!r}")
        try:
            return json.loads(txt)
        except Exception:
            raise RuntimeError(f"Non-JSON at {path}: {txt[:160]!r}")

    async def _ensure_ready(self, hass) -> bool:
        if not (self.base and self.user and self.passwd):
            _LOGGER.debug("UniFi: missing base/user/pass; skipping.")
            return False
        if not await self._login(hass):
            return False
        if not await self._probe_api_root(hass):
            # As a last resort, stay in proxy mode and let requests fail loudly
            self._use_proxy = True
        return True

    async def fetch_clients(self, hass) -> list[dict]:
        """
        Return controller 'sta' records.
        """
        ok = await self._ensure_ready(hass)
        if not ok:
            return []
        path = self._path(f"api/s/{self.site}/stat/sta")
        try:
            data = await self._get_json_obj(hass, path)
            rows = data.get("data", []) if isinstance(data, dict) else []
            _LOGGER.debug("UniFi: %s -> %d client rows", path, len(rows))
            return rows
        except Exception as exc:
            _LOGGER.warning("UniFi fetch clients failed: %s", exc)
            return []

    async def fetch_devices(self, hass) -> list[dict]:
        """
        Return controller device records (for AP names, etc).
        """
        ok = await self._ensure_ready(hass)
        if not ok:
            return []
        path = self._path(f"api/s/{self.site}/stat/device")
        try:
            data = await self._get_json_obj(hass, path)
            rows = data.get("data", []) if isinstance(data, dict) else []
            _LOGGER.debug("UniFi: %s -> %d device rows", path, len(rows))
            return rows
        except Exception as exc:
            _LOGGER.debug("UniFi fetch devices failed: %s", exc)
            return []
