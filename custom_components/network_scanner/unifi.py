# custom_components/network_scanner/unifi.py
from __future__ import annotations
from typing import Any, Optional
import json
import logging

from aiohttp import ClientError, ClientTimeout
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

class UniFiClient:
    """
    Robust UniFi client that:
      - Tries UniFi OS login (/api/auth/login), then legacy (/api/login).
      - PROBES the working API root after login:
          * /proxy/network/api/self/sites   (UniFi OS proxy)
          * /api/self/sites                 (legacy / direct)
      - Caches the chosen root and uses it for:
          * GET {root}/s/{site}/stat/sta     (clients)
          * GET {root}/s/{site}/stat/device  (devices)
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

        # Determined after login+probe:
        self._api_root: Optional[str] = None   # "/proxy/network/api" or "/api"

    # ------------- low-level HTTP -------------

    async def _session(self, hass):
        return async_get_clientsession(hass, verify_ssl=self.verify_tls)

    async def _post_json(self, hass, path: str, payload: dict) -> tuple[int, str]:
        sess = await self._session(hass)
        async with sess.post(self.base + path, json=payload, timeout=self.timeout) as resp:
            txt = await resp.text()
            return resp.status, txt

    async def _get_json_any(self, hass, full_path: str) -> tuple[int, str]:
        """GET full path (already absolute). Returns (status, body_text)."""
        sess = await self._session(hass)
        async with sess.get(self.base + full_path, timeout=self.timeout) as resp:
            txt = await resp.text()
            return resp.status, txt

    async def _get_json(self, hass, path_under_root: str) -> Any:
        """GET using decided API root, e.g. path_under_root='/s/{site}/stat/sta'."""
        if not self._api_root:
            raise RuntimeError("UniFi: API root not determined")
        status, txt = await self._get_json_any(hass, self._api_root + path_under_root)
        _LOGGER.debug("UniFi GET %s -> %s body[0:200]=%r", self._api_root + path_under_root, status, txt[:200])
        if status >= 400:
            raise RuntimeError(f"HTTP {status}: {txt[:200]!r}")
        try:
            return json.loads(txt)
        except Exception:
            raise RuntimeError(f"Non-JSON at {self._api_root + path_under_root}: {txt[:120]!r}")

    # ------------- login + root detection -------------

    async def _login(self, hass) -> bool:
        """Try UniFi OS first, then legacy. Succeeds if any returns 200."""
        if not (self.base and self.user and self.passwd):
            _LOGGER.warning("UniFi: missing base/user/pass")
            return False

        payload = {"username": self.user, "password": self.passwd}

        # 1) UniFi OS
        try:
            status, txt = await self._post_json(hass, "/api/auth/login", payload)
            _LOGGER.debug("UniFi login /api/auth/login -> %s body[0:160]=%r", status, txt[:160])
            if status == 200:
                return True
        except ClientError as exc:
            _LOGGER.debug("UniFi OS login failed: %s", exc)

        # 2) Legacy
        try:
            status, txt = await self._post_json(hass, "/api/login", payload)
            _LOGGER.debug("UniFi legacy login /api/login -> %s body[0:160]=%r", status, txt[:160])
            if status == 200:
                return True
        except ClientError as exc:
            _LOGGER.debug("UniFi legacy login failed: %s", exc)

        _LOGGER.warning("UniFi: login failed at %s", self.base)
        return False

    async def _detect_api_root(self, hass) -> bool:
        """
        After login, probe which API base works.
        Returns True if we picked a root.
        """
        # Try UniFi OS proxy first
        for candidate in ("/proxy/network/api", "/api"):
            try:
                status, txt = await self._get_json_any(hass, f"{candidate}/self/sites")
                _LOGGER.debug("UniFi probe %s/self/sites -> %s", candidate, status)
                if status == 200:
                    # Validate JSON
                    try:
                        data = json.loads(txt)
                        if isinstance(data, dict) and data.get("meta", {}).get("rc") in ("ok", "busy", "error"):
                            self._api_root = candidate
                            _LOGGER.debug("UniFi: selected API root %s (meta.rc=%s)", candidate, data["meta"].get("rc"))
                            return True
                        # Some controllers return just {"data":[...]} without meta
                        if isinstance(data, dict) and "data" in data:
                            self._api_root = candidate
                            _LOGGER.debug("UniFi: selected API root %s (data-only)", candidate)
                            return True
                    except Exception:
                        # Even if JSON parse fails but 200 status, keep probing next candidate
                        _LOGGER.debug("UniFi: JSON at %s/self/sites could not be parsed; trying next", candidate)
            except ClientError as exc:
                _LOGGER.debug("UniFi: probe %s/self/sites failed: %s", candidate, exc)

        return False

    async def _ensure_ready(self, hass) -> bool:
        if self._api_root:
            return True
        if not await self._login(hass):
            return False
        if not await self._detect_api_root(hass):
            _LOGGER.error("UniFi: could not determine API root after login (proxy vs legacy). "
                          "Check URL/port. Try the one that worked in your browser (e.g. https://host:4334).")
            return False
        _LOGGER.debug("UniFi ready. api_root=%s site=%s", self._api_root, self.site)
        return True

    # ------------- public API -------------

    async def fetch_clients(self, hass) -> list[dict]:
        if not await self._ensure_ready(hass):
            return []
        try:
            data = await self._get_json(hass, f"/s/{self.site}/stat/sta")
            rows = data.get("data", []) if isinstance(data, dict) else []
            _LOGGER.debug("UniFi: fetched %d clients", len(rows))
            return rows
        except Exception as exc:
            _LOGGER.warning("UniFi fetch clients failed: %s", exc)
            return []

    async def fetch_devices(self, hass) -> list[dict]:
        if not await self._ensure_ready(hass):
            return []
        try:
            data = await self._get_json(hass, f"/s/{self.site}/stat/device")
            rows = data.get("data", []) if isinstance(data, dict) else []
            _LOGGER.debug("UniFi: fetched %d devices", len(rows))
            return rows
        except Exception as exc:
            _LOGGER.debug("UniFi fetch devices failed: %s", exc)
            return []
