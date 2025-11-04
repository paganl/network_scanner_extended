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
    Robust UniFi client:
      - CSRF-aware login for UniFi OS (/api/auth/login) and legacy (/api/login)
      - Adds Origin/Referer headers (some controllers require them)
      - JSON body first, then form-encoded fallback
      - After login, probes working API root:
          * /proxy/network/api/self/sites  (UniFi OS proxy)
          * /api/self/sites                (legacy/direct)
      - Uses chosen root for:
          * GET {root}/s/{site}/stat/sta
          * GET {root}/s/{site}/stat/device
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

        # Decided after login + probe:
        self._api_root: Optional[str] = None  # "/proxy/network/api" or "/api"

    # ---------- low-level HTTP ----------

    async def _session(self, hass):
        return async_get_clientsession(hass, verify_ssl=self.verify_tls)

    def _headers(self, csrf: str | None = None) -> dict[str, str]:
        # Some builds want Origin/Referer to match the base.
        h = {
            "Accept": "application/json",
            "Referer": self.base + "/",
            "Origin": self.base,
        }
        if csrf:
            h["X-Csrf-Token"] = csrf
        return h

    async def _get_any(self, hass, path: str) -> tuple[int, str]:
        sess = await self._session(hass)
        async with sess.get(self.base + path, timeout=self.timeout) as resp:
            txt = await resp.text()
            return resp.status, txt

    async def _post_json(self, hass, path: str, payload: dict, csrf: str | None) -> tuple[int, str]:
        sess = await self._session(hass)
        async with sess.post(self.base + path, json=payload, headers=self._headers(csrf), timeout=self.timeout) as resp:
            txt = await resp.text()
            return resp.status, txt

    async def _post_form(self, hass, path: str, payload: dict, csrf: str | None) -> tuple[int, str]:
        sess = await self._session(hass)
        async with sess.post(self.base + path, data=payload, headers=self._headers(csrf), timeout=self.timeout) as resp:
            txt = await resp.text()
            return resp.status, txt

    async def _get_csrf(self, hass, path: str) -> str | None:
        try:
            sess = await self._session(hass)
            async with sess.get(self.base + path, headers=self._headers(), timeout=self.timeout) as resp:
                token = resp.headers.get("X-Csrf-Token")
                _LOGGER.debug("UniFi CSRF %s -> %s token=%s", path, resp.status, bool(token))
                return token
        except ClientError as exc:
            _LOGGER.debug("UniFi CSRF %s failed: %s", path, exc)
            return None

    # ---------- login + root detection ----------

    async def _login_once(self, hass, login_path: str, csrf_path: str) -> bool:
        csrf = await self._get_csrf(hass, csrf_path)
        payload = {"username": self.user, "password": self.passwd}

        # JSON first
        try:
            status, txt = await self._post_json(hass, login_path, payload, csrf)
            _LOGGER.debug("UniFi login JSON %s -> %s body[:160]=%r", login_path, status, txt[:160])
            if status == 200:
                return True
        except ClientError as exc:
            _LOGGER.debug("UniFi login JSON %s failed: %s", login_path, exc)

        # Form fallback
        try:
            status, txt = await self._post_form(hass, login_path, payload, csrf)
            _LOGGER.debug("UniFi login FORM %s -> %s body[:160]=%r", login_path, status, txt[:160])
            return status == 200
        except ClientError as exc:
            _LOGGER.debug("UniFi login FORM %s failed: %s", login_path, exc)
            return False

    async def _login(self, hass) -> bool:
        if not (self.base and self.user and self.passwd):
            _LOGGER.warning("UniFi: missing base/user/pass")
            return False

        # Try UniFi OS (common for :443, :4334 behind OS)
        if await self._login_once(hass, "/api/auth/login", "/api/auth/csrf"):
            _LOGGER.debug("UniFi: logged in via /api/auth/login")
            return True

        # Try legacy (common on :8443)
        if await self._login_once(hass, "/api/login", "/api/csrf"):
            _LOGGER.debug("UniFi: logged in via /api/login")
            return True

        _LOGGER.warning("UniFi: login failed at %s", self.base)
        return False

    async def _detect_api_root(self, hass) -> bool:
        for candidate in ("/proxy/network/api", "/api"):
            try:
                status, txt = await self._get_any(hass, f"{candidate}/self/sites")
                _LOGGER.debug("UniFi probe %s/self/sites -> %s", candidate, status)
                if status == 200:
                    try:
                        data = json.loads(txt)
                    except Exception:
                        data = None
                    # Typical: {"meta":{"rc":"ok"},"data":[...]} or {"data":[...]}
                    if isinstance(data, dict) and (data.get("data") is not None or data.get("meta")):
                        self._api_root = candidate
                        _LOGGER.debug("UniFi: selected API root %s", candidate)
                        return True
            except ClientError as exc:
                _LOGGER.debug("UniFi probe failed for %s: %s", candidate, exc)
        return False

    async def _ensure_ready(self, hass) -> bool:
        if self._api_root:
            return True
        if not await self._login(hass):
            return False
        if not await self._detect_api_root(hass):
            _LOGGER.error(
                "UniFi: could not determine API root after login (proxy vs legacy). "
                "Check URL/port. Use the one that worked in your browser (e.g. https://host:4334)."
            )
            return False
        return True

    # ---------- public API ----------

    async def _get_json_under_root(self, hass, path_under_root: str) -> Any:
        if not self._api_root:
            raise RuntimeError("UniFi: API root not determined")
        status, txt = await self._get_any(hass, self._api_root + path_under_root)
        _LOGGER.debug("UniFi GET %s -> %s body[:200]=%r", self._api_root + path_under_root, status, txt[:200])
        if status >= 400:
            raise RuntimeError(f"HTTP {status}: {txt[:200]!r}")
        try:
            return json.loads(txt)
        except Exception:
            raise RuntimeError(f"Non-JSON at {self._api_root + path_under_root}: {txt[:120]!r}")

    async def fetch_clients(self, hass) -> list[dict]:
        if not await self._ensure_ready(hass):
            return []
        try:
            data = await self._get_json_under_root(hass, f"/s/{self.site}/stat/sta")
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
            data = await self._get_json_under_root(hass, f"/s/{self.site}/stat/device")
            rows = data.get("data", []) if isinstance(data, dict) else []
            _LOGGER.debug("UniFi: fetched %d devices", len(rows))
            return rows
        except Exception as exc:
            _LOGGER.debug("UniFi fetch devices failed: %s", exc)
            return []
