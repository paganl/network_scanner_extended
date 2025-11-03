# custom_components/network_scanner/unifi.py
from __future__ import annotations
from typing import Dict, Any, Iterable, List, Optional
import json
import logging

from aiohttp import ClientError, ClientTimeout
from yarl import URL
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

# Known UniFi API path variants (UniFi OS vs Standalone)
API_PREFIXES = (
    "/proxy/network/api",  # UniFi OS (UDM/UDR/UXG)
    "/api",                # Standalone controller / older Cloud Key
)

LOGIN_PATHS = (
    "/api/login",       # newer
    "/api/auth/login",  # older
)

SITES_PATHS = (
    "/self/sites",           # under the chosen API prefix
    "/s/default/self/sites", # very old oddball
)


class UniFiClient:
    """
    Tolerant UniFi client:
      - Logs in (tries both /api/login and /api/auth/login)
      - Discovers API prefix (/proxy/network/api vs /api)
      - Discovers site name when not provided (first site)
      - Fetches clients (/s/{site}/stat/sta) and devices (/s/{site}/stat/device)

    Base URL must be just the controller root, e.g.:
      - UniFi OS: https://<udm-ip>
      - Standalone: https://<controller-ip>:8443
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        site: str = "",
        verify_tls: bool = True,
        timeout: int = 10,
    ) -> None:
        self.base = (base_url or "").rstrip("/")
        self.user = username or ""
        self.passwd = password or ""
        self.site = (site or "").strip()  # may be empty; we’ll auto-discover
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)

        # Resolved at runtime
        self._api_prefix: Optional[str] = None   # one of API_PREFIXES
        self._logged_in: bool = False

    # ------------- low-level HTTP -------------

    def _session(self, hass):
        # Use HA session; respect self-signed cert preference
        return async_get_clientsession(hass, verify_ssl=self.verify_tls)

    async def _post_json(self, hass, path: str, payload: dict) -> tuple[int, str]:
        sess = self._session(hass)
        url = self.base + path
        try:
            async with sess.post(url, json=payload, timeout=self.timeout) as resp:
                txt = await resp.text()
                return resp.status, txt
        except ClientError as exc:
            raise RuntimeError(f"POST {path} failed: {exc}") from exc

    async def _get_json_text(self, hass, url: str) -> tuple[int, str]:
        sess = self._session(hass)
        try:
            async with sess.get(url, timeout=self.timeout) as resp:
                txt = await resp.text()
                return resp.status, txt
        except ClientError as exc:
            raise RuntimeError(f"GET {url} failed: {exc}") from exc

    async def _get_json(self, hass, path: str) -> Any:
        if not self._api_prefix:
            raise RuntimeError("API prefix not resolved")
        url = self.base + self._api_prefix + path
        status, txt = await self._get_json_text(hass, url)
        if status >= 400:
            raise RuntimeError(f"HTTP {status} at {url!r}: {txt[:180]!r}")
        try:
            return json.loads(txt)
        except Exception:
            raise RuntimeError(f"Non-JSON at {url!r}: {txt[:180]!r}")

    # ------------- login + discovery -------------

    async def _login(self, hass) -> bool:
        if self._logged_in:
            return True
        if not (self.base and self.user and self.passwd):
            _LOGGER.warning("UniFi base/user/pass not configured")
            return False

        # Try both login endpoints
        for lp in LOGIN_PATHS:
            try:
                status, _ = await self._post_json(hass, lp, {"username": self.user, "password": self.passwd})
                if status == 200:
                    self._logged_in = True
                    _LOGGER.debug("UniFi login ok via %s", lp)
                    break
            except RuntimeError as exc:
                _LOGGER.debug("UniFi login via %s failed: %s", lp, exc)

        if not self._logged_in:
            _LOGGER.warning("UniFi login failed at %s", self.base)
            return False

        # Detect working API prefix
        for prefix in API_PREFIXES:
            try:
                # cheap probe: health/stat exists for both layouts
                status, _ = await self._get_json_text(hass, self.base + prefix + "/stat/health")
                if status == 200:
                    self._api_prefix = prefix
                    _LOGGER.debug("UniFi API prefix = %s", prefix)
                    break
            except RuntimeError:
                continue

        if not self._api_prefix:
            # 404 earlier was likely this: wrong prefix for your controller
            _LOGGER.warning("Could not resolve UniFi API prefix under %s", self.base)
            return False

        # Discover site if not supplied
        if not self.site:
            for sp in SITES_PATHS:
                try:
                    data = await self._get_json(hass, sp)
                    items = data.get("data") if isinstance(data, dict) else None
                    if isinstance(items, list) and items:
                        name = items[0].get("name") or items[0].get("desc") or "default"
                        self.site = str(name)
                        _LOGGER.debug("UniFi site discovered = %s", self.site)
                        break
                except Exception as exc:
                    _LOGGER.debug("Site discovery via %s failed: %s", sp, exc)

            if not self.site:
                # fall back
                self.site = "default"
                _LOGGER.debug("UniFi site fallback to 'default'")

        return True

    # ------------- public fetches -------------

    async def fetch_clients(self, hass) -> list[dict]:
        ok = await self._login(hass)
        if not ok:
            return []
        try:
            data = await self._get_json(hass, f"/s/{self.site}/stat/sta")
            return data.get("data", []) if isinstance(data, dict) else []
        except Exception as exc:
            _LOGGER.warning("UniFi fetch clients failed: %s", exc)
            return []

    async def fetch_devices(self, hass) -> list[dict]:
        # same session; do not re-login
        if not self._api_prefix:
            # ensure we completed discovery if someone calls directly
            ok = await self._login(hass)
            if not ok:
                return []
        try:
            data = await self._get_json(hass, f"/s/{self.site}/stat/device")
            return data.get("data", []) if isinstance(data, dict) else []
        except Exception as exc:
            _LOGGER.debug("UniFi fetch devices failed: %s", exc)
            return []
