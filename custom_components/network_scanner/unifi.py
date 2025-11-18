# custom_components/network_scanner/unifi.py
from __future__ import annotations
from typing import Any, Optional
import json
import logging

from aiohttp import ClientError, ClientTimeout
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)


def _extract_csrf_from_json(txt: str) -> str:
    """Pull CSRF token out of common UniFi JSON shapes."""
    try:
        j = json.loads(txt)
    except Exception:
        return ""
    if isinstance(j, dict):
        meta = j.get("meta")
        if isinstance(meta, dict) and isinstance(meta.get("csrf_token"), str):
            return meta["csrf_token"]
        data = j.get("data")
        if isinstance(data, list) and data and isinstance(data[0], dict):
            t = data[0].get("csrf_token")
            if isinstance(t, str):
                return t
    return ""


class UniFiClient:
    """
    UniFi client with token OR user/pass auth, CSRF awareness, API root detection,
    and 401 auto-retry (re-auth + re-probe once).

    Login order (when using user/pass):
      1) UniFi OS:   POST /api/auth/login
      2) Legacy:     POST /api/login

    CSRF pickup:
      - Try /api/auth/csrf, then /api/csrf (header X-Csrf-Token or JSON body)

    API root probe (after auth + CSRF):
      - /proxy/network/api/self/sites
      - /api/self/sites
      - fallback: hit data endpoints directly under /api
    """

    def __init__(
        self,
        base_url: str,
        username: str = "",
        password: str = "",
        *,
        token: str = "",
        site: str = "default",
        verify_tls: bool = True,
        timeout: int = 10,
    ) -> None:
        self.base = (base_url or "").rstrip("/")
        self.user = username or ""
        self.passwd = password or ""
        self.token = token or ""
        self.site = site or "default"
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)

        self._api_root: Optional[str] = None   # "/proxy/network/api" or "/api"
        self._csrf: Optional[str] = None
        self._mode: Optional[str] = None       # "os" | "legacy" | "token"

    # ---------------- low-level HTTP ----------------

    async def _session(self, hass):
        return async_get_clientsession(hass, verify_ssl=self.verify_tls)

    def _headers(self, extra_csrf: Optional[str] = None) -> dict[str, str]:
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Referer": self.base + "/",
            "Origin": self.base,
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        token = extra_csrf if extra_csrf is not None else self._csrf
        if token:
            h["X-Csrf-Token"] = token
        return h

    async def _request(self, hass, method: str, path: str, *, json_body: Any = None, form_body: Any = None) -> tuple[int, str]:
        sess = await self._session(hass)
        url = self.base + path
        hdrs = self._headers()
        try:
            if method == "GET":
                async with sess.get(url, headers=hdrs, timeout=self.timeout) as resp:
                    return resp.status, await resp.text()
            if method == "POST":
                if json_body is not None:
                    async with sess.post(url, json=json_body, headers=hdrs, timeout=self.timeout) as resp:
                        return resp.status, await resp.text()
                async with sess.post(url, data=form_body, headers=hdrs, timeout=self.timeout) as resp:
                    return resp.status, await resp.text()
        except ClientError as exc:
            raise RuntimeError(f"HTTP error {method} {url}: {exc}") from exc
        return 599, ""  # should not happen

    # ---------------- CSRF retrieval ----------------

    async def _fetch_csrf(self, hass) -> Optional[str]:
        """Try both OS and legacy CSRF endpoints; accept token from header or JSON body."""
        paths = (
            ["/api/auth/csrf", "/api/csrf"] if self._mode == "os"
            else ["/api/csrf", "/api/auth/csrf"] if self._mode == "legacy"
            else ["/api/auth/csrf", "/api/csrf"]
        )
        for p in paths:
            try:
                sess = await self._session(hass)
                async with sess.get(self.base + p, headers=self._headers(), timeout=self.timeout) as resp:
                    txt = await resp.text()
                    token = resp.headers.get("X-Csrf-Token") or _extract_csrf_from_json(txt)
                    _LOGGER.debug("UniFi CSRF %s -> %s token=%s", p, resp.status, bool(token))
                    if resp.status == 200 and token:
                        self._csrf = token
                        return token
            except ClientError as exc:
                _LOGGER.debug("UniFi CSRF %s failed: %s", p, exc)
        return None

    # ---------------- login + root detection ----------------

    async def _login_once(self, hass, login_path: str, mode: str) -> bool:
        payload = {"username": self.user, "password": self.passwd}
        # JSON
        try:
            st, body = await self._request(hass, "POST", login_path, json_body=payload)
            _LOGGER.debug("UniFi login JSON %s -> %s body[:160]=%r", login_path, st, body[:160])
            if st == 200:
                self._mode = mode
                return True
        except RuntimeError as exc:
            _LOGGER.debug("UniFi login JSON %s failed: %s", login_path, exc)
        # FORM (ancient)
        try:
            st, body = await self._request(hass, "POST", login_path, form_body=payload)
            _LOGGER.debug("UniFi login FORM %s -> %s body[:160]=%r", login_path, st, body[:160])
            if st == 200:
                self._mode = mode
                return True
        except RuntimeError as exc:
            _LOGGER.debug("UniFi login FORM %s failed: %s", login_path, exc)
        return False

    async def _login(self, hass) -> bool:
        if self.token:
            self._mode = "os"  # token is a UniFi OS concept; treat as OS mode
            _LOGGER.debug("UniFi: using Bearer token auth")
            return True
        if not (self.base and self.user and self.passwd):
            _LOGGER.warning("UniFi: missing base/user/pass and no token")
            return False

        # Prefer UniFi OS first
        if await self._login_once(hass, "/api/auth/login", "os"):
            _LOGGER.debug("UniFi: logged in via /api/auth/login")
            return True

        # Legacy
        if await self._login_once(hass, "/api/login", "legacy"):
            _LOGGER.debug("UniFi: logged in via /api/login")
            return True

        _LOGGER.warning("UniFi: login failed at %s", self.base)
        return False

    async def _detect_api_root(self, hass) -> bool:
        """Probe to find API root after auth + (ideally) CSRF."""
        for candidate in ("/proxy/network/api", "/api"):
            try:
                st, txt = await self._request(hass, "GET", f"{candidate}/self/sites")
                _LOGGER.debug("UniFi probe %s/self/sites -> %s", candidate, st)
                if st == 200:
                    try:
                        data = json.loads(txt)
                    except Exception:
                        data = None
                    if isinstance(data, dict) and (data.get("data") is not None or data.get("meta") is not None):
                        self._api_root = candidate
                        _LOGGER.debug("UniFi: selected API root %s", candidate)
                        return True
            except RuntimeError as exc:
                _LOGGER.debug("UniFi probe failed for %s: %s", candidate, exc)

        # Fallback: some legacy controllers won’t serve /self/sites without CSRF
        try:
            st_sta, _ = await self._request(hass, "GET", f"/api/s/{self.site}/stat/sta")
            st_dev, _ = await self._request(hass, "GET", f"/api/s/{self.site}/stat/device")
            _LOGGER.debug("UniFi direct probe /api stat/sta=%s stat/device=%s", st_sta, st_dev)
            if st_sta == 200 or st_dev == 200:
                self._api_root = "/api"
                return True
        except RuntimeError as exc:
            _LOGGER.debug("UniFi direct probe failed: %s", exc)

        return False

    async def _ensure_ready(self, hass) -> bool:
        if self._api_root:
            return True
        if not await self._login(hass):
            return False
        # CSRF (controllers often insist on it even with token)
        await self._fetch_csrf(hass)
        if not await self._detect_api_root(hass):
            _LOGGER.error(
                "UniFi: could not determine API root after auth. "
                "Check URL/port. Use the exact base that works in your browser."
            )
            return False
        _LOGGER.debug("UniFi ready: root=%s mode=%s site=%s", self._api_root, self._mode, self.site)
        return True

    async def _get_json_under_root(self, hass, path_under_root: str, *, _retry: bool = True) -> Any:
        if not await self._ensure_ready(hass):
            return []
        if not self._api_root:
            raise RuntimeError("UniFi: API root not determined")
        st, txt = await self._request(hass, "GET", self._api_root + path_under_root)
        _LOGGER.debug("UniFi GET %s -> %s body[:200]=%r", self._api_root + path_under_root, st, txt[:200])
        if st == 401 and _retry:
            # Session expired / CSRF invalid: re-auth and retry once
            _LOGGER.warning("UniFi: 401 on %s, attempting re-auth", path_under_root)
            self._api_root = None
            self._csrf = None
            if await self._login(hass):
                await self._fetch_csrf(hass)
                await self._detect_api_root(hass)
                return await self._get_json_under_root(hass, path_under_root, _retry=False)
        if st >= 400:
            raise RuntimeError(f"HTTP {st}: {txt[:200]!r}")
        try:
            return json.loads(txt)
        except Exception:
            raise RuntimeError(f"Non-JSON at {self._api_root + path_under_root}: {txt[:120]!r}")

    # ---------------- public API ----------------

    async def fetch_clients(self, hass) -> list[dict]:
        try:
            data = await self._get_json_under_root(hass, f"/s/{self.site}/stat/sta")
            rows = data.get("data", []) if isinstance(data, dict) else []
            _LOGGER.debug("UniFi: fetched %d clients", len(rows))
            return rows
        except Exception as exc:
            _LOGGER.warning("UniFi fetch clients failed: %s", exc)
            return []

    async def fetch_devices(self, hass) -> list[dict]:
        try:
            data = await self._get_json_under_root(hass, f"/s/{self.site}/stat/device")
            rows = data.get("data", []) if isinstance(data, dict) else []
            _LOGGER.debug("UniFi: fetched %d devices", len(rows))
            return rows
        except Exception as exc:
            _LOGGER.debug("UniFi fetch devices failed: %s", exc)
            return []
