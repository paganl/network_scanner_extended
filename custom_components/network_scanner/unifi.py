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
    UniFi client with CSRF-aware auth (UniFi OS & legacy):

      Login order:
        1) UniFi OS:   POST /api/auth/login  (+ later CSRF at /api/auth/csrf)
        2) Legacy:     POST /api/login       (+ later CSRF at /api/csrf)

      Root probe (after login + CSRF pickup):
        - /proxy/network/api/self/sites  (UniFi OS proxy)
        - /api/self/sites                (legacy/direct)

      Data:
        - GET {root}/s/{site}/stat/sta
        - GET {root}/s/{site}/stat/device
    """

    def _extract_csrf_from_json(txt: str) -> str:
        try:
            j = json.loads(txt)
        except Exception:
            return ""
        # common shapes:
        # {"meta":{"rc":"ok","csrf_token":"..."},"data":[]}
        t = ""
        if isinstance(j, dict):
            meta = j.get("meta", {})
            if isinstance(meta, dict):
                t = meta.get("csrf_token", "") or t
            if not t and isinstance(j.get("data"), list) and j["data"]:
                first = j["data"][0]
                if isinstance(first, dict):
                    t = first.get("csrf_token", "") or t
        return t    

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

        self._api_root: Optional[str] = None   # "/proxy/network/api" or "/api"
        self._csrf: Optional[str] = None
        self._mode: Optional[str] = None       # "os" | "legacy"

    # ---------------- low-level HTTP ----------------

    async def _session(self, hass):
        return async_get_clientsession(hass, verify_ssl=self.verify_tls)

    def _headers(self, extra_csrf: Optional[str] = None) -> dict[str, str]:
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Referer": self.base + "/",
            "Origin": self.base,
            "X-Requested-With": "XMLHttpRequest",   # <— important for /api/csrf on legacy
        }
        token = extra_csrf if extra_csrf is not None else self._csrf
        if token:
            h["X-Csrf-Token"] = token
        return h

        # --- make all requests carry our headers (no change if you used _headers already) ---
        async def _get_any(self, hass, path: str) -> tuple[int, str]:
            sess = await self._session(hass)
            async with sess.get(self.base + path, headers=self._headers(), timeout=self.timeout) as resp:
                return resp.status, await resp.text()
        
        async def _post_json(self, hass, path: str, payload: dict, csrf: Optional[str]) -> tuple[int, str]:
            sess = await self._session(hass)
            async with sess.post(self.base + path, json=payload, headers=self._headers(csrf), timeout=self.timeout) as resp:
                return resp.status, await resp.text()
        
        async def _post_form(self, hass, path: str, payload: dict, csrf: Optional[str]) -> tuple[int, str]:
            sess = await self._session(hass)
            async with sess.post(self.base + path, data=payload, headers=self._headers(csrf), timeout=self.timeout) as resp:
                return resp.status, await resp.text()


    # --- improve CSRF retrieval after login ---
    async def _fetch_csrf(self, hass) -> Optional[str]:
        # Try mode-specific first, then the other
        paths = (["/api/auth/csrf", "/api/csrf"] if self._mode == "os"
                 else ["/api/csrf", "/api/auth/csrf"] if self._mode == "legacy"
                 else ["/api/auth/csrf", "/api/csrf"])
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

        # try JSON
        try:
            status, txt = await self._post_json(hass, login_path, payload, csrf=None)
            _LOGGER.debug("UniFi login JSON %s -> %s body[:160]=%r", login_path, status, txt[:160])
            if status == 200:
                self._mode = mode
                return True
        except ClientError as exc:
            _LOGGER.debug("UniFi login JSON %s failed: %s", login_path, exc)

        # try FORM
        try:
            status, txt = await self._post_form(hass, login_path, payload, csrf=None)
            _LOGGER.debug("UniFi login FORM %s -> %s body[:160]=%r", login_path, status, txt[:160])
            if status == 200:
                self._mode = mode
                return True
        except ClientError as exc:
            _LOGGER.debug("UniFi login FORM %s failed: %s", login_path, exc)

        return False

    async def _login(self, hass) -> bool:
        if not (self.base and self.user and self.passwd):
            _LOGGER.warning("UniFi: missing base/user/pass")
            return False

        # Prefer UniFi OS first (works for 443/4334 on OS)
        if await self._login_once(hass, "/api/auth/login", "os"):
            _LOGGER.debug("UniFi: logged in via /api/auth/login")
            return True

        # Legacy (common on 8443)
        if await self._login_once(hass, "/api/login", "legacy"):
            _LOGGER.debug("UniFi: logged in via /api/login")
            return True

        _LOGGER.warning("UniFi: login failed at %s", self.base)
        return False

    async def _detect_api_root(self, hass) -> bool:
        """
        Must be called after _login() and CSRF retrieval.
        """
        for candidate in ("/proxy/network/api", "/api"):
            try:
                status, txt = await self._get_any(hass, f"{candidate}/self/sites")
                _LOGGER.debug("UniFi probe %s/self/sites -> %s", candidate, status)
                if status == 200:
                    try:
                        data = json.loads(txt)
                    except Exception:
                        data = None
                    if isinstance(data, dict) and (data.get("data") is not None or data.get("meta") is not None):
                        self._api_root = candidate
                        _LOGGER.debug("UniFi: selected API root %s", candidate)
                        return True
                elif status == 401:
                    _LOGGER.debug("UniFi probe %s/self/sites got 401 (likely missing/invalid CSRF)", candidate)
            except ClientError as exc:
                _LOGGER.debug("UniFi probe failed for %s: %s", candidate, exc)
        return False

    # --- after a successful login in _ensure_ready(), insist on CSRF before probing ---
    async def _ensure_ready(self, hass) -> bool:
        if self._api_root:
            return True
        if not await self._login(hass):
            return False
        # pickup CSRF (required on your controller)
        if not await self._fetch_csrf(hass):
            _LOGGER.debug("UniFi: CSRF not obtained (controller likely requires it); proceeding may 401")
        if not await self._detect_api_root(hass):
            _LOGGER.error(
                "UniFi: could not determine API root after login. "
                "Check URL/port. Use the exact base that works in your browser (e.g. https://host:4334)."
            )
            return False
        return True


    # ---------------- public API ----------------

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
