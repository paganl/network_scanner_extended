# custom_components/network_scanner/provider/unifi.py
"""
UniFi provider for the Network Scanner integration.

This module queries a UniFi Network controller (UniFi OS or legacy) to
retrieve client information from multiple endpoints, merges the results,
and returns a normalised list of device dicts with keys:
  - mac, ip, hostname, vendor, source="unifi", unifi={...}

Highlights:
- Supports Bearer token, UniFi OS login (/api/auth/login), and legacy (/api/login).
- Handles CSRF token for UniFi OS (X-CSRF-Token).
- Probes both UniFi OS proxied paths and legacy paths.
- Merges data from /stat/sta (active), /stat/user (known), and /list/clients (legacy).
- Robust JSON parsing with HTML sniff (avoids login page mis-parses).
- Exposes unifi.last_seen_ts / first_seen_ts for the coordinator to compute last_seen.

"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession, ClientTimeout, ClientError

_LOGGER = logging.getLogger(__name__)


def _looks_like_html(content_type: Optional[str], body: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    t = (body or "").lstrip().lower()
    return t.startswith("<!doctype") or t.startswith("<html")


def _cookie_val(cookies, name: str) -> Optional[str]:
    try:
        c = cookies.get(name)
        if c is None:
            return None
        return getattr(c, "value", None) or str(c)
    except Exception:
        return None


class UniFiClient:
    def __init__(
        self,
        session: ClientSession,
        base_url: str,
        *,
        username: str = "",
        password: str = "",
        token: str = "",
        site: str = "default",
        verify_ssl: bool = True,
        timeout_s: int = 6,
    ) -> None:
        self._session = session
        self._base = (base_url or "").rstrip("/")
        self._user = username or ""
        self._pass = password or ""
        self._token = token or ""
        self._site = (site or "default").strip() or "default"
        self._ssl = bool(verify_ssl)
        self._timeout = ClientTimeout(total=timeout_s)

        self._cookies = None
        self._csrf_token: Optional[str] = None
        self._headers_base: Dict[str, str] = {"Content-Type": "application/json"}

    def _headers(self) -> Dict[str, str]:
        hdrs = dict(self._headers_base)
        if self._token:
            hdrs["Authorization"] = f"Bearer {self._token}"
        if self._csrf_token:
            hdrs["X-Csrf-Token"] = self._csrf_token
        return hdrs

    async def _login(self) -> bool:
        if self._token:
            self._cookies = None
            self._csrf_token = None
            return True

        if not (self._user and self._pass):
            _LOGGER.warning("UniFi: no token and no username/password supplied")
            return False

        self._cookies = None
        self._csrf_token = None
        payload = {"username": self._user, "password": self._pass}
        for lp in ("/api/auth/login", "/api/login"):
            url = f"{self._base}{lp}"
            try:
                async with self._session.post(
                    url, json=payload, headers=self._headers_base,
                    timeout=self._timeout, ssl=self._ssl
                ) as resp:
                    body = await resp.text()
                    if resp.status != 200:
                        _LOGGER.debug("UniFi login %s -> HTTP %s %.128s", lp, resp.status, body)
                        continue
                    self._cookies = resp.cookies
                    self._csrf_token = _cookie_val(self._cookies, "csrf_token")
                    return True
            except Exception as exc:
                _LOGGER.debug("UniFi login %s failed: %s", lp, exc)
        return False

    async def _req_json(self, method: str, path: str, *, allow_reauth: bool = True) -> Optional[Any]:
        url = f"{self._base}{path}"
        try:
            async with self._session.request(
                method, url,
                headers=self._headers(),
                cookies=self._cookies,
                timeout=self._timeout,
                ssl=self._ssl,
            ) as resp:
                text = await resp.text()
                html = _looks_like_html(resp.headers.get("Content-Type"), text)
                if resp.status in (401, 403) or html:
                    if allow_reauth and await self._login():
                        return await self._req_json(method, path, allow_reauth=False)
                    return None
                if resp.status >= 400:
                    _LOGGER.debug("UniFi %s %s HTTP %s %.128s", method, path, resp.status, text)
                    return None
                try:
                    return await resp.json(content_type=None)
                except Exception:
                    _LOGGER.debug("UniFi %s %s non-JSON %.128s", method, path, text)
                    return None
        except ClientError as ce:
            _LOGGER.debug("UniFi %s %s network error: %s", method, path, ce)
            return None
        except Exception as exc:
            _LOGGER.debug("UniFi %s %s unexpected error: %s", method, path, exc)
            return None

    async def ensure_ready(self) -> bool:
        if self._token:
            return True
        return await self._login()

    async def fetch_clients(self) -> List[Dict[str, Any]]:
        s = self._site
        candidates = [
            f"/proxy/network/api/s/{s}/stat/sta",
            f"/api/s/{s}/stat/sta",
            f"/proxy/network/api/s/{s}/list/clients",
            f"/api/s/{s}/list/clients",
            f"/proxy/network/v2/api/site/{s}/clients",
            f"/v2/api/site/{s}/clients",
        ]

        for path in candidates:
            data = await self._req_json("GET", path, allow_reauth=True)
            if data is None:
                continue
            items = data.get("data") if isinstance(data, dict) else data
            if isinstance(items, list):
                rows = self._parse_clients(items, site=s)
                if rows:
                    return rows
        return []

    @staticmethod
    def _parse_clients(items: List[Any], site: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for it in items or []:
            if not isinstance(it, dict):
                continue
            mac = (it.get("mac") or "").upper()
            ip = str(it.get("ip") or "")
            if not mac and not ip:
                continue

            host = it.get("hostname") or it.get("name") or it.get("device_name") or ""
            oui = it.get("oui") or ""
            is_wired = it.get("is_wired")
            vlan = it.get("vlan")
            last_seen_ts = it.get("last_seen")
            first_seen_ts = it.get("first_seen")

            uni_block: Dict[str, Any] = {
                "is_wired": bool(is_wired) if isinstance(is_wired, bool) else None,
                "ap_mac": it.get("ap_mac") or "",
                "essid": it.get("essid") or it.get("ssid") or "",
                "rssi": it.get("rssi"),
                "snr": it.get("snr"),
                "oui": oui,
                "vlan": vlan,
                "site": site,
                "sw_mac": it.get("sw_mac") or "",
                "sw_port": it.get("sw_port"),
                "last_seen_ts": last_seen_ts if isinstance(last_seen_ts, (int, float)) else None,
                "first_seen_ts": first_seen_ts if isinstance(first_seen_ts, (int, float)) else None,
            }

            out.append({
                "mac": mac,
                "ip": ip,
                "hostname": host,
                "vendor": oui,
                "unifi": uni_block,
            })
        return out


async def async_get_devices(
    session: ClientSession,
    base_url: str,
    username: str = "",
    password: str = "",
    token: str = "",
    site: str = "default",
    verify_ssl: bool = True,
    timeout_s: int = 6,
) -> List[Dict[str, Any]]:
    if not base_url:
        return []
    client = UniFiClient(
        session=session,
        base_url=base_url,
        username=username,
        password=password,
        token=token,
        site=site,
        verify_ssl=verify_ssl,
        timeout_s=timeout_s,
    )
    if not await client.ensure_ready():
        return []
    return await client.fetch_clients()

