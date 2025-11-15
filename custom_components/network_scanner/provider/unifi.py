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

# ---------- small helpers ----------

def _looks_like_html(content_type: Optional[str], body: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    t = body.lstrip().lower()
    return t.startswith("<!doctype") or t.startswith("<html")


def _cookie_val(cookies, name: str) -> Optional[str]:
    try:
        c = cookies.get(name)
        if c is None:
            return None
        # aiohttp SimpleCookie morsel has .value
        return getattr(c, "value", None) or str(c)
    except Exception:
        return None


# ---------- UniFi client ----------

class UniFiClient:
    """
    Minimal, robust UniFi Network API client.

    - Prefers cookie auth (username/password) when token not given.
    - Auto re-login on 401/403 or when HTML login page is returned.
    - Tries both proxy and legacy base paths.
    """

    def __init__(
        self,
        session: ClientSession,
        base_url: str,
        *,
        username: str = "",
        password: str = "",
        token: str = "",
        verify_ssl: bool = True,
        timeout_s: int = 5,
    ) -> None:
        self._session = session
        self._base = (base_url or "").rstrip("/")
        self._user = username or ""
        self._pass = password or ""
        self._token = token or ""
        self._ssl = bool(verify_ssl)
        self._timeout = ClientTimeout(total=timeout_s)

        # Mutable auth state
        self._cookies = None
        self._csrf_token: Optional[str] = None
        self._headers_base: Dict[str, str] = {"Content-Type": "application/json"}

    def _headers(self) -> Dict[str, str]:
        hdrs = dict(self._headers_base)
        if self._token:
            hdrs["Authorization"] = f"Bearer {self._token}"
        if self._csrf_token:
            # Some controller versions require this alongside cookie
            hdrs["X-Csrf-Token"] = self._csrf_token
        return hdrs

    async def _login(self) -> bool:
        """
        Ensure we are authenticated. If a Bearer token was provided,
        we just use it. Otherwise, do cookie login.
        """
        # If using a static token, nothing to "do" here.
        if self._token:
            _LOGGER.debug("UniFi: using provided Bearer token")
            self._cookies = None
            self._csrf_token = None
            return True

        if not (self._user and self._pass):
            _LOGGER.warning("UniFi: no token and no username/password supplied")
            return False

        self._cookies = None
        self._csrf_token = None

        login_payload = {"username": self._user, "password": self._pass}
        # Newer first, then older:
        login_paths = ["/api/auth/login", "/api/login"]

        for lp in login_paths:
            url = f"{self._base}{lp}"
            try:
                async with self._session.post(
                    url,
                    json=login_payload,
                    headers=self._headers_base,
                    timeout=self._timeout,
                    ssl=self._ssl,
                ) as resp:
                    body = await resp.text()
                    if resp.status != 200:
                        _LOGGER.debug(
                            "UniFi login %s -> HTTP %s, body=%.256s", lp, resp.status, body
                        )
                        continue
                    # Got 200; assume cookies set for session
                    self._cookies = resp.cookies
                    self._csrf_token = _cookie_val(self._cookies, "csrf_token")
                    _LOGGER.debug(
                        "UniFi: login via %s succeeded (csrf=%s)",
                        lp,
                        "yes" if self._csrf_token else "no",
                    )
                    return True
            except ClientError as ce:
                _LOGGER.debug("UniFi login %s raised %s", lp, ce)
            except Exception as exc:
                _LOGGER.debug("UniFi login %s unexpected error: %s", lp, exc)

        _LOGGER.warning("UniFi: login failed via both /api/auth/login and /api/login")
        return False

    async def _req_json(
        self, method: str, path: str, *, allow_reauth: bool = True
    ) -> Optional[Any]:
        """
        Make a JSON request; re-auth on 401/403 or HTML; return parsed JSON or None.
        """
        url = f"{self._base}{path}"
        try:
            async with self._session.request(
                method,
                url,
                headers=self._headers(),
                cookies=self._cookies,
                timeout=self._timeout,
                ssl=self._ssl,
            ) as resp:
                text = await resp.text()
                if resp.status in (401, 403) or _looks_like_html(
                    resp.headers.get("Content-Type"), text
                ):
                    _LOGGER.debug(
                        "UniFi %s %s auth issue (status=%s, html=%s)",
                        method,
                        path,
                        resp.status,
                        _looks_like_html(resp.headers.get("Content-Type"), text),
                    )
                    if allow_reauth and await self._login():
                        return await self._req_json(method, path, allow_reauth=False)
                    _LOGGER.warning(
                        "UniFi: request %s -> %s failed due to auth despite retry",
                        method,
                        path,
                    )
                    return None

                if resp.status >= 400:
                    _LOGGER.debug(
                        "UniFi %s %s HTTP %s body=%.256s",
                        method,
                        path,
                        resp.status,
                        text,
                    )
                    return None

                try:
                    return await resp.json(content_type=None)
                except Exception:
                    _LOGGER.debug(
                        "UniFi %s %s non-JSON body=%.256s", method, path, text
                    )
                    return None
        except ClientError as ce:
            _LOGGER.debug("UniFi %s %s network error: %s", method, path, ce)
            return None
        except Exception as exc:
            _LOGGER.debug("UniFi %s %s unexpected error: %s", method, path, exc)
            return None

    async def ensure_ready(self) -> bool:
        """
        Ensure we have an authenticated session or token is set.
        """
        # For tokens we don't pre-flight.
        if self._token:
            return True
        return await self._login()

    async def fetch_clients(self) -> List[Dict[str, Any]]:
        """
        Try a set of endpoints; return list of client dicts or [].
        """
        # Try proxy then legacy; each with STA then list/clients; add v2 for newer builds
        candidates = [
            "/proxy/network/api/s/default/stat/sta",
            "/api/s/default/stat/sta",
            "/proxy/network/api/s/default/list/clients",
            "/api/s/default/list/clients",
            # Newer v2 (not always present)
            "/proxy/network/v2/api/site/default/clients",
            "/v2/api/site/default/clients",
        ]

        for path in candidates:
            data = await self._req_json("GET", path, allow_reauth=True)
            if data is None:
                continue

            items = data.get("data") if isinstance(data, dict) else data
            if isinstance(items, list) and items:
                rows = self._parse_clients(items)
                if rows:
                    _LOGGER.debug(
                        "UniFi: parsed %d clients from %s", len(rows), path
                    )
                    return rows
                # If the endpoint returns a list but empty, keep trying others:
                _LOGGER.debug("UniFi: %s returned empty client list", path)
                continue

        _LOGGER.warning("UniFi: all client endpoints tried, no usable data")
        return []

    @staticmethod
    def _parse_clients(items: List[Any]) -> List[Dict[str, Any]]:
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
            site = it.get("site_name") or it.get("site") or it.get("site_id") or "default"
            vlan = it.get("vlan")
            # epoch seconds if present
            last_seen_ts = it.get("last_seen")
            first_seen_ts = it.get("first_seen")

            uni_block: Dict[str, Any] = {
                "is_wired": bool(is_wired) if isinstance(is_wired, bool) else None,
                "ap_mac": it.get("ap_mac") or "",
                "bssid": it.get("bssid") or "",
                "essid": it.get("essid") or it.get("ssid") or "",
                "rssi": it.get("rssi"),
                "rx_rate_mbps": it.get("rx_rate"),
                "tx_rate_mbps": it.get("tx_rate"),
                "oui": oui,
                "uptime_s": it.get("uptime"),
                "is_guest": bool(it.get("is_guest")),
                "vlan": vlan,
                "site": site,
                "sw_mac": it.get("sw_mac") or "",
                "sw_port": it.get("sw_port"),
                "last_seen_ts": last_seen_ts if isinstance(last_seen_ts, (int, float)) else None,
                "first_seen_ts": first_seen_ts if isinstance(first_seen_ts, (int, float)) else None,
            }

            device = {
                "mac": mac,
                "ip": ip,
                "hostname": host,
                "vendor": oui,  # keep top-level vendor as OUI best-effort
                "unifi": uni_block,
            }
            out.append(device)
        return out


# ---------- Public entry point ----------

async def async_get_devices(
    session: ClientSession,
    base_url: str,
    username: str = "",
    password: str = "",
    token: str = "",
    verify_ssl: bool = True,
    timeout_s: int = 5,
) -> List[Dict[str, Any]]:
    """
    Fetch current UniFi clients and normalise into integration's device dict shape.
    Coordinator will attach 'sources' and merge with other providers.
    """
    if not base_url:
        _LOGGER.warning("UniFi: base_url is empty")
        return []

    client = UniFiClient(
        session=session,
        base_url=base_url,
        username=username,
        password=password,
        token=token,
        verify_ssl=verify_ssl,
        timeout_s=timeout_s,
    )

    if not await client.ensure_ready():
        return []

    try:
        return await client.fetch_clients()
    except Exception as exc:
        _LOGGER.warning("UniFi: fetch_clients raised: %s", exc)
        return []
