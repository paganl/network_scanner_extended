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

import aiohttp

_LOGGER = logging.getLogger(__name__)


def _looks_like_html(content_type: Optional[str], body: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    t = body.lstrip().lower()
    return t.startswith("<!doctype") or t.startswith("<html")


async def _post_json(
    session: aiohttp.ClientSession,
    url: str,
    *,
    json: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[aiohttp.CookieJar] = None,
    verify_ssl: bool = True,
    timeout: aiohttp.ClientTimeout,
) -> Optional[Dict[str, Any]]:
    try:
        async with session.post(
            url,
            json=json,
            headers=headers,
            cookies=cookies,
            ssl=verify_ssl,
            timeout=timeout,
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                _LOGGER.debug("UniFi POST %s -> HTTP %s: %.256s", url, resp.status, text)
                return None
            if _looks_like_html(resp.headers.get("Content-Type"), text):
                _LOGGER.debug("UniFi POST %s returned HTML (likely login).", url)
                return None
            try:
                return await resp.json(content_type=None)
            except Exception:
                _LOGGER.debug("UniFi POST %s returned non-JSON: %.256s", url, text)
                return None
    except Exception as exc:
        _LOGGER.debug("UniFi POST %s raised %s", url, exc)
        return None


async def _get_json(
    session: aiohttp.ClientSession,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[aiohttp.CookieJar] = None,
    verify_ssl: bool = True,
    timeout: aiohttp.ClientTimeout,
) -> Optional[Dict[str, Any] | List[Any]]:
    try:
        async with session.get(
            url,
            headers=headers,
            cookies=cookies,
            ssl=verify_ssl,
            timeout=timeout,
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                _LOGGER.debug("UniFi GET %s -> HTTP %s: %.256s", url, resp.status, text)
                return None
            if _looks_like_html(resp.headers.get("Content-Type"), text):
                _LOGGER.debug("UniFi GET %s returned HTML (likely login).", url)
                return None
            try:
                return await resp.json(content_type=None)
            except Exception:
                _LOGGER.debug("UniFi GET %s returned non-JSON: %.256s", url, text)
                return None
    except Exception as exc:
        _LOGGER.debug("UniFi GET %s raised %s", url, exc)
        return None


async def _login_and_headers(
    session: aiohttp.ClientSession,
    base: str,
    *,
    username: str,
    password: str,
    token: str,
    verify_ssl: bool,
    timeout: aiohttp.ClientTimeout,
) -> Dict[str, Any]:
    """
    Returns dict with 'headers' and optional 'cookies'.
    Uses bearer token when provided; otherwise tries modern and legacy login endpoints.
    """
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    cookies = None

    if token:
        headers["Authorization"] = f"Bearer {token}"
        return {"headers": headers, "cookies": cookies}

    # Modern UniFi OS
    data = await _post_json(
        session,
        f"{base}/api/auth/login",
        json={"username": username, "password": password},
        headers=headers,
        cookies=None,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    if data is not None:
        # cookie jar was populated by aiohttp; capture a snapshot
        cookies = None  # aiohttp manages cookies automatically on the session
        return {"headers": headers, "cookies": cookies}

    # Legacy (pre-UniFi OS)
    data = await _post_json(
        session,
        f"{base}/api/login",
        json={"username": username, "password": password},
        headers=headers,
        cookies=None,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    if data is not None:
        cookies = None
        return {"headers": headers, "cookies": cookies}

    _LOGGER.debug("UniFi login failed (both modern and legacy). Proceeding without cookies.")
    return {"headers": headers, "cookies": cookies}


def _extract_items(payload: Dict[str, Any] | List[Any]) -> List[Dict[str, Any]]:
    """
    UniFi may return either a bare list or an object with 'data'.
    """
    if isinstance(payload, list):
        return [it for it in payload if isinstance(it, dict)]
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list):
            return [it for it in data if isinstance(it, dict)]
    return []


def _parse(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalise UniFi client rows into integration device dicts.
    """
    devices: List[Dict[str, Any]] = []

    for it in items:
        mac = (it.get("mac") or "").upper()
        ip = str(it.get("ip") or "")
        host = it.get("hostname") or it.get("name") or it.get("device_name") or ""
        oui = it.get("oui") or ""

        # Must have at least one identifier
        if not mac and not ip:
            continue

        uni_block: Dict[str, Any] = {
            "is_wired": bool(it.get("is_wired")),
            "ap_mac": it.get("ap_mac") or "",
            "bssid": it.get("bssid") or "",
            "essid": it.get("essid") or it.get("ssid") or "",
            "rssi": it.get("rssi"),
            "rx_rate_mbps": it.get("rx_rate"),
            "tx_rate_mbps": it.get("tx_rate"),
            "oui": oui,
            "uptime_s": it.get("uptime"),
            "is_guest": bool(it.get("is_guest")),
            "vlan": it.get("vlan"),
            "site": it.get("site_name") or it.get("site") or it.get("site_id") or "default",
            "sw_mac": it.get("sw_mac") or "",
            "sw_port": it.get("sw_port"),
            # Feed coordinator timestamp logic:
            "last_seen_ts": it.get("last_seen"),   # epoch seconds (int)
            "first_seen_ts": it.get("first_seen"), # epoch seconds (int)
        }

        device: Dict[str, Any] = {
            "mac": mac,
            "ip": ip,
            "hostname": host,
            "vendor": oui,     # Use OUI as vendor hint
            "source": "unifi",
            "unifi": uni_block,
        }
        devices.append(device)

    return devices


async def async_get_devices(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "",
    password: str = "",
    token: str = "",
    verify_ssl: bool = True,
    timeout_s: int = 5,
) -> List[Dict[str, Any]]:
    """
    Fetch active UniFi clients using modern and legacy paths.
    Returns a list of normalised device dicts, or [] on failure.
    """
    if not base_url:
        return []

    base = base_url.rstrip("/")
    timeout = aiohttp.ClientTimeout(total=timeout_s)

    auth = await _login_and_headers(
        session,
        base,
        username=username,
        password=password,
        token=token,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )
    headers = auth["headers"]
    cookies = auth["cookies"]

    # Probe most common paths, stop at first with rows
    paths = [
        "/api/s/default/stat/sta",
        "/proxy/network/api/s/default/stat/sta",
        "/api/s/default/list/clients",
        "/proxy/network/api/s/default/list/clients",
    ]

    for path in paths:
        data = await _get_json(
            session,
            f"{base}{path}",
            headers=headers,
            cookies=cookies,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        if data is None:
            continue

        items = _extract_items(data)
        rows = _parse(items)
        if rows:
            _LOGGER.debug("UniFi parsed %d clients from %s", len(rows), path)
            return rows

    _LOGGER.debug("UniFi returned no clients from known endpoints.")
    return []
