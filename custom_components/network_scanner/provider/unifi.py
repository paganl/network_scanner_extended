# -*- coding: utf-8 -*-
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

# ------------------------- small utils -------------------------

def _looks_like_html(content_type: Optional[str], body: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    t = (body or "").lstrip().lower()
    return t.startswith("<!doctype") or t.startswith("<html")


def _pick(first: Any, *fallbacks: Any) -> Any:
    """Return the first truthy value from arguments."""
    if first:
        return first
    for f in fallbacks:
        if f:
            return f
    return first


def _norm_mac(v: Any) -> str:
    return (str(v or "")).upper()


# ------------------------- HTTP helpers -------------------------

async def _login_if_needed(
    session: aiohttp.ClientSession,
    base: str,
    headers: Dict[str, str],
    verify_ssl: bool,
    timeout: aiohttp.ClientTimeout,
    username: str,
    password: str,
) -> Dict[str, str]:
    """Try UniFi OS login first, then legacy. Returns (maybe updated) headers.
    Leaves cookies inside the session object; many UniFi installs rely on that.
    """
    # Try UniFi OS login (UDM/UDR, Network App on 8443)
    try:
        async with session.post(
            f"{base}/api/auth/login",
            json={"username": username, "password": password},
            headers=headers,
            ssl=verify_ssl,
            timeout=timeout,
        ) as r:
            if r.status == 200:
                csrf = r.headers.get("X-CSRF-Token")
                if csrf:
                    headers["X-CSRF-Token"] = csrf
                _LOGGER.debug("UniFi OS login OK, CSRF=%s", "yes" if csrf else "no")
                return headers
    except Exception as exc:
        _LOGGER.debug("UniFi OS login failed: %s", exc)

    # Try legacy login (pre-UniFi OS)
    try:
        async with session.post(
            f"{base}/api/login",
            json={"username": username, "password": password},
            headers=headers,
            ssl=verify_ssl,
            timeout=timeout,
        ) as r:
            if r.status == 200:
                _LOGGER.debug("Legacy UniFi login OK")
                return headers
    except Exception as exc:
        _LOGGER.debug("Legacy UniFi login failed: %s", exc)

    return headers


async def _json_get(
    session: aiohttp.ClientSession,
    url: str,
    headers: Dict[str, str],
    verify_ssl: bool,
    timeout: aiohttp.ClientTimeout,
) -> Optional[Any]:
    """GET JSON from URL, tolerant to wrong content-type, avoids HTML bodies."""
    try:
        async with session.get(url, headers=headers, ssl=verify_ssl, timeout=timeout) as r:
            text = await r.text()
            if r.status != 200:
                _LOGGER.debug("GET %s -> HTTP %s: %.200s", url, r.status, text)
                return None
            if _looks_like_html(r.headers.get("Content-Type"), text):
                _LOGGER.debug("GET %s -> HTML (likely auth portal); skipping", url)
                return None
            try:
                return await r.json(content_type=None)
            except Exception:
                _LOGGER.debug("GET %s -> non-JSON body: %.200s", url, text)
                return None
    except Exception as exc:
        _LOGGER.debug("GET %s raised %s", url, exc)
        return None


# ------------------------- public entrypoint -------------------------

async def async_get_devices(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "",
    password: str = "",
    token: str = "",
    verify_ssl: bool = True,
    timeout_s: int = 5,
) -> List[Dict[str, Any]]:
    """Return a list of normalised device dicts from UniFi Network."""
    if not base_url:
        return []

    base = base_url.rstrip("/")
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    headers: Dict[str, str] = {"Content-Type": "application/json"}

    # If caller provided a Bearer token, include it
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Attempt to establish cookies/CSRF if no token
    if not token and username and password:
        headers = await _login_if_needed(
            session, base, headers, verify_ssl, timeout, username, password
        )

    # Probe multiple endpoints (UniFi OS proxied + legacy), and multiple resources
    # Order matters: we prefer /stat/sta (active), then /stat/user (known), then /list/clients (legacy).
    candidate_paths = [
        "/proxy/network/api/s/default/stat/sta",
        "/api/s/default/stat/sta",
        "/proxy/network/api/s/default/stat/user",
        "/api/s/default/stat/user",
        "/proxy/network/api/s/default/list/clients",
        "/api/s/default/list/clients",
    ]

    # Fetch and merge by MAC across all endpoints we can read
    by_mac: Dict[str, Dict[str, Any]] = {}
    for path in candidate_paths:
        data = await _json_get(session, f"{base}{path}", headers, verify_ssl, timeout)
        if data is None:
            continue

        items = data.get("data") if isinstance(data, dict) else data
        if not isinstance(items, list):
            continue

        for it in items:
            _ingest_unifi_item(by_mac, it)

    # Emit sorted list (stable for UI)
    devices = list(by_mac.values())
    devices.sort(key=lambda d: (d.get("hostname") or "", d.get("mac") or d.get("ip") or ""))
    return devices


# ------------------------- parsing & merge -------------------------

def _ingest_unifi_item(by_mac: Dict[str, Dict[str, Any]], it: Dict[str, Any]) -> None:
    """Merge one UniFi client record into the accumulator keyed by MAC."""
    if not isinstance(it, dict):
        return

    mac = _norm_mac(it.get("mac"))
    ip = str(_pick(it.get("ip"), it.get("last_ip"), ""))

    # If we truly have neither MAC nor IP, skip.
    if not mac and not ip:
        return

    host = _pick(it.get("hostname"), it.get("name"), it.get("device_name"), "")
    vendor = _pick(it.get("oui"), it.get("manufacturer"), it.get("dev_vendor"), "")

    # Prepare the provider-specific block (carry raw-ish signals)
    uni_block: Dict[str, Any] = {
        "is_wired": bool(it.get("is_wired")),
        "ap_mac": it.get("ap_mac") or "",
        "bssid": it.get("bssid") or "",
        "essid": _pick(it.get("essid"), it.get("ssid"), ""),
        "rssi": it.get("rssi"),
        "rx_rate_mbps": it.get("rx_rate"),
        "tx_rate_mbps": it.get("tx_rate"),
        "oui": vendor,
        "uptime_s": it.get("uptime"),
        "is_guest": bool(it.get("is_guest")),
        "vlan": it.get("vlan"),
        "site": _pick(it.get("site_name"), it.get("site"), it.get("site_id"), "default"),
        # Wired switch info if present:
        "sw_mac": it.get("sw_mac") or "",
        "sw_port": it.get("sw_port"),
        # Time fields (epoch seconds):
        "last_seen_ts":
