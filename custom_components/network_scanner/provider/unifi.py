from __future__ import annotations
import aiohttp
from typing import Any, Dict, List

async def async_get_devices(
    session: aiohttp.ClientSession,
    base_url: str,
    username: str = "",
    password: str = "",
    token: str = "",
    verify_ssl: bool = True,
    timeout_s: int = 5,
) -> List[Dict[str, Any]]:
    if not base_url:
        return []
    base = base_url.rstrip("/")
    timeout = aiohttp.ClientTimeout(total=timeout_s)

    headers = {"Content-Type": "application/json"}
    cookies = None

    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        try:
            async with session.post(f"{base}/api/auth/login", json={"username": username, "password": password}, timeout=timeout, ssl=verify_ssl, headers=headers) as r:
                if r.status == 200:
                    cookies = r.cookies
                else:
                    async with session.post(f"{base}/api/login", json={"username": username, "password": password}, timeout=timeout, ssl=verify_ssl, headers=headers) as r2:
                        if r2.status == 200:
                            cookies = r2.cookies
        except Exception:
            pass

    for path in ("/api/s/default/stat/sta", "/proxy/network/api/s/default/stat/sta"):
        try:
            async with session.get(f"{base}{path}", headers=headers, cookies=cookies, timeout=timeout, ssl=verify_ssl) as r:
                if r.status != 200:
                    continue
                data = await r.json()
            items = data.get("data") if isinstance(data, dict) else data
            rows = _parse(items or [])
            if rows:
                return rows
        except Exception:
            continue

    for path in ("/api/s/default/list/clients", "/proxy/network/api/s/default/list/clients"):
        try:
            async with session.get(f"{base}{path}", headers=headers, cookies=cookies, timeout=timeout, ssl=verify_ssl) as r:
                if r.status != 200:
                    continue
                data = await r.json()
            items = data.get("data") if isinstance(data, dict) else data
            rows = _parse(items or [])
            if rows:
                return rows
        except Exception:
            continue

    return []

def _parse(items: list) -> List[Dict[str, Any]]:
    devices: List[Dict[str, Any]] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue

        mac = (it.get("mac") or "").upper()
        ip = str(it.get("ip") or "")
        host = it.get("hostname") or it.get("name") or it.get("device_name") or ""
        oui  = it.get("oui") or ""

        # Skip entries that have neither MAC nor IP
        if not mac and not ip:
            continue

        # Provider-specific enrichment straight from UniFi payload
        uni = {
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
            # Useful when the client is wired
            "sw_mac": it.get("sw_mac") or "",
            "sw_port": it.get("sw_port"),
            "last_seen_ts": sta.get("last_seen"),
            "first_seen_ts": sta.get("first_seen"),
        }

        device = {
            "mac": mac,
            "ip": ip,
            "hostname": host,
            "vendor": oui,          # top-level vendor = UniFi's OUI if present
            "source": "unifi",
            "unifi": uni,           # keep all UniFi specifics namespaced
        }
        devices.append(device)

    return devices

