from __future__ import annotations
import logging
import re
from typing import Any, Dict, List
from aiohttp import ClientSession, ClientTimeout

_LOGGER = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

def _is_mac(s: str | None) -> bool:
    return bool(s and _MAC_RE.match(s))

def _norm_mac(s: str | None) -> str:
    return (s or "").upper()

async def async_get_devices(
    session: ClientSession,
    base_url: str,
    username: str = "",
    password: str = "",
    verify_ssl: bool = True,
    timeout_s: int = 4,
) -> List[Dict[str, Any]]:
    """Return devices from AdGuard Home (DHCP + Clients).

    Tries bearer token login, but will gracefully continue without it if login
    is disabled. Parses both /control/dhcp/leases and /control/clients.
    """
    if not base_url:
        return []
    base = base_url.rstrip("/")
    tmo = ClientTimeout(total=timeout_s)

    token = None
    # Try to get a token; many setups have auth disabled so this can fail
    try:
        payload = {"name": username or "admin", "password": password or ""}
        async with session.post(f"{base}/control/login", json=payload, timeout=tmo, ssl=verify_ssl) as r:
            if r.status == 200:
                data = await r.json()
                token = (data or {}).get("token")
            else:
                _LOGGER.debug("AdGuard login returned HTTP %s", r.status)
    except Exception as exc:
        _LOGGER.debug("AdGuard login skipped/failed: %s", exc)

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    leases: List[Dict[str, Any]] = []
    clients: List[Dict[str, Any]] = []

    # Prefer direct leases endpoint; some versions also expose dhcp/status
    for path in ("/control/dhcp/leases", "/control/dhcp/status"):
        try:
            async with session.get(f"{base}{path}", headers=headers, timeout=tmo, ssl=verify_ssl) as r:
                if r.status != 200:
                    _LOGGER.debug("AdGuard GET %s -> HTTP %s", path, r.status)
                    continue
                data = await r.json()
            rows = _parse_dhcp(data)
            if rows:
                leases = rows
                break
        except Exception as exc:
            _LOGGER.debug("AdGuard GET %s failed: %s", path, exc)

    # Clients (can contain MACs even without DHCP service enabled)
    try:
        async with session.get(f"{base}/control/clients", headers=headers, timeout=tmo, ssl=verify_ssl) as r:
            if r.status == 200:
                data = await r.json()
                clients = _parse_clients(data)
            else:
                _LOGGER.debug("AdGuard GET /control/clients -> HTTP %s", r.status)
    except Exception as exc:
        _LOGGER.debug("AdGuard GET /control/clients failed: %s", exc)

    # Merge, preferring DHCP lease records over clients for IP/hostname
    by_mac: Dict[str, Dict[str, Any]] = {}

    for d in clients:
        mac = _norm_mac(d.get("mac"))
        if not mac and d.get("ip"):
            # allow IP-keyed entries if no MAC present
            by_mac.setdefault(f"IP:{d['ip']}", d)
            continue
        if mac:
            by_mac.setdefault(mac, d)

    for d in leases:
        mac = _norm_mac(d.get("mac"))
        key = mac or (f"IP:{d['ip']}" if d.get("ip") else None)
        if not key:
            continue
        cur = by_mac.get(key, {})
        # Prefer DHCP IP/hostname if present
        if d.get("ip"):
            cur["ip"] = d["ip"]
        if d.get("hostname"):
            cur["hostname"] = d["hostname"]
        # Ensure core fields
        cur["mac"] = mac
        cur["vendor"] = cur.get("vendor", "")  # AdGuard doesn't provide OUI
        cur["source"] = "adguard"
        by_mac[key] = cur

    # Normalise to list and ensure minimal shape
    out: List[Dict[str, Any]] = []
    for v in by_mac.values():
        out.append({
            "mac": _norm_mac(v.get("mac")),
            "ip": v.get("ip") or "",
            "hostname": v.get("hostname") or "",
            "vendor": v.get("vendor") or "",
            "source": "adguard",
            # keep a provider block if you later want to stash raw fields
            # "adguard": {...}
        })
    return out

def _parse_dhcp(data: Any) -> List[Dict[str, Any]]:
    """Parse /control/dhcp/leases or /control/dhcp/status payloads."""
    out: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        items = []
        # leases from /control/dhcp/leases
        if isinstance(data.get("leases"), list):
            items += data.get("leases") or []
        # static leases may appear in status
        if isinstance(data.get("static_leases"), list):
            items += data.get("static_leases") or []
        # some versions return directly a list under 'leases'
        if not items and isinstance(data.get("data"), list):
            items = data["data"]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    for it in items:
        if not isinstance(it, dict):
            continue
        mac = _norm_mac(it.get("mac") or it.get("hw_address"))
        ip = it.get("ip") or it.get("address") or it.get("ip_address") or ""
        host = it.get("hostname") or it.get("name") or ""
        if mac or ip:
            out.append({"mac": mac, "ip": str(ip), "hostname": host, "vendor": "", "source": "adguard"})
    return out

def _parse_clients(data: Any) -> List[Dict[str, Any]]:
    """Parse /control/clients, picking a real MAC from ids when available."""
    out: List[Dict[str, Any]] = []
    items = []
    if isinstance(data, dict):
        items = data.get("clients") or data.get("data") or []
    elif isinstance(data, list):
        items = data

    for it in items:
        if not isinstance(it, dict):
            continue
        ids = it.get("ids") or []
        mac = ""
        if isinstance(ids, list):
            # pick the first thing that looks like a MAC
            for ident in ids:
                if _is_mac(str(ident)):
                    mac = _norm_mac(ident)
                    break
        host = it.get("name") or it.get("hostname") or ""
        ip = ""
        # 'ip' can be a list or a string depending on version
        raw_ip = it.get("ip")
        if isinstance(raw_ip, list) and raw_ip:
            ip = str(raw_ip[0])
        elif isinstance(raw_ip, str):
            ip = raw_ip
        if mac or ip:
            out.append({"mac": mac, "ip": ip, "hostname": host, "vendor": "", "source": "adguard"})
    return out
