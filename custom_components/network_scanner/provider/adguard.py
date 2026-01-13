from __future__ import annotations

import logging
import re
import ipaddress
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession, ClientTimeout, BasicAuth

_LOGGER = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", re.IGNORECASE)


def _is_mac(s: Optional[str]) -> bool:
    return bool(s and _MAC_RE.match(s.strip()))


def _clean_mac(s: Optional[str]) -> str:
    """Normalise MAC and reject junk."""
    m = (s or "").strip().upper()
    if not m:
        return ""
    if m in ("*", "(INCOMPLETE)", "INCOMPLETE"):
        return ""
    if m.replace(":", "") == "000000000000":
        return ""
    return m if _MAC_RE.match(m) else ""


def _is_ip(s: Optional[str]) -> bool:
    if not s:
        return False
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


async def async_get_devices(
    session: ClientSession,
    base_url: str,
    username: str = "",
    password: str = "",
    verify_ssl: bool = True,
    timeout_s: int = 6,
) -> List[Dict[str, Any]]:
    """Return devices from AdGuard Home (DHCP + Clients)."""

    if not base_url:
        return []

    base = base_url.rstrip("/")
    tmo = ClientTimeout(total=timeout_s)

    # Optional BasicAuth only for reverse-proxy setups; AdGuard itself usually doesn’t need it.
    proxy_auth = BasicAuth(username, password) if username and password else None

    token: Optional[str] = None

    # Try login -> token (fine if it fails; many installs block /control/login)
    try:
        payload = {"name": username or "admin", "password": password or ""}
        async with session.post(
            f"{base}/control/login",
            json=payload,
            timeout=tmo,
            ssl=verify_ssl,
            auth=proxy_auth,
        ) as r:
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

    # DHCP leases
    for path in ("/control/dhcp/leases", "/control/dhcp/status"):
        try:
            async with session.get(
                f"{base}{path}",
                headers=headers,
                timeout=tmo,
                ssl=verify_ssl,
                auth=proxy_auth,
            ) as r:
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

    # Clients
    try:
        async with session.get(
            f"{base}/control/clients",
            headers=headers,
            timeout=tmo,
            ssl=verify_ssl,
            auth=proxy_auth,
        ) as r:
            if r.status == 200:
                data = await r.json()
                clients = _parse_clients(data)
            else:
                _LOGGER.debug("AdGuard GET /control/clients -> HTTP %s", r.status)
    except Exception as exc:
        _LOGGER.debug("AdGuard GET /control/clients failed: %s", exc)

    # Merge: key by MAC if possible else IP
    by_key: Dict[str, Dict[str, Any]] = {}

    def _key(mac: str, ip: str) -> str:
        mac = _clean_mac(mac)
        if mac:
            return mac
        ip = (ip or "").strip()
        return f"IP:{ip}" if ip else ""

    # Start with clients (often includes name even without DHCP)
    for d in clients:
        mac = _clean_mac(d.get("mac"))
        ip = (d.get("ip") or "").strip()
        k = _key(mac, ip)
        if not k:
            continue

        by_key.setdefault(k, {
            "mac": mac,
            "ip": ip,
            "hostname": d.get("hostname") or "",
            "vendor": "",
            "dhcp": {"server": "adguard", "lease_ip": "", "reservation_ip": ""},
            "adguard": {"from": "clients"},
            "source": "adguard",
        })

        # Fill hostname if empty
        if d.get("hostname") and not by_key[k].get("hostname"):
            by_key[k]["hostname"] = d["hostname"]

        # Keep a tiny raw slice (safe)
        by_key[k]["adguard"]["client_name"] = d.get("hostname") or ""

    # Overlay leases (prefer lease IP/hostname)
    for d in leases:
        mac = _clean_mac(d.get("mac"))
        ip = (d.get("ip") or "").strip()
        k = _key(mac, ip)
        if not k:
            continue

        cur = by_key.get(k) or {
            "mac": mac,
            "ip": ip,
            "hostname": "",
            "vendor": "",
            "dhcp": {"server": "adguard", "lease_ip": "", "reservation_ip": ""},
            "adguard": {"from": "dhcp"},
            "source": "adguard",
        }

        if ip:
            cur["ip"] = ip
            cur["dhcp"]["lease_ip"] = ip

        host = d.get("hostname") or ""
        if host:
            cur["hostname"] = host

        cur["mac"] = mac  # ensure cleaned
        # keep "clients" if we already have it; otherwise mark as dhcp
        cur.setdefault("adguard", {})
        if cur["adguard"].get("from") != "clients":
            cur["adguard"]["from"] = "dhcp"

        by_key[k] = cur

    out: List[Dict[str, Any]] = []
    for v in by_key.values():
        out.append({
            "mac": _clean_mac(v.get("mac")),
            "ip": (v.get("ip") or "").strip(),
            "hostname": v.get("hostname") or "",
            "vendor": v.get("vendor") or "",
            "dhcp": v.get("dhcp") or {"server": "adguard", "lease_ip": "", "reservation_ip": ""},
            "adguard": v.get("adguard") or {},
            "source": "adguard",
        })

    _LOGGER.info(
        "AdGuard parsed %d DHCP leases, %d clients, %d merged devices",
        len(leases),
        len(clients),
        len(out),
    )
    return out


def _parse_dhcp(data: Any) -> List[Dict[str, Any]]:
    """Parse /control/dhcp/leases or /control/dhcp/status payloads."""
    out: List[Dict[str, Any]] = []
    items: List[Any] = []

    if isinstance(data, dict):
        if isinstance(data.get("leases"), list):
            items += data.get("leases") or []
        if isinstance(data.get("static_leases"), list):
            items += data.get("static_leases") or []
        if not items and isinstance(data.get("data"), list):
            items = data["data"]
    elif isinstance(data, list):
        items = data

    for it in items:
        if not isinstance(it, dict):
            continue
        mac = _clean_mac(it.get("mac") or it.get("hw_address"))
        ip = str(it.get("ip") or it.get("address") or it.get("ip_address") or "").strip()
        host = str(it.get("hostname") or it.get("name") or "").strip()
        if mac or ip:
            out.append({"mac": mac, "ip": ip, "hostname": host})
    return out


def _parse_clients(data: Any) -> List[Dict[str, Any]]:
    """Parse /control/clients, picking MAC/IP from ids where possible."""
    out: List[Dict[str, Any]] = []
    items: List[Any] = []

    if isinstance(data, dict):
        items = data.get("clients") or data.get("data") or []
    elif isinstance(data, list):
        items = data

    for it in items:
        if not isinstance(it, dict):
            continue

        mac = ""
        ip = ""

        ids = it.get("ids") or []
        if isinstance(ids, list):
            for ident in ids:
                s = str(ident).strip()
                if not mac and _is_mac(s):
                    mac = _clean_mac(s)
                elif not ip and _is_ip(s):
                    ip = s
                if mac and ip:
                    break

        # Some versions also provide ip directly
        raw_ip = it.get("ip")
        if not ip:
            if isinstance(raw_ip, list) and raw_ip:
                ip = str(raw_ip[0]).strip()
            elif isinstance(raw_ip, str):
                ip = raw_ip.strip()

        host = (it.get("name") or it.get("hostname") or "").strip()

        if mac or ip:
            out.append({"mac": mac, "ip": ip, "hostname": host})

    return out
