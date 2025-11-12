from __future__ import annotations
from typing import Any, Dict, List
from aiohttp import ClientSession, ClientTimeout

async def async_get_devices(
    session: ClientSession,
    base_url: str,
    username: str,
    password: str,
    verify_ssl: bool = True,
    timeout_s: int = 4,
) -> List[Dict[str, Any]]:
    if not base_url:
        return []
    base = base_url.rstrip("/")
    tmo = ClientTimeout(total=timeout_s)

    token = None
    try:
        async with session.post(f"{base}/control/login", json={"name": username or "admin", "password": password or ""}, timeout=tmo, ssl=verify_ssl) as r:
            r.raise_for_status()
            data = await r.json()
            token = data.get("token")
    except Exception:
        token = None

    headers = {"Authorization": f"Bearer {token}"} if token else {}

    for path in ("/control/dhcp/status", "/control/dhcp/leases"):
        try:
            async with session.get(f"{base}{path}", headers=headers, timeout=tmo, ssl=verify_ssl) as r:
                r.raise_for_status()
                data = await r.json()
            rows = _parse_dhcp(data)
            if rows:
                return rows
        except Exception:
            continue

    try:
        async with session.get(f"{base}/control/clients", headers=headers, timeout=tmo, ssl=verify_ssl) as r:
            r.raise_for_status()
            data = await r.json()
        return _parse_clients(data)
    except Exception:
        return []

def _parse_dhcp(data: dict) -> List[Dict[str, Any]]:
    out=[]
    items = data.get("leases") or data.get("static_leases") or (data if isinstance(data, list) else [])
    if not isinstance(items, list):
        items = (data.get("leases") or []) + (data.get("static_leases") or [])
    for it in items:
        mac=(it.get("mac") or it.get("hw_address") or "").upper()
        ip = it.get("ip") or it.get("address") or ""
        host= it.get("hostname") or it.get("name") or ""
        if mac or ip: out.append({"mac":mac,"ip":ip,"hostname":host,"vendor":"","source":"adguard"})
    return out

def _parse_clients(data: dict) -> List[Dict[str, Any]]:
    out=[]; items=data.get("clients") or []
    for it in items:
        mac=(it.get("ids",[""])[0] or "").upper()
        ip =(it.get("ip",[""]) or [""])[0]
        host=it.get("name") or ""
        if mac or ip: out.append({"mac":mac,"ip":ip,"hostname":host,"vendor":"","source":"adguard"})
    return out
