
from __future__ import annotations

from typing import Any, Dict, List

from aiohttp import ClientTimeout, ClientSession


class AdGuardDHCPClient:
    def __init__(self, session: ClientSession, base_url: str, name: str, password: str) -> None:
        self._session = session
        self._base = base_url.rstrip("/")
        self._name = name or "admin"
        self._password = password or ""
        self._token: str | None = None

    async def _ensure_login(self) -> None:
        if self._token:
            return
        timeout = ClientTimeout(total=3)
        async with self._session.post(f"{self._base}/control/login", json={"name": self._name, "password": self._password}, timeout=timeout) as resp:
            resp.raise_for_status()
            data = await resp.json()
            self._token = data.get("token")

    async def _get_json(self, path: str) -> dict:
        timeout = ClientTimeout(total=3)
        headers = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        async with self._session.get(f"{self._base}{path}", headers=headers, timeout=timeout) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def async_get_clients(self) -> List[Dict[str, Any]]:
        try:
            await self._ensure_login()
        except Exception:
            self._token = None

        paths = ["/control/dhcp/status", "/control/dhcp/leases"]
        devices: List[Dict[str, Any]] = []
        for p in paths:
            try:
                data = await self._get_json(p)
                devices = self._parse_dhcp(data)
                if devices:
                    return devices
            except Exception:
                continue

        try:
            data = await self._get_json("/control/clients")
            return self._parse_clients(data)
        except Exception:
            return []

    def _parse_dhcp(self, data: dict) -> List[Dict[str, Any]]:
        rows = []
        items = data.get("leases") or data.get("static_leases") or (data if isinstance(data, list) else [])
        if not isinstance(items, list):
            items = (data.get("leases") or []) + (data.get("static_leases") or [])
        for it in items:
            mac = (it.get("mac") or it.get("hw_address") or "").upper()
            ip = it.get("ip") or it.get("address") or ""
            host = it.get("hostname") or it.get("name") or ""
            rows.append({
                "mac": mac,
                "ip": ip,
                "hostname": host,
                "vendor": "",
                "source": "adguard",
            })
        return rows

    def _parse_clients(self, data: dict) -> List[Dict[str, Any]]:
        rows = []
        items = data.get("clients") or []
        for it in items:
            mac = (it.get("ids", [""])[0] or "").upper()
            ip = (it.get("ip", [""]) or [""])[0]
            host = it.get("name") or ""
            rows.append({
                "mac": mac,
                "ip": ip,
                "hostname": host,
                "vendor": "",
                "source": "adguard",
            })
        return rows
