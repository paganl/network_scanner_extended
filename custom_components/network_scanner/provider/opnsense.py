
from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List

from aiohttp import ClientTimeout, ClientSession

_LOGGER = logging.getLogger(__name__)


class OPNsenseARPClient:
    def __init__(self, session: ClientSession, base_url: str, key: str, secret: str) -> None:
        self._session = session
        self._base = base_url.rstrip("/")
        auth_raw = f"{key}:{secret}".encode()
        self._auth = base64.b64encode(auth_raw).decode()

    async def _get_json(self, path: str) -> dict:
        url = f"{self._base}{path}"
        timeout = ClientTimeout(total=3)
        headers = {"Authorization": f"Basic {self._auth}"}
        async with self._session.get(url, headers=headers, timeout=timeout) as resp:
            text = await resp.text()
            resp.raise_for_status()
            try:
                return await resp.json()
            except Exception:
                _LOGGER.debug("OPNsense GET %s returned non-JSON: %s", url, text[:200])
                raise

    async def async_get_arp(self) -> List[Dict[str, Any]]:
        paths = [
            "/api/diagnostics/arp/search_arp",
            "/api/diagnostics/interface/search_arp",
            "/api/diagnostics/arp/get_arp",
            "/api/diagnostics/interface/get_arp",
            "/api/diagnostics/arp/searchArp",
            "/api/diagnostics/interface/searchArp",
            "/api/diagnostics/arp/getArp",
            "/api/diagnostics/interface/getArp",
        ]
        for p in paths:
            try:
                data = await self._get_json(p)
                rows = self._parse(data)
                if rows:
                    return rows
            except Exception:
                continue
        _LOGGER.warning("All OPNsense ARP endpoints failed or returned no rows")
        return []

    def _parse(self, data: dict) -> List[Dict[str, Any]]:
        rows_out: List[Dict[str, Any]] = []
        items = (
            data.get("rows")
            or data.get("data")
            or data.get("arp")
            or data.get("items")
            or data.get("result")
            or []
        )
        if isinstance(items, dict):
            items = items.get("rows", [])
        if not isinstance(items, list):
            return []

        def _first(d: dict, keys: list[str]) -> str:
            for k in keys:
                v = d.get(k)
                if v:
                    return str(v)
            return ""

        for it in items:
            if not isinstance(it, dict):
                continue
            mac = _first(it, ["mac", "macaddr", "lladdr", "ether"])
            ip = _first(it, ["ip", "ipaddr", "inet", "address", "ip-address", "ip_address"])
            host = _first(it, ["hostname", "fqdn", "name"])
            if not mac and ip:
                mac = f"IP:{ip}"
            rows_out.append({
                "mac": (mac or "").upper(),
                "ip": ip,
                "hostname": host,
                "vendor": "",
                "source": "opnsense",
            })
        return rows_out
