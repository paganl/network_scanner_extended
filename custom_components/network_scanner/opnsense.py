from __future__ import annotations

import logging
from typing import Any, Dict, List

from aiohttp import ClientSession, ClientTimeout, BasicAuth

_LOGGER = logging.getLogger(__name__)


def _first(d: dict, keys: list[str]) -> str:
    for k in keys:
        v = d.get(k)
        if v:
            return str(v)
    return ""


class OPNsenseARPClient:
    """
    POST-first ARP fetcher for OPNsense with robust fallbacks.
    - Tries POST /api/diagnostics/interface/search_arp (preferred)
    - Falls back to several GET endpoints seen across OPNsense versions
    """

    def __init__(
        self,
        session: ClientSession,
        base_url: str,
        key: str,
        secret: str,
        verify_ssl: bool = True,
        timeout_s: int = 4,
    ) -> None:
        self._session = session
        self._base = (base_url or "").rstrip("/")
        self._auth = BasicAuth(key or "", secret or "")
        self._ssl = bool(verify_ssl)
        self._timeout = ClientTimeout(total=timeout_s)

        # GET fallbacks (mix of historical endpoints)
        self._get_candidates: List[str] = [
            "/diagnostics/interface/get_arp",
            "/diagnostics/arp/get_arp",
            "/diagnostics/arp/search",
            "/diagnostics/arp",
            "/diagnostics/interface/getArp",
            "/diagnostics/if/arp",
            "/diagnostics/neighbor/search",
            "/routes/neighbor",
        ]

    def _build_url(self, path: str) -> str:
        # Ensure exactly one /api in the final URL
        base = self._base
        if not base.endswith("/api"):
            base = f"{base}/api"
        return f"{base}{path}"

    async def _post_json(self, path: str, data: Dict[str, Any]) -> dict:
        url = self._build_url(path)
        headers = {
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        async with self._session.post(
            url,
            auth=self._auth,
            data=data,                 # form-encoded, matches OPNsense UI calls
            headers=headers,
            timeout=self._timeout,
            ssl=self._ssl,
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                _LOGGER.debug("OPNsense POST %s -> HTTP %s body=%s", url, resp.status, text[:256])
            resp.raise_for_status()
            try:
                return await resp.json()
            except Exception:
                _LOGGER.debug("OPNsense POST %s returned non-JSON: %s", url, text[:256])
                raise

    async def _get_json(self, path: str) -> dict:
        url = self._build_url(path)
        headers = {"Accept": "application/json"}
        async with self._session.get(
            url,
            auth=self._auth,
            headers=headers,
            timeout=self._timeout,
            ssl=self._ssl,
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                _LOGGER.debug("OPNsense GET %s -> HTTP %s body=%s", url, resp.status, text[:256])
            resp.raise_for_status()
            try:
                return await resp.json()
            except Exception:
                _LOGGER.debug("OPNsense GET %s returned non-JSON: %s", url, text[:256])
                raise

    async def async_get_arp(self) -> List[Dict[str, Any]]:
        # 1) Preferred POST (modern, stable shape)
        post_paths = [
            "/diagnostics/interface/search_arp",
            "/diagnostics/interface/search_arp/",
        ]
        payload = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
        for p in post_paths:
            try:
                data = await self._post_json(p, payload)
                rows = self._parse_any_rows(data)
                if rows:
                    _LOGGER.debug("OPNsense ARP: parsed %d entries from POST %s", len(rows), p)
                    return rows
            except Exception as exc:
                _LOGGER.debug("OPNsense ARP: POST %s unusable: %s", p, exc)

        # 2) GET fallbacks (versions vary wildly)
        for p in self._get_candidates:
            try:
                data = await self._get_json(p)
                rows = self._parse_any_rows(data)
                if rows:
                    _LOGGER.debug("OPNsense ARP: parsed %d entries from GET %s", len(rows), p)
                    return rows
            except Exception as exc:
                _LOGGER.debug("OPNsense ARP: GET %s unusable: %s", p, exc)

        _LOGGER.warning("All OPNsense ARP endpoints failed or returned no rows")
        return []

    # ---------- parsing ----------

    def _parse_any_rows(self, data: Any) -> List[Dict[str, Any]]:
        """
        Accept multiple JSON shapes and return a list of {mac, ip, hostname, ...}.
        Supports:
          - {"rows":[{...}]}, {"data":[{...}]}, {"arp":[{...}]}, nested dicts
          - flat lists of dicts or lists
        """
        if isinstance(data, list):
            return self._parse_list_of_dicts(data) or self._parse_list_of_lists(data)

        if isinstance(data, dict):
            # common containers
            for key in ("rows", "data", "arp", "neighbors", "neighbours", "entries", "items", "result"):
                sub = data.get(key)
                if isinstance(sub, list):
                    out = self._parse_list_of_dicts(sub) or self._parse_list_of_lists(sub)
                    if out:
                        return out
            # nested scan
            for _, val in data.items():
                if isinstance(val, (dict, list)):
                    out = self._parse_any_rows(val)
                    if out:
                        return out
        return []

    def _parse_list_of_dicts(self, rows: list) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = _first(row, ["ip", "ipaddr", "ipaddress", "address", "inet"])
            mac = _first(row, ["mac", "macaddr", "lladdr", "ether", "hwaddr"])
            host = _first(row, ["hostname", "fqdn", "name"])
            mac_u = (mac or "").upper()
            if mac_u in ("", "(INCOMPLETE)", "00:00:00:00:00:00", "*"):
                continue
            if ip and mac_u:
                out.append({
                    "mac": mac_u,
                    "ip": ip,
                    "hostname": host,
                    "vendor": "",
                    "source": "opnsense",
                })
        return out

    def _parse_list_of_lists(self, rows: list) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in rows:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                ip = str(item[0])
                mac_u = str(item[1]).upper()
                if mac_u in ("", "(INCOMPLETE)", "00:00:00:00:00:00", "*"):
                    continue
                out.append({
                    "mac": mac_u,
                    "ip": ip,
                    "hostname": "",
                    "vendor": "",
                    "source": "opnsense",
                })
        return out
