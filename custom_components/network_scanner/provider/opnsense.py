"""OPNsense provider for the Network Scanner integration.

Fetches ARP/ND data from the OPNsense diagnostics API, preferring:
  POST /api/diagnostics/interface/search_arp

Falls back to several GET endpoints for older firmware.

Returns a list of normalised device dicts:
  mac, ip, hostname, vendor, opnsense={...}
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession, ClientTimeout, BasicAuth

_LOGGER = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", re.IGNORECASE)


def _looks_like_html(content_type: Optional[str], body: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    t = (body or "").lstrip().lower()
    return t.startswith("<!doctype") or t.startswith("<html")


def _get_first(d: Dict[str, Any], keys: List[str], default: str = "") -> str:
    for key in keys:
        v = d.get(key)
        if v is not None and v != "":
            return str(v)
    return default


def _clean_mac(s: Optional[str]) -> str:
    m = (s or "").strip().upper()
    if not m:
        return ""
    if m in ("*", "(INCOMPLETE)", "INCOMPLETE"):
        return ""
    if m.replace(":", "") == "000000000000":
        return ""
    return m if _MAC_RE.match(m) else ""


def _as_float(v: Any) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class OPNsenseARPClient:
    def __init__(
        self,
        session: ClientSession,
        base_url: str,
        key: str,
        secret: str,
        *,
        verify_ssl: bool = True,
        timeout_s: int = 6,
    ) -> None:
        self._session = session
        self._base = (base_url or "").rstrip("/")
        self._auth = BasicAuth(key or "", secret or "")
        self._ssl = bool(verify_ssl)
        self._timeout = ClientTimeout(total=timeout_s)

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
        base = self._base
        if not base.endswith("/api"):
            base = f"{base}/api"
        return f"{base}{path}"

    async def _post_json(self, path: str, data: Dict[str, Any]) -> Optional[Any]:
        url = self._build_url(path)
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        async with self._session.post(
            url,
            auth=self._auth,
            data=data,  # OPNsense expects form-like payload here
            headers=headers,
            timeout=self._timeout,
            ssl=self._ssl,
        ) as resp:
            text = await resp.text()
            if _looks_like_html(resp.headers.get("Content-Type"), text):
                _LOGGER.debug("OPNsense POST %s returned HTML (likely login page).", url)
                return None
            if resp.status >= 400:
                _LOGGER.debug("OPNsense POST %s HTTP %s: %.256s", url, resp.status, text)
                return None
            try:
                return await resp.json(content_type=None)
            except Exception:
                _LOGGER.debug("OPNsense POST %s non-JSON: %.256s", url, text)
                return None

    async def _get_json(self, path: str) -> Optional[Any]:
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
            if _looks_like_html(resp.headers.get("Content-Type"), text):
                _LOGGER.debug("OPNsense GET %s returned HTML (likely login page).", url)
                return None
            if resp.status >= 400:
                _LOGGER.debug("OPNsense GET %s HTTP %s: %.256s", url, resp.status, text)
                return None
            try:
                return await resp.json(content_type=None)
            except Exception:
                _LOGGER.debug("OPNsense GET %s non-JSON: %.256s", url, text)
                return None

    async def async_get_devices(self) -> List[Dict[str, Any]]:
        payload = {"current": 1, "rowCount": 9999, "searchPhrase": ""}

        for path in ("/diagnostics/interface/search_arp", "/diagnostics/interface/search_arp/"):
            try:
                data = await self._post_json(path, payload)
            except Exception as exc:
                _LOGGER.debug("OPNsense POST %s raised: %s", path, exc)
                data = None
            if data:
                devices = self._parse_any_rows(data)
                if devices:
                    _LOGGER.debug("OPNsense ARP: %d entries from POST %s", len(devices), path)
                    return devices

        for path in self._get_candidates:
            try:
                data = await self._get_json(path)
            except Exception as exc:
                _LOGGER.debug("OPNsense GET %s raised: %s", path, exc)
                data = None
            if data:
                devices = self._parse_any_rows(data)
                if devices:
                    _LOGGER.debug("OPNsense ARP: %d entries from GET %s", len(devices), path)
                    return devices

        _LOGGER.warning("OPNsense ARP: all endpoints failed or returned no rows")
        return []

    def _parse_any_rows(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return self._parse_list_of_dicts(data) or self._parse_list_of_lists(data)

        if isinstance(data, dict):
            for key in ("rows", "data", "arp", "neighbors", "neighbours", "entries", "items", "result"):
                sub = data.get(key)
                if isinstance(sub, list):
                    got = self._parse_list_of_dicts(sub) or self._parse_list_of_lists(sub)
                    if got:
                        return got
            for v in data.values():
                if isinstance(v, (dict, list)):
                    got = self._parse_any_rows(v)
                    if got:
                        return got
        return []

    def _parse_list_of_dicts(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []

        for row in rows:
            if not isinstance(row, dict):
                continue

            ip = _get_first(row, ["ip", "ipaddr", "ipaddress", "address", "inet", "addr"]).strip()
            mac = _clean_mac(_get_first(row, ["mac", "macaddr", "lladdr", "ether", "hwaddr"]))
            if not ip or not mac:
                continue

            host = _get_first(row, ["hostname", "fqdn", "name"]).strip()
            vendor = _get_first(row, ["manufacturer", "vendor", "oui"]).strip()

            op_block = {
                "intf": (row.get("intf") or "").strip(),
                "intf_description": (row.get("intf_description") or row.get("description") or "").strip(),
                "arp_type": (row.get("type") or "").strip(),
                "arp_expired": bool(row.get("expired")) if "expired" in row else None,
                "arp_expires_s": _as_float(row.get("expires")),
                "arp_permanent": bool(row.get("permanent")) if "permanent" in row else None,
            }

            devices.append({
                "mac": mac,
                "ip": ip,
                "hostname": host,
                "vendor": vendor,
                "opnsense": op_block,
            })

        return devices

    def _parse_list_of_lists(self, rows: List[Any]) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []
        for item in rows:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
            ip = str(item[0]).strip()
            mac = _clean_mac(str(item[1]))
            if not ip or not mac:
                continue
            devices.append({
                "mac": mac,
                "ip": ip,
                "hostname": "",
                "vendor": "",
                "opnsense": {},
            })
        return devices


async def async_get_devices(
    session: ClientSession,
    base_url: str,
    key: str,
    secret: str,
    *,
    verify_ssl: bool = True,
    timeout_s: int = 6,
) -> List[Dict[str, Any]]:
    client = OPNsenseARPClient(
        session=session,
        base_url=base_url,
        key=key,
        secret=secret,
        verify_ssl=verify_ssl,
        timeout_s=timeout_s,
    )
    return await client.async_get_devices()
