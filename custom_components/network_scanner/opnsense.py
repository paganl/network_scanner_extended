# custom_components/network_scanner/opnsense.py
from __future__ import annotations
from typing import Dict, Any, Iterable
import json
import logging

from aiohttp import ClientError, ClientTimeout, BasicAuth
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

def _clean_mac(s: str | None) -> str:
    m = (s or "").upper()
    if not m or m in ("(INCOMPLETE)", "00:00:00:00:00:00", "*"):
        return ""
    return m

class OPNsenseARPClient:
    """
    Very forgiving ARP/ND fetcher for OPNsense.
    Tries the modern POST /api/diagnostics/interface/search_arp first,
    then a handful of GET fallbacks seen in the wild.
    """

    def __init__(self, base_url: str, key: str, secret: str, verify_tls: bool = True, timeout: int = 10) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.key = key or ""
        self.secret = secret or ""
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)
        self._auth = BasicAuth(self.key, self.secret)

        # GET fallback candidates (shape differs by image/version)
        self._get_candidates: Iterable[str] = (
            "/api/diagnostics/arp/search",
            "/api/diagnostics/arp",
            "/api/diagnostics/interface/getArp",
            "/api/diagnostics/if/arp",
            "/api/diagnostics/neighbor/search",
            "/api/routes/neighbor",
        )

    async def fetch_map(self, hass) -> Dict[str, str]:
        """Return { ip: MAC } with MAC uppercased, or {} on failure."""
        if not self.base_url or not self.key or not self.secret:
            return {}

        # Prefer the POST interface because it supports filtering and stable JSON.
        post_paths = (
            "/api/diagnostics/interface/search_arp",
            "/api/diagnostics/interface/search_arp/",
        )

        session = async_get_clientsession(hass, verify_ssl=self.verify_tls)

        payload = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}

        # Try POST first
        for path in post_paths:
            url = f"{self.base_url}{path}"
            try:
                async with session.post(
                    url, auth=self._auth, data=payload, timeout=self.timeout, headers=headers
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        raise RuntimeError(f"HTTP {resp.status}: {text[:200]!r}")
                    data = json.loads(text)
                    mapping = self._parse_any(data)
                    if mapping:
                        _LOGGER.debug("OPNsense ARP: parsed %d entries from %s", len(mapping), path)
                        return mapping
            except (ClientError, json.JSONDecodeError, RuntimeError) as exc:
                _LOGGER.debug("OPNsense ARP: POST %s unusable: %s", path, exc)
            except Exception as exc:
                _LOGGER.debug("OPNsense ARP: POST %s unexpected: %s", path, exc)

        # Fallback to several GET endpoints
        for path in self._get_candidates:
            url = f"{self.base_url}{path}"
            try:
                async with session.get(url, auth=self._auth, timeout=self.timeout, headers=headers) as resp:
                    if resp.status >= 400:
                        continue
                    text = await resp.text()
                data = json.loads(text)
                mapping = self._parse_any(data)
                if mapping:
                    _LOGGER.debug("OPNsense ARP: parsed %d entries from %s", len(mapping), path)
                    return mapping
            except (ClientError, json.JSONDecodeError) as exc:
                _LOGGER.debug("OPNsense ARP: GET %s unusable: %s", path, exc)
            except Exception as exc:
                _LOGGER.debug("OPNsense ARP: GET %s unexpected: %s", path, exc)

        _LOGGER.warning("OPNsense ARP: no usable endpoint at %s", self.base_url)
        return {}

    # ---------------- parsing helpers ----------------

    def _parse_any(self, data: Any) -> Dict[str, str]:
        """
        Accept a variety of JSON shapes and return {ip: MAC}.
        Supports:
          - {"rows":[{...}]}
          - {"data":[{...}]}
          - flat lists of dicts or lists
          - nested dicts containing such lists
        """
        if isinstance(data, list):
            return self._parse_list_of_dicts(data) or self._parse_list_of_lists(data)

        if isinstance(data, dict):
            for key in ("rows", "data", "arp", "neighbors", "neighbours", "entries"):
                sub = data.get(key)
                if isinstance(sub, list):
                    m = self._parse_list_of_dicts(sub) or self._parse_list_of_lists(sub)
                    if m:
                        return m
            # Nested structures
            for _, val in data.items():
                if isinstance(val, (dict, list)):
                    m = self._parse_any(val)
                    if m:
                        return m

        return {}

    def _parse_list_of_dicts(self, rows: list) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = row.get("ip") or row.get("ipaddr") or row.get("ipaddress") or row.get("address") or row.get("inet") or ""
            mac = row.get("mac") or row.get("macaddr") or row.get("lladdr") or row.get("ether") or row.get("hwaddr") or ""
            mac = _clean_mac(mac)
            if ip and mac and mac != "(INCOMPLETE)":
                out[str(ip)] = mac
        return out

    def _parse_list_of_lists(self, rows: list) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for item in rows:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                ip, mac = str(item[0]), _clean_mac(str(item[1]))
                if ip and mac:
                    out[ip] = mac
        return out
