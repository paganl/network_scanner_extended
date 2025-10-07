# custom_components/network_scanner_extended/opnsense.py
from __future__ import annotations
from typing import Dict, Any, Iterable
import json
import logging

from aiohttp import ClientError, ClientTimeout, BasicAuth
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

class OPNsenseARPClient:
    """
    Very forgiving ARP/ND fetcher for OPNsense.
    Tries multiple likely endpoints and parses several shapes.
    """

    def __init__(self, base_url: str, key: str, secret: str, verify_tls: bool = True, timeout: int = 10) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.key = key or ""
        self.secret = secret or ""
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)

        # Most OPNsense installs use HTTP Basic with API key/secret
        self._auth = BasicAuth(self.key, self.secret)

        # Try a bunch of candidates — we accept whichever responds with parsable JSON
        self._candidates: Iterable[str] = (
            "/api/diagnostics/arp/search",      # common
            "/api/diagnostics/arp",             # some builds
            "/api/diagnostics/interface/getArp",# older/core variants
            "/api/diagnostics/if/arp",          # alt path
            "/api/diagnostics/neighbor/search", # ND on newer
            "/api/routes/neighbor",             # fallback on some images
        )

    async def fetch_map(self, hass) -> Dict[str, str]:
        """Return { ip: MAC } with MAC in UPPERCASE, or {} on failure."""
        if not self.base_url or not self.key or not self.secret:
            return {}

        session = async_get_clientsession(hass, verify_ssl=self.verify_tls)
        for path in self._candidates:
            url = f"{self.base_url}{path}"
            try:
                async with session.get(url, auth=self._auth, timeout=self.timeout) as resp:
                    if resp.status >= 400:
                        continue
                    text = await resp.text()
                data = json.loads(text)
                mapping = self._parse_any(data)
                if mapping:
                    _LOGGER.debug("OPNsense ARP: parsed %d entries from %s", len(mapping), path)
                    return mapping
            except (ClientError, json.JSONDecodeError) as exc:
                _LOGGER.debug("OPNsense ARP: endpoint %s not usable: %s", path, exc)
            except Exception as exc:
                _LOGGER.debug("OPNsense ARP: unexpected at %s: %s", path, exc)
        _LOGGER.warning("OPNsense ARP: no usable endpoint returned data at %s", self.base_url)
        return {}

    # ---------------- parsing helpers ----------------

    @staticmethod
    def _norm_mac(mac: str | None) -> str:
        return (mac or "").upper()

    def _parse_any(self, data: Any) -> Dict[str, str]:
        """Accept a variety of JSON shapes."""
        # Direct list
        if isinstance(data, list):
            return self._parse_list_of_dicts(data) or self._parse_list_of_lists(data)

        if isinstance(data, dict):
            # rows/data/arp/neighbor common keys
            for key in ("rows", "data", "arp", "neighbors", "neighbours"):
                if key in data:
                    sub = data.get(key)
                    if isinstance(sub, list):
                        m = self._parse_list_of_dicts(sub) or self._parse_list_of_lists(sub)
                        if m:
                            return m

            # Sometimes ARP table is nested deeper
            for key, val in data.items():
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
            ip = row.get("ip") or row.get("ipaddr") or row.get("ipaddress") or row.get("address") or ""
            mac = row.get("mac") or row.get("macaddr") or row.get("lladdr") or row.get("ether") or ""
            if ip and mac and mac != "(incomplete)":
                out[str(ip)] = self._norm_mac(str(mac))
        return out

    def _parse_list_of_lists(self, rows: list) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for item in rows:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                ip, mac = str(item[0]), str(item[1])
                if ip and mac and mac != "(incomplete)":
                    out[ip] = self._norm_mac(mac)
        return out
