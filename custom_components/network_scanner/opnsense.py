# custom_components/network_scanner/opnsense.py
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Iterable, Optional

from aiohttp import BasicAuth, ClientError, ClientTimeout
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


def _clean_mac(s: Optional[str]) -> str:
    """Normalise MACs and drop bogus/incomplete values."""
    m = (s or "").upper()
    if not m or m == "*" or m.replace(":", "") == "000000000000":
        return ""
    if m in ("(INCOMPLETE)", "INCOMPLETE"):
        return ""
    return m if _MAC_RE.match(m) else ""


class OPNsenseARPClient:
    """
    Forgiving ARP/ND fetcher for OPNsense.

    Primary path (preferred):
      POST /api/diagnostics/interface/search_arp[ / ]
      form: current=1,rowCount=9999,searchPhrase="",[interface=<iface>]

    Fallbacks (GET), shapes vary per image/plugin:
      /api/diagnostics/arp/search
      /api/diagnostics/arp
      /api/diagnostics/interface/getArp
      /api/diagnostics/if/arp
      /api/diagnostics/neighbor/search
      /api/routes/neighbor
    """

    def __init__(
        self,
        base_url: str,
        key: str,
        secret: str,
        verify_tls: bool = False,
        timeout: int = 10,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.key = key or ""
        self.secret = secret or ""
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)
        self._auth = BasicAuth(self.key, self.secret)

        self._fallbacks: Iterable[str] = (
            "/api/diagnostics/arp/search",
            "/api/diagnostics/arp",
            "/api/diagnostics/interface/getArp",
            "/api/diagnostics/if/arp",
            "/api/diagnostics/neighbor/search",
            "/api/routes/neighbor",
        )

    async def fetch_map(self, hass, interface: str | None = None) -> Dict[str, str]:
        """Return { ip: MAC } with cleaned UPPERCASE MACs, or {} on failure."""
        if not (self.base_url and self.key and self.secret):
            return {}

        session = async_get_clientsession(hass)

        # Preferred POST endpoint (with optional interface filter)
        for suffix in ("/api/diagnostics/interface/search_arp", "/api/diagnostics/interface/search_arp/"):
            url = f"{self.base_url}{suffix}"
            try:
                form = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
                if interface:
                    form["interface"] = interface
                async with session.post(
                    url,
                    auth=self._auth,
                    data=form,
                    timeout=self.timeout,
                    ssl=self.verify_tls,
                    headers={
                        "Accept": "application/json",
                        "X-Requested-With": "XMLHttpRequest",
                    },
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        raise RuntimeError(f"HTTP {resp.sta
