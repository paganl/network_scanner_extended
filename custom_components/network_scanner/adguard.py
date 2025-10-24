# custom_components/network_scanner/adguard.py
from __future__ import annotations
from typing import Dict, Any, Optional
import logging
import json

from aiohttp import ClientError, ClientTimeout, BasicAuth
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

def _uc(s: str | None) -> str:
    return (s or "").upper()

class AdGuardDHCPClient:
    """
    Minimal AdGuard Home client using Basic Auth (no cookie login):
      • GET /control/dhcp/leases        → [ { ip, mac, hostname? }, ... ]  (if supported)
      • GET /control/dhcp/status        → { leases: [...], static_leases: [...] } (fallback)
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool = True,
        timeout: int = 10,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.username = username or ""
        self.password = password or ""
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)
        self._auth: Optional[BasicAuth] = (
            BasicAuth(self.username, self.password) if (self.username and self.password) else None
        )

    async def _get_json(self, hass, path: str) -> Any:
        """GET JSON from AGH with Basic Auth."""
        if not self.base_url:
            return None
        session = async_get_clientsession(hass, verify_ssl=self.verify_tls)
        url = f"{self.base_url}{path}"
        try:
            async with session.get(url, auth=self._auth, timeout=self.timeout) as resp:
                txt = await resp.text()
                if resp.status >= 400:
                    _LOGGER.warning("AdGuard request failed %s → %s: %s", path, resp.status, txt[:200])
                    return None
                # Prefer JSON decode; fall back to text if content-type is off
                try:
                    return json.loads(txt)
                except json.JSONDecodeError:
                    return None
        except ClientError as exc:
            _LOGGER.warning("AdGuard request error for %s: %s", url, exc)
            return None

    async def fetch_map(self, hass) -> Dict[str, str]:
        """
        Return { ip: MAC } from DHCP leases (uppercased MACs).
        Tries /control/dhcp/leases first, falls back to /control/dhcp/status.
        """
        # 1) Try explicit leases endpoint (some builds expose this)
        data = await self._get_json(hass, "/control/dhcp/leases")
        leases: list[dict] | None = data if isinstance(data, list) else None

        # 2) Fallback to status wrapper
        if leases is None:
            st = await self._get_json(hass, "/control/dhcp/status")
            if isinstance(st, dict):
                leases = st.get("leases") if isinstance(st.get("leases"), list) else None
                # Optionally include static leases as well:
                static = st.get("static_leases")
                if isinstance(static, list):
                    leases = (leases or []) + static

        out: Dict[str, str] = {}
        if not leases:
            return out

        for row in leases:
            if not isinstance(row, dict):
                continue
            ip = row.get("ip") or row.get("ip_address")
            mac = row.get("mac") or row.get("mac_address")
            if not ip or not mac:
                continue
            mac_u = _uc(str(mac))
            if mac_u in ("(INCOMPLETE)", "00:00:00:00:00:00", "*"):
                continue
            out[str(ip)] = mac_u
        return out
