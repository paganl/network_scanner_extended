# custom_components/network_scanner/adguard.py
from __future__ import annotations
from typing import Dict, Any
import json
import logging

from aiohttp import ClientError, ClientTimeout
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

def _uc(s: str | None) -> str:
    return (s or "").upper()

class AdGuardDHCPClient:
    """
    Minimal AdGuard Home client:
      1) POST /control/login { name, password } -> { token }
      2) GET  /control/dhcp/leases           -> [ { ip, mac, hostname? }, ... ]
         Fallback: GET /control/dhcp/status  -> { leases: [...] }
    """

    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool = True, timeout: int = 10) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.username = username or ""
        self.password = password or ""
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)
        self._token: str | None = None

    async def _login(self, hass) -> bool:
        if not self.base_url or not self.username or not self.password:
            return False
        session = async_get_clientsession(hass, verify_ssl=self.verify_tls)
        url = f"{self.base_url}/control/login"
        try:
            async with session.post(url, json={"name": self.username, "password": self.password}, timeout=self.timeout) as resp:
                if resp.status >= 400:
                    txt = await resp.text()
                    raise RuntimeError(f"HTTP {resp.status}: {txt[:200]!r}")
                data = json.loads(await resp.text())
                tok = data.get("token")
                if not tok:
                    raise RuntimeError("No token in login response")
                self._token = tok
                return True
        except (ClientError, RuntimeError, json.JSONDecodeError) as exc:
            _LOGGER.warning("AdGuard login failed at %s: %s", url, exc)
            self._token = None
            return False

    async def _get_json(self, hass, path: str) -> Any:
        if not self._token:
            ok = await self._login(hass)
            if not ok:
                return None
        session = async_get_clientsession(hass, verify_ssl=self.verify_tls)
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {self._token}"}
        try:
            async with session.get(url, headers=headers, timeout=self.timeout) as resp:
                if resp.status == 401:
                    # token expired; retry once
                    if await self._login(hass):
                        return await self._get_json(hass, path)
                    return None
                if resp.status >= 400:
                    return None
                txt = await resp.text()
            return json.loads(txt)
        except (ClientError, json.JSONDecodeError):
            return None

    async def fetch_map(self, hass) -> Dict[str, str]:
        """Return { ip: MAC } from DHCP leases."""
        # Prefer explicit leases endpoint
        data = await self._get_json(hass, "/control/dhcp/leases")
        leases: list[dict] | None = None
        if isinstance(data, list):
            leases = data
        if leases is None:
            # Fallback: status wrapper
            st = await self._get_json(hass, "/control/dhcp/status")
            if isinstance(st, dict) and isinstance(st.get("leases"), list):
                leases = st["leases"]

        out: Dict[str, str] = {}
        if not leases:
            return out

        for row in leases:
            if not isinstance(row, dict):
                continue
            ip = row.get("ip") or row.get("ip_address")
            mac = row.get("mac") or row.get("mac_address")
            if ip and mac:
                mac_u = _uc(str(mac))
                if mac_u not in ("(INCOMPLETE)", "00:00:00:00:00:00", "*"):
                    out[str(ip)] = mac_u
        return out
