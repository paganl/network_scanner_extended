# custom_components/network_scanner/adguard.py
from __future__ import annotations
from typing import Dict, Any
import json
import logging
from urllib.parse import urljoin

from aiohttp import ClientError, ClientTimeout, BasicAuth
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

def _clean_mac(mac: str | None) -> str:
    s = (mac or "").upper()
    return s if s and s != "(INCOMPLETE)" and s != "00:00:00:00:00:00" else ""

def _ensure_control_base(base: str) -> str:
    # AdGuard Home API base is typically /control/*
    base = (base or "").rstrip("/")
    return base if base.endswith("/control") else base + "/control"

class AdGuardARPClient:
    """
    Fetch IP→MAC mappings from AdGuard Home:
      1) /control/dhcp/status (if DHCP is enabled)
      2) fallback: /control/clients (runtime clients list)
    Basic Auth with admin key/secret (username/password) is supported.
    """

    def __init__(self, base_url: str, key: str, secret: str, verify_tls: bool = True, timeout: int = 10) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.key = key or ""
        self.secret = secret or ""
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)
        self._auth = BasicAuth(self.key, self.secret)

    async def fetch_map(self, hass) -> Dict[str, str]:
        if not self.base_url or not self.key or not self.secret:
            return {}

        session = async_get_clientsession(hass, verify_ssl=self.verify_tls)
        ctrl = _ensure_control_base(self.base_url)

        # 1) DHCP status → leases (preferred)
        try:
            leases_url = urljoin(ctrl + "/", "dhcp/status")
            async with session.get(leases_url, auth=self._auth, timeout=self.timeout) as resp:
                if resp.status < 400:
                    data = json.loads(await resp.text())
                    m = self._parse_dhcp_status(data)
                    if m:
                        _LOGGER.debug("AdGuard: parsed %d leases from DHCP status", len(m))
                        return m
        except (ClientError, json.JSONDecodeError) as exc:
            _LOGGER.debug("AdGuard: dhcp/status unusable: %s", exc)
        except Exception as exc:
            _LOGGER.debug("AdGuard: dhcp/status unexpected: %s", exc)

        # 2) Fallback: clients list (runtime)
        try:
            clients_url = urljoin(ctrl + "/", "clients")
            async with session.get(clients_url, auth=self._auth, timeout=self.timeout) as resp:
                if resp.status < 400:
                    data = json.loads(await resp.text())
                    m = self._parse_clients(data)
                    if m:
                        _LOGGER.debug("AdGuard: parsed %d entries from clients", len(m))
                        return m
        except (ClientError, json.JSONDecodeError) as exc:
            _LOGGER.debug("AdGuard: clients unusable: %s", exc)
        except Exception as exc:
            _LOGGER.debug("AdGuard: clients unexpected: %s", exc)

        _LOGGER.warning("AdGuard: no usable endpoint returned data at %s", self.base_url)
        return {}

    # -------- parsing --------

    def _parse_dhcp_status(self, data: Any) -> Dict[str, str]:
        """
        AdGuard openapi describes /dhcp/status payload with leases lists.
        We accept both v4/v6 sections and different shapes.
        Returns {ip: MAC}
        """
        out: Dict[str, str] = {}

        def grab_list(rows):
            nonlocal out
            if isinstance(rows, list):
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    ip  = str(r.get("ip") or r.get("IP") or "")
                    mac = _clean_mac(r.get("mac") or r.get("MAC") or "")
                    if ip and mac:
                        out[ip] = mac

        if isinstance(data, dict):
            # Common nesting:
            # { "dhcp": { "v4": {..., "leases":[...]}, "v6": {...} } }
            for key in ("dhcp", "v4", "v6", "leases"):
                pass
            dhcp = data.get("dhcp") or data
            if isinstance(dhcp, dict):
                for section in ("v4", "v6"):
                    sec = dhcp.get(section)
                    if isinstance(sec, dict):
                        grab_list(sec.get("leases"))
                # Some builds flatten leases directly
                grab_list(dhcp.get("leases"))
        # Some images return just {"leases":[...]}
        if not out and isinstance(data, dict) and "leases" in data:
            grab_list(data.get("leases"))

        return out

    def _parse_clients(self, data: Any) -> Dict[str, str]:
        """
        /clients often returns objects with ip_addresses and macs.
        Map all discovered IPs to the client's MAC where present.
        """
        out: Dict[str, str] = {}
        rows = []
        if isinstance(data, dict) and "clients" in data:
            rows = data.get("clients") or []
        elif isinstance(data, list):
            rows = data
        for r in rows:
            if not isinstance(r, dict):
                continue
            mac = _clean_mac(r.get("macs", [None])[0] if isinstance(r.get("macs"), list) else r.get("mac"))
            if not mac:
                continue
            ips = r.get("ip_addresses") or r.get("ips") or []
            if isinstance(ips, list):
                for ip in ips:
                    if isinstance(ip, str) and ip:
                        out[ip] = mac
        return out
