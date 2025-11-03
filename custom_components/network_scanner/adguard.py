# custom_components/network_scanner/adguard.py
from __future__ import annotations
from typing import Dict, Any, Iterable
import json
import logging

from aiohttp import ClientError, ClientTimeout, BasicAuth
from homeassistant.helpers.aiohttp_client import async_get_clientsession

_LOGGER = logging.getLogger(__name__)

class AdGuardDHCPClient:
    """
    Fetch {ip: MAC} from AdGuard Home.
    Tries, in order:
      1) /control/dhcp/status (merges leases + static_leases)
      2) /control/dhcp/leases
      3) /control/clients
    """

    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool = True, timeout: int = 10) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.username = username or ""
        self.password = password or ""
        self.verify_tls = bool(verify_tls)
        self.timeout = ClientTimeout(total=timeout)
        self._auth = BasicAuth(self.username, self.password)

    @staticmethod
    def _norm_mac(mac: str | None) -> str:
        m = (mac or "").strip().upper()
        if not m:
            return ""
        if m in {"(INCOMPLETE)", "INCOMPLETE"}:
            return ""
        if m.replace(":", "") == "000000000000":
            return ""
        return m

    async def fetch_map(self, hass) -> Dict[str, str]:
        if not self.base_url or not self.username or not self.password:
            return {}

        session = async_get_clientsession(hass, verify_ssl=self.verify_tls)
        _LOGGER.debug("AdGuard: trying endpoints at %s: dhcp/status → dhcp/leases → clients", self.base_url)

        # 1) /control/dhcp/status
        status_url = f"{self.base_url}/control/dhcp/status"
        try:
            async with session.get(status_url, auth=self._auth, timeout=self.timeout, ssl=self.verify_tls) as resp:
                text = await resp.text()
                if resp.status == 404:
                    _LOGGER.debug("AdGuard: /control/dhcp/status 404; will try /control/dhcp/leases")
                elif resp.status >= 400:
                    _LOGGER.debug("AdGuard: status HTTP %s: %r", resp.status, text[:180])
                else:
                    data = json.loads(text)
                    mapped = self._parse_status(data)
                    if mapped:
                        _LOGGER.debug("AdGuard: parsed %d entries from dhcp/status", len(mapped))
                        return mapped
        except (ClientError, json.JSONDecodeError) as exc:
            _LOGGER.debug("AdGuard: dhcp/status fetch failed: %s", exc)
        except Exception as exc:
            _LOGGER.debug("AdGuard: unexpected during dhcp/status fetch: %s", exc)

        # 2) /control/dhcp/leases
        leases_url = f"{self.base_url}/control/dhcp/leases"
        try:
            async with session.get(leases_url, auth=self._auth, timeout=self.timeout, ssl=self.verify_tls) as resp:
                text = await resp.text()
                if resp.status == 404:
                    _LOGGER.debug("AdGuard: /control/dhcp/leases 404; will try /control/clients")
                elif resp.status >= 400:
                    _LOGGER.debug("AdGuard: leases HTTP %s: %r", resp.status, text[:180])
                else:
                    data = json.loads(text)
                    mapped = self._parse_leases(data)
                    if mapped:
                        _LOGGER.debug("AdGuard: parsed %d entries from dhcp/leases", len(mapped))
                        return mapped
        except (ClientError, json.JSONDecodeError) as exc:
            _LOGGER.debug("AdGuard: dhcp/leases fetch failed: %s", exc)
        except Exception as exc:
            _LOGGER.debug("AdGuard: unexpected during dhcp/leases fetch: %s", exc)

        # 3) /control/clients
        clients_url = f"{self.base_url}/control/clients"
        try:
            async with session.get(clients_url, auth=self._auth, timeout=self.timeout, ssl=self.verify_tls) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    _LOGGER.debug("AdGuard: clients HTTP %s: %r", resp.status, text[:180])
                    return {}
                data = json.loads(text)
                mapped = self._parse_clients(data)
                if not mapped:
                    _LOGGER.warning(
                        "AdGuard: /control/clients returned no IP/MAC pairs. "
                        "If DHCP is not managed by AdGuard, MACs may be missing; "
                        "use OPNsense ARP for complete data."
                    )
                else:
                    _LOGGER.debug("AdGuard: parsed %d entries from clients", len(mapped))
                return mapped
        except (ClientError, json.JSONDecodeError) as exc:
            _LOGGER.debug("AdGuard: clients fetch failed: %s", exc)
        except Exception as exc:
            _LOGGER.debug("AdGuard: unexpected during clients fetch: %s", exc)

        _LOGGER.warning("AdGuard: no usable endpoint at %s", self.base_url)
        return {}

    # ---------- parsers ----------

    def _parse_status(self, data: Any) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not isinstance(data, dict):
            return out
        for key in ("leases", "static_leases"):
            rows = data.get(key) or []
            if not isinstance(rows, list):
                continue
            for r in rows:
                if not isinstance(r, dict):
                    continue
                ip  = str(r.get("ip") or r.get("IP") or r.get("ip_address") or "")
                mac = self._norm_mac(r.get("mac") or r.get("MAC"))
                if ip and mac:
                    out[ip] = mac
        return out

    def _parse_leases(self, data: Any) -> Dict[str, str]:
        rows: Iterable[Any] = []
        if isinstance(data, dict) and isinstance(data.get("leases"), list):
            rows = data["leases"]
        elif isinstance(data, list):
            rows = data
        out: Dict[str, str] = {}
        for r in rows:
            if not isinstance(r, dict):
                continue
            ip  = str(r.get("ip") or r.get("IP") or r.get("ip_address") or "")
            mac = self._norm_mac(r.get("mac") or r.get("MAC"))
            if ip and mac:
                out[ip] = mac
        return out

    def _parse_clients(self, data: Any) -> Dict[str, str]:
        out: Dict[str, str] = {}
        rows: Iterable[Any] = data if isinstance(data, list) else data.get("clients", []) if isinstance(data, dict) else []
        for r in rows:
            if not isinstance(r, dict):
                continue
            ips  = r.get("ips") or r.get("ip_addrs") or r.get("ids") or []
            macs = r.get("macs") or r.get("mac") or r.get("hardware_addresses") or []
            if not isinstance(ips, list):
                ips = [ips] if ips else []
            if not isinstance(macs, list):
                macs = [macs] if macs else []
            ip  = str(ips[0]) if ips else ""
            mac = self._norm_mac(macs[0]) if macs else ""
            if ip and mac:
                out[ip] = mac
        return out
