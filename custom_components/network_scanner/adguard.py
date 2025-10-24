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
    Order of preference:
      1) /control/dhcp/status (merges leases + static_leases)
      2) /control/dhcp/leases  (older schemas / when available)
      3) /control/clients      (fallback; often missing MACs)
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
        return (mac or "").upper()

    async def fetch_map(self, hass) -> Dict[str, str]:
        if not self.base_url or not self.username or not self.password:
            return {}

        session = async_get_clientsession(hass, verify_ssl=self.verify_tls)

        # 1) /control/dhcp/status  → { leases:[], static_leases:[] }
        status_url = f"{self.base_url}/control/dhcp/status"
        try:
            async with session.get(status_url, auth=self._auth, timeout=self.timeout) as resp:
                text = await resp.text()
                if resp.status == 404:
                    _LOGGER.debug("AdGuard: /control/dhcp/status is 404; trying /control/dhcp/leases")
                elif resp.status >= 400:
                    _LOGGER.debug("AdGuard: status HTTP %s: %r", resp.status, text[:180])
                else:
                    data = json.loads(text)
                    mapped = self._parse_status(data)
                    if mapped:
                        _LOGGER.debug("AdGuard: parsed %d from dhcp/status", len(mapped))
                        return mapped
        except (ClientError, json.JSONDecodeError) as exc:
            _LOGGER.debug("AdGuard: dhcp/status fetch failed: %s", exc)
        except Exception as exc:
            _LOGGER.debug("AdGuard: unexpected during dhcp/status fetch: %s", exc)

        # 2) /control/dhcp/leases (some setups expose only this)
        leases_url = f"{self.base_url}/control/dhcp/leases"
        try:
            async with session.get(leases_url, auth=self._auth, timeout=self.timeout) as resp:
                text = await resp.text()
                if resp.status == 404:
                    _LOGGER.debug("AdGuard: /control/dhcp/leases 404; falling back to /control/clients")
                elif resp.status >= 400:
                    _LOGGER.debug("AdGuard: leases HTTP %s: %r", resp.status, text[:180])
                else:
                    data = json.loads(text)
                    mapped = self._parse_leases(data)
                    if mapped:
                        _LOGGER.debug("AdGuard: parsed %d from dhcp/leases", len(mapped))
                        return mapped
        except (ClientError, json.JSONDecodeError) as exc:
            _LOGGER.debug("AdGuard: dhcp/leases fetch failed: %s", exc)
        except Exception as exc:
            _LOGGER.debug("AdGuard: unexpected during dhcp/leases fetch: %s", exc)

        # 3) /control/clients (last resort; may lack MACs)
        clients_url = f"{self.base_url}/control/clients"
        try:
            async with session.get(clients_url, auth=self._auth, timeout=self.timeout) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    _LOGGER.debug("AdGuard: clients HTTP %s: %r", resp.status, text[:180])
                    return {}
                data = json.loads(text)
                mapped = self._parse_clients(data)
                if not mapped:
                    _LOGGER.warning(
                        "AdGuard: /control/clients returned no IP/MAC pairs. "
                        "Enable AdGuard DHCP or switch to OPNsense ARP to obtain MACs across VLANs."
                    )
                else:
                    _LOGGER.debug("AdGuard: parsed %d from clients", len(mapped))
                return mapped
        except (ClientError, json.JSONDecodeError) as exc:
            _LOGGER.debug("AdGuard: clients fetch failed: %s", exc)
        except Exception as exc:
            _LOGGER.debug("AdGuard: unexpected during clients fetch: %s", exc)

        return {}

    # ---------- parsers ----------

    def _parse_status(self, data: Any) -> Dict[str, str]:
        """
        Expected shape:
          {
            "leases": [ { "ip": "10.0.0.10", "mac": "aa:bb:...", ... }, ... ],
            "static_leases": [ { "ip": "...", "mac": "...", ... }, ... ]
          }
        """
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
                ip = str(r.get("ip") or r.get("IP") or "")
                mac = self._norm_mac(str(r.get("mac") or r.get("MAC") or ""))
                if ip and mac and mac.lower() != "(incomplete)":
                    out[ip] = mac
        return out

    def _parse_leases(self, data: Any) -> Dict[str, str]:
        # Some older builds expose only leases as a list or under {"leases":[...]}
        rows: Iterable[Any] = []
        if isinstance(data, dict) and isinstance(data.get("leases"), list):
            rows = data["leases"]
        elif isinstance(data, list):
            rows = data
        out: Dict[str, str] = {}
        for r in rows:
            if not isinstance(r, dict):
                continue
            ip  = str(r.get("ip") or r.get("IP") or "")
            mac = self._norm_mac(str(r.get("mac") or r.get("MAC") or ""))
            if ip and mac and mac.lower() != "(incomplete)":
                out[ip] = mac
        return out

    def _parse_clients(self, data: Any) -> Dict[str, str]:
        # Typical: [{"ids":["10.0.0.7"], "macs":["AA:BB:..."], ...}, ...]
        out: Dict[str, str] = {}
        rows: Iterable[Any] = data if isinstance(data, list) else data.get("clients", []) if isinstance(data, dict) else []
        for r in rows:
            if not isinstance(r, dict):
                continue
            ips = r.get("ips") or r.get("ip_addrs") or r.get("ids") or []
            macs = r.get("macs") or r.get("mac") or r.get("hardware_addresses") or []
            if isinstance(ips, str): ips = [ips]
            if isinstance(macs, str): macs = [macs]
            ip  = str(ips[0]) if ips else ""
            mac = self._norm_mac(macs[0]) if macs else ""
            if ip and mac:
                out[ip] = mac
        return out
