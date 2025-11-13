"""OPNsense provider for the Network Scanner integration.

This module implements a client for the OPNsense diagnostics API to
retrieve the current ARP/ND table.  It prefers the modern POST
interface exposed at ``/api/diagnostics/interface/search_arp`` but
includes a wide selection of GET fallbacks for older firmware
versions.  The returned data is normalised into a list of device
dicts with the keys ``mac``, ``ip``, ``hostname`` and ``vendor``.

This file is a drop‑in replacement for the built‑in provider.  It
avoids long running scans and strives to remain lean and robust.  If
you are receiving zero devices in Home Assistant, verify that your
API user has sufficient privileges (see the README) and that the
``verify_ssl`` option matches your OPNsense certificate setup.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession, ClientTimeout, BasicAuth

_LOGGER = logging.getLogger(__name__)


def _get_first(d: Dict[str, Any], keys: List[str], default: str = "") -> str:
    """Return the first non‑empty value from ``d`` for any of ``keys``.

    The original OPNsense JSON has a variety of field names for IP,
    MAC, manufacturer and hostname.  This helper centralises the
    lookup so we can support multiple schemas without branching all
    over the place.
    """
    for key in keys:
        value = d.get(key)
        if value:
            return str(value)
    return default


class OPNsenseARPClient:
    """Low level OPNsense ARP/ND fetcher.

    This class encapsulates all HTTP interactions with the OPNsense
    diagnostics API.  It will attempt to call the POST search
    endpoint first and fall back to a series of GET endpoints seen in
    the wild.  Parsed rows are returned as raw dicts with keys as
    provided by the API.
    """

    def __init__(
        self,
        session: ClientSession,
        base_url: str,
        key: str,
        secret: str,
        *,
        verify_ssl: bool = True,
        timeout_s: int = 5,
    ) -> None:
        self._session = session
        self._base = (base_url or "").rstrip("/")
        self._auth = BasicAuth(key or "", secret or "")
        self._ssl = bool(verify_ssl)
        self._timeout = ClientTimeout(total=timeout_s)

        # Potential GET endpoints, relative to ``/api``.  These were
        # observed across various OPNsense releases.  We try them in
        # this order after exhausting POST attempts.
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

    # -- internal helpers ----------------------------------------------------

    def _build_url(self, path: str) -> str:
        """Build a full URL for the given API path.

        Ensures exactly one ``/api`` component in the final URL.  If
        the user supplied ``base_url`` already ends with ``/api`` then
        this method won't add another one.  Otherwise it will append
        ``/api`` before concatenating the provided path.
        """
        base = self._base
        if not base.endswith("/api"):
            base = f"{base}/api"
        return f"{base}{path}"

    async def _post_json(self, path: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Perform a POST request and return a JSON body if successful.

        If the request returns a non‑200 status or fails to parse JSON
        then ``None`` is returned and a debug log is written.  Any
        exceptions are propagated to the caller for retry/fallback.
        """
        url = self._build_url(path)
        headers = {
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        try:
            async with self._session.post(
                url,
                auth=self._auth,
                data=data,
                headers=headers,
                timeout=self._timeout,
                ssl=self._ssl,
            ) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    _LOGGER.debug(
                        "OPNsense POST %s returned HTTP %s: %.256s",
                        url,
                        resp.status,
                        text,
                    )
                    return None
                try:
                    return await resp.json()
                except Exception:
                    _LOGGER.debug(
                        "OPNsense POST %s returned non‑JSON: %.256s", url, text
                    )
                    return None
        except Exception as exc:
            _LOGGER.debug("OPNsense POST %s raised %s", url, exc)
            raise

    async def _get_json(self, path: str) -> Optional[Dict[str, Any]]:
        """Perform a GET request and return a JSON body if successful.

        Similar semantics to :meth:`_post_json` but using HTTP GET.
        """
        url = self._build_url(path)
        headers = {
            "Accept": "application/json",
        }
        try:
            async with self._session.get(
                url,
                auth=self._auth,
                headers=headers,
                timeout=self._timeout,
                ssl=self._ssl,
            ) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    _LOGGER.debug(
                        "OPNsense GET %s returned HTTP %s: %.256s",
                        url,
                        resp.status,
                        text,
                    )
                    return None
                try:
                    return await resp.json()
                except Exception:
                    _LOGGER.debug(
                        "OPNsense GET %s returned non‑JSON: %.256s", url, text
                    )
                    return None
        except Exception as exc:
            _LOGGER.debug("OPNsense GET %s raised %s", url, exc)
            raise

    # -- public API ---------------------------------------------------------

    async def async_get_rows(self) -> List[Dict[str, Any]]:
        """Fetch the ARP/ND table and return a list of row dicts.

        Tries the POST search interface first, followed by a set of
        GET fallbacks.  If no endpoint yields any rows, returns an
        empty list and logs a warning.  Any exceptions from HTTP
        requests are propagated upward so that the caller can decide
        whether to swallow them.
        """
        # 1) modern POST search_arp endpoint
        payload = {"current": 1, "rowCount": 9999, "searchPhrase": ""}
        post_paths = [
            "/diagnostics/interface/search_arp",
            "/diagnostics/interface/search_arp/",
        ]
        for path in post_paths:
            data = await self._post_json(path, payload)
            if data:
                rows = self._parse_any_rows(data)
                if rows:
                    _LOGGER.debug(
                        "OPNsense ARP: parsed %d entries from POST %s", len(rows), path
                    )
                    return rows

        # 2) legacy GET endpoints
        for path in self._get_candidates:
            data = await self._get_json(path)
            if data:
                rows = self._parse_any_rows(data)
                if rows:
                    _LOGGER.debug(
                        "OPNsense ARP: parsed %d entries from GET %s", len(rows), path
                    )
                    return rows

        _LOGGER.warning("All OPNsense ARP endpoints failed or returned no rows")
        return []

    async def async_get_arp(self) -> Dict[str, str]:
        """Return a mapping of IP addresses to MAC addresses.

        Some parts of the integration (or older versions) expect a
        method named ``async_get_arp`` returning a dictionary of
        ``{ip: mac}``.  To preserve compatibility this method calls
        :meth:`async_get_rows` and normalises the result into a map.

        Returns an empty dict on failure or if no devices are found.
        """
        try:
            rows = await self.async_get_rows()
        except Exception:
            return {}
        mapping: Dict[str, str] = {}
        for row in rows:
            ip = row.get("ip")
            mac = row.get("mac")
            if ip and mac:
                mapping[str(ip)] = str(mac)
        return mapping

    # -- parsing helpers ----------------------------------------------------

    def _parse_any_rows(self, data: Any) -> List[Dict[str, Any]]:
        """Recursively parse arbitrary JSON shapes into a list of row dicts.

        The OPNsense API returns a variety of container shapes.  This
        helper accepts dicts, lists and nested combinations thereof.
        Each row dict will have at least an ``ip`` and ``mac`` key if
        possible.  Keys that are absent in the source are omitted.
        """
        if isinstance(data, list):
            # flat lists of dicts or lists
            return self._parse_list_of_dicts(data) or self._parse_list_of_lists(data)

        if isinstance(data, dict):
            # known containers
            for key in (
                "rows",
                "data",
                "arp",
                "neighbors",
                "neighbours",
                "entries",
                "items",
                "result",
            ):
                sub = data.get(key)
                if isinstance(sub, list):
                    devices = self._parse_list_of_dicts(sub) or self._parse_list_of_lists(sub)
                    if devices:
                        return devices
            # nested structures
            for value in data.values():
                if isinstance(value, (dict, list)):
                    devices = self._parse_any_rows(value)
                    if devices:
                        return devices
        # fallback: no usable rows found
        return []
        
    # NOTE: We normalise a provider-specific block under "opnsense" so the
    # coordinator can compute derived fields (role, vlan, risk) without
    # losing original fields like intf/intf_description/expiry.
    def _parse_list_of_dicts(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            # extract ip, mac, manufacturer and hostname.  OPNsense uses
            # multiple field names across releases; use helper to pick the
            # first available value.
            ip = _get_first(row, ["ip", "ipaddr", "ipaddress", "address", "inet", "addr"])
            mac = _get_first(row, ["mac", "macaddr", "lladdr", "ether", "hwaddr"])
            host = _get_first(row, ["hostname", "fqdn", "name"])
            manufacturer = _get_first(row, ["manufacturer", "vendor"])
            
            mac_upper = (mac or "").upper()
            # skip incomplete or invalid entries
            if mac_upper in ("", "(INCOMPLETE)", "00:00:00:00:00:00", "*"):
                continue
            if ip and mac_upper:
                # Provider-specific enrichment block from raw row
                op_block = {
                    "intf": row.get("intf") or "",
                    "intf_description": row.get("intf_description") or row.get("description") or "",
                    "arp_type": row.get("type") or "",
                    "arp_expired": bool(row.get("expired")) if "expired" in row else None,
                    "arp_expires_s": row.get("expires"),
                    "arp_permanent": bool(row.get("permanent")) if "permanent" in row else None,
                }
            
                device = {
                    "mac": mac_upper,
                    "ip": ip,
                    "hostname": host or "",
                    "vendor": (manufacturer or ""),
                    "source": "opnsense",
                    "opnsense": op_block,
                }
            
                # If upstream already set vendor elsewhere and manufacturer is empty,
                # this leaves existing vendor intact; otherwise use manufacturer.
                if not device["vendor"] and manufacturer:
                    device["vendor"] = manufacturer
            
                devices.append(device)
        return devices

    def _parse_list_of_lists(self, rows: List[Any]) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []
        for item in rows:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                ip = str(item[0])
                mac = str(item[1]).upper()
                if mac in ("", "(INCOMPLETE)", "00:00:00:00:00:00", "*"):
                    continue
                device = {
                    "mac": mac,
                    "ip": ip,
                    "hostname": "",
                    "vendor": "",
                    "source": "opnsense",
                    "opnsense": {},  # no extra fields available in this shape
                }
                devices.append(device)
        return devices


async def async_get_devices(
    session: ClientSession,
    base_url: str,
    key: str,
    secret: str,
    *,
    verify_ssl: bool = True,
    timeout_s: int = 5,
) -> List[Dict[str, Any]]:
    """Fetch the current ARP/ND table and return a list of devices.

    This is the primary entry point expected by the Network Scanner
    integration.  It constructs an :class:`OPNsenseARPClient`, fetches
    the raw rows and normalises them into the format consumed by
    Home Assistant.  The ``vendor`` field corresponds to the
    ``manufacturer`` column returned by OPNsense.
    """
    client = OPNsenseARPClient(
        session,
        base_url,
        key,
        secret,
        verify_ssl=verify_ssl,
        timeout_s=timeout_s,
    )
    rows: List[Dict[str, Any]] = []
    try:
        rows = await client.async_get_rows()
    except Exception as exc:
        # propagate errors to caller; coordinator will handle retries
        _LOGGER.debug("OPNsense client raised during fetch: %s", exc)
        raise
    return rows
