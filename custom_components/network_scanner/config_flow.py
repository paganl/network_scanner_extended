import json
import logging
from ipaddress import ip_network
import voluptuous as vol

from homeassistant import config_entries

# Selector fallback for older HA cores
try:
    from homeassistant.helpers.selector import selector as ha_selector

    def TextSelector():
        return ha_selector({"text": {"multiline": True}})
except Exception:  # pragma: no cover
    def TextSelector():
        return str

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def _format_for_log(d: dict) -> dict:
    return {k: str(v) for k, v in d.items()}


def _normalise_mac_key(mac: str) -> str:
    return mac.upper() if isinstance(mac, str) else ""


def _build_directory_from_legacy_yaml(yaml_cfg: dict) -> dict:
    """
    Accept legacy keys like:
      mac_mapping_1: "AA:BB:..:FF|Name|Desc"
      mac_mapping_2: "AA:BB:..:FF=Name|Desc"
    Loosely parsed on "|" with optional "=" between MAC and payload.
    """
    directory: dict[str, dict] = {}
    for i in range(1, 999):  # generous upper bound; break after a gap beyond 25
        key = f"mac_mapping_{i}"
        if key not in yaml_cfg:
            if i > 25:
                break
            continue

        raw = str(yaml_cfg.get(key, "")).strip()
        if not raw:
            continue

        if "=" in raw:
            mac_part, payload = raw.split("=", 1)
        else:
            parts = raw.split("|")
            mac_part, payload = parts[0], "|".join(parts[1:])

        mac = _normalise_mac_key(mac_part.strip())
        if not mac:
            continue

        name, desc = "", ""
        if "|" in payload:
            name, desc = payload.split("|", 1)
        else:
            name = payload

        directory[mac] = {"name": name.strip(), "desc": desc.strip()}

    return directory


class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the config flow for Network Scanner (Extended)."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors: dict[str, str] = {}

        # Pick up any YAML defaults preserved by __init__ (optional)
        yaml_config = self.hass.data.get(DOMAIN, {}) or {}
        _LOGGER.debug("YAML Config (raw): %s", _format_for_log(yaml_config))

        data_schema = vol.Schema(
            {
                vol.Required(
                    "ip_range",
                    description={
                        "suggested_value": yaml_config.get("ip_range", "192.168.1.0/24")
                    },
                ): str,
                vol.Optional(
                    "mac_directory_json_text",
                    description={
                        "suggested_value": yaml_config.get(
                            "mac_directory_json_text", ""
                        )
                    },
                ): TextSelector(),
                vol.Optional(
                    "mac_directory_json_url",
                    description={
                        "suggested_value": yaml_config.get(
                            "mac_directory_json_url", ""
                        )
                    },
                ): str,
            }
        )

        if user_input is None:
            return self.async_show_form(
                step_id="user",
                data_schema=data_schema,
                errors=errors,
                description_placeholders={
                    "description": "Enter the IP range and an optional MAC directory (JSON text or URL)."
                },
            )

        # --- Validate & assemble entry data ---
        ip_range = (user_input.get("ip_range") or "").strip()
        json_text = (user_input.get("mac_directory_json_text") or "").strip()
        json_url = (user_input.get("mac_directory_json_url") or "").strip()

        # Validate CIDR/IP early
        try:
            ip_network(ip_range, strict=False)
        except Exception:
            errors["ip_range"] = "invalid_ip_range"

        mac_directory: dict[str, dict] = {}

        # 1) Legacy YAML mac_mapping_* support
        legacy = _build_directory_from_legacy_yaml(yaml_config)
        if legacy:
            mac_directory.update(legacy)

        # 2) JSON pasted in textarea
        if json_text:
            try:
                parsed = json.loads(json_text)
                if not isinstance(parsed, dict):
                    errors["mac_directory_json_text"] = "invalid_json"
                else:
                    # Accept both { "data": {...} } and flat { "AA:BB:..": {...} }
                    block = parsed.get("data", parsed)
                    if not isinstance(block, dict):
                        errors["mac_directory_json_text"] = "invalid_json"
                    else:
                        for k, v in block.items():
                            mk = _normalise_mac_key(k)
                            if not mk:
                                continue
                            if isinstance(v, dict):
                                name = v.get("name", "")
                                desc = v.get("desc", "")
                            else:
                                name, desc = str(v), ""
                            mac_directory[mk] = {"name": str(name), "desc": str(desc)}
            except Exception as exc:  # log and surface a friendly error
                _LOGGER.warning(
                    "Failed to parse mac_directory_json_text: %s", exc, exc_info=True
                )
                errors["mac_directory_json_text"] = "invalid_json"

        entry_data = {
            "ip_range": ip_range,
            "mac_directory": mac_directory,  # processed dict with UPPERCASE keys
            "mac_directory_json_url": json_url,  # optional; fetch at runtime if you support it
        }

        if errors:
            return self.async_show_form(
                step_id="user",
                data_schema=data_schema,
                errors=errors,
                description_placeholders={"description": "Fix the errors and try again."},
            )

        _LOGGER.debug(
            "Creating entry: ip_range=%s, mac_directory_count=%d, url=%s",
            ip_range,
            len(mac_directory),
            json_url or "-",
        )
        return self.async_create_entry(
            title="Network Scanner Extended",
            data=entry_data,
        )
