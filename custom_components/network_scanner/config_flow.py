import json
import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.helpers.selector import selector

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

def _format_for_log(d: dict) -> dict:
    return {k: str(v) for k, v in d.items()}

def _normalise_mac_key(mac: str) -> str:
    if not isinstance(mac, str):
        return ""
    return mac.upper()  # keep separators as-is per your decision

def _build_directory_from_legacy_yaml(yaml_cfg: dict) -> dict:
    """
    Accept legacy keys like mac_mapping_1: "AA:BB:..|Name|Desc"
    or "AA:BB:..=Name|Desc". Loosely parsed on |.
    """
    directory = {}
    for i in range(1, 999):  # be generous; break when not found
        key = f"mac_mapping_{i}"
        if key not in yaml_cfg:
            if i > 25:
                break
            continue
        raw = str(yaml_cfg.get(key, "")).strip()
        if not raw:
            continue
        # accepted formats:
        #   "AA:BB:CC:DD:EE:FF|Device Name|Description"
        #   "AA:BB:CC:DD:EE:FF=Device Name|Description"
        if "=" in raw:
            mac_part, payload = raw.split("=", 1)
        else:
            parts = raw.split("|")
            mac_part, payload = parts[0], "|".join(parts[1:])
        mac = _normalise_mac_key(mac_part.strip())
        name, desc = "", ""
        if "|" in payload:
            name, desc = payload.split("|", 1)
        else:
            name = payload
        directory[mac] = {"name": name.strip(), "desc": desc.strip()}
    return directory

class NetworkScannerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Network Scanner."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Manage the configurations from the user interface."""
        errors = {}

        # Load any YAML provided defaults (optional)
        yaml_config = self.hass.data.get(DOMAIN, {}) or {}
        _LOGGER.debug("YAML Config (raw): %s", _format_for_log(yaml_config))

        # Build form schema with selectors (multiline text for JSON)
        data_schema = vol.Schema(
            {
                vol.Required(
                    "ip_range",
                    description={"suggested_value": yaml_config.get("ip_range", "192.168.1.0/24")},
                ): str,
                vol.Optional(
                    "mac_directory_json_text",
                    description={"suggested_value": yaml_config.get("mac_directory_json_text", "")},
                ): selector({"text": {"multiline": True}}),
                vol.Optional(
                    "mac_directory_json_url",
                    description={"suggested_value": yaml_config.get("mac_directory_json_url", "")},
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

        # --- Validate & assemble config entry data ---
        ip_range = user_input.get("ip_range", "").strip()
        json_text = user_input.get("mac_directory_json_text") or ""
        json_url = (user_input.get("mac_directory_json_url") or "").strip()

        mac_directory = {}

        # 1) Legacy YAML mac_mapping_* support (fold into directory)
        legacy_from_yaml = _build_directory_from_legacy_yaml(yaml_config)
        if legacy_from_yaml:
            mac_directory.update(legacy_from_yaml)

        # 2) JSON pasted in textarea
        if json_text:
            try:
                parsed = json.loads(json_text)
                if not isinstance(parsed, dict):
                    errors["mac_directory_json_text"] = "invalid_json"
                else:
                    # Support both {"AA:...":{"name":..,"desc":..}} and {"data": {...}}
                    data_block = parsed.get("data", parsed)
                    if not isinstance(data_block, dict):
                        errors["mac_directory_json_text"] = "invalid_json"
                    else:
                        for k, v in data_block.items():
                            mac = _normalise_mac_key(k)
                            if not mac:
                                continue
                            if isinstance(v, dict):
                                name = v.get("name", "")
                                desc = v.get("desc", "")
                            else:
                                # allow simple string as name
                                name, desc = str(v), ""
                            mac_directory[mac] = {"name": str(name), "desc": str(desc)}
            except Exception as exc:  # noqa: BLE001 (we want to log anything)
                _LOGGER.warning("Failed to parse mac_directory_json_text: %s", exc)
                errors["mac_directory_json_text"] = "invalid_json"

        # 3) URL is optional; we just store it and let the coordinator fetch/refresh
        #    (Do not fetch here; config flows should avoid I/O where possible.)
        entry_data = {
            "ip_range": ip_range,
            "mac_directory": mac_directory,  # dict ready to use
            "mac_directory_json_url": json_url,  # optional; fetch later in update loop
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
        return self.async_create_entry(title="Network Scanner", data=entry_data)
