"""Binary sensor for the 'new devices' detection in a network scanner integration."""
import logging
import nmap

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities):
    """Set up the new device detection binary sensor from a config entry."""
    # 1) Extract IP range
    ip_range = config_entry.data.get("ip_range", "192.168.1.0/24")
    _LOGGER.debug("NewDeviceBinarySensor: using ip_range: %s", ip_range)

    # 2) Gather mac_mappings lines from the config entry
    mac_mappings_list = []
    # Ensure we handle at least 25 lines, then keep going if there are more
    for i in range(25):
        key = f"mac_mapping_{i+1}"
        mac_line = config_entry.data.get(key, "")
        mac_mappings_list.append(mac_line)

    i = 25
    while True:
        key = f"mac_mapping_{i+1}"
        if key in config_entry.data:
            mac_line = config_entry.data.get(key, "")
            mac_mappings_list.append(mac_line)
            i += 1
        else:
            break

    # 3) Combine into a single string to parse
    mac_mappings = "\n".join(mac_mappings_list)
    _LOGGER.debug("NewDeviceBinarySensor: gathered mac_mappings:\n%s", mac_mappings)

    # 4) Create and add the binary sensor entity
    sensor = NewDeviceBinarySensor(hass, ip_range, mac_mappings)
    async_add_entities([sensor], True)


class NewDeviceBinarySensor(BinarySensorEntity):
    """Binary sensor that reports True if any brand new device is detected on the network."""

    def __init__(self, hass, ip_range, mac_mapping):
        """Initialize the binary sensor."""
        self.hass = hass
        self.ip_range = ip_range
        self.mac_mapping = self.parse_mac_mapping(mac_mapping)

        # We'll use nmap PortScanner just like the main sensor
        self.nm = nmap.PortScanner()

        # Keep a set of devices we have already seen (MAC or IP fallback)
        self._known_devices = set()

        # The sensor state (True if new device found in the most recent scan)
        self._is_on = False

        # We can store which devices were newly discovered *this* cycle
        self._newly_found_this_cycle = {"new_devices": []}

    @property
    def name(self):
        """Return a friendly name for this binary sensor."""
        return "New Device Detected"

    @property
    def unique_id(self):
        """Return a unique ID for this sensor."""
        return f"new_device_sensor_{self.ip_range}"

    @property
    def should_poll(self):
        """Home Assistant should periodically poll this sensor."""
        return True

    @property
    def is_on(self):
        """Return True if we found any new devices during the last scan."""
        return self._is_on

    @property
    def extra_state_attributes(self):
        """Return any extra attributes, e.g. which devices are new."""
        return self._newly_found_this_cycle

    async def async_update(self):
        """Periodically run a network scan and detect new devices."""
        try:
            _LOGGER.debug("NewDeviceBinarySensor: scanning network...")
            current_devices = await self.hass.async_add_executor_job(self.scan_network)

            # Reset for each scan
            self._is_on = False
            self._newly_found_this_cycle = {"new_devices": []}

            for dev_id in current_devices:
                # If we haven't seen this ID yet, it's new
                if dev_id not in self._known_devices:
                    self._is_on = True
                    self._newly_found_this_cycle["new_devices"].append(dev_id)
                    self._known_devices.add(dev_id)

            if self._is_on:
                _LOGGER.info("NewDeviceBinarySensor: Found new devices: %s", self._newly_found_this_cycle["new_devices"])

        except Exception as exc:
            _LOGGER.error("Error scanning for new devices: %s", exc)

    def parse_mac_mapping(self, mapping_string):
        """Parse the MAC mapping string (optional for more advanced usage)."""
        # You could do more with this if you want vendor/device name lookups.
        mapping = {}
        for line in mapping_string.split("\n"):
            parts = line.split(";")
            if len(parts) >= 3:
                mac = parts[0].lower()
                # name, device_type = parts[1], parts[2], etc.
                mapping[mac] = (parts[1], parts[2])
        return mapping

    def scan_network(self):
        """Scan the network and return a list of IDs (MAC or IP) for all hosts found."""
        # Adjust if you have a 'privileged' mode in your config
        scan_args = "-sn"
        self.nm.scan(hosts=self.ip_range, arguments=scan_args)

        found_ids = []

        for host in self.nm.all_hosts():
            addresses = self.nm[host].get("addresses", {})
            ip = addresses.get("ipv4", host)
            mac = addresses.get("mac")

            # Use MAC if present, else fallback to IP
            dev_id = mac if mac else ip
            found_ids.append(dev_id)

        return found_ids
