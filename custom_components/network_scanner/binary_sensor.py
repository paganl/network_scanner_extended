"""Binary sensors for the network scanner integration."""
import logging
import nmap
from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, Event

from .const import DOMAIN, EVENT_SCAN_STARTED, EVENT_SCAN_COMPLETED

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities):
    """Set up the binary sensors."""
    # Extract configuration
    ip_range = config_entry.data.get("ip_range", "192.168.1.0/24")
    _LOGGER.debug("Setting up binary sensors for IP range: %s", ip_range)

    # Gather mac_mappings
    mac_mappings_list = []
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

    mac_mappings = "\n".join(mac_mappings_list)
    
    # Create both binary sensors
    new_device_sensor = NewDeviceBinarySensor(hass, ip_range, mac_mappings)
    scan_status_sensor = ScanStatusBinarySensor(hass, config_entry)
    
    async_add_entities([new_device_sensor, scan_status_sensor], True)


class NewDeviceBinarySensor(BinarySensorEntity):
    """Binary sensor that reports True if any brand new device is detected on the network."""

    def __init__(self, hass, ip_range, mac_mapping):
        """Initialize the binary sensor."""
        self.hass = hass
        self.ip_range = ip_range
        self.mac_mapping = self.parse_mac_mapping(mac_mapping)
        self.nm = nmap.PortScanner()
        self._known_devices = set()
        self._is_on = False
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
        """Entity should be polled."""
        return True

    @property
    def is_on(self):
        """Return True if new devices were found."""
        return self._is_on

    @property
    def extra_state_attributes(self):
        """Return any extra state attributes."""
        return self._newly_found_this_cycle

    def parse_mac_mapping(self, mapping_string):
        """Parse the MAC mapping string."""
        mapping = {}
        for line in mapping_string.split("\n"):
            parts = line.split(";")
            if len(parts) >= 3:
                mac = parts[0].lower()
                mapping[mac] = (parts[1], parts[2])
        return mapping

    async def async_update(self):
        """Periodically check for new devices."""
        try:
            current_devices = await self.hass.async_add_executor_job(self.scan_network)

            self._is_on = False
            self._newly_found_this_cycle = {"new_devices": []}

            for dev_id in current_devices:
                if dev_id and dev_id not in self._known_devices:
                    self._is_on = True
                    self._newly_found_this_cycle["new_devices"].append(dev_id)
                    self._known_devices.add(dev_id)

            if self._is_on:
                _LOGGER.info("NewDeviceBinarySensor: Found new devices: %s", 
                           self._newly_found_this_cycle["new_devices"])

        except Exception as exc:
            _LOGGER.error("Error scanning for new devices: %s", exc)

    def scan_network(self):
        """Scan the network and return a list of IDs (MAC or IP) for all hosts found."""
        scan_args = "-sn"
        self.nm.scan(hosts=self.ip_range, arguments=scan_args)

        found_ids = []
        for host in self.nm.all_hosts():
            addresses = self.nm[host].get("addresses", {})
            ip = addresses.get("ipv4", host)
            mac = addresses.get("mac")
            dev_id = mac.lower() if mac else f"ip_{ip}"
            found_ids.append(dev_id)

        return found_ids


class ScanStatusBinarySensor(BinarySensorEntity):
    """Binary sensor that shows if a network scan is currently running."""

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry):
        """Initialize the binary sensor."""
        self.hass = hass
        self._is_on = False
        self._attr_name = "Network Scan Status"
        self._attr_unique_id = f"scan_status_{config_entry.data.get('ip_range', '').replace('/', '_')}"
        
        # Set up event listeners
        self.hass.bus.async_listen(EVENT_SCAN_STARTED, self._handle_scan_started)
        self.hass.bus.async_listen(EVENT_SCAN_COMPLETED, self._handle_scan_completed)

    @property
    def device_class(self):
        """Return the class of this sensor."""
        return "running"

    @property
    def is_on(self):
        """Return true if a scan is currently running."""
        return self._is_on

    async def _handle_scan_started(self, event: Event):
        """Handle scan started event."""
        self._is_on = True
        self.async_write_ha_state()

    async def _handle_scan_completed(self, event: Event):
        """Handle scan completed event."""
        self._is_on = False
        self.async_write_ha_state()
