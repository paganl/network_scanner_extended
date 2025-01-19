"""Binary sensor for the 'new devices' detection in a network scanner integration."""
import logging
from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store
from homeassistant.helpers.entity_registry import async_get as async_get_entity_registry
from homeassistant.const import STATE_UNKNOWN

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)
STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}_known_devices"

async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities):
    """Set up the new device detection binary sensor from a config entry."""
    ip_range = config_entry.data.get("ip_range", "192.168.1.0/24")
    _LOGGER.debug("NewDeviceBinarySensor: using ip_range: %s", ip_range)

    # Find the main sensor's entity ID
    entity_registry = async_get_entity_registry(hass)
    main_sensor_unique_id = f"network_scanner_{ip_range}"
    
    main_sensor_entity_id = None
    for entity in entity_registry.entities.values():
        if entity.unique_id == main_sensor_unique_id:
            main_sensor_entity_id = entity.entity_id
            break

    if not main_sensor_entity_id:
        _LOGGER.error("Could not find main network scanner sensor")
        return

    sensor = NewDeviceBinarySensor(hass, ip_range, main_sensor_entity_id)
    async_add_entities([sensor], True)


class NewDeviceBinarySensor(BinarySensorEntity):
    """Binary sensor that reports True if any brand new device is detected on the network."""

    def __init__(self, hass, ip_range, main_sensor_entity_id):
        """Initialize the binary sensor."""
        self.hass = hass
        self.ip_range = ip_range
        self.main_sensor_entity_id = main_sensor_entity_id
        
        # Initialize storage for known devices
        self._store = Store(self.hass, STORAGE_VERSION, STORAGE_KEY)
        self._known_devices = set()
        
        # State variables
        self._is_on = False
        self._newly_found_this_cycle = {"new_devices": []}
        
    async def async_added_to_hass(self):
        """Run when entity about to be added to hass."""
        await super().async_added_to_hass()
        
        # Load known devices from storage
        try:
            stored_data = await self._store.async_load()
            if stored_data is not None:
                self._known_devices = set(stored_data.get("devices", []))
                _LOGGER.debug("Loaded %d known devices from storage", len(self._known_devices))
        except Exception as exc:
            _LOGGER.error("Error loading known devices from storage: %s", exc)
            self._known_devices = set()

    async def _save_known_devices(self):
        """Save known devices to persistent storage."""
        try:
            data = {
                "devices": list(self._known_devices)
            }
            await self._store.async_save(data)
            _LOGGER.debug("Saved %d known devices to storage", len(self._known_devices))
        except Exception as exc:
            _LOGGER.error("Error saving known devices to storage: %s", exc)

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
        """Return extra state attributes."""
        return self._newly_found_this_cycle

    async def async_update(self):
        """Update the state using data from the main sensor."""
        try:
            # Get state from main sensor
            state = self.hass.states.get(self.main_sensor_entity_id)
            if state is None or state.state == STATE_UNKNOWN:
                _LOGGER.warning("Main sensor state not available")
                return

            # Get the devices list from the main sensor's attributes
            if not state.attributes or "devices" not in state.attributes:
                _LOGGER.warning("No devices data in main sensor attributes")
                return

            # Reset state for this cycle
            self._is_on = False
            self._newly_found_this_cycle = {"new_devices": []}

            # Process each device from the main sensor
            devices = state.attributes["devices"]
            for device in devices:
                # Get device identifier (prefer MAC over IP)
                device_id = device.get("mac")
                if not device_id:
                    device_id = f"ip_{device.get('ip')}"
                
                if device_id and device_id not in self._known_devices:
                    self._is_on = True
                    self._newly_found_this_cycle["new_devices"].append({
                        "id": device_id,
                        "ip": device.get("ip"),
                        "name": device.get("name", "Unknown"),
                        "type": device.get("type", "Unknown"),
                        "vendor": device.get("vendor", "Unknown")
                    })
                    self._known_devices.add(device_id)
                    _LOGGER.info("Found new device: %s (%s)", 
                               device.get("name", "Unknown"), device_id)

            # If we found new devices, save the updated list
            if self._is_on:
                _LOGGER.info("NewDeviceBinarySensor: Found new devices: %s", 
                           self._newly_found_this_cycle["new_devices"])
                await self._save_known_devices()

        except Exception as exc:
            _LOGGER.error("Error updating new device sensor: %s", exc)
    
