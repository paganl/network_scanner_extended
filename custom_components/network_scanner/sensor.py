"""The main sensor entity for the network scanner."""
import logging
import nmap
from datetime import timedelta
from homeassistant.helpers.entity import Entity
from .const import DOMAIN, EVENT_SCAN_STARTED, EVENT_SCAN_COMPLETED, CONF_PRIVILEGED

SCAN_INTERVAL = timedelta(minutes=15)

_LOGGER = logging.getLogger(__name__)

class NetworkScanner(Entity):
    """Representation of a Network Scanner."""

    def __init__(self, hass, ip_range, mac_mapping):
        """Initialize the sensor."""
        self._state = None
        self.hass = hass
        self.ip_range = ip_range

        _LOGGER.debug("Initializing NetworkScanner with IP range: %s", ip_range)
        _LOGGER.debug("MAC mapping input (raw): %s", mac_mapping)
        self.mac_mapping = self.parse_mac_mapping(mac_mapping)
        _LOGGER.debug("MAC mapping parsed result: %s", self.mac_mapping)

        try:
            self.nm = nmap.PortScanner()
            _LOGGER.info("Nmap scanner initialized successfully")
        except Exception as e:
            _LOGGER.error("Failed to initialize Nmap scanner: %s", str(e))
            raise

        # Add this entity to the domain's entity list for service handling
        if DOMAIN not in hass.data:
            hass.data[DOMAIN] = {}
        if "entities" not in hass.data[DOMAIN]:
            hass.data[DOMAIN]["entities"] = []
        hass.data[DOMAIN]["entities"].append(self)

    async def async_will_remove_from_hass(self):
        """Run when entity will be removed from hass."""
        # Remove this entity from the domain's entity list
        if DOMAIN in self.hass.data and "entities" in self.hass.data[DOMAIN]:
            if self in self.hass.data[DOMAIN]["entities"]:
                self.hass.data[DOMAIN]["entities"].remove(self)

    @property
    def should_poll(self):
        return True

    @property
    def unique_id(self):
        return f"network_scanner_{self.ip_range}"

    @property
    def name(self):
        return 'Network Scanner'

    @property
    def state(self):
        return self._state

    @property
    def unit_of_measurement(self):
        return 'Devices'

    async def async_update(self):
        """Fetch new state data for the sensor."""
        try:
            _LOGGER.debug("Starting network scan for range: %s", self.ip_range)
            
            # Fire scan started event
            self.hass.bus.async_fire(EVENT_SCAN_STARTED)
            
            # Perform the scan
            devices = await self.hass.async_add_executor_job(self.scan_network)
            self._state = len(devices)
            
            # Log detailed device information
            _LOGGER.debug("Scan complete. Found %d devices:", len(devices))
            for device in devices:
                _LOGGER.debug("Device details: IP: %s, MAC: %s, Name: %s, Type: %s, Hostname: %s, Vendor: %s",
                            device.get('ip', 'N/A'),
                            device.get('mac', 'N/A'),
                            device.get('name', 'N/A'),
                            device.get('type', 'N/A'),
                            device.get('hostname', 'N/A'),
                            device.get('vendor', 'N/A'))
            
            self._attr_extra_state_attributes = {"devices": devices}
            
            # Fire scan completed event
            self.hass.bus.async_fire(EVENT_SCAN_COMPLETED)
            
        except Exception as e:
            _LOGGER.error("Error during network scan update: %s", str(e))
            _LOGGER.exception("Full traceback:")
            # Fire scan completed event even on error
            self.hass.bus.async_fire(EVENT_SCAN_COMPLETED)

    def parse_mac_mapping(self, mapping_string):
        """Parse the MAC mapping string into a dictionary."""
        mapping = {}
        _LOGGER.debug("Starting MAC mapping parse")
        
        if not mapping_string:
            _LOGGER.warning("Empty MAC mapping string provided")
            return mapping
            
        for line in mapping_string.split('\n'):
            if not line.strip():
                continue
                
            _LOGGER.debug("Processing mapping line: %s", line)
            parts = line.split(';')
            if len(parts) >= 3:
                mac = parts[0].lower()
                mapping[mac] = (parts[1], parts[2])
                _LOGGER.debug("Added mapping: %s -> (%s, %s)", mac, parts[1], parts[2])
            else:
                _LOGGER.warning("Invalid mapping line (skipped): %s", line)
                
        return mapping

    def get_device_info_from_mac(self, mac_address):
        """Retrieve (device_name, device_type) from the MAC mapping."""
        if not mac_address:
            _LOGGER.debug("Empty MAC address provided to get_device_info_from_mac")
            return ("Unknown Device", "Unknown Device")
            
        result = self.mac_mapping.get(mac_address.lower(), ("Unknown Device", "Unknown Device"))
        _LOGGER.debug("MAC lookup: %s -> %s", mac_address, result)
        return result

    def scapy_arp_scan(self, ip_list, interface=None):
        """Perform an ARP scan for the given list of IP addresses."""
        _LOGGER.debug("Starting Scapy ARP scan for IPs: %s", ip_list)
        
        if not ip_list:
            _LOGGER.debug("Empty IP list provided for ARP scan")
            return {}

        try:
            conf.verb = 0
            ips_string = " ".join(ip_list)
            _LOGGER.debug("Creating ARP request for IPs: %s", ips_string)

            _LOGGER.debug("Sending ARP requests with timeout=2, interface=%s", interface)
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips_string),
                timeout=2,
                iface=interface,
                inter=0.1
            )

            _LOGGER.debug("ARP scan complete. Answered packets: %d, Unanswered: %d",
                         len(ans), len(unans))

            found_macs = {}
            for send_pkt, recv_pkt in ans:
                ip = recv_pkt.psrc
                mac = recv_pkt.src
                found_macs[ip] = mac
                _LOGGER.debug("ARP response: IP %s -> MAC %s", ip, mac)

            # Log IPs that didn't respond
            for pkt in unans:
                _LOGGER.debug("No ARP response from IP: %s", pkt[1].pdst)

            return found_macs

        except Exception as e:
            _LOGGER.error("Error during ARP scan: %s", str(e))
            _LOGGER.exception("Full traceback:")
            return {}

    def scan_network(self):
        """Scan the network with Nmap, then fill missing MACs via Scapy ARP."""
        _LOGGER.debug("Starting network scan with Nmap")
        
        try:
            privileged = self.hass.data[DOMAIN].get(CONF_PRIVILEGED, False)
            scan_args = "--privileged -sn -PR" if privileged else "-sn -PR"
            _LOGGER.debug("Nmap scan arguments: %s", scan_args)

            _LOGGER.debug("Starting Nmap scan for hosts: %s", self.ip_range)
            self.nm.scan(hosts=self.ip_range, arguments=scan_args)
            _LOGGER.debug("Nmap scan complete. Found hosts: %s", self.nm.all_hosts())

            devices = []
            hosts_without_mac = []

            for host in self.nm.all_hosts():
                _LOGGER.debug("Processing Nmap results for host: %s", host)
                addresses = self.nm[host].get('addresses', {})
                _LOGGER.debug("Raw address data for %s: %s", host, addresses)
                
                ip = addresses.get('ipv4', host)
                mac = addresses.get('mac')
                hostname = self.nm[host].hostname()
                vendor = "Unknown"

                if mac:
                    _LOGGER.debug("MAC found via Nmap for %s: %s", ip, mac)
                    if 'vendor' in self.nm[host] and mac in self.nm[host]['vendor']:
                        vendor = self.nm[host]['vendor'][mac]
                        _LOGGER.debug("Vendor found: %s", vendor)
                    device_name, device_type = self.get_device_info_from_mac(mac)
                else:
                    _LOGGER.debug("No MAC found via Nmap for %s", ip)
                    hosts_without_mac.append(ip)
                    device_name, device_type = ("Unknown Device", "Unknown Device")

                devices.append({
                    "ip": ip,
                    "mac": mac if mac else None,
                    "name": device_name,
                    "type": device_type,
                    "vendor": vendor,
                    "hostname": hostname,
                })

            if hosts_without_mac:
                _LOGGER.debug("Attempting ARP fallback for %d hosts without MAC", len(hosts_without_mac))
                found_macs = self.scapy_arp_scan(hosts_without_mac)
                _LOGGER.debug("ARP scan results: %s", found_macs)

                for dev in devices:
                    if dev["mac"] is None and dev["ip"] in found_macs:
                        mac = found_macs[dev["ip"]]
                        _LOGGER.debug("Found MAC via ARP for %s: %s", dev["ip"], mac)
                        dev["mac"] = mac
                        device_name, device_type = self.get_device_info_from_mac(mac)
                        dev["name"] = device_name
                        dev["type"] = device_type
                    elif dev["mac"] is None:
                        _LOGGER.warning("Failed to resolve MAC for IP %s via both Nmap and ARP", dev["ip"])

            devices.sort(key=lambda x: [int(num) for num in x['ip'].split('.') if num.isdigit()])
            return devices

        except Exception as e:
            _LOGGER.error("Error during network scan: %s", str(e))
            _LOGGER.exception("Full traceback:")
            return []

async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up the Network Scanner sensor from a config entry."""
    ip_range = config_entry.data.get("ip_range")
    _LOGGER.debug("Setting up NetworkScanner with IP range: %s", ip_range)
    
    mac_mappings_list = []
    
    # Process MAC mappings
    for i in range(25):
        key = f"mac_mapping_{i+1}"
        mac_mapping = config_entry.data.get(key, "")
        mac_mappings_list.append(mac_mapping)
        _LOGGER.debug("MAC mapping %d: %s", i+1, mac_mapping)

    # Additional mappings
    i = 25
    while True:
        key = f"mac_mapping_{i+1}"
        if key in config_entry.data:
            mac_mapping = config_entry.data.get(key)
            mac_mappings_list.append(mac_mapping)
            _LOGGER.debug("Additional MAC mapping %d: %s", i+1, mac_mapping)
            i += 1
        else:
            break

    mac_mappings = "\n".join(mac_mappings_list)
    _LOGGER.debug("Combined MAC mappings: %s", mac_mappings)

    try:
        scanner = NetworkScanner(hass, ip_range, mac_mappings)
        async_add_entities([scanner], True)
        _LOGGER.info("NetworkScanner entity added successfully")
    except Exception as e:
        _LOGGER.error("Failed to create NetworkScanner: %s", str(e))
        _LOGGER.exception("Full traceback:")
