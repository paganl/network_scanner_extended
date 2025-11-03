# Network Scanner Extended

A Home Assistant custom integration that discovers devices on your network by combining **ARP/DHCP sources** (e.g., OPNsense, AdGuard Home) with optional **nmap** probing. Results are **merged**, **enriched**, and exposed as a single sensor with a detailed `devices` attribute (Schema **v2**).

> Works well in routed/VLAN environments when your ARP/DHCP source has visibility across segments.

---

## Highlights

* **Multiple providers** (pick one):

  * **OPNsense** ARP table (API)
  * **AdGuard Home** DHCP/clients (HTTP API)
  * *(Optional / planned)* UniFi Controller for Wi-Fi metadata
* **nmap** (optional) ping sweep to find additional hosts & vendor/hostname
* **Schema v2** device records with optional fields (RSSI, VLAN, tags, notes, etc.)
* **MAC Directory v2** for human-friendly overrides (names, types, tags, notes)
* A **“Scan Now”** button + periodic auto scans
* Safe, non-blocking updates using Home Assistant’s dispatcher

---

## Requirements

* Home Assistant 2024.8+ (recommended)
* `python-nmap` (installed via manifest)
* For providers:

  * **OPNsense**: API key & secret, API reachable from HA
  * **AdGuard Home**: UI/HTTP username & password, HTTP reachable from HA

---

## Installation

1. Copy the integration into:

   ```
   config/custom_components/network_scanner/
   ```
2. Restart Home Assistant.
3. In **Settings → Devices & Services** click **Add Integration** → search for **Network Scanner Extended**.

> If upgrading from an older fork with a different domain/folder, remove the old one first.

---

## Configuration

### Quick Start

1. **IP ranges** (CIDRs): e.g. `10.0.0.0/24, 10.0.1.0/24`
2. **nmap args** (optional): defaults to

   ```
   -sn -PE -PS22,80,443 -PA80,443 -PU53 -T4
   ```

   Set **scan interval (min)** to `0` if you only want manual scans.
3. **Provider**: choose **OPNsense** or **AdGuard Home** and fill in credentials/URL.
4. Optionally set **MAC Directory** JSON (inline or URL) for naming/typing devices.
5. Save. Use the **Scan Now** button or wait for the next interval.

### Providers

#### OPNsense (ARP)

* **URL**: e.g. `https://10.0.0.2`
* **Key/Secret**: API key pair
* **Interface**: optional (e.g. `lan`, `vlan30`)
* **Verify TLS**: enable if you use a valid certificate (disable for self-signed)

The integration tries `/api/diagnostics/interface/search_arp` (and a few variants). If you can curl it successfully, HA should work with the same base URL/creds.

#### AdGuard Home (DHCP/Clients)

* **URL**: e.g. `http://10.2.0.3:3000`
* **User/Pass**: AdGuard UI credentials
* Endpoints used (in order):

  1. `/control/dhcp/status` (preferred; merges `leases` and `static_leases`)
  2. `/control/dhcp/leases` (fallback)
  3. `/control/clients` (last resort; may miss MACs)

> If you run AdGuard add-on in HA: the HTTP port shown in AdGuard’s “About” page (e.g. `45158`) might be different from the docker-exposed port (e.g. `3000`). Use whichever **works with curl**.

---

## Entities

* **Sensor**: `sensor.network_scanner`

  * `state`: device count
  * `attributes`:

    * `status`: `idle | scanning | enriching | ok | error`
    * `phase`: `idle | arp | nmap`
    * `last_scan_started`, `last_scan_finished` (ISO 8601)
    * `devices`: list of **Schema v2** records (see below)

* **Sensor (status)**: `sensor.network_scanner_status`
  Diagnostic mirror of status/timing/metrics.

* **Button**: `button.network_scanner_scan_now`
  Immediate scan (works regardless of auto-scan interval).

---

## Device Schema (v2)

Every entry in `attributes.devices` is a merged, normalized record. Not every field is always present.

| Field        | Type          | Example                    | Notes                                     |
| ------------ | ------------- | -------------------------- | ----------------------------------------- |
| `ip`         | string        | `"10.0.0.42"`              | IP at time of scan (IP-keyed merge).      |
| `mac`        | string        | `"AA:BB:CC:DD:EE:FF"`      | Upper-case, normalized.                   |
| `hostname`   | string        | `"laptop.local"`           | From nmap/ARP when available.             |
| `vendor`     | string        | `"Apple, Inc."`            | From nmap vendor map (needs MAC).         |
| `name`       | string        | `"Paul’s MacBook"`         | **Override** from MAC Directory.          |
| `type`       | string        | `"Laptop"`                 | **Override** from MAC Directory (`desc`). |
| `source`     | string[]      | `["arp","nmap","adguard"]` | Union of providers.                       |
| `first_seen` | ISO8601       | `"2025-10-24T12:01:33Z"`   | When first observed.                      |
| `last_seen`  | ISO8601       | `"2025-10-24T12:05:02Z"`   | Updated each scan.                        |
| `is_wired`   | bool | null   | `false`                    | From UniFi (planned).                     |
| `ssid`       | string | null | `"Home-24"`                | From UniFi (planned).                     |
| `ap_name`    | string | null | `"Landing-AP"`             | From UniFi (planned).                     |
| `rssi`       | number | null | `-58`                      | From UniFi (planned).                     |
| `vlan`       | number | null | `30`                       | From UniFi/provider when available.       |
| `tags`       | string[]      | `["work","primary"]`       | From MAC Directory.                       |
| `notes`      | string | null | `"Do not block"`           | From MAC Directory.                       |

**Backwards compatibility**: v1 fields remain (`ip`, `mac`, `hostname`, `vendor`, `name`, `type`, `source`). `source` is always a list in v2.

---

## MAC Directory (v2)

Use a MAC → data map to label devices. You can paste JSON into the options page or point to a URL. All MAC keys are case-insensitive; they are normalized internally.

Supported shapes:

**Flat:**

```json
{
  "11:22:33:44:55:66": "Kitchen Display"
}
```

**Object:**

```json
{
  "AA:BB:CC:DD:EE:FF": {
    "name": "Paul’s MacBook",
    "desc": "Laptop",
    "tags": ["work", "primary"],
    "notes": "Pinned to VLAN30"
  }
}
```

**Wrapped:**

```json
{
  "data": {
    "AA:BB:CC:DD:EE:FF": {
      "name": "Paul’s MacBook",
      "desc": "Laptop"
    }
  }
}
```

**Field mapping:**

* `name` → device `name`
* `desc` → device `type`
* `tags` (array) → device `tags`
* `notes` → device `notes`

---

## Tips & Examples

### CIDR examples

* Single /24: `10.0.0.0/24`
* Multiple ranges: `10.0.0.0/24,10.0.1.0/24`
* Whole 10/8 (big!): `10.0.0.0/8` *(expect long scans)*

### “nmap only” vs “ARP/DHCP only”

* **ARP/DHCP only**: leave nmap args empty in options
* **nmap only**: set provider to `none` and provide ranges

### Manual-only scans

Set **scan interval** to `0` and use the **Scan Now** button.

---

## Troubleshooting

### “No devices added” but provider shows devices

* Confirm provider with `curl`:

  * **OPNsense**

    ```bash
    curl -ksu KEY:SECRET https://10.0.0.2/api/diagnostics/interface/search_arp
    ```
  * **AdGuard Home** (try all)

    ```bash
    curl -sS -u user:pass http://ADG:PORT/control/dhcp/status
    curl -sS -u user:pass http://ADG:PORT/control/dhcp/leases
    curl -sS -u user:pass http://ADG:PORT/control/clients
    ```
* If curl works but HA returns nothing:

  * Check **URL/port** matches your working curl.
  * Toggle **Verify TLS** off for self-signed HTTPS.
  * Ensure your **IP ranges** actually include the devices (the integration filters provider data to the configured CIDRs).

### “Scan button doesn’t update the sensor”

* Make sure you updated to the dispatcher-based sensor. Entities should update immediately after each phase. If stuck, reload the integration from **Settings → Devices & Services** (three-dot menu → Reload).

### “Detected calls from thread other than the event loop”

* Ensure you’re on current code. The integration uses `loop.call_soon_threadsafe` for dispatcher emits and avoids calling HA APIs from executor threads.

### Logging

Add this to `configuration.yaml` to increase verbosity:

```yaml
logger:
  default: warning
  logs:
    custom_components.network_scanner: debug
    custom_components.network_scanner.controller: debug
    custom_components.network_scanner.opnsense: debug
    custom_components.network_scanner.adguard: debug
```

Restart HA and check **Settings → System → Logs**.

---

## Known Limitations

* IP-keyed merge can duplicate the same MAC if it changes IP within a scan window (rare).
* nmap accuracy varies by network, firewalls, and host OS.
* AdGuard `/control/clients` may not provide MACs in all setups; use DHCP endpoints or OPNsense when possible.
* UniFi enrichment is planned; fields appear when provider is enabled and data is available.

---

## FAQ

**Q: Can I keep my old template sensor?**
A: You shouldn’t need it. The primary sensor exposes `devices` directly. If you have a legacy dashboard, you can down-map v2 fields.

**Q: Do I need to enable both provider and nmap?**
A: No. You can use provider-only (fast & cross-VLAN) or nmap-only (slower) or both (best coverage).

**Q: My AdGuard add-on shows port 45158 but curl works on 3000 — which is it?**
A: Use whichever port works with curl from your HA container/host. The integration just uses the URL you provide.

---

## Development Notes

* Domain: `network_scanner`
* Platforms: `sensor`, `button`
* Dispatcher signal: `network_scanner_extended_updated`
* Schema v2 maintained in controller; MAC Directory v2 parsed with support for flat/object/wrapped inputs.

---

## Changelog (highlights)

* **v0.10.x**: AdGuard provider; dispatcher-based updates; Schema v2; MAC Directory v2; thread-safe fixes.
* **Earlier**: OPNsense provider; options flow; scan button; nmap integration.

---

## License

MIT

---

## Credits

* Inspired by community scanners and extended for multi-provider enrichment.
* Thanks to testers for logs, ranges, and edge-case endpoints.

---

If you want me to tailor the README to your exact repo structure (badges, screenshots, example dashboards), just share the preferred titles/links and I’ll add them.
