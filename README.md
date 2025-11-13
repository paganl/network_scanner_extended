Here you go — a complete, polished **README.md** for your Home Assistant custom integration.

---

# Network Scanner (Home Assistant custom integration)

Lightweight network inventory for Home Assistant that **discovers devices** from one or more sources (OPNsense, UniFi, AdGuard), **merges** them into a single view, and **enriches** each device with useful metadata (VLAN, site, role, first/last seen, risk score, etc.).
Exposes a single sensor with rich attributes designed to be **easy to template** in dashboards and automations.

---

## ✨ Features

* **Multiple providers**

  * **OPNsense** (ARP/ND diagnostics API)
  * **UniFi** (clients/stations API; UniFi OS and pre-OS paths supported)
  * **AdGuard Home** (DHCP leases)
* **Merge & de-duplicate** by MAC (fallback to IP): aggregates IPs, prefers non-empty hostname/vendor, keeps per-provider blocks
* **Derived context**

  * `vlan_id` from UniFi or interface name (OPNsense)
  * `device_type` (`wifi`/`wired`) from UniFi
  * `site` from UniFi
  * `network_role` from OPNsense interface description (if present)
* **Lifecycle tracking** (per entry)

  * `first_seen` / `last_seen`
  * `derived.new_device` on first sighting
  * `derived.stale` if not seen for 24h (configurable in code)
* **Simple risk score** (0–100) for quick triage
* **Dashboard-friendly attributes**

  * `devices` (full detail)
  * `flat` (table-ready view)
  * `index` (lookup by MAC/IP → row)
  * `summary` (counts by vendor/VLAN)

---

## 🧩 Entity model

The integration creates **one sensor** (e.g. `sensor.network_scanner_devices`) whose **state** is the number of merged devices and whose **attributes** include:

```yaml
devices:                # full, structured list; one item per merged device
  - mac: "D8:3A:DD:E4:88:DD"
    ips: ["10.0.0.3", ...]          # all known IPs
    hostname: "Home Assistant"
    vendor: "Raspberry Pi Trading Ltd"
    device_type: "wired" | "wifi" | "unknown"
    vlan_id: 3 | null
    network_role: "iot" | "guest" | "media" | ""  # from OPNsense intf desc, if available
    interface: "vlan0.3" | ""        # from OPNsense
    site: "67e68f05..." | null       # from UniFi
    tags: ["opnsense", "unifi"]      # sources the device came from
    sources: ["opnsense", "unifi"]

    # Provider blocks (if available)
    opnsense:
      intf: "vlan0.3"
      intf_description: "iot"
      ... (depends on firmware/endpoint)
    unifi:
      is_wired: true|false
      ap_mac: "9c:05:d6:..."
      bssid: "..."
      essid: "MORSON-N"
      rssi: 44
      rx_rate_mbps: 1201000
      tx_rate_mbps: 1201000
      oui: "Vendor"
      uptime_s: 879921
      is_guest: false
      vlan: 3
      site: "67e68f05..."
      sw_mac: "9c:05:d6:..."
      sw_port: 7
    adguard:
      # if provider returns extra fields in future

    # Lifecycle + scoring
    first_seen: "2025-11-13T12:09:56.848034+00:00"
    last_seen:  "2025-11-13T12:10:06.730368+00:00"
    derived:
      new_device: false
      stale: false
      risk_score: 20

count: 40                            # equals sensor state
last_refresh_utc: "2025-11-13T12:10:06.337811+00:00"

flat:                                # table-ready list for dashboards
  - hostname: "Home Assistant"
    ip: "10.0.0.3"
    mac: "D8:3A:DD:E4:88:DD"
    vendor: "Raspberry Pi Trading Ltd"
    role: ""                         # from network_role
    vlan_id: 3 | null
    type: "wired" | "wifi" | "unknown"
    site: "67e68f05..." | ""
    new: false
    risk: 20
    first_seen: "..."
    last_seen: "..."
    source_str: "opnsense,unifi"

index:
  mac: { "D8:3A:DD:E4:88:DD": 14, ... } # MAC → flat index
  ip:  { "10.0.0.3": 14, ... }          # IP  → flat index

summary:
  vendors: { "Amazon Technologies Inc.": 6, "Unknown": 13, ... }
  vlans:   { "2": 22, "3": 6, "4": 7, None: 5 }
```

> **Tip:** use `flat` for rendering tables and simple conditions. Use `devices` when you need the rich per-provider data.

---

## 🔎 Risk scoring

Defined in code as a simple additive score:

* **+30** if `vendor` is empty/unknown
* **+20** if `device_type == "wifi"` **and** `network_role` not in `{ "iot", "guest", "media" }`
* **+10** if `derived.new_device == true`
* **+5**  if `network_role == "guest"`
* Clamped to **0…100**

You can tune weights in `coordinator.py::_risk_score`.

---

## 🔧 Installation

### HACS (recommended)

1. Add this repository as a **Custom Repository** in HACS (Category: Integration).
2. Install **Network Scanner**.
3. Restart Home Assistant.
4. Go to **Settings → Devices & Services → Add Integration** and search for **Network Scanner**.

### Manual

1. Copy this repo into `<config>/custom_components/network_scanner/`

   ```
   custom_components/
     network_scanner/
       __init__.py
       coordinator.py
       sensor.py
       const.py
       manifest.json
       provider/
         __init__.py
         opnsense.py
         unifi.py
         adguard.py
   ```
2. Restart Home Assistant.
3. Add the integration via **Settings → Devices & Services**.

---

## ⚙️ Configuration

Open **Settings → Devices & Services → Network Scanner → Configure**.

### Common options

* **Provider**: `opnsense`, `unifi`, `adguard`, or `opnsense_unifi`
* **Interval (minutes)**: Poll cadence (default **3**)
* **Verify SSL**: Enable if your endpoints have valid certificates; disable for self-signed lab setups

### OPNsense options

* **Base URL**: e.g. `https://opnsense.local` (the code will add `/api` if needed)
* **Key** / **Secret**: API key/secret
* **Permissions**: grant your API key read access to **Diagnostics → ARP Table** (and related diagnostics as required by your firmware)

> The integration tries **POST** `/diagnostics/interface/search_arp` first, then falls back to multiple legacy **GET** endpoints seen across releases.

### UniFi options

* **Base URL**: e.g. `https://unifi.local` or `https://<controller-ip>`
* **Auth**: either:

  * **Token** (recommended): paste a valid Bearer token; or
  * **Username / Password** (the integration will login and use cookies)
* **Paths**: the integration tries both UniFi OS and pre-OS endpoints:

  * `/api/s/default/stat/sta`
  * `/proxy/network/api/s/default/stat/sta`
    (and similar fallbacks for `list/clients`)

### AdGuard options

* **Base URL**: e.g. `http://adguard.local:3000`
* **Username / Password**: AdGuard UI credentials

---

## 🖥️ Dashboards & templates

### A. Markdown table card (works in Lovelace)

```yaml
type: markdown
title: Network devices
content: >-
  {% set flat = state_attr('sensor.network_scanner_devices','flat') or [] %}
  {% if flat %}
  | Hostname | IP | MAC | Vendor | Role | VLAN | Type | Site | New | Risk |
  |---|---|---|---|---|---:|---|---|:--:|---:|
  {%- for d in flat | sort(attribute='hostname') -%}
  | {{ d.hostname|default('—') }} | `{{ d.ip }}` | `{{ d.mac }}` | {{ d.vendor|default('—') }} | {{ d.role|default('—') }} | {{ d.vlan_id if d.vlan_id is not none else '—' }} | {{ d.type|default('—') }} | {{ d.site|default('—') }} | {{ '✓' if d.new else '' }} | {{ d.risk|int }}
  {%- endfor -%}
  {% else %}
  _No devices yet._
  {% endif %}
```

> If your entity id differs, replace `sensor.network_scanner_devices` accordingly (check **Developer Tools → States**).

### B. “New device” alert (one-shot on first sighting)

```yaml
alias: Alert on new network device
mode: single
trigger:
  - platform: template
    value_template: >
      {% set flat = state_attr('sensor.network_scanner_devices','flat') or [] %}
      {{ (flat | selectattr('new','eq', true) | list | length) > 0 }}
action:
  - service: persistent_notification.create
    data:
      title: "New device detected"
      message: >
        {% for d in (state_attr('sensor.network_scanner_devices','flat') or []) if d.new -%}
        • {{ d.hostname or d.mac }} ({{ d.ip }}) VLAN={{ d.vlan_id | default('—') }} Risk={{ d.risk }}
        {% endfor %}
```

### C. High-risk devices badge

```yaml
type: entity
entity: sensor.network_scanner_devices
name: High-risk devices
attribute: count
state_color: true
# Use a template sensor to compute the number:
template:
  - sensor:
      - name: network_scanner_high_risk_count
        state: >-
          {% set flat = state_attr('sensor.network_scanner_devices','flat') or [] %}
          {{ flat | selectattr('risk','ge', 50) | list | length }}
```

---

## 🔁 Merging rules (how devices are unified)

1. **Key:** prefer `MAC` (uppercased). If missing, use `IP:` prefix (e.g., `IP:10.0.0.5`).
2. **IPs:** union into `ips[]` (sorted).
3. **Hostname/Vendor:** take the first non-empty seen across sources.
4. **Provider blocks:** attach `opnsense`, `unifi`, `adguard` sub-dicts when available.
5. **Derived values:**

   * `device_type`: `wired` if UniFi `is_wired`, else `wifi` if explicitly false, otherwise `unknown`.
   * `vlan_id`: from UniFi `vlan` (int) else parsed from interface name like `vlan0.2`.
   * `site`: from UniFi `site`.
   * `network_role`: from OPNsense interface description (if present).
6. **Tags/sources:** accumulate source names (e.g., `["opnsense","unifi"]`).

---

## 🗃️ Persistence (per entry)

A lightweight store keeps:

* `first_seen` (ISO8601 UTC)
* `last_seen` (ISO8601 UTC)
* Reserved fields for user annotations (future use): `owner`, `room`, `notes`, `tags_user`

During each refresh:

* `derived.new_device` is set **true** only the **first** time we see a key.
* `derived.stale` is true if **now − last_seen > 24h** (change `STALE_HOURS` in code).
* Timestamps are also surfaced on each `device` for easy templating.

---

## 🧪 Troubleshooting

### “All OPNsense ARP endpoints failed or returned no rows”

* Check **Base URL** (must be reachable from HA) and **Verify SSL** setting (self-signed cert?).
* Confirm **API Key/Secret** are correct.
* Ensure the API user has privileges for **Diagnostics → ARP Table** (and related diagnostics, depending on firmware).
* Try browsing to `https://<opnsense>/api/diagnostics/interface/search_arp` to confirm endpoint exists on your version.

### UniFi returns empty

* Verify **Token** (preferred) or **Username/Password** are valid.
* Controller path differences are handled, but ensure **Base URL** points to the controller (UniFi OS gateways usually require the `/proxy/network` path, which is tried automatically).
* Guest isolation may hide clients from upstream views.

### “ImportError: cannot import name 'UnitOfNone'”

* Use the integration’s **updated** `sensor.py` that does **not** import `UnitOfNone` (removed in newer HA releases).

### Markdown table looks broken

* Use the exact **whitespace-trimmed** Jinja shown above (`-{%` and `%}-`), which avoids stray blank lines that break GitHub/HA tables.
* Ensure the `flat` attribute exists (check **Developer Tools → States**).

### Enable debug logs

```yaml
logger:
  default: info
  logs:
    custom_components.network_scanner: debug
    custom_components.network_scanner.provider.opnsense: debug
    custom_components.network_scanner.provider.unifi: debug
    custom_components.network_scanner.provider.adguard: debug
```

---

## 📏 Performance & polling

* Default interval is **3 minutes**.
* Calls are lightweight: one provider request set per cycle; UniFi & OPNsense endpoints return compact JSON.
* The merge is in-memory and linear in number of rows.

---

## 🔒 Security notes

* If possible, use **HTTPS** endpoints with valid certificates and **Verify SSL** = on.
* Prefer **UniFi token** over password login.
* Treat snapshots of the sensor attributes as sensitive (they include MAC/IPs and device names).

---

## 🛠️ Development notes

* Inventory storage key is per entry: `network_scanner_inventory_<entry_id>`.
* `STALE_HOURS` currently **24** (set at top of `coordinator.py`).
* Risk scoring is in `NetworkScannerCoordinator._risk_score()`.
* VLAN derivation in `_derive_vlan_id()`.

---

## 🧰 Example: build quick helper sensors

```yaml
template:
  - sensor:
      - name: network_scanner_total
        state: "{{ state_attr('sensor.network_scanner_devices','count') or 0 }}"
      - name: network_scanner_vlan2_count
        state: >-
          {% set flat = state_attr('sensor.network_scanner_devices','flat') or [] %}
          {{ flat | selectattr('vlan_id','equalto', 2) | list | length }}
      - name: network_scanner_unknown_vendor
        state: >-
          {% set flat = state_attr('sensor.network_scanner_devices','flat') or [] %}
          {{ flat | selectattr('vendor','equalto','Unknown') | list | length }}
```

---

## ❓ FAQ

**Q: Why are some vendors “Unknown”?**
A: Depends on source. If a provider doesn’t supply an OUI/vendor (or your device randomises MACs), vendor may be blank.

**Q: Why is my device “wifi” but not “iot/guest/media”?**
A: The `network_role` is inferred from OPNsense interface description (if set). Add meaningful descriptions there to change the risk calculus.

**Q: How long is a device “new”?**
A: Exactly one refresh cycle — the first time the integration sees its key (MAC or IP).

---

## 📄 License

MIT — see `LICENSE`.

---

## 🤝 Contributing

Issues and PRs welcome. Please include:

* Your Home Assistant version
* Provider(s) used
* Redacted logs with `debug` enabled
* If OPNsense: firmware version and which ARP endpoint(s) exist on your box

---

## 🗒️ Changelog (highlights)

* **v0.14.0**

  * Per-entry inventory store
  * `first_seen` / `last_seen` surfaced on each device
  * `flat/index/summary` helper views
  * UniFi provider enrichments (`site`, switch port, rates, RSSI, etc.)
  * Robust OPNsense endpoint fallbacks
  * Risk score & stale flag

---

### Credits

Built for practical, brownfield-friendly network visibility in Home Assistant — with a focus on **simple merge logic**, **actionable metadata**, and **dashboards that don’t fight you**.
