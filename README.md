<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>

  <h1 align="center">Network Scanner Extended (Home Assistant)</h1>

  <p align="center">
    <img alt="Network Scanner Extended" src="images/logo.svg" width="360" />
  </p>

  <p>
    <strong>Network Scanner Extended</strong> is an unofficial custom integration for
    Home Assistant that discovers devices across one or more subnets, enriches them with
    optional ARP and user directory data, and exposes compact sensor entities suitable for
    dashboards and automations.
  </p>

  <h2>Features</h2>
  <ul>
    <li>Scans one or multiple CIDR ranges (e.g. <code>10.0.0.0/24 10.0.3.0/24</code>).</li>
    <li><strong>Two-phase scan</strong> (optional): fast ARP via OPNsense, then nmap merge.</li>
    <li>Attributes include full device list with <em>ip, mac, hostname, vendor, name, type, source</em>.</li>
    <li>Directory enrichment by MAC from JSON (inline or URL, e.g. <code>/local/devices.json</code>).</li>
    <li>Manual <em>Scan Now</em> button + configurable auto scan interval (minutes; 0 = manual only).</li>
    <li>Works locally on your LAN; no cloud calls.</li>
  </ul>

  <h2>Requirements</h2>
  <ul>
    <li>Home Assistant (any install type).</li>
    <li><code>nmap</code> binary available to HA if you enable nmap scanning.
      <br/>The integration uses <em>python-nmap</em> which shells out to the system <code>nmap</code>.
    </li>
    <li>(Optional) OPNsense if you want ARP-based discovery across VLANs.</li>
  </ul>

  <h2>Why nmap often can’t give MACs on VLANs</h2>
  <p>
    nmap discovers hosts using ICMP/TCP/UDP probes (<em>Layer-3</em>). Getting a device’s MAC address
    requires <em>Layer-2</em> knowledge (ARP/ND), which only exists on the local broadcast domain.
    When HA is on VLAN A and you scan VLAN B, packets traverse a router; HA cannot see VLAN B’s ARP
    traffic, so nmap returns hosts but usually <em>without MAC addresses</em>. That’s why this
    integration can use an ARP provider (your router/firewall) to obtain correct IP→MAC mappings
    across VLANs, then merge them with nmap results.
  </p>

  <h2>Installation</h2>
  <h3>Manual</h3>
  <ol>
    <li>Copy the folder <code>custom_components/network_scanner_extended/</code> into your
        Home Assistant <code>config/custom_components/</code> directory.</li>
    <li>Restart Home Assistant.</li>
    <li>Go to <em>Settings → Devices &amp; Services → Add Integration</em> and search
        for “Network Scanner Extended”.</li>
  </ol>

  <h3>HACS (optional)</h3>
  <ol>
    <li>Add this repository to HACS as a custom repository.</li>
    <li>Install, then restart Home Assistant.</li>
    <li>Add the integration from <em>Devices &amp; Services</em>.</li>
  </ol>

  <h2>Configuration (in the UI)</h2>
  <ul>
    <li><strong>IP Range</strong> — One or more CIDRs separated by space or comma
      (e.g. <code>10.0.0.0/24, 10.0.3.0/24</code>).</li>
    <li><strong>Scan Interval (minutes)</strong> — <code>0</code> disables auto-scan; use the button to scan manually.</li>
    <li><strong>nmap args</strong> — Default:
      <code>-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4</code>.
      <br/>This is a fast “ping” sweep using multiple probe types to improve detection across subnets.
    </li>
    <li><strong>ARP Provider</strong> — <code>none</code> or <code>opnsense</code>.</li>
    <li><strong>OPNsense URL</strong> — e.g. <code>http://10.0.0.2</code> (base URL, no trailing slash)</li>
    <li><strong>OPNsense Key / Secret</strong> — API credentials.</li>
    <li><strong>OPNsense Interface</strong> — Optional. If set, the ARP API is filtered server-side to one interface.</li>
    <li><strong>Directory JSON (text)</strong> — Paste a JSON map keyed by MAC to enrich device names/types.</li>
    <li><strong>Directory JSON URL</strong> — Or host the same JSON at a URL (e.g. <code>http://HA-IP:8123/local/devices.json</code>).</li>
  </ul>

  <h3>Directory JSON schema (enrichment)</h3>
  <p>The integration accepts either a flat map or an object map, optionally wrapped in <code>data</code>:</p>
  <pre><code>{
  "AA:BB:CC:DD:EE:FF": "Kitchen Display",
  "11:22:33:44:55:66": { "name": "Paul’s iPhone", "desc": "User VLAN" }
}</code></pre>
  <p>Or:</p>
  <pre><code>{
  "data": {
    "AA:BB:CC:DD:EE:FF": "Kitchen Display",
    "11:22:33:44:55:66": { "name": "Paul’s iPhone", "desc": "User VLAN" }
  }
}</code></pre>

  <h3>Serving JSON from your HA filesystem</h3>
  <p>
    Any file under <code>&lt;config&gt;/www/</code> is publicly available under
    <code>/local/</code>. Example:
  </p>
  <ul>
    <li>File: <code>&lt;config&gt;/www/devices.json</code></li>
    <li>URL: <code>http://&lt;HA_IP&gt;:8123/local/devices.json</code></li>
  </ul>

  <h2>How it works (async, two-phase)</h2>
  <ol>
    <li><strong>Phase 1 — ARP (optional):</strong> If ARP provider = OPNsense, the integration calls
      <code>/api/diagnostics/interface/search_arp</code> with your key/secret, parses the ARP table, filters it to the configured
      IP ranges, enriches with your directory JSON, and <em>publishes immediately</em> with status
      <code>enriching</code> (phase <code>arp</code>).
    </li>
    <li><strong>Phase 2 — nmap (optional):</strong> Each configured CIDR is scanned with the chosen
      nmap arguments. Results are merged with ARP (filling in missing MACs where available),
      then enriched again by directory JSON. Final state is published with status <code>ok</code>
      (phase <code>nmap</code>).
    </li>
  </ol>
  <p>
    If <strong>Scan Interval = 0</strong>, auto-scans are disabled. Use the
    <em>Scan Now</em> button entity to run a scan on demand.
  </p>

  <h2>Entities created</h2>

  <h3>Sensor: <code>Network Scanner Extended</code></h3>
  <ul>
    <li><strong>State:</strong> number of devices.</li>
    <li><strong>Attributes:</strong>
      <ul>
        <li><code>status</code> — <code>idle | scanning | enriching | ok | error</code></li>
        <li><code>phase</code> — <code>idle | arp | nmap</code></li>
        <li><code>ip_ranges</code> — list of CIDRs</li>
        <li><code>nmap_args</code>, <code>scan_interval</code></li>
        <li><code>last_scan_started</code>, <code>last_scan_finished</code> (ISO timestamps)</li>
        <li><code>counts_by_segment</code>, <code>counts_by_source</code></li>
        <li><code>devices</code> — array of:
          <pre><code>{
  "ip": "10.0.3.24",
  "mac": "F0:05:1B:14:6A:A3",
  "hostname": "Pauls-Z-Flip6",
  "vendor": "Samsung Electronics Co.,Ltd",
  "name": "Paul’s Phone",     // from directory JSON if provided
  "type": "USER",             // from directory JSON (desc) if provided
  "source": ["arp","nmap"]    // which sources saw it
}</code></pre>
        </li>
      </ul>
    </li>
  </ul>

  <h3>Sensor: <code>Network Scanner Extended Status</code></h3>
  <ul>
    <li><strong>State:</strong> <code>idle | scanning | enriching | ok | error</code>.</li>
    <li>Attributes mirror the status-related attributes listed above.</li>
  </ul>

  <h3>Button: <code>Scan Now</code></h3>
  <ul>
    <li>Triggers an immediate two-phase scan regardless of the configured scan interval.</li>
  </ul>

  <h2>Defaults &amp; recommendations</h2>
  <ul>
    <li><strong>nmap args default:</strong>
      <code>-sn -PE -PS22,80,443 -PA80,443 -PU53 -T4</code> — a lean “host discovery” sweep:
      <ul>
        <li><code>-sn</code> host discovery only (no port scans).</li>
        <li><code>-PE</code> ICMP Echo, <code>-PS</code> TCP SYN, <code>-PA</code> TCP ACK, <code>-PU</code> UDP 53.</li>
        <li><code>-T4</code> faster timing.</li>
      </ul>
      Tune this if your network blocks certain probes (e.g. drop <code>-PE</code> if ICMP is filtered).
    </li>
    <li>If you have multiple VLANs, enable the OPNsense ARP provider for accurate MACs across segments.</li>
    <li>Set a scan interval that fits your environment. nmap over large ranges can take minutes; 10–30 minutes is typical. Set to 0 for manual only.</li>
  </ul>

  <h2>Troubleshooting</h2>
  <ul>
    <li><strong>No MACs on other VLANs:</strong> Enable the OPNsense ARP provider (and optionally set the interface). nmap alone cannot see L2 info across VLANs.</li>
    <li><strong>OPNsense returns HTML / 302:</strong> Use the <em>API</em> endpoint:
      <code>/api/diagnostics/interface/search_arp</code>. Provide API Key/Secret. The base URL should be like
      <code>http://10.0.0.2</code> or <code>https://10.0.0.2</code> (no trailing slash). Self-signed certs are handled.</li>
    <li><strong>nmap “not found”:</strong> Ensure the <code>nmap</code> binary is installed in the HA environment.</li>
    <li><strong>Directory JSON not applied:</strong> Validate JSON format, check MAC capitalization and colon format
      (e.g. <code>AA:BB:CC:DD:EE:FF</code>), and if using a URL under <code>www/</code> use
      <code>http://&lt;HA_IP&gt;:8123/local/devices.json</code>.</li>
    <li><strong>Long scans “took longer than interval”:</strong> Increase the scan interval minutes, reduce the number of CIDRs,
      or rely more on ARP phase for quick visibility.</li>
  </ul>

  <h2>Privacy &amp; security</h2>
  <ul>
    <li>All discovery runs locally on your network.</li>
    <li>OPNsense API credentials are stored in Home Assistant’s config storage. Treat them as secrets.</li>
    <li>Files under <code>/local/</code> (i.e. <code>config/www</code>) are publicly readable to anyone who can reach your HA URL.</li>
  </ul>

  <h2>License</h2>
  <p>MIT</p>

</body>
</html>
