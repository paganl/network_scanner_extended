<h1>Network Scanner Extended (Lean) – Home Assistant Custom Integration</h1>

<p>
A lightweight network inventory integration for Home Assistant. It polls one or more providers
(<b>OPNsense</b>, <b>UniFi</b>, <b>AdGuard Home</b>), merges devices into a single list (primarily by MAC),
and exposes the results as entities.
</p>

<hr/>

<h2>What this integration creates</h2>

<ul>
  <li><b>Platforms</b>: <code>sensor</code>, <code>device_tracker</code></li>
  <li><b>Services</b>:
    <ul>
      <li><code>network_scanner.rescan</code> – refresh all Network Scanner entries</li>
      <li><code>network_scanner.cleanup_entities</code> – remove orphaned <code>device_tracker</code> entities</li>
    </ul>
  </li>
</ul>

<hr/>

<h2>Entities</h2>

<h3>Sensor</h3>
<p>
The sensor platform exposes a summary view of the coordinator data. In the current build, you have a sensor that
reports the number of merged devices and includes useful attributes (e.g. a table-ready <code>flat</code> list).
</p>

<p><b>Coordinator payload keys (current)</b></p>
<ul>
  <li><code>devices</code> – merged list of devices (structured)</li>
  <li><code>count</code> – integer device count</li>
  <li><code>last_refresh_utc</code> – timestamp of last refresh</li>
  <li><code>flat</code> – flattened list suitable for dashboards/templates</li>
  <li><code>index</code> – lookup maps (MAC/IP → index)</li>
  <li><code>summary</code> – counts grouped by vendor/VLAN</li>
</ul>

<h3>Device trackers</h3>
<p>
The device tracker platform creates one <code>device_tracker</code> per device from the current coordinator snapshot.
Each tracker is registered into the device registry using the device MAC address (where available), so Home Assistant
can group related entities on the same “device page”.
</p>

<p><b>Important behavioural detail (current)</b></p>
<ul>
  <li>Trackers are created from the current snapshot during platform setup.</li>
  <li>If completely new devices appear later, you may need to reload the config entry or restart Home Assistant to create new tracker entities.</li>
  <li>The cleanup service exists to remove trackers that no longer exist in the current coordinator device list.</li>
</ul>

<hr/>

<h2>Configuration</h2>

<p>
Configuration is done through the UI (config flow). Go to:
<b>Settings → Devices &amp; Services → Add Integration → Network Scanner</b>
</p>

<h3>Common options</h3>
<ul>
  <li><b>Providers</b> (<code>providers</code>): choose any of <code>opnsense</code>, <code>unifi</code>, <code>adguard</code></li>
  <li><b>Verify SSL</b> (<code>verify_ssl</code>): whether to verify TLS certificates</li>
  <li><b>Interval (minutes)</b> (<code>interval_min</code>): polling interval</li>
</ul>

<h3>OPNsense</h3>
<ul>
  <li><code>opnsense_url</code></li>
  <li><code>key</code></li>
  <li><code>secret</code></li>
</ul>

<h3>UniFi</h3>
<ul>
  <li><code>unifi_url</code></li>
  <li><code>token</code> (optional)</li>
  <li><code>username</code> / <code>password</code> (optional)</li>
  <li><code>site</code> (default: <code>default</code>)</li>
</ul>

<h3>AdGuard Home</h3>
<ul>
  <li><code>adguard_url</code></li>
  <li><code>username</code> / <code>password</code></li>
</ul>

<hr/>

<h2>AdGuard Home – exact API behaviour (current)</h2>

<p>
The AdGuard provider uses these endpoints:
</p>

<ul>
  <li><code>/control/login</code> (attempted; failures are tolerated)</li>
  <li><code>/control/dhcp/leases</code> and <code>/control/dhcp/status</code> (DHCP information; some installs return 404 for one path)</li>
  <li><code>/control/clients</code> (clients list)</li>
</ul>

<p><b>Auth logic (current)</b></p>
<ul>
  <li>It first attempts a login POST to <code>/control/login</code> using JSON payload <code>{"name": "...", "password": "..."}</code>.</li>
  <li>If login succeeds and returns a token, it sets <code>Authorization: Bearer &lt;token&gt;</code> on requests.</li>
  <li>Requests to DHCP/clients endpoints are made with <b>HTTP Basic Auth</b> (<code>BasicAuth(username, password)</code>) when credentials are provided.
      This supports setups where a reverse proxy requires Basic Auth.</li>
  <li>Login may return <code>403</code> on some setups (e.g. blocked by proxy). This does not prevent device collection if the GET endpoints work.</li>
</ul>

<hr/>

<h2>MAC directory overlay options</h2>

<p>
The integration UI includes the following options:
</p>

<ul>
  <li><code>mac_directory_json_url</code></li>
  <li><code>mac_directory_json_text</code></li>
</ul>

<p>
<b>Current behaviour:</b> these fields exist in options, but device tracker enrichment from this directory is not applied unless you have added
the overlay logic into the coordinator/platforms. If you want name/description enrichment, implement it in the coordinator and have entities
prefer the directory name over provider hostname.
</p>

<hr/>

<h2>Services</h2>

<ul>
  <li><b><code>network_scanner.rescan</code></b>
    <ul>
      <li>Triggers <code>async_request_refresh()</code> on all Network Scanner coordinators.</li>
    </ul>
  </li>

  <li><b><code>network_scanner.cleanup_entities</code></b>
    <ul>
      <li>Removes <code>device_tracker</code> entities from the entity registry if they are no longer present in the coordinator device list.</li>
      <li>Unique ID convention used by cleanup: <code>&lt;entry_id&gt;:&lt;uid&gt;</code></li>
    </ul>
  </li>
</ul>

<hr/>

<h2>Installation</h2>

<h3>HACS</h3>
<ol>
  <li>Add this repository as a <b>Custom Repository</b> in HACS (category: Integration).</li>
  <li>Install the integration.</li>
  <li>Restart Home Assistant.</li>
  <li>Add it via <b>Settings → Devices &amp; Services → Add Integration</b>.</li>
</ol>

<h3>Manual</h3>
<ol>
  <li>Copy <code>custom_components/network_scanner</code> into your Home Assistant <code>config/custom_components</code> directory.</li>
  <li>Restart Home Assistant.</li>
  <li>Add the integration via the UI.</li>
</ol>

<hr/>

<h2>Troubleshooting</h2>

<ul>
  <li><b>Sensor shows devices but no device_trackers</b>: confirm <code>network_scanner.device_tracker</code> is loading and that entities are being created from the snapshot.</li>
  <li><b>AdGuard shows 401/403</b>: usually an auth mismatch. The provider tolerates login failure; check that the GET endpoints are working and that Basic Auth credentials are set.</li>
  <li><b>AdGuard DHCP endpoint returns 404</b>: common depending on AdGuard build/config; the provider also tries the alternative path.</li>
</ul>

<h3>Enable debug logging</h3>

<pre><code>logger:
  default: info
  logs:
    custom_components.network_scanner: debug
    custom_components.network_scanner.provider.adguard: debug
</code></pre>

<hr/>

<h2>Security</h2>

<ul>
  <li>MAC/IP/hostnames are sensitive in many environments. Treat logs and exports accordingly.</li>
  <li>Prefer TLS with valid certificates where possible.</li>
  <li>Use least-privilege API credentials for OPNsense/UniFi.</li>
</ul>
