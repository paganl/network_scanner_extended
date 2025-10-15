<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Virgin Modem Status – Home Assistant Integration</title>
</head>
<body>
  <h1>Virgin Modem Status (Unofficial)</h1>

  <p>
    A lightweight custom integration for Home Assistant that polls the Virgin Media modem
    (e.g. Hub in Modem Mode) at <code>http://192.168.100.1</code> and exposes:
  </p>
  <ul>
    <li><strong>binary_sensor.virgin_modem_online</strong> — modem UI reachable (HTTP 200).</li>
    <li><strong>sensor.virgin_last_docsis_event</strong> — most recent DOCSIS log/event text, with full
        message/time maps in attributes for automation.</li>
  </ul>

  <p>
    This readme explains installation, setup, network/VLAN/ARP considerations, entity mapping, and troubleshooting.
  </p>

  <hr>

  <h2>Requirements</h2>
  <ul>
    <li>Home Assistant 2023.6+ (HA OS / Container / Core).</li>
    <li>Virgin Media modem in <em>Modem Mode</em> (UI reachable on <code>192.168.100.1</code>).</li>
    <li>Home Assistant must be able to reach <code>192.168.100.1</code> from its network namespace.</li>
    <li>OPNsense or similar firewall if you are multi-homed or using VLANs.</li>
  </ul>

  <hr>

  <h2>Installation</h2>

  <h3>Via HACS (Preferred if you later add it to a repo index)</h3>
  <ol>
    <li>HACS → Integrations → Three dots → <em>Custom repositories</em> → Add your GitHub repo URL → Category: <em>Integration</em>.</li>
    <li>Search for “Virgin Modem Status”, install, and restart Home Assistant.</li>
  </ol>

  <h3>Manual</h3>
  <ol>
    <li>Copy the folder <code>custom_components/virgin_modem_status</code> into your HA config directory.</li>
    <li>Restart Home Assistant.</li>
  </ol>

  <hr>

  <h2>Configuration (UI)</h2>
  <ol>
    <li>Settings → Devices &amp; Services → <em>+ Add Integration</em> → search “Virgin Modem Status”.</li>
    <li>Host: <code>http://192.168.100.1</code> (leave default unless your modem UI lives elsewhere).</li>
    <li>Scan interval (seconds): default <code>60</code>. You can change later in the integration’s <em>Options</em>.</li>
  </ol>

  <p>
    After a successful first refresh, you will see a <em>Device</em> named “Virgin Modem” with the two entities.
  </p>

  <hr>

  <h2>Entities</h2>
  <ul>
    <li><strong>Virgin Modem</strong> (device)</li>
    <li><strong>binary_sensor.virgin_modem_online</strong> (device_class: connectivity) — <em>on</em> when the UI answers.</li>
    <li><strong>sensor.virgin_last_docsis_event</strong> — string of the newest DOCSIS event.
      <br>Attributes include:
      <ul>
        <li><code>times</code>: a map of OIDs → timestamp strings.</li>
        <li><code>messages</code>: a map of OIDs → event messages (e.g. T3 timeout, RCS Partial Service).</li>
      </ul>
    </li>
  </ul>

  <p><strong>Polling:</strong> The integration polls on the configured scan interval (default 60s). You can change this from the integration’s <em>Options</em>.</p>

  <hr>

  <h2>What the Integration Reads</h2>
  <p>
    The modem UI exposes a JSON endpoint (e.g. <code>/getRouterStatus</code>) containing DOCSIS and event OIDs.
    The integration selects the newest non-empty event from those OIDs and exposes it as
    <code>sensor.virgin_last_docsis_event</code>, while keeping the full time/message maps in attributes for advanced use.
  </p>

  <hr>

  <h2>Networking: VLAN &amp; ARP Considerations</h2>

  <h3>Why this matters</h3>
  <p>
    When the Virgin Hub is in Modem Mode, it places its management UI at <code>192.168.100.1</code> on the
    <em>WAN-side</em> L2 segment. Many setups block or simply don’t route that network by default.
    Also, some modems only respond to ARP from the device directly connected to them (your firewall/router).
    If Home Assistant can’t reach <code>192.168.100.1</code>, the integration will always show the modem as offline.
  </p>

  <h3>Typical OPNsense Setup (recommended)</h3>
  <ol>
    <li><strong>Virtual IP on WAN:</strong> add an IP alias on the WAN interface in the modem’s subnet,
        e.g. <code>192.168.100.2/24</code>. This makes the firewall L3-adjacent to the modem UI.</li>
    <li><strong>Firewall rule on WAN:</strong> allow traffic from <em>WAN address</em> to <code>192.168.100.1</code> (HTTP).</li>
    <li><strong>Outbound NAT for LAN → modem:</strong> add a rule so that LAN hosts (e.g. your HA box) accessing
        <code>192.168.100.1</code> are NATed to the firewall’s <code>192.168.100.2</code>.
        This makes the modem see your firewall as the source (solves ARP restrictions).</li>
    <li><strong>Disable “Block private networks”</strong> on WAN if it prevents the above rule from working in your build.</li>
  </ol>

  <p>
    With the above, any host on your LAN (including Home Assistant) can browse
    <code>http://192.168.100.1</code> and the connection will be NATed through the firewall’s WAN alias. The modem only needs to ARP the firewall’s MAC.
  </p>

  <h3>VLAN Approach (alternative)</h3>
  <p>
    Some users create a dedicated <em>“modem management”</em> VLAN that is bridged or extended to the WAN side on a managed switch.
    In that design, Home Assistant is given access to the VLAN so it directly reaches <code>192.168.100.1</code>.
    This can work, but be careful:
  </p>
  <ul>
    <li>Do not leak untrusted WAN broadcast domains into your LAN.</li>
    <li>Keep strict switch port profiles: the modem/WAN port untagged, HA port tagged only as needed.</li>
    <li>Prefer the OPNsense alias + NAT method unless you are very comfortable with L2/L3 separation.</li>
  </ul>

  <h3>Why ARP Tables Are Mentioned</h3>
  <p>
    Many cable modems in bridge mode will only reply to the MAC that lives on the directly attached port.
    If a LAN host tries to ARP <code>192.168.100.1</code> across the firewall, the modem may not respond.
    By NATing the LAN host’s traffic to the firewall’s <code>192.168.100.2</code> (WAN-side alias),
    the modem only needs to ARP for that one address (the firewall), and the firewall handles the return path.
  </p>

  <hr>

  <h2>Automations Ideas</h2>
  <ul>
    <li>Notify when <code>binary_sensor.virgin_modem_online</code> is <em>off</em> for 2 minutes.</li>
    <li>Parse <code>sensor.virgin_last_docsis_event</code> for
      <em>T3 timeout</em>, <em>RCS Partial Service</em>, or <em>T4</em> to distinguish ISP/line issues from LAN problems.</li>
    <li>Pause auto-heals (modem power cycles) when you detect upstream plant issues (lots of T3/T4) to avoid thrashing.</li>
  </ul>

  <hr>

  <h2>Options &amp; Schema</h2>
  <p><strong>Options:</strong></p>
  <ul>
    <li><code>scan_interval</code> (seconds): default 60. Poll frequency for the modem status endpoint.</li>
  </ul>

  <p><strong>Data Model (high level):</strong></p>
  <ul>
    <li>Integration fetches JSON from the modem’s status endpoint.</li>
    <li>Known OID lists are used to extract event <em>message</em> and <em>time</em> arrays.</li>
    <li>Newest non-empty message is surfaced as the sensor value; full maps are exposed as attributes.</li>
  </ul>

  <hr>

  <h2>Troubleshooting</h2>
  <ul>
    <li><strong>Sensors never update:</strong> verify you can open <code>http://192.168.100.1</code> from the HA host (SSH into HA or use a diagnostics add-on and curl it). If not, fix routing/NAT as above.</li>
    <li><strong>Only the firewall can browse the modem UI:</strong> add the WAN alias and outbound NAT so LAN hosts (including HA) are translated to the WAN alias.</li>
    <li><strong>Frequent T3/T4 or RCS Partial Service:</strong> this is an upstream signal/noise problem. Collect logs and contact the ISP; power-cycling won’t fix ingress/noise.</li>
    <li><strong>“Modem online” is off but Internet works:</strong> the modem UI can be rate-limited or briefly unavailable; increase scan interval to 120s or back off on timeouts.</li>
  </ul>

  <hr>

  <h2>Security Notes</h2>
  <ul>
    <li>The integration uses HTTP (no auth) to the modem UI on a private network. Do not expose <code>192.168.100.1</code> externally.</li>
    <li>Keep your firewall rules minimal and specific to the modem UI.</li>
  </ul>

  <hr>

  <h2>Changelog (short)</h2>
  <ul>
    <li>v0.1.0 — First public version with reachability + last DOCSIS event.</li>
  </ul>

  <p>
    Contributions welcome. Open issues/PRs for signal level sensors, richer event parsing, and diagnostics.
  </p>
</body>
</html>
