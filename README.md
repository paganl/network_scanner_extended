
# Network Scanner (Lean drop-in, v0.7.2)

Fixes:
- CIDR field now displays correctly even if it was previously saved as a string (no more `10,.0,.0,.0,/,16`).
- Setup no longer blocks waiting for the first network call; refresh runs in the background.
- HTTP timeouts reduced to 3s per endpoint to avoid UI freezing if OPNsense/AdGuard is slow.

Notes:
- Username/password are **only for AdGuard**. For OPNsense use **API key/secret**.
- Provider must match your target (`opnsense` vs `adguard`).

One sensor is created:
- `sensor.network_scanner_devices` (state = count, attributes = `devices` list).
