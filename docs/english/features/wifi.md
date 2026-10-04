<!-- vim-markdown-toc GFM -->

* [WIFI](#wifi)
    * [`ssid`: SSID](#ssid-ssid)
    * [`state`: Wifi state](#state-wifi-state)
    * [`bssid`: BSSID](#bssid-bssid)
    * [`password`: Password](#password-password)
    * [`hidden`: Hidden network](#hidden-hidden-network)
    * [`base-iface`: Base interface](#base-iface-base-interface)
    * [`auth-type`: Authentication type](#auth-type-authentication-type)
    * [`generation`: Wifi generation](#generation-wifi-generation)
    * [`frequency-mhz`: Frequency](#frequency-mhz-frequency)
    * [`rx-bitrate-mb`: Receive bitrate](#rx-bitrate-mb-receive-bitrate)
    * [`tx-bitrate-mb`: Transmit bitrate](#tx-bitrate-mb-transmit-bitrate)
    * [`signal-dbm`: Signal level](#signal-dbm-signal-level)
    * [`signal-percent`: Signal percentage](#signal-percent-signal-percentage)

<!-- vim-markdown-toc -->
# WIFI

WIFI configuration in Nipart uses two interface types:

- **`wifi-phy`**: A kernel wifi physical interface (e.g. `wlan0`). Used for
  current state (query results) or when the physical interface name is known
  ahead of time.
- **`wifi-cfg`**: A psuedo/userspace-only interface that holds the desired wifi
  connection configuration. It has no kernel index and lives only in the Nipart
  desired state. You can optionally bind it to a specific `wifi-phy` via
  `base-iface`, or leave it unbound (meaning "any available wifi-phy").

Example YAML for WIFI configuration with static IP:

```yaml
version: 1
routes:
  config:
  - destination: 0.0.0.0/0
    next-hop-interface: wlan0
    next-hop-address: 192.0.2.1
    metric: 100
interfaces:
- name: wlan0
  type: wifi-phy
  state: up
  mtu: 1492
  ipv4:
    enabled: true
    dhcp: false
    address:
    - ip: 192.0.2.6
      prefix-length: 24
  wifi:
    ssid: ExampleNetwork
    bssid: 02:00:00:00:00:11
    password: <_hidden_>
```

## `ssid`: SSID

The SSID (Service Set Identifier) of the wifi network to connect to.

## `state`: Wifi state

Query only property. The current connection state of the wifi link:

- `disconnected`: BSS disconnected
- `scanning`: Scanning for SSID
- `connecting`: SSID found, trying to associate and authenticate with a BSS/SSID
- `completed`: Data connection is fully configured and operational
- `unknown`: State could not be determined

## `bssid`: BSSID

The BSSID (Basic Service Set Identifier) of the access point. When set, Nipart
will only connect to the specified AP. If omitted, any AP broadcasting the SSID
may be used.

## `password`: Password

The password or pre-shared key for authentication. This field is replaced
with `<_hidden_>` when querying current state.

## `hidden`: Hidden network

Set to `true` when the AP does not include its SSID in beacons. Nipart
then asks shuli to probe the SSID with a directed probe request, so
hidden networks can be discovered and connected.

## `base-iface`: Base interface

The kernel name of the wifi physical interface to bind this configuration to.
If set, the wifi connection is restricted to that specific interface.

When using `wifi-phy` type, this field defaults to the interface name itself.
When using `wifi-cfg` type with `base-iface: <name>`, the config binds to that
physical interface. When undefined (unbound), the config applies to any eligible
`wifi-phy` interface.

## `auth-type`: Authentication type

Query only property. The simplified authentication type of the current
connection. Ignored when applying.

Supported authentication types:

- `OPEN`: No authentication (open network)
- `WPA2-PSK`: WPA 2 Pre-shared Key
- `WPA3-PSK`: WPA 3 Pre-shared Key using SAE
- `unknown`: Could not be determined

`npt wifi scan` prints a table in the style of `nmcli device wifi list`:

```text
IN-USE  BSSID              SSID              CHAN  BAND   SIGNAL  BARS  SECURITY
*       02:00:00:00:00:11  Home              36    5 GHz  78      ▂▄▆_  WPA2
```

Use `npt wifi scan -y` to print the YAML format.

The underlying `WifiScanResult` schema reports `auth-types` on each entry:
a list of detailed authentication types, each containing the simplified
`auth-type` plus the AKM (Authentication and Key Management) and cipher suites
advertised by the access point, e.g.:

```yaml
- ssid: ExampleNetwork
  base-iface: wlan0
  bssid: 02:00:00:00:00:11
  frequency-mhz: 5180
  signal-dbm: -45
  signal-percent: 78
  auth-types:
  - auth-type: WPA2-PSK
    akm:
    - PSK
    cipher:
    - CCMP
```

## `generation`: Wifi generation

Query only property. The wifi generation, e.g. `6` for WiFi 6.

## `frequency-mhz`: Frequency

Query only property. The wifi frequency in MHz.

## `rx-bitrate-mb`: Receive bitrate

Query only property. The receive bitrate in 1 Mb/s.

## `tx-bitrate-mb`: Transmit bitrate

Query only property. The transmit bitrate in 1 Mb/s.

## `signal-dbm`: Signal level

Query only property. The signal strength in dBm.

## `signal-percent`: Signal percentage

Query only property. The signal strength as a percentage (0-100).

## Connect verification

An apply which explicitly requests a WIFI connection - `npt wifi connect
<SSID>`, `npt up <wifi profile>`, or `npt apply` of a `wifi-phy`/`wifi-cfg`
profile carrying an SSID - waits until the wifi plugin reports the
association authenticated (the 4-way handshake completed) before returning.
The command fails with the real reason when the connection cannot succeed,
e.g. for a wrong password:

    NipartError: authentication-error: wrong password for SSID 'Test-WIFI'

A failed `npt wifi connect` is rolled back: the rejected profile is not
persisted and the saved WIFI profiles are handed back to the plugin, so the
previous connection (or the best remaining saved network) comes back without
a manual `npt up`.

Use `npt apply --no-verify` when the AP is not available yet: the profile is
saved and the plugin keeps hunting for the AP in the background.

## Unsupported security

Nipart refuses networks whose security mode shuli does not implement
instead of associating insecurely. An AP that only offers a deprecated
mode - for example a WPA/WPA2 hybrid router whose group cipher is TKIP -
makes `npt wifi connect <SSID>` fail as soon as the scan finds it, with:

    NipartError: no-support: TKIP WPA2 is not supported

The failed apply is rolled back and the saved WIFI profiles are handed
back to the plugin, so the previous connection (or the best remaining
saved network) comes back without a manual `npt up`.

Reconfigure the AP to WPA2/WPA3 with AES (CCMP) to connect.
