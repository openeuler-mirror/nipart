# TODO

- OVS bridge
- MacSec
- HSR
- MacVlan
- Infiniband
- SRIOV
- IPSec
- IpVlan
- Plugin cannot send back logs to user
- `nmc wifi connect` should wait connect and retry for wrong-password
- Expose per-SSID wifi roaming config (`roaming` / `roaming-threshold`)
- in `WifiConfig` schema and pass through to shuli `NetworkConfig`
- (currently uses shuli defaults: roaming enabled at -70 dBm)
- `wifi_phy_later_test.py`: after a saved `wifi-cfg` is handed to the
  wifi plugin on a new-phy event, shuli's ongoing scan makes
  `hostapd_is_up_open()` fail with `iw scan` returning device busy. The
  test fails consistently on `dev` before hostapd can be verified.
- `wifi_hidden_test.py`: hidden-SSID apply can fail verification because
  the daemon still reads an empty SSID after shuli reports connected and
  hostapd completed the handshake.  The same test passes when run alone,
  but fails consistently when the full file runs.
