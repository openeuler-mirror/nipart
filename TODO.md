# TODO

- No-daemon mode cannot verify `auto-connect`: the kernel never reports this
  daemon-only property and no-daemon apply has no saved config, so
  `npt apply --no-daemon` on a state containing `auto-connect: false` (or
  `true`) applies the config and then fails with `verification-error:
  Verification failure: <name>.interface.auto-connect desire 'false',
  current 'null'`. Nipart should raise error for daemon only config been desired
  for no-daemon mode.
- Rollback of an interface rename fails: when the desired state renames an
  existing NIC (e.g. `kernel-iface-name: cunet` on `eth0`) and a later
  verification fails, the revert state still refers to the old kernel name,
  hence the rollback errors with `invalid-argument: Interface eth0 does not
  exist and veth section is not defined to create it` and the renamed
  interface is left behind.
- `src/lib/dns` still duplicates the `mudz` packet codec and UDP client;
  re-export the `mudz` types instead once the error type change is wanted.
- Restart DHCPv6 service upon link local address changes
- Support filtering full network query to a single interface
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
- `wait-ip: no|any|ipv4|ipv6|ipv4+ipv6` for whether wait IP applied.
- NmPolicy support as nmstate does
