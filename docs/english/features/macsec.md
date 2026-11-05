<!-- vim-markdown-toc GFM -->

* [MACsec](#macsec)
    * [`base-iface`: Base interface](#base-iface-base-interface)
    * [`encrypt`: Encrypt transmitted traffic](#encrypt-encrypt-transmitted-traffic)
    * [`mka-cak`: MKA CAK](#mka-cak-mka-cak)
    * [`mka-ckn`: MKA CKN](#mka-ckn-mka-ckn)
    * [`sci`: Secure Channel Identifier](#sci-secure-channel-identifier)
    * [`port`: SCI port](#port-sci-port)
    * [`validation`: Frame validation](#validation-frame-validation)
    * [`send-sci`: Send SCI](#send-sci-send-sci)
    * [`offload`: Hardware offload](#offload-hardware-offload)

<!-- vim-markdown-toc -->

# MACsec

Example YAML of a MACsec interface configuration:

```yaml
version: 1
interfaces:
- name: macsec0
  type: macsec
  state: up
  macsec:
    base-iface: eth1
    encrypt: true
    mka-cak: 50b71a8ef0bd5751ea76de6d6c98c03a
    mka-ckn: f2b4297d39da7330910a74abc0449feb45b5c0b9fc23df1430e1898fcf1c4550
    port: 1
    validation: strict
    send-sci: true
```

MACsec (IEEE 802.1AE) protects Ethernet frames on a point-to-point link. The
MACsec interface is created on top of an Ethernet parent interface, and the
parent carries the encrypted/protected traffic.

> **Note:** Changing `base-iface` or `port` on an existing MACsec interface
> deletes and recreates the interface. Other properties are updated in place.

> **Note:** The kernel MACsec interface is configured by the shared
> no-daemon engine. When the daemon is running, the `nipart-plugin-8021x`
> plugin drives the MKA key agreement of the `mka-cak`/`mka-ckn` pair via
> `shuli-wired`: it becomes a key server candidate, distributes the SAK, and
> installs the TX/RX secure associations on the MACsec interface. In
> daemonless mode (`npt -n`) there is no plugin process, so the MACsec
> interface is created without MKA key agreement.
>
> `mka-cak` is saved in the secrets file and hidden from output, while
> `mka-ckn` is a public key name and is kept in the normal saved state. They
> cannot be queried back from the kernel and are not verified after apply.

## `base-iface`: Base interface

The Ethernet parent interface used by the MACsec interface, e.g. `eth1`.

Mandatory when creating a new MACsec interface. When applying changes to an
existing MACsec, leaving this unset preserves the current base interface.

## `encrypt`: Encrypt transmitted traffic

When set to `true`, transmitted frames are encrypted. When set to `false`,
frames are protected (authenticated) without encryption. Defaults to the kernel
default (`false`) when omitted during creation.

## `mka-cak`: MKA CAK

The pre-shared Connectivity Association Key (CAK) for MACsec Key Agreement.
Must be a string of exactly 32 hexadecimal characters.

`mka-cak` and `mka-ckn` must either both be defined or both be omitted.

When MKA keys are defined, the kernel SCI must be the base interface MAC
address with port 1: `port` must be omitted or set to `1`, and `sci` cannot be
defined. This matches the SCI advertised by the MKA implementation.

The value is displayed as `<_hidden_>` in debug/display output.

## `mka-ckn`: MKA CKN

The Connectivity-association Key Name (CKN) for MACsec Key Agreement. Must be a
string of hexadecimal characters with an even length between 2 and 64.

## `sci`: Secure Channel Identifier

The 64-bit Secure Channel Identifier (SCI) used to create the interface, as a
hexadecimal value with or without the `0x` prefix, e.g.
`0x0011223344550001`. The upper 48 bits are the MAC address and the lower 16
bits are the port, matching the value printed by `ip -d link show`.

When `sci` is defined it takes precedence over `port`. If both are defined,
the lower 16 bits of `sci` must match `port`. The query output always includes
`sci`; the lower 16 bits also populate `port`.

An explicit `sci` requires `send-sci` to be true; defining `send-sci: false`
together with `sci` is rejected.

An explicit `sci` cannot be used together with `mka-cak`/`mka-ckn`; see
[`mka-cak`](#mka-cak-mka-cak).

Changing `sci` on an existing MACsec interface deletes and recreates the
interface.

## `port`: SCI port

The port component of the Secure Channel Identifier (SCI) used to create the
interface. The valid range is 0 to 65535. If `sci` is not defined, the kernel
builds the SCI from the interface MAC address and this port.

When `mka-cak`/`mka-ckn` are defined, `port` must be omitted or set to `1`.

Changing it on an existing MACsec interface deletes and recreates the
interface.

## `validation`: Frame validation

Validation mode for incoming frames:
 * `disabled`: Do not validate incoming frames.
 * `check`: Validate frames and discard invalid ones.
 * `strict`: Validate frames and discard both invalid frames and frames
   without a valid SecTAG.

## `send-sci`: Send SCI

When set to `true`, the SCI is included in every transmitted packet.

## `offload`: Hardware offload

Hardware offload mode:
 * `off`: No hardware offload (software implementation).
 * `phy`: Offload to the PHY.
 * `mac`: Offload to the MAC.
