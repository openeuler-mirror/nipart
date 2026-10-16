<!-- vim-markdown-toc GFM -->

* [Nipart Base Interface support](#nipart-base-interface-support)
    * [`name`: Interface name](#name-interface-name)
    * [`type`: Interface type](#type-interface-type)
    * [`description` - Description](#description---interface-description)
    * [`iface-index` - Interface index](#iface-index---interface-index)
    * [`state` - Interface state](#state---interface-state)
    * [`link-state`: Link state](#link-state-link-state)
    * [`controller` - Controller interface](#controller---controller-interface)
    * [`mac-address` - MAC address](#mac-address---mac-address)
    * [`permanent-mac-address` - Permanent MAC address](#permanent-mac-address---permanent-mac-address)
    * [`mtu` - MTU](#mtu---mtu)
    * [`min-mtu` - Minimum MTU](#min-mtu---minimum-mtu)
    * [`max-mtu` - Maximum MTU](#max-mtu---maximum-mtu)
    * [`ipv4` and `ipv6` - IP configuration](#ipv4-and-ipv6---ip-configuration)

<!-- vim-markdown-toc -->

# Nipart Base Interface support

All interface types supported by Nipart support this YAML structure:

```yaml
---
version: 1
interfaces:
- name: eth1
  type: veth
  description: Main interface connected to switch S1
  iface-index: 8
  state: up
  link-state: up
  controller: bond0
  mac-address: 02:00:00:00:00:0f
  permanent-mac-address: 02:00:00:00:00:0f
  mtu: 1500
  min-mtu: 68
  max-mtu: 65535
  ipv4:
    enabled: false
  ipv6:
    enabled: false
```


## `name`: Interface name

The kernel name of interface

## `type`: Interface type

The type of interface, e.g. `veth`, `bond`, `bridge`, etc.

## `description` - Interface description

Save-only property. It is stored in the saved state and surfaced in the
running-state query, but never applied to the kernel nor checked during
verification.

Setting it to an empty string clears the saved description.

## `iface-index` - Interface index

The kernel index of the interface. Query only property.

## `state` - Interface state

The management state of the interface:
 * `up`: the interface is administratively up
 * `down`: the interface is administratively down
 * `absent`: apply only property, request nipart to delete this interface or
   restore physical interface to kernel default state
 * `ignore`: Not managed by nipart. In daemon mode the entry is persisted in
   the saved state: later applies, link events and WIFI profile binding keep
   the interface untouched until a later apply requests another state
   (`up`/`down`/`absent`).
 * `up-ignore`: Interface is administratively up but not managed by nipart
 * `down-ignore`: Interface is administratively down but not managed by nipart

## `link-state`: Link state

Query only property. Interface carrier state:
 * `up`: the interface has carrier
 * `down`: the interface does not have carrier
 * `dormant`: the interface is dormant, e.g. a wireless interface in power
   saving mode
 * `lower-layer-down`: the interface is down due to lower layer failure, e.g. a
   physical interface is down
 * `testing`: the interface is in testing mode

## `controller` - Controller interface

The kernel interface name of the controller interface.

When applying, setting this property to empty string means detach from its
current controller.
When applying, setting this property to a non-empty string means attach to the
controller interface.


## `mac-address` - MAC address

The current MAC address of the interface.

When applying, setting this property to empty string means restore the
permanent MAC address.
When applying, setting this property to a non-empty string means set the MAC
address.

## `permanent-mac-address` - Permanent MAC address

Query only property. The permanent MAC address of the interface


## `mtu` - MTU

MTU of the interface

## `min-mtu` - Minimum MTU

Query only property. The minimum MTU supported by the interface

## `max-mtu` - Maximum MTU

Query only property. The maximum MTU supported by the interface

## `ipv4` and `ipv6` - IP configuration

Please check [IP configuration](./ip.md) for details.

## `alt-names` - Alternative names

List of alternative names of the interface.  An entry with `state: absent`
removes that alternative name:

```yaml
interfaces:
  - name: port1
    type: ethernet
    identifier: mac-address
    mac-address: 02:00:00:00:00:08
    alt-names:
      - name: port1
      - name: primary
```

Only the listed entries are touched on apply (incremental semantic, same as
nmstate): other existing alt-names (e.g. systemd's auto-generated ones) are
left alone.  Unlike nmstate, no systemd link files are created — nipart is a
daemon and re-applies the saved alt-names from its own saved state at boot.
