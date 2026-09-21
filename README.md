# Nipart

Nipart is a Rust-based Linux network management tool, offering a memory-safe,
thread-safe daemon, command-line tool, and API library.

Nipart's declarative YAML dramatically reduces the complexity of network
deployment.

Nipart supports a daemonless mode for swift network configuration with zero
residual processes or files — purpose-built for cloud-native container
environments.

With a polished plugin interface, Nipart supports custom VPN and third-party
interface management plugins.

## YAML API Example

Example output of `npt show`:

```bash
---
version: 1
routes:
  config:
  - destination: 0.0.0.0/0
    next-hop-interface: bond1
    next-hop-address: 192.0.2.1
    table-id: 254
    metric: 1000
interfaces:
  - name: bond1
    type: bond
    state: up
    ipv4:
      address:
      - ip: 192.0.2.252
        prefix-length: 24
      dhcp: false
      enabled: true
    bond:
      mode: active-backup
      ports:
        - name: port1
        - name: port2
  - name: port1
    type: ethernet
    state: up
    mac-address: 00:23:45:67:89:1a
    identifier: mac-address
  - name: port2
    type: ethernet
    state: up
    mac-address: 00:23:45:67:89:1b
    identifier: mac-address
```


## Features

* [Base Interface Management](docs/english/features/base.md)
* [IP Address](docs/english/features/ip.md)
* [No Daemon Mode](docs/english/features/no_daemon_mode.md)
* [WIFI](docs/english/features/wifi.md)
* [Route](docs/english/features/route.md)
* [Conditional Network Up/Down](docs/english/features/auto_connect.md)
* [Wait Online](docs/english/features/wait-online.md)
* [Vlan](docs/english/features/vlan.md)
* [VxLAN](docs/english/features/vxlan.md)
* [Bond](docs/english/features/bond.md)
* [Linux Bridge](docs/english/features/bridge.md)
* [OpenvSwitch Bridge](docs/english/features/ovs.md)
* [Wireguard](docs/english/features/wireguard.md)

## Installation

### Build from source
```bash
cargo build --release
sudo systemctl stop nipart || true
sudo cp -fv target/release/nipartd /usr/bin/
sudo cp -fv target/release/npt /usr/bin/
sudo cp -fv packaging/nipart.service /etc/systemd/system/
sudo cp -fv packaging/nipart-wait-online.service /etc/systemd/system/
sudo systemctl enable nipart.service
sudo systemctl enable nipart-wait-online.service
sudo systemctl start nipart.service
```

### Install from Archlinux AUR

TODO: Upload to AUR

### Install from Fedora COPR

TODO: Upload to COPR

## Usage

### List configured interfaces

```bash
# Show npc-style brief info of configured interfaces
sudo npt
# Show brief info of a specific configured interface or profile
sudo npt brief <interface_or_profile>
# Show brief info of all running interfaces
sudo npt brief --running
# Short option of `--running`
sudo npt brief -r
# Alias of `brief`
sudo npt b <interface_or_profile>
# Short option of `--running` with the `brief` alias
sudo npt b -r
```

### Show current network state

```bash
# daemon mode
sudo npt show
# no-daemon mode
sudo npt show -n
```

### Show saved config of daemon

```bash
sudo npt show -s
```

### Show running status of certain interface

```bash
sudo npt show wlan0
```

### Show only DNS resolver or routes section

```bash
sudo npt show dns
sudo npt show route
# Show an interface/profile whose name collides with the section keywords
sudo npt show --iface route
```

### Scan WIFI networks

```bash
sudo npt wifi scan
```

### Connect to WIFI

```bash
# This command will ask you to input your wifi password
sudo npt wifi connect <SSID>
```

### Bring an interface or saved profile up/down

```bash
# Apply the saved config, restart DHCP, and reconnect WIFI if needed
sudo npt up <interface_name_or_profile_name>
# Bring the interface down, purge IP/routes, remove virtual interfaces, or
# switch WIFI to the next best saved SSID
sudo npt down <interface_name_or_profile_name>
```

The saved configuration is not modified by `npt up`/`npt down`.
