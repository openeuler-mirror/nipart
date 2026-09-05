// SPDX-License-Identifier: Apache-2.0

use crate::{NetworkState, NipartInterface, NipartWaitOnlineCondition};

fn round_trip(yaml_str: &str) -> (NetworkState, NetworkState) {
    let state = NetworkState::new_from_yaml(yaml_str).unwrap();
    let serialized = rmsd_yaml::to_string(&state).unwrap();
    let reparsed = NetworkState::new_from_yaml(&serialized).unwrap();
    (state, reparsed)
}

#[test]
fn test_yaml_round_trip_ethernet_with_ip() {
    let (state, reparsed) = round_trip(
        r#"---
        interfaces:
          - name: eth1
            type: ethernet
            mtu: 9000
            mac-address: 02:00:00:00:00:0e
            ipv4:
              enabled: true
              dhcp: false
              address:
                - ip: 192.0.2.251
                  prefix-length: 24
            ipv6:
              enabled: true
              dhcp: true
              autoconf: true
        "#,
    );
    assert_eq!(state, reparsed);
}

#[test]
fn test_yaml_round_trip_interface_description() {
    let (state, reparsed) = round_trip(
        r#"---
        interfaces:
          - name: eth1
            type: ethernet
            state: up
            description: "Main interface connected to switch S1"
        "#,
    );
    assert_eq!(
        state
            .ifaces
            .kernel_ifaces
            .get("eth1")
            .unwrap()
            .base_iface()
            .description
            .as_deref(),
        Some("Main interface connected to switch S1")
    );
    assert_eq!(state, reparsed);
}

#[test]
fn test_yaml_round_trip_bond_with_ports() {
    let (state, reparsed) = round_trip(
        r#"---
        interfaces:
          - name: bond0
            type: bond
            bond:
              mode: active-backup
              options:
                miimon: 100
          - name: eth1
            type: ethernet
            controller: bond0
          - name: eth2
            type: ethernet
            controller: bond0
        "#,
    );
    assert_eq!(state, reparsed);
}

#[test]
fn test_yaml_round_trip_linux_bridge() {
    let (state, reparsed) = round_trip(
        r#"---
        interfaces:
          - name: br0
            type: linux-bridge
            bridge:
              options:
                stp:
                  enabled: true
              port:
                - name: eth1
        "#,
    );
    assert_eq!(state, reparsed);
}

#[test]
fn test_yaml_round_trip_vlan_and_vxlan() {
    let (state, reparsed) = round_trip(
        r#"---
        interfaces:
          - name: eth1.100
            type: vlan
            vlan:
              base-iface: eth1
              id: 100
          - name: vxlan0
            type: vxlan
            vxlan:
              base-iface: eth1.100
              id: 100
        "#,
    );
    assert_eq!(state, reparsed);
}

#[test]
fn test_yaml_round_trip_wireguard() {
    let (state, reparsed) = round_trip(
        r#"---
        interfaces:
          - name: wg0
            type: wireguard
            wireguard:
              listen-port: 51820
              private-key: aGFuZCBvdmVyIHRoZSBrZXk=
              peers:
                - public-key: cGVlciBwdWJsaWMga2V5
                  preshared-key: cHJlLXNoYXJlZA==
                  endpoint: 192.0.2.2:51820
                  persistent-keepalive: 25
                  allowed-ips:
                    - ip: 192.0.2.0
                      prefix-length: 24
        "#,
    );
    assert_eq!(state, reparsed);
}

#[test]
fn test_yaml_round_trip_routes() {
    let (state, reparsed) = round_trip(
        r#"---
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-address: 192.0.2.1
              next-hop-interface: eth1
              metric: 100
            - destination: 198.51.100.0/24
              next-hop-interface: eth2
              state: absent
          running:
            - destination: 203.0.113.0/24
              next-hop-address: 192.0.2.9
              next-hop-interface: eth1
        "#,
    );
    assert_eq!(state, reparsed);
}

#[test]
fn test_yaml_round_trip_route_rules() {
    let (state, reparsed) = round_trip(
        r#"---
        route-rules:
          config:
            - ip-from: 198.51.100.0/24
              ip-to: 192.0.2.0/24
              priority: 100
              route-table: 500
              fwmark: 0x30
              fwmask: 0x10
              iif: eth1
            - state: absent
              route-table: 500
        "#,
    );
    assert_eq!(state, reparsed);
    let rules = state.route_rules.config.unwrap();
    assert_eq!(rules.len(), 2);
}

#[test]
fn test_yaml_round_trip_top_level_properties() {
    let (state, reparsed) = round_trip(
        r#"---
        version: 1
        description: round trip test
        wait-online:
          timeout-sec: 10
          conditions:
            - gateway4
            - gateway6
        "#,
    );
    assert_eq!(state, reparsed);
    assert_eq!(
        state.wait_online.as_ref().unwrap().conditions,
        vec![
            NipartWaitOnlineCondition::Gateway4,
            NipartWaitOnlineCondition::Gateway6,
        ]
    );
}

#[test]
fn test_yaml_serialize_hide_secrets() {
    let mut state = NetworkState::new_from_yaml(
        r#"---
        interfaces:
          - name: wlan0
            type: wifi-phy
            wifi:
              ssid: Test-WIFI
              password: 12345678
        "#,
    )
    .unwrap();

    state.hide_secrets();
    let serialized = rmsd_yaml::to_string(&state).unwrap();

    assert!(serialized.contains(NetworkState::HIDE_SECRET_STR));
    assert!(!serialized.contains("12345678"));
}

#[test]
fn test_yaml_serialize_skips_none_fields() {
    let state = NetworkState::new_from_yaml(
        r#"---
        interfaces:
          - name: eth1
            type: ethernet
        "#,
    )
    .unwrap();

    let value = rmsd_yaml::to_value(&state).unwrap();

    let iface = value
        .get("interfaces")
        .and_then(|v| v.as_sequence())
        .unwrap()
        .first()
        .unwrap()
        .clone();
    assert!(iface.get("name").is_some());
    assert!(iface.get("type").is_some());
    assert!(iface.get("mtu").is_none());
    assert!(iface.get("mac-address").is_none());
    assert!(iface.get("controller").is_none());
    assert!(iface.get("ipv4").is_none());
    assert!(iface.get("ipv6").is_none());

    assert!(value.get("description").is_none());
    assert!(value.get("wait-online").is_none());
}
