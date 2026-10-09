// SPDX-License-Identifier: Apache-2.0

use nipart::{InterfaceType, NetworkState, NipartInterface};

use super::{
    gen_non_nic_state, gen_saved_route_reconcile_state,
    gen_wifi_off_purge_state, remove_manual_activation,
};

#[test]
fn test_gen_saved_route_reconcile_state_keeps_only_target_routes() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        routes:
          config:
            - destination: 203.0.113.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 103
            - destination: 198.51.100.0/24
              next-hop-interface: eth1
              next-hop-address: 192.0.2.1
              metric: 104
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
              auto-gateway: false
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
              auto-gateway: false
        "#,
    )
    .unwrap();
    let cur: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
              dhcp-state: done
              address:
                - ip: 192.0.2.100
                  prefix-length: 24
          - name: eth1
            type: ethernet
            state: up
        "#,
    )
    .unwrap();

    let ret = gen_saved_route_reconcile_state(&saved, &cur, "eth0");

    assert_eq!(ret.ifaces.iter().count(), 1);
    assert_eq!(ret.ifaces.iter().next().unwrap().name(), "eth0");
    let routes = ret.routes.config.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination.as_deref(), Some("203.0.113.0/24"));
    assert_eq!(routes[0].next_hop_iface.as_deref(), Some("eth0"));
}

#[test]
fn test_gen_saved_route_reconcile_state_matches_mac_identified_profile() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        routes:
          config:
            - destination: 203.0.113.0/24
              next-hop-interface: lan0
              next-hop-address: 192.0.2.1
              metric: 103
        interfaces:
          - name: lan0
            type: ethernet
            identifier: mac-address
            mac-address: 02:00:00:00:00:02
            state: up
            ipv4:
              enabled: true
              dhcp: true
              auto-gateway: false
        "#,
    )
    .unwrap();
    let cur: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth2
            type: ethernet
            state: up
            mac-address: 02:00:00:00:00:02
        "#,
    )
    .unwrap();

    let ret = gen_saved_route_reconcile_state(&saved, &cur, "eth2");

    assert_eq!(ret.ifaces.iter().next().unwrap().name(), "lan0");
    let routes = ret.routes.config.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination.as_deref(), Some("203.0.113.0/24"));
}

#[test]
fn test_gen_non_nic_state_keeps_virtual_and_global_only() {
    let state: NetworkState = rmsd_yaml::from_str(
        r#"---
            routes:
              config:
                - destination: 203.0.113.0/24
                  next-hop-interface: eth0
                  next-hop-address: 192.0.2.1
                  metric: 103
                - destination: 198.51.100.0/24
                  next-hop-interface: bond0
                  next-hop-address: 192.0.2.1
                  metric: 104
                - destination: 192.0.2.0/24
                  metric: 105
                - destination: 198.18.0.0/24
                  next-hop-interface: vlan0
                  next-hop-address: 192.0.2.1
                  metric: 106
            route-rules:
              config:
                - ip-from: 203.0.113.0/24
                  route-table: 500
                - ip-from: 198.51.100.0/24
                  route-table: 500
                  iif: eth0
                - ip-from: 192.0.2.0/24
                  route-table: 500
                  iif: bond0
                - ip-from: 198.18.0.0/24
                  route-table: 500
                  iif: vlan0
            interfaces:
              - name: eth0
                type: ethernet
                state: up
              - name: bond0
                type: bond
                state: up
                bond:
                  mode: balance-rr
                  ports:
                    - name: eth0
              - name: vlan0
                type: vlan
                state: up
                vlan:
                  base-iface: bond0
                  id: 100
            "#,
    )
    .unwrap();

    // Without the eth0 port present, neither bond0 nor the VLAN built on top
    // of it can be created: only the global route and rule are applied now.
    let empty_cur_state = NetworkState::default();
    let non_nic = gen_non_nic_state(&state, &empty_cur_state);
    // All virtual interfaces are still in the creation state; only the
    // virtual routes/rules which cannot be installed are deferred.
    assert_eq!(non_nic.ifaces.iter().count(), 2);
    let routes = non_nic.routes.config.as_ref().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination.as_deref(), Some("192.0.2.0/24"));
    let rules = non_nic.route_rules.config.as_ref().unwrap();
    assert_eq!(rules.len(), 1);
    assert!(
        rules[0].iif.is_none()
            && rules[0].ip_from.as_deref() == Some("203.0.113.0/24")
    );

    // With eth0 present, bond0 is creatable and the VLAN built on top of it
    // becomes creatable through the dependency chain: their routes and rules
    // are applied by this transaction.
    let cur_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: eth0
                type: ethernet
                state: up
            "#,
    )
    .unwrap();
    let non_nic = gen_non_nic_state(&state, &cur_state);
    let routes = non_nic.routes.config.as_ref().unwrap();
    let destinations: Vec<&str> = routes
        .iter()
        .filter_map(|r| r.destination.as_deref())
        .collect();
    assert_eq!(destinations.len(), 3);
    assert!(destinations.contains(&"198.51.100.0/24"));
    assert!(destinations.contains(&"192.0.2.0/24"));
    assert!(destinations.contains(&"198.18.0.0/24"));
    let rules = non_nic.route_rules.config.as_ref().unwrap();
    let iifs: Vec<Option<&str>> =
        rules.iter().map(|r| r.iif.as_deref()).collect();
    // The eth0 rule is deferred to the event path; the global, bond0 and
    // vlan0 rules are applied here.
    assert!(!iifs.contains(&Some("eth0")));
    assert!(iifs.contains(&Some("bond0")));
    assert!(iifs.contains(&Some("vlan0")));
    assert!(iifs.contains(&None));
}

#[test]
fn test_remove_manual_activation() {
    // Interfaces with `auto-connect: false`, their dependents, and
    // routes pointing to them are removed from the boot state.
    let mut state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: eth0
                type: ethernet
                state: up
                auto-connect: false
              - name: eth0.100
                type: vlan
                state: up
                vlan:
                  base-iface: eth0
                  id: 100
              - name: eth1
                type: ethernet
                state: up
                auto-connect: true
              - name: eth2
                type: ethernet
                state: up
              - name: bond0
                type: bond
                state: up
                auto-connect: false
                bond:
                  mode: balance-rr
              - name: eth3
                type: ethernet
                state: up
                controller: bond0
            routes:
              config:
                - destination: 192.0.2.0/24
                  next-hop-interface: eth0
                - destination: 198.51.100.0/24
                  next-hop-interface: eth1
            "#,
    )
    .unwrap();

    remove_manual_activation(&mut state);

    assert!(!state.ifaces.kernel_ifaces.contains_key("eth0"));
    // VLAN on top of an excluded interface is also excluded.
    assert!(!state.ifaces.kernel_ifaces.contains_key("eth0.100"));
    assert!(!state.ifaces.kernel_ifaces.contains_key("bond0"));
    // Port of an excluded controller is also excluded.
    assert!(!state.ifaces.kernel_ifaces.contains_key("eth3"));
    assert!(state.ifaces.kernel_ifaces.contains_key("eth1"));
    // Interface without `auto-connect` keeps the default auto behavior.
    assert!(state.ifaces.kernel_ifaces.contains_key("eth2"));

    let rts = state.routes.config.unwrap();
    assert_eq!(rts.len(), 1);
    assert_eq!(rts[0].next_hop_iface.as_deref(), Some("eth1"));
}

#[test]
fn test_remove_manual_activation_removes_matching_route_rules() {
    let mut state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: eth0
                type: ethernet
                state: up
                auto-connect: false
              - name: eth1
                type: ethernet
                state: up
            route-rules:
              config:
                - ip-from: 203.0.113.0/24
                  route-table: 500
                  iif: eth0
                - ip-from: 198.51.100.0/24
                  route-table: 500
                  iif: eth1
                - ip-from: 192.0.2.0/24
                  route-table: 500
            "#,
    )
    .unwrap();

    remove_manual_activation(&mut state);

    let rules = state.route_rules.config.unwrap();
    assert_eq!(rules.len(), 2);
    assert!(rules.iter().all(|rule| rule.iif.as_deref() != Some("eth0")));
}

#[test]
fn test_gen_wifi_off_purge_state_disables_wifi_phy_ip() {
    let cur_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: wlan0
                type: wifi-phy
                state: up
                ipv4:
                  enabled: true
                  dhcp: false
                  address:
                    - ip: 192.0.2.99
                      prefix-length: 24
                ipv6:
                  enabled: true
                  autoconf: true
              - name: eth0
                type: ethernet
                state: up
                ipv4:
                  enabled: true
            "#,
    )
    .unwrap();

    let desired_state = gen_wifi_off_purge_state(&cur_state);
    let ifaces: Vec<_> = desired_state.ifaces.iter().collect();
    assert_eq!(ifaces.len(), 1);
    assert_eq!(ifaces[0].iface_type(), &InterfaceType::WifiPhy);
    assert_eq!(ifaces[0].kernel_iface_name(), "wlan0");
    assert!(ifaces[0].base_iface().state.is_up());
    assert_eq!(
        ifaces[0]
            .base_iface()
            .ipv4
            .as_ref()
            .and_then(|ipv4| ipv4.enabled),
        Some(false)
    );
    assert_eq!(
        ifaces[0]
            .base_iface()
            .ipv6
            .as_ref()
            .and_then(|ipv6| ipv6.enabled),
        Some(false)
    );
}
