// SPDX-License-Identifier: Apache-2.0

use nipart::{BaseInterface, InterfaceType, NetworkState, NipartInterface};

use super::{
    base_iface_for_dhcp_restore, gen_saved_route_reconcile_state,
    gen_wifi_off_purge_state, remove_manual_activation, remove_ready_state,
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
fn test_base_iface_for_dhcp_restore_inherits_config_only_ipv4() {
    let kernel_base: BaseInterface = rmsd_yaml::from_str(
        r#"---
            name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
            "#,
    )
    .unwrap();
    let saved_base: BaseInterface = rmsd_yaml::from_str(
        r#"---
            name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
              auto-gateway: false
              auto-route-metric: 321
            "#,
    )
    .unwrap();

    let ret = base_iface_for_dhcp_restore(&kernel_base, &saved_base);
    assert_eq!(ret.ipv4.as_ref().and_then(|i| i.auto_gateway), Some(false));
    assert_eq!(
        ret.ipv4.as_ref().and_then(|i| i.auto_route_metric),
        Some(321)
    );
}

#[test]
fn test_base_iface_for_dhcp_restore_defaults_to_none() {
    // Without `auto-gateway` in the saved config, the restored client
    // keeps the default behavior (gateway routes added).
    let kernel_base: BaseInterface = rmsd_yaml::from_str(
        r#"---
            name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
            "#,
    )
    .unwrap();
    // The saved config carries no IPv4 section at all.
    let saved_base: BaseInterface = rmsd_yaml::from_str(
        r#"---
            name: eth0
            type: ethernet
            state: up
            "#,
    )
    .unwrap();

    let ret = base_iface_for_dhcp_restore(&kernel_base, &saved_base);
    assert_eq!(ret.ipv4.as_ref().and_then(|i| i.auto_gateway), None);
    assert_eq!(ret.ipv4.as_ref().and_then(|i| i.auto_route_metric), None);
}

#[test]
fn test_remove_ready_state_moves_userspace_wifi_cfg() {
    // A `wifi-cfg` profile is a userspace interface: it must be moved
    // into the ready state so the boot retry loop can terminate, even
    // when no kernel NIC is ready yet.
    let mut state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: MyWiFi
                type: wifi-cfg
                state: up
                wifi:
                  ssid: MyWiFi
            "#,
    )
    .unwrap();

    let ready = remove_ready_state(&mut state, &[]);

    let wifi_cfgs: Vec<_> = ready
        .ifaces
        .iter()
        .filter(|i| i.iface_type() == &InterfaceType::WifiCfg)
        .collect();
    assert_eq!(wifi_cfgs.len(), 1);
    assert_eq!(wifi_cfgs[0].name(), "MyWiFi");
    assert!(state.ifaces.is_empty());
}

#[test]
fn test_remove_ready_state_keeps_unready_kernel_iface() {
    // The non-virtual kernel interface without udev initialization must
    // stay in the saved state for later retry, while the userspace
    // `wifi-cfg` is moved out immediately.
    let mut state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: eth0
                type: ethernet
                state: up
              - name: MyWiFi
                type: wifi-cfg
                state: up
                wifi:
                  ssid: MyWiFi
            "#,
    )
    .unwrap();

    let ready = remove_ready_state(&mut state, &[]);

    assert_eq!(
        ready
            .ifaces
            .iter()
            .filter(|i| i.iface_type() == &InterfaceType::WifiCfg)
            .count(),
        1
    );
    // eth0 is not ready yet, it should still be pending in saved state.
    assert!(state.ifaces.kernel_ifaces.contains_key("eth0"));
    assert!(state.ifaces.user_ifaces.is_empty());
}

#[test]
fn test_remove_ready_state_moves_global_route_rules_and_defers_iif() {
    let mut state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: eth0
                type: ethernet
                state: up
            route-rules:
              config:
                - ip-from: 198.51.100.0/24
                  route-table: 500
                - ip-from: 203.0.113.0/24
                  route-table: 500
                  iif: eth0
            "#,
    )
    .unwrap();

    let ready = remove_ready_state(&mut state, &[]);

    let ready_rules = ready.route_rules.config.unwrap();
    assert_eq!(ready_rules.len(), 1);
    assert!(ready_rules[0].iif.is_none());
    let pending_rules = state.route_rules.config.unwrap();
    assert_eq!(pending_rules.len(), 1);
    assert_eq!(pending_rules[0].iif.as_deref(), Some("eth0"));
}

#[test]
fn test_remove_ready_state_moves_route_rule_when_iif_ready() {
    let mut state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: eth0
                type: ethernet
                state: up
            route-rules:
              config:
                - ip-from: 203.0.113.0/24
                  route-table: 500
                  iif: eth0
            "#,
    )
    .unwrap();

    let ready = remove_ready_state(&mut state, &["eth0".to_string()]);

    let ready_rules = ready.route_rules.config.unwrap();
    assert_eq!(ready_rules.len(), 1);
    assert_eq!(ready_rules[0].iif.as_deref(), Some("eth0"));
    assert!(state.route_rules.config.unwrap().is_empty());
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
