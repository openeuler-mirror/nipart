// SPDX-License-Identifier: Apache-2.0

use super::*;

fn saved_state() -> NetworkState {
    rmsd_yaml::from_str(
        r#"---
            routes:
              config:
                - destination: 0.0.0.0/0
                  next-hop-interface: eth0
            route-rules:
              config:
                - ip-from: 198.51.100.0/24
                  route-table: 500
                  iif: eth0
            interfaces:
              - name: eth0
                type: ethernet
                state: up
                ipv4:
                  enabled: true
                  dhcp: true
              - name: HomeWiFi
                type: wifi-cfg
                state: up
                wifi:
                  ssid: HomeWiFi
                  base-iface: wlan0
              - name: GuestWiFi
                type: wifi-cfg
                state: up
                wifi:
                  ssid: GuestWiFi
                  base-iface: wlan0
            "#,
    )
    .unwrap()
}

#[test]
fn test_find_saved_iface_by_name_and_profile() {
    let state = saved_state();
    assert_eq!(
        find_saved_iface(&state, "eth0").unwrap().iface_type(),
        &InterfaceType::Ethernet
    );
    assert_eq!(
        find_saved_iface(&state, "HomeWiFi").unwrap().iface_type(),
        &InterfaceType::WifiCfg
    );
    assert!(find_saved_iface(&state, "missing").is_none());
}

#[test]
fn test_up_state_keeps_routes_and_marks_up() {
    let state = saved_state();
    let iface = find_saved_iface(&state, "eth0").unwrap();
    let desired = gen_state_for_up(iface, &state);
    assert_eq!(
        desired.ifaces.iter().next().unwrap().base_iface().state,
        InterfaceState::Up
    );
    assert_eq!(
        desired
            .routes
            .config
            .as_ref()
            .unwrap()
            .iter()
            .filter(|rt| !rt.is_absent())
            .count(),
        1
    );
    assert_eq!(
        desired
            .route_rules
            .config
            .as_ref()
            .unwrap()
            .iter()
            .filter(|rule| !rule.is_absent())
            .count(),
        1
    );
}

#[test]
fn test_wifi_down_state_keeps_other_profiles_up() {
    let state = saved_state();
    let target = find_saved_iface(&state, "HomeWiFi").unwrap();
    let desired = gen_wifi_cfg_down_state(&state, target);
    let ifaces: Vec<_> = desired.ifaces.iter().collect();
    assert_eq!(ifaces.len(), 2);
    let home = ifaces
        .iter()
        .find(|iface| iface.name() == "HomeWiFi")
        .unwrap();
    let guest = ifaces
        .iter()
        .find(|iface| iface.name() == "GuestWiFi")
        .unwrap();
    assert!(home.is_down());
    assert!(guest.is_up());
}

#[test]
fn test_down_virtual_uses_absent_and_nonvirtual_uses_down() {
    let state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: dummy0
                type: dummy
                state: up
              - name: eth0
                type: ethernet
                state: up
            "#,
    )
    .unwrap();
    let dummy = find_saved_iface(&state, "dummy0").unwrap();
    let eth0 = find_saved_iface(&state, "eth0").unwrap();
    assert!(
        gen_state_for_down(dummy, &state)
            .ifaces
            .iter()
            .next()
            .unwrap()
            .is_absent()
    );
    assert!(
        gen_state_for_down(eth0, &state)
            .ifaces
            .iter()
            .next()
            .unwrap()
            .is_down()
    );
}

#[test]
fn test_down_preserves_ipv6_link_local_address() {
    let state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: wlan0
                type: wifi-phy
                state: up
            "#,
    )
    .unwrap();
    let wlan0 = find_saved_iface(&state, "wlan0").unwrap();

    for desired in [
        gen_state_for_down(wlan0, &state),
        gen_state_for_down_current_only(wlan0),
    ] {
        let iface = desired.ifaces.iter().next().unwrap();
        assert_eq!(
            iface.base_iface().ipv6,
            Some(InterfaceIpv6::new_purge_keep_link_local())
        );
    }
}

#[test]
fn test_down_marks_matching_route_rules_absent() {
    let state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: dummy0
                type: dummy
                state: up
            route-rules:
              config:
                - ip-from: 198.51.100.0/24
                  route-table: 500
                  iif: dummy0
            "#,
    )
    .unwrap();
    let dummy = find_saved_iface(&state, "dummy0").unwrap();
    let desired = gen_state_for_down(dummy, &state);
    let rules = desired.route_rules.config.as_ref().unwrap();
    assert_eq!(rules.len(), 1);
    assert!(rules[0].is_absent());
    assert_eq!(rules[0].iif.as_deref(), Some("dummy0"));
}
