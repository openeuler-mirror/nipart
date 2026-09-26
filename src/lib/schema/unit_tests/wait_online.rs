// SPDX-License-Identifier: Apache-2.0

use crate::{NetworkState, NipartWaitOnlineCondition, RouteEntry};

const IFACE: &str = "wlan0";

fn current_state(link_state: &str) -> NetworkState {
    rmsd_yaml::from_str(&format!(
        r#"---
        interfaces:
          - name: {IFACE}
            type: wifi-phy
            state: up
            link-state: {link_state}
        "#
    ))
    .unwrap()
}

fn add_route(
    state: &mut NetworkState,
    destination: &str,
    next_hop_iface: Option<&str>,
) {
    let route = RouteEntry {
        destination: Some(destination.to_string()),
        next_hop_iface: next_hop_iface.map(str::to_string),
        ..Default::default()
    };
    state.routes.running = Some(vec![route]);
}

#[test]
fn test_gateway_met_only_when_iface_link_usable() {
    let mut up = current_state("up");
    add_route(&mut up, "0.0.0.0/0", Some(IFACE));
    assert!(NipartWaitOnlineCondition::Gateway.is_met(&up));

    // Tunnels, dummy and wireguard report `unknown` while up.
    let mut unknown = current_state("unknown");
    add_route(&mut unknown, "0.0.0.0/0", Some(IFACE));
    assert!(NipartWaitOnlineCondition::Gateway.is_met(&unknown));

    for link_state in ["down", "dormant", "lower-layer-down"] {
        let mut state = current_state(link_state);
        add_route(&mut state, "0.0.0.0/0", Some(IFACE));
        assert!(
            !NipartWaitOnlineCondition::Gateway.is_met(&state),
            "gateway on {link_state} interface must not count as online"
        );
    }
}

#[test]
fn test_gateway_met_with_route_on_another_usable_iface() {
    let mut state: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: wlan0
            type: wifi-phy
            state: up
            link-state: down
          - name: wg0
            type: wireguard
            state: up
            link-state: unknown
        "#,
    )
    .unwrap();
    let mut bad = RouteEntry {
        destination: Some("0.0.0.0/0".to_string()),
        next_hop_iface: Some("wlan0".to_string()),
        ..Default::default()
    };
    bad.metric = Some(100);
    let good = RouteEntry {
        destination: Some("0.0.0.0/0".to_string()),
        next_hop_iface: Some("wg0".to_string()),
        ..Default::default()
    };
    state.routes.running = Some(vec![bad, good]);
    assert!(NipartWaitOnlineCondition::Gateway.is_met(&state));
}

#[test]
fn test_gateway_not_met_without_nexthop_iface() {
    let mut state = current_state("up");
    add_route(&mut state, "0.0.0.0/0", None);
    assert!(!NipartWaitOnlineCondition::Gateway.is_met(&state));
}

#[test]
fn test_gateway_not_met_when_iface_missing_from_state() {
    let mut state = current_state("up");
    add_route(&mut state, "0.0.0.0/0", Some("wlan1"));
    assert!(!NipartWaitOnlineCondition::Gateway.is_met(&state));
}

#[test]
fn test_gateway_not_met_without_running_routes() {
    assert!(!NipartWaitOnlineCondition::Gateway.is_met(&current_state("up")));
}

#[test]
fn test_gateway4_and_gateway6_are_family_specific() {
    let mut v4 = current_state("up");
    add_route(&mut v4, "0.0.0.0/0", Some(IFACE));
    assert!(NipartWaitOnlineCondition::Gateway4.is_met(&v4));
    assert!(!NipartWaitOnlineCondition::Gateway6.is_met(&v4));
    assert!(NipartWaitOnlineCondition::Gateway.is_met(&v4));

    let mut v6 = current_state("up");
    add_route(&mut v6, "::/0", Some(IFACE));
    assert!(!NipartWaitOnlineCondition::Gateway4.is_met(&v6));
    assert!(NipartWaitOnlineCondition::Gateway6.is_met(&v6));
    assert!(NipartWaitOnlineCondition::Gateway.is_met(&v6));
}
