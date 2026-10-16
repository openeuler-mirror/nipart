// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use nipart::{InterfaceState, NetworkState, NipartInterface};

use super::{append_saved_only_route_rules, merge_saved_into_running};

/// A running interface matched by a saved `state: ignore` profile is shown
/// as `state: ignore` and is not treated as a managed/active profile.
#[test]
fn test_saved_ignore_marks_running_iface_ignore() {
    let mut net_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: wlan1
                type: wifi-phy
                state: up
                mac-address: 02:00:00:00:00:01
            "#,
    )
    .unwrap();
    let mut saved_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: wlan1
                type: wifi-phy
                state: ignore
            "#,
    )
    .unwrap();
    let mut managed_ifaces: HashSet<String> = HashSet::new();

    let saved_only = merge_saved_into_running(
        &mut net_state,
        &mut saved_state,
        &mut managed_ifaces,
    );

    assert!(saved_only.is_empty());
    assert!(!managed_ifaces.contains("wlan1"));
    let cur_iface = net_state.ifaces.kernel_ifaces.get("wlan1").unwrap();
    assert_eq!(cur_iface.base_iface().state, InterfaceState::Ignore);
}

/// A saved `state: ignore` profile whose NIC is absent stays
/// `state: ignore` in the saved-only output instead of `state: saved`.
#[test]
fn test_saved_ignore_without_kernel_match_stays_ignore() {
    let mut net_state = NetworkState::default();
    let mut saved_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: usb0
                type: ethernet
                state: ignore
                identifier: mac-address
                mac-address: 02:00:00:00:00:42
            "#,
    )
    .unwrap();
    let mut managed_ifaces: HashSet<String> = HashSet::new();

    let saved_only = merge_saved_into_running(
        &mut net_state,
        &mut saved_state,
        &mut managed_ifaces,
    );

    assert_eq!(saved_only.len(), 1);
    assert_eq!(saved_only[0].base_iface().state, InterfaceState::Ignore);
}

#[test]
fn test_saved_route_rule_without_priority_not_duplicated() {
    let mut net_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            route-rules:
              config:
                - ip-from: 198.51.100.1/32
                  route-table: 254
                  priority: 30000
            "#,
    )
    .unwrap();
    let saved_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            route-rules:
              config:
                - ip-from: 198.51.100.1
            "#,
    )
    .unwrap();

    append_saved_only_route_rules(&mut net_state, &saved_state);

    let rules = net_state.route_rules.config.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].priority, Some(30000));
}

#[test]
fn test_saved_default_table_rule_not_matched_by_action_rule() {
    let mut net_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            route-rules:
              config:
                - ip-from: 198.51.100.1/32
                  action: blackhole
                  priority: 30000
            "#,
    )
    .unwrap();
    let saved_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            route-rules:
              config:
                - ip-from: 198.51.100.1
            "#,
    )
    .unwrap();

    append_saved_only_route_rules(&mut net_state, &saved_state);

    let rules = net_state.route_rules.config.unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[1].ip_from.as_deref(), Some("198.51.100.1"));
    assert_eq!(rules[1].table_id, Some(254));
}
