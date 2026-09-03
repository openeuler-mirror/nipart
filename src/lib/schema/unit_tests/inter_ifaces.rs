// SPDX-License-Identifier: Apache-2.0

use crate::{
    BaseInterface, DhcpState, Interface, InterfaceIdentifier, InterfaceIpv4,
    InterfaceIpv6, InterfaceState, InterfaceType, Interfaces, MergedInterfaces,
    MergedNetworkState, NetworkState, NipartInterface,
};

/// Desired `state: saved` must persist the profile without applying or
/// verifying anything in the kernel.
#[test]
fn test_desired_state_saved_only_persists_without_apply() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: cunet
          type: ethernet
          state: saved
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();

    let merged =
        MergedInterfaces::new(desired, Interfaces::default(), None).unwrap();

    let merged_iface = merged.kernel_ifaces.get("cunet").unwrap();
    assert!(merged_iface.for_apply.is_none());
    assert!(merged_iface.for_verify.is_none());
    assert!(merged_iface.for_revert.is_none());
    assert!(merged_iface.merged.base_iface().state.is_saved());

    let for_save = merged_iface.for_save.as_ref().unwrap();
    assert_eq!(for_save.base_iface().state, InterfaceState::Up);
    assert_eq!(for_save.name(), "cunet");
}

/// Desired `state: saved` keeps the previous saved state when updating an
/// existing profile.
#[test]
fn test_desired_state_saved_keeps_previous_saved_state() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: cunet
          type: ethernet
          state: saved
          mtu: 1280
        "#,
    )
    .unwrap();
    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: cunet
          type: ethernet
          state: down
        "#,
    )
    .unwrap();

    let merged =
        MergedInterfaces::new(desired, Interfaces::default(), Some(saved))
            .unwrap();

    let merged_iface = merged.kernel_ifaces.get("cunet").unwrap();
    assert!(merged_iface.for_apply.is_none());
    let for_save = merged_iface.for_save.as_ref().unwrap();
    assert_eq!(for_save.base_iface().state, InterfaceState::Down);
    assert_eq!(for_save.base_iface().mtu, Some(1280));
}

/// Desired `state: saved` on an existing running interface must not change
/// the kernel, only the persisted config.
#[test]
fn test_desired_state_saved_does_not_change_current() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: cunet
          type: ethernet
          state: saved
          mtu: 1280
        "#,
    )
    .unwrap();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: cunet
          type: ethernet
          state: up
          mtu: 1500
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let merged_iface = merged.kernel_ifaces.get("cunet").unwrap();
    assert!(merged_iface.for_apply.is_none());
    assert!(merged_iface.for_verify.is_none());
    let for_save = merged_iface.for_save.as_ref().unwrap();
    assert_eq!(for_save.base_iface().mtu, Some(1280));
}

/// Test basic MAC address matching with MAC provided.
#[test]
fn test_resolve_mac_identifier_basic_with_mac() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    // Interface should be keyed by kernel name
    assert!(merged.kernel_ifaces.contains_key("eth0"));
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    assert_eq!(for_apply.base_iface().kernel_iface_name.as_str(), "eth0");
}

/// Test MAC address matching for `wifi-phy` interfaces.
#[test]
fn test_resolve_mac_identifier_wifi_phy() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: HomeWiFi
          type: wifi-phy
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wlan0
          type: wifi-phy
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    assert!(merged.kernel_ifaces.contains_key("wlan0"));
    let merged_iface = merged.kernel_ifaces.get("wlan0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    assert_eq!(for_apply.base_iface().kernel_iface_name.as_str(), "wlan0");
}

/// Test that the force apply option keeps the full desired config even when
/// the current kernel state already matches it, so explicit up/down actions
/// can restart DHCP/WIFI instead of being treated as a no-op.
#[test]
fn test_force_apply_keeps_full_desired_when_unchanged() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
        "#,
    )
    .unwrap();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
        "#,
    )
    .unwrap();

    let normal =
        MergedInterfaces::new(desired.clone(), current.clone(), None).unwrap();
    assert!(
        normal
            .kernel_ifaces
            .get("eth0")
            .unwrap()
            .for_apply
            .is_none()
    );

    let forced =
        MergedInterfaces::new_with_force(desired, current, None, true).unwrap();
    let forced_apply = forced
        .kernel_ifaces
        .get("eth0")
        .unwrap()
        .for_apply
        .as_ref()
        .unwrap();
    assert_eq!(
        forced_apply
            .base_iface()
            .ipv4
            .as_ref()
            .map(|ipv4| ipv4.dhcp),
        Some(Some(true))
    );
}

/// Test MAC address matching with `permanent-mac-address`.
#[test]
fn test_resolve_mac_identifier_perm_mac() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 00:00:00:00:00:00
          permanent-mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    assert_eq!(for_apply.base_iface().kernel_iface_name.as_str(), "eth0");
}

/// Test error when MAC does not match any current interface.
#[test]
fn test_resolve_mac_identifier_no_match() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 00:00:00:00:00:00
        "#,
    )
    .unwrap();

    let result = MergedInterfaces::new(desired, current, None);
    assert!(result.is_err());
}

/// Test re-resolution when profile_name already set and NIC name changed.
#[test]
fn test_resolve_mac_identifier_re_resolve() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
          profile-name: wan0
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: enp0s3
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    // Should be keyed by new kernel name
    assert!(merged.kernel_ifaces.contains_key("enp0s3"));
    let merged_iface = merged.kernel_ifaces.get("enp0s3").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    assert_eq!(for_apply.base_iface().kernel_iface_name.as_str(), "enp0s3");
}

/// Test that absent interfaces with MAC identifier still merge correctly.
#[test]
fn test_resolve_mac_identifier_absent_skipped() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
          state: absent
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    // Absent interface should still be matched by MAC and keyed by
    // kernel name
    assert!(merged.kernel_ifaces.contains_key("eth0"));
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    // Non-virtual interface should have state: down in for_apply
    assert_eq!(
        merged_iface.for_apply.as_ref().unwrap().base_iface().state,
        InterfaceState::Down
    );
    // for_save should preserve the absent intent
    assert_eq!(
        merged_iface.for_save.as_ref().unwrap().base_iface().state,
        InterfaceState::Absent
    );
}

/// Test resolving interface with MAC identifier matches by MAC
/// regardless of interface type in desired state.
#[test]
fn test_resolve_mac_identifier_unknown_type() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    // Merged type should be Ethernet
    assert_eq!(merged_iface.merged.iface_type(), &InterfaceType::Ethernet);
}

/// Test error when mac_address is not provided.
#[test]
fn test_resolve_mac_identifier_missing_mac() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let result = MergedInterfaces::new(desired, current, None);
    assert!(result.is_err());
}

/// Test that already-resolved interface (name matches kernel name) works.
#[test]
fn test_resolve_mac_identifier_already_resolved() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
          profile-name: wan0
          kernel-iface-name: eth0
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    // Should still have eth0
    assert!(merged.kernel_ifaces.contains_key("eth0"));
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    assert_eq!(for_apply.base_iface().kernel_iface_name.as_str(), "eth0");
}

/// Test case-insensitive MAC address matching.
#[test]
fn test_resolve_mac_identifier_case_insensitive() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    assert!(merged.kernel_ifaces.contains_key("eth0"));
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    assert_eq!(for_apply.base_iface().kernel_iface_name.as_str(), "eth0");
}

/// Test resolving multiple interfaces with MAC identifiers.
#[test]
fn test_resolve_mac_identifier_multiple_ifaces() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:03
        - name: wan1
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:0c
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:03
        - name: eth1
          type: ethernet
          mac-address: 02:00:00:00:00:0c
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    assert!(merged.kernel_ifaces.contains_key("eth0"));
    assert!(merged.kernel_ifaces.contains_key("eth1"));
    let merged1 = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply1 = merged1.for_apply.as_ref().unwrap();
    assert_eq!(for_apply1.base_iface().kernel_iface_name.as_str(), "eth0");
    let merged2 = merged.kernel_ifaces.get("eth1").unwrap();
    let for_apply2 = merged2.for_apply.as_ref().unwrap();
    assert_eq!(for_apply2.base_iface().kernel_iface_name.as_str(), "eth1");
}

/// Test that permanent_mac_address is preferred over mac_address when
/// matching.
#[test]
fn test_resolve_mac_identifier_perm_mac_preferred() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:03
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: ff:ff:ff:ff:ff:ff
          permanent-mac-address: 02:00:00:00:00:03
        - name: eth1
          type: ethernet
          mac-address: 02:00:00:00:00:03
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    // Should match eth0 (permanent_mac_address match)
    assert!(merged.kernel_ifaces.contains_key("eth0"));
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    assert!(merged_iface.is_desired());
}

/// Test that matching against multiple NICs with the same MAC picks the
/// first match.
#[test]
fn test_resolve_mac_identifier_duplicate_mac_across_nics() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: wan0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:03
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:03
        - name: eth1
          type: ethernet
          mac-address: 02:00:00:00:00:03
        "#,
    )
    .unwrap();

    // Should succeed, picking the first MAC match
    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    // One of eth0/eth1 should be the desired matched interface
    let desired_count = merged
        .kernel_ifaces
        .values()
        .filter(|i| i.is_desired())
        .count();
    assert_eq!(desired_count, 1);
}

/// Test re-resolution when NIC renamed (eth0 -> eth1).
#[test]
fn test_resolve_mac_identifier_re_resolve_type_change() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
          profile-name: wan0
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth1
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    assert!(merged.kernel_ifaces.contains_key("eth1"));
    let merged_iface = merged.kernel_ifaces.get("eth1").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    assert_eq!(for_apply.base_iface().kernel_iface_name.as_str(), "eth1");
}

/// Test full merge flow with MAC identifier via MergedNetworkState.
#[test]
fn test_merge_flow_with_mac_identifier() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: wan0
            type: ethernet
            state: up
            identifier: mac-address
            mac-address: 02:00:00:00:00:01
            ipv4:
              enabled: true
              address:
                - ip: 192.168.1.100
                  prefix-length: 24
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: eth0
            type: ethernet
            mac-address: 02:00:00:00:00:01
            state: up
        "#,
    )
    .unwrap();

    let merged =
        MergedNetworkState::new(desired, current, None, Default::default())
            .unwrap();
    let apply_state = merged.gen_state_for_apply();

    // After merge, the interface should be keyed by kernel name
    let apply_iface = apply_state.ifaces.kernel_ifaces.get("eth0").unwrap();
    assert_eq!(apply_iface.base_iface().name, "eth0");
    assert_eq!(apply_iface.base_iface().kernel_iface_name.as_str(), "eth0");
    assert_eq!(
        apply_iface.base_iface().profile_name.as_deref(),
        Some("wan0")
    );
    // IP config should have been merged
    assert!(apply_iface.base_iface().ipv4.is_some());
}

/// Test that sanitize converts MAC addresses to uppercase.
#[test]
fn test_sanitize_mac_address_to_uppercase() {
    let mut base =
        BaseInterface::new("eth0".to_string(), InterfaceType::Ethernet);
    base.identifier = Some(InterfaceIdentifier::MacAddress);
    base.mac_address = Some("02:00:00:00:00:02".to_string());
    base.permanent_mac_address = Some("02:00:00:00:00:0c".to_string());

    let mut for_save = base.clone();
    let mut for_apply = base.clone();
    let mut for_verify = base.clone();
    let mut merged = base.clone();

    base.sanitize(
        None,
        None,
        &mut for_save,
        &mut for_apply,
        &mut for_verify,
        &mut merged,
    )
    .unwrap();

    assert_eq!(for_apply.mac_address.as_deref(), Some("02:00:00:00:00:02"));
    assert_eq!(for_verify.mac_address.as_deref(), Some("02:00:00:00:00:02"));
    assert_eq!(for_save.mac_address.as_deref(), Some("02:00:00:00:00:02"));
    assert_eq!(merged.mac_address.as_deref(), Some("02:00:00:00:00:02"));
    // permanent_mac_address is query-only, only merged should hold it
    assert_eq!(for_apply.permanent_mac_address.as_deref(), None);
    assert_eq!(for_save.permanent_mac_address.as_deref(), None);
    assert_eq!(for_verify.permanent_mac_address.as_deref(), None);
    assert_eq!(
        merged.permanent_mac_address.as_deref(),
        Some("02:00:00:00:00:0C")
    );
}

/// Test that sanitize does NOT override kernel_iface_name for MacAddress
/// identifier.
#[test]
fn test_sanitize_does_not_override_mac_kernel_iface_name() {
    let base = BaseInterface::new("wan0".to_string(), InterfaceType::Ethernet);
    let mut for_save = base.clone();
    let mut for_apply = base.clone();
    let mut for_verify = base.clone();
    let mut merged = base.clone();
    for_apply.identifier = Some(InterfaceIdentifier::MacAddress);
    for_apply.kernel_iface_name = "eth0".to_string();
    base.sanitize(
        None,
        None,
        &mut for_save,
        &mut for_apply,
        &mut for_verify,
        &mut merged,
    )
    .unwrap();
    // kernel_iface_name should be preserved (not overwritten by sanitize)
    assert_eq!(for_apply.kernel_iface_name.as_str(), "eth0");
}

/// A MAC-identifier desired interface with a route referencing its logical
/// name must resolve the next-hop-interface to the kernel name even when the
/// saved state holds both the MAC-identifier config and a plain saved config
/// of the same kernel interface (which must not overwrite the merged
/// interface).
#[test]
fn test_route_next_hop_iface_with_plain_saved_config_not_overwritten() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: my-gw-iface
            type: ethernet
            state: up
            identifier: mac-address
            mac-address: 86:FC:DF:CF:66:E1
            ipv4:
              enabled: true
              dhcp: false
              address:
                - ip: 192.0.2.99
                  prefix-length: 24
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-interface: my-gw-iface
              next-hop-address: 192.0.2.1
              table-id: 254
              metric: 199
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: veth-mac0
            kernel-iface-name: veth-mac0
            type: ethernet
            mac-address: 86:FC:DF:CF:66:E1
            state: up
            ipv4:
              enabled: false
            ipv6:
              enabled: true
              dhcp: false
              autoconf: false
              address:
                - ip: fe80::38ce:43ff:fea8:fcc5
                  prefix-length: 64
            ethernet:
              auto-negotiation: false
              speed: 10000
              duplex: full
            veth:
              peer: veth-mac1
        "#,
    )
    .unwrap();

    // Saved config of the previous apply (keyed by profile name), plus the
    // plain saved config of the same kernel interface from its creation.
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: my-veth
            profile-name: my-veth
            type: ethernet
            identifier: mac-address
            state: up
            mac-address: 86:FC:DF:CF:66:E1
            ipv4:
              enabled: true
              dhcp: false
              address:
                - ip: 192.0.2.99
                  prefix-length: 24
            veth:
              peer: veth-mac1
          - name: veth-mac0
            kernel-iface-name: veth-mac0
            type: ethernet
            state: up
            veth:
              peer: veth-mac1
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();
    let changed: Vec<&str> = merged
        .routes
        .changed_routes
        .iter()
        .filter_map(|r| r.next_hop_iface.as_deref())
        .collect();
    assert_eq!(changed, vec!["veth-mac0"]);
}

/// Test that route next-hop-interface with MAC identifier resolves from
/// logical name (profile_name) to kernel name.
#[test]
fn test_route_next_hop_iface_resolves_by_profile_name() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: wan0
            type: ethernet
            state: up
            identifier: mac-address
            mac-address: 02:00:00:00:00:01
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-interface: wan0
              next-hop-address: 192.168.1.1
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: eth0
            type: ethernet
            mac-address: 02:00:00:00:00:01
            state: up
            ipv4:
              enabled: true
              dhcp: false
        "#,
    )
    .unwrap();

    let merged =
        MergedNetworkState::new(desired, current, None, Default::default())
            .unwrap();

    let changed: Vec<&str> = merged
        .routes
        .changed_routes
        .iter()
        .filter_map(|r| r.next_hop_iface.as_deref())
        .collect();
    assert_eq!(changed, vec!["eth0"]);
}

/// Test that route next-hop-interface with direct kernel name succeeds
/// without profile_name lookup.
#[test]
fn test_route_next_hop_iface_direct_kernel_name() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: wan0
            type: ethernet
            state: up
            identifier: mac-address
            mac-address: 02:00:00:00:00:01
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-interface: eth0
              next-hop-address: 192.168.1.1
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: eth0
            type: ethernet
            mac-address: 02:00:00:00:00:01
            state: up
            ipv4:
              enabled: true
              dhcp: false
        "#,
    )
    .unwrap();

    let merged =
        MergedNetworkState::new(desired, current, None, Default::default())
            .unwrap();

    let changed: Vec<&str> = merged
        .routes
        .changed_routes
        .iter()
        .filter_map(|r| r.next_hop_iface.as_deref())
        .collect();
    assert_eq!(changed, vec!["eth0"]);
}

/// Test that route next-hop-interface pointing to absent interface
/// via logical name raises error.
#[test]
fn test_route_next_hop_iface_absent_by_logical_name() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: wan0
            type: ethernet
            state: absent
            identifier: mac-address
            mac-address: 02:00:00:00:00:01
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-interface: wan0
              next-hop-address: 192.168.1.1
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: eth0
            type: ethernet
            mac-address: 02:00:00:00:00:01
            state: up
        "#,
    )
    .unwrap();

    let result =
        MergedNetworkState::new(desired, current, None, Default::default());
    assert!(result.is_err());
    assert!(result.unwrap_err().msg.contains("marked as absent"));
}

/// Test that resolve_route_next_hop_iface with duplicate profile_name
/// resolves to one of the matches via MergedInterfaces::new().
#[test]
fn test_route_next_hop_iface_duplicate_logical_name() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          profile-name: eth1
        - name: eth1
          type: ethernet
          state: up
          profile-name: eth1
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
        - name: eth1
          type: ethernet
        "#,
    )
    .unwrap();

    let merged_ifaces = MergedInterfaces::new(desired, current, None).unwrap();

    // IfaceSearch stores last inserted profile mapping
    let result = merged_ifaces.resolve_route_next_hop_iface("eth1");
    assert!(result.is_some());
}

/// Test that resolve_route_next_hop_iface returns None
/// when no match is found (neither kernel name nor profile_name).
#[test]
fn test_route_next_hop_iface_no_match_returns_none() {
    let merged_ifaces = MergedInterfaces::default();

    let result = merged_ifaces.resolve_route_next_hop_iface("nonexistent");
    assert!(result.is_none());
}

/// Test that resolve_route_next_hop_iface returns kernel name when
/// a single profile_name match is found via MergedInterfaces::new().
#[test]
fn test_route_next_hop_iface_single_profile_match() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          profile-name: eth1
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
        "#,
    )
    .unwrap();

    let merged_ifaces = MergedInterfaces::new(desired, current, None).unwrap();

    let result = merged_ifaces.resolve_route_next_hop_iface("eth1");
    assert_eq!(result, Some("eth0".to_string()));
}

/// Test that route with next-hop-interface pointing to a non-existent
/// interface raises error.
#[test]
fn test_route_next_hop_iface_unmatched_logical_name_adds_route() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-interface: nonexistent
              next-hop-address: 192.168.1.1
              table-id: 254
        "#,
    )
    .unwrap();

    let current = NetworkState::default();

    let result =
        MergedNetworkState::new(desired, current, None, Default::default());
    assert!(result.is_err());
}

/// A route whose `next-hop-interface` names an up `wifi-cfg` profile must
/// resolve to the kernel `wifi-phy` currently connected to that profile,
/// not be left pointing at the userspace profile name.
#[test]
fn test_wifi_cfg_route_next_hop_resolves_to_connected_phy() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: HomeWiFi
            type: wifi-cfg
            state: up
            ipv4:
              enabled: true
              dhcp: false
              address:
                - ip: 192.0.2.99
                  prefix-length: 24
            wifi:
              ssid: HomeWiFi
              base-iface: wlan0
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: HomeWiFi
              next-hop-address: 192.0.2.1
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: wlan0
            type: wifi-phy
            state: up
            link-state: up
            mac-address: 02:00:00:00:00:01
            wifi:
              ssid: HomeWiFi
        "#,
    )
    .unwrap();

    let merged =
        MergedNetworkState::new(desired, current, None, Default::default())
            .unwrap();
    let changed: Vec<&str> = merged
        .routes
        .changed_routes
        .iter()
        .filter_map(|rt| rt.next_hop_iface.as_deref())
        .collect();
    assert_eq!(changed, vec!["wlan0"]);
}

/// A route to an up `wifi-cfg` whose wifi-phy is not connected yet must not
/// be sent to the kernel. It is persisted so the link-up event can apply it
/// after the profile associates.
#[test]
fn test_wifi_cfg_route_deferred_when_phy_not_connected() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: HomeWiFi
            type: wifi-cfg
            state: up
            wifi:
              ssid: HomeWiFi
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: HomeWiFi
              next-hop-address: 192.0.2.1
              table-id: 254
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        NetworkState::default(),
        None,
        Default::default(),
    )
    .unwrap();

    assert!(merged.routes.changed_routes.is_empty());
    assert!(merged.routes.route_changed_ifaces.is_empty());

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert_eq!(saved_routes.len(), 1);
    assert_eq!(saved_routes[0].next_hop_iface.as_deref(), Some("HomeWiFi"));
}

/// The route resolver must not treat userspace-only profiles (e.g.
/// `wifi-cfg`) as kernel interface names.
#[test]
fn test_resolve_route_next_hop_ignores_userspace_wifi_cfg() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: HomeWiFi
          type: wifi-cfg
          state: up
          wifi:
            ssid: HomeWiFi
        "#,
    )
    .unwrap();

    let merged =
        MergedInterfaces::new(desired, Interfaces::default(), None).unwrap();
    assert_eq!(merged.resolve_route_next_hop_iface("HomeWiFi"), None);
}

/// Test parsing `auto-gateway` in IPv4 DHCP config.
#[test]
fn test_ipv4_auto_gateway_false() {
    let net_state: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
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

    let iface = net_state
        .ifaces
        .kernel_ifaces
        .get("eth1")
        .map(|i| i.base_iface().ipv4.as_ref().unwrap().clone())
        .unwrap();

    assert_eq!(iface.auto_gateway, Some(false));
}

/// Test that default value for `auto-gateway` is `None` when not specified.
#[test]
fn test_ipv4_auto_gateway_defaults() {
    let net_state: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
        "#,
    )
    .unwrap();

    let iface = net_state
        .ifaces
        .kernel_ifaces
        .get("eth1")
        .map(|i| i.base_iface().ipv4.as_ref().unwrap().clone())
        .unwrap();

    assert_eq!(iface.auto_gateway, None);
}

/// Test `auto-gateway: true`.
#[test]
fn test_ipv4_auto_gateway_true() {
    let net_state: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
              auto-gateway: true
        "#,
    )
    .unwrap();

    let iface = net_state
        .ifaces
        .kernel_ifaces
        .get("eth1")
        .map(|i| i.base_iface().ipv4.as_ref().unwrap().clone())
        .unwrap();

    assert_eq!(iface.auto_gateway, Some(true));
}

/// Test parsing `auto-route-metric` in IPv4 DHCP config.
#[test]
fn test_ipv4_auto_route_metric() {
    let net_state: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
              auto-route-metric: 321
        "#,
    )
    .unwrap();

    let iface = net_state
        .ifaces
        .kernel_ifaces
        .get("eth1")
        .map(|i| i.base_iface().ipv4.as_ref().unwrap().clone())
        .unwrap();

    assert_eq!(iface.auto_route_metric, Some(321));
}

/// Test that the default value for `auto-route-metric` is `None` when not
/// specified.
#[test]
fn test_ipv4_auto_route_metric_defaults() {
    let net_state: NetworkState = rmsd_yaml::from_str(
        r#"
        interfaces:
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: true
        "#,
    )
    .unwrap();

    let iface = net_state
        .ifaces
        .kernel_ifaces
        .get("eth1")
        .map(|i| i.base_iface().ipv4.as_ref().unwrap().clone())
        .unwrap();

    assert_eq!(iface.auto_route_metric, None);
}

/// Test that `auto-route-metric` survives the merge into both `merged` and
/// `for_apply` when DHCP is already running in the kernel.
///
/// The DHCPv4 lease paths decide the gateway route metric from the merged
/// IPv4 config, so losing it during the merge would make
/// `auto-route-metric` ineffective.
#[test]
fn test_ipv4_auto_route_metric_survives_merge() {
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth1
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
        "#,
    )
    .unwrap();

    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth1
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            auto-route-metric: 321
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth1").unwrap();

    let merged_ipv4 = merged_iface.merged.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(merged_ipv4.auto_route_metric, Some(321));

    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(apply_ipv4.auto_route_metric, Some(321));
}

/// Test DHCP route metric selection with `auto-route-metric` defined.
#[test]
fn test_ipv4_dhcp_route_metric_uses_auto_route_metric() {
    let ipv4 = InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(true),
        auto_route_metric: Some(321),
        ..Default::default()
    };
    assert_eq!(ipv4.dhcp_route_metric(Some(9), 0), Some(321));
    assert_eq!(ipv4.dhcp_route_metric(Some(9), 1), Some(321));
}

/// Test DHCP route metric fallback to `iface-index * 100`.
#[test]
fn test_ipv4_dhcp_route_metric_falls_back_to_iface_index() {
    let ipv4 = InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(true),
        ..Default::default()
    };
    assert_eq!(ipv4.dhcp_route_metric(Some(9), 0), Some(900));
    assert_eq!(ipv4.dhcp_route_metric(Some(9), 1), Some(901));
    assert_eq!(ipv4.dhcp_route_metric(None, 0), None);
}

/// Test DHCP route metric treats `-1` as "use the default metric".
#[test]
fn test_ipv4_dhcp_route_metric_default_metric_value() {
    let ipv4 = InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(true),
        auto_route_metric: Some(-1),
        ..Default::default()
    };
    assert_eq!(ipv4.dhcp_route_metric(Some(9), 0), Some(900));
}

/// Test that `auto-gateway: false` survives the merge into both `merged`
/// and `for_apply` when DHCP is already running in the kernel.
///
/// The no-daemon DHCPv4 lease path decides whether to add the gateway routes
/// from `merged_iface.merged.base_iface().ipv4.auto_gateway`, so losing it
/// during the merge would make `auto-gateway: false` ineffective there.
#[test]
fn test_ipv4_auto_gateway_false_survives_merge() {
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth1
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
        "#,
    )
    .unwrap();

    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
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

    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth1").unwrap();

    let merged_ipv4 = merged_iface.merged.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(merged_ipv4.auto_gateway, Some(false));

    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(apply_ipv4.auto_gateway, Some(false));
}

/// Test that `InterfaceIpv4::new_disabled()` sets new fields to None.
#[test]
fn test_ipv4_new_disabled() {
    let ipv4 = InterfaceIpv4::new_disabled();
    assert_eq!(ipv4.auto_gateway, None);
    assert_eq!(ipv4.auto_route_metric, None);
}

/// Test that sanitize clears auto_gateway when DHCP is off.
#[test]
fn test_ipv4_sanitize_clears_when_dhcp_off() {
    let mut ipv4 = InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(false),
        dhcp_state: None,
        addresses: None,
        auto_gateway: Some(false),
        auto_route_metric: Some(321),
    };
    ipv4.sanitize(None).unwrap();
    assert_eq!(ipv4.auto_gateway, None);
    assert_eq!(ipv4.auto_route_metric, None);
}

/// Test that sanitize clears auto_gateway when IP disabled.
#[test]
fn test_ipv4_sanitize_clears_when_ip_disabled() {
    let mut ipv4 = InterfaceIpv4 {
        enabled: Some(false),
        dhcp: Some(true),
        dhcp_state: None,
        addresses: None,
        auto_gateway: Some(false),
        auto_route_metric: Some(321),
    };
    ipv4.sanitize(None).unwrap();
    assert_eq!(ipv4.auto_gateway, None);
    assert_eq!(ipv4.auto_route_metric, None);
}

/// Test that sanitize rejects out-of-range `auto-route-metric`.
#[test]
fn test_ipv4_sanitize_rejects_out_of_range_auto_route_metric() {
    let mut ipv4 = InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(true),
        dhcp_state: None,
        addresses: None,
        auto_gateway: None,
        auto_route_metric: Some(u32::MAX as i64 + 1),
    };
    assert!(ipv4.sanitize(None).is_err());
}

/// Test that ipv6 sanitize clears dhcp_state (query only field).
#[test]
fn test_ipv6_sanitize_clears_dhcp_state() {
    let mut ipv6 = InterfaceIpv6 {
        enabled: Some(true),
        dhcp: Some(true),
        dhcp_state: Some(DhcpState::Done),
        autoconf: Some(false),
        addresses: None,
    };
    ipv6.sanitize(None).unwrap();
    assert_eq!(ipv6.dhcp_state, None);
    assert_eq!(ipv6.dhcp, Some(true));
}

/// Test that bond port names are resolved from profile names to kernel
/// interface names when ports use MAC address identifier.
#[test]
fn test_bond_resolve_port_ref_by_mac_identifier() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: port1
            - name: port2
        - name: port1
          type: ethernet
          mac-address: 02:00:00:00:00:01
          identifier: mac-address
        - name: port2
          type: ethernet
          mac-address: 02:00:00:00:00:02
          identifier: mac-address"#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01
        - name: eth1
          type: ethernet
          mac-address: 02:00:00:00:00:02"#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let bond = merged.kernel_ifaces.get("bond1").unwrap();

    assert_eq!(
        bond.for_apply.as_ref().unwrap().ports().unwrap(),
        vec!["eth0", "eth1"]
    );
    assert_eq!(
        bond.for_verify.as_ref().unwrap().ports().unwrap(),
        vec!["eth0", "eth1"]
    );
    assert_eq!(
        bond.for_save.as_ref().unwrap().ports().unwrap(),
        vec!["port1", "port2"]
    );
    assert_eq!(bond.merged.ports().unwrap(), vec!["eth0", "eth1"]);
}

/// Test that linux bridge port names are resolved from profile names to
/// kernel interface names when ports use MAC address identifier.
#[test]
fn test_linux_bridge_resolve_port_ref_by_mac_identifier() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: br0
          type: linux-bridge
          state: up
          bridge:
            port:
            - name: port1
        - name: port1
          type: ethernet
          mac-address: 02:00:00:00:00:01
          identifier: mac-address"#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01"#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let br = merged.kernel_ifaces.get("br0").unwrap();

    assert_eq!(
        br.for_apply.as_ref().unwrap().ports().unwrap(),
        vec!["eth0"]
    );
    assert_eq!(
        br.for_verify.as_ref().unwrap().ports().unwrap(),
        vec!["eth0"]
    );
    assert_eq!(
        br.for_save.as_ref().unwrap().ports().unwrap(),
        vec!["port1"]
    );
    assert_eq!(br.merged.ports().unwrap(), vec!["eth0"]);
}

/// Test that OVS bridge port names are resolved from profile names to
/// kernel interface names when ports use MAC address identifier.
#[test]
fn test_ovs_bridge_resolve_port_ref_by_mac_identifier() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: ovs-br0
          type: ovs-bridge
          state: up
          bridge:
            ports:
            - name: port1
        - name: port1
          type: ethernet
          mac-address: 02:00:00:00:00:01
          identifier: mac-address"#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:01
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let br = merged
        .user_ifaces
        .get(&("ovs-br0".to_string(), crate::InterfaceType::OvsBridge))
        .unwrap();

    assert_eq!(
        br.for_apply.as_ref().unwrap().ports().unwrap(),
        vec!["eth0"]
    );
    assert_eq!(
        br.for_verify.as_ref().unwrap().ports().unwrap(),
        vec!["eth0"]
    );
    assert_eq!(
        br.for_save.as_ref().unwrap().ports().unwrap(),
        vec!["port1"]
    );
    assert_eq!(br.merged.ports().unwrap(), vec!["eth0"]);
}

/// Test gen_state_for_apply() and gen_state_for_save() with bond ports
/// resolved by MAC identifier matching uppercase MACs in current state.
#[test]
fn test_bond_gen_state_for_apply_and_save() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: port1
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:01
        - name: port2
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:02
        - name: bond0
          kernel-iface-name: bond0
          type: bond
          state: up
          bond:
            mode: balance-rr
            ports:
            - name: port1
            - name: port2"#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth1
          kernel-iface-name: eth1
          type: ethernet
          state: down
          mac-address: 02:00:00:00:00:01
        - name: eth2
          kernel-iface-name: eth2
          type: ethernet
          state: down
          mac-address: 02:00:00:00:00:02"#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let apply_state = merged.gen_state_for_apply();
    let save_state = merged.gen_state_for_save();

    let eth1_apply = apply_state.kernel_ifaces.get("eth1").unwrap();
    let eth1_saved = save_state.kernel_ifaces.get("port1").unwrap();

    let eth2_apply = apply_state.kernel_ifaces.get("eth2").unwrap();
    let eth2_saved = save_state.kernel_ifaces.get("port2").unwrap();
    assert_eq!(eth1_apply.name(), "eth1");
    assert_eq!(eth1_saved.name(), "port1");
    assert_eq!(
        eth1_apply.base_iface().profile_name.as_deref(),
        Some("port1")
    );
    assert_eq!(
        eth1_saved.base_iface().profile_name.as_deref(),
        Some("port1")
    );
    assert_eq!(eth2_apply.name(), "eth2");
    assert_eq!(eth2_saved.name(), "port2");
    assert_eq!(
        eth2_apply.base_iface().profile_name.as_deref(),
        Some("port2")
    );
    assert_eq!(
        eth2_saved.base_iface().profile_name.as_deref(),
        Some("port2")
    );
}

/// Test that BaseInterface::sanitize preserves for_save IP config when
/// for_apply has no IP changes (the diff omitted ipv4/ipv6 because the
/// current kernel state already matches).
#[test]
fn test_sanitize_preserves_ip_when_for_apply_has_no_ip() {
    let mut base =
        BaseInterface::new("eth0".to_string(), InterfaceType::Ethernet);
    base.ipv4 = Some(InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(true),
        auto_gateway: Some(false),
        ..Default::default()
    });
    base.ipv6 = Some(InterfaceIpv6 {
        enabled: Some(true),
        dhcp: Some(true),
        autoconf: Some(false),
        ..Default::default()
    });

    // for_save has the full desired IP config
    let mut for_save = base.clone();
    let mut for_verify = base.clone();
    let mut merged = base.clone();

    // for_apply has NO ipv4/ipv6 (diff produced no IP changes)
    let mut for_apply = base.clone();
    for_apply.ipv4 = None;
    for_apply.ipv6 = None;

    base.sanitize(
        None,
        None,
        &mut for_save,
        &mut for_apply,
        &mut for_verify,
        &mut merged,
    )
    .unwrap();

    // for_save should still have the original IP config
    let ipv4 = for_save.ipv4.as_ref().expect("ipv4 should be preserved");
    assert_eq!(ipv4.enabled, Some(true));
    assert_eq!(ipv4.dhcp, Some(true));
    assert_eq!(ipv4.auto_gateway, Some(false));

    let ipv6 = for_save.ipv6.as_ref().expect("ipv6 should be preserved");
    assert_eq!(ipv6.enabled, Some(true));
    assert_eq!(ipv6.dhcp, Some(true));
    assert_eq!(ipv6.autoconf, Some(false));
}

/// Test that BaseInterface::sanitize fills `for_apply` with the full merged
/// IP config (derived from `for_save`) instead of the partial diff, then
/// propagates the sanitized config to `for_verify`, while `for_save` keeps
/// its full config.
#[test]
fn test_sanitize_fills_for_apply_ip_with_full_config() {
    let mut base =
        BaseInterface::new("eth0".to_string(), InterfaceType::Ethernet);
    base.ipv4 = Some(InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(true),
        auto_gateway: Some(false),
        ..Default::default()
    });

    let mut for_save = base.clone();
    let mut for_verify = base.clone();
    let mut merged = base.clone();
    // for_apply holds only a partial IPv4 diff (e.g. dhcp toggled)
    let mut for_apply = base.clone();
    for_apply.ipv4 = Some(InterfaceIpv4 {
        dhcp: Some(false),
        ..Default::default()
    });

    base.sanitize(
        None,
        None,
        &mut for_save,
        &mut for_apply,
        &mut for_verify,
        &mut merged,
    )
    .unwrap();

    // for_apply must carry the full merged config from for_save, sanitized.
    let apply_ipv4 = for_apply.ipv4.as_ref().expect("ipv4 should be present");
    assert_eq!(apply_ipv4.enabled, Some(true));
    assert_eq!(apply_ipv4.dhcp, Some(true));
    assert_eq!(apply_ipv4.auto_gateway, Some(false));

    // for_verify receives the same sanitized full config.
    let verify_ipv4 = for_verify.ipv4.as_ref().expect("ipv4 should be present");
    assert_eq!(verify_ipv4.enabled, Some(true));
    assert_eq!(verify_ipv4.dhcp, Some(true));
    assert_eq!(verify_ipv4.auto_gateway, Some(false));

    // for_save keeps its full config.
    let save_ipv4 = for_save.ipv4.as_ref().expect("ipv4 should be present");
    assert_eq!(save_ipv4.enabled, Some(true));
    assert_eq!(save_ipv4.dhcp, Some(true));
    assert_eq!(save_ipv4.auto_gateway, Some(false));
}

/// Test that `for_apply` carries the full merged IPv4 config (desired +
/// saved), not just the diff against the current kernel state, so `for_save`
/// never loses the untouched properties.
///
/// Previously `for_apply` only held the *changed* IPv4 properties (e.g. a
/// new address without `enabled`/`dhcp`), and sanitize() copied that partial
/// diff onto `for_save`, purging the rest of the saved IP config.
#[test]
fn test_for_apply_ipv4_uses_full_merged_config_not_diff() {
    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();

    // Kernel state matches the saved config, so the diff would only contain
    // the newly added address, omitting `enabled` and `dhcp`.
    let current: Interfaces = saved.clone();

    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
            - ip: 192.0.2.2
              prefix-length: 24
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();

    // for_apply must hold the full merged IPv4 config, including the
    // untouched `enabled` and `dhcp` properties.
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(apply_ipv4.enabled, Some(true));
    assert_eq!(apply_ipv4.dhcp, Some(false));
    let apply_addrs = apply_ipv4.addresses.as_ref().unwrap();
    assert_eq!(apply_addrs.len(), 2);
    assert_eq!(apply_addrs[0].ip.to_string(), "192.0.2.1");
    assert_eq!(apply_addrs[1].ip.to_string(), "192.0.2.2");

    // for_save keeps the same full config.
    let for_save = merged_iface.for_save.as_ref().unwrap();
    let save_ipv4 = for_save.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(save_ipv4.enabled, Some(true));
    assert_eq!(save_ipv4.dhcp, Some(false));
    assert_eq!(save_ipv4.addresses.as_ref().unwrap().len(), 2);

    // gen_state_for_save() must persist the full IPv4 config.
    let save_state = merged.gen_state_for_save();
    let saved_iface = save_state.kernel_ifaces.get("eth0").unwrap();
    let saved_ipv4 = saved_iface.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(saved_ipv4.enabled, Some(true));
    assert_eq!(saved_ipv4.dhcp, Some(false));
    let saved_addrs = saved_ipv4.addresses.as_ref().unwrap();
    assert_eq!(saved_addrs.len(), 2);
    assert_eq!(saved_addrs[0].ip.to_string(), "192.0.2.1");
    assert_eq!(saved_addrs[1].ip.to_string(), "192.0.2.2");
}

/// When the previous state is static IPv4 and the desired state enables
/// DHCP, the stale static addresses must be discarded from both `for_apply`
/// and `for_save`.
#[test]
fn test_for_apply_ipv4_discards_static_addr_when_switch_to_dhcp() {
    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();

    let current: Interfaces = saved.clone();

    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            dhcp: true
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();

    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(apply_ipv4.enabled, Some(true));
    assert_eq!(apply_ipv4.dhcp, Some(true));
    assert!(
        apply_ipv4.addresses.is_none(),
        "static addresses must be discarded when switching to DHCP"
    );

    let for_save = merged_iface.for_save.as_ref().unwrap();
    let save_ipv4 = for_save.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(save_ipv4.dhcp, Some(true));
    assert!(
        save_ipv4.addresses.is_none(),
        "saved state must not keep stale static addresses"
    );
}

/// When the previous state is auto IPv4 (DHCP) and the desired state
/// disables DHCP, the dynamic addresses must be replaced with the desired
/// ones; when the desired state does not specify addresses, IPv4 gets no IP.
#[test]
fn test_for_apply_ipv4_discards_dynamic_addr_when_disable_auto() {
    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            address:
            - ip: 192.0.2.55
              prefix-length: 24
        "#,
    )
    .unwrap();

    // Desired disables DHCP without specifying addresses: no IP at all.
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            dhcp: false
        "#,
    )
    .unwrap();

    let merged =
        MergedInterfaces::new(desired, current.clone(), Some(saved)).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(apply_ipv4.enabled, Some(true));
    assert_eq!(apply_ipv4.dhcp, Some(false));
    assert!(
        apply_ipv4.addresses.is_none(),
        "dynamic addresses must be discarded when DHCP is disabled"
    );

    // Desired disables DHCP with static addresses specified: use them.
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            dhcp: false
            address:
            - ip: 10.0.0.1
              prefix-length: 24
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(apply_ipv4.dhcp, Some(false));
    let apply_addrs = apply_ipv4.addresses.as_ref().unwrap();
    assert_eq!(apply_addrs.len(), 1);
    assert_eq!(apply_addrs[0].ip.to_string(), "10.0.0.1");
    assert_eq!(apply_addrs[0].prefix_length, 24);
}

/// When the previous state is static IPv6 and the desired state enables
/// autoconf, the stale static addresses must be discarded.
#[test]
fn test_for_apply_ipv6_discards_static_addr_when_switch_to_autoconf() {
    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv6:
            enabled: true
            address:
            - ip: 2001:db8::1
              prefix-length: 64
        "#,
    )
    .unwrap();

    let current: Interfaces = saved.clone();

    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv6:
            autoconf: true
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();

    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv6 = for_apply.base_iface().ipv6.as_ref().unwrap();
    assert_eq!(apply_ipv6.enabled, Some(true));
    assert_eq!(apply_ipv6.autoconf, Some(true));
    assert!(
        apply_ipv6.addresses.is_none(),
        "static addresses must be discarded when switching to autoconf"
    );

    let for_save = merged_iface.for_save.as_ref().unwrap();
    let save_ipv6 = for_save.base_iface().ipv6.as_ref().unwrap();
    assert_eq!(save_ipv6.autoconf, Some(true));
    assert!(
        save_ipv6.addresses.is_none(),
        "saved state must not keep stale static addresses"
    );
}

/// When the previous state is auto IPv6 (DHCPv6) and the desired state
/// disables both DHCP and autoconf, the dynamic addresses must be replaced
/// with the desired ones; when the desired state does not specify addresses,
/// IPv6 keeps only the kernel-generated link-local address.
#[test]
fn test_for_apply_ipv6_discards_dynamic_addr_when_disable_auto() {
    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv6:
            enabled: true
            dhcp: true
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv6:
            enabled: true
            dhcp: true
            address:
            - ip: 2001:db8::55
              prefix-length: 64
        "#,
    )
    .unwrap();

    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv6:
            dhcp: false
            autoconf: false
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();

    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv6 = for_apply.base_iface().ipv6.as_ref().unwrap();
    assert_eq!(apply_ipv6.enabled, Some(true));
    assert_eq!(apply_ipv6.dhcp, Some(false));
    assert_eq!(apply_ipv6.autoconf, Some(false));
    assert!(
        apply_ipv6.addresses.is_none(),
        "dynamic addresses must be discarded, only link-local remains"
    );

    let for_save = merged_iface.for_save.as_ref().unwrap();
    let save_ipv6 = for_save.base_iface().ipv6.as_ref().unwrap();
    assert_eq!(save_ipv6.dhcp, Some(false));
    assert_eq!(save_ipv6.autoconf, Some(false));
    assert!(save_ipv6.addresses.is_none());
}

/// When there is no saved config, the current kernel state must not leak
/// `enabled`/`dhcp`/`autoconf` into `for_apply` — the kernel reports
/// `enabled: false` when no IP is assigned, which would otherwise strip the
/// desired addresses (via sanitize) or spuriously start DHCP.
#[test]
fn test_for_apply_ipv4_no_saved_does_not_inherit_kernel_state() {
    // Current IPv4 is disabled (kernel query format when no IP assigned).
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: false
        "#,
    )
    .unwrap();

    // First-time static IPv4 without explicit `enabled` must be applied.
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_ne!(apply_ipv4.enabled, Some(false));
    let apply_addrs = apply_ipv4.addresses.as_ref().unwrap();
    assert_eq!(apply_addrs.len(), 1);
    assert_eq!(apply_addrs[0].ip.to_string(), "192.0.2.1");
    assert_eq!(apply_addrs[0].prefix_length, 24);

    // First-time DHCP on a disabled interface must keep `dhcp: true`.
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: false
        "#,
    )
    .unwrap();
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            dhcp: true
        "#,
    )
    .unwrap();
    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(apply_ipv4.dhcp, Some(true));
    assert_ne!(apply_ipv4.enabled, Some(false));

    // Switching an interface currently on DHCP to static must not inherit
    // `dhcp: true` from the current state (which would restart DHCP on top
    // of the static config).
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            address:
            - ip: 192.0.2.55
              prefix-length: 24
        "#,
    )
    .unwrap();
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            address:
            - ip: 10.0.0.1
              prefix-length: 24
        "#,
    )
    .unwrap();
    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_ne!(apply_ipv4.dhcp, Some(true));
    let apply_addrs = apply_ipv4.addresses.as_ref().unwrap();
    assert_eq!(apply_addrs.len(), 1);
    assert_eq!(apply_addrs[0].ip.to_string(), "10.0.0.1");
    assert_eq!(apply_addrs[0].prefix_length, 24);
}

/// The DHCP worker applies a lease as the desired state (`dhcp: true` plus
/// the lease address) against a current state with IPv4 disabled. The
/// previous state holds no static addresses, so the static→auto transition
/// rule must NOT discard the lease address.
#[test]
fn test_for_apply_ipv4_keeps_lease_addr_when_prev_ipv4_disabled() {
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: false
        "#,
    )
    .unwrap();

    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            address:
            - ip: 192.0.2.225
              prefix-length: 24
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    let apply_ipv4 = for_apply.base_iface().ipv4.as_ref().unwrap();
    assert_eq!(apply_ipv4.dhcp, Some(true));
    let apply_addrs = apply_ipv4.addresses.as_ref().unwrap();
    assert_eq!(apply_addrs.len(), 1);
    assert_eq!(apply_addrs[0].ip.to_string(), "192.0.2.225");
    assert_eq!(apply_addrs[0].prefix_length, 24);
}

/// A MAC-identifier desired interface matching a current interface whose
/// saved config is a plain one (no `identifier`/`mac-address`, e.g. the
/// veth was created before being referenced by MAC) must keep its IPv4
/// config in `for_apply`/`for_save`. The saved config must be consumed
/// (merged into `for_save`) instead of being pushed as a saved-only
/// interface which would overwrite the merged interface.
#[test]
fn test_mac_identifier_desired_keeps_ipv4_with_plain_saved_config() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: my-veth
          type: ethernet
          identifier: mac-address
          mac-address: 86:FC:DF:CF:66:E1
          state: up
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.99
              prefix-length: 24
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: veth-mac0
          type: ethernet
          mac-address: 86:FC:DF:CF:66:E1
          state: up
          ipv4:
            enabled: false
        "#,
    )
    .unwrap();

    // The saved config of the veth does not carry the identifier or the
    // MAC address, so the MAC-based saved matching fails.
    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: veth-mac0
          type: ethernet
          state: up
          veth:
            peer: veth-mac1
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();
    let merged_iface = merged.kernel_ifaces.get("veth-mac0").unwrap();
    assert!(
        merged_iface
            .for_apply
            .as_ref()
            .unwrap()
            .base_iface()
            .ipv4
            .is_some(),
        "for_apply must keep ipv4"
    );
    let for_save = merged_iface.for_save.as_ref().unwrap().base_iface();
    let save_ipv4 = for_save.ipv4.as_ref().expect("for_save must keep ipv4");
    assert_eq!(save_ipv4.enabled, Some(true));
    assert_eq!(save_ipv4.dhcp, Some(false));
    assert_eq!(save_ipv4.addresses.as_ref().unwrap().len(), 1);

    // The saved veth config must be merged into for_save, not dropped.
    // MAC-identifier ifaces are saved keyed by `profile-name`.
    let save_state = merged.gen_state_for_save();
    let saved_iface = save_state.kernel_ifaces.get("my-veth").unwrap();
    assert!(
        matches!(
            saved_iface,
            Interface::Ethernet(eth) if eth.veth.as_ref().is_some()
        ),
        "saved veth config must be retained: {saved_iface:?}"
    );
}

/// Saved MAC-identifier ifaces must all be retained in for_save when
/// they are not part of the desired state.
#[test]
fn test_saved_mac_identifier_ifaces_kept_when_not_desired() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: vpn0
          type: wireguard
          state: up
          wireguard:
            private-key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            peers:
            - endpoint: 192.0.2.1:51820
              public-key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
              allowed-ips:
              - ip: 0.0.0.0
                prefix-length: 0
              protocol-version: 1
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          mac-address: 02:00:00:00:00:03
        - name: eth1
          type: ethernet
          mac-address: 02:00:00:00:00:06
        - name: eth2
          type: ethernet
          mac-address: 02:00:00:00:00:07
        "#,
    )
    .unwrap();

    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: nic1
          profile-name: nic1
          type: ethernet
          identifier: mac-address
          state: up
          mac-address: 02:00:00:00:00:03
        - name: nic2
          profile-name: nic2
          type: ethernet
          identifier: mac-address
          state: up
          mac-address: 02:00:00:00:00:06
        - name: nic3
          profile-name: nic3
          type: ethernet
          identifier: mac-address
          state: up
          mac-address: 02:00:00:00:00:07
        - name: TEST-WIFI
          type: wifi-cfg
          state: up
          ipv4:
            enabled: true
            dhcp: true
          wifi:
            ssid: TEST-WIFI
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();
    let for_save = merged.gen_state_for_save();

    let names: Vec<String> =
        for_save.iter().map(|i| i.name().to_string()).collect();
    for expected in ["vpn0", "nic1", "nic2", "nic3", "TEST-WIFI"] {
        assert!(
            names.contains(&expected.to_string()),
            "for_save {names:?} is missing {expected}"
        );
    }
}

/// A partial apply (e.g. a link event) must not remove the routes of
/// interfaces it does not touch, even when those interfaces are currently
/// IP-disabled (e.g. a DHCP interface whose lease has not been re-acquired
/// after daemon restart). Regression test for routes dropped on boot.
#[test]
fn test_partial_apply_keeps_routes_of_untouched_iface() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              address:
                - ip: 192.0.2.2
                  prefix-length: 24
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              address:
                - ip: 192.0.2.2
                  prefix-length: 24
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: false
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth1
              next-hop-address: 198.51.100.254
              table-id: 254
        "#,
    )
    .unwrap();

    let merged =
        MergedNetworkState::new(desired, current, None, Default::default())
            .unwrap();

    assert!(
        merged
            .routes
            .changed_routes
            .iter()
            .filter(|rt| rt.is_absent())
            .all(|rt| rt.next_hop_iface.as_deref() != Some("eth1")),
        "Partial apply must not mark routes of untouched interface eth1 \
         absent, got changed routes: {:?}",
        merged.routes.changed_routes
    );
}

/// When the apply itself disables IP on a desired interface, its current
/// routes must still be removed (intended behavior kept).
#[test]
fn test_apply_ip_disabled_iface_removes_its_routes() {
    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: false
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: true
              address:
                - ip: 198.51.100.2
                  prefix-length: 24
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth1
              next-hop-address: 198.51.100.254
              table-id: 254
        "#,
    )
    .unwrap();

    let merged =
        MergedNetworkState::new(desired, current, None, Default::default())
            .unwrap();

    assert!(
        merged
            .routes
            .changed_routes
            .iter()
            .filter(|rt| rt.is_absent())
            .any(|rt| rt.next_hop_iface.as_deref() == Some("eth1")),
        "Apply disabling IP on eth1 must remove eth1 routes, got changed \
         routes: {:?}",
        merged.routes.changed_routes
    );
}

/// The desired `routes.config` is additive: applying a desired state with
/// static routes must not drop the previously saved routes of interfaces not
/// mentioned in the desired state. `gen_state_for_save()` must persist both
/// the new routes and the surviving saved ones.
#[test]
fn test_gen_state_for_save_keeps_saved_routes_of_untouched_iface() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              address:
                - ip: 192.0.2.3
                  prefix-length: 24
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
            - destination: 203.0.113.0/24
              next-hop-interface: eth0
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              address:
                - ip: 192.0.2.3
                  prefix-length: 24
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: true
              address:
                - ip: 192.0.2.10
                  prefix-length: 24
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
            - destination: 203.0.113.0/24
              next-hop-interface: eth0
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth1
            type: ethernet
            state: up
            ipv4:
              enabled: true
              address:
                - ip: 192.0.2.10
                  prefix-length: 24
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-interface: eth1
              next-hop-address: 192.0.2.254
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    // The new default route plus the two saved routes of the untouched
    // interface `eth0` must all be persisted.
    let mut destinations: Vec<&str> = saved_routes
        .iter()
        .filter_map(|r| r.destination.as_deref())
        .collect();
    destinations.sort_unstable();
    assert_eq!(
        destinations,
        vec!["0.0.0.0/0", "198.51.100.0/24", "203.0.113.0/24"]
    );
}

/// A saved route explicitly matched by an `absent` route in the desired
/// state is dropped from the persisted state.
#[test]
fn test_gen_state_for_save_drops_explicitly_absent_route() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
            - destination: 203.0.113.0/24
              next-hop-interface: eth0
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
            - destination: 203.0.113.0/24
              next-hop-interface: eth0
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              state: absent
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert_eq!(saved_routes.len(), 1);
    assert_eq!(
        saved_routes[0].destination.as_deref(),
        Some("203.0.113.0/24")
    );
}

/// Saved routes whose next hop interface is marked `absent` in the desired
/// state are dropped from the persisted state.
#[test]
fn test_gen_state_for_save_drops_routes_of_absent_iface() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: absent
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert!(
        saved_routes.is_empty(),
        "Routes of the deleted interface eth0 must not be persisted, got \
         {saved_routes:?}"
    );
}

/// Saved routes of an interface whose IPv4 is disabled by the desired state
/// are dropped, while its IPv6 routes are kept.
#[test]
fn test_gen_state_for_save_drops_routes_of_ip_disabled_iface() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv6:
              enabled: true
              autoconf: false
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
            - destination: 2001:db8::/64
              next-hop-interface: eth0
              next-hop-address: 2001:db8::1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv6:
              enabled: true
              autoconf: false
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
            - destination: 2001:db8::/64
              next-hop-interface: eth0
              next-hop-address: 2001:db8::1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: false
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert_eq!(saved_routes.len(), 1);
    assert_eq!(
        saved_routes[0].destination.as_deref(),
        Some("2001:db8::/64")
    );
}

/// When the desired state does not mention routes at all, the saved routes
/// are preserved as-is.
#[test]
fn test_gen_state_for_save_preserves_saved_routes_without_route_section() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        routes: {}
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert_eq!(saved_routes.len(), 1);
    assert_eq!(
        saved_routes[0].destination.as_deref(),
        Some("198.51.100.0/24")
    );
}

/// The saved routes of an interface whose NIC is not present in the kernel
/// (e.g. unplugged) must be kept when the desired state merely mentions the
/// interface without an `ipv4` section: the merged state defaults to
/// IPv4-disabled for an absent interface, but the user did not ask to
/// disable its IP, and the interface's IPv4 config is still preserved in
/// the saved state.
#[test]
fn test_gen_state_for_save_keeps_routes_of_absent_nic_iface() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: br0
            type: linux-bridge
            state: up
            ipv4:
              enabled: true
              dhcp: false
              address:
                - ip: 192.0.2.10
                  prefix-length: 24
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: br0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    // The NIC has been removed: no interface in the current state.
    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: br0
            type: linux-bridge
            state: up
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert_eq!(saved_routes.len(), 1);
    assert_eq!(
        saved_routes[0].destination.as_deref(),
        Some("198.51.100.0/24")
    );
    // The interface IPv4 config is preserved alongside its routes.
    let saved_state = merged.gen_state_for_save();
    let saved_iface = saved_state.ifaces.kernel_ifaces.get("br0").unwrap();
    assert!(saved_iface.base_iface().is_ipv4_enabled());
}

/// The saved routes of an interface whose IP is already disabled in the
/// kernel (e.g. left over by a link-down event) must be kept when the
/// desired state mentions the interface without re-enabling the IP.
#[test]
fn test_gen_state_for_save_keeps_routes_of_ip_disabled_current_iface() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: true
              dhcp: false
              address:
                - ip: 192.0.2.10
                  prefix-length: 24
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            ipv4:
              enabled: false
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert_eq!(saved_routes.len(), 1);
    assert_eq!(
        saved_routes[0].destination.as_deref(),
        Some("198.51.100.0/24")
    );
}
#[test]
fn test_gen_state_for_save_preserves_saved_routes_with_empty_config() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        routes:
          config: []
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert_eq!(saved_routes.len(), 1);
    assert_eq!(
        saved_routes[0].destination.as_deref(),
        Some("198.51.100.0/24")
    );
}

/// Saved routes reference a MAC-identified interface by its logical (profile)
/// name, but the interface-change lists are keyed by kernel interface name.
/// Marking that interface `absent` in the desired state must still drop its
/// saved routes from the persisted state.
#[test]
fn test_gen_state_for_save_drops_routes_of_absent_mac_identified_iface() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: wan0
            type: ethernet
            state: up
            identifier: mac-address
            mac-address: 02:00:00:00:00:0A
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: wan0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            mac-address: 02:00:00:00:00:0A
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: wan0
            type: ethernet
            state: absent
            identifier: mac-address
            mac-address: 02:00:00:00:00:0A
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert!(
        saved_routes.is_empty(),
        "Routes of the deleted MAC-identified interface wan0 must not be \
         persisted, got {saved_routes:?}"
    );
}

/// An `absent` route in the desired state referencing a MAC-identified
/// interface by its profile name must also drop the saved route persisted
/// with the same profile name (the absent desired route is resolved to the
/// kernel interface name before matching).
#[test]
fn test_gen_state_for_save_drops_explicitly_absent_profile_named_route() {
    let saved: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: wan0
            type: ethernet
            state: up
            identifier: mac-address
            mac-address: 02:00:00:00:00:0B
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: wan0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let current: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: eth0
            type: ethernet
            state: up
            mac-address: 02:00:00:00:00:0B
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: eth0
              next-hop-address: 192.0.2.1
              metric: 100
              table-id: 254
        "#,
    )
    .unwrap();

    let desired: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
          - name: wan0
            type: ethernet
            state: up
            identifier: mac-address
            mac-address: 02:00:00:00:00:0B
        routes:
          config:
            - destination: 198.51.100.0/24
              next-hop-interface: wan0
              state: absent
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        current,
        Some(saved),
        Default::default(),
    )
    .unwrap();

    let saved_routes = merged.gen_state_for_save().routes.config.unwrap();
    assert!(
        saved_routes.is_empty(),
        "The explicitly absent route must not be persisted, got \
         {saved_routes:?}"
    );
}

/// The MAC address of a `identifier: mac-address` config is only an
/// identifier used to locate the interface. When the matched interface is
/// already a bond port (its MAC is controlled by the bond kernel driver,
/// e.g. active-backup mode assigns the bond's MAC to every slave), the MAC
/// must not be applied nor verified — otherwise apply of an already-settled
/// state fails verification forever.
#[test]
fn test_mac_identifier_bond_port_mac_not_applied_or_verified() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: port1
            - name: port2
        - name: port1
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:0a
        - name: port2
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:09
        "#,
    )
    .unwrap();

    // The current MAC of the bond port differs from its permanent MAC (the
    // identifier) because the bond reassigned the port's MAC on enslave.
    // `controller-type` is not reported by the kernel query, only resolved
    // during merge.
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: enp1s0
            - name: enp2s0
        - name: enp1s0
          type: ethernet
          mac-address: 02:00:00:00:00:09
          permanent-mac-address: 02:00:00:00:00:0a
          state: up
          controller: bond1
        - name: enp2s0
          type: ethernet
          mac-address: 02:00:00:00:00:09
          permanent-mac-address: 02:00:00:00:00:09
          state: up
          controller: bond1
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    for (name, merged_iface) in &merged.kernel_ifaces {
        if merged_iface.merged.base_iface().identifier
            != Some(InterfaceIdentifier::MacAddress)
        {
            continue;
        }
        assert!(
            merged_iface
                .for_verify
                .as_ref()
                .and_then(|i| i.base_iface().mac_address.as_ref())
                .is_none(),
            "{name}: for_verify must not carry mac-address for a bond port"
        );
        assert!(
            merged_iface
                .for_apply
                .as_ref()
                .and_then(|i| i.base_iface().mac_address.as_ref())
                .is_none(),
            "{name}: for_apply must not carry mac-address for a bond port"
        );
    }

    // And verification must pass against the post-apply current state where
    // the bond port MAC differs from the identifier MAC.
    let post_apply_current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: enp1s0
            - name: enp2s0
        - name: enp1s0
          type: ethernet
          mac-address: 02:00:00:00:00:09
          permanent-mac-address: 02:00:00:00:00:0a
          state: up
          controller: bond1
        - name: enp2s0
          type: ethernet
          mac-address: 02:00:00:00:00:09
          permanent-mac-address: 02:00:00:00:00:09
          state: up
          controller: bond1
        "#,
    )
    .unwrap();
    merged
        .verify(&post_apply_current)
        .expect("verification must pass for settled bond port state");
}

/// The same as `test_mac_identifier_bond_port_mac_not_applied_or_verified`,
/// but for the transition case where the bond does not exist yet and the
/// MAC-identified interfaces are attached as bond ports in this apply.
#[test]
fn test_mac_identifier_bond_port_mac_not_applied_or_verified_transition() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: port1
            - name: port2
        - name: port1
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:0a
        - name: port2
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:09
        "#,
    )
    .unwrap();

    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: enp1s0
          type: ethernet
          mac-address: 02:00:00:00:00:0a
          permanent-mac-address: 02:00:00:00:00:0a
          state: up
        - name: enp2s0
          type: ethernet
          mac-address: 02:00:00:00:00:09
          permanent-mac-address: 02:00:00:00:00:09
          state: up
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();
    for (name, merged_iface) in &merged.kernel_ifaces {
        if merged_iface.merged.base_iface().identifier
            != Some(InterfaceIdentifier::MacAddress)
        {
            continue;
        }
        assert!(
            merged_iface
                .for_apply
                .as_ref()
                .and_then(|i| i.base_iface().mac_address.as_ref())
                .is_none(),
            "{name}: for_apply must not carry mac-address for a bond port"
        );
    }
}

/// When the `identifier: mac-address` ports of a bond resolve to a
/// different kernel port order than the current bond (e.g. the user
/// swapped the MAC addresses of port1/port2 while the port set is
/// unchanged), verification must not fail on the port order: the bond
/// ports are sorted before comparison.
#[test]
fn test_mac_identifier_bond_port_order_swapped_passes_verify() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: port1
            - name: port2
        - name: port1
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:09
        - name: port2
          type: ethernet
          identifier: mac-address
          mac-address: 02:00:00:00:00:0a
        "#,
    )
    .unwrap();

    // port1 now matches enp2s0 and port2 matches enp1s0, so the desired
    // bond port order resolves to [enp2s0, enp1s0] while the current
    // bond holds [enp1s0, enp2s0].
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: enp1s0
            - name: enp2s0
        - name: enp1s0
          type: ethernet
          mac-address: 02:00:00:00:00:09
          permanent-mac-address: 02:00:00:00:00:0a
          state: up
          controller: bond1
        - name: enp2s0
          type: ethernet
          mac-address: 02:00:00:00:00:09
          permanent-mac-address: 02:00:00:00:00:09
          state: up
          controller: bond1
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current.clone(), None).unwrap();
    // The post-apply current state still holds the ports in the original
    // kernel order: verification must pass.
    merged
        .verify(&current)
        .expect("verification must pass when bond port order differs");
}

/// Sorting the bond ports before verification must not mask a real port
/// set change: when the apply failed to change the port set, verification
/// must still fail.
#[test]
fn test_bond_port_set_change_still_fails_verify() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: enp1s0
            - name: enp2s0
        "#,
    )
    .unwrap();

    // Current bond holds enp1s0 + enp3s0 while enp2s0 exists standalone:
    // the desired port set differs from the current one.
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond1
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: enp3s0
            - name: enp1s0
        - name: enp1s0
          type: ethernet
          state: up
          controller: bond1
        - name: enp2s0
          type: ethernet
          state: up
        - name: enp3s0
          type: ethernet
          state: up
          controller: bond1
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current.clone(), None).unwrap();
    // The post-apply state still holds the old port set (the apply did not
    // manage to change it): sorting must not hide the difference.
    let result = merged.verify(&current);
    assert!(
        result.is_err(),
        "verification must fail when the bond port set differs: {result:?}"
    );
}

#[test]
fn test_bond_port_with_ip_rejected() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond0
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: dummy1
        - name: dummy1
          type: dummy
          state: up
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();

    let result = MergedInterfaces::new(desired, Interfaces::default(), None);
    assert!(result.is_err());
    if let Err(e) = result {
        assert_eq!(e.kind(), crate::ErrorKind::InvalidArgument);
        assert!(
            e.msg().contains("cannot have IP enabled"),
            "Unexpected error: {}",
            e.msg()
        );
        assert!(
            e.msg().contains("controller bond0"),
            "Unexpected error: {}",
            e.msg()
        );
    }
}

#[test]
fn test_bridge_port_with_ip_rejected() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: br0
          type: linux-bridge
          state: up
          bridge:
            port:
            - name: dummy1
        - name: dummy1
          type: dummy
          state: up
          ipv6:
            enabled: true
        "#,
    )
    .unwrap();

    let result = MergedInterfaces::new(desired, Interfaces::default(), None);
    assert!(result.is_err());
    if let Err(e) = result {
        assert_eq!(e.kind(), crate::ErrorKind::InvalidArgument);
        assert!(
            e.msg().contains("cannot have IP enabled"),
            "Unexpected error: {}",
            e.msg()
        );
    }
}

#[test]
fn test_vrf_port_with_ip_allowed() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: vrf0
          type: vrf
          state: up
          vrf:
            route-table-id: 100
            ports:
            - dummy1
        - name: dummy1
          type: dummy
          state: up
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();

    let merged =
        MergedInterfaces::new(desired, Interfaces::default(), None).unwrap();
    let dummy1 = merged.kernel_ifaces.get("dummy1").unwrap();
    // VRF port keeps its IP in the merged state.
    assert!(dummy1.merged.base_iface().can_have_ip());
    assert_eq!(
        dummy1
            .merged
            .base_iface()
            .ipv4
            .as_ref()
            .and_then(|ipv4| ipv4.enabled),
        Some(true),
    );
}

#[test]
fn test_vrf_with_ip_allowed() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: vrf0
          type: vrf
          state: up
          vrf:
            route-table-id: 100
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();

    let merged =
        MergedInterfaces::new(desired, Interfaces::default(), None).unwrap();
    let vrf0 = merged.kernel_ifaces.get("vrf0").unwrap();
    assert!(vrf0.merged.base_iface().can_have_ip());
}

#[test]
fn test_bond_port_with_explicit_controller_and_ip_rejected() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond0
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: dummy1
        - name: dummy1
          type: dummy
          state: up
          controller: bond0
          ipv4:
            enabled: true
        "#,
    )
    .unwrap();

    let result = MergedInterfaces::new(desired, Interfaces::default(), None);
    assert!(result.is_err());
    if let Err(e) = result {
        assert_eq!(e.kind(), crate::ErrorKind::InvalidArgument);
        assert!(
            e.msg().contains("cannot have IP enabled"),
            "Unexpected error: {}",
            e.msg()
        );
    }
}

#[test]
fn test_bond_port_ip_purged_from_save_when_attached() {
    // Saved config has IP on dummy1, desired state moves dummy1 to bond0:
    // the apply must not fail and the IP must be purged from the saved
    // config (and disabled in for_apply so the running address is removed).
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: bond0
          type: bond
          state: up
          bond:
            mode: active-backup
            ports:
            - name: dummy1
        "#,
    )
    .unwrap();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: dummy1
          type: dummy
          state: up
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();
    let saved = current.clone();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();

    let dummy1 = merged.kernel_ifaces.get("dummy1").unwrap();
    // Saved config must be purged.
    assert_eq!(dummy1.for_save.as_ref().unwrap().base_iface().ipv4, None,);
    assert_eq!(dummy1.for_save.as_ref().unwrap().base_iface().ipv6, None,);
    // for_apply must disable IPv4 so the running address is removed.
    assert_eq!(
        dummy1
            .for_apply
            .as_ref()
            .unwrap()
            .base_iface()
            .ipv4
            .as_ref()
            .and_then(|ipv4| ipv4.enabled),
        Some(false),
    );
    // merged must not hold IP.
    assert_eq!(dummy1.merged.base_iface().ipv4, None);
}

#[test]
fn test_vrf_port_ip_kept_in_save_when_attached() {
    // VRF ports can hold IP: attaching dummy1 to a VRF must NOT purge the
    // IP from the saved config.
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: vrf0
          type: vrf
          state: up
          vrf:
            route-table-id: 100
            ports:
            - dummy1
        "#,
    )
    .unwrap();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: dummy1
          type: dummy
          state: up
          ipv4:
            enabled: true
            dhcp: false
            address:
            - ip: 192.0.2.1
              prefix-length: 24
        "#,
    )
    .unwrap();
    let saved = current.clone();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();

    let dummy1 = merged.kernel_ifaces.get("dummy1").unwrap();
    assert!(dummy1.merged.base_iface().can_have_ip());
    assert_eq!(
        dummy1
            .for_save
            .as_ref()
            .unwrap()
            .base_iface()
            .ipv4
            .as_ref()
            .and_then(|ipv4| ipv4.enabled),
        Some(true),
    );
}

#[test]
fn test_description_not_applied_or_verified() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          description: "Main interface connected to switch S1"
        "#,
    )
    .unwrap();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    // A description-only change must not trigger a kernel apply.
    assert!(merged_iface.for_apply.is_none());
    assert_eq!(merged_iface.for_revert, None);
    // The description is kept for persistence.
    assert_eq!(
        merged_iface
            .for_save
            .as_ref()
            .unwrap()
            .base_iface()
            .description
            .as_deref(),
        Some("Main interface connected to switch S1")
    );
    // The description is not verified.
    assert_eq!(
        merged_iface
            .for_verify
            .as_ref()
            .unwrap()
            .base_iface()
            .description,
        None
    );
}

#[test]
fn test_description_kept_in_save_with_real_change() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          description: "Main interface connected to switch S1"
          mtu: 9000
        "#,
    )
    .unwrap();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, None).unwrap();

    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    let for_apply = merged_iface.for_apply.as_ref().unwrap();
    assert_eq!(for_apply.base_iface().mtu, Some(9000));
    assert_eq!(for_apply.base_iface().description, None);
    assert_eq!(
        merged_iface
            .for_save
            .as_ref()
            .unwrap()
            .base_iface()
            .description
            .as_deref(),
        Some("Main interface connected to switch S1")
    );
}

#[test]
fn test_description_survives_merge_with_saved_state() {
    let desired: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          mtu: 9000
        "#,
    )
    .unwrap();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
        "#,
    )
    .unwrap();
    let saved: Interfaces = rmsd_yaml::from_str(
        r#"---
        - name: eth0
          type: ethernet
          state: up
          description: "Main interface connected to switch S1"
        "#,
    )
    .unwrap();

    let merged = MergedInterfaces::new(desired, current, Some(saved)).unwrap();

    let merged_iface = merged.kernel_ifaces.get("eth0").unwrap();
    assert_eq!(
        merged_iface
            .for_save
            .as_ref()
            .unwrap()
            .base_iface()
            .description
            .as_deref(),
        Some("Main interface connected to switch S1")
    );
}
