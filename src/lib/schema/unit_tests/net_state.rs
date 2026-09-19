// SPDX-License-Identifier: Apache-2.0

use crate::{
    ErrorKind, Interface, MergedNetworkState, NetworkState, NipartApplyOption,
    NipartWaitOnlineCondition,
};

#[test]
fn test_new_from_yaml_valid_full_state() {
    let state = NetworkState::new_from_yaml(
        r#"---
        version: 1
        description: full state
        wait-online:
          timeout-sec: 60
          conditions:
            - gateway4
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-address: 192.0.2.1
              next-hop-interface: eth1
        interfaces:
          - name: eth1
            type: ethernet
            state: up
        "#,
    )
    .unwrap();

    assert_eq!(state.version, Some(1));
    assert_eq!(state.description, Some("full state".to_string()));

    let wait_online = state.wait_online.as_ref().unwrap();
    assert_eq!(wait_online.timeout_sec, 60);
    assert_eq!(
        wait_online.conditions,
        vec![NipartWaitOnlineCondition::Gateway4]
    );

    let routes = state.routes.config.as_ref().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination.as_deref(), Some("0.0.0.0/0"));

    assert!(!state.ifaces.is_empty());
    assert!(state.ifaces.kernel_ifaces.contains_key("eth1"));
}

#[test]
fn test_new_from_yaml_invalid_syntax() {
    let result = NetworkState::new_from_yaml("interfaces: [unclosed");
    assert!(result.is_err());

    let e = result.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    assert!(e.msg.contains("Invalid YAML string"));
}

#[test]
fn test_new_from_yaml_unknown_field() {
    let result = NetworkState::new_from_yaml(
        r#"---
        bogus-field: true
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn test_new_from_yaml_empty_string() {
    let state = NetworkState::new_from_yaml("").unwrap();
    assert!(state.is_empty());
    assert!(state.ifaces.is_empty());
    assert!(state.routes.is_empty());
    assert!(state.wait_online.is_none());
}

#[test]
fn test_description_and_wait_online_saved_when_desired_omits_them() {
    let saved = NetworkState::new_from_yaml(
        r#"---
        version: 1
        description: saved description
        wait-online:
          timeout-sec: 60
          conditions:
            - gateway4
        "#,
    )
    .unwrap();
    let desired = NetworkState::new_from_yaml(
        r#"---
        version: 1
        interfaces:
          - name: test-saved0
            type: dummy
            state: saved
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        NetworkState::default(),
        Some(saved),
        NipartApplyOption::default(),
    )
    .unwrap();
    let state_to_save = merged.gen_state_for_save();

    assert_eq!(
        state_to_save.description.as_deref(),
        Some("saved description")
    );
    let wait_online = state_to_save.wait_online.as_ref().unwrap();
    assert_eq!(wait_online.timeout_sec, 60);
    assert_eq!(
        wait_online.conditions,
        vec![NipartWaitOnlineCondition::Gateway4]
    );
}

#[test]
fn test_description_and_wait_online_override_saved_state() {
    let saved = NetworkState::new_from_yaml(
        r#"---
        version: 1
        description: saved description
        wait-online:
          timeout-sec: 60
          conditions:
            - gateway4
        "#,
    )
    .unwrap();
    let desired = NetworkState::new_from_yaml(
        r#"---
        version: 1
        description: desired description
        wait-online:
          timeout-sec: 5
          conditions: []
        interfaces:
          - name: test-saved0
            type: dummy
            state: saved
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        NetworkState::default(),
        Some(saved),
        NipartApplyOption::default(),
    )
    .unwrap();
    let state_to_save = merged.gen_state_for_save();

    assert_eq!(
        state_to_save.description.as_deref(),
        Some("desired description")
    );
    let wait_online = state_to_save.wait_online.as_ref().unwrap();
    assert_eq!(wait_online.timeout_sec, 5);
    assert!(wait_online.conditions.is_empty());
}

fn wifi_password(state: &NetworkState) -> Option<&str> {
    state
        .ifaces
        .kernel_ifaces
        .get("wlan0")
        .and_then(|iface| match iface {
            Interface::WifiPhy(wifi) => wifi.wifi.as_ref(),
            _ => None,
        })
        .and_then(|wifi| wifi.password.as_deref())
}

#[test]
fn test_extract_secrets_only_contains_iface_secrets() {
    let mut state = NetworkState::new_from_yaml(
        r#"---
        version: 1
        description: test
        wait-online:
          timeout-sec: 60
        routes:
          config:
            - destination: 0.0.0.0/0
              next-hop-address: 192.0.2.1
              next-hop-interface: eth1
        dns-resolver:
          config:
            server:
              - 127.0.0.1
          cache:
            enabled: true
        interfaces:
          - name: wlan0
            type: wifi-phy
            wifi:
              ssid: Test-WIFI
              password: '12345678'
        "#,
    )
    .unwrap();

    let secrets = state.extract_secrets().unwrap();

    // Non-secret sections must not leak into the root-owned secrets file:
    // merging it later would override a manual edit of `applied.yml`.
    assert!(secrets.description.is_none());
    assert!(secrets.wait_online.is_none());
    assert!(secrets.routes.is_empty());
    assert!(secrets.route_rules.is_empty());
    assert!(secrets.dns_resolver.is_empty());

    assert_eq!(wifi_password(&secrets), Some("12345678"));
    assert_eq!(wifi_password(&state), Some(NetworkState::HIDE_SECRET_STR));
}
