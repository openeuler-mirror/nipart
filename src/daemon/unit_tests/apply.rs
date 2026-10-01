// SPDX-License-Identifier: Apache-2.0

use nipart::{
    Interface, InterfaceAutoConnect, InterfaceType, MergedNetworkState,
    NetworkState, NipartInterface,
};

use super::{pretend_config_is_saved, saved_wifi_restore_state};

const IFACE_YAML: &str = r#"---
    name: eth0
    type: ethernet
    state: up
    ipv4:
      enabled: true
      dhcp: false
      address:
        - ip: 192.0.2.1
          prefix-length: 24
    "#;

const WIFI_CFG_IFACE_YAML: &str = r#"---
    name: test-ssid
    type: wifi-cfg
    state: up
    wifi:
      ssid: test-ssid
    "#;

fn has_wifi_cfg(state: &NetworkState) -> bool {
    state
        .ifaces
        .user_ifaces
        .contains_key(&("test-ssid".to_string(), InterfaceType::WifiCfg))
}

fn gen_merged_wifi_cfg_state(desired_iface_yaml: &str) -> MergedNetworkState {
    let mut desired_state = NetworkState::default();
    desired_state
        .ifaces
        .push(rmsd_yaml::from_str(desired_iface_yaml).unwrap());
    MergedNetworkState::new(
        desired_state,
        NetworkState::default(),
        None,
        Default::default(),
    )
    .unwrap()
}

fn gen_iface(auto_connect: Option<InterfaceAutoConnect>) -> Interface {
    let mut iface: Interface = rmsd_yaml::from_str(IFACE_YAML).unwrap();
    iface.base_iface_mut().auto_connect = auto_connect;
    iface
}

fn gen_state(auto_connect: Option<InterfaceAutoConnect>) -> NetworkState {
    let mut state = NetworkState::default();
    state.ifaces.push(gen_iface(auto_connect));
    state
}

/// Kernel state queried after apply: the kernel never reports the
/// daemon-only `auto-connect` property.
fn post_apply_state() -> NetworkState {
    gen_state(None)
}

fn get_auto_connect(state: &NetworkState) -> Option<InterfaceAutoConnect> {
    state
        .ifaces
        .kernel_ifaces
        .get("eth0")
        .and_then(|iface| iface.base_iface().auto_connect.clone())
}

/// A failed partial `npt wifi connect` rollback must hand the saved WIFI
/// profiles back to the plugin, otherwise shuli is left with no network
/// and the previous connection does not come back until a manual
/// `npt up`.
#[test]
fn test_saved_wifi_restore_state_keeps_up_wifi_profiles_only() {
    let saved_state: NetworkState = rmsd_yaml::from_str(
        r#"---
        interfaces:
        - name: wlan0
          kernel-iface-name: wlan0
          type: wifi-phy
          state: up
        - name: Test-WIFI
          type: wifi-cfg
          state: up
          wifi:
            ssid: Test-WIFI
        - name: Manual-WIFI
          type: wifi-cfg
          state: up
          auto-connect: false
          wifi:
            ssid: Manual-WIFI
        - name: Removed-WIFI
          type: wifi-cfg
          state: absent
          wifi:
            ssid: Removed-WIFI
        - name: eth0
          type: ethernet
          state: up
        "#,
    )
    .unwrap();

    let restore = saved_wifi_restore_state(&saved_state);
    let names: Vec<&str> =
        restore.ifaces.iter().map(|iface| iface.name()).collect();
    assert_eq!(
        names,
        ["wlan0", "Test-WIFI"],
        "only the phy and auto-connectable wifi-cfg profiles may come back"
    );
}

/// Re-applying an unchanged `auto-connect: false` config: the apply diff
/// carries no `auto-connect` change, but the verification must still see the
/// saved value instead of a `None` erasing it.
#[test]
fn test_pretend_config_is_saved_on_unchanged_reapply() {
    let saved_iface = gen_iface(Some(InterfaceAutoConnect::Manual));
    let mut saved_state = NetworkState::default();
    saved_state.ifaces.push(saved_iface.clone());
    // The daemon query of the running state inherits `auto-connect` from the
    // saved config, e.g. the second `npt apply` of the same file.
    let mut current_state = NetworkState::default();
    current_state.ifaces.push(saved_iface.clone());
    let mut desired_state = NetworkState::default();
    desired_state.ifaces.push(saved_iface);

    let merged = MergedNetworkState::new(
        desired_state,
        current_state,
        Some(saved_state),
        Default::default(),
    )
    .unwrap();

    // An unchanged `auto-connect` is absent from the apply diff, which is the
    // reason why the diff cannot be used to pretend the saved value.
    let merged_iface = merged.ifaces.kernel_ifaces.get("eth0").unwrap();
    assert_eq!(
        merged_iface
            .for_apply
            .as_ref()
            .and_then(|iface| iface.base_iface().auto_connect.clone()),
        None
    );

    let mut post_apply = post_apply_state();
    pretend_config_is_saved(&mut post_apply, &merged);

    assert_eq!(
        get_auto_connect(&post_apply),
        Some(InterfaceAutoConnect::Manual)
    );
    merged.verify(&post_apply).unwrap();
}

/// Changing `auto-connect` is not a kernel change, so the daemon has to
/// pretend the value which is going to be saved.
#[test]
fn test_pretend_config_is_saved_uses_state_to_be_saved() {
    let mut saved_state = NetworkState::default();
    saved_state
        .ifaces
        .push(gen_iface(Some(InterfaceAutoConnect::Manual)));
    let mut current_state = NetworkState::default();
    current_state
        .ifaces
        .push(gen_iface(Some(InterfaceAutoConnect::Manual)));
    let mut desired_state = NetworkState::default();
    desired_state
        .ifaces
        .push(gen_iface(Some(InterfaceAutoConnect::AutoConnect)));

    let merged = MergedNetworkState::new(
        desired_state,
        current_state,
        Some(saved_state),
        Default::default(),
    )
    .unwrap();

    let mut post_apply = post_apply_state();
    pretend_config_is_saved(&mut post_apply, &merged);

    assert_eq!(
        get_auto_connect(&post_apply),
        Some(InterfaceAutoConnect::AutoConnect)
    );
    merged.verify(&post_apply).unwrap();
}

/// A wifi-cfg profile is stored by the daemon only, the queried post-apply
/// state has to carry it for the verification.
#[test]
fn test_pretend_config_is_saved_injects_up_wifi_cfg() {
    let merged = gen_merged_wifi_cfg_state(WIFI_CFG_IFACE_YAML);

    let mut post_apply = NetworkState::default();
    pretend_config_is_saved(&mut post_apply, &merged);

    assert!(has_wifi_cfg(&post_apply));
    merged.verify(&post_apply).unwrap();
}

/// A removed wifi-cfg profile is only dropped from the saved config after the
/// verification, so the post-apply state must not carry it anymore.
#[test]
fn test_pretend_config_is_saved_removes_down_wifi_cfg() {
    let merged = gen_merged_wifi_cfg_state(
        r#"---
        name: test-ssid
        type: wifi-cfg
        state: down
        wifi:
          ssid: test-ssid
        "#,
    );

    let mut post_apply = NetworkState::default();
    post_apply
        .ifaces
        .push(rmsd_yaml::from_str(WIFI_CFG_IFACE_YAML).unwrap());
    assert!(has_wifi_cfg(&post_apply));

    pretend_config_is_saved(&mut post_apply, &merged);

    assert!(!has_wifi_cfg(&post_apply));
    merged.verify(&post_apply).unwrap();
}
