// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use nipart::{
    Interface, InterfaceAutoConnect, InterfaceIpv4, InterfaceLinkEvent,
    InterfaceState, InterfaceType, MergedNetworkState, NetworkState,
    NipartInterface,
};

use super::{
    gen_desired_iface_down, gen_routes_for_iface_up,
    gen_routes_for_wifi_cfg_up, gen_wifi_plugin_state_for_phy,
    handle_event_auto_connect, handle_wifi_phy_event, is_route_matching_iface,
    is_stale_link_down_event, nic_is_gone, wifi_cfg_to_wifi_phy, wifi_phy_ssid,
};

fn gen_wifi_cfg_iface() -> Interface {
    rmsd_yaml::from_str(
        r#"---
            name: Test-WIFI
            type: wifi-cfg
            state: up
            ipv4:
              enabled: true
              dhcp: true
            wifi:
              ssid: Test-WIFI
              base-iface: wlan0
            "#,
    )
    .unwrap()
}

fn gen_wifi_phy_event(is_up: bool, ssid: Option<&str>) -> InterfaceLinkEvent {
    InterfaceLinkEvent {
        iface_name: "wlan0".to_string(),
        iface_index: 18,
        iface_type: InterfaceType::WifiPhy,
        is_up,
        is_delete: false,
        time_stamp: SystemTime::now(),
        ssid: ssid.map(|s| s.to_string()),
        is_new_wifi_phy: false,
    }
}

fn gen_saved_state() -> NetworkState {
    rmsd_yaml::from_str(
        r#"---
version: 1
routes:
  config:
  - destination: 0.0.0.0/0
    next-hop-interface: wan0
    next-hop-address: 192.0.2.254
    metric: 100
    table-id: 254
  - destination: 198.51.100.0/24
    next-hop-interface: eth2
    next-hop-address: 198.51.100.254
    metric: 103
    table-id: 254
  - destination: 203.0.113.0/24
    next-hop-interface: wifi0
    next-hop-address: 203.0.113.254
    metric: 102
    table-id: 254
  - destination: 203.0.113.128/25
    next-hop-interface: wifi0
    next-hop-address: 203.0.113.254
    metric: 104
    table-id: 254
  - destination: 192.0.2.0/24
    next-hop-interface: vpn0
    next-hop-address: 192.0.2.1
    metric: 100
    table-id: 254
interfaces:
- name: wan0
  type: ethernet
  kernel-iface-name: eth0
  state: up
  profile-name: wan0
  identifier: mac-address
  mac-address: 02:00:00:00:00:01
- name: lan0
  type: ethernet
  kernel-iface-name: eth2
  state: up
  profile-name: lan0
  identifier: mac-address
  mac-address: 02:00:00:00:00:02
- name: wifi0
  type: ethernet
  kernel-iface-name: wlan0
  state: up
  profile-name: wifi0
  identifier: mac-address
  mac-address: 02:00:00:00:00:03
"#,
    )
    .unwrap()
}

fn gen_wifi_cfg_state_with_route() -> NetworkState {
    rmsd_yaml::from_str(
        r#"---
            version: 1
            routes:
              config:
              - destination: 203.0.113.0/24
                next-hop-interface: Test-WIFI
                next-hop-address: 203.0.113.254
                metric: 102
                table-id: 254
            interfaces:
              - name: Test-WIFI
                type: wifi-cfg
                state: up
                ipv4:
                  enabled: true
                  dhcp: true
                wifi:
                  ssid: Test-WIFI
                  base-iface: wlan0
            "#,
    )
    .unwrap()
}

fn find_iface<'a>(state: &'a NetworkState, name: &str) -> &'a Interface {
    state.ifaces.iter().find(|i| i.name() == name).unwrap()
}

#[test]
fn test_route_matching_by_profile_name() {
    let state = gen_saved_state();
    let wan0 = find_iface(&state, "wan0");
    let routes = gen_routes_for_iface_up(wan0, &state);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination.as_deref(), Some("0.0.0.0/0"));
}

#[test]
fn test_route_matching_by_kernel_iface_name() {
    let state = gen_saved_state();
    let red = find_iface(&state, "lan0");
    let routes = gen_routes_for_iface_up(red, &state);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination.as_deref(), Some("198.51.100.0/24"));
}

#[test]
fn test_route_matching_by_iface_name() {
    let state = gen_saved_state();
    let wifi0 = find_iface(&state, "wifi0");
    let routes = gen_routes_for_iface_up(wifi0, &state);
    let mut dests: Vec<_> = routes
        .iter()
        .filter_map(|rt| rt.destination.as_deref())
        .collect();
    dests.sort_unstable();
    assert_eq!(dests, vec!["203.0.113.0/24", "203.0.113.128/25"]);
}

#[test]
fn test_route_not_matching_iface_excluded() {
    let state = gen_saved_state();
    for name in ["wan0", "lan0", "wifi0"] {
        let iface = find_iface(&state, name);
        assert!(
            !gen_routes_for_iface_up(iface, &state)
                .iter()
                .any(|rt| rt.destination.as_deref() == Some("192.0.2.0/24")),
            "{name} should not pick up the vpn0 route"
        );
    }
}

#[test]
fn test_wifi_cfg_routes_included_on_wifi_phy_up() {
    let state = gen_wifi_cfg_state_with_route();
    let wifi_cfg = find_iface(&state, "Test-WIFI");
    let routes = gen_routes_for_wifi_cfg_up(wifi_cfg, &state);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination.as_deref(), Some("203.0.113.0/24"));
    assert_eq!(routes[0].next_hop_iface.as_deref(), Some("Test-WIFI"));
}

#[test]
fn test_is_route_matching_iface() {
    let state = gen_saved_state();
    let wan0 = find_iface(&state, "wan0");
    let vpn0_rt = state
        .routes
        .config
        .as_ref()
        .unwrap()
        .iter()
        .find(|rt| rt.destination.as_deref() == Some("192.0.2.0/24"))
        .unwrap();
    assert!(!is_route_matching_iface(vpn0_rt, wan0));
}

#[test]
fn test_gen_wifi_plugin_state_matches_phy_only() {
    let state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: eth0
                type: ethernet
                state: up
              - name: wlan0
                type: wifi-phy
                state: up
              - name: Test-WIFI
                type: wifi-cfg
                state: up
                wifi:
                  ssid: Test-WIFI
                  base-iface: wlan0
              - name: Other-WIFI
                type: wifi-cfg
                state: up
                wifi:
                  ssid: Other-WIFI
                  base-iface: wlan1
              - name: Any-WIFI
                type: wifi-cfg
                state: up
                wifi:
                  ssid: Any-WIFI
            "#,
    )
    .unwrap();

    let wifi_state = gen_wifi_plugin_state_for_phy("wlan0", &state);
    // eth0, the wifi-phy for wlan1 and the profile bound to wlan1 are out;
    // the bound and the unbound profiles are in.
    assert_eq!(wifi_state.ifaces.iter().count(), 3);
    let names: Vec<&str> = wifi_state.ifaces.iter().map(|i| i.name()).collect();
    assert!(names.contains(&"wlan0"));
    assert!(names.contains(&"Test-WIFI"));
    assert!(names.contains(&"Any-WIFI"));
}

#[test]
fn test_gen_wifi_plugin_state_skips_phy_without_config() {
    let state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: wlan0
                type: wifi-phy
                state: up
              - name: Manual-WIFI
                type: wifi-cfg
                state: up
                auto-connect: false
                wifi:
                  ssid: Manual-WIFI
            "#,
    )
    .unwrap();

    // A wifi-phy without any matching SSID profile is not a wifi config:
    // the plugin must not be contacted for it.
    assert!(gen_wifi_plugin_state_for_phy("wlan0", &state).is_empty());
}

fn gen_link_event(iface_name: &str, is_up: bool) -> InterfaceLinkEvent {
    InterfaceLinkEvent {
        iface_name: iface_name.to_string(),
        iface_index: 18,
        iface_type: InterfaceType::Ethernet,
        is_up,
        is_delete: false,
        time_stamp: SystemTime::now(),
        ssid: None,
        is_new_wifi_phy: false,
    }
}

#[test]
fn test_stale_link_down_event_skipped_when_current_up() {
    // A down event processed while the interface is already up is a
    // leftover of the boot-time transient state: it must be skipped so
    // the boot apply result (IP + routes) is not torn down.
    let saved_state = gen_saved_state();
    let wan0 = find_iface(&saved_state, "wan0");
    let mut cur_iface = wan0.clone();
    cur_iface.base_iface_mut().link_state =
        Some(nipart::InterfaceLinkState::Up);

    assert!(is_stale_link_down_event(
        &gen_link_event("eth0", false),
        Some(&cur_iface)
    ));
}

#[test]
fn test_link_down_event_processed_when_current_down() {
    // A real link-down event: the current kernel link state is down, so
    // the event reflects a genuine state change and must be processed
    // (purge IP and routes).
    let saved_state = gen_saved_state();
    let wan0 = find_iface(&saved_state, "wan0");
    let mut cur_iface = wan0.clone();
    cur_iface.base_iface_mut().link_state =
        Some(nipart::InterfaceLinkState::Down);

    assert!(!is_stale_link_down_event(
        &gen_link_event("eth0", false),
        Some(&cur_iface)
    ));
}

#[test]
fn test_up_event_never_stale() {
    // Up events always go through: they are the mechanism to (re)apply
    // the saved config, and skipping them would break hotplug (e.g.
    // wifi association or veth re-plug).
    let saved_state = gen_saved_state();
    let wan0 = find_iface(&saved_state, "wan0");
    let mut cur_iface = wan0.clone();
    cur_iface.base_iface_mut().link_state =
        Some(nipart::InterfaceLinkState::Up);

    assert!(!is_stale_link_down_event(
        &gen_link_event("eth0", true),
        Some(&cur_iface)
    ));
    // Interface already gone: delete event is handled separately.
    assert!(!is_stale_link_down_event(
        &gen_link_event("eth0", false),
        None
    ));
}

#[test]
fn test_nic_is_gone() {
    let saved_state = gen_saved_state();
    let wan0 = find_iface(&saved_state, "wan0");
    let mut delete_event = gen_link_event("eth0", false);
    delete_event.is_delete = true;

    assert!(nic_is_gone(&delete_event, Some(wan0)));
    assert!(nic_is_gone(&gen_link_event("eth0", false), None));
    assert!(!nic_is_gone(&gen_link_event("eth0", false), Some(wan0)));
    assert!(!nic_is_gone(&gen_link_event("eth0", true), Some(wan0)));
}

#[test]
fn test_wifi_phy_ssid_extraction() {
    let phy: Interface = rmsd_yaml::from_str(
        r#"---
            name: wlan0
            type: wifi-phy
            state: up
            wifi:
              ssid: Test-WIFI
            "#,
    )
    .unwrap();

    assert_eq!(wifi_phy_ssid(Some(&phy)).as_deref(), Some("Test-WIFI"));
    assert_eq!(wifi_phy_ssid(None), None);

    let eth: Interface = rmsd_yaml::from_str(
        r#"---
            name: eth0
            type: ethernet
            state: up
            "#,
    )
    .unwrap();
    assert_eq!(wifi_phy_ssid(Some(&eth)), None);
}

#[test]
fn test_auto_connect_defaults_to_true_on_link_up() {
    // Interface without `auto-connect` defaults to `auto-connect: true`,
    // hence link up should apply the interface along with its routes.
    let saved_state = gen_saved_state();
    let wan0 = find_iface(&saved_state, "wan0");
    let event = gen_link_event("eth0", true);

    let (new_iface, routes) = handle_event_auto_connect(
        &event,
        wan0,
        &saved_state,
        &NetworkState::default(),
    )
    .expect("auto-connect defaults to true");

    assert_eq!(new_iface.name(), "wan0");
    assert_eq!(new_iface.base_iface().state, InterfaceState::Up);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination.as_deref(), Some("0.0.0.0/0"));
}

#[test]
fn test_auto_connect_defaults_to_true_on_link_down() {
    // On link down, the default auto-connect purges IP and marks routes
    // absent, but does not bring the interface down.
    let saved_state = gen_saved_state();
    let wan0 = find_iface(&saved_state, "wan0");
    let event = gen_link_event("eth0", false);

    let (new_iface, routes) = handle_event_auto_connect(
        &event,
        wan0,
        &saved_state,
        &NetworkState::default(),
    )
    .expect("auto-connect defaults to true");

    assert_eq!(new_iface.base_iface().state, InterfaceState::Up);
    assert_eq!(
        new_iface.base_iface().ipv4,
        Some(InterfaceIpv4::new_disabled())
    );
    assert_eq!(routes.len(), 1);
    assert!(routes[0].is_absent());
}

#[test]
fn test_wifi_phy_link_down_purge_drops_wifi_section() {
    let saved_iface: Interface = rmsd_yaml::from_str(
        r#"---
            name: wlan0
            type: wifi-phy
            state: up
            wifi:
              ssid: Test-WIFI
              base-iface: wlan0
            "#,
    )
    .unwrap();

    let (new_iface, _) = gen_desired_iface_down(
        &InterfaceAutoConnect::AutoConnect,
        &saved_iface,
        &NetworkState::default(),
    );
    let Interface::WifiPhy(new_iface) = new_iface else {
        panic!("expected wifi-phy interface");
    };
    assert!(new_iface.wifi.is_none());
}

#[test]
fn test_wifi_phy_down_event_does_not_reapply_wifi_cfg() {
    // The SSID config is already sent to the plugin at boot/apply
    // time: a wifi-phy link-down event must only purge IP (handled
    // elsewhere), not re-apply the wifi-cfg, which would make the
    // plugin switch away from its current connection.
    let saved_iface = gen_wifi_cfg_iface();
    let event = gen_wifi_phy_event(false, None);

    assert!(handle_wifi_phy_event(&event, &saved_iface).is_none());
}

#[test]
fn test_wifi_phy_down_event_does_not_return_saved_wifi_phy() {
    // A saved wifi-phy itself is not re-applied on link down: the IP
    // purge is handled by the event worker before this helper.
    let saved_iface: Interface = rmsd_yaml::from_str(
        r#"---
            name: wlan0
            type: wifi-phy
            state: up
            "#,
    )
    .unwrap();
    let event = gen_wifi_phy_event(false, None);

    assert!(handle_wifi_phy_event(&event, &saved_iface).is_none());
}

#[test]
fn test_wifi_phy_up_event_applies_ip_config_of_matching_wifi_cfg() {
    // On wifi-phy link up with the matching SSID, the IP config of
    // the saved wifi-cfg is applied to the kernel wifi-phy.
    let saved_iface = gen_wifi_cfg_iface();
    let event = gen_wifi_phy_event(true, Some("Test-WIFI"));

    let new_iface = handle_wifi_phy_event(&event, &saved_iface)
        .expect("matching SSID should apply IP config");
    assert_eq!(new_iface.iface_type(), &InterfaceType::WifiPhy);
    assert_eq!(new_iface.kernel_iface_name(), "wlan0");
    assert_eq!(new_iface.name(), "wlan0");
    assert!(new_iface.base_iface().ipv4.is_some());
}

#[test]
fn test_wifi_cfg_event_route_resolves_to_connected_phy() {
    let saved_state = gen_wifi_cfg_state_with_route();
    let saved_iface = find_iface(&saved_state, "Test-WIFI");
    let mut desired_state = NetworkState::default();
    desired_state
        .ifaces
        .push(wifi_cfg_to_wifi_phy("wlan0", saved_iface));
    desired_state.routes = saved_state.routes.clone();

    let current_state: NetworkState = rmsd_yaml::from_str(
        r#"---
            interfaces:
              - name: wlan0
                type: wifi-phy
                state: up
                link-state: up
                wifi:
                  ssid: Test-WIFI
            "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired_state,
        current_state,
        None,
        Default::default(),
    )
    .unwrap();
    let changed: Vec<&str> = merged
        .routes
        .changed_routes
        .iter()
        .filter_map(|rt| rt.next_hop_iface.as_deref())
        .collect();
    assert_eq!(changed, vec!["wlan0"]);
}

#[test]
fn test_wifi_phy_up_event_with_other_ssid_ignores_wifi_cfg() {
    // A wifi-phy already up with a different SSID must not be
    // reconfigured: the plugin decides which SSID to connect at
    // boot/apply time.
    let saved_iface = gen_wifi_cfg_iface();
    let event = gen_wifi_phy_event(true, Some("Other-SSID"));

    assert!(handle_wifi_phy_event(&event, &saved_iface).is_none());
}
