// SPDX-License-Identifier: Apache-2.0

use nipart::{
    BaseInterface, InterfaceState, InterfaceType, WifiCfgInterface,
    WifiPhyInterface,
};

use super::*;

#[test]
fn has_wifi_ssid_up_request_requires_ssid() {
    let mut wifi_cfg = WifiCfgInterface::new(BaseInterface::new(
        "Test-WIFI".to_string(),
        InterfaceType::WifiCfg,
    ));
    wifi_cfg.base.state = InterfaceState::Up;
    wifi_cfg.wifi = Some(WifiConfig {
        ssid: "Test-WIFI".to_string(),
        ..Default::default()
    });
    assert!(has_wifi_ssid_up_request(&[Interface::WifiCfg(Box::new(
        wifi_cfg
    ))]));

    let mut wifi_phy = WifiPhyInterface::default();
    wifi_phy.base =
        BaseInterface::new("wlan0".to_string(), InterfaceType::WifiPhy);
    wifi_phy.base.state = InterfaceState::Up;
    assert!(!has_wifi_ssid_up_request(&[Interface::WifiPhy(Box::new(
        wifi_phy
    ))]));
}

#[tokio::test]
async fn set_control_off_on_toggles_wifi_state() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let mut state = WifiClientState::new(enabled_flag.clone(), wifi_live);

    state.set_control(NipartWifiControl::Off).await.unwrap();
    assert!(!enabled_flag.load(Ordering::Acquire));
    assert!(!state.has_client());
    assert!(!state.is_connected());

    state.set_control(NipartWifiControl::On).await.unwrap();
    assert!(enabled_flag.load(Ordering::Acquire));
    assert!(!state.has_client());
    assert!(!state.is_connected());
}

#[tokio::test]
async fn restart_client_resets_connected_state() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let mut state = WifiClientState::new(enabled_flag, wifi_live);
    state.connected = true;

    state.restart_client().await;

    assert!(!state.is_connected());
    assert!(!state.has_client());
}

#[test]
fn notify_resume_without_client_is_noop() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let state = WifiClientState::new(enabled_flag, wifi_live);

    state.notify_resume();

    assert!(!state.has_client());
}

#[test]
fn live_state_tracks_connected_ifaces_per_interface() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let mut state = WifiClientState::new(enabled_flag, wifi_live.clone());

    state.set_live_connected(
        "wlan0",
        WifiLiveState {
            ssid: "Home-SSID".to_string(),
            bssid: None,
        },
    );
    state.set_live_connected(
        "wlan1",
        WifiLiveState {
            ssid: "Office-SSID".to_string(),
            bssid: None,
        },
    );
    assert!(state.is_connected());

    state.clear_live_iface("wlan0");
    assert!(state.is_connected());
    assert_eq!(
        wifi_live.lock().unwrap().get("wlan1").unwrap().ssid,
        "Office-SSID"
    );

    state.clear_live_iface("wlan1");
    assert!(!state.is_connected());
    assert!(wifi_live.lock().unwrap().is_empty());
}

#[tokio::test]
async fn set_control_off_clears_live_state() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let mut state = WifiClientState::new(enabled_flag, wifi_live.clone());
    state.set_live_connected(
        "wlan0",
        WifiLiveState {
            ssid: "Home-SSID".to_string(),
            bssid: None,
        },
    );

    state.set_control(NipartWifiControl::Off).await.unwrap();

    assert!(!state.is_connected());
    assert!(wifi_live.lock().unwrap().is_empty());
}

fn wifi_cfg(ssid: &str, password: Option<&str>) -> WifiConfig {
    WifiConfig {
        ssid: ssid.to_string(),
        password: password.map(str::to_string),
        ..Default::default()
    }
}

#[test]
fn build_shuli_networks_keeps_order_and_dedupes() {
    let cfgs = [
        wifi_cfg("A", None),
        wifi_cfg("B", Some("secret")),
        wifi_cfg("A", None),
    ];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();
    let networks = build_shuli_networks(&refs).unwrap();
    assert_eq!(networks.len(), 2);
    assert_eq!(networks[0].ssid, "A");
    assert_eq!(networks[0].password, None);
    assert_eq!(networks[1].ssid, "B");
    assert_eq!(networks[1].password.as_deref(), Some("secret"));
}

#[test]
fn build_shuli_networks_rejects_conflicting_password() {
    let cfgs = [wifi_cfg("A", Some("one")), wifi_cfg("A", Some("two"))];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();
    assert!(build_shuli_networks(&refs).is_err());
}

#[test]
fn same_saved_networks_ignoring_prefered_only() {
    let preferred = [network("A", None, true)];
    let normal = [network("A", None, false)];
    assert!(same_saved_networks_ignoring_prefered(&preferred, &normal));

    let different_password = [network("A", Some("secret"), false)];
    assert!(!same_saved_networks_ignoring_prefered(
        &preferred,
        &different_password
    ));

    let extra_network = [network("A", None, true), network("B", None, false)];
    assert!(!same_saved_networks_ignoring_prefered(
        &preferred,
        &extra_network
    ));
}

#[test]
fn forced_single_ssid_rescans_when_already_on_desired_ssid() {
    let networks = [network("Home-SSID", None, true)];
    assert!(should_reconnect_to_networks(
        Some("Home-SSID"),
        &networks,
        true,
        Some("Home-SSID")
    ));
}

#[test]
fn forced_apply_reconnects_when_ssid_differs_or_disconnected() {
    let networks = [network("Office-SSID", None, true)];
    assert!(should_reconnect_to_networks(
        Some("Home-SSID"),
        &networks,
        true,
        Some("Office-SSID")
    ));
    assert!(should_reconnect_to_networks(
        None,
        &networks,
        true,
        Some("Office-SSID")
    ));
    assert!(!should_reconnect_to_networks(
        Some("Office-SSID"),
        &networks,
        false,
        Some("Office-SSID")
    ));
}

#[test]
fn forced_full_list_keeps_connection_on_any_desired_ssid() {
    let networks = [network("A", None, false), network("B", None, false)];
    assert!(!should_reconnect_to_networks(
        Some("A"),
        &networks,
        true,
        None
    ));
    assert!(!should_reconnect_to_networks(
        Some("B"),
        &networks,
        true,
        None
    ));
    assert!(should_reconnect_to_networks(
        Some("C"),
        &networks,
        true,
        None
    ));
}

#[test]
fn forced_single_ssid_reconnects_when_other_saved_ssid_connected() {
    let networks = [
        network("Home-SSID", None, true),
        network("Office-SSID", None, false),
    ];
    assert!(should_reconnect_to_networks(
        Some("Office-SSID"),
        &networks,
        true,
        Some("Home-SSID")
    ));
}

fn network(
    ssid: &str,
    password: Option<&str>,
    prefered: bool,
) -> ShuliNetworkConfig {
    let mut network = ShuliNetworkConfig::new(ssid);
    if let Some(password) = password {
        network.set_password(password);
    }
    network.prefered = prefered;
    network
}

#[test]
fn merge_preferred_networks_keeps_others_and_prefers_requested() {
    let existing = [
        network("A", None, false),
        network("B", Some("b-secret"), true),
    ];
    let cfgs = [wifi_cfg("B", Some("b-new"))];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    let merged = merge_preferred_networks(&existing, &refs).unwrap();

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].ssid, "A");
    assert!(!merged[0].prefered);
    assert_eq!(merged[1].ssid, "B");
    assert!(merged[1].prefered);
    assert_eq!(merged[1].password.as_deref(), Some("b-new"));
}

#[test]
fn merge_preferred_networks_appends_new_ssid() {
    let existing = [network("A", None, false)];
    let cfgs = [wifi_cfg("B", None)];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    let merged = merge_preferred_networks(&existing, &refs).unwrap();

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].ssid, "A");
    assert!(!merged[0].prefered);
    assert_eq!(merged[1].ssid, "B");
    assert!(merged[1].prefered);
}

#[test]
fn merge_preferred_networks_dedupes_requested_ssids() {
    let cfgs = [wifi_cfg("A", Some("secret")), wifi_cfg("A", Some("secret"))];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    let merged = merge_preferred_networks(&[], &refs).unwrap();

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].ssid, "A");
    assert!(merged[0].prefered);
}

#[test]
fn merge_preferred_networks_rejects_conflicting_password() {
    let cfgs = [wifi_cfg("A", Some("one")), wifi_cfg("A", Some("two"))];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    assert!(merge_preferred_networks(&[], &refs).is_err());
}
