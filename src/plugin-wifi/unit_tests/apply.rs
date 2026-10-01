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

fn wifi_errors() -> Arc<Mutex<HashMap<String, WifiConnectError>>> {
    Arc::new(Mutex::new(HashMap::new()))
}

fn no_support_error(ssid: &str) -> WifiConnectError {
    WifiConnectError {
        ssid: ssid.to_string(),
        error: NipartError::new(
            ErrorKind::NoSupport,
            "TKIP WPA2 is not supported".to_string(),
        ),
    }
}

#[test]
fn clear_applied_connect_errors_drops_only_matching_ssids() {
    let mut errors = HashMap::new();
    errors.insert("wlan0".to_string(), no_support_error("空蝉"));
    errors.insert("wlan1".to_string(), no_support_error("SweatHome5G"));

    // A new apply of 空蝉 invalidates its stale error only.
    let (cfg_iface, _) = cfg_iface("空蝉", None);
    clear_applied_connect_errors(&mut errors, &[cfg_iface]);

    assert!(!errors.contains_key("wlan0"));
    assert!(errors.contains_key("wlan1"));
}

#[test]
fn latched_connect_error_matches_iface_and_ssid() {
    let mut errors = HashMap::new();
    errors.insert("wlan0".to_string(), no_support_error("空蝉"));

    let err = latched_connect_error(&errors, "wlan0", "空蝉")
        .expect("matching iface+ssid must report the error");
    assert_eq!(err.kind(), ErrorKind::NoSupport);
    assert_eq!(err.msg(), "TKIP WPA2 is not supported");

    // Another SSID or interface must not see the stale error.
    assert!(latched_connect_error(&errors, "wlan0", "Other").is_none());
    assert!(latched_connect_error(&errors, "wlan1", "空蝉").is_none());
}

#[test]
fn connect_error_latch_is_cleared_for_new_attempt_and_restart() {
    let errors = wifi_errors();
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let mut state =
        WifiClientState::new(enabled_flag, wifi_live, errors.clone());

    state.set_connect_error("wlan0", no_support_error("空蝉"));
    assert!(errors.lock().unwrap().contains_key("wlan0"));

    // A fresh apply of the interface clears the latch.
    state.clear_connect_error("wlan0");
    assert!(errors.lock().unwrap().is_empty());

    // A client restart drops every latched error.
    state.set_connect_error("wlan0", no_support_error("空蝉"));
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(state.restart_client());
    assert!(errors.lock().unwrap().is_empty());
}

#[tokio::test]
async fn set_control_off_on_toggles_wifi_state() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let mut state =
        WifiClientState::new(enabled_flag.clone(), wifi_live, wifi_errors());

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
    let mut state =
        WifiClientState::new(enabled_flag, wifi_live, wifi_errors());
    state.connected = true;

    state.restart_client().await;

    assert!(!state.is_connected());
    assert!(!state.has_client());
}

#[test]
fn notify_resume_without_client_is_noop() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let state = WifiClientState::new(enabled_flag, wifi_live, wifi_errors());

    state.notify_resume();

    assert!(!state.has_client());
}

#[test]
fn live_state_tracks_connected_ifaces_per_interface() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let mut state =
        WifiClientState::new(enabled_flag, wifi_live.clone(), wifi_errors());

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
    let mut state =
        WifiClientState::new(enabled_flag, wifi_live.clone(), wifi_errors());
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
fn same_saved_networks_ignores_entry_order() {
    // A re-ordered re-apply of the same profiles (the daemon delivers
    // them through hash-map-backed state, so the order is not stable)
    // must not be mistaken for a configuration change.
    let a = network("A", None, false);
    let b = network("B", Some("secret"), true);
    assert!(same_saved_networks_ignoring_prefered(
        &[a.clone(), b.clone()],
        &[b.clone(), a.clone()]
    ));

    // Multiplicity still matters.
    assert!(!same_saved_networks_ignoring_prefered(
        &[a.clone(), a.clone()],
        &[a.clone(), b.clone()]
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

fn phy_iface(name: &str, state: InterfaceState) -> Interface {
    let mut phy = WifiPhyInterface::default();
    phy.base = BaseInterface::new(name.to_string(), InterfaceType::WifiPhy);
    phy.base.kernel_iface_name = name.to_string();
    phy.base.state = state;
    Interface::WifiPhy(Box::new(phy))
}

fn cfg_iface(name: &str, base_iface: Option<&str>) -> (Interface, WifiConfig) {
    let mut cfg = wifi_cfg(name, None);
    cfg.base_iface = base_iface.map(str::to_string);
    let mut iface = WifiCfgInterface::new(BaseInterface::new(
        name.to_string(),
        InterfaceType::WifiCfg,
    ));
    iface.wifi = Some(cfg.clone());
    (Interface::WifiCfg(Box::new(iface)), cfg)
}

#[test]
fn up_wifi_phys_keeps_up_kernel_phys_only() {
    let ifaces = [
        phy_iface("wlan0", InterfaceState::Up),
        phy_iface("wlan1", InterfaceState::Down),
        phy_iface("wlan2", InterfaceState::Up),
    ];

    assert_eq!(
        up_wifi_phys(&ifaces),
        vec!["wlan0".to_string(), "wlan2".to_string()]
    );
}

#[test]
fn unbound_wifi_cfg_targets_every_up_wifi_phy() {
    let up_phys = vec!["wlan0".to_string(), "wlan1".to_string()];
    let (iface, cfg) = cfg_iface("Test-WIFI", None);

    assert_eq!(wifi_cfg_phy_names(&iface, &cfg, &up_phys), up_phys);
}

#[test]
fn unbound_wifi_cfg_without_phy_targets_none() {
    let (iface, cfg) = cfg_iface("Test-WIFI", None);

    assert!(wifi_cfg_phy_names(&iface, &cfg, &[]).is_empty());
}

#[test]
fn bound_wifi_cfg_targets_base_iface_only() {
    let up_phys = vec!["wlan0".to_string(), "wlan1".to_string()];
    let (iface, cfg) = cfg_iface("Test-WIFI", Some("wlan1"));

    assert_eq!(
        wifi_cfg_phy_names(&iface, &cfg, &up_phys),
        vec!["wlan1".to_string()]
    );
    assert_eq!(
        wifi_cfg_phy_names(&iface, &cfg, &[]),
        vec!["wlan1".to_string()]
    );
}

#[test]
fn wifi_phy_targets_its_own_kernel_name() {
    let iface = phy_iface("wlan0", InterfaceState::Up);
    let cfg = wifi_cfg("Test-WIFI", None);

    assert_eq!(
        wifi_cfg_phy_names(&iface, &cfg, &["wlan1".to_string()]),
        vec!["wlan0".to_string()]
    );
}
