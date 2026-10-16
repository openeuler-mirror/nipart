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
fn fatal_shuli_errors_are_mapped_for_the_daemon_wait() {
    use shuli::ErrorKind as ShuliErrorKind;

    let err = nipart_error_from_shuli(&shuli::WifiError::new(
        ShuliErrorKind::WrongPassword,
        "wrong password for SSID 'Test-WIFI'",
    ))
    .expect("a wrong password must be latched");
    assert_eq!(err.kind(), ErrorKind::AuthenticationError);

    let err = nipart_error_from_shuli(&shuli::WifiError::new(
        ShuliErrorKind::NoSupport,
        "TKIP WPA2 is not supported",
    ))
    .expect("unsupported security must be latched");
    assert_eq!(err.kind(), ErrorKind::NoSupport);

    assert!(
        nipart_error_from_shuli(&shuli::WifiError::new(
            ShuliErrorKind::Nl80211,
            "transient netlink error",
        ))
        .is_none(),
        "transient errors must not fail a connection wait"
    );
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
async fn apply_ignore_marker_disconnects_managed_phy() {
    let enabled_flag = Arc::new(AtomicBool::new(true));
    let wifi_live = Arc::new(Mutex::new(HashMap::new()));
    let mut state =
        WifiClientState::new(enabled_flag, wifi_live.clone(), wifi_errors());
    state.ifaces.insert(
        "wlan1".to_string(),
        WifiIfaceState {
            if_index: 42,
            desired_networks: vec![network("Home-SSID", None, false)],
        },
    );
    state.set_live_connected(
        "wlan1",
        WifiLiveState {
            ssid: "Home-SSID".to_string(),
            bssid: None,
        },
    );

    state
        .apply(&[phy_iface("wlan1", InterfaceState::Ignore)], false)
        .await
        .expect("a `state: ignore` marker must be accepted");

    assert!(
        !state.ifaces.contains_key("wlan1"),
        "an ignored wifi-phy must be dropped from the managed set"
    );
    assert!(
        !state.is_connected(),
        "the ignored phy's live connection must be cleared"
    );
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
    let networks = build_shuli_networks(&refs, &HashMap::new()).unwrap();
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
    assert!(build_shuli_networks(&refs, &HashMap::new()).is_err());
}

#[test]
fn build_shuli_networks_maps_bssid_pin() {
    let mut cfg = wifi_cfg("A", None);
    cfg.bssid = Some("02:00:00:00:00:01".to_string());
    // An identical duplicate entry is still de-duplicated.
    let cfgs = [cfg.clone(), cfg];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    let networks = build_shuli_networks(&refs, &HashMap::new()).unwrap();

    assert_eq!(networks.len(), 1);
    assert_eq!(
        networks[0].bssid,
        Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        "wifi-cfg.bssid must pin the shuli network to that AP"
    );
}

#[test]
fn build_shuli_networks_rejects_invalid_bssid() {
    let mut cfg = wifi_cfg("A", None);
    cfg.bssid = Some("not-a-mac".to_string());
    let refs = [&cfg];

    let err = build_shuli_networks(&refs, &HashMap::new())
        .expect_err("an invalid BSSID must fail the apply");
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    assert!(
        err.msg().contains("Invalid BSSID"),
        "unexpected error: {err}"
    );
}

#[test]
fn build_shuli_networks_rejects_conflicting_bssid() {
    let mut one = wifi_cfg("A", Some("secret"));
    one.bssid = Some("02:00:00:00:00:01".to_string());
    let mut two = wifi_cfg("A", Some("secret"));
    two.bssid = Some("02:00:00:00:00:02".to_string());
    let cfgs = [one, two];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    assert!(build_shuli_networks(&refs, &HashMap::new()).is_err());
}

#[test]
fn build_shuli_networks_attaches_hints_to_matching_ssid() {
    let cfgs = [wifi_cfg("A", None), wifi_cfg("B", None)];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();
    let mut hint_map = HashMap::new();
    hint_map.insert(
        "A".to_string(),
        hints::LoadedHints {
            frequencies_mhz: vec![2412, 5180],
            known_bss: vec![
                ([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 2412),
                ([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 5180),
            ],
        },
    );

    let networks = build_shuli_networks(&refs, &hint_map).unwrap();

    assert_eq!(networks[0].hints.frequencies_mhz, vec![2412, 5180]);
    assert_eq!(
        networks[0].hints.known_bss,
        vec![
            ShuliKnownBss::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 2412),
            ShuliKnownBss::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 5180),
        ]
    );
    assert_eq!(
        networks[0].hints.bssid, None,
        "no complete BSS hint: shuli's scan-free path must not be enabled"
    );
    assert!(
        networks[1].hints.frequencies_mhz.is_empty()
            && networks[1].hints.known_bss.is_empty(),
        "a hinted SSID must not leak hints to another SSID"
    );
}

#[test]
fn empty_hints_are_not_attached() {
    let cfgs = [wifi_cfg("A", None)];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();
    let mut hint_map = HashMap::new();
    hint_map.insert("A".to_string(), hints::LoadedHints::default());

    let networks = build_shuli_networks(&refs, &hint_map).unwrap();

    assert!(networks[0].hints.frequencies_mhz.is_empty());
    assert!(networks[0].hints.known_bss.is_empty());
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
fn same_saved_networks_ignores_hint_changes() {
    // A BSS recorded while connected changes the hints of a saved
    // profile; an idempotent re-apply must still compare equal so the
    // live client is not restarted.
    let plain = [network("A", None, false)];
    let mut hinted = network("A", None, false);
    hinted.set_hints(
        ShuliNetworkConfigHints::new().with_frequencies_mhz(vec![2412]),
    );

    assert!(same_saved_networks_ignoring_prefered(
        std::slice::from_ref(&hinted),
        &plain
    ));
    assert!(same_saved_networks_ignoring_prefered(&plain, &[hinted]));
}

#[test]
fn same_saved_networks_detects_bssid_pin_change() {
    let plain = [network("A", None, false)];
    let mut pinned = network("A", None, false);
    pinned.set_bssid(Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));

    assert!(
        !same_saved_networks_ignoring_prefered(
            &plain,
            std::slice::from_ref(&pinned)
        ),
        "adding a BSSID pin is a configuration change"
    );
    assert!(
        !same_saved_networks_ignoring_prefered(
            std::slice::from_ref(&pinned),
            &plain
        ),
        "removing a BSSID pin is a configuration change"
    );
}

#[test]
fn refresh_hints_updates_only_the_hints() {
    let mut current = vec![network("A", Some("pw"), true)];
    let mut desired = network("A", None, false);
    desired.set_hints(
        ShuliNetworkConfigHints::new().with_frequencies_mhz(vec![5180]),
    );

    refresh_hints(&mut current, &[desired]);

    assert_eq!(current[0].hints.frequencies_mhz, vec![5180]);
    assert_eq!(current[0].password.as_deref(), Some("pw"));
    assert!(current[0].prefered, "the preferred mark must be preserved");
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
fn forced_single_ssid_keeps_connection_when_already_on_desired_ssid() {
    let networks = [network("Home-SSID", None, true)];
    assert!(!should_reconnect_to_networks(
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

    let merged =
        merge_preferred_networks(&existing, &refs, &HashMap::new()).unwrap();

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

    let merged =
        merge_preferred_networks(&existing, &refs, &HashMap::new()).unwrap();

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].ssid, "A");
    assert!(!merged[0].prefered);
    assert_eq!(merged[1].ssid, "B");
    assert!(merged[1].prefered);
}

#[test]
fn merge_preferred_networks_drops_hints_of_unrelated_ssids() {
    let mut hinted = network("A", None, false);
    hinted.set_hints(
        ShuliNetworkConfigHints::new()
            .with_frequencies_mhz(vec![2412])
            .with_known_bss(vec![ShuliKnownBss::new(
                [0x02, 0x00, 0x00, 0x00, 0x01, 1],
                2412,
            )]),
    );
    let existing = [hinted];
    let cfgs = [wifi_cfg("B", None)];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    let merged =
        merge_preferred_networks(&existing, &refs, &HashMap::new()).unwrap();

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].ssid, "A");
    assert!(!merged[0].prefered);
    assert!(
        merged[0].hints.frequencies_mhz.is_empty()
            && merged[0].hints.known_bss.is_empty(),
        "another profile's hints must not restrict the requested scan"
    );
    assert_eq!(merged[1].ssid, "B");
    assert!(merged[1].prefered);
}

#[test]
fn merge_preferred_networks_dedupes_requested_ssids() {
    let cfgs = [wifi_cfg("A", Some("secret")), wifi_cfg("A", Some("secret"))];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    let merged = merge_preferred_networks(&[], &refs, &HashMap::new()).unwrap();

    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].ssid, "A");
    assert!(merged[0].prefered);
}

#[test]
fn merge_preferred_networks_rejects_conflicting_password() {
    let cfgs = [wifi_cfg("A", Some("one")), wifi_cfg("A", Some("two"))];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    assert!(merge_preferred_networks(&[], &refs, &HashMap::new()).is_err());
}

#[test]
fn merge_preferred_networks_keeps_the_bssid_pin() {
    let mut cfg = wifi_cfg("B", None);
    cfg.bssid = Some("02:00:00:00:00:01".to_string());
    let refs = [&cfg];

    let merged = merge_preferred_networks(&[], &refs, &HashMap::new()).unwrap();

    assert!(merged[0].prefered);
    assert_eq!(merged[0].bssid, Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
}

#[test]
fn merge_preferred_networks_rejects_conflicting_bssid() {
    let mut one = wifi_cfg("A", Some("secret"));
    one.bssid = Some("02:00:00:00:00:01".to_string());
    let mut two = wifi_cfg("A", Some("secret"));
    two.bssid = Some("02:00:00:00:00:02".to_string());
    let cfgs = [one, two];
    let refs: Vec<&WifiConfig> = cfgs.iter().collect();

    assert!(merge_preferred_networks(&[], &refs, &HashMap::new()).is_err());
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

    assert_eq!(wifi_cfg_phy_names(&iface, &cfg, &up_phys, &[]), up_phys);
}

#[test]
fn unbound_wifi_cfg_falls_back_to_present_phys() {
    let (iface, cfg) = cfg_iface("Test-WIFI", None);

    assert!(wifi_cfg_phy_names(&iface, &cfg, &[], &[]).is_empty());
    // An apply carrying only saved profiles (e.g. the new-wifi-phy
    // event) still binds the profile to the present phys.
    assert_eq!(
        wifi_cfg_phy_names(&iface, &cfg, &[], &["wlan0".to_string()]),
        vec!["wlan0".to_string()]
    );
}

#[test]
fn empty_base_iface_is_unbound() {
    let up_phys = vec!["wlan0".to_string(), "wlan1".to_string()];
    let (iface, cfg) = cfg_iface("Test-WIFI", Some(""));

    // An empty base-iface behaves like an undefined one.
    assert_eq!(wifi_cfg_phy_names(&iface, &cfg, &up_phys, &[]), up_phys);
    assert_eq!(
        wifi_cfg_phy_names(&iface, &cfg, &[], &["wlan0".to_string()]),
        vec!["wlan0".to_string()]
    );
}

#[test]
fn bound_wifi_cfg_targets_base_iface_only() {
    let up_phys = vec!["wlan0".to_string(), "wlan1".to_string()];
    let (iface, cfg) = cfg_iface("Test-WIFI", Some("wlan1"));

    // The bound phy is brought up by this apply.
    assert_eq!(
        wifi_cfg_phy_names(&iface, &cfg, &up_phys, &[]),
        vec!["wlan1".to_string()]
    );
    // The bound phy is already present in the kernel.
    assert_eq!(
        wifi_cfg_phy_names(&iface, &cfg, &[], &["wlan1".to_string()]),
        vec!["wlan1".to_string()]
    );
    // The bound phy is absent: the profile is deferred until it appears,
    // never handed to shuli as a non-existent interface.
    assert!(
        wifi_cfg_phy_names(&iface, &cfg, &[], &["wlan0".to_string()])
            .is_empty()
    );
    assert!(wifi_cfg_phy_names(&iface, &cfg, &[], &[]).is_empty());
}

#[test]
fn wifi_phy_targets_its_own_kernel_name() {
    let iface = phy_iface("wlan0", InterfaceState::Up);
    let cfg = wifi_cfg("Test-WIFI", None);

    assert_eq!(
        wifi_cfg_phy_names(&iface, &cfg, &["wlan1".to_string()], &[]),
        vec!["wlan0".to_string()]
    );
}
