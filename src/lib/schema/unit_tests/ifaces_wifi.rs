// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{Interface, NetworkState};

#[test]
fn test_hide_secrets_in_debug_wificfg() {
    let wifi_cfg = WifiConfig {
        ssid: "test-wifi".into(),
        password: Some("12345678".into()),
        ..Default::default()
    };
    let debug_str = format!("{:?}", wifi_cfg);
    println!("Debug string {:?}", debug_str);
    assert!(!debug_str.contains("12345678"));
}

#[test]
fn test_hide_secrets_in_display_wificfg() {
    let wifi_cfg = WifiConfig {
        ssid: "test-wifi".into(),
        password: Some("12345678".into()),
        ..Default::default()
    };
    let debug_str = format!("{}", wifi_cfg);
    println!("Display string {}", debug_str);
    assert!(!debug_str.contains("12345678"));
}

#[test]
fn test_hide_secrets_in_display_wifiiface() {
    let wifi_iface = WifiPhyInterface {
        base: Default::default(),
        wifi: Some(WifiConfig {
            ssid: "test-wifi".into(),
            password: Some("12345678".into()),
            ..Default::default()
        }),
    };
    let debug_str = format!("{}", wifi_iface);
    println!("Display string {}", debug_str);
    assert!(!debug_str.contains("12345678"));
}

#[test]
fn test_hide_secrets_in_display_iface() {
    let iface = Interface::WifiPhy(Box::new(WifiPhyInterface {
        base: Default::default(),
        wifi: Some(WifiConfig {
            ssid: "test-wifi".into(),
            password: Some("12345678".into()),
            ..Default::default()
        }),
    }));
    let debug_str = format!("{}", iface);
    println!("Display string {}", debug_str);
    assert!(!debug_str.contains("12345678"));
}

#[test]
fn test_hide_secrets_in_display_net_state() {
    let iface = Interface::WifiPhy(Box::new(WifiPhyInterface {
        base: Default::default(),
        wifi: Some(WifiConfig {
            ssid: "test-wifi".into(),
            password: Some("12345678".into()),
            ..Default::default()
        }),
    }));
    let mut net_state = NetworkState::new();
    net_state.ifaces.push(iface);
    let debug_str = format!("{}", net_state);
    println!("Display string {}", debug_str);
    assert!(!debug_str.contains("12345678"));
}

#[test]
fn test_sanitize_empty_base_iface_as_unbound() {
    let mut wifi_cfg = WifiConfig {
        ssid: "test-wifi".into(),
        base_iface: Some(String::new()),
        ..Default::default()
    };
    wifi_cfg.sanitize();
    assert_eq!(wifi_cfg.base_iface, None);

    let mut wifi_cfg = WifiConfig {
        ssid: "test-wifi".into(),
        base_iface: Some("wlan0".into()),
        ..Default::default()
    };
    wifi_cfg.sanitize();
    assert_eq!(wifi_cfg.base_iface.as_deref(), Some("wlan0"));
}

#[test]
fn test_merge_wifi_new_ssid_drops_old_credentials() {
    let old = WifiConfig {
        ssid: "test-wifi".into(),
        password: Some("12345678".into()),
        bssid: Some("AA:BB:CC:DD:EE:FF".into()),
        hidden: true,
        ..Default::default()
    };
    let new = WifiConfig {
        ssid: "test-wifi-2".into(),
        ..Default::default()
    };
    let merged = old.merge(&new).unwrap();
    assert_eq!(merged.ssid, "test-wifi-2");
    assert_eq!(merged.password, None);
    assert_eq!(merged.bssid, None);
    assert!(!merged.hidden);
}

#[test]
fn test_merge_wifi_new_ssid_drops_hidden_secret_marker() {
    let old = WifiConfig {
        ssid: "test-wifi".into(),
        password: Some("12345678".into()),
        ..Default::default()
    };
    let new = WifiConfig {
        ssid: "test-wifi-2".into(),
        password: Some(crate::NetworkState::HIDE_SECRET_STR.to_string()),
        ..Default::default()
    };
    let merged = old.merge(&new).unwrap();
    assert_eq!(merged.password, None);
}

#[test]
fn test_merge_wifi_same_ssid_keeps_old_password() {
    let old = WifiConfig {
        ssid: "test-wifi".into(),
        password: Some("12345678".into()),
        ..Default::default()
    };
    let new = WifiConfig {
        ssid: "test-wifi".into(),
        ..Default::default()
    };
    let merged = old.merge(&new).unwrap();
    assert_eq!(merged.password.as_deref(), Some("12345678"));
}

#[test]
fn test_merge_wifi_new_ssid_keeps_explicit_password() {
    let old = WifiConfig {
        ssid: "test-wifi".into(),
        password: Some("12345678".into()),
        ..Default::default()
    };
    let new = WifiConfig {
        ssid: "test-wifi-2".into(),
        password: Some("87654321".into()),
        ..Default::default()
    };
    let merged = old.merge(&new).unwrap();
    assert_eq!(merged.password.as_deref(), Some("87654321"));
}
