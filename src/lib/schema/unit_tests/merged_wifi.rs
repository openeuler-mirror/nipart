// SPDX-License-Identifier: Apache-2.0

use super::expand_wifi_cfg_to_connected_phy;
use crate::{Interface, InterfaceType, Interfaces, NipartInterface};

fn wifi_cfg_desired() -> Interfaces {
    rmsd_yaml::from_str(
        r#"---
            - name: HomeWiFi
              type: wifi-cfg
              state: up
              ipv4:
                enabled: true
                dhcp: true
              ipv6:
                enabled: true
                dhcp: true
                autoconf: true
              wifi:
                ssid: HomeWiFi
            "#,
    )
    .unwrap()
}

fn connected_wifi_phy() -> Interfaces {
    rmsd_yaml::from_str(
        r#"---
            - name: wlan0
              type: wifi-phy
              state: up
              link-state: up
              mac-address: 02:00:00:00:00:01
              permanent-mac-address: 02:00:00:00:00:01
              profile-name: wlan0
              wifi:
                ssid: HomeWiFi
            "#,
    )
    .unwrap()
}

#[test]
fn test_expand_wifi_cfg_ip_to_connected_phy() {
    let mut desired = wifi_cfg_desired();
    expand_wifi_cfg_to_connected_phy(&mut desired, &connected_wifi_phy());

    let phy = desired.kernel_ifaces.get("wlan0").unwrap();
    assert!(matches!(phy, Interface::WifiPhy(_)));
    assert_eq!(phy.iface_type(), &InterfaceType::WifiPhy);
    assert_eq!(
        phy.base_iface().ipv6.as_ref().and_then(|ipv6| ipv6.dhcp),
        Some(true)
    );
    assert!(
        desired
            .user_ifaces
            .contains_key(&("HomeWiFi".to_string(), InterfaceType::WifiCfg))
    );
}

#[test]
fn test_no_expand_when_wifi_phy_not_connected() {
    let mut desired = wifi_cfg_desired();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
            - name: wlan0
              type: wifi-phy
              state: up
              link-state: down
              mac-address: 02:00:00:00:00:01
              wifi:
                ssid: HomeWiFi
            "#,
    )
    .unwrap();

    expand_wifi_cfg_to_connected_phy(&mut desired, &current);

    assert!(!desired.kernel_ifaces.contains_key("wlan0"));
}

#[test]
fn test_no_expand_wifi_cfg_to_ignored_phy() {
    let mut desired = wifi_cfg_desired();
    let current: Interfaces = rmsd_yaml::from_str(
        r#"---
            - name: wlan0
              type: wifi-phy
              state: ignore
              link-state: up
              mac-address: 02:00:00:00:00:01
              permanent-mac-address: 02:00:00:00:00:01
              wifi:
                ssid: HomeWiFi
            "#,
    )
    .unwrap();

    expand_wifi_cfg_to_connected_phy(&mut desired, &current);

    assert!(!desired.kernel_ifaces.contains_key("wlan0"));
}
