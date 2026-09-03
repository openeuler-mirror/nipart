// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use crate::{
    Interface, InterfaceIdentifier, InterfaceLinkState, InterfaceState,
    InterfaceType, Interfaces, MergedInterfaces, NipartInterface,
    WifiCfgInterface,
};

pub(crate) fn wifi_cfg_matches_phy(
    wifi_cfg: &WifiCfgInterface,
    cur_iface: &Interface,
) -> bool {
    let Some(wifi) = wifi_cfg.wifi.as_ref() else {
        return false;
    };
    if cur_iface.iface_type() != &InterfaceType::WifiPhy {
        return false;
    }
    let ssid_match = matches!(
        cur_iface,
        Interface::WifiPhy(phy) if phy.ssid() == Some(wifi.ssid.as_str())
    );
    let base_match = wifi.base_iface.as_deref().is_some_and(|base_iface| {
        base_iface == cur_iface.kernel_iface_name()
            || base_iface == cur_iface.name()
    });
    (base_match || wifi.base_iface.is_none()) && ssid_match
}

pub(crate) fn find_connected_wifi_phy_for_cfg<'a>(
    current: &'a Interfaces,
    wifi_cfg: &WifiCfgInterface,
) -> Option<&'a Interface> {
    current.kernel_ifaces.values().find(|cur_iface| {
        wifi_cfg_matches_phy(wifi_cfg, cur_iface)
            && cur_iface.base_iface().link_state == Some(InterfaceLinkState::Up)
    })
}

/// Expand the IP config of a `wifi-cfg` onto its already-connected
/// `wifi-phy`.
///
/// A `wifi-cfg` is userspace-only, so its IP config is normally applied by
/// the link-up event after shuli associates. When the wifi-phy is already
/// up and connected to that SSID at apply time, no link event will fire and
/// the IP/DHCP change would be silently stored but never applied. Generate a
/// synthetic `wifi-phy` desired interface carrying the wifi-cfg's IP config
/// so the normal apply path (including DHCP client startup) handles it
/// immediately.
pub(crate) fn expand_wifi_cfg_to_connected_phy(
    desired: &mut Interfaces,
    current: &Interfaces,
) {
    let mut extra_ifaces: Vec<Interface> = Vec::new();
    for iface in desired.iter() {
        let Interface::WifiCfg(wifi_cfg) = iface else {
            continue;
        };
        if !wifi_cfg.is_up() {
            continue;
        }
        if wifi_cfg.base_iface().ipv4.is_none()
            && wifi_cfg.base_iface().ipv6.is_none()
        {
            continue;
        }
        let Some(cur_phy) = find_connected_wifi_phy_for_cfg(current, wifi_cfg)
        else {
            continue;
        };
        let phy_name = cur_phy.kernel_iface_name().to_string();
        if desired.kernel_ifaces.contains_key(&phy_name) {
            continue;
        }
        let cur_base = cur_phy.base_iface();
        let mut base = wifi_cfg.base_iface().clone();
        base.name = cur_base.name.clone();
        base.kernel_iface_name = cur_base.kernel_iface_name.clone();
        base.iface_type = InterfaceType::WifiPhy;
        base.state = InterfaceState::Up;
        // Copy the identifier from the current kernel interface so the
        // synthetic desired interface matches the same saved config (e.g. a
        // MAC-identified wifi-phy) instead of clobbering it on save.
        base.identifier = Some(InterfaceIdentifier::MacAddress);
        base.mac_address = cur_base.mac_address.clone();
        base.permanent_mac_address = None;
        if base.profile_name.is_none() {
            base.profile_name = cur_base.profile_name.clone();
        }
        log::debug!(
            "Expanding wifi-cfg {}/{} IP config to connected wifi-phy {}",
            wifi_cfg.name(),
            wifi_cfg.iface_type(),
            phy_name,
        );
        extra_ifaces.push(base.into());
    }
    for iface in extra_ifaces {
        desired.push(iface);
    }
}

impl MergedInterfaces {
    /// For WIFI bind to any interface, we should mark all suitable wifi-phy up
    pub(crate) fn post_merge_sanitize_wifi(&mut self) {
        let mut phy_names_to_bring_up: HashSet<String> = HashSet::new();
        if self.has_any_bind_wifi() {
            phy_names_to_bring_up.extend(
                self.kernel_ifaces
                    .iter()
                    .filter(|(_, merged_iface)| {
                        merged_iface.merged.iface_type()
                            == &InterfaceType::WifiPhy
                            && merged_iface.current.is_some()
                    })
                    .map(|(name, _)| name.clone()),
            );
        }
        // A `wifi-cfg` with an explicit `base-iface` must also bring its
        // referenced wifi-phy up, otherwise the client starts on a down
        // interface (e.g. after the phy was brought down by a previous
        // apply).
        for merged_iface in self.user_ifaces.values() {
            let Some(Interface::WifiCfg(wifi_cfg)) =
                merged_iface.for_apply.as_ref()
            else {
                continue;
            };
            if !wifi_cfg.is_up() {
                continue;
            }
            let Some(base_iface) =
                wifi_cfg.wifi.as_ref().and_then(|w| w.base_iface.as_deref())
            else {
                continue;
            };
            let phy_name = self
                .iface_search
                .search_name(base_iface)
                .unwrap_or_else(|| base_iface.to_string());
            phy_names_to_bring_up.insert(phy_name);
        }

        if phy_names_to_bring_up.is_empty() {
            return;
        }
        for merged_iface in
            self.kernel_ifaces.values_mut().filter(|merged_iface| {
                merged_iface.merged.iface_type() == &InterfaceType::WifiPhy
                    && merged_iface
                        .desired
                        .as_ref()
                        .map(|i| i.is_absent() || i.is_down() || i.is_ignore())
                        != Some(true)
                    && merged_iface.current.is_some()
                    && phy_names_to_bring_up
                        .contains(merged_iface.merged.kernel_iface_name())
            })
        {
            merged_iface.mark_as_changed();
            if let Some(iface) = merged_iface.for_apply.as_mut() {
                iface.base_iface_mut().state = InterfaceState::Up;
            }
        }
    }

    pub(crate) fn has_any_bind_wifi(&self) -> bool {
        self.user_ifaces.values().any(|merged_iface| {
            if let Some(Interface::WifiCfg(iface)) =
                merged_iface.for_apply.as_ref()
                && iface.is_up()
                && iface.wifi.as_ref().map(|w| w.base_iface.is_none())
                    == Some(true)
            {
                true
            } else {
                false
            }
        })
    }
}

#[cfg(test)]
mod tests {
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
            desired.user_ifaces.contains_key(&(
                "HomeWiFi".to_string(),
                InterfaceType::WifiCfg
            ))
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
}
