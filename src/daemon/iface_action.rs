// SPDX-License-Identifier: Apache-2.0

use nipart::{
    ErrorKind, Interface, InterfaceIpv4, InterfaceIpv6, InterfaceState,
    InterfaceType, NetworkState, NipartApplyOption, NipartError,
    NipartInterface, RouteEntry, RouteRuleEntry, RouteRuleState, RouteState,
};

use super::commander::NipartCommander;

impl NipartCommander {
    /// Bring an interface or saved profile up.
    ///
    /// The full saved config is applied with `memory-only` so the persisted
    /// state is untouched, and the `force` apply option restarts DHCP and
    /// WIFI even when the kernel state already matches the saved config.
    pub(crate) async fn up_interface(
        &mut self,
        name: &str,
    ) -> Result<NetworkState, NipartError> {
        let saved_state = self.conf_manager.query_state().await?;
        let saved_iface =
            find_saved_iface(&saved_state, name).ok_or_else(|| {
                NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "No interface or profile '{name}' found in saved state"
                    ),
                )
            })?;
        log::info!(
            "Bringing interface {}/{} up",
            saved_iface.name(),
            saved_iface.iface_type()
        );

        // An earlier `npt down` only kept the interface down in memory;
        // explicit `npt up` must release that marker so link events can
        // manage the saved profile again.
        self.monitor_manager
            .clear_explicitly_down(saved_iface)
            .await?;

        let desired_state = gen_state_for_up(saved_iface, &saved_state);
        let opt = NipartApplyOption::new().memory_only().force();
        self.apply_network_state_with_saved_config(
            None,
            desired_state,
            opt,
            None,
        )
        .await
    }

    /// Bring an interface or saved profile down.
    ///
    /// A `wifi-cfg` profile is removed from the live shuli network list while
    /// the remaining saved wifi profiles stay eligible. Other virtual
    /// interfaces are deleted from the kernel; non-virtual interfaces are
    /// set down with their IP stack and routes purged. The persisted saved
    /// state is not modified (`memory-only`).
    pub(crate) async fn down_interface(
        &mut self,
        name: &str,
    ) -> Result<NetworkState, NipartError> {
        let saved_state = self.conf_manager.query_state().await?;
        let (desired_state, marked_iface) =
            if let Some(saved_iface) = find_saved_iface(&saved_state, name) {
                log::info!(
                    "Bringing interface {}/{} down",
                    saved_iface.name(),
                    saved_iface.iface_type()
                );
                (
                    gen_state_for_down(saved_iface, &saved_state),
                    Some(saved_iface.clone()),
                )
            } else {
                // No saved profile: allow bringing down a live kernel interface
                // by its kernel name.
                let cur_state =
                    self.query_network_state(None, Default::default()).await?;
                let cur_iface = cur_state
                    .ifaces
                    .iter()
                    .find(|iface| iface_matches_name(iface, name))
                    .cloned()
                    .ok_or_else(|| {
                        NipartError::new(
                            ErrorKind::InvalidArgument,
                            format!(
                                "No interface or profile '{name}' found in \
                                 saved state or running state"
                            ),
                        )
                    })?;
                log::info!(
                    "Bringing live interface {}/{} down",
                    cur_iface.name(),
                    cur_iface.iface_type()
                );
                (gen_state_for_down_current_only(&cur_iface), Some(cur_iface))
            };

        // Remember the explicit down in the monitor worker before applying:
        // the monitor link dump emitted after the apply must not be sent to
        // the event worker, which would re-apply the saved config and routes.
        if let Some(marked_iface) = marked_iface.as_ref() {
            self.monitor_manager
                .mark_explicitly_down(marked_iface)
                .await?;
        }

        let opt = NipartApplyOption::new().memory_only().force();
        let result = self
            .apply_network_state_with_saved_config(
                None,
                desired_state,
                opt,
                None,
            )
            .await;
        if result.is_err()
            && let Some(marked_iface) = marked_iface.as_ref()
            && let Err(e) = self
                .monitor_manager
                .clear_explicitly_down(marked_iface)
                .await
        {
            log::error!(
                "Failed to clear explicit-down state after failed `npt down`: \
                 {e}"
            );
        }
        result
    }
}

fn find_saved_iface<'a>(
    saved_state: &'a NetworkState,
    name: &str,
) -> Option<&'a Interface> {
    saved_state
        .ifaces
        .iter()
        .find(|iface| iface_matches_name(iface, name))
}

fn iface_matches_name(iface: &Interface, name: &str) -> bool {
    iface.name() == name
        || iface.kernel_iface_name() == name
        || iface.base_iface().profile_name.as_deref() == Some(name)
}

fn gen_state_for_up(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> NetworkState {
    let mut state = NetworkState::default();
    let mut new_iface = saved_iface.clone();
    new_iface.base_iface_mut().state = InterfaceState::Up;
    // An explicit `npt up` overrides conditional activation.
    new_iface.base_iface_mut().auto_connect = None;
    state.ifaces.push(new_iface);

    // A wifi-cfg profile is userspace-only: its IP and routes are applied by
    // the link-event path after shuli associates, not directly here.
    if !saved_iface.is_userspace() {
        let routes = gen_routes_for_iface_up(saved_iface, saved_state);
        if !routes.is_empty() {
            state.routes.config = Some(routes);
        }
        let rules = gen_route_rules_for_iface_up(saved_iface, saved_state);
        if !rules.is_empty() {
            state.route_rules.config = Some(rules);
        }
    }
    state
}

fn gen_state_for_down(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> NetworkState {
    if saved_iface.iface_type() == &InterfaceType::WifiCfg {
        return gen_wifi_cfg_down_state(saved_state, saved_iface);
    }

    let mut state = NetworkState::default();
    let mut new_iface = saved_iface.clone();
    // An explicit `npt down` overrides conditional activation.
    new_iface.base_iface_mut().auto_connect = None;
    new_iface.base_iface_mut().state = if saved_iface.is_virtual() {
        InterfaceState::Absent
    } else {
        InterfaceState::Down
    };
    // Explicitly disable the IP stack so routes are purged and the running
    // addresses are removed together with the link state change.
    new_iface.base_iface_mut().ipv4 = Some(InterfaceIpv4::new_disabled());
    new_iface.base_iface_mut().ipv6 = Some(InterfaceIpv6::new_disabled());
    state.ifaces.push(new_iface);

    let routes = gen_routes_for_iface_down(saved_iface, saved_state);
    if !routes.is_empty() {
        state.routes.config = Some(routes);
    }
    let rules = gen_route_rules_for_iface_down(saved_iface, saved_state);
    if !rules.is_empty() {
        state.route_rules.config = Some(rules);
    }
    state
}

fn gen_state_for_down_current_only(cur_iface: &Interface) -> NetworkState {
    let mut state = NetworkState::default();
    let mut new_iface = cur_iface.clone();
    new_iface.base_iface_mut().auto_connect = None;
    new_iface.base_iface_mut().state = if cur_iface.is_virtual() {
        InterfaceState::Absent
    } else {
        InterfaceState::Down
    };
    new_iface.base_iface_mut().ipv4 = Some(InterfaceIpv4::new_disabled());
    new_iface.base_iface_mut().ipv6 = Some(InterfaceIpv6::new_disabled());
    state.ifaces.push(new_iface);
    state
}

/// Keep every saved wifi profile on the live list except the target one.
/// shuli then picks the strongest remaining SSID, and if none remain the
/// client disconnects.
fn gen_wifi_cfg_down_state(
    saved_state: &NetworkState,
    target: &Interface,
) -> NetworkState {
    let mut state = NetworkState::default();
    for saved_iface in saved_state
        .ifaces
        .iter()
        .filter(|iface| iface.iface_type() == &InterfaceType::WifiCfg)
    {
        let mut new_iface = saved_iface.clone();
        new_iface.base_iface_mut().auto_connect = None;
        new_iface.base_iface_mut().state =
            if same_saved_iface(saved_iface, target) {
                InterfaceState::Down
            } else {
                InterfaceState::Up
            };
        state.ifaces.push(new_iface);
    }
    state
}

fn same_saved_iface(a: &Interface, b: &Interface) -> bool {
    if a.name() == b.name()
        || (!a.kernel_iface_name().is_empty()
            && a.kernel_iface_name() == b.kernel_iface_name())
    {
        return true;
    }
    matches!(
        (
            a.base_iface().profile_name.as_deref(),
            b.base_iface().profile_name.as_deref(),
        ),
        (Some(a_name), Some(b_name)) if a_name == b_name
    )
}

fn gen_routes_for_iface_up(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> Vec<RouteEntry> {
    let mut ret_routes = Vec::new();
    if let Some(config_rts) = saved_state.routes.config.as_ref() {
        for rt in config_rts
            .iter()
            .filter(|rt| is_route_matching_iface(rt, saved_iface))
        {
            ret_routes.push(rt.clone());
        }
    }
    ret_routes
}

fn gen_routes_for_iface_down(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> Vec<RouteEntry> {
    let mut ret_routes = Vec::new();
    if let Some(config_rts) = saved_state.routes.config.as_ref() {
        for rt in config_rts
            .iter()
            .filter(|rt| is_route_matching_iface(rt, saved_iface))
        {
            let mut new_route = rt.clone();
            new_route.state = Some(RouteState::Absent);
            ret_routes.push(new_route);
        }
    }
    ret_routes
}

fn gen_route_rules_for_iface_up(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> Vec<RouteRuleEntry> {
    let mut ret_rules = Vec::new();
    if let Some(config_rules) = saved_state.route_rules.config.as_ref() {
        for rule in config_rules
            .iter()
            .filter(|rule| is_route_rule_matching_iface(rule, saved_iface))
        {
            ret_rules.push(rule.clone());
        }
    }
    ret_rules
}

fn gen_route_rules_for_iface_down(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> Vec<RouteRuleEntry> {
    let mut ret_rules = Vec::new();
    if let Some(config_rules) = saved_state.route_rules.config.as_ref() {
        for rule in config_rules
            .iter()
            .filter(|rule| is_route_rule_matching_iface(rule, saved_iface))
        {
            let mut new_rule = rule.clone();
            new_rule.state = Some(RouteRuleState::Absent);
            ret_rules.push(new_rule);
        }
    }
    ret_rules
}

fn is_route_rule_matching_iface(
    rule: &RouteRuleEntry,
    iface: &Interface,
) -> bool {
    let Some(iif) = rule.iif.as_deref() else {
        return false;
    };
    iif == iface.kernel_iface_name()
        || iif == iface.name()
        || iface.base_iface().profile_name.as_deref() == Some(iif)
}

fn is_route_matching_iface(rt: &RouteEntry, iface: &Interface) -> bool {
    let Some(next_hop_iface) = rt.next_hop_iface.as_deref() else {
        return false;
    };
    next_hop_iface == iface.kernel_iface_name()
        || next_hop_iface == iface.name()
        || iface.base_iface().profile_name.as_deref() == Some(next_hop_iface)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved_state() -> NetworkState {
        rmsd_yaml::from_str(
            r#"---
            routes:
              config:
                - destination: 0.0.0.0/0
                  next-hop-interface: eth0
            route-rules:
              config:
                - ip-from: 198.51.100.0/24
                  route-table: 500
                  iif: eth0
            interfaces:
              - name: eth0
                type: ethernet
                state: up
                ipv4:
                  enabled: true
                  dhcp: true
              - name: HomeWiFi
                type: wifi-cfg
                state: up
                wifi:
                  ssid: HomeWiFi
                  base-iface: wlan0
              - name: GuestWiFi
                type: wifi-cfg
                state: up
                wifi:
                  ssid: GuestWiFi
                  base-iface: wlan0
            "#,
        )
        .unwrap()
    }

    #[test]
    fn test_find_saved_iface_by_name_and_profile() {
        let state = saved_state();
        assert_eq!(
            find_saved_iface(&state, "eth0").unwrap().iface_type(),
            &InterfaceType::Ethernet
        );
        assert_eq!(
            find_saved_iface(&state, "HomeWiFi").unwrap().iface_type(),
            &InterfaceType::WifiCfg
        );
        assert!(find_saved_iface(&state, "missing").is_none());
    }

    #[test]
    fn test_up_state_keeps_routes_and_marks_up() {
        let state = saved_state();
        let iface = find_saved_iface(&state, "eth0").unwrap();
        let desired = gen_state_for_up(iface, &state);
        assert_eq!(
            desired.ifaces.iter().next().unwrap().base_iface().state,
            InterfaceState::Up
        );
        assert_eq!(
            desired
                .routes
                .config
                .as_ref()
                .unwrap()
                .iter()
                .filter(|rt| !rt.is_absent())
                .count(),
            1
        );
        assert_eq!(
            desired
                .route_rules
                .config
                .as_ref()
                .unwrap()
                .iter()
                .filter(|rule| !rule.is_absent())
                .count(),
            1
        );
    }

    #[test]
    fn test_wifi_down_state_keeps_other_profiles_up() {
        let state = saved_state();
        let target = find_saved_iface(&state, "HomeWiFi").unwrap();
        let desired = gen_wifi_cfg_down_state(&state, target);
        let ifaces: Vec<_> = desired.ifaces.iter().collect();
        assert_eq!(ifaces.len(), 2);
        let home = ifaces
            .iter()
            .find(|iface| iface.name() == "HomeWiFi")
            .unwrap();
        let guest = ifaces
            .iter()
            .find(|iface| iface.name() == "GuestWiFi")
            .unwrap();
        assert!(home.is_down());
        assert!(guest.is_up());
    }

    #[test]
    fn test_down_virtual_uses_absent_and_nonvirtual_uses_down() {
        let state: NetworkState = rmsd_yaml::from_str(
            r#"---
            interfaces:
              - name: dummy0
                type: dummy
                state: up
              - name: eth0
                type: ethernet
                state: up
            "#,
        )
        .unwrap();
        let dummy = find_saved_iface(&state, "dummy0").unwrap();
        let eth0 = find_saved_iface(&state, "eth0").unwrap();
        assert!(
            gen_state_for_down(dummy, &state)
                .ifaces
                .iter()
                .next()
                .unwrap()
                .is_absent()
        );
        assert!(
            gen_state_for_down(eth0, &state)
                .ifaces
                .iter()
                .next()
                .unwrap()
                .is_down()
        );
    }

    #[test]
    fn test_down_marks_matching_route_rules_absent() {
        let state: NetworkState = rmsd_yaml::from_str(
            r#"---
            interfaces:
              - name: dummy0
                type: dummy
                state: up
            route-rules:
              config:
                - ip-from: 198.51.100.0/24
                  route-table: 500
                  iif: dummy0
            "#,
        )
        .unwrap();
        let dummy = find_saved_iface(&state, "dummy0").unwrap();
        let desired = gen_state_for_down(dummy, &state);
        let rules = desired.route_rules.config.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].is_absent());
        assert_eq!(rules[0].iif.as_deref(), Some("dummy0"));
    }
}
