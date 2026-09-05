// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use nipart::{
    ErrorKind, Interface, InterfaceState, InterfaceType, NetworkState,
    NipartError, NipartInterface, NipartIpcConnection, NipartNoDaemon,
    NipartQueryOption, RouteEntry, RouteRuleEntry, RouteState,
};

use super::commander::NipartCommander;

impl NipartCommander {
    pub(crate) async fn query_network_state(
        &mut self,
        mut conn: Option<&mut NipartIpcConnection>,
        opt: NipartQueryOption,
    ) -> Result<NetworkState, NipartError> {
        if let Some(conn) = conn.as_mut() {
            conn.log_debug(format!("querying network state with option {opt}"))
                .await;
        } else {
            log::debug!("querying network state with option {opt}");
        }
        match (opt.running, opt.saved) {
            (true, false) => self.query_running_state(opt).await,
            (false, true) => self.query_saved_state(opt).await,
            (true, true) => self.query_running_and_saved_state(opt).await,
            (false, false) => Err(NipartError::new(
                ErrorKind::InvalidArgument,
                "Query option must enable `running` or `saved`".to_string(),
            )),
        }
    }

    /// Kernel interfaces plus activated saved profiles. Saved-only profiles
    /// are not included.
    async fn query_running_state(
        &mut self,
        opt: NipartQueryOption,
    ) -> Result<NetworkState, NipartError> {
        let mut net_state = self.query_kernel_state(&opt).await?;
        let mut saved_state = self.conf_manager.query_state().await?;
        merge_saved_into_running(
            &mut net_state,
            &mut saved_state,
            &mut HashSet::new(),
        );
        self.fill_dhcp_states(&mut net_state).await?;
        if !opt.include_secrets {
            net_state.hide_secrets();
        }
        Ok(net_state)
    }

    /// Saved profiles only: activated ones are marked `state: up`, inactive
    /// ones `state: saved`.
    async fn query_saved_state(
        &mut self,
        opt: NipartQueryOption,
    ) -> Result<NetworkState, NipartError> {
        let mut state = self.conf_manager.query_state().await?;
        let cur_state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;
        for iface in state.ifaces.iter_mut() {
            if iface.is_userspace() || iface.is_absent() {
                continue;
            }
            iface.base_iface_mut().state =
                if saved_iface_has_kernel_match(iface, &cur_state) {
                    InterfaceState::Up
                } else {
                    InterfaceState::Saved
                };
        }
        if !opt.include_secrets {
            state.hide_secrets();
        }
        Ok(state)
    }

    /// Combined view: activated profiles as `state: up`, inactive profiles
    /// as `state: saved`, kernel interfaces not managed by nipart as
    /// `state: ignore`.
    async fn query_running_and_saved_state(
        &mut self,
        opt: NipartQueryOption,
    ) -> Result<NetworkState, NipartError> {
        let mut net_state = self.query_kernel_state(&opt).await?;
        let mut saved_state = self.conf_manager.query_state().await?;
        let mut managed_ifaces: HashSet<String> = HashSet::new();
        let saved_only_ifaces = merge_saved_into_running(
            &mut net_state,
            &mut saved_state,
            &mut managed_ifaces,
        );

        for iface in net_state.ifaces.kernel_ifaces.values_mut() {
            iface.base_iface_mut().state =
                if managed_ifaces.contains(iface.kernel_iface_name()) {
                    InterfaceState::Up
                } else {
                    InterfaceState::Ignore
                };
        }

        // Inactive saved profiles, marked `state: saved`.
        let saved_only_names: HashSet<String> = saved_only_ifaces
            .iter()
            .flat_map(|i| [i.kernel_iface_name(), i.name()])
            .map(|name| name.to_string())
            .collect();
        for saved_iface in saved_only_ifaces {
            net_state.ifaces.push(saved_iface);
        }
        append_saved_only_routes(
            &mut net_state,
            &saved_state,
            &saved_only_names,
        );
        append_saved_only_route_rules(&mut net_state, &saved_state);

        self.fill_dhcp_states(&mut net_state).await?;
        if !opt.include_secrets {
            net_state.hide_secrets();
        }
        Ok(net_state)
    }

    async fn query_kernel_state(
        &mut self,
        opt: &NipartQueryOption,
    ) -> Result<NetworkState, NipartError> {
        let mut net_state =
            NipartNoDaemon::query_network_state(opt.clone()).await?;

        let plugins_net_states = self
            .plugin_manager
            .query_network_state(opt.clone(), &net_state)
            .await?;

        for plugins_net_state in plugins_net_states {
            net_state.merge(&plugins_net_state)?;
        }
        Ok(net_state)
    }

    async fn fill_dhcp_states(
        &mut self,
        net_state: &mut NetworkState,
    ) -> Result<(), NipartError> {
        self.dhcpv4_manager.fill_dhcp_states(net_state).await?;
        self.dhcpv6_manager.fill_dhcp_states(net_state).await?;
        Ok(())
    }
}

/// Merge saved config properties which cannot be queried from kernel state
/// into matching kernel interfaces:
///  * `auto-connect`: daemon-only config stored in conf_manager.
///  * `profile-name`: the logical name of the saved config managing this kernel
///    interface.
///  * `description`: save-only description.
///
/// Saved configs without a kernel match are returned, already marked
/// `state: saved`. The names of matched kernel interfaces are recorded in
/// `managed_ifaces`.
fn merge_saved_into_running(
    net_state: &mut NetworkState,
    saved_state: &mut NetworkState,
    managed_ifaces: &mut HashSet<String>,
) -> Vec<Interface> {
    // Load user space from conf_manager
    for (_, iface) in saved_state.ifaces.user_ifaces.drain() {
        if iface.iface_type() == &InterfaceType::WifiCfg {
            net_state.ifaces.push(iface);
        }
    }

    let mut saved_only_ifaces: Vec<Interface> = Vec::new();
    for (_, mut saved_iface) in saved_state.ifaces.kernel_ifaces.drain() {
        // The saved config of `identifier: mac-address` interface holds no
        // `kernel-iface-name`(keyed by profile name), hence search by MAC
        // address match.
        let cur_iface = if saved_iface.is_name_matching() {
            net_state
                .ifaces
                .kernel_ifaces
                .get_mut(saved_iface.kernel_iface_name())
        } else {
            net_state
                .ifaces
                .kernel_ifaces
                .values_mut()
                .find(|cur_iface| saved_iface.is_match(cur_iface))
        };
        let Some(cur_iface) = cur_iface else {
            saved_iface.base_iface_mut().state = InterfaceState::Saved;
            saved_only_ifaces.push(saved_iface);
            continue;
        };
        managed_ifaces.insert(cur_iface.kernel_iface_name().to_string());
        // Multiple saved configs may resolve to the same running interface
        // (e.g. a name-matched and a MAC-matched config for the same NIC),
        // and the `drain()` order is nondeterministic. Only fill missing
        // values so a `None` never clobbers a set one.
        if let Some(auto_connect) =
            saved_iface.base_iface_mut().auto_connect.take()
            && cur_iface.base_iface().auto_connect.is_none()
        {
            cur_iface.base_iface_mut().auto_connect = Some(auto_connect);
        }
        if let Some(profile_name) =
            saved_iface.base_iface().profile_name.as_ref()
            && cur_iface.base_iface().profile_name.is_none()
        {
            cur_iface.base_iface_mut().profile_name =
                Some(profile_name.clone());
        }
        if let Some(description) = saved_iface.base_iface().description.as_ref()
            && cur_iface.base_iface().description.is_none()
        {
            cur_iface.base_iface_mut().description = Some(description.clone());
        }
    }
    saved_only_ifaces
}

/// Saved-only routes: routes explicitly persisted with `state: saved`, or
/// routes of saved-only profiles. Mark them `state: saved` and avoid
/// duplicating routes already present in the kernel config.
fn append_saved_only_routes(
    net_state: &mut NetworkState,
    saved_state: &NetworkState,
    saved_only_names: &HashSet<String>,
) {
    if let Some(saved_rts) = saved_state.routes.config.as_ref() {
        let kernel_rts = net_state.routes.config.as_deref();
        let mut saved_only_rts: Vec<RouteEntry> = Vec::new();
        for rt in saved_rts.iter().filter(|rt| !rt.is_absent()) {
            let via_saved_only = rt
                .next_hop_iface
                .as_deref()
                .is_some_and(|name| saved_only_names.contains(name));
            if !rt.is_saved() && !via_saved_only {
                continue;
            }
            if kernel_rts
                .is_some_and(|rts| rts.iter().any(|krt| krt.is_match(rt)))
            {
                continue;
            }
            let mut saved_only_rt = rt.clone();
            saved_only_rt.state = Some(RouteState::Saved);
            saved_only_rts.push(saved_only_rt);
        }
        if !saved_only_rts.is_empty() {
            let mut config_rts =
                net_state.routes.config.take().unwrap_or_default();
            config_rts.extend(saved_only_rts);
            net_state.routes.config = Some(config_rts);
        }
    }
}

/// Append saved route rules which are not currently present in the kernel.
/// Route rules have no `state: saved`, but a rule whose `iif` interface is
/// not present must still be visible in the running-and-saved view so it is
/// not silently lost from the output.
fn append_saved_only_route_rules(
    net_state: &mut NetworkState,
    saved_state: &NetworkState,
) {
    let Some(saved_rules) = saved_state.route_rules.config.as_ref() else {
        return;
    };
    let kernel_rules = net_state.route_rules.config.as_deref();
    let mut pending_rules: Vec<RouteRuleEntry> = Vec::new();
    for rule in saved_rules.iter().filter(|rule| !rule.is_absent()) {
        let mut rule = rule.clone();
        if rule.action.is_none() && rule.table_id.is_none() {
            rule.table_id = Some(RouteRuleEntry::DEFAULT_ROUTE_TABLE_ID);
        }
        if kernel_rules
            .is_some_and(|rules| rules.iter().any(|cur| rule.is_match(cur)))
        {
            continue;
        }
        pending_rules.push(rule);
    }
    if !pending_rules.is_empty() {
        let mut config_rules =
            net_state.route_rules.config.take().unwrap_or_default();
        config_rules.extend(pending_rules);
        net_state.route_rules.config = Some(config_rules);
    }
}

fn saved_iface_has_kernel_match(
    saved_iface: &Interface,
    cur_state: &NetworkState,
) -> bool {
    if saved_iface.is_name_matching() {
        cur_state
            .ifaces
            .kernel_ifaces
            .contains_key(saved_iface.kernel_iface_name())
    } else {
        cur_state
            .ifaces
            .kernel_ifaces
            .values()
            .any(|cur_iface| saved_iface.is_match(cur_iface))
    }
}

#[cfg(test)]
mod tests {
    use nipart::NetworkState;

    use super::append_saved_only_route_rules;

    #[test]
    fn test_saved_route_rule_without_priority_not_duplicated() {
        let mut net_state: NetworkState = rmsd_yaml::from_str(
            r#"---
            route-rules:
              config:
                - ip-from: 198.51.100.1/32
                  route-table: 254
                  priority: 30000
            "#,
        )
        .unwrap();
        let saved_state: NetworkState = rmsd_yaml::from_str(
            r#"---
            route-rules:
              config:
                - ip-from: 198.51.100.1
            "#,
        )
        .unwrap();

        append_saved_only_route_rules(&mut net_state, &saved_state);

        let rules = net_state.route_rules.config.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].priority, Some(30000));
    }

    #[test]
    fn test_saved_default_table_rule_not_matched_by_action_rule() {
        let mut net_state: NetworkState = rmsd_yaml::from_str(
            r#"---
            route-rules:
              config:
                - ip-from: 198.51.100.1/32
                  action: blackhole
                  priority: 30000
            "#,
        )
        .unwrap();
        let saved_state: NetworkState = rmsd_yaml::from_str(
            r#"---
            route-rules:
              config:
                - ip-from: 198.51.100.1
            "#,
        )
        .unwrap();

        append_saved_only_route_rules(&mut net_state, &saved_state);

        let rules = net_state.route_rules.config.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].ip_from.as_deref(), Some("198.51.100.1"));
        assert_eq!(rules[1].table_id, Some(254));
    }
}
