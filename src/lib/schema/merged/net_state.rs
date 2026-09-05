// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{
    InterfaceType, JsonDisplayHideSecrets, MergedInterfaces, MergedRouteRules,
    MergedRoutes, NetworkState, NipartApplyOption, NipartError,
    NipartInterface, NipartWaitOnline,
};

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Deserialize,
    Serialize,
    JsonDisplayHideSecrets,
)]
#[non_exhaustive]
pub struct MergedNetworkState {
    pub version: Option<u32>,
    pub description: Option<String>,
    pub ifaces: MergedInterfaces,
    pub routes: MergedRoutes,
    pub route_rules: MergedRouteRules,
    pub wait_online: NipartWaitOnline,
    pub option: NipartApplyOption,
    pub desired: NetworkState,
}

impl MergedNetworkState {
    pub fn new(
        desired: NetworkState,
        current: NetworkState,
        saved_config: Option<NetworkState>,
        option: NipartApplyOption,
    ) -> Result<Self, NipartError> {
        let desired_clone = desired.clone();

        let (saved_ifaces, saved_routes, saved_route_rules) = match saved_config
        {
            Some(c) => (Some(c.ifaces), Some(c.routes), Some(c.route_rules)),
            None => (None, None, None),
        };

        let merged_ifaces = MergedInterfaces::new_with_force(
            desired.ifaces,
            current.ifaces,
            saved_ifaces,
            option.force,
        )?;
        let merged_routes = MergedRoutes::new(
            desired.routes,
            current.routes,
            saved_routes,
            &merged_ifaces,
        )?;
        let mut merged_route_rules = MergedRouteRules::new(
            desired.route_rules,
            current.route_rules,
            saved_route_rules,
        )?;
        let ignored_ifaces: Vec<&str> = merged_ifaces
            .kernel_ifaces
            .values()
            .filter(|merged_iface| merged_iface.merged.is_ignore())
            .map(|merged_iface| merged_iface.merged.kernel_iface_name())
            .collect();
        if !ignored_ifaces.is_empty() {
            merged_route_rules.remove_rules_to_ignored_ifaces(&ignored_ifaces);
        }

        Ok(Self {
            version: desired.version,
            description: desired.description.clone(),
            ifaces: merged_ifaces,
            routes: merged_routes,
            route_rules: merged_route_rules,
            wait_online: desired
                .wait_online
                .or(current.wait_online)
                .unwrap_or_default(),
            option,
            desired: desired_clone,
        })
    }

    pub fn verify(&self, current: &NetworkState) -> Result<(), NipartError> {
        self.ifaces.verify(&current.ifaces)?;
        self.route_rules.verify(&current.route_rules)
    }

    /// Generate a NetworkState with desired and impact changes only.
    pub fn gen_state_for_apply(&self) -> NetworkState {
        NetworkState {
            ifaces: self.ifaces.gen_state_for_apply(),
            routes: self.routes.gen_state_for_apply(),
            route_rules: self.route_rules.gen_state_for_apply(),
            wait_online: self.desired.wait_online.clone(),
            version: self.version,
            description: self.description.clone(),
        }
    }

    /// Generate a NetworkState combined with desired, impacted and previous
    /// stored state.
    pub fn gen_state_for_save(&self) -> NetworkState {
        NetworkState {
            ifaces: self.ifaces.gen_state_for_save(),
            routes: self.routes.gen_state_for_save(),
            route_rules: self.route_rules.gen_state_for_save(),
            wait_online: self.desired.wait_online.clone(),
            version: self.version,
            description: self.description.clone(),
        }
    }

    pub fn hide_secrets(&mut self) {
        self.ifaces.hide_secrets()
    }

    /// Retains interface which can be bring up in `MergedInterfaces`
    pub fn remove_conditional_activation(&mut self) {
        // Hold conditional activation interface which is not ready to up yet
        let mut pending_changes: Vec<(String, InterfaceType)> = Vec::new();
        for merged_iface in self.ifaces.iter().filter(|i| i.for_apply.is_some())
        {
            if merged_iface.merged.is_up()
                && !merged_iface.can_bring_up(&self.ifaces)
            {
                pending_changes.push((
                    merged_iface.merged.kernel_iface_name().to_string(),
                    merged_iface.merged.iface_type().clone(),
                ));
            }
        }
        for (iface_name, iface_type) in &pending_changes {
            log::trace!(
                "Interface {}/{} is ignored for instant apply because its \
                 auto-connect condition is not met yet",
                iface_name,
                iface_type
            );
            if iface_type.is_userspace() {
                self.ifaces
                    .user_ifaces
                    .remove(&(iface_name.clone(), iface_type.clone()));
            } else {
                self.routes.route_changed_ifaces.retain(|n| n != iface_name);
                self.routes.changed_routes.retain(|rt| {
                    rt.next_hop_iface.as_ref() != Some(iface_name)
                });
                self.route_rules
                    .changed_rules
                    .retain(|rule| rule.iif.as_deref() != Some(iface_name));
                if let Some(config_rules) =
                    self.route_rules.desired.config.as_mut()
                {
                    config_rules
                        .retain(|rule| rule.iif.as_deref() != Some(iface_name));
                }
                if let Some(config_rts) = self.routes.desired.config.as_mut() {
                    config_rts.retain(|rt| {
                        rt.next_hop_iface.as_ref() != Some(iface_name)
                    });
                }
                self.ifaces.kernel_ifaces.remove(iface_name);
            }
        }
    }
}

impl NetworkState {
    pub fn merge(&mut self, new_state: &Self) -> Result<(), NipartError> {
        self.version = new_state.version.or(self.version);
        self.description = new_state
            .description
            .clone()
            .or_else(|| self.description.clone());
        self.routes = self.routes.merge(&new_state.routes)?;
        self.route_rules = self.route_rules.merge(&new_state.route_rules)?;
        self.ifaces.merge(&new_state.ifaces)?;
        self.wait_online =
            new_state.wait_online.clone().or(self.wait_online.clone());
        Ok(())
    }
}
