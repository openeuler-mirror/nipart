// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use super::super::value::copy_undefined_value;
use crate::{
    ErrorKind, Interface, InterfaceIdentifier, InterfaceIpv4, InterfaceIpv6,
    InterfaceState, InterfaceType, JsonDisplay, MergedInterfaces, NipartError,
    NipartInterface,
};

#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonDisplay,
)]
#[non_exhaustive]
pub struct MergedInterface {
    pub desired: Option<Interface>,
    pub current: Option<Interface>,
    /// Merged interface configuration with desired and current.
    pub merged: Interface,
    /// Interface configuration for apply action. It contains:
    ///  * impacted changes
    ///  * desired changes
    pub for_apply: Option<Interface>,
    /// Interface configuration for verification action.
    pub for_verify: Option<Interface>,
    /// Interface configuration for saving to disk. It contains:
    ///  * impacted changes
    ///  * desired changes
    ///  * previous saved changes
    pub for_save: Option<Interface>,
    /// If desired is defined, for_revert holds the state to revert the changes
    /// made by for_apply.
    pub for_revert: Option<Interface>,
    /// In which order should this interface been activated. The smallest
    /// number will be activated first.
    /// For undesired interface up_priority is None
    /// For desired interface, up_priority None means don't know activation
    /// order yet.
    /// This should be set by MergedInterfaces::new().
    pub up_priority: Option<u32>,
    /// Whether this up interface will be deleted and recreated during
    /// apply (e.g. VLAN ID change). Routes on this interface will be
    /// purged by the kernel when the interface is deleted.
    #[serde(default)]
    pub will_delete: bool,
}

impl MergedInterface {
    pub fn new(
        desired: Option<Interface>,
        current: Option<Interface>,
        saved: Option<Interface>,
        force: bool,
    ) -> Result<Self, NipartError> {
        let saved = saved.as_ref();
        let saved_only = desired
            .as_ref()
            .is_some_and(|d| d.base_iface().state.is_saved());
        let for_save = if let Some(desired) = desired.as_ref() {
            if let Some(saved) = saved {
                Some(saved.merge(desired)?)
            } else {
                Some(desired.clone())
            }
        } else {
            saved.cloned()
        };

        // We cannot use for_save as for_verify, because the kernel_iface_name
        // been resolved. We use original desired state.
        // `description` is save-only, so it is never part of verification.
        let mut for_verify = desired.clone();
        if let Some(for_verify) = for_verify.as_mut() {
            for_verify.base_iface_mut().description = None;
        }

        // We only apply changed properties
        let for_apply = if let Some(current) = current.as_ref()
            && let Some(for_save) = for_save.as_ref()
        {
            if force {
                Some(for_save.clone())
            } else {
                for_save.gen_diff_for_apply(current)?
            }
        } else if desired.is_some() {
            for_save.clone()
        } else {
            // not desired but have saved config, no touch
            None
        };
        // We don't process merged and for_revert state yet, it need to be done
        // after interface sensitization finished.
        let merged = match (desired.as_ref(), current.as_ref()) {
            (Some(desired), Some(current)) => current.merge(desired)?,
            (None, Some(current)) => current.clone(),
            (Some(desired), None) => desired.clone(),
            (None, None) => Interface::default(),
        };

        let mut ret = Self {
            for_apply,
            for_verify,
            desired,
            current,
            merged,
            for_save,
            for_revert: None,
            up_priority: None,
            will_delete: false,
        };

        ret.sanitize(saved)?;

        if saved_only {
            // `state: saved` requests save-only: the config is persisted but
            // nothing is applied to kernel, verified or reverted.
            ret.for_apply = None;
            ret.for_verify = None;
            ret.for_revert = None;
            if let Some(for_save) = ret.for_save.as_mut() {
                // `state: saved` is not a persistent state: keep the
                // previous saved state (or default to up) so the profile
                // can be activated later.
                for_save.base_iface_mut().state = saved
                    .map(|s| s.base_iface().state)
                    .unwrap_or(InterfaceState::Up);
            }
        }

        Ok(ret)
    }

    /// Only sanitize desired interfaces:
    /// * Validate user's input
    /// * Unify the IP address or MAC address format, and etc
    /// * Fill for_apply with real kernel interface name
    /// * Generate `merged` state
    /// * Generate `for_revert` state
    fn sanitize(
        &mut self,
        saved: Option<&Interface>,
    ) -> Result<(), NipartError> {
        if let Some(desired) = self.desired.as_mut()
            && let Some(for_apply) = self.for_apply.as_mut()
            && let Some(for_save) = self.for_save.as_mut()
            && let Some(for_verify) = self.for_verify.as_mut()
        {
            desired.base_iface_mut().sanitize(
                self.current.as_ref().map(|i| i.base_iface()),
                saved.map(|i| i.base_iface()),
                for_save.base_iface_mut(),
                for_apply.base_iface_mut(),
                for_verify.base_iface_mut(),
                self.merged.base_iface_mut(),
            )?;
            // Use `for_apply` (cloned from current via gen_diff) for
            // the virtual check: the desired absent state may lack
            // type-specific sections (e.g. veth), but `for_apply`
            // retains them from the current kernel state.
            if for_apply.is_absent() && !for_apply.is_virtual() {
                for_apply.base_iface_mut().state = InterfaceState::Down;
            }
            desired.sanitize(
                self.current.as_ref(),
                for_save,
                for_apply,
                for_verify,
                &mut self.merged,
            )?;
            // The `mark_as_changed()` will handle `for_apply`, `for_revert`
            // for undesired but impacted interface.
            if let Some(for_apply) = self.for_apply.as_mut() {
                self.for_revert =
                    for_apply.generate_revert(self.current.as_ref())?;
            } else {
                return Err(NipartError::new(
                    ErrorKind::Bug,
                    format!("for_apply is None but desired: {self}"),
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn is_userspace(&self) -> bool {
        self.merged.is_userspace()
    }

    pub(crate) fn name(&self) -> &str {
        self.merged.name()
    }

    pub(crate) fn iface_type(&self) -> &InterfaceType {
        self.merged.iface_type()
    }

    pub(crate) fn kernel_iface_name(&self) -> &str {
        self.merged.kernel_iface_name()
    }

    pub(crate) fn is_desired(&self) -> bool {
        self.desired.is_some()
    }

    pub fn is_changed(&self) -> bool {
        self.for_apply.is_some()
    }

    pub(crate) fn will_delete_before_apply(&self) -> bool {
        self.for_apply
            .as_ref()
            .zip(self.current.as_ref())
            .is_some_and(|(for_apply, current)| {
                Interface::need_delete_before_change(for_apply, current)
            })
    }

    pub fn is_absent(&self) -> bool {
        self.for_apply.as_ref().map(|i| i.is_absent()) == Some(true)
    }

    pub fn hide_secrets(&mut self) {
        for s in [
            self.desired.as_mut(),
            self.current.as_mut(),
            Some(&mut self.merged),
            self.for_apply.as_mut(),
            self.for_verify.as_mut(),
            self.for_save.as_mut(),
            self.for_revert.as_mut(),
        ]
        .iter_mut()
        .flatten()
        {
            s.hide_secrets();
        }
    }

    pub fn mark_as_changed(&mut self) {
        self.for_apply = self.current.as_ref().map(|iface| {
            Interface::from(iface.base_iface().clone_name_type_only())
        });
    }

    pub(crate) fn apply_ctrller_change(
        &mut self,
        ctrl_name: String,
        ctrl_type: InterfaceType,
        ctrl_state: InterfaceState,
    ) -> Result<(), NipartError> {
        if self.merged.base_iface().need_controller()
            && ctrl_name.is_empty()
            && let Some(org_ctrl) = self
                .current
                .as_ref()
                .and_then(|c| c.base_iface().controller.as_ref())
            && Some(true) == self.for_apply.as_ref().map(|i| i.is_up())
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Interface {} cannot live without controller, but it is \
                     detached from original controller {org_ctrl}, cannot \
                     apply desired `state:up`",
                    self.merged.name()
                ),
            ));
        }

        if !self.is_desired() {
            self.mark_as_changed();
            if ctrl_state == InterfaceState::Up {
                self.merged.base_iface_mut().state = InterfaceState::Up;
                if let Some(apply_iface) = self.for_apply.as_mut() {
                    apply_iface.base_iface_mut().state = InterfaceState::Up;
                }
            }
            log::info!(
                "Include interface {} to edit as its controller required so",
                self.merged.name()
            );
        } else if self.for_apply.is_none() {
            // The desired state did not change this interface, but its
            // controller relation did: the controller just appeared (or its
            // port list changed) and this port must be attached through a
            // minimal diff carrying the controller.
            self.mark_as_changed();
        }
        let Some(apply_iface) = self.for_apply.as_mut() else {
            return Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Reached unreachable code: apply_ctrller_change() \
                     self.for_apply still None: {self:?}"
                ),
            ));
        };

        // Some interface cannot live without controller
        if self.merged.base_iface().need_controller() && ctrl_name.is_empty() {
            if let Some(org_ctrl) = self
                .current
                .as_ref()
                .and_then(|c| c.base_iface().controller.as_ref())
            {
                log::info!(
                    "Interface {} cannot live without controller, marking as \
                     absent as it has been detached from its original \
                     controller {org_ctrl}",
                    self.merged.name(),
                );
            }
            self.merged.base_iface_mut().state = InterfaceState::Absent;
            apply_iface.base_iface_mut().state = InterfaceState::Absent;
            if let Some(verify_iface) = self.for_verify.as_mut() {
                verify_iface.base_iface_mut().state = InterfaceState::Absent;
            }
        } else {
            log::info!(
                "Changing controller of interface {}/{} to: {}/{}",
                apply_iface.name(),
                apply_iface.iface_type(),
                ctrl_name,
                ctrl_type
            );
            apply_iface.base_iface_mut().controller =
                Some(ctrl_name.to_string());
            apply_iface.base_iface_mut().controller_type =
                Some(ctrl_type.clone());
            // MAC address might change after port attached to bond.
            // Remove mac-address from for_verify to avoid false
            // verification errors.
            if ctrl_type == InterfaceType::Bond
                && apply_iface.base_iface().identifier
                    == Some(InterfaceIdentifier::MacAddress)
                && let Some(for_verify) = self.for_verify.as_mut()
            {
                for_verify.base_iface_mut().mac_address = None;
            }
            self.merged.base_iface_mut().controller = Some(ctrl_name);
            self.merged.base_iface_mut().controller_type = Some(ctrl_type);
            if !self.merged.base_iface().can_have_ip() {
                self.merged.base_iface_mut().ipv4 = None;
                self.merged.base_iface_mut().ipv6 = None;
                // The port is attached to a controller which does not allow
                // IP on its ports. When the desired state does not explicitly
                // enable IP (an explicit `ipv4/ipv6.enabled: true` is
                // rejected by `validate_can_have_ip()`), purge the IP from
                // the saved config so the boot restore of the saved state
                // does not fail, and disable it in `for_apply` so the
                // running address is removed as well.
                let desired_ip_enabled =
                    self.desired.as_ref().is_some_and(|desired| {
                        desired
                            .base_iface()
                            .ipv4
                            .as_ref()
                            .and_then(|ipv4| ipv4.enabled)
                            == Some(true)
                            || desired
                                .base_iface()
                                .ipv6
                                .as_ref()
                                .and_then(|ipv6| ipv6.enabled)
                                == Some(true)
                    });
                if !desired_ip_enabled {
                    if let Some(for_save) = self.for_save.as_mut() {
                        for_save.base_iface_mut().ipv4 = None;
                        for_save.base_iface_mut().ipv6 = None;
                    }
                    if let Some(for_apply) = self.for_apply.as_mut() {
                        for_apply.base_iface_mut().ipv4 = Some(InterfaceIpv4 {
                            enabled: Some(false),
                            dhcp: Some(false),
                            ..Default::default()
                        });
                        for_apply.base_iface_mut().ipv6 = Some(InterfaceIpv6 {
                            enabled: Some(false),
                            dhcp: Some(false),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether specified interface can be bring up
    pub(crate) fn can_bring_up(
        &self,
        merged_ifaces: &MergedInterfaces,
    ) -> bool {
        if let Some(iface) = self.for_apply.as_ref() {
            if let Some(cur_iface) = self.current.as_ref() {
                match iface.process_auto_connect(
                    &cur_iface.into(),
                    &merged_ifaces.current,
                ) {
                    None => iface.base_iface().state == InterfaceState::Up,
                    Some(false) => false,
                    Some(true) => true,
                }
            } else {
                iface.is_virtual()
            }
        } else {
            false
        }
    }

    pub(crate) fn is_up_priority_valid(&self) -> bool {
        if let Some(for_apply) = self.for_apply.as_ref()
            && for_apply.is_up()
            && (for_apply.has_controller() || for_apply.has_parent())
        {
            self.up_priority.is_some()
        } else {
            true
        }
    }
}

impl Interface {
    /// Use properties defined in new_state to override properties defined in
    /// self. Return the newly created [Interface].
    pub fn merge(&self, new_state: &Self) -> Result<Self, NipartError> {
        let mut new_value = serde_json::to_value(new_state)?;
        let old_value = serde_json::to_value(self)?;
        copy_undefined_value(&mut new_value, &old_value);

        let old_state = self.clone();

        let mut ret: Self = serde_json::from_value(new_value)?;
        ret.base_iface_mut().post_merge(old_state.base_iface())?;
        ret.post_merge(new_state, &old_state)?;

        Ok(ret)
    }
}
