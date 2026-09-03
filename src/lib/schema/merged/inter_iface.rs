// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    AltNameEntry, ErrorKind, Interface, InterfaceIdentifier, InterfaceType,
    Interfaces, JsonDisplayHideSecrets, MergedInterface, NipartError,
    NipartInterface, schema::IfaceSearch,
};

// The max loop count for Interfaces.set_ifaces_up_priority()
// This allows interface with 4 nested levels in any order.
// To support more nested level, user could place top controller at the
// beginning of desire state
const INTERFACES_SET_PRIORITY_MAX_RETRY: u32 = 4;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    JsonDisplayHideSecrets,
)]
#[non_exhaustive]
pub struct MergedInterfaces {
    /// Interface has kernel interface index number.
    /// The HashMap key is kernel interface name
    pub kernel_ifaces: HashMap<String, MergedInterface>,
    /// Interface does not have kernel interface index number.
    /// The HashMap key is interface name and type
    pub user_ifaces: HashMap<(String, InterfaceType), MergedInterface>,
    /// The ordering of interface in desired YAML/JSON or original desired
    /// state `insert_order` property.
    /// The HashMap key is the kernel_iface_name for kernel interface and
    /// interface.name for userspace interface.
    pub insert_order: Vec<(String, InterfaceType)>,
    pub current: Interfaces,
    /// Use for indexed search data.
    // TODO: speed up InterfaceIdentifier::MacAddress
    pub(crate) iface_search: IfaceSearch,
}

impl MergedInterfaces {
    pub fn hide_secrets(&mut self) {
        for merged_iface in self.iter_mut() {
            merged_iface.hide_secrets()
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &MergedInterface> {
        self.kernel_ifaces.values().chain(self.user_ifaces.values())
    }

    pub fn push(&mut self, merged_iface: MergedInterface) {
        // Saved-only interfaces (not defined in desired state nor present
        // in current state) have an empty `merged` (Unknown default), so
        // the merged-based accessors below carry no identity and all of
        // them would collide on one key, leaving only the last one and
        // purging the rest of the stored config on save. Use the saved
        // config from `for_save` to determine the correct map and key,
        // falling back to `profile-name` (then `name`) when the stored
        // `kernel-iface-name` is empty (e.g. `identifier: mac-address`).
        //
        // When the derived key already holds a desired merged interface
        // (e.g. a MAC-identifier desired matched to the same kernel
        // interface, while an unconsumed plain saved config for that
        // interface also exists), the saved config is already represented
        // by that interface's `for_save` — do not overwrite it, or the
        // pending apply/save state would be purged.
        if merged_iface.name().is_empty()
            && let Some(saved) = merged_iface.for_save.as_ref()
        {
            if saved.is_userspace() {
                let key =
                    (saved.name().to_string(), saved.iface_type().clone());
                if let Some(existing) = self.user_ifaces.get_mut(&key) {
                    // The interface is already represented. A desired
                    // interface already carries the saved config in its
                    // `for_save`; a current-only interface should keep its
                    // current/merged state while retaining the saved config
                    // so it is not purged on save.
                    if existing.for_apply.is_none()
                        && existing.for_save.is_none()
                    {
                        existing.for_save = merged_iface.for_save;
                    }
                    return;
                }
                self.insert_order.push(key.clone());
                self.user_ifaces.insert(key, merged_iface);
            } else {
                let base = saved.base_iface();
                let iface_name = if !base.kernel_iface_name.is_empty() {
                    base.kernel_iface_name.clone()
                } else if let Some(profile_name) = base.profile_name.as_ref() {
                    profile_name.clone()
                } else {
                    base.name.clone()
                };
                if let Some(existing) = self.kernel_ifaces.get_mut(&iface_name)
                {
                    // See the userspace case above: never overwrite an
                    // existing merged interface (its current/merged state is
                    // needed by the apply logic, e.g. re-attaching bond
                    // ports), just retain the saved config on it.
                    if existing.for_apply.is_none()
                        && existing.for_save.is_none()
                    {
                        existing.for_save = merged_iface.for_save;
                    }
                    return;
                }
                let iface_type = saved.iface_type().clone();
                self.insert_order.push((iface_name.clone(), iface_type));
                self.kernel_ifaces.insert(iface_name, merged_iface);
            }
            return;
        }

        if merged_iface.is_userspace() {
            self.insert_order.push((
                merged_iface.name().to_string(),
                merged_iface.iface_type().clone(),
            ));
            self.user_ifaces.insert(
                (
                    merged_iface.name().to_string(),
                    merged_iface.iface_type().clone(),
                ),
                merged_iface,
            );
        } else {
            self.insert_order.push((
                merged_iface.kernel_iface_name().to_string(),
                merged_iface.iface_type().clone(),
            ));
            self.kernel_ifaces.insert(
                merged_iface.kernel_iface_name().to_string(),
                merged_iface,
            );
        }
    }

    pub fn new(
        desired: Interfaces,
        current: Interfaces,
        saved: Option<Interfaces>,
    ) -> Result<Self, NipartError> {
        Self::new_with_force(desired, current, saved, false)
    }

    /// Same as [`MergedInterfaces::new`], but when `force` is true every
    /// desired interface uses its full merged config for apply even when the
    /// kernel already matches it. This is used by explicit `npt up`/`npt down`
    /// actions which must restart services (DHCP, WIFI) rather than only
    /// applying differences.
    pub fn new_with_force(
        desired: Interfaces,
        current: Interfaces,
        saved: Option<Interfaces>,
        force: bool,
    ) -> Result<Self, NipartError> {
        let mut desired = desired;
        let mut current = current;
        let mut ret = Self {
            current: current.clone(),
            ..Default::default()
        };
        let mut consumed_saved_ifaces: HashSet<(String, InterfaceType)> =
            HashSet::new();
        let mut consumed_current_ifaces: HashSet<(String, InterfaceType)> =
            HashSet::new();

        desired.unify_veth_and_ethernet();
        current.unify_veth_and_ethernet();

        super::wifi::expand_wifi_cfg_to_connected_phy(&mut desired, &current);

        // TODO: Remove ignore interface
        // TODO: Resolve `type: unknown` in desired based on current state
        for mut des_iface in desired.drain() {
            // TODO: when certain interface been marked as ignore, we should
            //       also make sure it is ignored all side-changes like
            //       port check and route changes.
            if des_iface.is_ignore() {
                log::info!(
                    "Ignoring interface {} for `state: ignore`",
                    des_iface.name()
                );
                continue;
            }

            let mut saved_iface = saved.as_ref().and_then(|s| {
                s.get_matched_iface_from_save(des_iface.base_iface())
            });
            if let Some(saved_iface) = saved_iface.as_ref() {
                log::debug!(
                    "Matches saved config for {}/{}: {saved_iface}",
                    des_iface.name(),
                    des_iface.iface_type()
                );
                consumed_saved_ifaces.insert((
                    saved_iface.name().to_string(),
                    saved_iface.iface_type().clone(),
                ));
                // When desired interface is pointing to saved config which
                // saved state is holding special identifier
                // config, we will not able to search out
                // current interface because desired interface
                // has no identifier configurations.
                // Hence, we copy saved identifier information to desired
                // interface
                if !saved_iface.is_name_matching()
                    && des_iface.base_iface().identifier.is_none()
                {
                    des_iface
                        .base_iface_mut()
                        .copy_identifier_config_from(saved_iface.base_iface());
                    if des_iface.base_iface_mut().profile_name.is_none() {
                        des_iface.base_iface_mut().profile_name =
                            saved_iface.base_iface().profile_name.clone();
                    }
                }
            }
            let cur_iface = current
                .get_matched_iface_from_current(des_iface.base_iface())?;
            if let Some(cur_iface) = cur_iface.as_ref() {
                log::debug!(
                    "Matches current config for {}/{}: {cur_iface}",
                    des_iface.name(),
                    des_iface.iface_type()
                );
                consumed_current_ifaces.insert((
                    cur_iface.name().to_string(),
                    cur_iface.iface_type().clone(),
                ));
                // For MAC identifier, resolve the desired interface name
                // to the kernel interface name.
                if des_iface.base_iface().identifier
                    == Some(InterfaceIdentifier::MacAddress)
                {
                    let cur_kernel_name =
                        cur_iface.kernel_iface_name().to_string();
                    if des_iface.base_iface().profile_name.is_none() {
                        des_iface.base_iface_mut().profile_name =
                            Some(des_iface.name().to_string());
                    }
                    // An explicit `kernel-iface-name` renames the matched
                    // interface to that name (keeping the original kernel
                    // name as an alt-name unless the user manages
                    // alt-names explicitly); otherwise the interface keeps
                    // its current kernel name.
                    let des_kernel_name =
                        des_iface.base_iface().kernel_iface_name.clone();
                    if !des_kernel_name.is_empty()
                        && des_kernel_name != cur_kernel_name
                    {
                        des_iface.base_iface_mut().name =
                            des_kernel_name.clone();
                        des_iface.base_iface_mut().kernel_iface_name =
                            des_kernel_name;
                        if des_iface.base_iface().alt_names.is_none()
                            && saved_iface
                                .as_ref()
                                .and_then(|s| s.base_iface().alt_names.as_ref())
                                .is_none()
                        {
                            des_iface.base_iface_mut().alt_names =
                                Some(vec![AltNameEntry {
                                    name: cur_kernel_name.clone(),
                                    state: None,
                                }]);
                        }
                    } else {
                        des_iface.base_iface_mut().name =
                            cur_kernel_name.clone();
                        des_iface.base_iface_mut().kernel_iface_name =
                            cur_kernel_name;
                    }
                }
            }
            // When the desired interface matches a current interface by
            // `identifier: mac-address` but its saved config is a plain one
            // (no `identifier`/`mac-address` stored, e.g. the interface was
            // created as a veth before being referenced by MAC address),
            // `get_matched_iface_from_save()` cannot match it. Fall back to
            // the saved config holding the same resolved kernel name so it
            // gets consumed (merged into `for_save`) instead of being
            // pushed as a saved-only interface which would overwrite this
            // merged interface in `MergedInterfaces::push()`.
            if saved_iface.is_none()
                && des_iface.base_iface().identifier
                    == Some(InterfaceIdentifier::MacAddress)
                && cur_iface.is_some()
                && let Some(saved_ifaces) = saved.as_ref()
            {
                saved_iface = saved_ifaces
                    .kernel_ifaces
                    .get(des_iface.kernel_iface_name());
                if let Some(saved_iface) = saved_iface {
                    log::debug!(
                        "Fallback matched saved config for {}/{}: \
                         {saved_iface}",
                        des_iface.name(),
                        des_iface.iface_type()
                    );
                    consumed_saved_ifaces.insert((
                        saved_iface.name().to_string(),
                        saved_iface.iface_type().clone(),
                    ));
                }
            }
            let merged_iface = MergedInterface::new(
                Some(des_iface),
                cur_iface.cloned(),
                saved_iface.cloned(),
                force,
            )?;
            ret.push(merged_iface);
        }

        // Include current exist but not desired interfaces
        for cur_iface in current.drain() {
            if !consumed_current_ifaces.contains(&(
                cur_iface.name().to_string(),
                cur_iface.iface_type().clone(),
            )) {
                // Single current interface can match multiple saved
                // config, hence no reason to search saved config for
                // undesired interface.
                let merged_iface =
                    MergedInterface::new(None, Some(cur_iface), None, false)?;
                ret.push(merged_iface);
            }
        }

        // Include saved config but not desired interfaces
        if let Some(mut saved_ifaces) = saved {
            for saved_iface in saved_ifaces.drain() {
                if !consumed_saved_ifaces.contains(&(
                    saved_iface.name().to_string(),
                    saved_iface.iface_type().clone(),
                )) {
                    let merged_iface = MergedInterface::new(
                        None,
                        None,
                        Some(saved_iface),
                        false,
                    )?;
                    ret.push(merged_iface);
                }
            }
        }

        ret.iface_search = IfaceSearch::new(ret.gen_merged_state().iter());

        ret.post_merge_sanitize()?;

        ret.validate_alt_names()?;

        ret._set_up_priority()?;

        ret.mark_will_delete();

        Ok(ret)
    }

    fn mark_will_delete(&mut self) {
        for merged_iface in self.kernel_ifaces.values_mut() {
            if merged_iface.merged.is_up()
                && merged_iface.will_delete_before_apply()
            {
                log::debug!(
                    "Interface {}/{} will be deleted and recreated during \
                     apply",
                    merged_iface.merged.kernel_iface_name(),
                    merged_iface.merged.iface_type()
                );
                merged_iface.will_delete = true;
            }
        }
    }

    fn _set_up_priority(&mut self) -> Result<(), NipartError> {
        for _ in 0..INTERFACES_SET_PRIORITY_MAX_RETRY {
            if self.set_ifaces_up_priority()? {
                return Ok(());
            }
        }
        log::error!(
            "Failed to set up priority: please order the interfaces in desire \
             state to place controller before its ports"
        );
        Err(NipartError::new(
            ErrorKind::InvalidArgument,
            "Failed to set up priority: nipart only support nested interface \
             up to 4 levels. To support more nest level, please order the \
             interfaces in desire state to place controller before its ports"
                .to_string(),
        ))
    }

    pub fn gen_state_for_apply(&self) -> Interfaces {
        let mut ret_vec: Vec<(bool, u32, Interface)> = self
            .iter()
            .filter_map(|i| {
                i.for_apply.as_ref().map(|for_apply| {
                    (
                        i.is_absent(),
                        i.up_priority.unwrap_or_default(),
                        for_apply.clone(),
                    )
                })
            })
            .collect();

        // Place interface to delete at the beginning.
        ret_vec.sort_unstable_by_key(|(is_absent, up_priority, _)| {
            (!is_absent, *up_priority)
        });
        Interfaces::new(
            ret_vec.into_iter().map(|(_, _, iface)| iface).collect(),
        )
    }

    pub fn gen_state_for_save(&self) -> Interfaces {
        let mut ret_vec: Vec<(bool, u32, Interface)> = self
            .iter()
            .filter_map(|i| {
                i.for_save.as_ref().map(|for_save| {
                    (
                        i.is_absent(),
                        i.up_priority.unwrap_or_default(),
                        for_save.clone(),
                    )
                })
            })
            .collect();

        // Place interface to delete at the beginning.
        ret_vec.sort_unstable_by_key(|(is_absent, up_priority, _)| {
            (!is_absent, *up_priority)
        });
        Interfaces::new(
            ret_vec.into_iter().map(|(_, _, iface)| iface).collect(),
        )
    }

    pub(crate) fn gen_merged_state(&self) -> Interfaces {
        let mut ret_vec: Vec<(bool, u32, Interface)> = self
            .iter()
            .map(|i| {
                (
                    i.is_absent(),
                    i.up_priority.unwrap_or_default(),
                    i.merged.clone(),
                )
            })
            .collect();

        // Place interface to delete at the beginning.
        ret_vec.sort_unstable_by_key(|(is_absent, up_priority, _)| {
            (!is_absent, *up_priority)
        });
        Interfaces::new(
            ret_vec.into_iter().map(|(_, _, iface)| iface).collect(),
        )
    }

    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut MergedInterface> {
        self.user_ifaces
            .values_mut()
            .chain(self.kernel_ifaces.values_mut())
    }

    pub(crate) fn resolve_route_next_hop_iface(
        &self,
        name: &str,
    ) -> Option<String> {
        // Resolve kernel names/profile names first, then an up `wifi-cfg`
        // to the connected wifi-phy carrying its SSID.
        if let Some(kernel_iface_name) = self.iface_search.search_name(name) {
            return Some(kernel_iface_name);
        }
        for merged_iface in self.user_ifaces.values() {
            let Interface::WifiCfg(wifi_cfg) = &merged_iface.merged else {
                continue;
            };
            if !wifi_cfg.is_up() {
                continue;
            }
            let Some(wifi) = wifi_cfg.wifi.as_ref() else {
                continue;
            };
            if wifi_cfg.name() != name && wifi.ssid.as_str() != name {
                continue;
            }
            if let Some(cur_iface) =
                super::wifi::find_connected_wifi_phy_for_cfg(
                    &self.current,
                    wifi_cfg,
                )
            {
                return Some(cur_iface.kernel_iface_name().to_string());
            }
        }
        None
    }

    /// Whether `name` refers to an up `wifi-cfg` profile whose wifi-phy is
    /// not connected yet. Routes to such profiles are persisted and applied
    /// later by the wifi-phy link-up event instead of failing the apply.
    pub(crate) fn is_pending_wifi_cfg_route_target(&self, name: &str) -> bool {
        self.user_ifaces.values().any(|merged_iface| {
            let Interface::WifiCfg(wifi_cfg) = &merged_iface.merged else {
                return false;
            };
            if !wifi_cfg.is_up() {
                return false;
            }
            let name_matched = wifi_cfg.name() == name
                || wifi_cfg
                    .wifi
                    .as_ref()
                    .is_some_and(|wifi| wifi.ssid.as_str() == name);
            name_matched
                && super::wifi::find_connected_wifi_phy_for_cfg(
                    &self.current,
                    wifi_cfg,
                )
                .is_none()
        })
    }

    pub(crate) fn verify(
        &self,
        current: &Interfaces,
    ) -> Result<(), NipartError> {
        let mut merged = self.clone();
        let mut current = current.clone();

        current.unify_veth_and_ethernet();

        for des_iface in merged.iter_mut().filter(|i| i.is_desired()) {
            let iface = if let Some(i) = des_iface.for_verify.as_mut() {
                i
            } else {
                continue;
            };
            iface.hide_secrets();
            let cur_iface = if iface.is_userspace() {
                current.user_ifaces.get_mut(&(
                    iface.name().to_string(),
                    iface.iface_type().clone(),
                ))
            } else if !iface.kernel_iface_name().is_empty() {
                current.kernel_ifaces.get_mut(iface.kernel_iface_name())
            } else {
                current.kernel_ifaces.get_mut(iface.name())
            };

            if iface.is_absent() || (iface.is_virtual() && iface.is_down()) {
                if let Some(cur_iface) = cur_iface {
                    verify_desire_absent_but_found_in_current(
                        iface, cur_iface,
                    )?;
                }
            } else if let Some(cur_iface) = cur_iface {
                iface
                    .base_iface_mut()
                    .sanitize_before_verify(cur_iface.base_iface_mut());
                iface.sanitize_before_verify(cur_iface);
                // Do not verify physical interface with state:down
                if iface.is_up() {
                    iface.verify(cur_iface)?;
                }
            } else if iface.is_up() {
                return Err(NipartError::new(
                    ErrorKind::VerificationError,
                    format!(
                        "Failed to find desired interface {} {:?}",
                        iface.name(),
                        iface.iface_type()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Sanitize actions which require cross-interfaces information:
    /// * Controller/port relationship
    /// * Parent/child relationship
    /// * WIFI Phy and Cfg relationship
    fn post_merge_sanitize(&mut self) -> Result<(), NipartError> {
        self.post_merge_sanitize_veth();
        self.post_merge_sanitize_wifi();
        self.post_merge_sanitize_controller_and_port()?;

        Ok(())
    }

    /// Validate that no two interfaces share the same alternative name, and
    /// that no alternative name collides with an existing kernel interface
    /// name.  Mirrors nmstate's `MergedInterfaces::validate_alt_names()`.
    fn validate_alt_names(&self) -> Result<(), NipartError> {
        // HashMap<alt_name, current_kernel_iface_name>
        let mut all_alt_names: HashMap<&str, &str> = HashMap::new();

        let all_iface_names: HashSet<&str> =
            self.kernel_ifaces.keys().map(|s| s.as_str()).collect();

        for merged_iface in self.kernel_ifaces.values() {
            if let Some(cur_iface) = merged_iface.current.as_ref()
                && let Some(alt_names) =
                    cur_iface.base_iface().alt_names.as_ref()
            {
                for alt_name in alt_names {
                    all_alt_names
                        .insert(alt_name.name.as_str(), cur_iface.name());
                }
            }
        }
        for merged_iface in self.kernel_ifaces.values() {
            let Some(des_iface) = merged_iface.for_apply.as_ref() else {
                continue;
            };
            // The desired (post-rename) kernel name of this same interface:
            // an existing alt-name owned by it is not a conflict (e.g. a
            // `identifier: mac-address` config whose desired `name` is the
            // profile name, not the kernel name).  When the config renames
            // the interface, the target name is the interface's own name,
            // not the current one (which becomes an alt-name).
            let self_kernel_name = Some(des_iface.kernel_iface_name());
            // The current (pre-rename) kernel name of this same interface:
            // the name being renamed away is still a kernel interface name
            // at validation time, but it belongs to this interface and
            // becomes its alt-name, so it is not "an interface name of
            // other NIC".
            let self_cur_kernel_name =
                merged_iface.current.as_ref().map(|i| i.kernel_iface_name());
            let mut iface_seen_alt_names: HashSet<&str> = HashSet::new();
            if let Some(alt_names) = des_iface.base_iface().alt_names.as_ref() {
                for alt_name in alt_names {
                    if !iface_seen_alt_names.insert(alt_name.name.as_str()) {
                        return Err(NipartError::new(
                            ErrorKind::InvalidArgument,
                            format!(
                                "Duplicate alt-name {} on interface {}",
                                alt_name.name,
                                des_iface.name(),
                            ),
                        ));
                    }
                    if alt_name.is_absent() {
                        all_alt_names.remove(alt_name.name.as_str());
                    } else if self_kernel_name == Some(alt_name.name.as_str()) {
                        // The kernel forbids an interface holding an
                        // alt-name equal to its own kernel name.
                        return Err(NipartError::new(
                            ErrorKind::InvalidArgument,
                            format!(
                                "Alternative name {} for interface {} cannot \
                                 be the same as its kernel interface name",
                                alt_name.name,
                                des_iface.name(),
                            ),
                        ));
                    } else if let Some(other_iface_name) =
                        all_alt_names.get(alt_name.name.as_str())
                    {
                        if self_kernel_name != Some(*other_iface_name) {
                            return Err(NipartError::new(
                                ErrorKind::InvalidArgument,
                                format!(
                                    "Desired alt-name {} for interface {} is \
                                     already used by interface {}",
                                    alt_name.name,
                                    des_iface.name(),
                                    other_iface_name
                                ),
                            ));
                        };
                    } else if all_iface_names.contains(alt_name.name.as_str())
                        && self_cur_kernel_name != Some(alt_name.name.as_str())
                    {
                        return Err(NipartError::new(
                            ErrorKind::InvalidArgument,
                            format!(
                                "Desired alt-name {} for interface {} is \
                                 already an interface name of other NIC",
                                alt_name.name,
                                des_iface.name(),
                            ),
                        ));
                    } else {
                        all_alt_names
                            .insert(alt_name.name.as_str(), des_iface.name());
                    }
                }
            }
        }
        Ok(())
    }

    // Return True if we have all up_priority fixed.
    fn set_ifaces_up_priority(&mut self) -> Result<bool, NipartError> {
        // Return true when all interface has correct priority.
        let mut ret = true;
        let mut pending_changes: HashMap<String, u32> = HashMap::new();
        // Use the push order to allow user providing help on dependency order

        for (iface_name, iface_type) in &self.insert_order {
            let merged_iface = if iface_type.is_userspace() {
                self.user_ifaces
                    .get(&(iface_name.to_string(), iface_type.clone()))
            } else {
                self.kernel_ifaces.get(iface_name)
            };

            let Some(merged_iface) = merged_iface else {
                continue;
            };

            if merged_iface.is_up_priority_valid() {
                continue;
            }
            let Some(for_apply) = merged_iface.for_apply.as_ref() else {
                continue;
            };

            if !for_apply.is_up() {
                continue;
            }

            if let Some(ctrl_name) = for_apply.base_iface().controller.as_ref()
            {
                if ctrl_name.is_empty() {
                    continue;
                }
                let Some(ctrl_iface_type) =
                    for_apply.base_iface().controller_type.as_ref()
                else {
                    return Err(NipartError::new(
                        ErrorKind::Bug,
                        format!(
                            "Got for_apply interface with empty \
                             controller_type and non-empty controller: \
                             {for_apply}"
                        ),
                    ));
                };
                let ctrl_iface = if ctrl_iface_type.is_userspace() {
                    self.user_ifaces
                        .get(&(ctrl_name.to_string(), ctrl_iface_type.clone()))
                } else {
                    self.kernel_ifaces.get(ctrl_name)
                };

                if let Some(ctrl_iface) = ctrl_iface {
                    if let Some(ctrl_pri) = pending_changes.remove(ctrl_name) {
                        pending_changes.insert(ctrl_name.to_string(), ctrl_pri);
                        pending_changes
                            .insert(iface_name.to_string(), ctrl_pri + 1);
                    } else if ctrl_iface.is_up_priority_valid() {
                        pending_changes.insert(
                            iface_name.to_string(),
                            ctrl_iface.up_priority.unwrap_or_default() + 1,
                        );
                    } else {
                        // Its controller does not have valid up priority yet.
                        log::debug!(
                            "Controller {ctrl_name} of {iface_name} is has no \
                             up priority yet"
                        );
                        ret = false;
                    }
                } else {
                    // self.post_merge_sanitize() should already
                    return Err(NipartError::new(
                        ErrorKind::Bug,
                        format!(
                            "Failed to find controller interface of {}/{}: \
                             {self}",
                            for_apply.name(),
                            for_apply.iface_type()
                        ),
                    ));
                }
            } else {
                // Interface has no controller defined in desire
                continue;
            }
        }

        // If not remaining unknown up_priority, we set up the parent/child
        // up_priority
        if ret {
            for (iface_name, iface_type) in &self.insert_order {
                let merged_iface = if iface_type.is_userspace() {
                    self.user_ifaces
                        .get(&(iface_name.to_string(), iface_type.clone()))
                } else {
                    self.kernel_ifaces.get(iface_name)
                };

                let Some(merged_iface) = merged_iface else {
                    continue;
                };

                if merged_iface.is_up_priority_valid() {
                    continue;
                }
                let Some(for_apply) = merged_iface.for_apply.as_ref() else {
                    continue;
                };

                if !for_apply.is_up() {
                    continue;
                }

                if let Some(parent) = for_apply.parent() {
                    let parent_priority = pending_changes.get(parent).cloned();
                    if let Some(parent_priority) = parent_priority {
                        pending_changes.insert(
                            iface_name.to_string(),
                            parent_priority + 1,
                        );
                    } else if let Some(parent_iface) =
                        self.kernel_ifaces.get(parent)
                        && parent_iface.is_up_priority_valid()
                    {
                        pending_changes.insert(
                            iface_name.to_string(),
                            parent_iface.up_priority.unwrap_or_default() + 1,
                        );
                    }
                }
            }
        }

        if !pending_changes.is_empty() {
            log::debug!(
                "Pending kernel up priority changes {pending_changes:?}"
            );
            for (iface_name, priority) in pending_changes.iter() {
                if let Some(iface) = self.kernel_ifaces.get_mut(iface_name) {
                    iface.up_priority = Some(*priority);
                }
            }
        }

        Ok(ret)
    }
}

fn verify_desire_absent_but_found_in_current(
    des_iface: &Interface,
    cur_iface: &Interface,
) -> Result<(), NipartError> {
    // Use `cur_iface` for the virtual check: the desired absent state
    // may lack type-specific sections (e.g. veth), but the current
    // kernel state retains them.
    if cur_iface.is_virtual() {
        // Virtual interface should be deleted by absent action
        Err(NipartError::new(
            ErrorKind::VerificationError,
            format!(
                "Absent/Down interface {}/{} still found as {:?}",
                des_iface.name(),
                des_iface.iface_type(),
                cur_iface
            ),
        ))
    } else {
        // Real hardware NIC cannot be removed
        Ok(())
    }
}

impl Interfaces {
    pub fn unify_veth_and_ethernet(&mut self) {
        for iface in self
            .iter_mut()
            .filter(|i| i.iface_type() == &InterfaceType::Veth)
        {
            iface.base_iface_mut().iface_type = InterfaceType::Ethernet;
        }
    }

    pub fn merge(&mut self, new_ifaces: &Self) -> Result<(), NipartError> {
        for new_iface in new_ifaces.iter() {
            if let Some(old_iface) = self.get_mut(new_iface.base_iface()) {
                *old_iface = old_iface.merge(new_iface)?;
            } else {
                self.push(new_iface.clone())
            }
        }
        Ok(())
    }
}
