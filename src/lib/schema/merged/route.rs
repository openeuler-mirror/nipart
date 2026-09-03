// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file are:
//  * Gris Ge <fge@redhat.com>
//  * Wen Liang <liangwen12year@gmail.com>
//  * Jan Vaclav <jvaclav@redhat.com>
//  * Íñigo Huguet <ihuguet@redhat.com>
//  * Fernando Fernandez Mancera <ffmancera@riseup.net>

use std::collections::{HashMap, HashSet, hash_map::Entry};

use serde::{Deserialize, Serialize};

use crate::{
    ErrorKind, JsonDisplay, MergedInterfaces, NipartError, NipartInterface,
    RouteEntry, RouteState, Routes,
};

const LOOPBACK_IFACE_NAME: &str = "lo";

struct IfaceLists<'a> {
    absent: HashSet<&'a str>,
    ipv4_disabled: HashSet<&'a str>,
    ipv6_disabled: HashSet<&'a str>,
    dhcpv4_enabled: HashSet<&'a str>,
    will_delete: HashSet<&'a str>,
    // Profiles requested with `state: saved`: their routes are persisted
    // but never applied.
    saved_only: HashSet<&'a str>,
    // Kernel interfaces present in the desired state. Only these may have
    // their current routes removed due to IPv4/IPv6 being disabled: a
    // partial apply (e.g. a link event) must not infer route removal from
    // the transient IP-disabled state of untouched interfaces (e.g. a DHCP
    // interface whose lease has not been re-acquired yet after daemon
    // restart).
    desired_ifaces: HashSet<&'a str>,
}

#[derive(
    Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonDisplay,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct MergedRoutes {
    // When all routes next hop to a interface are all marked as absent,
    // the `MergedRoutes.merged` will not have entry for this interface, but
    // interface name is found in `MergedRoutes.route_changed_ifaces`.
    // For backend use incremental route changes, please use
    // `MergedRoutes.changed_routes`.
    pub merged: HashMap<String, Vec<RouteEntry>>,
    pub route_changed_ifaces: Vec<String>,
    // The `changed_routes` contains desired new routes and also including
    // current routes been marked as absent. Not including desired route equal
    // to current route.
    pub changed_routes: Vec<RouteEntry>,
    pub desired: Routes,
    pub current: Routes,
    #[serde(default)]
    pub saved: Option<Routes>,
    // Routes to persist, computed in `new()` where the interface changes
    // are known: desired routes plus previously saved routes that survive
    // this apply (see `gen_routes_for_save()`).
    #[serde(default)]
    pub(crate) for_save: Routes,
}

impl MergedRoutes {
    pub fn new(
        mut desired: Routes,
        current: Routes,
        saved: Option<Routes>,
        merged_ifaces: &MergedInterfaces,
    ) -> Result<Self, NipartError> {
        desired.remove_ignored_routes();
        desired.validate()?;
        desired.resolve_vrf_name(merged_ifaces)?;

        let iface_lists = collect_iface_lists(merged_ifaces);

        let desired_routes =
            resolve_desired_routes(&desired, merged_ifaces, &iface_lists)?;

        let mut changed_ifaces: HashSet<&str> = HashSet::new();

        validate_desired_routes(
            &desired_routes,
            &iface_lists,
            &mut changed_ifaces,
        )?;
        collect_absent_route_changes(
            &desired_routes,
            &current,
            &mut changed_ifaces,
        );

        let mut changed_routes: HashSet<RouteEntry> = HashSet::new();
        let mut merged_routes = build_merged_and_changed_routes(
            &current,
            &desired_routes,
            &iface_lists,
            &mut changed_routes,
        );

        // For interfaces that will be deleted and recreated, current
        // routes are purged by kernel. Include saved routes so they
        // are re-applied along with desired routes.
        if let Some(saved) = saved.as_ref()
            && let Some(saved_rts) = saved.config.as_ref()
        {
            for rt in saved_rts {
                if rt.is_absent() {
                    continue;
                }
                if let Some(via) = rt.next_hop_iface.as_ref()
                    && iface_lists.will_delete.contains(&via.as_str())
                    && !changed_routes.iter().any(|r| rt.is_match(r))
                {
                    changed_routes.insert(rt.clone());
                    merged_routes.push(rt.clone());
                    changed_ifaces.insert(via.as_str());
                }
            }
        }

        let merged = group_by_next_hop_iface(merged_routes);

        let route_changed_ifaces: Vec<String> =
            changed_ifaces.iter().map(|i| i.to_string()).collect();

        let mut ret = Self {
            merged,
            desired,
            current,
            saved,
            route_changed_ifaces,
            changed_routes: changed_routes.drain().collect(),
            for_save: Routes::default(),
        };

        let ignored_ifaces = ret.remove_routes_to_ignored_ifaces(merged_ifaces);

        ret.for_save = gen_routes_for_save(
            &ret.desired,
            ret.saved.as_ref(),
            &iface_lists,
            &ignored_ifaces,
            merged_ifaces,
        );

        Ok(ret)
    }

    fn remove_routes_to_ignored_ifaces(
        &mut self,
        merged_ifaces: &MergedInterfaces,
    ) -> Vec<String> {
        let ignored_ifaces: Vec<String> = merged_ifaces
            .kernel_ifaces
            .values()
            .filter_map(|merged_iface| {
                if merged_iface.merged.is_ignore() {
                    Some(merged_iface.merged.kernel_iface_name().to_string())
                } else {
                    None
                }
            })
            .collect();

        for iface in &ignored_ifaces {
            self.merged.remove(iface);
        }
        self.route_changed_ifaces
            .retain(|n| !ignored_ifaces.contains(n));
        ignored_ifaces
    }

    pub(crate) fn is_changed(&self) -> bool {
        !self.route_changed_ifaces.is_empty()
    }

    pub(crate) fn gen_state_for_apply(&self) -> Routes {
        Routes {
            running: None,
            config: Some(self.changed_routes.clone()),
        }
    }

    pub(crate) fn gen_state_for_save(&self) -> Routes {
        // The desired `routes.config` is additive (documented): it adds
        // routes to the existing ones instead of replacing them. Hence
        // persist the desired routes plus the previously saved routes that
        // survive this apply, otherwise a partial apply would silently drop
        // the saved routes of interfaces not touched by it (or keep stale
        // routes of interfaces this apply deletes or disables). The
        // surviving set was precomputed in `new()` as `for_save`.
        Routes {
            running: None,
            config: self.for_save.config.clone(),
        }
    }
}

/// Compute the routes to persist: the desired routes plus every previously
/// saved route that survives this apply. A saved route survives unless it is
/// explicitly marked `absent` in the desired state, or its next hop
/// interface is being deleted (`absent`) or has its IP stack disabled by
/// this apply, or is marked as `ignore`.
fn gen_routes_for_save(
    desired: &Routes,
    saved: Option<&Routes>,
    iface_lists: &IfaceLists,
    ignored_ifaces: &[String],
    merged_ifaces: &MergedInterfaces,
) -> Routes {
    let mut routes: HashSet<RouteEntry> = HashSet::new();
    if let Some(rts) = desired.config.as_ref() {
        for rt in rts.iter().filter(|rt| !rt.is_absent()) {
            routes.insert(rt.clone());
        }
    }
    if let Some(saved) = saved
        && let Some(saved_rts) = saved.config.as_ref()
    {
        for rt in saved_rts.iter().filter(|rt| !rt.is_absent()) {
            if saved_route_is_removed(
                rt,
                desired,
                iface_lists,
                ignored_ifaces,
                merged_ifaces,
            ) {
                continue;
            }
            routes.insert(rt.clone());
        }
    }
    let mut rts: Vec<RouteEntry> = routes.into_iter().collect();
    rts.sort_unstable();
    Routes {
        running: None,
        config: Some(rts),
        ..Default::default()
    }
}

/// Whether a previously saved route should be dropped from the persisted
/// state by this apply: it is explicitly marked `absent` in the desired
/// state, or its next hop interface is marked `absent`, has its IP stack
/// explicitly disabled by this apply (i.e. the desired state sets
/// `ipv4`/`ipv6` to `enabled: false`), or is marked as `ignore`.
fn saved_route_is_removed(
    rt: &RouteEntry,
    desired: &Routes,
    iface_lists: &IfaceLists,
    ignored_ifaces: &[String],
    merged_ifaces: &MergedInterfaces,
) -> bool {
    // Saved routes may reference their next hop interface by profile or
    // logical name (the persisted format preserves them), while desired
    // absent routes and the interface change lists are keyed by kernel
    // interface name, so resolve before comparing.
    let kernel_name: Option<String> = rt.next_hop_iface.as_ref().map(|via| {
        merged_ifaces
            .resolve_route_next_hop_iface(via)
            .unwrap_or_else(|| via.clone())
    });
    let mut resolved_rt = rt.clone();
    if let Some(kernel_name) = kernel_name.as_ref() {
        resolved_rt.next_hop_iface = Some(kernel_name.clone());
    }

    if let Some(desired_rts) = desired.config.as_ref()
        && desired_rts
            .iter()
            .filter(|r| r.is_absent())
            .any(|absent_rt| {
                // The absent desired route may reference the next hop
                // interface by profile or logical name (e.g. a
                // MAC-identified interface), while `resolved_rt` carries the
                // kernel interface name: resolve the absent route the same
                // way before matching.
                let mut resolved_absent_rt = (*absent_rt).clone();
                if let Some(name) = resolved_absent_rt.next_hop_iface.as_ref()
                    && let Some(kernel_iface_name) =
                        merged_ifaces.resolve_route_next_hop_iface(name)
                {
                    resolved_absent_rt.next_hop_iface = Some(kernel_iface_name);
                }
                resolved_absent_rt.is_match(&resolved_rt)
            })
    {
        return true;
    }
    let Some(via) = kernel_name.as_ref() else {
        // Routes without next hop interface (e.g. blackhole) can only be
        // removed by an explicit absent match handled above.
        return false;
    };
    ignored_ifaces.iter().any(|i| i == via)
        || iface_lists.absent.contains(&via.as_str())
        || (iface_lists.desired_ifaces.contains(&via.as_str())
            && ((rt.is_ipv6()
                && desired_iface_ipv6_disabled(via, merged_ifaces))
                || (!rt.is_ipv6()
                    && desired_iface_ipv4_disabled(via, merged_ifaces))))
}

/// Whether the desired state for the given kernel interface explicitly
/// disables IPv4.
///
/// An interface merely mentioned in the desired state without an `ipv4`
/// section does not count: when the interface is absent from the kernel
/// (e.g. its NIC is unplugged) or its IP is already disabled, the merged
/// interface defaults to IPv4-disabled.  Treating that default as an
/// explicit disable would silently drop the saved routes of the interface,
/// even though its IPv4 config is still preserved in the saved state (the
/// interface merge keeps untouched properties) and the routes are meant to
/// be restored when the NIC is back.
fn desired_iface_ipv4_disabled(
    kernel_iface_name: &str,
    merged_ifaces: &MergedInterfaces,
) -> bool {
    merged_ifaces
        .kernel_ifaces
        .get(kernel_iface_name)
        .and_then(|merged_iface| merged_iface.desired.as_ref())
        .is_some_and(|desired| {
            desired
                .base_iface()
                .ipv4
                .as_ref()
                .is_some_and(|ipv4| !ipv4.is_enabled())
        })
}

/// Whether the desired state for the given kernel interface explicitly
/// disables IPv6.  See [`desired_iface_ipv4_disabled`].
fn desired_iface_ipv6_disabled(
    kernel_iface_name: &str,
    merged_ifaces: &MergedInterfaces,
) -> bool {
    merged_ifaces
        .kernel_ifaces
        .get(kernel_iface_name)
        .and_then(|merged_iface| merged_iface.desired.as_ref())
        .is_some_and(|desired| {
            desired
                .base_iface()
                .ipv6
                .as_ref()
                .is_some_and(|ipv6| !ipv6.is_enabled())
        })
}

fn collect_iface_lists(merged_ifaces: &MergedInterfaces) -> IfaceLists<'_> {
    let absent: HashSet<&str> = merged_ifaces
        .kernel_ifaces
        .values()
        .filter(|i| i.merged.is_absent())
        .map(|i| i.merged.kernel_iface_name())
        .collect();

    let ipv4_disabled: HashSet<&str> = merged_ifaces
        .kernel_ifaces
        .values()
        .filter(|i| !i.merged.base_iface().is_ipv4_enabled())
        .map(|i| i.merged.kernel_iface_name())
        .collect();

    let ipv6_disabled: HashSet<&str> = merged_ifaces
        .kernel_ifaces
        .values()
        .filter(|i| !i.merged.base_iface().is_ipv6_enabled())
        .map(|i| i.merged.kernel_iface_name())
        .collect();

    let dhcpv4_enabled: HashSet<&str> = merged_ifaces
        .kernel_ifaces
        .values()
        .filter(|i| {
            i.merged.base_iface().ipv4.as_ref().and_then(|ip| ip.dhcp)
                == Some(true)
        })
        .map(|i| i.merged.kernel_iface_name())
        .collect();

    let will_delete: HashSet<&str> = merged_ifaces
        .kernel_ifaces
        .values()
        .filter(|i| i.will_delete)
        .map(|i| i.merged.kernel_iface_name())
        .collect();

    let saved_only: HashSet<&str> = merged_ifaces
        .kernel_ifaces
        .values()
        .filter(|i| i.merged.base_iface().state.is_saved())
        .flat_map(|i| [i.merged.kernel_iface_name(), i.merged.name()])
        .collect();

    let desired_ifaces: HashSet<&str> = merged_ifaces
        .kernel_ifaces
        .values()
        .filter(|i| i.desired.is_some())
        .map(|i| i.merged.kernel_iface_name())
        .collect();

    IfaceLists {
        absent,
        ipv4_disabled,
        ipv6_disabled,
        dhcpv4_enabled,
        will_delete,
        saved_only,
        desired_ifaces,
    }
}

fn resolve_desired_routes(
    desired: &Routes,
    merged_ifaces: &MergedInterfaces,
    iface_lists: &IfaceLists,
) -> Result<Vec<RouteEntry>, NipartError> {
    let mut desired_routes = Vec::new();
    if let Some(rts) = desired.config.as_ref() {
        for rt in rts {
            let mut rt = rt.clone();
            rt.sanitize()?;
            // Routes marked `state: saved`, or routes of profiles requested
            // with `state: saved`, are persisted but not applied: skip
            // kernel resolution and change collection for them.
            if rt.is_saved()
                || rt
                    .next_hop_iface
                    .as_deref()
                    .is_some_and(|name| iface_lists.saved_only.contains(name))
            {
                continue;
            }
            if let Some(name) = rt.next_hop_iface.as_ref() {
                if let Some(kernel_iface_name) =
                    merged_ifaces.resolve_route_next_hop_iface(name)
                {
                    rt.next_hop_iface = Some(kernel_iface_name);
                } else if merged_ifaces.is_pending_wifi_cfg_route_target(name) {
                    // A `wifi-cfg` profile is userspace-only: its route can
                    // only be installed once the wifi-phy carrying its SSID
                    // is connected. Keep the route in the saved state and
                    // let the link-up event apply it then.
                    log::debug!(
                        "Deferring route {rt}: wifi-cfg {} has no connected \
                         wifi-phy yet",
                        name
                    );
                    continue;
                } else {
                    return Err(NipartError::new(
                        ErrorKind::InvalidArgument,
                        format!(
                            "Failed to find kernel interface name for route \
                             {rt}"
                        ),
                    ));
                }
            }
            // Kernel rejects IPv4 route with gateway defined before
            // DHCPv4 lease acquired on next hop interface, hence we
            // set onlink flag to bypass kernel gateway validation.
            if rt.onlink.is_none()
                && !rt.is_absent()
                && !rt.is_ipv6()
                && rt.next_hop_addr.is_some()
                && rt
                    .next_hop_iface
                    .as_deref()
                    .is_some_and(|i| iface_lists.dhcpv4_enabled.contains(&i))
            {
                log::debug!(
                    "Setting onlink flag for route '{rt}' as its next hop \
                     interface is DHCPv4 enabled"
                );
                rt.onlink = Some(true);
            }
            desired_routes.push(rt);
        }
    }
    Ok(desired_routes)
}

fn validate_desired_routes<'a>(
    desired_routes: &'a [RouteEntry],
    iface_lists: &IfaceLists<'_>,
    changed_ifaces: &mut HashSet<&'a str>,
) -> Result<(), NipartError> {
    for rt in desired_routes.iter().filter(|rt| !rt.is_absent()) {
        if let Some(via) = rt.next_hop_iface.as_ref() {
            if iface_lists.absent.contains(&via.as_str()) {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "The next hop interface of desired Route '{rt}' has \
                         been marked as absent"
                    ),
                ));
            }
            if rt.is_ipv6() && iface_lists.ipv6_disabled.contains(&via.as_str())
            {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "The next hop interface of desired Route '{rt}' has \
                         been marked as IPv6 disabled"
                    ),
                ));
            }
            if (!rt.is_ipv6())
                && iface_lists.ipv4_disabled.contains(&via.as_str())
            {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "The next hop interface of desired Route '{rt}' has \
                         been marked as IPv4 disabled"
                    ),
                ));
            }
            changed_ifaces.insert(via.as_str());
        } else if rt.route_type.is_some() {
            changed_ifaces.insert(LOOPBACK_IFACE_NAME);
        }
    }
    Ok(())
}

fn collect_absent_route_changes<'a>(
    desired_routes: &[RouteEntry],
    current: &'a Routes,
    changed_ifaces: &mut HashSet<&'a str>,
) {
    for absent_rt in desired_routes.iter().filter(|rt| rt.is_absent()) {
        for rt in current
            .config
            .iter()
            .flatten()
            .chain(current.running.iter().flatten())
        {
            if absent_rt.is_match(rt) {
                if let Some(via) = rt.next_hop_iface.as_ref() {
                    changed_ifaces.insert(via.as_str());
                } else {
                    changed_ifaces.insert(LOOPBACK_IFACE_NAME);
                }
            }
        }
    }
}

fn build_merged_and_changed_routes(
    current: &Routes,
    desired_routes: &[RouteEntry],
    iface_lists: &IfaceLists,
    changed_routes: &mut HashSet<RouteEntry>,
) -> Vec<RouteEntry> {
    let mut merged_routes: Vec<RouteEntry> = Vec::new();

    if let Some(cur_rts) = current.config.as_ref() {
        for rt in cur_rts {
            if let Some(via) = rt.next_hop_iface.as_ref() {
                if iface_lists.will_delete.contains(&via.as_str()) {
                    // Routes on will_delete interfaces will be purged
                    // by kernel when the interface is deleted, skip
                    // them from current so they get re-applied.
                    continue;
                }
                // Only interfaces changed by this apply may have their
                // routes removed due to IP being disabled: a current-only
                // interface may be temporarily IP-disabled (e.g. DHCP
                // lease not re-acquired after daemon restart) and its
                // routes must not be dropped by an unrelated apply.
                let via_ip_disabled = iface_lists
                    .desired_ifaces
                    .contains(&via.as_str())
                    && ((rt.is_ipv6()
                        && iface_lists.ipv6_disabled.contains(&via.as_str()))
                        || (!rt.is_ipv6()
                            && iface_lists
                                .ipv4_disabled
                                .contains(&via.as_str())));
                if iface_lists.absent.contains(&via.as_str()) {
                    // The next hop interface is being deleted: kernel
                    // purges its routes on deletion, so there is no need
                    // (nor ability, once the link is gone) to remove them
                    // explicitly.
                    continue;
                }
                if via_ip_disabled
                    || desired_routes
                        .iter()
                        .filter(|r| r.is_absent())
                        .any(|absent_rt| absent_rt.is_match(rt))
                {
                    let mut new_rt = rt.clone();
                    new_rt.state = Some(RouteState::Absent);
                    changed_routes.insert(new_rt);
                } else {
                    merged_routes.push(rt.clone());
                }
            }
        }
    }

    for rt in desired_routes.iter().filter(|rt| !rt.is_absent()) {
        let is_will_delete_iface = rt
            .next_hop_iface
            .as_deref()
            .is_some_and(|via| iface_lists.will_delete.contains(via));
        if is_will_delete_iface {
            // Current routes on this interface are purged, so always
            // treat desired routes as new.
            changed_routes.insert(rt.clone());
            merged_routes.push(rt.clone());
        } else if !current_route_matches(current, rt) {
            changed_routes.insert(rt.clone());
            merged_routes.push(rt.clone());
        } else {
            // The route already exists in the running or config state
            // (e.g. a kernel connected route materialized by an address
            // assignment), so there is nothing to change.
        }
    }

    merged_routes.sort_unstable();
    merged_routes.dedup();
    merged_routes
}

/// Whether the desired route is already present in the current running or
/// config routes. Kernel connected routes (`proto kernel`) are only reported
/// under `running`, so both lists must be checked for idempotent applies.
fn current_route_matches(current: &Routes, rt: &RouteEntry) -> bool {
    current
        .config
        .iter()
        .flatten()
        .chain(current.running.iter().flatten())
        .any(|cur_rt| rt.is_match(cur_rt))
}

fn group_by_next_hop_iface(
    merged_routes: Vec<RouteEntry>,
) -> HashMap<String, Vec<RouteEntry>> {
    let mut merged: HashMap<String, Vec<RouteEntry>> = HashMap::new();
    for rt in merged_routes {
        if let Some(via) = rt.next_hop_iface.as_ref() {
            let rts: &mut Vec<RouteEntry> = match merged.entry(via.to_string())
            {
                Entry::Occupied(o) => o.into_mut(),
                Entry::Vacant(v) => v.insert(Vec::new()),
            };
            rts.push(rt);
        } else if rt.route_type.is_some() {
            let rts: &mut Vec<RouteEntry> =
                match merged.entry(LOOPBACK_IFACE_NAME.to_string()) {
                    Entry::Occupied(o) => o.into_mut(),
                    Entry::Vacant(v) => v.insert(Vec::new()),
                };
            rts.push(rt);
        }
    }
    merged
}

impl Routes {
    /// Return new Routes data contains the merged data.
    pub(crate) fn merge(&self, new_routes: &Self) -> Result<Self, NipartError> {
        new_routes.validate()?;

        if let Some(new_routes) = new_routes.config.as_ref() {
            let mut route_sets: HashSet<RouteEntry> = HashSet::new();
            for new_route in new_routes.iter().filter(|r| !r.is_absent()) {
                route_sets.insert(new_route.clone());
            }
            if let Some(old_routes) = self.config.as_ref() {
                for old_route in old_routes {
                    if new_routes
                        .iter()
                        .any(|r| r.is_absent() && r.is_match(old_route))
                    {
                        let mut absent_route = old_route.clone();
                        absent_route.state = Some(RouteState::Absent);
                        route_sets.insert(absent_route);
                    } else {
                        route_sets.insert(old_route.clone());
                    }
                }
            }
            let mut routes: Vec<RouteEntry> = route_sets.into_iter().collect();
            routes.sort_unstable();

            Ok(Routes {
                config: Some(routes),
                ..Default::default()
            })
        } else {
            Ok(self.clone())
        }
    }
}
