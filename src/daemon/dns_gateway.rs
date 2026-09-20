// SPDX-License-Identifier: Apache-2.0

//! Detect a changed default gateway for the DNS cache.
//!
//! The embedded DNS cache (the `mudz` crate) marks an upstream dead after
//! two failed queries and skips it until its retry cooldown (5 seconds,
//! doubling after every failed probe) elapsed. A changed default gateway
//! means the network path of the upstream nameservers may work again, hence
//! the daemon notifies the cache so it retries the failed upstream groups
//! at once instead of failing fast until the cooldown elapsed:
//!
//!  * The apply and rollback paths call
//!    [`NipartCommander::notify_dns_cache_on_gateway_change()`]. They know the
//!    routes before and after the apply without any extra kernel query. This
//!    also covers the boot saved-state restore, which applies the saved state
//!    through the same code path.
//!  * The DHCPv4 worker installs its lease routes outside of that apply path,
//!    so it compares the default routes of the interface before and after
//!    applying a lease and asks the daemon to notify the cache (see
//!    `NipartDhcpV4Worker` and `NipartManagerCmd::GatewayChanged`).

use nipart::{MergedNetworkState, NipartError, RouteEntry, RouteType};

use super::commander::NipartCommander;

const IPV4_DEFAULT_ROUTE: &str = "0.0.0.0/0";
const IPV6_DEFAULT_ROUTE: &str = "::/0";

impl NipartCommander {
    /// Notify the DNS cache when this apply changes the default routes.
    ///
    /// `merged_state.routes.current.config` holds the routes before the
    /// apply and `merged_state.routes.merged` the routes existing after it,
    /// both limited to the static routes. `current.running` deliberately is
    /// not used: it carries the DHCP/IPv6-RA learned routes too, which the
    /// merged routes do not know and which would be reported as a change by
    /// every apply.
    ///
    /// A failure to notify does not fail the apply: the cache then falls
    /// back to its own retry cooldown.
    pub(crate) async fn notify_dns_cache_on_gateway_change(
        &mut self,
        merged_state: &MergedNetworkState,
    ) {
        let before = default_gateway_fingerprint(
            merged_state.routes.current.config.iter().flatten(),
        );
        let after = default_gateway_fingerprint(
            merged_state.routes.merged.values().flatten(),
        );
        if before == after {
            return;
        }
        log::debug!(
            "Default gateway changed from {before:?} to {after:?}, notifying \
             the DNS cache to retry its failed upstream groups"
        );
        if let Err(e) = self.notify_dns_cache_network_change().await {
            log::warn!(
                "Failed to notify the DNS cache about the changed default \
                 gateway: {e}"
            );
        }
    }

    /// Notify the running DNS cache that the network path of its upstream
    /// nameservers changed, e.g. the default gateway was replaced by a route
    /// apply, a DHCP lease or the boot-up state restore.
    ///
    /// The cache keeps its cached replies but retries the upstream groups
    /// which were marked dead instead of waiting out their retry backoff. A
    /// stopped cache is not an error: a cache started later has no failure
    /// state to clear.
    pub(crate) async fn notify_dns_cache_network_change(
        &mut self,
    ) -> Result<(), NipartError> {
        self.dns_manager.notify_network_change().await
    }
}

/// Fingerprint identifying the default routes of `routes`.
///
/// Every default route contributes its next hop interface, next hop
/// address, metric and table, so a replaced default route is noticed while
/// a change of an unrelated route is not. Non-unicast default routes
/// (blackhole, unreachable and prohibit) carry no gateway and cannot be the
/// network path of a DNS upstream, hence they are skipped.
pub(crate) fn default_gateway_fingerprint<'a>(
    routes: impl IntoIterator<Item = &'a RouteEntry>,
) -> Vec<String> {
    let mut ret: Vec<String> = Vec::new();
    for route in routes {
        if route.is_absent()
            || !is_default_route(route)
            || matches!(
                route.route_type,
                Some(
                    RouteType::Blackhole
                        | RouteType::Unreachable
                        | RouteType::Prohibit
                )
            )
        {
            continue;
        }
        ret.push(format!(
            "{}|{}|{}|{}",
            route.next_hop_iface.as_deref().unwrap_or_default(),
            route.next_hop_addr.as_deref().unwrap_or_default(),
            route.metric.map(|m| m.to_string()).unwrap_or_default(),
            route.table_id.map(|t| t.to_string()).unwrap_or_default(),
        ));
    }
    ret.sort_unstable();
    ret.dedup();
    ret
}

/// Whether `route` targets the default destination of either address family.
fn is_default_route(route: &RouteEntry) -> bool {
    matches!(
        route.destination.as_deref(),
        Some(IPV4_DEFAULT_ROUTE) | Some(IPV6_DEFAULT_ROUTE)
    )
}

#[cfg(test)]
#[path = "unit_tests/dns_gateway.rs"]
mod unit_tests;
