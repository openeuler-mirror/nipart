// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file are:
//  * Gris Ge <fge@redhat.com>
//  * Wen Liang <liangwen12year@gmail.com>
//  * Íñigo Huguet <ihuguet@redhat.com>

use crate::{
    MergedRouteRules, NipartError, RouteRuleEntry, RouteRules,
    netlink::rule::{
        apply_route_rules as netlink_apply_route_rules,
        get_route_rules as netlink_get_route_rules,
    },
};

pub(crate) async fn get_route_rules() -> Result<RouteRules, NipartError> {
    netlink_get_route_rules().await
}

pub(crate) async fn apply_route_rules(
    merged_rules: &MergedRouteRules,
) -> Result<(), NipartError> {
    if !merged_rules.is_changed() {
        log::debug!("Route rule is not changed");
        return Ok(());
    }

    let mut ordered_rules: Vec<RouteRuleEntry> =
        Vec::with_capacity(merged_rules.changed_rules.len());
    // Remove absent rules before adding new ones, so a rule replaced in a
    // single transaction never conflicts with its old entry.
    for rule in merged_rules
        .changed_rules
        .iter()
        .filter(|rule| rule.is_absent())
    {
        log::debug!("Removing route rule {rule}");
        ordered_rules.push(rule.clone());
    }
    for rule in merged_rules
        .changed_rules
        .iter()
        .filter(|rule| !rule.is_absent())
    {
        log::debug!("Adding route rule {rule}");
        ordered_rules.push(rule.clone());
    }

    netlink_apply_route_rules(&ordered_rules).await
}
