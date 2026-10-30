// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use std::net::IpAddr;

use futures_util::TryStreamExt;
use rtnetlink::{
    IpVersion,
    packet_route::{
        AddressFamily,
        route::{RouteHeader, RouteProtocol as NetlinkRouteProtocol},
        rule::{RuleAction, RuleAttribute, RuleMessage},
    },
};

use crate::{
    AddressFamily as NipartAddressFamily, ErrorKind, NipartError,
    RouteRuleAction, RouteRuleEntry, RouteRules,
    netlink::{map_rtnetlink_error, new_connection},
};

// The kernel adds `ip rule` entries with protocol boot by default, while
// NetworkManager used protocol unspec historically.  Include both plus the
// static protocol when presenting rules as manageable configuration.
const SUPPORTED_STATIC_ROUTE_RULE_PROTOCOL: [NetlinkRouteProtocol; 3] = [
    NetlinkRouteProtocol::Boot,
    NetlinkRouteProtocol::Static,
    NetlinkRouteProtocol::Unspec,
];

pub(crate) fn route_rules_from_messages<'a>(
    messages: impl IntoIterator<Item = &'a RuleMessage>,
) -> RouteRules {
    let mut rules = Vec::new();
    for message in messages {
        let Some(rule) = route_rule_from_message(message) else {
            continue;
        };
        rules.push(rule);
    }
    rules.sort_unstable();
    rules.dedup();
    RouteRules {
        config: Some(rules),
    }
}

fn route_rule_from_message(message: &RuleMessage) -> Option<RouteRuleEntry> {
    let mut rule = RouteRuleEntry::new();
    match message.header.action {
        RuleAction::ToTable => (),
        RuleAction::Blackhole => rule.action = Some(RouteRuleAction::Blackhole),
        RuleAction::Unreachable => {
            rule.action = Some(RouteRuleAction::Unreachable)
        }
        RuleAction::Prohibit => rule.action = Some(RouteRuleAction::Prohibit),
        action => {
            log::debug!(
                "Got unsupported route rule action {action:?} in {message:?}"
            );
            return None;
        }
    }

    let mut protocol = None;
    for attribute in &message.attributes {
        match attribute {
            RuleAttribute::Protocol(value) => protocol = Some(*value),
            RuleAttribute::Source(source) => {
                rule.ip_from =
                    Some(format!("{source}/{}", message.header.src_len));
            }
            RuleAttribute::Destination(destination) => {
                rule.ip_to =
                    Some(format!("{destination}/{}", message.header.dst_len));
            }
            RuleAttribute::Iifname(iface) => {
                rule.iif = Some(iface.to_string());
            }
            RuleAttribute::Priority(priority) => {
                rule.priority = Some(i64::from(*priority));
            }
            RuleAttribute::FwMark(fwmark) => {
                rule.fwmark = Some(*fwmark);
            }
            RuleAttribute::FwMask(fwmask) => {
                rule.fwmask = Some(*fwmask);
            }
            RuleAttribute::SuppressPrefixLen(prefix_length) => {
                if *prefix_length != u32::MAX {
                    rule.suppress_prefix_length = Some(*prefix_length);
                }
            }
            RuleAttribute::Table(table) => {
                if *table > u32::from(RouteHeader::RT_TABLE_UNSPEC) {
                    rule.table_id = Some(*table);
                }
            }
            _ => {
                log::debug!("Unknown NLA message for route rule {attribute:?}")
            }
        }
    }

    if let Some(protocol) = protocol
        && !SUPPORTED_STATIC_ROUTE_RULE_PROTOCOL.contains(&protocol)
    {
        log::debug!(
            "Skipping route rule with unsupported protocol {protocol:?}: \
             {message:?}"
        );
        return None;
    }
    if rule.table_id.is_none()
        && message.header.table > RouteHeader::RT_TABLE_UNSPEC
    {
        rule.table_id = Some(u32::from(message.header.table));
    }

    rule.family = match message.header.family {
        AddressFamily::Inet => Some(NipartAddressFamily::Ipv4),
        AddressFamily::Inet6 => Some(NipartAddressFamily::Ipv6),
        family => {
            log::warn!("Unsupported route rule family {family:?}");
            None
        }
    };
    Some(rule)
}

