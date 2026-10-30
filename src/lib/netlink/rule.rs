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

pub(crate) async fn get_route_rules() -> Result<RouteRules, NipartError> {
    let handle = new_connection().await?;
    let mut messages = Vec::new();
    for ip_version in [IpVersion::V6, IpVersion::V4] {
        let mut stream = handle.rule().get(ip_version).execute();
        while let Some(message) = stream.try_next().await.map_err(|e| {
            map_rtnetlink_error("Failed to dump kernel route rules", e)
        })? {
            messages.push(message);
        }
    }
    Ok(route_rules_from_messages(&messages))
}

pub(crate) fn route_rule_add_message(
    rule: &RouteRuleEntry,
) -> Result<RuleMessage, NipartError> {
    route_rule_message(rule)
}

pub(crate) fn route_rule_del_message(
    rule: &RouteRuleEntry,
) -> Result<RuleMessage, NipartError> {
    route_rule_message(rule)
}

fn route_rule_message(
    rule: &RouteRuleEntry,
) -> Result<RuleMessage, NipartError> {
    let Some(priority) = rule.priority else {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!("Route rule {rule} has no priority defined"),
        ));
    };
    let priority = u32::try_from(priority).map_err(|_| {
        NipartError::new(
            ErrorKind::InvalidArgument,
            format!(
                "Invalid route rule priority {priority}, expecting a \
                 non-negative integer no greater than {}",
                u32::MAX
            ),
        )
    })?;

    let family = if rule.is_ipv6() {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    let action = match rule.action {
        Some(RouteRuleAction::Blackhole) => RuleAction::Blackhole,
        Some(RouteRuleAction::Unreachable) => RuleAction::Unreachable,
        Some(RouteRuleAction::Prohibit) => RuleAction::Prohibit,
        None => RuleAction::ToTable,
    };

    let mut message = RuleMessage::default();
    message.header.family = family;
    message.header.action = action;

    if let Some(table_id) = rule
        .table_id
        .filter(|table_id| *table_id != RouteRuleEntry::USE_DEFAULT_ROUTE_TABLE)
    {
        if table_id <= u8::MAX.into() {
            message.header.table = table_id as u8;
        } else {
            message.attributes.push(RuleAttribute::Table(table_id));
        }
    } else if action == RuleAction::ToTable {
        message.header.table = RouteHeader::RT_TABLE_MAIN;
    }

    if let Some(source) = rule.ip_from.as_deref() {
        let (address, prefix_length) = parse_rule_network(source, family)?;
        message.header.src_len = prefix_length;
        message.attributes.push(RuleAttribute::Source(address));
    }
    if let Some(destination) = rule.ip_to.as_deref() {
        let (address, prefix_length) = parse_rule_network(destination, family)?;
        message.header.dst_len = prefix_length;
        message.attributes.push(RuleAttribute::Destination(address));
    }
    message.attributes.push(RuleAttribute::Priority(priority));
    if let Some(fwmark) = rule.fwmark {
        message.attributes.push(RuleAttribute::FwMark(fwmark));
    }
    if let Some(fwmask) = rule.fwmask {
        message.attributes.push(RuleAttribute::FwMask(fwmask));
    }
    if let Some(iif) = rule.iif.as_deref() {
        message
            .attributes
            .push(RuleAttribute::Iifname(iif.to_string()));
    }
    if let Some(prefix_length) = rule.suppress_prefix_length {
        message
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(prefix_length));
    }
    Ok(message)
}

fn parse_rule_network(
    ip_net: &str,
    family: AddressFamily,
) -> Result<(IpAddr, u8), NipartError> {
    let splits: Vec<&str> = ip_net.split('/').collect();
    if splits.len() > 2 || splits.is_empty() {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!("Invalid route rule network {ip_net}"),
        ));
    }
    let address = splits[0].parse::<IpAddr>().map_err(|e| {
        NipartError::new(
            ErrorKind::InvalidArgument,
            format!("Invalid route rule network {ip_net}: {e}"),
        )
    })?;
    let prefix_length = if let Some(prefix_length) = splits.get(1) {
        prefix_length.parse::<u8>().map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid route rule network {ip_net}: {e}"),
            )
        })?
    } else if address.is_ipv6() {
        128
    } else {
        32
    };
    if address.is_ipv6() != (family == AddressFamily::Inet6) {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!(
                "Route rule network {ip_net} does not match the address family"
            ),
        ));
    }
    let max_prefix_length = if address.is_ipv6() { 128 } else { 32 };
    if prefix_length > max_prefix_length {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!(
                "Invalid route rule network {ip_net}: prefix length should be \
                 no greater than {max_prefix_length}"
            ),
        ));
    }
    Ok((address, prefix_length))
}

