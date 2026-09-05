// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file are:
//  * Gris Ge <fge@redhat.com>
//  * Wen Liang <liangwen12year@gmail.com>
//  * Íñigo Huguet <ihuguet@redhat.com>

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    AddressFamily, NipartError, RouteRuleAction, RouteRuleEntry, RouteRules,
};

// The kernel adds `ip rule` entries with protocol boot by default, while
// NetworkManager used protocol unspec historically.  Include both plus the
// static protocol when presenting rules as manageable configuration.
const SUPPORTED_STATIC_ROUTE_RULE_PROTOCOL: [nispor::RouteProtocol; 3] = [
    nispor::RouteProtocol::Boot,
    nispor::RouteProtocol::Static,
    nispor::RouteProtocol::Unspec,
];

pub(crate) fn get_route_rules(np_rules: &[nispor::RouteRule]) -> RouteRules {
    let mut rules = Vec::new();
    for np_rule in np_rules {
        let mut rule = RouteRuleEntry::new();
        match np_rule.action {
            nispor::RuleAction::Table => (),
            nispor::RuleAction::Blackhole => {
                rule.action = Some(RouteRuleAction::Blackhole)
            }
            nispor::RuleAction::Unreachable => {
                rule.action = Some(RouteRuleAction::Unreachable)
            }
            nispor::RuleAction::Prohibit => {
                rule.action = Some(RouteRuleAction::Prohibit)
            }
            _ => {
                log::debug!("Got unsupported route rule {np_rule:?}");
                continue;
            }
        }
        if let Some(rule_protocol) = np_rule.protocol.as_ref()
            && !SUPPORTED_STATIC_ROUTE_RULE_PROTOCOL.contains(rule_protocol)
        {
            continue;
        }
        rule.iif.clone_from(&np_rule.iif);
        rule.ip_to.clone_from(&np_rule.dst);
        rule.ip_from.clone_from(&np_rule.src);
        rule.table_id = np_rule.table;
        rule.priority = np_rule.priority.map(i64::from);
        rule.fwmark = np_rule.fw_mark;
        rule.fwmask = np_rule.fw_mask;
        rule.suppress_prefix_length = np_rule.suppress_prefix_len;
        rule.family = match np_rule.address_family {
            nispor::AddressFamily::Ipv4 => Some(AddressFamily::Ipv4),
            nispor::AddressFamily::Ipv6 => Some(AddressFamily::Ipv6),
            _ => {
                log::warn!(
                    "Unsupported route rule family {:?}",
                    np_rule.address_family
                );
                None
            }
        };
        rules.push(rule);
    }
    rules.sort_unstable();
    rules.dedup();
    RouteRules {
        config: Some(rules),
    }
}

pub(crate) async fn apply_route_rules(
    merged_rules: &crate::MergedRouteRules,
) -> Result<(), NipartError> {
    if !merged_rules.is_changed() {
        log::debug!("Route rule is not changed");
        return Ok(());
    }

    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| {
        NipartError::new(
            crate::ErrorKind::Bug,
            format!("Failed to create rtnetlink connection: {e}"),
        )
    })?;
    tokio::spawn(connection);

    for rule in merged_rules
        .changed_rules
        .iter()
        .filter(|rule| rule.is_absent())
    {
        log::debug!("Removing route rule {rule}");
        let msg = nipart_rule_to_netlink_rule(rule)?;
        handle.rule().del(msg).execute().await.map_err(|e| {
            NipartError::new(
                crate::ErrorKind::Bug,
                format!("Failed to remove route rule {rule}: {e}"),
            )
        })?;
    }

    for rule in merged_rules
        .changed_rules
        .iter()
        .filter(|rule| !rule.is_absent())
    {
        log::debug!("Adding route rule {rule}");
        let msg = nipart_rule_to_netlink_rule(rule)?;
        let mut add_request = handle.rule().add();
        *add_request.message_mut() = msg;
        add_request.execute().await.map_err(|e| {
            NipartError::new(
                crate::ErrorKind::Bug,
                format!("Failed to add route rule {rule}: {e}"),
            )
        })?;
    }

    Ok(())
}

fn nipart_rule_to_netlink_rule(
    rule: &RouteRuleEntry,
) -> Result<rtnetlink::packet_route::rule::RuleMessage, NipartError> {
    use rtnetlink::packet_route::{
        AddressFamily as NlAddressFamily,
        route::RouteHeader,
        rule::{RuleAction, RuleAttribute, RuleMessage},
    };
    let is_ipv6 = rule.is_ipv6();
    let family = if is_ipv6 {
        NlAddressFamily::Inet6
    } else {
        NlAddressFamily::Inet
    };

    let mut msg = RuleMessage::default();
    msg.header.family = family;
    msg.header.action = match rule.action {
        Some(RouteRuleAction::Blackhole) => RuleAction::Blackhole,
        Some(RouteRuleAction::Unreachable) => RuleAction::Unreachable,
        Some(RouteRuleAction::Prohibit) => RuleAction::Prohibit,
        None => RuleAction::ToTable,
    };

    if let Some(table_id) = rule.table_id {
        if table_id <= u8::MAX.into() {
            msg.header.table = table_id as u8;
        } else {
            msg.attributes.push(RuleAttribute::Table(table_id));
        }
    } else if msg.header.action == RuleAction::ToTable {
        msg.header.table = RouteHeader::RT_TABLE_MAIN;
    }

    if let Some(ip_from) = rule.ip_from.as_ref() {
        let (ip, prefix_len) = parse_ip_network(ip_from, is_ipv6)?;
        msg.header.src_len = prefix_len;
        msg.attributes.push(RuleAttribute::Source(ip));
    }
    if let Some(ip_to) = rule.ip_to.as_ref() {
        let (ip, prefix_len) = parse_ip_network(ip_to, is_ipv6)?;
        msg.header.dst_len = prefix_len;
        msg.attributes.push(RuleAttribute::Destination(ip));
    }
    if let Some(priority) = rule.priority {
        let priority = u32::try_from(priority).map_err(|_| {
            NipartError::new(
                crate::ErrorKind::InvalidArgument,
                format!(
                    "Invalid route rule priority {priority}, expecting a \
                     non-negative integer"
                ),
            )
        })?;
        msg.attributes.push(RuleAttribute::Priority(priority));
    }
    if let Some(fwmark) = rule.fwmark {
        msg.attributes.push(RuleAttribute::FwMark(fwmark));
    }
    if let Some(fwmask) = rule.fwmask {
        msg.attributes.push(RuleAttribute::FwMask(fwmask));
    }
    if let Some(iif) = rule.iif.as_ref() {
        msg.attributes.push(RuleAttribute::Iifname(iif.clone()));
    }
    if let Some(suppress_prefix_length) = rule.suppress_prefix_length {
        msg.attributes
            .push(RuleAttribute::SuppressPrefixLen(suppress_prefix_length));
    }

    Ok(msg)
}

fn parse_ip_network(
    ip_net: &str,
    expect_ipv6: bool,
) -> Result<(IpAddr, u8), NipartError> {
    let (ip, prefix_len) = ip_net.rsplit_once('/').ok_or_else(|| {
        NipartError::new(
            crate::ErrorKind::InvalidArgument,
            format!("Invalid route rule network '{ip_net}'"),
        )
    })?;
    let prefix_len = prefix_len.parse::<u8>().map_err(|e| {
        NipartError::new(
            crate::ErrorKind::InvalidArgument,
            format!("Invalid route rule prefix length '{prefix_len}': {e}"),
        )
    })?;
    let ip = if expect_ipv6 {
        IpAddr::V6(ip.parse::<Ipv6Addr>().map_err(|e| {
            NipartError::new(
                crate::ErrorKind::InvalidArgument,
                format!("Invalid IPv6 route rule network '{ip_net}': {e}"),
            )
        })?)
    } else {
        IpAddr::V4(ip.parse::<Ipv4Addr>().map_err(|e| {
            NipartError::new(
                crate::ErrorKind::InvalidArgument,
                format!("Invalid IPv4 route rule network '{ip_net}': {e}"),
            )
        })?)
    };
    Ok((ip, prefix_len))
}
