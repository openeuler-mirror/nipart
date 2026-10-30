// SPDX-License-Identifier: Apache-2.0

use rtnetlink::packet_route::{
    AddressFamily,
    route::RouteHeader,
    rule::{RuleAction, RuleAttribute, RuleHeader, RuleMessage},
};

use crate::{
    AddressFamily as NipartAddressFamily, ErrorKind, RouteRuleAction,
    RouteRuleEntry, RouteRuleState,
    netlink::rule::{
        route_rule_add_message, route_rule_del_message,
        route_rules_from_messages,
    },
};

fn rule_message(family: AddressFamily, action: RuleAction) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header = RuleHeader {
        family,
        action,
        table: 100,
        ..Default::default()
    };
    message
}

#[test]
fn test_route_rule_parse_ipv4() {
    let mut message = rule_message(AddressFamily::Inet, RuleAction::ToTable);
    message.header.src_len = 24;
    message.header.dst_len = 24;
    message.attributes = vec![
        RuleAttribute::Source("192.0.2.0".parse().unwrap()),
        RuleAttribute::Destination("198.51.100.0".parse().unwrap()),
        RuleAttribute::Priority(1000),
        RuleAttribute::FwMark(123),
        RuleAttribute::FwMask(255),
        RuleAttribute::Iifname("dummy0".to_string()),
        RuleAttribute::SuppressPrefixLen(10),
        RuleAttribute::Protocol(
            rtnetlink::packet_route::route::RouteProtocol::Boot,
        ),
    ];
    let rules = route_rules_from_messages([&message]);
    let rules = rules.config.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].family, Some(NipartAddressFamily::Ipv4));
    assert_eq!(rules[0].action, None);
    assert_eq!(rules[0].ip_from.as_deref(), Some("192.0.2.0/24"));
    assert_eq!(rules[0].ip_to.as_deref(), Some("198.51.100.0/24"));
    assert_eq!(rules[0].table_id, Some(100));
    assert_eq!(rules[0].priority, Some(1000));
    assert_eq!(rules[0].fwmark, Some(123));
    assert_eq!(rules[0].fwmask, Some(255));
    assert_eq!(rules[0].iif.as_deref(), Some("dummy0"));
    assert_eq!(rules[0].suppress_prefix_length, Some(10));
}

#[test]
fn test_route_rule_parse_ipv6_actions() {
    for (action, expected) in [
        (RuleAction::Blackhole, RouteRuleAction::Blackhole),
        (RuleAction::Unreachable, RouteRuleAction::Unreachable),
        (RuleAction::Prohibit, RouteRuleAction::Prohibit),
    ] {
        let mut message = rule_message(AddressFamily::Inet6, action);
        message.attributes = vec![RuleAttribute::Priority(2000)];
        let rules = route_rules_from_messages([&message]);
        let rules = rules.config.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].family, Some(NipartAddressFamily::Ipv6));
        assert_eq!(rules[0].action, Some(expected));
        assert_eq!(rules[0].priority, Some(2000));
    }
}

#[test]
fn test_route_rule_parse_table_attribute() {
    let mut message = rule_message(AddressFamily::Inet, RuleAction::ToTable);
    message.header.table = RouteHeader::RT_TABLE_UNSPEC;
    message.attributes =
        vec![RuleAttribute::Table(1000), RuleAttribute::Priority(1000)];
    let rules = route_rules_from_messages([&message]);
    assert_eq!(rules.config.unwrap()[0].table_id, Some(1000));

    message.attributes = vec![RuleAttribute::Priority(1000)];
    let rules = route_rules_from_messages([&message]);
    assert_eq!(rules.config.unwrap()[0].table_id, None);
}

#[test]
fn test_route_rule_parse_unsupported_action() {
    for action in [RuleAction::Goto, RuleAction::Nop, RuleAction::Unspec] {
        let message = rule_message(AddressFamily::Inet, action);
        let rules = route_rules_from_messages([&message]);
        assert!(rules.config.unwrap().is_empty());
    }
}

#[test]
fn test_route_rule_parse_protocol_filter() {
    let mut message = rule_message(AddressFamily::Inet, RuleAction::ToTable);
    message.attributes = vec![RuleAttribute::Protocol(
        rtnetlink::packet_route::route::RouteProtocol::Bgp,
    )];
    let rules = route_rules_from_messages([&message]);
    assert!(rules.config.unwrap().is_empty());

    message.attributes = vec![RuleAttribute::Protocol(
        rtnetlink::packet_route::route::RouteProtocol::Boot,
    )];
    let rules = route_rules_from_messages([&message]);
    assert_eq!(rules.config.unwrap().len(), 1);

    message.attributes = vec![RuleAttribute::Priority(1000)];
    let rules = route_rules_from_messages([&message]);
    assert_eq!(rules.config.unwrap().len(), 1);
}

#[test]
fn test_route_rule_parse_suppress_max_ignored() {
    let mut message = rule_message(AddressFamily::Inet, RuleAction::ToTable);
    message.attributes = vec![RuleAttribute::SuppressPrefixLen(u32::MAX)];
    let rules = route_rules_from_messages([&message]);
    assert_eq!(rules.config.unwrap()[0].suppress_prefix_length, None);
}

#[test]
fn test_route_rule_parse_sorts_and_dedups() {
    let message = rule_message(AddressFamily::Inet, RuleAction::ToTable);
    let duplicate = message.clone();
    let rules = route_rules_from_messages([&message, &duplicate]);
    assert_eq!(rules.config.unwrap().len(), 1);
}

#[test]
fn test_route_rule_add_message() {
    let rule = RouteRuleEntry {
        family: Some(NipartAddressFamily::Ipv4),
        ip_from: Some("192.0.2.0/24".to_string()),
        ip_to: Some("198.51.100.0/24".to_string()),
        priority: Some(1000),
        table_id: Some(100),
        fwmark: Some(123),
        fwmask: Some(255),
        iif: Some("dummy0".to_string()),
        suppress_prefix_length: Some(10),
        ..Default::default()
    };
    let message = route_rule_add_message(&rule).unwrap();
    assert_eq!(message.header.family, AddressFamily::Inet);
    assert_eq!(message.header.action, RuleAction::ToTable);
    assert_eq!(message.header.table, 100);
    assert_eq!(message.header.src_len, 24);
    assert_eq!(message.header.dst_len, 24);
    assert!(
        message
            .attributes
            .contains(&RuleAttribute::Source("192.0.2.0".parse().unwrap()))
    );
    assert!(message.attributes.contains(&RuleAttribute::Destination(
        "198.51.100.0".parse().unwrap()
    )));
    assert!(message.attributes.contains(&RuleAttribute::Priority(1000)));
    assert!(message.attributes.contains(&RuleAttribute::FwMark(123)));
    assert!(message.attributes.contains(&RuleAttribute::FwMask(255)));
    assert!(
        message
            .attributes
            .contains(&RuleAttribute::Iifname("dummy0".to_string()))
    );
    assert!(
        message
            .attributes
            .contains(&RuleAttribute::SuppressPrefixLen(10))
    );
}

#[test]
fn test_route_rule_add_message_actions() {
    for (action, expected) in [
        (RouteRuleAction::Blackhole, RuleAction::Blackhole),
        (RouteRuleAction::Unreachable, RuleAction::Unreachable),
        (RouteRuleAction::Prohibit, RuleAction::Prohibit),
    ] {
        let rule = RouteRuleEntry {
            action: Some(action),
            priority: Some(1000),
            ..Default::default()
        };
        let message = route_rule_add_message(&rule).unwrap();
        assert_eq!(message.header.action, expected);
        assert_eq!(message.header.table, RouteHeader::RT_TABLE_UNSPEC);
    }
}

#[test]
fn test_route_rule_add_message_ipv6() {
    let rule = RouteRuleEntry {
        family: Some(NipartAddressFamily::Ipv6),
        ip_from: Some("2001:db8::/64".to_string()),
        priority: Some(1000),
        table_id: Some(1000),
        ..Default::default()
    };
    let message = route_rule_add_message(&rule).unwrap();
    assert_eq!(message.header.family, AddressFamily::Inet6);
    assert_eq!(message.header.src_len, 64);
    assert!(message.attributes.contains(&RuleAttribute::Table(1000)));
}

#[test]
fn test_route_rule_del_message_wildcard() {
    let rule = RouteRuleEntry {
        state: Some(RouteRuleState::Absent),
        ip_from: Some("192.0.2.0/24".to_string()),
        priority: Some(1000),
        ..Default::default()
    };
    let message = route_rule_del_message(&rule).unwrap();
    assert_eq!(message.header.action, RuleAction::ToTable);
    assert_eq!(message.header.table, RouteHeader::RT_TABLE_MAIN);
    assert!(
        message
            .attributes
            .contains(&RuleAttribute::Source("192.0.2.0".parse().unwrap()))
    );
    assert!(message.attributes.contains(&RuleAttribute::Priority(1000)));
}

#[test]
fn test_route_rule_message_validation() {
    let rule = RouteRuleEntry {
        ip_from: Some("192.0.2.0/24".to_string()),
        ..Default::default()
    };
    let error = route_rule_add_message(&rule).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);

    let rule = RouteRuleEntry {
        ip_from: Some("192.0.2.0/24".to_string()),
        priority: Some(-1),
        ..Default::default()
    };
    let error = route_rule_add_message(&rule).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);

    let rule = RouteRuleEntry {
        family: Some(NipartAddressFamily::Ipv6),
        ip_from: Some("192.0.2.0/24".to_string()),
        priority: Some(1000),
        ..Default::default()
    };
    let error = route_rule_add_message(&rule).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);

    let rule = RouteRuleEntry {
        ip_from: Some("192.0.2.0/33".to_string()),
        priority: Some(1000),
        ..Default::default()
    };
    let error = route_rule_add_message(&rule).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
}
