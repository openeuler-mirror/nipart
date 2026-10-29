// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use super::parity::{
    ipv4_from_nispor_json, ipv6_from_nispor_json,
    route_entry_for_type_from_nispor_json, route_entry_from_nispor_json,
    route_rules_from_nispor_json, route_rules_from_nispor_json_array,
};
use crate::{
    AddressFamily, InterfaceIpAddr, InterfaceIpv4, InterfaceIpv6, RouteEntry,
    RouteRuleAction, RouteRuleEntry, RouteType, schema::RouteProtocol,
};

const BASE_IFACE: &str = r#""name": "dummy0",
    "index": 3,
    "type": "dummy",
    "state": "up",
    "mtu": 1500,
    "flags": ["up"],
    "alt-names": [],
    "mac-address": "02:00:00:00:00:01",
    "permanent-mac-address": """#;

fn iface_with_ip(ip_field: &str) -> String {
    format!("{{{BASE_IFACE}, {ip_field}}}")
}

fn ipv4_addr(
    address: &str,
    prefix_length: u8,
    valid_life_time: Option<&str>,
    preferred_life_time: Option<&str>,
) -> InterfaceIpAddr {
    InterfaceIpAddr {
        ip: address.parse::<IpAddr>().unwrap(),
        prefix_length,
        valid_life_time: valid_life_time.map(str::to_string),
        preferred_life_time: preferred_life_time.map(str::to_string),
    }
}

#[test]
fn test_ipv4_static_parity() {
    let json = iface_with_ip(
        r#""ipv4": {
            "addresses": [{
                "address": "192.0.2.10",
                "prefix-len": 24,
                "scope": "universe",
                "valid-lft": "forever",
                "preferred-lft": "forever",
                "flags": []
            }]
        }"#,
    );
    let expected = InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(false),
        addresses: Some(vec![ipv4_addr("192.0.2.10", 24, None, None)]),
        ..Default::default()
    };
    assert_eq!(ipv4_from_nispor_json(&json), Some(expected));
}

#[test]
fn test_ipv4_dhcp_parity() {
    let json = iface_with_ip(
        r#""ipv4": {
            "addresses": [{
                "address": "192.0.2.20",
                "prefix-len": 24,
                "scope": "universe",
                "valid-lft": "3600sec",
                "preferred-lft": "1800sec",
                "flags": []
            }]
        }"#,
    );
    let expected = InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(true),
        addresses: Some(vec![ipv4_addr(
            "192.0.2.20",
            24,
            Some("3600sec"),
            Some("1800sec"),
        )]),
        ..Default::default()
    };
    assert_eq!(ipv4_from_nispor_json(&json), Some(expected));
}

#[test]
fn test_ipv6_static_parity() {
    let json = iface_with_ip(
        r#""ipv6": {
            "addresses": [{
                "address": "2001:db8::10",
                "prefix-len": 64,
                "scope": "universe",
                "valid-lft": "forever",
                "preferred-lft": "forever",
                "flags": []
            }]
        }"#,
    );
    let expected = InterfaceIpv6 {
        enabled: Some(true),
        dhcp: Some(false),
        autoconf: Some(false),
        addresses: Some(vec![ipv4_addr("2001:db8::10", 64, None, None)]),
        ..Default::default()
    };
    assert_eq!(ipv6_from_nispor_json(&json), Some(expected));
}

#[test]
fn test_ipv6_slaac_parity() {
    let json = iface_with_ip(
        r#""ipv6": {
            "addresses": [{
                "address": "2001:db8::20",
                "prefix-len": 64,
                "scope": "universe",
                "valid-lft": "forever",
                "preferred-lft": "forever",
                "flags": [],
                "protocol": "ra"
            }]
        }"#,
    );
    let expected = InterfaceIpv6 {
        enabled: Some(true),
        dhcp: None,
        autoconf: Some(true),
        addresses: Some(vec![ipv4_addr("2001:db8::20", 64, None, None)]),
        ..Default::default()
    };
    assert_eq!(ipv6_from_nispor_json(&json), Some(expected));
}

#[test]
fn test_ipv6_dhcpv6_parity() {
    let json = iface_with_ip(
        r#""ipv6": {
            "addresses": [{
                "address": "2001:db8::30",
                "prefix-len": 128,
                "scope": "universe",
                "valid-lft": "3600sec",
                "preferred-lft": "1800sec",
                "flags": []
            }]
        }"#,
    );
    let expected = InterfaceIpv6 {
        enabled: Some(true),
        dhcp: Some(true),
        autoconf: None,
        addresses: Some(vec![ipv4_addr(
            "2001:db8::30",
            128,
            Some("3600sec"),
            Some("1800sec"),
        )]),
        ..Default::default()
    };
    assert_eq!(ipv6_from_nispor_json(&json), Some(expected));
}

#[test]
fn test_ipv6_link_local_parity() {
    let json = iface_with_ip(
        r#""ipv6": {
            "addresses": [{
                "address": "fe80::1",
                "prefix-len": 64,
                "scope": "link",
                "valid-lft": "forever",
                "preferred-lft": "forever",
                "flags": [],
                "protocol": "kernel_ll"
            }]
        }"#,
    );
    let expected = InterfaceIpv6 {
        enabled: Some(true),
        dhcp: Some(false),
        autoconf: Some(false),
        addresses: Some(vec![ipv4_addr("fe80::1", 64, None, None)]),
        ..Default::default()
    };
    assert_eq!(ipv6_from_nispor_json(&json), Some(expected));
}

#[test]
fn test_ipv4_route_parity() {
    let route = route_entry_from_nispor_json(
        r#"{
            "address-family": "ipv4",
            "tos": 0,
            "table": 100,
            "protocol": "static",
            "scope": "universe",
            "route-type": "unicast",
            "flags": ["onlink"],
            "dst": "198.51.100.0/24",
            "oif": "dummy0",
            "gateway": "192.0.2.1",
            "prefered-src": "192.0.2.10",
            "metric": 100,
            "lock": 128,
            "cwnd": 20,
            "initcwnd": 10,
            "initrwnd": 20,
            "mtu": 1400,
            "quickack": 1,
            "advmss": 1360
        }"#,
    );
    assert_eq!(
        route,
        RouteEntry {
            destination: Some("198.51.100.0/24".to_string()),
            next_hop_iface: Some("dummy0".to_string()),
            next_hop_addr: Some("192.0.2.1".to_string()),
            source: Some("192.0.2.10".to_string()),
            metric: Some(100),
            table_id: Some(100),
            cwnd: Some(20),
            initcwnd: Some(10),
            initrwnd: Some(20),
            mtu: Some(1400),
            quickack: Some(true),
            advmss: Some(1360),
            onlink: Some(true),
            protocol: Some(RouteProtocol::Static),
            ..Default::default()
        }
    );
}

#[test]
fn test_ipv6_default_route_parity() {
    let route = route_entry_from_nispor_json(
        r#"{
            "address-family": "ipv6",
            "tos": 0,
            "table": 254,
            "protocol": "ra",
            "scope": "universe",
            "route-type": "unicast",
            "flags": [],
            "oif": "dummy0",
            "gateway": "fe80::1",
            "metric": 1024
        }"#,
    );
    assert_eq!(
        route,
        RouteEntry {
            destination: Some("::/0".to_string()),
            next_hop_iface: Some("dummy0".to_string()),
            next_hop_addr: Some("fe80::1".to_string()),
            metric: Some(1024),
            table_id: Some(254),
            protocol: Some(RouteProtocol::Ra),
            ..Default::default()
        }
    );
}

#[test]
fn test_route_type_parity() {
    let cases = [
        ("black-hole", RouteType::Blackhole, "203.0.113.0/24"),
        ("unreachable", RouteType::Unreachable, "198.51.100.0/24"),
        ("prohibit", RouteType::Prohibit, "192.0.2.0/24"),
    ];
    for (json_route_type, expected_type, destination) in cases {
        let json = format!(
            r#"{{
                "address-family": "ipv4",
                "tos": 0,
                "table": 254,
                "protocol": "boot",
                "scope": "universe",
                "route-type": "{json_route_type}",
                "flags": [],
                "dst": "{destination}",
                "metric": 50
            }}"#
        );
        let route = route_entry_for_type_from_nispor_json(&json);
        assert_eq!(
            route,
            RouteEntry {
                destination: Some(destination.to_string()),
                metric: Some(50),
                table_id: Some(254),
                route_type: Some(expected_type),
                protocol: Some(RouteProtocol::Boot),
                ..Default::default()
            }
        );
    }
}

#[test]
fn test_route_rule_parity() {
    let rules = route_rules_from_nispor_json_array(
        r#"[{
            "action": "blackhole",
            "address-family": "ipv4",
            "flags": [],
            "tos": 0,
            "table": 100,
            "src": "192.0.2.0/24",
            "dst": "198.51.100.0/24",
            "iif": "dummy0",
            "priority": 1000,
            "fw-mark": 123,
            "fw-mask": 255,
            "suppress-prefix-len": 10
        }, {
            "action": "table",
            "address-family": "ipv6",
            "flags": [],
            "tos": 0,
            "table": 254,
            "src": "2001:db8:2::/64",
            "dst": "2001:db8:1::/64",
            "priority": 2000
        }]"#,
    );
    let rules = rules.config.unwrap();
    let expected_v4 = RouteRuleEntry {
        family: Some(AddressFamily::Ipv4),
        action: Some(RouteRuleAction::Blackhole),
        ip_from: Some("192.0.2.0/24".to_string()),
        ip_to: Some("198.51.100.0/24".to_string()),
        iif: Some("dummy0".to_string()),
        priority: Some(1000),
        table_id: Some(100),
        fwmark: Some(123),
        fwmask: Some(255),
        suppress_prefix_length: Some(10),
        ..Default::default()
    };
    let expected_v6 = RouteRuleEntry {
        family: Some(AddressFamily::Ipv6),
        ip_from: Some("2001:db8:2::/64".to_string()),
        ip_to: Some("2001:db8:1::/64".to_string()),
        priority: Some(2000),
        table_id: Some(254),
        ..Default::default()
    };
    assert!(rules.contains(&expected_v4));
    assert!(rules.contains(&expected_v6));
}

#[test]
fn test_route_rule_single_fixture_helper() {
    let rules = route_rules_from_nispor_json(
        r#"{
            "action": "table",
            "address-family": "ipv4",
            "flags": [],
            "tos": 0,
            "table": 100,
            "priority": 1000
        }"#,
    );
    assert_eq!(rules.config.unwrap().len(), 1);
}
