// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use super::parity::{ipv4_from_nispor_json, ipv6_from_nispor_json};
use crate::{InterfaceIpAddr, InterfaceIpv4, InterfaceIpv6};

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
