// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rtnetlink::packet_route::{
    AddressFamily,
    address::{
        AddressAttribute, AddressMessage, AddressProtocol, CacheInfo,
    },
};

use super::parity::{ipv4_from_nispor_json, ipv6_from_nispor_json};
use crate::{
    InterfaceIpv4, InterfaceIpv6,
    netlink::addr::{address_info, ipv4_from_address_infos, ipv6_from_address_infos},
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

fn ipv4_message(
    address: Ipv4Addr,
    prefix_len: u8,
    preferred: u32,
    valid: u32,
) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.prefix_len = prefix_len;
    message.header.index = 3;
    message.attributes = vec![
        AddressAttribute::Address(IpAddr::V4(address)),
        AddressAttribute::Local(IpAddr::V4(address)),
        AddressAttribute::CacheInfo(CacheInfo {
            ifa_preferred: preferred,
            ifa_valid: valid,
            ..Default::default()
        }),
    ];
    message
}

fn ipv6_message(
    address: Ipv6Addr,
    prefix_len: u8,
    preferred: u32,
    valid: u32,
    protocol: Option<AddressProtocol>,
) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet6;
    message.header.prefix_len = prefix_len;
    message.header.index = 3;
    message.attributes = vec![
        AddressAttribute::Address(IpAddr::V6(address)),
        AddressAttribute::CacheInfo(CacheInfo {
            ifa_preferred: preferred,
            ifa_valid: valid,
            ..Default::default()
        }),
    ];
    if let Some(protocol) = protocol {
        message
            .attributes
            .push(AddressAttribute::Protocol(protocol));
    }
    message
}

fn new_ipv4(message: &AddressMessage) -> Option<InterfaceIpv4> {
    let info = address_info(message)?;
    ipv4_from_address_infos([&info])
}

fn new_ipv6(message: &AddressMessage) -> Option<InterfaceIpv6> {
    let info = address_info(message)?;
    ipv6_from_address_infos([&info])
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
    let message = ipv4_message(
        Ipv4Addr::new(192, 0, 2, 10),
        24,
        u32::MAX,
        u32::MAX,
    );
    assert_eq!(new_ipv4(&message), ipv4_from_nispor_json(&json));
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
    let message = ipv4_message(
        Ipv4Addr::new(192, 0, 2, 20),
        24,
        1800,
        3600,
    );
    assert_eq!(new_ipv4(&message), ipv4_from_nispor_json(&json));
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
    let message = ipv6_message(
        "2001:db8::10".parse().unwrap(),
        64,
        u32::MAX,
        u32::MAX,
        None,
    );
    assert_eq!(new_ipv6(&message), ipv6_from_nispor_json(&json));
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
    let message = ipv6_message(
        "2001:db8::20".parse().unwrap(),
        64,
        u32::MAX,
        u32::MAX,
        Some(AddressProtocol::RouterAnnouncement),
    );
    assert_eq!(new_ipv6(&message), ipv6_from_nispor_json(&json));
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
    let message = ipv6_message(
        "2001:db8::30".parse().unwrap(),
        128,
        1800,
        3600,
        None,
    );
    assert_eq!(new_ipv6(&message), ipv6_from_nispor_json(&json));
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
    let message = ipv6_message(
        "fe80::1".parse().unwrap(),
        64,
        u32::MAX,
        u32::MAX,
        Some(AddressProtocol::LinkLocal),
    );
    assert_eq!(new_ipv6(&message), ipv6_from_nispor_json(&json));
}
