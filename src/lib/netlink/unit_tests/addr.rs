// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rtnetlink::packet_route::{
    AddressFamily,
    address::{
        AddressAttribute, AddressFlags, AddressMessage, AddressProtocol,
        CacheInfo,
    },
};

use crate::{
    InterfaceIpv4, InterfaceIpv6,
    netlink::addr::{
        address_info, ipv4_from_address_infos, ipv6_from_address_infos,
        lifetime_to_string,
    },
};

fn ipv4_message(attributes: Vec<AddressAttribute>) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.prefix_len = 24;
    message.header.index = 3;
    message.attributes = attributes;
    message
}

fn ipv6_message(
    prefix_len: u8,
    attributes: Vec<AddressAttribute>,
) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet6;
    message.header.prefix_len = prefix_len;
    message.header.index = 3;
    message.attributes = attributes;
    message
}

fn cache_info(preferred: u32, valid: u32) -> AddressAttribute {
    AddressAttribute::CacheInfo(CacheInfo {
        ifa_preferred: preferred,
        ifa_valid: valid,
        ..Default::default()
    })
}

#[test]
fn test_parse_ipv4_static_address() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 10,
        ))),
        AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        cache_info(u32::MAX, u32::MAX),
    ]);
    let info = address_info(&message).unwrap();
    assert_eq!(info.iface_index, 3);
    assert_eq!(
        info.address.ip,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
    );
    assert_eq!(info.address.prefix_length, 24);
    assert_eq!(info.address.valid_life_time.as_deref(), Some("forever"));
    assert_eq!(
        info.address.preferred_life_time.as_deref(),
        Some("forever")
    );
}

#[test]
fn test_parse_ipv4_prefers_local_attribute() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
            198, 51, 100, 1,
        ))),
        AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 1,
        ))),
    ]);
    let info = address_info(&message).unwrap();
    assert_eq!(
        info.address.ip,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    );
}

#[test]
fn test_parse_ipv4_dynamic_lifetime() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 20,
        ))),
        cache_info(1800, 3600),
    ]);
    let info = address_info(&message).unwrap();
    assert_eq!(
        info.address.valid_life_time.as_deref(),
        Some("3600sec")
    );
    assert_eq!(
        info.address.preferred_life_time.as_deref(),
        Some("1800sec")
    );
}

#[test]
fn test_parse_ipv6_static_address() {
    let message = ipv6_message(
        64,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "2001:db8::10".parse::<Ipv6Addr>().unwrap(),
            )),
            cache_info(u32::MAX, u32::MAX),
        ],
    );
    let info = address_info(&message).unwrap();
    assert_eq!(
        info.address.ip,
        IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>().unwrap())
    );
    assert_eq!(info.address.prefix_length, 64);
    assert_eq!(info.address.valid_life_time.as_deref(), Some("forever"));
}

#[test]
fn test_parse_ipv6_local_attribute_uses_host_prefix() {
    let message = ipv6_message(
        64,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
            )),
            AddressAttribute::Local(IpAddr::V6(
                "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            )),
        ],
    );
    let info = address_info(&message).unwrap();
    assert_eq!(
        info.address.ip,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
    );
    assert_eq!(info.address.prefix_length, 128);
}

#[test]
fn test_parse_address_flags_and_protocol() {
    let message = ipv6_message(
        64,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "2001:db8::20".parse::<Ipv6Addr>().unwrap(),
            )),
            AddressAttribute::Flags(
                AddressFlags::Permanent | AddressFlags::Noprefixroute,
            ),
            AddressAttribute::Protocol(AddressProtocol::RouterAnnouncement),
        ],
    );
    let info = address_info(&message).unwrap();
    assert!(info.flags.contains(AddressFlags::Permanent));
    assert!(info.flags.contains(AddressFlags::Noprefixroute));
    assert_eq!(
        info.protocol,
        Some(AddressProtocol::RouterAnnouncement)
    );
}

#[test]
fn test_unsupported_address_family_is_skipped() {
    let mut message = ipv4_message(vec![]);
    message.header.family = AddressFamily::Bridge;
    assert_eq!(address_info(&message), None);
}

#[test]
fn test_lifetime_to_string() {
    assert_eq!(lifetime_to_string(u32::MAX), "forever");
    assert_eq!(lifetime_to_string(3600), "3600sec");
    assert_eq!(lifetime_to_string(0), "0sec");
}

#[test]
fn test_ipv4_conversion_static_address() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 10,
        ))),
        cache_info(u32::MAX, u32::MAX),
    ]);
    let info = address_info(&message).unwrap();
    let ipv4 = ipv4_from_address_infos([&info]).unwrap();
    assert_eq!(ipv4.enabled, Some(true));
    assert_eq!(ipv4.dhcp, Some(false));
    let addresses = ipv4.addresses.unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(
        addresses[0].ip,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
    );
    assert_eq!(addresses[0].prefix_length, 24);
    assert_eq!(addresses[0].valid_life_time, None);
    assert_eq!(addresses[0].preferred_life_time, None);
}

#[test]
fn test_ipv4_conversion_dhcp_address() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 20,
        ))),
        cache_info(1800, 3600),
    ]);
    let info = address_info(&message).unwrap();
    let ipv4 = ipv4_from_address_infos([&info]).unwrap();
    assert_eq!(ipv4.dhcp, Some(true));
    let addresses = ipv4.addresses.unwrap();
    assert_eq!(
        addresses[0].valid_life_time.as_deref(),
        Some("3600sec")
    );
    assert_eq!(
        addresses[0].preferred_life_time.as_deref(),
        Some("1800sec")
    );
}

#[test]
fn test_ipv6_conversion_static_address() {
    let message = ipv6_message(
        64,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "2001:db8::10".parse::<Ipv6Addr>().unwrap(),
            )),
            cache_info(u32::MAX, u32::MAX),
        ],
    );
    let info = address_info(&message).unwrap();
    let ipv6 = ipv6_from_address_infos([&info]).unwrap();
    assert_eq!(ipv6.enabled, Some(true));
    assert_eq!(ipv6.dhcp, Some(false));
    assert_eq!(ipv6.autoconf, Some(false));
    assert_eq!(ipv6.addresses.unwrap()[0].valid_life_time, None);
}

#[test]
fn test_ipv6_conversion_router_announcement() {
    let message = ipv6_message(
        64,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "2001:db8::20".parse::<Ipv6Addr>().unwrap(),
            )),
            AddressAttribute::Protocol(AddressProtocol::RouterAnnouncement),
            cache_info(u32::MAX, u32::MAX),
        ],
    );
    let info = address_info(&message).unwrap();
    let ipv6 = ipv6_from_address_infos([&info]).unwrap();
    assert_eq!(ipv6.autoconf, Some(true));
    assert_eq!(ipv6.dhcp, None);
}

#[test]
fn test_ipv6_conversion_dhcpv6_address() {
    let message = ipv6_message(
        128,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "2001:db8::30".parse::<Ipv6Addr>().unwrap(),
            )),
            cache_info(1800, 3600),
        ],
    );
    let info = address_info(&message).unwrap();
    let ipv6 = ipv6_from_address_infos([&info]).unwrap();
    assert_eq!(ipv6.dhcp, Some(true));
    assert_eq!(ipv6.autoconf, None);
}

#[test]
fn test_ipv6_conversion_link_local() {
    let message = ipv6_message(
        64,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "fe80::1".parse::<Ipv6Addr>().unwrap(),
            )),
            AddressAttribute::Protocol(AddressProtocol::LinkLocal),
            cache_info(u32::MAX, u32::MAX),
        ],
    );
    let info = address_info(&message).unwrap();
    let ipv6 = ipv6_from_address_infos([&info]).unwrap();
    assert_eq!(ipv6.dhcp, Some(false));
    assert_eq!(ipv6.autoconf, Some(false));
    assert_eq!(ipv6.addresses.unwrap()[0].prefix_length, 64);
}

#[test]
fn test_empty_address_lists_are_disabled() {
    let ipv4: InterfaceIpv4 =
        ipv4_from_address_infos(std::iter::empty()).unwrap();
    assert_eq!(ipv4.enabled, Some(false));
    let ipv6: InterfaceIpv6 =
        ipv6_from_address_infos(std::iter::empty()).unwrap();
    assert_eq!(ipv6.enabled, Some(false));
}

#[test]
fn test_address_maps_group_by_interface() {
    let mut message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 10,
        ))),
        cache_info(u32::MAX, u32::MAX),
    ]);
    let mut second = ipv6_message(
        64,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "2001:db8::10".parse::<Ipv6Addr>().unwrap(),
            )),
            cache_info(u32::MAX, u32::MAX),
        ],
    );
    second.header.index = 4;
    message.header.index = 3;

    let messages = vec![message, second];
    let ipv4_map = crate::netlink::addr::ipv4_map_from_messages(&messages);
    let ipv6_map = crate::netlink::addr::ipv6_map_from_messages(&messages);
    assert_eq!(ipv4_map.len(), 1);
    assert_eq!(
        ipv4_map[&3].addresses.as_ref().unwrap()[0].ip,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
    );
    assert_eq!(ipv6_map.len(), 1);
    assert_eq!(
        ipv6_map[&4].addresses.as_ref().unwrap()[0].ip,
        IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>().unwrap())
    );
}
