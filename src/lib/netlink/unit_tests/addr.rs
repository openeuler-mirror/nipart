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
    let mut cache_info = CacheInfo::default();
    cache_info.ifa_preferred = preferred;
    cache_info.ifa_valid = valid;
    AddressAttribute::CacheInfo(cache_info)
}

#[test]
fn test_parse_ipv4_static_address() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        cache_info(u32::MAX, u32::MAX),
    ]);
    let info = address_info(&message).unwrap();
    assert_eq!(info.iface_index, 3);
    assert_eq!(info.address.ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(info.address.prefix_length, 24);
    assert_eq!(info.address.valid_life_time.as_deref(), Some("forever"));
    assert_eq!(info.address.preferred_life_time.as_deref(), Some("forever"));
}

#[test]
fn test_parse_ipv4_prefers_local_attribute() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
        AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
    ]);
    let info = address_info(&message).unwrap();
    assert_eq!(info.address.ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
}

#[test]
fn test_parse_ipv4_dynamic_lifetime() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))),
        cache_info(1800, 3600),
    ]);
    let info = address_info(&message).unwrap();
    assert_eq!(info.address.valid_life_time.as_deref(), Some("3600sec"));
    assert_eq!(info.address.preferred_life_time.as_deref(), Some("1800sec"));
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
    assert_eq!(info.protocol, Some(AddressProtocol::RouterAnnouncement));
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
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        cache_info(u32::MAX, u32::MAX),
    ]);
    let info = address_info(&message).unwrap();
    let ipv4 = ipv4_from_address_infos([&info]).unwrap();
    assert_eq!(ipv4.enabled, Some(true));
    assert_eq!(ipv4.dhcp, Some(false));
    let addresses = ipv4.addresses.unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(addresses[0].prefix_length, 24);
    assert_eq!(addresses[0].valid_life_time, None);
    assert_eq!(addresses[0].preferred_life_time, None);
}

#[test]
fn test_ipv4_conversion_dhcp_address() {
    let message = ipv4_message(vec![
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))),
        cache_info(1800, 3600),
    ]);
    let info = address_info(&message).unwrap();
    let ipv4 = ipv4_from_address_infos([&info]).unwrap();
    assert_eq!(ipv4.dhcp, Some(true));
    let addresses = ipv4.addresses.unwrap();
    assert_eq!(addresses[0].valid_life_time.as_deref(), Some("3600sec"));
    assert_eq!(addresses[0].preferred_life_time.as_deref(), Some("1800sec"));
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
        AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
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

#[test]
fn test_address_add_message_static_ipv4() {
    let address = crate::InterfaceIpAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        24,
    );
    let message =
        crate::netlink::addr::address_add_message(7, &address, None).unwrap();
    assert_eq!(message.header.family, AddressFamily::Inet);
    assert_eq!(message.header.index, 7);
    assert_eq!(message.header.prefix_len, 24);
    assert!(matches!(
        message.attributes.as_slice(),
        [
            AddressAttribute::Address(_),
            AddressAttribute::Local(_),
            AddressAttribute::Broadcast(_),
        ]
    ));
}

#[test]
fn test_address_add_message_dynamic_ipv6() {
    let mut address = crate::InterfaceIpAddr::new(
        IpAddr::V6("2001:db8::30".parse::<Ipv6Addr>().unwrap()),
        128,
    );
    address.valid_life_time = Some("3600sec".to_string());
    address.preferred_life_time = Some("1800sec".to_string());
    let message = crate::netlink::addr::address_add_message(
        7,
        &address,
        Some(AddressProtocol::RouterAnnouncement),
    )
    .unwrap();
    assert_eq!(message.header.family, AddressFamily::Inet6);
    assert!(message.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            AddressAttribute::Protocol(AddressProtocol::RouterAnnouncement)
        )
    }));
    let cache_info = message
        .attributes
        .iter()
        .find_map(|attribute| {
            if let AddressAttribute::CacheInfo(cache_info) = attribute {
                Some(*cache_info)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(cache_info.ifa_valid, 3600);
    assert_eq!(cache_info.ifa_preferred, 1800);
}

#[test]
fn test_address_add_message_rejects_invalid_prefix() {
    let address = crate::InterfaceIpAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        64,
    );
    let error = crate::netlink::addr::address_add_message(7, &address, None)
        .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
}

#[test]
fn test_address_delete_message_ipv6() {
    let address = crate::InterfaceIpAddr::new(
        IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
        64,
    );
    let message = crate::netlink::addr::address_del_message(
        7,
        &address,
        Some(AddressProtocol::LinkLocal),
    )
    .unwrap();
    assert_eq!(message.header.family, AddressFamily::Inet6);
    assert_eq!(message.header.index, 7);
    assert_eq!(message.header.prefix_len, 64);
    assert_eq!(
        message.attributes,
        vec![
            AddressAttribute::Address(IpAddr::V6(
                "fe80::1".parse::<Ipv6Addr>().unwrap()
            )),
            AddressAttribute::Protocol(AddressProtocol::LinkLocal),
        ]
    );
}

#[test]
fn test_address_delete_message_rejects_invalid_prefix() {
    let address = crate::InterfaceIpAddr::new(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        129,
    );
    let error = crate::netlink::addr::address_del_message(7, &address, None)
        .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
}

#[test]
fn test_address_add_message_permanent_lifetime_has_no_cache_info() {
    let mut address = crate::InterfaceIpAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
        24,
    );
    address.valid_life_time = Some("forever".to_string());
    address.preferred_life_time = Some("forever".to_string());
    let message =
        crate::netlink::addr::address_add_message(7, &address, None).unwrap();
    assert!(
        !message.attributes.iter().any(|attribute| matches!(
            attribute,
            AddressAttribute::CacheInfo(_)
        ))
    );
}

fn iface_with_ipv4(ipv4: InterfaceIpv4) -> crate::BaseInterface {
    let mut iface = crate::BaseInterface::new(
        "eth0".to_string(),
        crate::InterfaceType::Ethernet,
    );
    iface.ipv4 = Some(ipv4);
    iface
}

fn iface_with_ipv6(ipv6: InterfaceIpv6) -> crate::BaseInterface {
    let mut iface = crate::BaseInterface::new(
        "eth0".to_string(),
        crate::InterfaceType::Ethernet,
    );
    iface.ipv6 = Some(ipv6);
    iface
}

fn addr(ip: &str, prefix_length: u8) -> crate::InterfaceIpAddr {
    crate::InterfaceIpAddr::new(ip.parse().unwrap(), prefix_length)
}

#[test]
fn test_ipv6_link_local_not_removed_when_enabled() {
    let des_iface = iface_with_ipv6(InterfaceIpv6 {
        enabled: Some(true),
        dhcp: Some(true),
        addresses: None,
        ..Default::default()
    });
    let cur_iface = iface_with_ipv6(InterfaceIpv6 {
        enabled: Some(true),
        addresses: Some(vec![addr("fe80::1", 64), addr("2001:db8::1", 64)]),
        ..Default::default()
    });

    let actions =
        crate::netlink::addr::ip_address_actions(&des_iface, Some(&cur_iface));
    assert_eq!(actions.len(), 1);
    assert!(actions[0].remove);
    assert_eq!(
        actions[0].address.ip,
        "2001:db8::1".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn test_ipv6_link_local_removed_when_disabled() {
    let des_iface = iface_with_ipv6(InterfaceIpv6 {
        enabled: Some(false),
        ..Default::default()
    });
    let cur_iface = iface_with_ipv6(InterfaceIpv6 {
        enabled: Some(true),
        addresses: Some(vec![addr("fe80::1", 64)]),
        ..Default::default()
    });

    let actions =
        crate::netlink::addr::ip_address_actions(&des_iface, Some(&cur_iface));
    assert_eq!(actions.len(), 1);
    assert!(actions[0].remove);
    assert_eq!(actions[0].address.ip, "fe80::1".parse::<IpAddr>().unwrap());
}

#[test]
fn test_ipv4_appending_only_adds_new_address() {
    let des_iface = iface_with_ipv4(InterfaceIpv4 {
        enabled: Some(true),
        addresses: Some(vec![
            addr("192.0.2.10", 24),
            addr("192.0.2.11", 24),
            addr("192.0.2.12", 24),
        ]),
        ..Default::default()
    });
    let cur_iface = iface_with_ipv4(InterfaceIpv4 {
        enabled: Some(true),
        addresses: Some(vec![addr("192.0.2.10", 24), addr("192.0.2.11", 24)]),
        ..Default::default()
    });

    let actions =
        crate::netlink::addr::ip_address_actions(&des_iface, Some(&cur_iface));
    assert_eq!(actions.len(), 1);
    assert!(!actions[0].remove);
    assert_eq!(
        actions[0].address.ip,
        "192.0.2.12".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn test_ipv4_replacing_keeps_all_addresses() {
    let des_iface = iface_with_ipv4(InterfaceIpv4 {
        enabled: Some(true),
        addresses: Some(vec![addr("192.0.2.12", 24), addr("192.0.2.10", 24)]),
        ..Default::default()
    });
    let cur_iface = iface_with_ipv4(InterfaceIpv4 {
        enabled: Some(true),
        addresses: Some(vec![addr("192.0.2.10", 24), addr("192.0.2.12", 24)]),
        ..Default::default()
    });

    let actions =
        crate::netlink::addr::ip_address_actions(&des_iface, Some(&cur_iface));
    assert_eq!(actions.len(), 2);
    assert!(actions.iter().all(|action| !action.remove));
}

#[test]
fn test_ipv4_reordering_purges_then_adds() {
    let des_iface = iface_with_ipv4(InterfaceIpv4 {
        enabled: Some(true),
        addresses: Some(vec![addr("192.0.2.12", 24), addr("192.0.2.11", 24)]),
        ..Default::default()
    });
    let cur_iface = iface_with_ipv4(InterfaceIpv4 {
        enabled: Some(true),
        addresses: Some(vec![addr("192.0.2.10", 24), addr("192.0.2.11", 24)]),
        ..Default::default()
    });

    let actions =
        crate::netlink::addr::ip_address_actions(&des_iface, Some(&cur_iface));
    assert_eq!(actions.len(), 4);
    assert!(actions[0].remove);
    assert!(actions[1].remove);
    assert!(!actions[2].remove);
    assert!(!actions[3].remove);
}
