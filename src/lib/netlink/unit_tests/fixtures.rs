// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use rtnetlink::packet_route::{
    AddressFamily,
    address::{AddressHeader, AddressMessage},
    link::{
        InfoData, InfoKind, InfoVeth, InfoVlan, LinkAttribute, LinkFlags,
        LinkHeader, LinkLayerType, LinkMessage,
    },
    route::{RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType},
    rule::{RuleAction, RuleHeader, RuleMessage},
};

pub(super) fn link_message(
    index: u32,
    name: &str,
    link_layer_type: LinkLayerType,
    flags: LinkFlags,
) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.header = LinkHeader {
        interface_family: AddressFamily::Unspec,
        index,
        link_layer_type,
        flags,
        change_mask: LinkFlags::empty(),
    };
    message.attributes = vec![LinkAttribute::IfName(name.to_string())];
    message
}

pub(super) fn address_message(
    family: AddressFamily,
    index: u32,
    prefix_len: u8,
    address: IpAddr,
) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header = AddressHeader {
        family,
        prefix_len,
        index,
        ..Default::default()
    };
    message.attributes =
        vec![rtnetlink::packet_route::address::AddressAttribute::Address(
            address,
        )];
    message
}

pub(super) fn route_message(
    family: AddressFamily,
    destination_prefix_length: u8,
) -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header = RouteHeader {
        address_family: family,
        destination_prefix_length,
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: RouteProtocol::Boot,
        scope: RouteScope::Universe,
        kind: RouteType::Unicast,
        ..Default::default()
    };
    message
}

pub(super) fn rule_message(
    family: AddressFamily,
    action: RuleAction,
) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header = RuleHeader {
        family,
        action,
        table: RouteHeader::RT_TABLE_MAIN,
        ..Default::default()
    };
    message
}

pub(super) fn link_info_attribute(
    kind: InfoKind,
    data: Option<InfoData>,
) -> LinkAttribute {
    let mut infos = vec![rtnetlink::packet_route::link::LinkInfo::Kind(kind)];
    if let Some(data) = data {
        infos.push(rtnetlink::packet_route::link::LinkInfo::Data(data));
    }
    LinkAttribute::LinkInfo(infos)
}

pub(super) fn vlan_info_data(id: u16, protocol: u16) -> InfoData {
    InfoData::Vlan(vec![InfoVlan::Id(id), InfoVlan::Protocol(protocol.into())])
}

pub(super) fn veth_info_data(peer_name: &str, peer_index: u32) -> InfoData {
    InfoData::Veth(InfoVeth::Peer(link_message(
        peer_index,
        peer_name,
        LinkLayerType::Ether,
        LinkFlags::Up,
    )))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use rtnetlink::{
        packet_core::{Emitable, Parseable},
        packet_route::{
            AddressFamily,
            address::AddressMessage,
            link::{
                InfoData, InfoKind, InfoVeth, InfoVlan, LinkAttribute,
                LinkFlags, LinkLayerType, LinkMessage,
            },
            route::{RouteMessage, RouteProtocol, RouteScope, RouteType},
            rule::{RuleAction, RuleMessage},
        },
    };

    use super::{
        address_message, link_info_attribute, link_message, route_message,
        rule_message, veth_info_data, vlan_info_data,
    };

    fn round_trip_link(message: &LinkMessage) -> LinkMessage {
        let mut buffer = vec![0u8; message.buffer_len()];
        message.emit(&mut buffer);
        LinkMessage::parse(&buffer).unwrap()
    }

    fn round_trip_address(message: &AddressMessage) -> AddressMessage {
        let mut buffer = vec![0u8; message.buffer_len()];
        message.emit(&mut buffer);
        AddressMessage::parse(&buffer).unwrap()
    }

    fn round_trip_route(message: &RouteMessage) -> RouteMessage {
        let mut buffer = vec![0u8; message.buffer_len()];
        message.emit(&mut buffer);
        RouteMessage::parse(&buffer).unwrap()
    }

    fn round_trip_rule(message: &RuleMessage) -> RuleMessage {
        let mut buffer = vec![0u8; message.buffer_len()];
        message.emit(&mut buffer);
        RuleMessage::parse(&buffer).unwrap()
    }

    #[test]
    fn test_link_message_fixture_round_trip() {
        let message = link_message(
            2,
            "eth1",
            LinkLayerType::Ether,
            LinkFlags::Up | LinkFlags::LowerUp,
        );
        let parsed = round_trip_link(&message);
        assert_eq!(parsed.header.index, 2);
        assert_eq!(parsed.header.link_layer_type, LinkLayerType::Ether);
        assert!(parsed.header.flags.contains(LinkFlags::Up));
        assert!(parsed.header.flags.contains(LinkFlags::LowerUp));
        assert_eq!(
            parsed.attributes,
            vec![LinkAttribute::IfName("eth1".to_string())]
        );
    }

    #[test]
    fn test_address_message_fixture_round_trip() {
        let message = address_message(
            AddressFamily::Inet6,
            3,
            64,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        );
        let parsed = round_trip_address(&message);
        assert_eq!(parsed.header.family, AddressFamily::Inet6);
        assert_eq!(parsed.header.index, 3);
        assert_eq!(parsed.header.prefix_len, 64);
        assert_eq!(parsed.attributes.len(), 1);
    }

    #[test]
    fn test_route_message_fixture_round_trip() {
        let mut message = route_message(AddressFamily::Inet, 24);
        message.attributes =
            vec![rtnetlink::packet_route::route::RouteAttribute::Destination(
                Ipv4Addr::new(192, 0, 2, 0).into(),
            )];
        let parsed = round_trip_route(&message);
        assert_eq!(parsed.header.address_family, AddressFamily::Inet);
        assert_eq!(parsed.header.destination_prefix_length, 24);
        assert_eq!(parsed.header.protocol, RouteProtocol::Boot);
        assert_eq!(parsed.header.scope, RouteScope::Universe);
        assert_eq!(parsed.header.kind, RouteType::Unicast);
        assert_eq!(parsed.attributes, message.attributes);
    }

    #[test]
    fn test_rule_message_fixture_round_trip() {
        let mut message =
            rule_message(AddressFamily::Inet6, RuleAction::ToTable);
        message.attributes = vec![
            rtnetlink::packet_route::rule::RuleAttribute::Priority(1000),
            rtnetlink::packet_route::rule::RuleAttribute::Table(100),
        ];
        let parsed = round_trip_rule(&message);
        assert_eq!(parsed.header.family, AddressFamily::Inet6);
        assert_eq!(parsed.header.action, RuleAction::ToTable);
        assert_eq!(parsed.attributes, message.attributes);
    }

    #[test]
    fn test_link_info_fixture_round_trip() {
        let mut vlan_message =
            link_message(4, "vlan1", LinkLayerType::Ether, LinkFlags::Up);
        vlan_message.attributes.push(link_info_attribute(
            InfoKind::Vlan,
            Some(vlan_info_data(100, 0x8100)),
        ));
        let parsed_vlan = round_trip_link(&vlan_message);
        assert!(parsed_vlan.attributes.contains(&LinkAttribute::LinkInfo(
            vec![
                rtnetlink::packet_route::link::LinkInfo::Kind(InfoKind::Vlan),
                rtnetlink::packet_route::link::LinkInfo::Data(InfoData::Vlan(
                    vec![InfoVlan::Id(100), InfoVlan::Protocol(0x8100.into()),]
                )),
            ]
        )));

        let mut veth_message =
            link_message(5, "veth0", LinkLayerType::Ether, LinkFlags::Up);
        veth_message.attributes.push(link_info_attribute(
            InfoKind::Veth,
            Some(veth_info_data("veth1", 6)),
        ));
        let parsed_veth = round_trip_link(&veth_message);
        assert!(parsed_veth.attributes.iter().any(|attribute| {
            if let LinkAttribute::LinkInfo(infos) = attribute {
                infos.iter().any(|info| {
                    matches!(
                        info,
                        rtnetlink::packet_route::link::LinkInfo::Data(
                            InfoData::Veth(InfoVeth::Peer(_))
                        )
                    )
                })
            } else {
                false
            }
        }));
    }
}
