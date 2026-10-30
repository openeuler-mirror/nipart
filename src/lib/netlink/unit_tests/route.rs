// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv4Addr, Ipv6Addr};

use rtnetlink::packet_route::{
    AddressFamily,
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage,
        RouteMetric, RouteNextHop, RouteProtocol as NetlinkRouteProtocol,
        RouteScope, RouteType, RouteVia,
    },
};

use crate::{
    ErrorKind, RouteEntry, RouteState, RouteType as NipartRouteType,
    netlink::{
        link::LinkIndexMap,
        route::{
            route_add_message, route_del_message, route_entry,
            routes_from_messages,
        },
    },
    schema::RouteProtocol,
};

fn index_map() -> LinkIndexMap {
    let mut map = LinkIndexMap::default();
    map.insert(2, "dummy0".to_string());
    map.insert(3, "dummy1".to_string());
    map
}

fn next_hop(gateway: Ipv4Addr, interface_index: u32, hops: u8) -> RouteNextHop {
    let mut next_hop = RouteNextHop::default();
    next_hop.hops = hops;
    next_hop.interface_index = interface_index;
    next_hop.attributes = vec![RouteAttribute::Gateway(gateway.into())];
    next_hop
}

fn route_message(
    family: AddressFamily,
    destination_prefix_length: u8,
) -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = family;
    message.header.destination_prefix_length = destination_prefix_length;
    message.header.table = RouteHeader::RT_TABLE_MAIN;
    message.header.protocol = NetlinkRouteProtocol::Static;
    message.header.scope = RouteScope::Universe;
    message.header.kind = RouteType::Unicast;
    message
}

#[test]
fn test_parse_route_header_ipv4() {
    let mut message = route_message(AddressFamily::Inet, 24);
    message.header.table = 100;
    message.header.protocol = NetlinkRouteProtocol::Boot;
    message.header.scope = RouteScope::Link;
    message.attributes = vec![
        RouteAttribute::Destination(Ipv4Addr::new(198, 51, 100, 0).into()),
        RouteAttribute::Oif(2),
    ];
    let entry = route_entry(&message, &index_map());
    assert_eq!(entry.destination.as_deref(), Some("198.51.100.0/24"));
    assert_eq!(entry.table_id, Some(100));
    assert_eq!(entry.protocol, Some(RouteProtocol::Boot));
    assert_eq!(entry.next_hop_iface.as_deref(), Some("dummy0"));
    assert_eq!(entry.next_hop_addr.as_deref(), Some("0.0.0.0"));
    assert_eq!(entry.route_type, None);
    assert_eq!(entry.onlink, None);
}

#[test]
fn test_parse_route_header_ipv6() {
    let mut message = route_message(AddressFamily::Inet6, 64);
    message.header.protocol = NetlinkRouteProtocol::Ra;
    message.attributes = vec![
        RouteAttribute::Destination(
            "2001:db8:1::".parse::<Ipv6Addr>().unwrap().into(),
        ),
        RouteAttribute::Oif(3),
        RouteAttribute::Gateway("fe80::1".parse::<Ipv6Addr>().unwrap().into()),
        RouteAttribute::Priority(1024),
        RouteAttribute::Table(1000),
    ];
    let entry = route_entry(&message, &index_map());
    assert_eq!(entry.destination.as_deref(), Some("2001:db8:1::/64"));
    assert_eq!(entry.table_id, Some(1000));
    assert_eq!(entry.protocol, Some(RouteProtocol::Ra));
    assert_eq!(entry.next_hop_iface.as_deref(), Some("dummy1"));
    assert_eq!(entry.next_hop_addr.as_deref(), Some("fe80::1"));
    assert_eq!(entry.metric, Some(1024));
}

#[test]
fn test_parse_route_default_destination() {
    for (family, expected) in [
        (AddressFamily::Inet, "0.0.0.0/0"),
        (AddressFamily::Inet6, "::/0"),
    ] {
        let mut message = route_message(family, 0);
        message.attributes = vec![RouteAttribute::Oif(2)];
        let entry = route_entry(&message, &index_map());
        assert_eq!(entry.destination.as_deref(), Some(expected));
    }
}

#[test]
fn test_parse_route_via_attribute() {
    let mut message = route_message(AddressFamily::Inet6, 64);
    message.attributes = vec![
        RouteAttribute::Destination(
            "2001:db8:1::".parse::<Ipv6Addr>().unwrap().into(),
        ),
        RouteAttribute::Oif(2),
        RouteAttribute::Via(RouteVia::Inet6(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
        )),
    ];
    let entry = route_entry(&message, &index_map());
    assert_eq!(entry.next_hop_addr.as_deref(), Some("2001:db8::1"));
}

#[test]
fn test_parse_route_metrics_and_flags() {
    let mut message = route_message(AddressFamily::Inet, 24);
    message.header.flags.insert(RouteFlags::Onlink);
    message.attributes = vec![
        RouteAttribute::Destination(Ipv4Addr::new(198, 51, 100, 0).into()),
        RouteAttribute::Oif(2),
        RouteAttribute::PrefSource(Ipv4Addr::new(192, 0, 2, 10).into()),
        RouteAttribute::Metrics(vec![
            RouteMetric::Lock(1 << 7),
            RouteMetric::Cwnd(20),
            RouteMetric::InitCwnd(10),
            RouteMetric::InitRwnd(30),
            RouteMetric::Mtu(1400),
            RouteMetric::QuickAck(1),
            RouteMetric::Advmss(1360),
        ]),
    ];
    let entry = route_entry(&message, &index_map());
    assert_eq!(entry.cwnd, Some(20));
    assert_eq!(entry.initcwnd, Some(10));
    assert_eq!(entry.initrwnd, Some(30));
    assert_eq!(entry.mtu, Some(1400));
    assert_eq!(entry.quickack, Some(true));
    assert_eq!(entry.advmss, Some(1360));
    assert_eq!(entry.onlink, Some(true));
    assert_eq!(entry.source.as_deref(), Some("192.0.2.10"));

    message.attributes = vec![
        RouteAttribute::Oif(2),
        RouteAttribute::Metrics(vec![
            RouteMetric::Cwnd(20),
            RouteMetric::QuickAck(0),
        ]),
    ];
    let entry = route_entry(&message, &index_map());
    assert_eq!(entry.cwnd, None);
    assert_eq!(entry.quickack, Some(false));
}

