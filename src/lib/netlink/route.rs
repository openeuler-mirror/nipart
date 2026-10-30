// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use std::net::IpAddr;

use futures_util::TryStreamExt;
use rtnetlink::{
    Handle, RouteMessageBuilder,
    packet_route::{
        AddressFamily,
        route::{
            RouteAddress, RouteAttribute, RouteFlags, RouteHeader,
            RouteMessage, RouteMetric, RouteNextHop,
            RouteProtocol as NetlinkRouteProtocol, RouteScope, RouteType,
            RouteVia,
        },
    },
};

use crate::{
    ErrorKind, NipartError, RouteEntry, Routes,
    netlink::{
        link::LinkIndexMap, map_rtnetlink_error, new_connection,
        new_connection_with_strict_check,
    },
    schema::RouteProtocol,
};

pub(crate) const SUPPORTED_ROUTE_SCOPE: [RouteScope; 2] =
    [RouteScope::Universe, RouteScope::Link];

pub(crate) const SUPPORTED_ROUTE_PROTOCOL: [RouteProtocol; 8] = [
    // Connected routes created by the kernel when an address is assigned.
    RouteProtocol::Kernel,
    RouteProtocol::Boot,
    RouteProtocol::Static,
    RouteProtocol::Ra,
    RouteProtocol::Dhcp,
    RouteProtocol::Mrouted,
    RouteProtocol::KeepAlived,
    RouteProtocol::Babel,
];

pub(crate) const SUPPORTED_STATIC_ROUTE_PROTOCOL: [RouteProtocol; 2] =
    [RouteProtocol::Boot, RouteProtocol::Static];

// Table used by the kernel for local and broadcast routes; these are
// derived from the interface itself and not part of the route config.
pub(crate) const LOCAL_ROUTE_TABLE: u32 = 255;

const RTAX_CWND: u32 = 7;

const IPV4_DEFAULT_GATEWAY: &str = "0.0.0.0/0";
const IPV6_DEFAULT_GATEWAY: &str = "::/0";
const IPV4_EMPTY_NEXT_HOP_ADDRESS: &str = "0.0.0.0";
const IPV6_EMPTY_NEXT_HOP_ADDRESS: &str = "::";

pub(crate) fn route_protocol_from_netlink(
    protocol: NetlinkRouteProtocol,
) -> RouteProtocol {
    RouteProtocol::from(u8::from(protocol))
}

pub(crate) fn route_protocol_to_netlink(
    protocol: RouteProtocol,
) -> NetlinkRouteProtocol {
    NetlinkRouteProtocol::from(u8::from(protocol))
}

pub(crate) fn route_table(message: &RouteMessage) -> u32 {
    let mut table = u32::from(message.header.table);
    for attribute in &message.attributes {
        if let RouteAttribute::Table(value) = attribute {
            table = *value;
        }
    }
    table
}

pub(crate) fn is_supported_route(
    message: &RouteMessage,
    protocol: RouteProtocol,
) -> bool {
    SUPPORTED_ROUTE_PROTOCOL.contains(&protocol)
        && route_table(message) != LOCAL_ROUTE_TABLE
        && SUPPORTED_ROUTE_SCOPE.contains(&message.header.scope)
}

pub(crate) fn routes_from_messages<'a>(
    messages: impl IntoIterator<Item = &'a RouteMessage>,
    index_map: &LinkIndexMap,
) -> Routes {
    let mut running = Vec::new();
    let mut config = Vec::new();

    for message in messages {
        let protocol = route_protocol_from_netlink(message.header.protocol);
        if !is_supported_route(message, protocol) {
            continue;
        }
        let is_static_protocol =
            SUPPORTED_STATIC_ROUTE_PROTOCOL.contains(&protocol);

        if is_multipath(message) {
            let entries = flat_multipath_route(message, index_map);
            running.extend(entries.iter().cloned());
            if is_static_protocol {
                config.extend(entries);
            }
        } else if let Some(route_type) =
            route_type_from_netlink(message.header.kind)
        {
            let entry = route_entry_for_type(message, index_map, route_type);
            running.push(entry.clone());
            if is_static_protocol {
                config.push(entry);
            }
        } else if let Some(entry) = route_entry_for_unicast(message, index_map)
        {
            running.push(entry.clone());
            if is_static_protocol {
                config.push(entry);
            }
        }
    }

    Routes {
        running: Some(running),
        config: Some(config),
    }
}

fn route_entry_for_unicast(
    message: &RouteMessage,
    index_map: &LinkIndexMap,
) -> Option<RouteEntry> {
    let entry = route_entry(message, index_map);
    entry.next_hop_iface.as_ref()?;
    Some(entry)
}

pub(crate) fn route_entry(
    message: &RouteMessage,
    index_map: &LinkIndexMap,
) -> RouteEntry {
    let metrics = route_metrics(message);
    let next_hop_addr = route_next_hop_addr(message)
        .or_else(|| empty_next_hop_addr(message.header.address_family));

    RouteEntry {
        destination: route_destination(message),
        next_hop_iface: route_oif(message, index_map),
        next_hop_addr,
        source: route_preferred_source(message),
        metric: route_metric(message).map(i64::from),
        table_id: Some(route_table(message)),
        cwnd: if metrics.lock.unwrap_or_default() & (1 << RTAX_CWND) != 0 {
            metrics.cwnd
        } else {
            None
        },
        initcwnd: metrics.initcwnd,
        initrwnd: metrics.initrwnd,
        mtu: metrics.mtu,
        quickack: metrics.quickack.map(|quickack| quickack > 0),
        advmss: metrics.advmss,
        onlink: message
            .header
            .flags
            .contains(RouteFlags::Onlink)
            .then_some(true),
        protocol: Some(route_protocol_from_netlink(message.header.protocol)),
        ..Default::default()
    }
}

pub(crate) fn route_entry_for_type(
    message: &RouteMessage,
    index_map: &LinkIndexMap,
    route_type: crate::RouteType,
) -> RouteEntry {
    let metrics = route_metrics(message);
    let mut entry = RouteEntry {
        destination: route_destination(message),
        metric: route_metric(message).map(i64::from),
        table_id: Some(route_table(message)),
        cwnd: if metrics.lock.unwrap_or_default() & (1 << RTAX_CWND) != 0 {
            metrics.cwnd
        } else {
            None
        },
        route_type: Some(route_type),
        protocol: Some(route_protocol_from_netlink(message.header.protocol)),
        ..Default::default()
    };
    if message.header.address_family == AddressFamily::Inet6 {
        entry.next_hop_iface = route_oif(message, index_map);
    }
    entry
}

pub(crate) fn is_multipath(message: &RouteMessage) -> bool {
    message.attributes.iter().any(|attribute| {
        matches!(attribute, RouteAttribute::MultiPath(next_hops)
            if !next_hops.is_empty())
    })
}

pub(crate) fn flat_multipath_route(
    message: &RouteMessage,
    index_map: &LinkIndexMap,
) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    for attribute in &message.attributes {
        let RouteAttribute::MultiPath(next_hops) = attribute else {
            continue;
        };
        for next_hop in next_hops {
            let mut entry = route_entry(message, index_map);
            entry.next_hop_iface = Some(
                index_map
                    .name(next_hop.interface_index)
                    .map(str::to_string)
                    .unwrap_or_else(|| next_hop.interface_index.to_string()),
            );
            entry.next_hop_addr = Some(
                next_hop_gateway(next_hop)
                    .map(|gateway| gateway.to_string())
                    .unwrap_or_default(),
            );
            if message.header.address_family == AddressFamily::Inet {
                entry.weight = Some(u16::from(next_hop.hops) + 1);
            }
            entries.push(entry);
        }
    }
    entries
}

pub(crate) fn route_type_from_netlink(
    route_type: RouteType,
) -> Option<crate::RouteType> {
    match route_type {
        RouteType::BlackHole => Some(crate::RouteType::Blackhole),
        RouteType::Unreachable => Some(crate::RouteType::Unreachable),
        RouteType::Prohibit => Some(crate::RouteType::Prohibit),
        _ => None,
    }
}

fn route_destination(message: &RouteMessage) -> Option<String> {
    for attribute in &message.attributes {
        if let RouteAttribute::Destination(destination) = attribute {
            return route_address_to_string(destination).map(|address| {
                format!(
                    "{address}/{}",
                    message.header.destination_prefix_length
                )
            });
        }
    }
    match message.header.address_family {
        AddressFamily::Inet => Some(IPV4_DEFAULT_GATEWAY.to_string()),
        AddressFamily::Inet6 => Some(IPV6_DEFAULT_GATEWAY.to_string()),
        family => {
            log::warn!(
                "Route is holding unsupported address family {family:?}"
            );
            None
        }
    }
}

fn route_oif(
    message: &RouteMessage,
    index_map: &LinkIndexMap,
) -> Option<String> {
    for attribute in &message.attributes {
        if let RouteAttribute::Oif(index) = attribute {
            return Some(
                index_map
                    .name(*index)
                    .map(str::to_string)
                    .unwrap_or_else(|| index.to_string()),
            );
        }
    }
    None
}

fn route_next_hop_addr(message: &RouteMessage) -> Option<String> {
    let mut gateway = None;
    let mut via = None;
    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Gateway(address) => {
                gateway = route_address_to_string(address);
            }
            RouteAttribute::Via(RouteVia::Inet(address)) => {
                via = Some(address.to_string());
            }
            RouteAttribute::Via(RouteVia::Inet6(address)) => {
                via = Some(address.to_string());
            }
            _ => (),
        }
    }
    via.or(gateway)
}

fn route_preferred_source(message: &RouteMessage) -> Option<String> {
    for attribute in &message.attributes {
        if let RouteAttribute::PrefSource(source) = attribute {
            return route_address_to_string(source);
        }
    }
    None
}

fn route_metric(message: &RouteMessage) -> Option<u32> {
    for attribute in &message.attributes {
        if let RouteAttribute::Priority(metric) = attribute {
            return Some(*metric);
        }
    }
    None
}

fn next_hop_gateway(next_hop: &RouteNextHop) -> Option<String> {
    for attribute in &next_hop.attributes {
        if let RouteAttribute::Gateway(address) = attribute {
            return route_address_to_string(address);
        }
    }
    None
}

fn route_address_to_string(address: &RouteAddress) -> Option<String> {
    match address {
        RouteAddress::Inet(address) => Some(address.to_string()),
        RouteAddress::Inet6(address) => Some(address.to_string()),
        address => {
            log::debug!("Unknown route address {address:?}");
            None
        }
    }
}

fn empty_next_hop_addr(family: AddressFamily) -> Option<String> {
    match family {
        AddressFamily::Inet => Some(IPV4_EMPTY_NEXT_HOP_ADDRESS.to_string()),
        AddressFamily::Inet6 => Some(IPV6_EMPTY_NEXT_HOP_ADDRESS.to_string()),
        family => {
            log::warn!(
                "Route is holding unsupported address family {family:?}"
            );
            None
        }
    }
}

#[derive(Debug, Default)]
struct RouteMetrics {
    lock: Option<u32>,
    cwnd: Option<u32>,
    initcwnd: Option<u32>,
    initrwnd: Option<u32>,
    mtu: Option<u32>,
    quickack: Option<u32>,
    advmss: Option<u32>,
}

fn route_metrics(message: &RouteMessage) -> RouteMetrics {
    let mut metrics = RouteMetrics::default();
    for attribute in &message.attributes {
        let RouteAttribute::Metrics(nlas) = attribute else {
            continue;
        };
        for nla in nlas {
            match nla {
                RouteMetric::Lock(value) => metrics.lock = Some(*value),
                RouteMetric::Cwnd(value) => metrics.cwnd = Some(*value),
                RouteMetric::InitCwnd(value) => metrics.initcwnd = Some(*value),
                RouteMetric::InitRwnd(value) => metrics.initrwnd = Some(*value),
                RouteMetric::Mtu(value) => metrics.mtu = Some(*value),
                RouteMetric::QuickAck(value) => metrics.quickack = Some(*value),
                RouteMetric::Advmss(value) => metrics.advmss = Some(*value),
                _ => log::debug!("Unknown RTA_METRICS message {nla:?}"),
            }
        }
    }
    metrics
}

