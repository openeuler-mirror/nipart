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

