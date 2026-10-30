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

fn route_dump_message(
    family: AddressFamily,
    protocol: NetlinkRouteProtocol,
) -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = family;
    message.header.protocol = protocol;
    message.header.scope = RouteScope::Universe;
    message.header.kind = RouteType::Unspec;
    message.header.table = RouteHeader::RT_TABLE_MAIN;
    message.attributes.push(RouteAttribute::Table(0));
    message
}

async fn dump_protocol_routes(
    handle: &Handle,
    family: AddressFamily,
    protocol: RouteProtocol,
) -> Result<Vec<RouteMessage>, NipartError> {
    let mut messages = Vec::new();
    let mut stream = handle
        .route()
        .get(route_dump_message(
            family,
            route_protocol_to_netlink(protocol),
        ))
        .execute();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|e| map_rtnetlink_error("Failed to dump kernel routes", e))?
    {
        // Always filter in user space: the kernel only applies the protocol
        // filter with NETLINK_GET_STRICT_CHK enabled.
        if route_protocol_from_netlink(message.header.protocol) == protocol {
            messages.push(message);
        }
    }
    Ok(messages)
}

pub(crate) async fn get_routes(
    index_map: &LinkIndexMap,
) -> Result<Routes, NipartError> {
    let handle = match new_connection_with_strict_check().await {
        Ok(handle) => handle,
        Err(e) => {
            log::debug!(
                "Failed to create strict rtnetlink connection, falling back \
                 to user space route filtering: {e}"
            );
            new_connection().await?
        }
    };

    let mut messages = Vec::new();
    for protocol in SUPPORTED_ROUTE_PROTOCOL {
        for family in [AddressFamily::Inet6, AddressFamily::Inet] {
            match dump_protocol_routes(&handle, family, protocol).await {
                Ok(new_messages) => messages.extend(new_messages),
                Err(e) => {
                    log::warn!(
                        "Failed to retrieve {protocol:?} route via netlink: \
                         {e}"
                    );
                }
            }
        }
    }
    Ok(routes_from_messages(&messages, index_map))
}

fn parse_ip_network(destination: &str) -> Result<(IpAddr, u8), NipartError> {
    let splits: Vec<&str> = destination.split('/').collect();
    if splits.len() > 2 || splits.is_empty() {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!("Invalid IP network address {destination}"),
        ));
    }
    let address = splits[0].parse::<IpAddr>().map_err(|e| {
        NipartError::new(
            ErrorKind::InvalidArgument,
            format!("Invalid IP network address {destination}: {e}"),
        )
    })?;
    let prefix_length = if let Some(prefix_length) = splits.get(1) {
        prefix_length.parse::<u8>().map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid IP network prefix {destination}: {e}"),
            )
        })?
    } else if address.is_ipv6() {
        128
    } else {
        32
    };
    let max_prefix_length = if address.is_ipv6() { 128 } else { 32 };
    if prefix_length > max_prefix_length {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!(
                "Invalid IP network prefix {destination}: should be no \
                 greater than {max_prefix_length}"
            ),
        ));
    }
    Ok((address, prefix_length))
}

fn validate_route_for_apply(route: &RouteEntry) -> Result<(), NipartError> {
    if let Some(table_id) = route.table_id
        && table_id > u8::MAX.into()
    {
        return Err(NipartError::new(
            ErrorKind::NoSupport,
            format!(
                "netlink apply does not support route table ID bigger than {} \
                 yet, got {table_id}, ignoring",
                u8::MAX
            ),
        ));
    }
    if route.weight.is_some() {
        return Err(NipartError::new(
            ErrorKind::NoSupport,
            "netlink apply does not support route weight yet".to_string(),
        ));
    }
    if route.route_type.is_some() {
        return Err(NipartError::new(
            ErrorKind::NoSupport,
            "netlink apply does not support route type yet".to_string(),
        ));
    }
    if route.cwnd.is_some() {
        return Err(NipartError::new(
            ErrorKind::NoSupport,
            "netlink apply does not support route congestion window yet"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn route_add_message(
    route: &RouteEntry,
    index_map: &LinkIndexMap,
) -> Result<RouteMessage, NipartError> {
    route_message(route, index_map, false)
}

pub(crate) fn route_del_message(
    route: &RouteEntry,
    index_map: &LinkIndexMap,
) -> Result<RouteMessage, NipartError> {
    route_message(route, index_map, true)
}

fn route_message(
    route: &RouteEntry,
    index_map: &LinkIndexMap,
    remove: bool,
) -> Result<RouteMessage, NipartError> {
    validate_route_for_apply(route)?;

    let destination = route.destination.as_deref().ok_or_else(|| {
        NipartError::new(
            ErrorKind::InvalidArgument,
            format!("Route {route} has no destination defined"),
        )
    })?;
    let (destination, prefix_length) = parse_ip_network(destination)?;
    let mut builder = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(destination, prefix_length)
        .map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid route destination {destination}/{prefix_length}: \
                     {e}"
                ),
            )
        })?;

    if remove {
        builder = builder
            .protocol(
                route
                    .protocol
                    .map(route_protocol_to_netlink)
                    .unwrap_or(NetlinkRouteProtocol::Unspec),
            )
            .scope(RouteScope::NoWhere)
            .kind(RouteType::Unspec);
    } else {
        builder = builder
            .protocol(
                route
                    .protocol
                    .map(route_protocol_to_netlink)
                    .unwrap_or(NetlinkRouteProtocol::Static),
            )
            .scope(RouteScope::Universe)
            .kind(RouteType::Unicast);
    }

    if let Some(table_id) = route.table_id {
        builder = builder.table_id(table_id);
    }
    if let Some(metric) = route.metric.and_then(|m| u32::try_from(m).ok()) {
        builder = builder.priority(metric);
    }
    if let Some(iface) = route.next_hop_iface.as_deref() {
        let index = index_map.index(iface).ok_or_else(|| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Interface {iface} does not exist"),
            )
        })?;
        builder = builder.output_interface(index);
    }
    if let Some(gateway) = route.next_hop_addr.as_deref() {
        let gateway = gateway.parse::<IpAddr>().map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid route next hop address {gateway}: {e}"),
            )
        })?;
        builder = builder.gateway(gateway).map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid route next hop address {gateway}: {e}"),
            )
        })?;
    }
    if let Some(source) = route.source.as_deref() {
        let source = source.parse::<IpAddr>().map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid route source address {source}: {e}"),
            )
        })?;
        builder = builder.pref_source(source).map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid route source address {source}: {e}"),
            )
        })?;
    }
    if !remove && route.onlink.unwrap_or_default() {
        builder = builder.onlink();
    }
    Ok(builder.build())
}

