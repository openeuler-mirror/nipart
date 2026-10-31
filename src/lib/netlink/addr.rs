// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use std::{collections::HashMap, net::IpAddr};

use futures_util::TryStreamExt;
use rtnetlink::{
    Handle,
    packet_route::{
        AddressFamily,
        address::{
            AddressAttribute, AddressFlags, AddressMessage, AddressProtocol,
            CacheInfo,
        },
    },
};

use crate::{
    ErrorKind, InterfaceIpAddr, InterfaceIpv4, InterfaceIpv6, NipartError,
    netlink::{map_rtnetlink_error, new_connection},
};

const FOREVER: &str = "forever";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddressInfo {
    pub(crate) iface_index: u32,
    pub(crate) address: InterfaceIpAddr,
    pub(crate) protocol: Option<AddressProtocol>,
    pub(crate) flags: AddressFlags,
}

pub(crate) fn address_info(message: &AddressMessage) -> Option<AddressInfo> {
    match message.header.family {
        AddressFamily::Inet => ipv4_address_info(message),
        AddressFamily::Inet6 => ipv6_address_info(message),
        family => {
            log::debug!("Skipping unsupported address family {family:?}");
            None
        }
    }
}

pub(crate) fn ipv4_from_address_infos<'a>(
    infos: impl IntoIterator<Item = &'a AddressInfo>,
) -> Option<InterfaceIpv4> {
    let mut addresses = Vec::new();
    let mut dhcp = None;
    for info in infos {
        if !info.address.ip.is_ipv4() {
            continue;
        }
        if info.address.valid_life_time.as_deref() != Some(FOREVER) {
            dhcp = Some(true);
        }
        addresses.push(schema_address(&info.address));
    }
    if addresses.is_empty() {
        return Some(InterfaceIpv4::default());
    }
    Some(InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(dhcp.unwrap_or(false)),
        addresses: Some(addresses),
        ..Default::default()
    })
}

pub(crate) fn ipv6_from_address_infos<'a>(
    infos: impl IntoIterator<Item = &'a AddressInfo>,
) -> Option<InterfaceIpv6> {
    let mut addresses = Vec::new();
    let mut dhcp = None;
    let mut autoconf = None;
    for info in infos {
        if !info.address.ip.is_ipv6() {
            continue;
        }
        if info.protocol == Some(AddressProtocol::RouterAnnouncement) {
            autoconf = Some(true);
        } else if info.address.valid_life_time.as_deref() != Some(FOREVER) {
            if info.address.prefix_length == 128 {
                dhcp = Some(true);
            } else {
                autoconf = Some(true);
            }
        }
        addresses.push(schema_address(&info.address));
    }
    if addresses.is_empty() {
        return Some(InterfaceIpv6::default());
    }
    let mut ip = InterfaceIpv6 {
        enabled: Some(true),
        dhcp,
        autoconf,
        addresses: Some(addresses),
        ..Default::default()
    };
    if ip.autoconf.is_none() && ip.dhcp.is_none() {
        ip.dhcp = Some(false);
        ip.autoconf = Some(false);
    }
    Some(ip)
}

pub(crate) fn ipv4_map_from_messages(
    messages: &[AddressMessage],
) -> HashMap<u32, InterfaceIpv4> {
    let mut grouped: HashMap<u32, Vec<AddressInfo>> = HashMap::new();
    for info in messages.iter().filter_map(address_info) {
        if info.address.ip.is_ipv4() {
            grouped.entry(info.iface_index).or_default().push(info);
        }
    }
    grouped
        .into_iter()
        .map(|(index, infos)| {
            (
                index,
                ipv4_from_address_infos(&infos).unwrap_or_default(),
            )
        })
        .collect()
}

pub(crate) fn ipv6_map_from_messages(
    messages: &[AddressMessage],
) -> HashMap<u32, InterfaceIpv6> {
    let mut grouped: HashMap<u32, Vec<AddressInfo>> = HashMap::new();
    for info in messages.iter().filter_map(address_info) {
        if info.address.ip.is_ipv6() {
            grouped.entry(info.iface_index).or_default().push(info);
        }
    }
    grouped
        .into_iter()
        .map(|(index, infos)| {
            (
                index,
                ipv6_from_address_infos(&infos).unwrap_or_default(),
            )
        })
        .collect()
}

fn schema_address(address: &InterfaceIpAddr) -> InterfaceIpAddr {
    let mut address = address.clone();
    if address.valid_life_time.as_deref() == Some(FOREVER) {
        address.valid_life_time = None;
    }
    if address.preferred_life_time.as_deref() == Some(FOREVER) {
        address.preferred_life_time = None;
    }
    address
}

fn ipv4_address_info(message: &AddressMessage) -> Option<AddressInfo> {
    let mut address = None;
    let mut local = None;
    for attribute in &message.attributes {
        match attribute {
            AddressAttribute::Address(value) => address = Some(*value),
            AddressAttribute::Local(value) => local = Some(*value),
            _ => (),
        }
    }
    let address = local.or(address)?;
    if !address.is_ipv4() {
        log::warn!("IPv4 address message holds non-IPv4 address {address}");
        return None;
    }
    Some(address_info_for(
        message,
        address,
        message.header.prefix_len,
    ))
}

fn ipv6_address_info(message: &AddressMessage) -> Option<AddressInfo> {
    let mut address = None;
    let mut local = None;
    for attribute in &message.attributes {
        match attribute {
            AddressAttribute::Address(value) => address = Some(*value),
            AddressAttribute::Local(value) => local = Some(*value),
            _ => (),
        }
    }
    if let Some(local) = local {
        if !local.is_ipv6() {
            log::warn!("IPv6 address message holds non-IPv6 address {local}");
            return None;
        }
        Some(address_info_for(message, local, 128))
    } else {
        let address = address?;
        if !address.is_ipv6() {
            log::warn!("IPv6 address message holds non-IPv6 address {address}");
            return None;
        }
        Some(address_info_for(
            message,
            address,
            message.header.prefix_len,
        ))
    }
}

fn address_info_for(
    message: &AddressMessage,
    ip: IpAddr,
    prefix_length: u8,
) -> AddressInfo {
    let mut valid_life_time = String::new();
    let mut preferred_life_time = String::new();
    let mut protocol = None;
    let mut flags = AddressFlags::empty();
    for attribute in &message.attributes {
        match attribute {
            AddressAttribute::CacheInfo(cache_info) => {
                valid_life_time = lifetime_to_string(cache_info.ifa_valid);
                preferred_life_time =
                    lifetime_to_string(cache_info.ifa_preferred);
            }
            AddressAttribute::Protocol(value) => protocol = Some(*value),
            AddressAttribute::Flags(value) => flags = *value,
            _ => (),
        }
    }

    AddressInfo {
        iface_index: message.header.index,
        address: InterfaceIpAddr {
            ip,
            prefix_length,
            valid_life_time: Some(valid_life_time),
            preferred_life_time: Some(preferred_life_time),
        },
        protocol,
        flags,
    }
}

pub(crate) fn lifetime_to_string(left_time: u32) -> String {
    if left_time == u32::MAX {
        FOREVER.to_string()
    } else {
        format!("{left_time}sec")
    }
}

pub(crate) fn cache_info_from_lifetimes(
    address: &InterfaceIpAddr,
) -> Result<Option<CacheInfo>, NipartError> {
    if is_forever(address.valid_life_time.as_deref())
        && is_forever(address.preferred_life_time.as_deref())
    {
        return Ok(None);
    }
    Ok(Some(CacheInfo {
        ifa_preferred: parse_lifetime(
            "preferred-life-time",
            address.preferred_life_time.as_deref(),
        )?,
        ifa_valid: parse_lifetime(
            "valid-life-time",
            address.valid_life_time.as_deref(),
        )?,
        ..Default::default()
    }))
}

fn is_forever(life_time: Option<&str>) -> bool {
    matches!(life_time, None | Some("") | Some(FOREVER))
}

fn parse_lifetime(
    name: &str,
    value: Option<&str>,
) -> Result<u32, NipartError> {
    let Some(value) = value else {
        return Ok(u32::MAX);
    };
    if value.is_empty() || value == FOREVER {
        return Ok(u32::MAX);
    }
    value
        .strip_suffix("sec")
        .ok_or_else(|| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid {name} format: expect format 50sec, got {value}"),
            )
        })?
        .parse::<u32>()
        .map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid {name} format: expect format 50sec, got {value}: {e}"),
            )
        })
}

pub(crate) async fn get_address_messages()
-> Result<Vec<AddressMessage>, NipartError> {
    let handle = new_connection().await?;
    dump_address_messages(&handle).await
}

async fn dump_address_messages(
    handle: &Handle,
) -> Result<Vec<AddressMessage>, NipartError> {
    let mut messages = Vec::new();
    let mut stream = handle.address().get().execute();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|e| map_rtnetlink_error("Failed to dump kernel addresses", e))?
    {
        messages.push(message);
    }
    Ok(messages)
}
