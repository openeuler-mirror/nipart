// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use std::net::IpAddr;

use rtnetlink::packet_route::{
    AddressFamily,
    address::{
        AddressAttribute, AddressFlags, AddressMessage, AddressProtocol,
        CacheInfo,
    },
};

use crate::{
    ErrorKind, InterfaceIpAddr, InterfaceIpv4, InterfaceIpv6, NipartError,
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
    for info in infos {
        if info.address.ip.is_ipv4() {
            addresses.push(info.address.clone());
        }
    }
    if addresses.is_empty() {
        Some(InterfaceIpv4::default())
    } else {
        Some(InterfaceIpv4 {
            enabled: Some(true),
            addresses: Some(addresses),
            ..Default::default()
        })
    }
}

pub(crate) fn ipv6_from_address_infos<'a>(
    infos: impl IntoIterator<Item = &'a AddressInfo>,
) -> Option<InterfaceIpv6> {
    let mut addresses = Vec::new();
    for info in infos {
        if info.address.ip.is_ipv6() {
            addresses.push(info.address.clone());
        }
    }
    if addresses.is_empty() {
        Some(InterfaceIpv6::default())
    } else {
        Some(InterfaceIpv6 {
            enabled: Some(true),
            addresses: Some(addresses),
            ..Default::default()
        })
    }
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
