// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use std::{collections::HashMap, net::IpAddr};

use futures_util::TryStreamExt;
use rtnetlink::{
    AddressMessageBuilder, Handle,
    packet_route::{
        AddressFamily,
        address::{
            AddressAttribute, AddressFlags, AddressMessage, AddressProtocol,
            CacheInfo,
        },
    },
};

use crate::{
    BaseInterface, ErrorKind, InterfaceIpAddr, InterfaceIpv4, InterfaceIpv6,
    NipartError,
    netlink::{
        link::get_index_map, map_rtnetlink_error, new_connection,
    },
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

pub(crate) async fn has_link_local_addr(
    iface_name: &str,
) -> Result<bool, NipartError> {
    let handle = new_connection().await?;
    let index_map = get_index_map(&handle).await?;
    let Some(index) = index_map.index(iface_name) else {
        return Ok(false);
    };
    let messages = dump_address_messages(&handle).await?;
    Ok(messages
        .iter()
        .filter(|message| message.header.index == index)
        .filter_map(address_info)
        .any(|info| match info.address.ip {
            IpAddr::V6(ip) => ip.is_unicast_link_local(),
            IpAddr::V4(_) => false,
        }))
}

#[cfg(test)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddressAction {
    pub(crate) address: InterfaceIpAddr,
    pub(crate) remove: bool,
    pub(crate) protocol: Option<AddressProtocol>,
}

pub(crate) fn ip_address_actions(
    des_iface: &BaseInterface,
    cur_iface: Option<&BaseInterface>,
) -> Vec<AddressAction> {
    if des_iface.is_absent() {
        return Vec::new();
    }
    let empty_iface = des_iface.clone_name_type_only();
    let cur_iface = cur_iface.unwrap_or(&empty_iface);
    let mut actions = Vec::new();

    if des_iface.ipv4.as_ref() != cur_iface.ipv4.as_ref()
        && let Some(des_ipv4) = des_iface.ipv4.as_ref()
    {
        let des_addrs = if des_ipv4.is_enabled() {
            des_ipv4.addresses.as_deref().unwrap_or_default()
        } else {
            &[]
        };
        let cur_addrs = cur_iface
            .ipv4
            .as_ref()
            .filter(|ipv4| ipv4.is_enabled())
            .and_then(|ipv4| ipv4.addresses.as_deref())
            .unwrap_or_default();
        actions.extend(address_list_actions(des_addrs, cur_addrs));
    }

    if des_iface.ipv6.as_ref() != cur_iface.ipv6.as_ref()
        && let Some(des_ipv6) = des_iface.ipv6.as_ref()
    {
        let des_addrs = if des_ipv6.is_enabled() {
            des_ipv6.addresses.as_deref().unwrap_or_default()
        } else {
            &[]
        };
        let cur_addrs: Vec<InterfaceIpAddr> = cur_iface
            .ipv6
            .as_ref()
            .filter(|ipv6| ipv6.is_enabled())
            .and_then(|ipv6| ipv6.addresses.as_ref())
            .map(|addresses| {
                addresses
                    .iter()
                    .filter(|address| {
                        if des_ipv6.is_enabled() {
                            match address.ip {
                                IpAddr::V6(ip) => !ip.is_unicast_link_local(),
                                IpAddr::V4(_) => true,
                            }
                        } else {
                            true
                        }
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        actions.extend(address_list_actions(des_addrs, &cur_addrs));
    }

    actions
}

fn address_list_actions(
    des_addrs: &[InterfaceIpAddr],
    cur_addrs: &[InterfaceIpAddr],
) -> Vec<AddressAction> {
    let mut actions = Vec::new();

    if is_appending(des_addrs, cur_addrs) {
        for cur_addr in cur_addrs {
            if !des_addrs.contains(cur_addr) {
                actions.push(AddressAction {
                    address: cur_addr.clone(),
                    remove: true,
                    protocol: None,
                });
            }
        }
        for des_addr in des_addrs {
            if !cur_addrs.contains(des_addr) {
                actions.push(AddressAction {
                    address: des_addr.clone(),
                    remove: false,
                    protocol: None,
                });
            }
        }
    } else if is_replacing(des_addrs, cur_addrs) {
        for des_addr in des_addrs {
            actions.push(AddressAction {
                address: des_addr.clone(),
                remove: false,
                protocol: None,
            });
        }
    } else {
        // Purge all current IP addresses, so we get expected address order.
        for cur_addr in cur_addrs {
            actions.push(AddressAction {
                address: cur_addr.clone(),
                remove: true,
                protocol: None,
            });
        }
        for des_addr in des_addrs {
            actions.push(AddressAction {
                address: des_addr.clone(),
                remove: false,
                protocol: None,
            });
        }
    }

    actions
}

fn is_appending(
    des_addrs: &[InterfaceIpAddr],
    cur_addrs: &[InterfaceIpAddr],
) -> bool {
    cur_addrs.len() < des_addrs.len()
        && &des_addrs[..cur_addrs.len()] == cur_addrs
}

fn is_replacing(
    des_addrs: &[InterfaceIpAddr],
    cur_addrs: &[InterfaceIpAddr],
) -> bool {
    cur_addrs.len() == des_addrs.len()
        && des_addrs.iter().all(|des_addr| {
            cur_addrs.iter().any(|cur_addr| {
                des_addr.ip == cur_addr.ip
                    && des_addr.prefix_length == cur_addr.prefix_length
            })
        })
}

pub(crate) async fn apply_iface_ip_changes(
    des_iface: &BaseInterface,
    cur_iface: Option<&BaseInterface>,
) -> Result<(), NipartError> {
    let actions = ip_address_actions(des_iface, cur_iface);
    if actions.is_empty() {
        return Ok(());
    }
    let handle = new_connection().await?;
    let index_map = get_index_map(&handle).await?;
    let index = index_map.index(&des_iface.name).ok_or_else(|| {
        NipartError::new(
            ErrorKind::InvalidArgument,
            format!(
                "Interface {} does not exist for IP address apply",
                des_iface.name
            ),
        )
    })?;
    apply_address_actions(&handle, index, &actions).await
}

async fn apply_address_actions(
    handle: &Handle,
    index: u32,
    actions: &[AddressAction],
) -> Result<(), NipartError> {
    for action in actions {
        if action.remove {
            let message = address_del_message(
                index,
                &action.address,
                action.protocol,
            )?;
            log::trace!(
                "Removing IP address {}/{} from interface index {index}",
                action.address.ip,
                action.address.prefix_length
            );
            match handle.address().del(message).execute().await {
                Ok(()) => (),
                Err(e)
                    if is_errno(&e, nix::errno::Errno::EADDRNOTAVAIL) => (),
                Err(e) => {
                    return Err(map_rtnetlink_error(
                        "Failed to remove IP address",
                        e,
                    ));
                }
            }
        } else {
            log::trace!(
                "Adding IP address {}/{} to interface index {index}",
                action.address.ip,
                action.address.prefix_length
            );
            let mut request = handle
                .address()
                .add(
                    index,
                    action.address.ip,
                    action.address.prefix_length,
                )
                .replace();
            request
                .message_mut()
                .attributes
                .extend(address_extra_attributes(
                    &action.address,
                    action.protocol,
                )?);
            if let Err(e) = request.execute().await {
                return Err(map_rtnetlink_error(
                    "Failed to add IP address",
                    e,
                ));
            }
        }
    }
    Ok(())
}

fn is_errno(error: &rtnetlink::Error, errno: nix::errno::Errno) -> bool {
    matches!(error, rtnetlink::Error::NetlinkError(e)
        if e.raw_code() == -(errno as i32))
}

pub(crate) fn address_add_message(
    index: u32,
    address: &InterfaceIpAddr,
    protocol: Option<AddressProtocol>,
) -> Result<AddressMessage, NipartError> {
    validate_prefix_length(address)?;
    let mut message = match address.ip {
        IpAddr::V4(ip) => AddressMessageBuilder::<std::net::Ipv4Addr>::new()
            .index(index)
            .address(ip, address.prefix_length)
            .build(),
        IpAddr::V6(ip) => AddressMessageBuilder::<std::net::Ipv6Addr>::new()
            .index(index)
            .address(ip, address.prefix_length)
            .build(),
    };
    message
        .attributes
        .extend(address_extra_attributes(address, protocol)?);
    Ok(message)
}

pub(crate) fn address_del_message(
    index: u32,
    address: &InterfaceIpAddr,
    protocol: Option<AddressProtocol>,
) -> Result<AddressMessage, NipartError> {
    validate_prefix_length(address)?;
    let mut message = AddressMessage::default();
    message.header.index = index;
    message.header.prefix_len = address.prefix_length;
    message.header.family = match address.ip {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    message
        .attributes
        .push(AddressAttribute::Address(address.ip));
    if let Some(protocol) = protocol {
        message
            .attributes
            .push(AddressAttribute::Protocol(protocol));
    }
    Ok(message)
}

pub(crate) fn address_extra_attributes(
    address: &InterfaceIpAddr,
    protocol: Option<AddressProtocol>,
) -> Result<Vec<AddressAttribute>, NipartError> {
    let mut attributes = Vec::new();
    if let Some(protocol) = protocol {
        attributes.push(AddressAttribute::Protocol(protocol));
    }
    if let Some(cache_info) = cache_info_from_lifetimes(address)? {
        attributes.push(AddressAttribute::CacheInfo(cache_info));
    }
    Ok(attributes)
}

fn validate_prefix_length(
    address: &InterfaceIpAddr,
) -> Result<(), NipartError> {
    let max_prefix_length = if address.ip.is_ipv4() { 32 } else { 128 };
    if address.prefix_length > max_prefix_length {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!(
                "Invalid prefix length {} for address {}, should be no \
                 greater than {max_prefix_length}",
                address.prefix_length, address.ip
            ),
        ));
    }
    Ok(())
}
