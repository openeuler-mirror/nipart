// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use std::collections::HashSet;

use rtnetlink::{
    Handle, LinkMessageBuilder, LinkUnspec,
    packet_route::link::{InfoKind, LinkMessage},
};

use super::{
    bond, bridge, get_iface_index, get_iface_index_opt, macsec, vlan, vrf,
    vxlan, wireguard::apply_wireguard_config,
};
use crate::{
    BaseInterface, BondInterface, ErrorKind, Interface, InterfaceState,
    LinuxBridgeInterface, NipartError, NipartInterface,
    netlink::map_rtnetlink_error,
};

pub(crate) async fn apply_iface_link_changes(
    handle: &Handle,
    des_iface: &Interface,
    cur_iface: Option<&Interface>,
    existing_iface_names: &HashSet<String>,
) -> Result<(), NipartError> {
    let mut messages = prepare_link_messages(
        handle,
        des_iface,
        cur_iface,
        existing_iface_names,
    )
    .await?;

    if cur_iface.is_some() {
        for message in messages {
            log::trace!(
                "Changing interface {}/{} via netlink",
                des_iface.name(),
                des_iface.iface_type()
            );
            handle.link().change(message).execute().await.map_err(|e| {
                map_rtnetlink_error(
                    &format!("Failed to change interface {}", des_iface.name()),
                    e,
                )
            })?;
        }
    } else {
        if !messages.is_empty() {
            let message = messages.remove(0);
            log::trace!(
                "Creating interface {}/{} via netlink",
                des_iface.name(),
                des_iface.iface_type()
            );
            handle.link().add(message).execute().await.map_err(|e| {
                map_rtnetlink_error(
                    &format!("Failed to create interface {}", des_iface.name()),
                    e,
                )
            })?;
        }
        for message in messages {
            log::trace!(
                "Changing interface {}/{} via netlink",
                des_iface.name(),
                des_iface.iface_type()
            );
            handle.link().change(message).execute().await.map_err(|e| {
                map_rtnetlink_error(
                    &format!("Failed to change interface {}", des_iface.name()),
                    e,
                )
            })?;
        }
    }

    apply_alt_names(handle, des_iface, cur_iface).await?;

    if let Interface::LinuxBridge(bridge_iface) = des_iface {
        apply_bridge_vlans(handle, bridge_iface, cur_iface).await?;
    }

    if let Interface::Wireguard(wg_iface) = des_iface
        && let Some(config) = wg_iface.wireguard.as_ref()
    {
        apply_wireguard_config(&wg_iface.base.name, config).await?;
    }

    if let Interface::MacSec(macsec_iface) = des_iface
        && cur_iface.is_some()
        && let Some(offload) = macsec_iface
            .macsec
            .as_ref()
            .and_then(|config| config.offload)
    {
        macsec::apply_macsec_offload(
            handle,
            macsec_iface.base.name.as_str(),
            offload,
        )
        .await?;
    }

    Ok(())
}

async fn prepare_link_messages(
    handle: &Handle,
    des_iface: &Interface,
    cur_iface: Option<&Interface>,
    existing_iface_names: &HashSet<String>,
) -> Result<Vec<LinkMessage>, NipartError> {
    match des_iface {
        Interface::LinuxBridge(bridge_iface) => {
            let cur_bridge = cur_iface.and_then(|i| match i {
                Interface::LinuxBridge(cur) => Some(cur.as_ref()),
                _ => None,
            });
            let builder =
                bridge::bridge_link_builder(bridge_iface, cur_bridge)?;
            apply_base_link_changes(handle, builder, des_iface, cur_iface).await
        }
        Interface::Ethernet(eth_iface) => {
            if let Some(veth) = eth_iface.veth.as_ref() {
                let cur_peer = cur_iface.and_then(|i| match i {
                    Interface::Ethernet(cur) => {
                        cur.veth.as_ref().map(|v| v.peer.as_str())
                    }
                    _ => None,
                });
                let mut messages = if let Some(cur_peer) = cur_peer {
                    if !veth.peer.is_empty()
                        && cur_peer.parse::<i32>().is_err()
                        && veth.peer.as_str() != cur_peer
                    {
                        return Err(NipartError::new(
                            ErrorKind::InvalidArgument,
                            format!(
                                "Cannot change veth interface {} peer from {} \
                                 to {} without removing a veth first",
                                eth_iface.base.name, cur_peer, veth.peer
                            ),
                        ));
                    }
                    let builder = LinkMessageBuilder::<
                        rtnetlink::LinkVeth,
                    >::new_with_info_kind(InfoKind::Veth)
                    .name(eth_iface.base.name.to_string());
                    apply_base_link_changes(
                        handle, builder, des_iface, cur_iface,
                    )
                    .await?
                } else {
                    let builder = rtnetlink::LinkVeth::new(
                        eth_iface.base.name.as_str(),
                        veth.peer.as_str(),
                    );
                    apply_base_link_changes(
                        handle, builder, des_iface, cur_iface,
                    )
                    .await?
                };
                if cur_iface.is_none()
                    && eth_iface.is_up()
                    && !veth.peer.is_empty()
                {
                    messages.push(
                        LinkUnspec::new_with_name(veth.peer.as_str())
                            .up()
                            .build(),
                    );
                }
                Ok(messages)
            } else {
                apply_base_link_changes(
                    handle,
                    LinkUnspec::new_with_name(eth_iface.base.name.as_str()),
                    des_iface,
                    cur_iface,
                )
                .await
            }
        }
        Interface::Bond(bond_iface) => {
            let cur_bond = cur_iface.and_then(|i| match i {
                Interface::Bond(cur) => Some(cur.as_ref()),
                _ => None,
            });
            let mut messages = Vec::new();
            if let Some(cur_bond) = cur_bond {
                messages.extend(
                    bond::bond_mode_change_messages(
                        handle,
                        bond_iface,
                        cur_bond,
                        existing_iface_names,
                    )
                    .await?,
                );
            }
            let builder =
                bond::bond_link_builder(handle, bond_iface, cur_bond).await?;
            messages.extend(
                apply_base_link_changes(handle, builder, des_iface, cur_iface)
                    .await?,
            );
            Ok(messages)
        }
        Interface::Vlan(vlan_iface) => {
            let cur_vlan = cur_iface.and_then(|i| match i {
                Interface::Vlan(cur) => Some(cur.as_ref()),
                _ => None,
            });
            let builder =
                vlan::vlan_link_builder(handle, vlan_iface, cur_vlan).await?;
            apply_base_link_changes(handle, builder, des_iface, cur_iface).await
        }
        Interface::Vrf(vrf_iface) => {
            let cur_vrf = cur_iface.and_then(|i| match i {
                Interface::Vrf(cur) => Some(cur.as_ref()),
                _ => None,
            });
            let builder = vrf::vrf_link_builder(vrf_iface, cur_vrf)?;
            apply_base_link_changes(handle, builder, des_iface, cur_iface).await
        }
        Interface::Vxlan(vxlan_iface) => {
            let cur_vxlan = cur_iface.and_then(|i| match i {
                Interface::Vxlan(cur) => Some(cur.as_ref()),
                _ => None,
            });
            if cur_iface.is_some() {
                let mut messages = apply_base_link_changes(
                    handle,
                    LinkUnspec::new_with_name(vxlan_iface.base.name.as_str()),
                    des_iface,
                    cur_iface,
                )
                .await?;
                messages.push(
                    vxlan::vxlan_link_builder(handle, vxlan_iface, cur_vxlan)
                        .await?
                        .build(),
                );
                Ok(messages)
            } else {
                let builder =
                    vxlan::vxlan_link_builder(handle, vxlan_iface, None)
                        .await?;
                apply_base_link_changes(handle, builder, des_iface, cur_iface)
                    .await
            }
        }
        Interface::Dummy(dummy_iface) if cur_iface.is_none() => {
            apply_base_link_changes(
                handle,
                rtnetlink::LinkDummy::new(dummy_iface.base.name.as_str()),
                des_iface,
                cur_iface,
            )
            .await
        }
        Interface::Wireguard(wg_iface) if cur_iface.is_none() => {
            apply_base_link_changes(
                handle,
                LinkMessageBuilder::<LinkUnspec>::new_with_info_kind(
                    InfoKind::Wireguard,
                )
                .name(wg_iface.base.name.to_string()),
                des_iface,
                cur_iface,
            )
            .await
        }
        Interface::MacSec(macsec_iface) => {
            let builder = macsec::macsec_link_builder(
                handle,
                macsec_iface,
                cur_iface.is_some(),
            )
            .await?;
            apply_base_link_changes(handle, builder, des_iface, cur_iface).await
        }
        _ => {
            apply_base_link_changes(
                handle,
                LinkUnspec::new_with_name(des_iface.name()),
                des_iface,
                cur_iface,
            )
            .await
        }
    }
}

async fn apply_base_link_changes<T>(
    handle: &Handle,
    mut builder: LinkMessageBuilder<T>,
    des_iface: &Interface,
    cur_iface: Option<&Interface>,
) -> Result<Vec<LinkMessage>, NipartError> {
    let des_base = des_iface.base_iface();
    let cur_base = cur_iface.map(|i| i.base_iface());
    let mut ret = Vec::new();

    if let Some(cur_base) = cur_base
        && need_state_down_before_apply(des_base, cur_base)
        && cur_base.state == InterfaceState::Up
        && let Some(index) = cur_base.iface_index
    {
        ret.push(LinkUnspec::new_with_index(index).down().build());
    }

    if let Some(mtu) = des_base.mtu {
        builder = builder.mtu(mtu as u32);
    }

    if let Some(des_mac) = des_base.mac_address.as_deref()
        && !des_mac.is_empty()
    {
        let should_set = cur_base
            .map(|cur| {
                !cur.mac_address
                    .as_deref()
                    .unwrap_or_default()
                    .eq_ignore_ascii_case(des_mac)
            })
            .unwrap_or(true);
        if should_set {
            builder = builder
                .address(crate::netlink::mac::parse_mac_address(des_mac)?);
        }
    }

    // Apply the controller unconditionally when it is defined: the cached
    // current state may be stale after a controller was deleted and recreated
    // in this same apply, which detaches all of its ports in the kernel.
    // Re-attaching an already attached port is a no-op.
    if let Some(des_controller) = des_base.controller.as_ref() {
        if des_controller.is_empty() {
            builder = builder.nocontroller();
        } else {
            builder = builder
                .controller(get_iface_index(handle, des_controller).await?);
        }
    }

    ret.push(builder.build());

    match des_base.state {
        InterfaceState::Up => {
            ret.push(
                LinkUnspec::new_with_name(des_base.name.as_str())
                    .up()
                    .build(),
            );
        }
        InterfaceState::Down => {
            ret.push(
                LinkUnspec::new_with_name(des_base.name.as_str())
                    .down()
                    .build(),
            );
        }
        _ => (),
    }

    Ok(ret)
}

fn need_state_down_before_apply(
    des_base: &BaseInterface,
    cur_base: &BaseInterface,
) -> bool {
    if let Some(des_mac) = des_base.mac_address.as_deref()
        && !des_mac.is_empty()
        && !cur_base
            .mac_address
            .as_deref()
            .unwrap_or_default()
            .eq_ignore_ascii_case(des_mac)
    {
        return true;
    }
    des_base.controller.is_some() && des_base.controller != cur_base.controller
}

async fn apply_alt_names(
    handle: &Handle,
    des_iface: &Interface,
    cur_iface: Option<&Interface>,
) -> Result<(), NipartError> {
    let des_base = des_iface.base_iface();
    let Some(des_alt_names) = des_base.alt_names.as_ref() else {
        return Ok(());
    };
    let index = match cur_iface
        .and_then(|cur| cur.base_iface().iface_index)
        .or(des_base.iface_index)
    {
        Some(index) => index,
        None => get_iface_index(handle, des_base.name.as_str()).await?,
    };
    let cur_alt_names: HashSet<&str> = cur_iface
        .and_then(|cur| cur.base_iface().alt_names.as_ref())
        .map(|entries| {
            entries.iter().map(|entry| entry.name.as_str()).collect()
        })
        .unwrap_or_default();
    let mut to_add = Vec::new();
    let mut to_remove = Vec::new();
    for des_alt_name in des_alt_names {
        let des_absent = des_alt_name.is_absent();
        let cur_exists = cur_alt_names.contains(des_alt_name.name.as_str());
        match (des_absent, cur_exists) {
            (false, false) => to_add.push(des_alt_name.name.as_str()),
            (true, true) => to_remove.push(des_alt_name.name.as_str()),
            _ => (),
        }
    }
    if !to_add.is_empty() {
        handle
            .link()
            .property_add(index)
            .alt_ifname(&to_add)
            .execute()
            .await
            .map_err(|e| {
                map_rtnetlink_error("Failed to add alternative names", e)
            })?;
    }
    if !to_remove.is_empty() {
        handle
            .link()
            .property_del(index)
            .alt_ifname(&to_remove)
            .execute()
            .await
            .map_err(|e| {
                map_rtnetlink_error("Failed to remove alternative names", e)
            })?;
    }
    Ok(())
}

async fn apply_bridge_vlans(
    handle: &Handle,
    bridge_iface: &LinuxBridgeInterface,
    cur_iface: Option<&Interface>,
) -> Result<(), NipartError> {
    let Some(des_vlan) = bridge_iface
        .bridge
        .as_ref()
        .and_then(|bridge| bridge.vlan.as_ref())
    else {
        return Ok(());
    };
    let cur_bridge = cur_iface.and_then(|i| match i {
        Interface::LinuxBridge(cur) => Some(cur.as_ref()),
        _ => None,
    });
    let cur_vlan = cur_bridge
        .and_then(|cur| cur.bridge.as_ref())
        .and_then(|bridge| bridge.vlan.as_ref());
    let index =
        get_iface_index(handle, bridge_iface.base.name.as_str()).await?;
    let entries = bridge::gen_bridge_vlan_entries(des_vlan, cur_vlan);
    if let Some(message) =
        bridge::bridge_vlan_del_message(index, true, &entries)
    {
        handle
            .link()
            .del_with_message(message)
            .execute()
            .await
            .map_err(|e| {
                map_rtnetlink_error("Failed to remove bridge VLANs", e)
            })?;
    }
    if let Some(message) =
        bridge::bridge_vlan_add_message(index, true, &entries)
    {
        handle.link().set(message).execute().await.map_err(|e| {
            map_rtnetlink_error("Failed to set bridge VLANs", e)
        })?;
    }
    Ok(())
}

pub(crate) async fn delete_iface(
    handle: &Handle,
    iface_name: &str,
) -> Result<(), NipartError> {
    let Some(index) = get_iface_index_opt(handle, iface_name).await? else {
        log::debug!("Absent interface {iface_name} not found, no action");
        return Ok(());
    };
    handle.link().del(index).execute().await.map_err(|e| {
        map_rtnetlink_error(
            &format!("Failed to delete interface {iface_name}"),
            e,
        )
    })
}

pub(crate) async fn apply_bond_port_configs(
    handle: &Handle,
    iface: &BondInterface,
) -> Result<(), NipartError> {
    let Some(ports) = iface.bond.as_ref().and_then(|bond| bond.ports.as_ref())
    else {
        return Ok(());
    };
    for port in ports.iter().filter(|port| !port.is_name_only()) {
        let index = get_iface_index(handle, port.name.as_str()).await?;
        let mut builder = rtnetlink::LinkBondPort::new(index);
        if let Some(value) = port.queue_id {
            builder = builder.queue_id(value);
        }
        if let Some(value) = port.priority {
            builder = builder.prio(value);
        }
        handle
            .link()
            .change(builder.build())
            .execute()
            .await
            .map_err(|e| {
                map_rtnetlink_error(
                    &format!("Failed to configure bond port {}", port.name),
                    e,
                )
            })?;
    }
    Ok(())
}

pub(crate) async fn apply_bridge_port_configs(
    handle: &Handle,
    iface: &LinuxBridgeInterface,
    cur_iface: Option<&LinuxBridgeInterface>,
) -> Result<(), NipartError> {
    let Some(ports) = iface
        .bridge
        .as_ref()
        .and_then(|bridge| bridge.ports.as_ref())
    else {
        return Ok(());
    };
    for port in ports.iter().filter(|port| !port.is_name_only()) {
        let index = get_iface_index(handle, port.name.as_str()).await?;
        let message = bridge::bridge_port_message(index, port);
        handle.link().change(message).execute().await.map_err(|e| {
            map_rtnetlink_error(
                &format!("Failed to configure linux bridge port {}", port.name),
                e,
            )
        })?;
        if let Some(des_vlan) = port.vlan.as_ref() {
            let cur_vlan = cur_iface
                .and_then(|cur| cur.get_port_conf(port.name.as_str()))
                .and_then(|cur_port| cur_port.vlan.as_ref());
            let entries = bridge::gen_bridge_vlan_entries(des_vlan, cur_vlan);
            if let Some(message) =
                bridge::bridge_vlan_del_message(index, false, &entries)
            {
                handle
                    .link()
                    .del_with_message(message)
                    .execute()
                    .await
                    .map_err(|e| {
                        map_rtnetlink_error(
                            &format!(
                                "Failed to remove bridge port VLANs of {}",
                                port.name
                            ),
                            e,
                        )
                    })?;
            }
            if let Some(message) =
                bridge::bridge_vlan_add_message(index, false, &entries)
            {
                handle.link().set(message).execute().await.map_err(|e| {
                    map_rtnetlink_error(
                        &format!(
                            "Failed to set bridge port VLANs of {}",
                            port.name
                        ),
                        e,
                    )
                })?;
            }
        }
    }
    Ok(())
}
