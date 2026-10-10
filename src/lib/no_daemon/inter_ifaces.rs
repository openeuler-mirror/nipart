// SPDX-License-Identifier: Apache-2.0

use super::{
    iface::{apply_iface_link_changes, nipart_iface_type_to_nispor},
    ip::apply_iface_ip_changes,
};
use crate::{
    ErrorKind, Interface, MergedInterface, MergedInterfaces, NipartError,
    NipartInterface, NipartNoDaemon,
};

pub(crate) async fn apply_ifaces(
    merged_ifaces: &mut MergedInterfaces,
) -> Result<(), NipartError> {
    let to_apply_ifaces = merged_ifaces.gen_state_for_apply();
    for apply_iface in to_apply_ifaces.iter() {
        log::info!("Applying: {apply_iface}");
    }
    delete_ifaces_before_apply(merged_ifaces).await?;
    rename_ifaces_before_apply(merged_ifaces).await?;

    // Some interface might been deleted when apply, hence it is OK to fail, we
    // trust verification stage to find the problem
    if let Err(e) = apply_ifaces_link_changes(merged_ifaces).await {
        log::info!("{e}");
    }
    if let Err(e) = apply_ifaces_ip_changes(merged_ifaces).await {
        log::info!("{e}");
    }

    Ok(())
}

async fn delete_ifaces_before_apply(
    merged_ifaces: &mut MergedInterfaces,
) -> Result<(), NipartError> {
    let mut np_ifaces: Vec<nispor::IfaceConf> = Vec::new();

    // Some changed interfaces might need delete first
    for merged_iface in merged_ifaces.kernel_ifaces.values_mut().filter(|m| {
        m.merged.is_up() && m.for_apply.is_some() && m.current.is_some()
    }) {
        if let Some(for_apply) = merged_iface.for_apply.as_ref()
            && let Some(for_save) = merged_iface.for_save.as_ref()
            && let Some(current) = merged_iface.current.as_ref()
            && Interface::need_delete_before_change(for_apply, current)
        {
            log::debug!(
                "Need to delete interface {}/{} before making changes",
                for_apply.name(),
                for_apply.iface_type()
            );
            let mut np_iface = nispor::IfaceConf::default();
            np_iface.name = for_apply.kernel_iface_name().to_string();
            np_iface.iface_type =
                Some(nipart_iface_type_to_nispor(for_apply.iface_type()));
            np_iface.state = nispor::IfaceState::Absent;
            np_ifaces.push(np_iface);
            merged_iface.current = None;
            merged_iface.merged = for_save.clone();
            merged_iface.for_apply = Some(for_save.clone());
            merged_iface.for_verify = Some(for_save.clone());
        }
    }
    for for_apply in merged_ifaces
        .kernel_ifaces
        .values()
        .filter_map(|m| m.for_apply.as_ref())
        .filter(|i| i.is_absent())
    {
        if for_apply.kernel_iface_name().is_empty() {
            return Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Got kernel for_apply iface with state: absent but \
                     holding empty kernel_iface_name: {for_apply}"
                ),
            ));
        }
        let mut np_iface = nispor::IfaceConf::default();
        np_iface.name = for_apply.kernel_iface_name().to_string();
        np_iface.iface_type =
            Some(nipart_iface_type_to_nispor(for_apply.iface_type()));
        np_iface.state = nispor::IfaceState::Absent;
        np_ifaces.push(np_iface);
    }
    if !np_ifaces.is_empty() {
        let mut net_conf = nispor::NetConf::default();
        net_conf.ifaces = Some(np_ifaces);

        log::debug!(
            "Pending nispor changes {}",
            serde_json::to_string(&net_conf).unwrap_or_default()
        );

        if let Err(e) = net_conf.apply_async().await {
            return Err(NipartError::new(
                ErrorKind::Bug,
                format!("Failed to delete interfaces: {e}"),
            ));
        }
    }
    Ok(())
}

/// Rename the interfaces whose desired `kernel-iface-name` differs from
/// their current kernel name (e.g. a `identifier: mac-address` config with
/// an explicit `kernel-iface-name` renames the matched interface).  nispor
/// cannot rename an existing interface, so the rename must be done before
/// the nispor batch below (which looks the interface up by its new name).
async fn rename_ifaces_before_apply(
    merged_ifaces: &MergedInterfaces,
) -> Result<(), NipartError> {
    // Vec<(iface_index, cur_name, new_name)>
    let mut renames: Vec<(u32, String, String)> = Vec::new();
    for merged_iface in merged_ifaces.iter() {
        let Some(apply_iface) = merged_iface.for_apply.as_ref() else {
            continue;
        };
        let Some(cur_iface) = merged_iface.current.as_ref() else {
            continue;
        };
        if apply_iface.is_absent() {
            continue;
        }
        let new_name = apply_iface.kernel_iface_name();
        let cur_name = cur_iface.kernel_iface_name();
        if new_name.is_empty() || new_name == cur_name {
            continue;
        }
        let Some(iface_index) = cur_iface.base_iface().iface_index else {
            continue;
        };
        renames.push((iface_index, cur_name.to_string(), new_name.to_string()));
    }
    if renames.is_empty() {
        return Ok(());
    }
    let (conn, handle, _) = rtnetlink::new_connection().map_err(|e| {
        NipartError::new(
            ErrorKind::Bug,
            format!("Failed to create rtnetlink connection: {e}"),
        )
    })?;
    tokio::spawn(conn);
    for (iface_index, cur_name, new_name) in renames {
        log::info!("Renaming interface {cur_name} to {new_name}");
        let msg = rtnetlink::LinkUnspec::new_with_index(iface_index)
            .name(new_name.clone())
            .build();
        handle.link().set(msg).execute().await.map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to rename interface {cur_name} to {new_name}: {e}"
                ),
            )
        })?;
    }
    Ok(())
}

/// Apply link level changes (e.g. state up/down, attach to controller)
async fn apply_ifaces_link_changes(
    merged_ifaces: &MergedInterfaces,
) -> Result<(), NipartError> {
    let mut np_ifaces: Vec<nispor::IfaceConf> = Vec::new();

    let mut sorted_changed_mergd_ifaces: Vec<MergedInterface> = merged_ifaces
        .iter()
        .filter_map(|m| {
            if m.is_changed() && !m.is_absent() {
                Some(m.clone())
            } else {
                None
            }
        })
        .collect();

    sorted_changed_mergd_ifaces.sort_unstable_by_key(|m| {
        (!m.is_absent(), m.up_priority.unwrap_or_default())
    });

    for merged_iface in sorted_changed_mergd_ifaces.as_slice() {
        let apply_iface = if let Some(i) = merged_iface.for_apply.as_ref() {
            i
        } else {
            continue;
        };

        // Skip interface when it is not virtual and not exist in current.
        if !apply_iface.is_virtual() && merged_iface.current.is_none() {
            log::debug!(
                "Ignore non-exist physical interface {}/{}",
                apply_iface.name(),
                apply_iface.iface_type()
            );
            continue;
        }

        if !apply_iface.iface_type().is_userspace() {
            for np_iface in
                apply_iface_link_changes(merged_iface, merged_ifaces)?
            {
                np_ifaces.push(np_iface);
            }
        }
    }

    // When port config changed in controller, the `apply_ifaces` above
    // will not have port. And we cannot touch ports when processing controller
    // because port might be virtual interface which is about to created.
    // Hence we handle port config in this separate loop.
    for merged_iface in
        sorted_changed_mergd_ifaces.iter().filter(|merged_iface| {
            merged_iface.merged.is_controller()
                && merged_iface.is_desired()
                && merged_iface.merged.is_up()
        })
    {
        let apply_iface = if let Some(i) = merged_iface.for_apply.as_ref() {
            i
        } else {
            continue;
        };
        match apply_iface {
            Interface::Bond(bond_iface) => {
                np_ifaces.extend(bond_iface.apply_bond_port_configs());
            }
            Interface::LinuxBridge(br_iface) => {
                np_ifaces.extend(br_iface.apply_linux_bridge_port_configs(
                    if let Some(Interface::LinuxBridge(cur_br_iface)) =
                        merged_iface.current.as_ref()
                    {
                        Some(cur_br_iface)
                    } else {
                        None
                    },
                ));
            }
            Interface::OvsBridge(_) => {
                // Place holder
            }
            _ => (),
        }
    }

    if !np_ifaces.is_empty() {
        let mut net_conf = nispor::NetConf::default();
        net_conf.ifaces = Some(np_ifaces);

        log::trace!(
            "Pending nispor changes {}",
            serde_json::to_string(&net_conf).unwrap_or_default()
        );
        if let Err(e) = net_conf.apply_async().await {
            return Err(NipartError::new(
                ErrorKind::Bug,
                format!("Failed to change link layer: {e}"),
            ));
        }
    }

    Ok(())
}

async fn apply_ifaces_ip_changes(
    merged_ifaces: &MergedInterfaces,
) -> Result<(), NipartError> {
    let mut np_ifaces: Vec<nispor::IfaceConf> = Vec::new();

    for merged_iface in merged_ifaces.kernel_ifaces.values() {
        // Force allow IPv6 router advertisements when autoconf is enabled,
        // so that SLAAC works even when IPv6 forwarding is enabled. IPv6
        // must be enabled first, otherwise the accept_ra setting has no
        // effect. Key off the desired state so the sysctls are applied even
        // when the interface diff is empty. Use the resolved kernel name
        // (`merged_iface.name()`) because `des_iface.name()` might hold a
        // profile name.
        if let Some(des_iface) = merged_iface.desired.as_ref()
            && let Some(ipv6_conf) = des_iface.base_iface().ipv6.as_ref()
            && ipv6_conf.autoconf == Some(true)
        {
            let iface_name = merged_iface.name();
            log::debug!(
                "Forcing IPv6 autoconf (accept_ra=2) on interface {iface_name}"
            );
            NipartNoDaemon::enable_ipv6(iface_name).await?;
            NipartNoDaemon::enable_autoconf(iface_name).await?;
        }

        if let Some(apply_iface) = merged_iface.for_apply.as_ref()
            && let Some(np_iface) = apply_iface_ip_changes(
                apply_iface.base_iface(),
                merged_iface.current.as_ref().map(|c| c.base_iface()),
            )?
        {
            np_ifaces.push(np_iface);
        }
    }
    if !np_ifaces.is_empty() {
        let mut net_conf = nispor::NetConf::default();
        net_conf.ifaces = Some(np_ifaces);

        log::debug!(
            "Pending nispor changes {}",
            serde_json::to_string(&net_conf).unwrap_or_default()
        );

        if let Err(e) = net_conf.apply_async().await {
            return Err(NipartError::new(
                ErrorKind::Bug,
                format!("Failed to change IP: {e}"),
            ));
        }
    }

    Ok(())
}
