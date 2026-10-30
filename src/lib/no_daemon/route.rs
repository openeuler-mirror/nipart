// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file are:
//  * Gris Ge <fge@redhat.com>
//  * Wen Liang <liangwen12year@gmail.com>
//  * Íñigo Huguet <ihuguet@redhat.com>
//  * Jan Vaclav <jvaclav@redhat.com>

use std::collections::HashMap;

use crate::{
    ErrorKind, Interfaces, MergedRoutes, NipartError, NipartInterface,
    RouteEntry, Routes,
    netlink::{
        link::LinkIndexMap,
        route::{
            apply_routes as netlink_apply_routes,
            get_routes as netlink_get_routes,
        },
    },
};

pub(crate) async fn get_routes(ifaces: &Interfaces) -> Routes {
    let mut index_map = LinkIndexMap::default();
    for iface in ifaces.iter() {
        let base_iface = iface.base_iface();
        if let Some(index) = base_iface.iface_index {
            index_map.insert(index, base_iface.name.clone());
        }
    }
    match netlink_get_routes(&index_map).await {
        Ok(routes) => routes,
        Err(e) => {
            log::warn!("Failed to retrieve routes via netlink: {e}");
            Routes {
                running: Some(Vec::new()),
                config: Some(Vec::new()),
            }
        }
    }
}

pub(crate) async fn apply_routes(
    merged_routes: &MergedRoutes,
) -> Result<(), NipartError> {
    if !merged_routes.is_changed() {
        log::debug!("Route is not changed");
        return Ok(());
    }
    validate_routes(merged_routes)?;
    netlink_apply_routes(&merged_routes.changed_routes).await
}

fn validate_routes(merged_routes: &MergedRoutes) -> Result<(), NipartError> {
    for iface in merged_routes.route_changed_ifaces.as_slice() {
        let Some(iface_routes) = merged_routes.merged.get(iface) else {
            continue;
        };

        let mut hashed_rts: HashMap<(&str, Option<u32>), &RouteEntry> =
            HashMap::new();
        for rt in iface_routes {
            if rt.weight.is_some() {
                return Err(NipartError::new(
                    ErrorKind::NoSupport,
                    "Kernel mode does not support ECMP routes".to_string(),
                ));
            }

            // The `Routes::validate()` already confirmed non-absent routes
            // always has destination.
            // The `merged_routes.merged` does not have absent route.
            let dst = if let Some(dst) = rt.destination.as_deref() {
                dst
            } else {
                continue;
            };

            if hashed_rts
                .insert(
                    (dst, rt.metric.and_then(|m| u32::try_from(m).ok())),
                    rt,
                )
                .is_some()
            {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "Multiple routes to {dst} are sharing the same \
                         metric, please use `state: absent` to remove others."
                    ),
                ));
            }
        }
    }
    Ok(())
}
