// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file
// (rust/src/lib/ifaces/vrf.rs) are:
//  * Gris Ge <fge@redhat.com>

use serde::{Deserialize, Serialize};

use crate::{
    BaseInterface, ErrorKind, InterfaceType, JsonDisplay, NipartError,
    NipartInterface,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonDisplay)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
/// Linux kernel Virtual Routing and Forwarding(VRF) interface. The example
/// yaml output of a [crate::NetworkState] with a VRF interface would be:
/// ```yml
/// interfaces:
/// - name: vrf0
///   type: vrf
///   state: up
///   ipv4:
///     enabled: false
///   ipv6:
///     enabled: false
///   vrf:
///     ports:
///     - eth1
///     - eth2
///     route-table-id: 100
/// ```
pub struct VrfInterface {
    #[serde(flatten)]
    pub base: BaseInterface,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vrf: Option<VrfConfig>,
}

impl Default for VrfInterface {
    fn default() -> Self {
        Self {
            base: BaseInterface {
                iface_type: InterfaceType::Vrf,
                ..Default::default()
            },
            vrf: None,
        }
    }
}

impl NipartInterface for VrfInterface {
    fn base_iface(&self) -> &BaseInterface {
        &self.base
    }

    fn base_iface_mut(&mut self) -> &mut BaseInterface {
        &mut self.base
    }

    fn is_virtual(&self) -> bool {
        true
    }

    fn ports(&self) -> Option<Vec<&str>> {
        self.vrf
            .as_ref()
            .and_then(|vrf_conf| vrf_conf.ports.as_ref())
            .map(|ports| ports.iter().map(|p| p.as_str()).collect())
    }

    /// * Ignore the MAC address as VRF is a layer 3(IP) interface.
    /// * `route-table-id` is mandatory for new VRF interface.
    /// * Fill `route-table-id` from current when desired undefined or 0.
    /// * Keep the saved config complete: fill the `vrf` section and the port
    ///   list from current when the desired state does not define them, so the
    ///   daemon can restore the whole VRF (including its ports) from the saved
    ///   config after restart.
    /// * Sort ports.
    fn sanitize(
        &self,
        current: Option<&Self>,
        for_save: &mut Self,
        for_apply: &mut Self,
        for_verify: &mut Self,
        merged: &mut Self,
    ) -> Result<(), NipartError> {
        let desired = self;

        if desired.is_absent() {
            return Ok(());
        }

        // VRF is a layer 3(IP) interface, kernel derives its MAC address
        // from the first enslaved port, ignore user defined MAC address.
        if let Some(mac) = desired.base.mac_address.as_ref() {
            log::warn!(
                "Ignoring MAC address {mac} of VRF interface {} as it is a \
                 layer 3(IP) interface",
                desired.name()
            );
        }
        for iface in [&mut *for_save, for_apply, for_verify, merged] {
            iface.base_iface_mut().mac_address = None;
        }

        let des_table_id = desired.vrf.as_ref().and_then(|v| v.table_id);
        let cur_table_id = current
            .as_ref()
            .and_then(|c| c.vrf.as_ref())
            .and_then(|v| v.table_id);

        if current.is_none()
            && (des_table_id.is_none() || des_table_id == Some(0))
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "`vrf.route-table-id` is mandatory for creating new VRF \
                     interface {}",
                    desired.name()
                ),
            ));
        }

        // Treat `route-table-id: 0` as undefined, fill from current like
        // nmstate does.
        if let Some(cur_table_id) = cur_table_id {
            for iface in [&mut *for_save, for_apply, for_verify, merged] {
                if let Some(vrf_conf) = iface.vrf.as_mut()
                    && (vrf_conf.table_id.is_none()
                        || vrf_conf.table_id == Some(0))
                {
                    vrf_conf.table_id = Some(cur_table_id);
                }
            }
        }

        // Keep the saved config complete so the daemon can restore the whole
        // VRF (including its ports and table ID) from the saved config after
        // restart: when the desired state does not define the `vrf` section
        // (or its port list), preserve the current values in `for_save`.
        // An explicitly empty `ports` list is kept as-is (removes all ports).
        if let Some(cur_vrf_conf) =
            current.as_ref().and_then(|c| c.vrf.as_ref())
        {
            if for_save.vrf.is_none() {
                for_save.vrf = Some(cur_vrf_conf.clone());
            } else if let Some(for_save_conf) = for_save.vrf.as_mut()
                && for_save_conf.ports.is_none()
            {
                for_save_conf.ports = cur_vrf_conf.ports.clone();
            }
        }

        // Sort ports so verification and diff are not affected by ordering.
        for iface in [&mut *for_save, for_apply, for_verify, merged] {
            if let Some(ports) =
                iface.vrf.as_mut().and_then(|c| c.ports.as_mut())
            {
                ports.sort_unstable();
            }
        }

        Ok(())
    }

    /// The Linux kernel does not support changing the route table ID of an
    /// existing VRF interface, hence nispor rejects such change and we need
    /// to delete and recreate the VRF interface first.
    fn need_delete_before_change(&self, current: &Self) -> bool {
        let desired = self;
        if let Some(des_table_id) =
            desired.vrf.as_ref().and_then(|v| v.table_id)
            && des_table_id != 0
        {
            return current.vrf.as_ref().and_then(|v| v.table_id)
                != Some(des_table_id);
        }
        false
    }
}

impl VrfInterface {
    pub(crate) fn change_port_name(
        &mut self,
        origin_name: &str,
        new_name: String,
    ) {
        if let Some(port_name) = self
            .vrf
            .as_mut()
            .and_then(|vrf_conf| vrf_conf.ports.as_mut())
            .and_then(|ports| {
                ports
                    .iter_mut()
                    .find(|port_name| port_name.as_str() == origin_name)
            })
        {
            *port_name = new_name;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct VrfConfig {
    #[serde(alias = "port", skip_serializing_if = "Option::is_none")]
    /// Port list.
    /// Deserialize and serialize from/to `ports`.
    /// Also deserialize from `port` for backwards compatibility.
    pub ports: Option<Vec<String>>,
    #[serde(
        rename = "route-table-id",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::deserializer::option_u32_or_string"
    )]
    /// Route table ID of this VRF interface.
    /// Deserialize and serialize from/to `route-table-id`.
    pub table_id: Option<u32>,
}
