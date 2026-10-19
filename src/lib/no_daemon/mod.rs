// SPDX-License-Identifier: Apache-2.0

mod apply;
mod dhcp;
mod inter_ifaces;
mod ip;
mod query;
mod resolv_conf;
mod route;
mod route_rule;
mod watcher;

use std::collections::HashSet;

use crate::InterfaceType;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NipartNoDaemon {}

impl NipartNoDaemon {
    /// Interface types that can be applied via kernel (no_daemon) path.
    /// Plugin-handled types (OvsBridge, OvsInterface, WifiCfg) and
    /// unsupported types are excluded.
    pub fn supported_iface_types() -> HashSet<InterfaceType> {
        HashSet::from([
            InterfaceType::Ethernet,
            InterfaceType::LinuxBridge,
            InterfaceType::Bond,
            InterfaceType::Dummy,
            InterfaceType::Loopback,
            InterfaceType::Veth,
            InterfaceType::Vlan,
            InterfaceType::Vrf,
            InterfaceType::Vxlan,
            InterfaceType::WifiPhy,
            InterfaceType::Wireguard,
            InterfaceType::MacSec,
        ])
    }
}
