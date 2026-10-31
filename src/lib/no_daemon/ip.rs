// SPDX-License-Identifier: Apache-2.0

use crate::{
    BaseInterface, InterfaceIpv4, InterfaceIpv6, NipartError, NipartNoDaemon,
};

pub(crate) use crate::netlink::addr::apply_iface_ip_changes;

impl NipartNoDaemon {
    /// Purge all IPv4 and IPv6 addresses from the interface.
    ///
    /// Used before restarting DHCP when the wifi-phy switches to a
    /// different SSID, so the previous network's lease cannot survive
    /// the switch.
    pub async fn purge_iface_ip(
        base_iface: &BaseInterface,
        current: Option<&BaseInterface>,
    ) -> Result<(), NipartError> {
        let mut purge_iface = base_iface.clone_name_type_only();
        purge_iface.ipv4 = Some(InterfaceIpv4::new_disabled());
        purge_iface.ipv6 = Some(InterfaceIpv6::new_disabled());
        apply_iface_ip_changes(&purge_iface, current).await
    }
}
