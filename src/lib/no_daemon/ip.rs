// SPDX-License-Identifier: Apache-2.0

use std::{net::IpAddr, str::FromStr};

use crate::{
    BaseInterface, InterfaceIpAddr, InterfaceIpv4, InterfaceIpv6, NipartError,
    NipartNoDaemon,
    netlink::addr::apply_iface_ip_changes,
};

pub(crate) fn np_ipv4_to_nipart(
    np_iface: &nispor::Iface,
) -> Option<InterfaceIpv4> {
    if let Some(np_ip) = &np_iface.ipv4 {
        let mut ip = InterfaceIpv4 {
            enabled: Some(!np_ip.addresses.is_empty()),
            ..Default::default()
        };
        if !ip.is_enabled() {
            return Some(ip);
        }
        let mut addresses = Vec::new();
        for np_addr in &np_ip.addresses {
            if np_addr.valid_lft != "forever" {
                ip.dhcp = Some(true);
            }
            match std::net::IpAddr::from_str(np_addr.address.as_str()) {
                Ok(i) => {
                    let addr = InterfaceIpAddr {
                        ip: i,
                        prefix_length: np_addr.prefix_len,
                        valid_life_time: if np_addr.valid_lft != "forever" {
                            Some(np_addr.valid_lft.clone())
                        } else {
                            None
                        },
                        preferred_life_time: if np_addr.preferred_lft
                            != "forever"
                        {
                            Some(np_addr.preferred_lft.clone())
                        } else {
                            None
                        },
                        ..Default::default()
                    };
                    addresses.push(addr);
                }
                Err(e) => {
                    log::warn!(
                        "BUG: nispor got invalid IP address {}, error {}",
                        np_addr.address.as_str(),
                        e
                    );
                }
            }
        }
        ip.addresses = Some(addresses);
        if ip.dhcp.is_none() {
            ip.dhcp = Some(false);
        }
        Some(ip)
    } else {
        // IP might just disabled
        Some(InterfaceIpv4::default())
    }
}

pub(crate) fn np_ipv6_to_nipart(
    np_iface: &nispor::Iface,
) -> Option<InterfaceIpv6> {
    if let Some(np_ip) = &np_iface.ipv6 {
        let mut ip = InterfaceIpv6 {
            enabled: Some(!np_ip.addresses.is_empty()),
            ..Default::default()
        };

        if !ip.is_enabled() {
            return Some(ip);
        }
        let mut addresses = Vec::new();
        for np_addr in &np_ip.addresses {
            // A `kernel_ra` address might hold `forever` lifetime (e.g. RA
            // with infinite valid lifetime), detect it via the address
            // protocol so autoconf can still be verified.
            if np_addr.protocol
                == Some(nispor::AddressProtocol::RouterAnnouncement)
            {
                ip.autoconf = Some(true);
            } else if np_addr.valid_lft != "forever" {
                if np_addr.prefix_len == 128 {
                    ip.dhcp = Some(true);
                } else {
                    ip.autoconf = Some(true);
                }
            }
            match std::net::IpAddr::from_str(np_addr.address.as_str()) {
                Ok(i) => {
                    let addr = InterfaceIpAddr {
                        ip: i,
                        prefix_length: np_addr.prefix_len,
                        valid_life_time: if np_addr.valid_lft != "forever" {
                            Some(np_addr.valid_lft.clone())
                        } else {
                            None
                        },
                        preferred_life_time: if np_addr.preferred_lft
                            != "forever"
                        {
                            Some(np_addr.preferred_lft.clone())
                        } else {
                            None
                        },
                        ..Default::default()
                    };
                    addresses.push(addr);
                }
                Err(e) => {
                    log::warn!(
                        "BUG: nispor got invalid IP address {}, error {}",
                        np_addr.address.as_str(),
                        e
                    );
                }
            }
        }
        ip.addresses = Some(addresses);
        if ip.autoconf.is_none() && ip.dhcp.is_none() {
            ip.dhcp = Some(false);
            ip.autoconf = Some(false);
        }
        Some(ip)
    } else {
        // IP might just disabled
        Some(InterfaceIpv6::default())
    }
}

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

#[cfg(test)]
#[path = "unit_tests/ip.rs"]
mod tests;
