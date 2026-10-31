// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use futures_util::stream::{StreamExt, TryStreamExt};
use rtnetlink::{
    MulticastGroup, new_multicast_connection,
    packet_core::NetlinkPayload,
    packet_route::{
        RouteNetlinkMessage,
        link::{LinkAttribute, LinkFlags},
    },
};

use crate::{
    ErrorKind, NipartError, NipartNoDaemon,
    netlink::addr::has_link_local_addr,
};

const LINK_CARRIER_QUERY_INTERVAL_SEC: u64 = 30;

impl NipartNoDaemon {
    pub async fn wait_link_carrier_up(
        iface_name: &str,
    ) -> Result<(), NipartError> {
        wait_link_carrier(iface_name, true).await
    }

    pub async fn wait_link_carrier_down(
        iface_name: &str,
    ) -> Result<(), NipartError> {
        wait_link_carrier(iface_name, false).await
    }

    /// Enable IPv6 on the interface by setting
    /// `/proc/sys/net/ipv6/conf/<iface>/disable_ipv6` to `0`.
    /// The DHCPv6 client requires the interface to hold an IPv6 link-local
    /// address as the source address of its traffic, so this must be done
    /// before starting DHCPv6 when IPv6 was previously disabled.
    pub async fn enable_ipv6(iface_name: &str) -> Result<(), NipartError> {
        let sysctl_path =
            format!("/proc/sys/net/ipv6/conf/{iface_name}/disable_ipv6");
        tokio::fs::write(&sysctl_path, "0\n").await.map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to enable IPv6 on interface {iface_name} by \
                     writing {sysctl_path}: {e}"
                ),
            )
        })?;
        Ok(())
    }

    /// Force allow IPv6 router advertisements on the interface by setting
    /// `/proc/sys/net/ipv6/conf/<iface>/accept_ra` to `2`.
    /// This is required for IPv6 autoconf (SLAAC) to run even when IPv6
    /// forwarding is enabled on the interface.
    pub async fn enable_autoconf(iface_name: &str) -> Result<(), NipartError> {
        let sysctl_path =
            format!("/proc/sys/net/ipv6/conf/{iface_name}/accept_ra");
        tokio::fs::write(&sysctl_path, "2\n").await.map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to enable IPv6 autoconf on interface {iface_name} \
                     by writing {sysctl_path}: {e}"
                ),
            )
        })?;
        Ok(())
    }

    /// When the interface holds no IPv6 link-local address, flip the
    /// `disable_ipv6` sysctl so the kernel regenerates the IPv6 link-local
    /// address for it. No-op when the link-local address already exists.
    pub async fn regenerate_link_local(
        iface_name: &str,
    ) -> Result<(), NipartError> {
        if has_link_local_addr(iface_name).await? {
            return Ok(());
        }
        log::info!(
            "Interface {iface_name} holds no IPv6 link-local address, \
             flipping disable_ipv6 to force the kernel to regenerate it"
        );
        let sysctl_path =
            format!("/proc/sys/net/ipv6/conf/{iface_name}/disable_ipv6");
        for value in ["1", "0"] {
            tokio::fs::write(&sysctl_path, value).await.map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to flip IPv6 disable_ipv6 on interface \
                         {iface_name} by writing {sysctl_path}: {e}"
                    ),
                )
            })?;
        }
        Ok(())
    }
}

async fn wait_link_carrier(
    iface_name: &str,
    link_up: bool,
) -> Result<(), NipartError> {
    // netlink multicast socket will be used for one-time query and also follow
    // up monitor
    let (conn, handle, mut messages) =
        new_multicast_connection(&[MulticastGroup::Link]).map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Failed to create netlink multicast socket for interface \
                     {iface_name}: {e}"
                ),
            )
        })?;
    tokio::spawn(conn);
    let mut multicast_socket_dropped = false;

    let cur_link_state = is_link_oper_up(&handle, iface_name).await?;
    if link_up == cur_link_state {
        return Ok(());
    }

    let iface_name_attr = LinkAttribute::IfName(iface_name.to_string());
    // The multicast stream may drop or batch notifications when the kernel
    // is busy, and a non-ENOBUFS socket error ends the stream, so poll the
    // link state as a fallback.
    let mut query_interval = tokio::time::interval(Duration::from_secs(
        LINK_CARRIER_QUERY_INTERVAL_SEC,
    ));
    // Consume the immediate first tick; the initial query already ran above.
    query_interval.tick().await;

    loop {
        tokio::select! {
            result = async {
                if multicast_socket_dropped {
                    std::future::pending::<Option<_>>().await
                } else {
                    messages.next().await
                }
            } => {
                let Some((nl_msg, _)) = result else {
                    log::warn!(
                        "Netlink multicast socket stream for interface {} \
                         ended, falling back to periodic link state query",
                        iface_name
                    );
                    multicast_socket_dropped = true;
                    continue;
                };
                if let NetlinkPayload::InnerMessage(
                    RouteNetlinkMessage::NewLink(link_msg),
                ) = nl_msg.payload
                    && link_msg
                        .attributes
                        .iter()
                        .any(|attr| attr == &iface_name_attr)
                    && (if link_up {
                        link_msg.header.flags.contains(LinkFlags::Running)
                    } else {
                        !link_msg.header.flags.contains(LinkFlags::Running)
                    })
                {
                    return Ok(());
                }
            }
            _ = query_interval.tick() => {
                if is_link_oper_up(&handle, iface_name).await? == link_up {
                    return Ok(());
                }
            }
        }
    }
}

async fn is_link_oper_up(
    handle: &rtnetlink::Handle,
    iface_name: &str,
) -> Result<bool, NipartError> {
    let mut links = handle
        .link()
        .get()
        .match_name(iface_name.to_string())
        .execute();
    while let Some(link_msg) = links.try_next().await.map_err(|e| {
        NipartError::new(
            ErrorKind::Bug,
            format!(
                "Failed to query rtnetlink link subsystem for checking link \
                 carrier of {}: {e}",
                iface_name
            ),
        )
    })? {
        // `IFF_RUNNING` means RFC2863 operational state UP or UNKNOWN;
        // the kernel documentation recommends DHCP clients wait for it
        // before querying an address.
        if link_msg.header.flags.contains(LinkFlags::Running) {
            return Ok(true);
        }
    }
    Ok(false)
}
