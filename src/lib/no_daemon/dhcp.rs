// SPDX-License-Identifier: Apache-2.0

use futures_util::{StreamExt, stream::FuturesUnordered};
use mozim::{
    DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State, DhcpV6Client,
    DhcpV6Config, DhcpV6Lease, DhcpV6Mode, DhcpV6State,
};

use super::{ip::apply_iface_ip_changes, route::apply_routes};
use crate::{
    BaseInterface, ErrorKind, InterfaceIpAddr, InterfaceIpv4, InterfaceIpv6,
    InterfaceType, MergedInterfaces, MergedRoutes, NipartError,
    NipartInterface, NipartNoDaemon, RouteEntry, Routes,
};

const DEFAULT_ROUTE_TABLE_ID: u32 = 254;

const DHCPV6_INIT_RETRY_COUNT: usize = 30;
const DHCPV6_INIT_RETRY_INTERVAL_MS: u64 = 1000;

impl NipartNoDaemon {
    pub(crate) async fn run_dhcp_once(
        merged_ifaces: &MergedInterfaces,
    ) -> Result<(), NipartError> {
        // DHCPv4
        let mut v4_get_lease_futures = FuturesUnordered::new();

        for iface in merged_ifaces
            .kernel_ifaces
            .values()
            .filter_map(|i| i.for_apply.as_ref())
            .filter(|i| {
                i.base_iface().ipv4.as_ref().and_then(|ip| ip.dhcp)
                    == Some(true)
            })
        {
            let get_lease_future =
                get_lease_v4(iface.kernel_iface_name(), iface.iface_type());
            v4_get_lease_futures.push(get_lease_future);
        }

        while let Some(result) = v4_get_lease_futures.next().await {
            // Should fail the whole apply action for any errors of DHCP.
            let (kernel_iface_name, lease) = result?;
            apply_lease_v4(merged_ifaces, kernel_iface_name, lease).await?;
        }

        // DHCPv6
        let mut v6_get_lease_futures = FuturesUnordered::new();

        for iface in merged_ifaces
            .kernel_ifaces
            .values()
            .filter_map(|i| i.for_apply.as_ref())
            .filter(|i| {
                i.base_iface().ipv6.as_ref().and_then(|ip| ip.dhcp)
                    == Some(true)
            })
        {
            let get_lease_future =
                get_lease_v6(iface.kernel_iface_name(), iface.iface_type());
            v6_get_lease_futures.push(get_lease_future);
        }

        while let Some(result) = v6_get_lease_futures.next().await {
            // Should fail the whole apply action for any errors of DHCP.
            let (kernel_iface_name, lease) = result?;
            apply_lease_v6(merged_ifaces, kernel_iface_name, lease).await?;
        }
        Ok(())
    }
}

async fn get_lease_v4<'a>(
    kernel_iface_name: &'a str,
    iface_type: &InterfaceType,
) -> Result<(&'a str, DhcpV4Lease), NipartError> {
    let dhcp_config = DhcpV4Config::new(kernel_iface_name);
    log::debug!(
        "Waiting link carrier up for interface {}/{} before start DHCP",
        kernel_iface_name,
        iface_type
    );
    NipartNoDaemon::wait_link_carrier_up(kernel_iface_name).await?;
    log::debug!(
        "Interface {}/{} link carrier is up, starting DHCP process",
        kernel_iface_name,
        iface_type
    );
    let mut dhcp_client =
        DhcpV4Client::init(dhcp_config, None).await.map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to start DHCPv4 client on iface {}/{}: {e}",
                    kernel_iface_name, iface_type,
                ),
            )
        })?;
    loop {
        let state = dhcp_client.run().await.map_err(|e| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("DHCPv4 failed: {e}"),
            )
        })?;
        if let DhcpV4State::Done(lease) = state {
            log::info!(
                "DHCPv4 on interface acquired lease: {}/{}",
                lease.yiaddr,
                lease.prefix_length()
            );
            return Ok((kernel_iface_name, *lease));
        } else {
            log::info!(
                "DHCPv4 on interface {kernel_iface_name}/{iface_type} reach \
                 {state} state",
            );
        }
    }
}

async fn get_lease_v6<'a>(
    kernel_iface_name: &'a str,
    iface_type: &InterfaceType,
) -> Result<(&'a str, DhcpV6Lease), NipartError> {
    log::debug!(
        "Waiting link carrier up for interface {}/{} before start DHCPv6",
        kernel_iface_name,
        iface_type
    );
    NipartNoDaemon::wait_link_carrier_up(kernel_iface_name).await?;
    log::debug!(
        "Interface {}/{} link carrier is up, starting DHCPv6 process",
        kernel_iface_name,
        iface_type
    );
    // The DHCPv6 client needs the IPv6 link-local address as its source
    // address, enable IPv6 first if it was previously disabled.
    NipartNoDaemon::enable_ipv6(kernel_iface_name).await?;
    let mut dhcp_client =
        init_dhcp_v6_client(kernel_iface_name, iface_type).await?;
    loop {
        let state = match dhcp_client.run().await {
            Ok(state) => state,
            Err(e) => {
                // A single transient error (e.g. UDP socket bind while the
                // IPv6 link-local address is still tentative right after
                // wifi association) must not abort the whole DHCPv6
                // acquisition. Reset the client, wait for the link to be
                // usable again, then re-resolve the interface and retry.
                log::warn!(
                    "DHCPv6 on interface {kernel_iface_name}/{iface_type} \
                     failed, restarting client: {e}"
                );
                dhcp_client.clean_up();
                NipartNoDaemon::wait_link_carrier_up(kernel_iface_name).await?;
                dhcp_client =
                    init_dhcp_v6_client(kernel_iface_name, iface_type).await?;
                continue;
            }
        };
        if let DhcpV6State::Done(lease) = state {
            log::info!(
                "DHCPv6 on interface acquired lease: {}/{}",
                lease.address,
                lease.prefix_len
            );
            return Ok((kernel_iface_name, *lease));
        } else {
            log::info!(
                "DHCPv6 on interface {kernel_iface_name}/{iface_type} reach \
                 {state} state",
            );
        }
    }
}

async fn init_dhcp_v6_client(
    kernel_iface_name: &str,
    iface_type: &InterfaceType,
) -> Result<DhcpV6Client, NipartError> {
    // Whether we already forced the kernel to regenerate the IPv6 link-local
    // address for this round of init attempts.
    let mut link_local_regenerated = false;
    // The DHCPv6 client init resolves the interface index and link-local
    // address via netlink, retry a few times to cover the window between
    // link carrier up and the link-local address being assigned on the
    // interface.
    for retry_count in 0..DHCPV6_INIT_RETRY_COUNT {
        let dhcp_config = DhcpV6Config::new(
            kernel_iface_name,
            DhcpV6Mode::NonTemporaryAddresses,
        );
        match DhcpV6Client::init(dhcp_config, None).await {
            Ok(cli) => {
                return Ok(cli);
            }
            Err(e) => {
                // The init failure is usually caused by the interface holding
                // no IPv6 link-local address, flip `disable_ipv6` once so the
                // kernel regenerates the link-local address for it.
                if !link_local_regenerated {
                    link_local_regenerated = true;
                    log::info!(
                        "DHCPv6 client init failed on iface {}/{}, forcing \
                         the kernel to regenerate the IPv6 link-local \
                         address: {e}",
                        kernel_iface_name,
                        iface_type,
                    );
                    if let Err(regen_err) =
                        NipartNoDaemon::regenerate_link_local(kernel_iface_name)
                            .await
                    {
                        log::warn!(
                            "Failed to regenerate IPv6 link-local address on \
                             iface {}/{}: {regen_err}",
                            kernel_iface_name,
                            iface_type,
                        );
                    }
                }
                if retry_count + 1 == DHCPV6_INIT_RETRY_COUNT {
                    return Err(NipartError::new(
                        ErrorKind::Bug,
                        format!(
                            "Failed to start DHCPv6 client on iface {}/{}: {e}",
                            kernel_iface_name, iface_type,
                        ),
                    ));
                }
                log::debug!(
                    "Failed to init DHCPv6 client on iface {}/{}, retry \
                     ({retry_count}/{DHCPV6_INIT_RETRY_COUNT}): {e}",
                    kernel_iface_name,
                    iface_type,
                );
                tokio::time::sleep(std::time::Duration::from_millis(
                    DHCPV6_INIT_RETRY_INTERVAL_MS,
                ))
                .await;
            }
        }
    }
    unreachable!()
}

/// Apply DHCPv6 lease to kernel directly.
/// The DHCPv6 lease only provides a /128 address, no routes are generated.
impl NipartNoDaemon {
    pub async fn apply_dhcpv6_lease(
        base_iface: &BaseInterface,
        lease: &DhcpV6Lease,
    ) -> Result<(), NipartError> {
        log::debug!(
            "Applying DHCPv6 lease {}/{} to interface {}({})",
            lease.address,
            lease.prefix_len,
            base_iface.name,
            base_iface.iface_type
        );

        let mut ip_addr =
            InterfaceIpAddr::new(lease.address.into(), lease.prefix_len);
        ip_addr.preferred_life_time =
            Some(format!("{}sec", lease.preferred_time_sec));
        ip_addr.valid_life_time = Some(format!("{}sec", lease.valid_time_sec));

        let ipv6_conf = InterfaceIpv6 {
            enabled: Some(true),
            dhcp: Some(true),
            addresses: Some(vec![ip_addr]),
            ..Default::default()
        };

        let mut apply_base_iface = base_iface.clone_name_type_only();
        apply_base_iface.ipv6 = Some(ipv6_conf);

        // Apply directly to kernel without going through the schema sanitize()
        // which drops dynamic (auto) IPv6 addresses from desired state.
        apply_iface_ip_changes(&apply_base_iface, None).await?;
        Ok(())
    }
}

async fn apply_lease_v4(
    merged_ifaces: &MergedInterfaces,
    kernel_iface_name: &str,
    lease: DhcpV4Lease,
) -> Result<(), NipartError> {
    let Some(merged_iface) = merged_ifaces.kernel_ifaces.get(kernel_iface_name)
    else {
        return Err(NipartError::new(
            ErrorKind::Bug,
            format!(
                "apply_lease_v4(): Failed to find merged interface for \
                 interface {kernel_iface_name}"
            ),
        ));
    };
    log::debug!(
        "Applying DHCPv4 lease {}/{} to interface {}/{}",
        lease.yiaddr,
        lease.prefix_length(),
        kernel_iface_name,
        merged_iface.merged.iface_type(),
    );

    let mut ip_addr =
        InterfaceIpAddr::new(lease.yiaddr.into(), lease.prefix_length());
    ip_addr.preferred_life_time = Some(format!("{}sec", lease.lease_time_sec));
    ip_addr.valid_life_time = Some(format!("{}sec", lease.lease_time_sec));

    let ipv4_conf = InterfaceIpv4 {
        enabled: Some(true),
        dhcp: Some(true),
        addresses: Some(vec![ip_addr]),
        ..Default::default()
    };

    let mut apply_base_iface =
        merged_iface.merged.base_iface().clone_name_type_only();

    apply_base_iface.ipv4 = Some(ipv4_conf);
    if let Some(mtu) = lease.mtu {
        apply_base_iface.mtu = Some(mtu.into());
    }

    apply_iface_ip_changes(
        &apply_base_iface,
        merged_iface.current.as_ref().map(|c| c.base_iface()),
    )
    .await?;

    let mut conf_routes: Vec<RouteEntry> = Vec::new();
    // TODO: Handle multiple addresses of router
    if let Some(gateways) = lease.gateways.as_ref()
        && merged_iface
            .merged
            .base_iface()
            .ipv4
            .as_ref()
            .map(|i| i.auto_gateway.unwrap_or(true))
            != Some(false)
    {
        let ipv4 = merged_iface.merged.base_iface().ipv4.as_ref();
        let iface_index = merged_iface
            .current
            .as_ref()
            .and_then(|c| c.base_iface().iface_index);
        for (index, gateway) in gateways.iter().enumerate() {
            let route = RouteEntry {
                destination: Some("0.0.0.0/0".to_string()),
                next_hop_iface: Some(kernel_iface_name.to_string()),
                next_hop_addr: Some(gateway.to_string()),
                table_id: Some(DEFAULT_ROUTE_TABLE_ID),
                // Lease is already applied, no need to bypass kernel
                // gateway validation via onlink flag.
                onlink: Some(false),
                metric: ipv4.and_then(|ipv4| {
                    ipv4.dhcp_route_metric(iface_index, index)
                }),
                ..Default::default()
            };
            conf_routes.push(route);
        }
    }

    let des_routes = Routes {
        config: Some(conf_routes),
        ..Default::default()
    };

    let merged_routes =
        MergedRoutes::new(des_routes, Default::default(), None, merged_ifaces)?;

    apply_routes(&merged_routes).await?;

    Ok(())
}

async fn apply_lease_v6(
    merged_ifaces: &MergedInterfaces,
    kernel_iface_name: &str,
    lease: DhcpV6Lease,
) -> Result<(), NipartError> {
    let Some(merged_iface) = merged_ifaces.kernel_ifaces.get(kernel_iface_name)
    else {
        return Err(NipartError::new(
            ErrorKind::Bug,
            format!(
                "apply_lease_v6(): Failed to find merged interface for \
                 interface {kernel_iface_name}"
            ),
        ));
    };
    log::debug!(
        "Applying DHCPv6 lease {}/{} to interface {}/{}",
        lease.address,
        lease.prefix_len,
        kernel_iface_name,
        merged_iface.merged.iface_type(),
    );

    NipartNoDaemon::apply_dhcpv6_lease(merged_iface.merged.base_iface(), &lease)
        .await
}
