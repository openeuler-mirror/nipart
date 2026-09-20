// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures_channel::{
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded},
    oneshot::Sender,
};
use futures_util::StreamExt;
use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease, DhcpV4State};
use nipart::{
    BaseInterface, DhcpState, ErrorKind, Interface, InterfaceIpAddr,
    InterfaceIpv4, NetworkState, NipartApplyOption, NipartError,
    NipartNoDaemon, NipartQueryOption, RouteEntry, RouteState, Routes,
};

use crate::{
    TaskWorker, daemon::NipartManagerCmd,
    dns_gateway::default_gateway_fingerprint,
};

const DEFAULT_ROUTE_TABLE_ID: u32 = 254;

#[derive(Debug, Clone)]
pub(crate) enum NipartDhcpCmd {
    StartIfaceDhcp(Box<BaseInterface>),
    StopIfaceDhcp(String),
    Query,
    /// Nameservers learned from the current leases, keyed by interface
    /// name.  Used as `auto-dns` upstream of the DNS cache.
    Nameservers,
    /// Set the sender used to notify the daemon.  Must be invoked right
    /// after the worker started; without it the DHCP worker cannot report
    /// a changed default gateway to the daemon.
    SetCommanderSender(UnboundedSender<NipartManagerCmd>),
}

impl std::fmt::Display for NipartDhcpCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StartIfaceDhcp(base_iface) => {
                write!(f, "start-iface-dhcp:{}", base_iface.name)
            }
            Self::StopIfaceDhcp(iface) => {
                write!(f, "stop-iface-dhcp:{iface}")
            }
            Self::Query => {
                write!(f, "query-dhcp")
            }
            Self::Nameservers => {
                write!(f, "nameservers-dhcp")
            }
            Self::SetCommanderSender(_) => {
                write!(f, "set-commander-sender-dhcp")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NipartDhcpReply {
    None,
    QueryReply(HashMap<String, DhcpState>),
    NameserverReply(HashMap<String, Vec<String>>),
}

type FromManager =
    (NipartDhcpCmd, Sender<Result<NipartDhcpReply, NipartError>>);

#[derive(Debug)]
pub(crate) struct NipartDhcpV4Worker {
    threads: HashMap<String, NipartDhcpV4Thread>,
    receiver: UnboundedReceiver<FromManager>,
    /// Sender for notifying the daemon, e.g. that a lease changed the
    /// default gateway.  `None` until `SetCommanderSender` arrives.
    msg_to_daemon: Option<UnboundedSender<NipartManagerCmd>>,
}

impl TaskWorker for NipartDhcpV4Worker {
    type Cmd = NipartDhcpCmd;
    type Reply = NipartDhcpReply;

    async fn new(
        receiver: UnboundedReceiver<(
            Self::Cmd,
            Sender<Result<Self::Reply, NipartError>>,
        )>,
    ) -> Result<Self, NipartError> {
        Ok(Self {
            threads: HashMap::new(),
            receiver,
            msg_to_daemon: None,
        })
    }

    fn receiver(&mut self) -> &mut UnboundedReceiver<FromManager> {
        &mut self.receiver
    }

    async fn process_cmd(
        &mut self,
        cmd: NipartDhcpCmd,
    ) -> Result<NipartDhcpReply, NipartError> {
        match cmd {
            NipartDhcpCmd::SetCommanderSender(msg_to_daemon) => {
                self.msg_to_daemon = Some(msg_to_daemon);
                Ok(NipartDhcpReply::None)
            }
            NipartDhcpCmd::StartIfaceDhcp(base_iface) => {
                let iface_name = base_iface.name.clone();
                let thread = NipartDhcpV4Thread::new(
                    *base_iface,
                    self.msg_to_daemon.clone(),
                )
                .await?;
                self.threads.insert(iface_name.clone(), thread);
                log::debug!("DHCP thread started on interface {iface_name}");
                Ok(NipartDhcpReply::None)
            }
            NipartDhcpCmd::StopIfaceDhcp(iface) => {
                self.threads.remove(&iface);
                Ok(NipartDhcpReply::None)
            }
            NipartDhcpCmd::Query => {
                let mut ret = HashMap::new();
                for (iface_name, thread) in self.threads.iter() {
                    ret.insert(iface_name.to_string(), thread.get_state()?);
                }

                Ok(NipartDhcpReply::QueryReply(ret))
            }
            NipartDhcpCmd::Nameservers => {
                let mut ret = HashMap::new();
                for (iface_name, thread) in self.threads.iter() {
                    let nameservers = thread.get_nameservers()?;
                    if !nameservers.is_empty() {
                        ret.insert(iface_name.to_string(), nameservers);
                    }
                }
                Ok(NipartDhcpReply::NameserverReply(ret))
            }
        }
    }
}

#[derive(Debug, Default)]
struct NipartDhcpShareData {
    state: DhcpState,
    nameservers: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct NipartDhcpV4Thread {
    pub(crate) base_iface: BaseInterface,
    // No need to send any data. Dropping this Sender will cause
    // Receiver.recv() got None which trigger DHCP thread quit.
    _quit_notifer: UnboundedSender<()>,
    share_data: Arc<Mutex<NipartDhcpShareData>>,
}

impl NipartDhcpV4Thread {
    pub(crate) async fn new(
        base_iface: BaseInterface,
        msg_to_daemon: Option<UnboundedSender<NipartManagerCmd>>,
    ) -> Result<Self, NipartError> {
        let (sender, receiver) = unbounded();
        let ret = Self {
            base_iface: base_iface.clone(),
            _quit_notifer: sender,
            share_data: Arc::new(Mutex::new(NipartDhcpShareData::default())),
        };
        let mac_addr = match base_iface.mac_address.as_deref() {
            Some(m) => m,
            None => {
                return Err(NipartError::new(
                    ErrorKind::Bug,
                    format!(
                        "Got no MAC address for DHCPv4 on interface {}({})",
                        base_iface.name, base_iface.iface_type
                    ),
                ));
            }
        };
        let iface_index = match base_iface.iface_index {
            Some(m) => m,
            None => {
                return Err(NipartError::new(
                    ErrorKind::Bug,
                    format!(
                        "Got no interface index for DHCPv4 on interface {}({})",
                        base_iface.name, base_iface.iface_type
                    ),
                ));
            }
        };
        let mut dhcp_config = DhcpV4Config::new(base_iface.name.as_str());
        dhcp_config
            .set_iface_index(iface_index)
            .set_iface_mac(mac_addr)
            .map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to set iface {}/{} MAC {}: {e}",
                        base_iface.name, base_iface.iface_type, mac_addr,
                    ),
                )
            })?
            .use_mac_as_client_id();
        // TODO(Gris Ge): Support loading previous stored lease
        let dhcp_client =
            DhcpV4Client::init(dhcp_config, None).await.map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to start DHCPv4 client on iface {}/{}: {e}",
                        base_iface.name, base_iface.iface_type,
                    ),
                )
            })?;

        let share_data = ret.share_data.clone();
        tokio::spawn(async move {
            if let Err(e) = dhcp_thread(
                dhcp_client,
                base_iface,
                receiver,
                share_data,
                msg_to_daemon,
            )
            .await
            {
                log::error!("{e}");
            }
        });
        Ok(ret)
    }

    pub(crate) fn get_state(&self) -> Result<DhcpState, NipartError> {
        match self.share_data.lock() {
            Ok(data) => Ok(data.state.clone()),
            Err(e) => Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to lock share data of DHCP thread for interface \
                     {}: {e}",
                    self.base_iface.name
                ),
            )),
        }
    }

    pub(crate) fn get_nameservers(&self) -> Result<Vec<String>, NipartError> {
        match self.share_data.lock() {
            Ok(data) => Ok(data.nameservers.clone()),
            Err(e) => Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to lock share data of DHCP thread for interface \
                     {}: {e}",
                    self.base_iface.name
                ),
            )),
        }
    }
}

async fn dhcp_thread(
    mut dhcp_client: DhcpV4Client,
    base_iface: BaseInterface,
    mut quit_indicator: UnboundedReceiver<()>,
    share_data: Arc<Mutex<NipartDhcpShareData>>,
    msg_to_daemon: Option<UnboundedSender<NipartManagerCmd>>,
) -> Result<(), NipartError> {
    log::debug!(
        "Waiting link carrier up for interface {}/{} before start DHCP",
        base_iface.name,
        base_iface.iface_type
    );
    NipartNoDaemon::wait_link_carrier_up(base_iface.name.as_str()).await?;
    log::debug!(
        "Interface {}/{} link carrier is up, starting DHCP process",
        base_iface.name,
        base_iface.iface_type
    );
    match share_data.lock() {
        Ok(mut share_data) => {
            share_data.state = DhcpState::Running;
        }
        Err(e) => {
            return Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to lock DHCPv4 {}({}) share data: {e}",
                    base_iface.name, base_iface.iface_type,
                ),
            ));
        }
    }
    let result = loop {
        tokio::select! {
            result = dhcp_client.run() => {
                match result {
                    Ok(DhcpV4State::Done(lease)) => {
                        log::info!(
                            "DHCPv4 on {}({}) got lease {}",
                            base_iface.name,
                            base_iface.iface_type,
                            lease.yiaddr,
                        );
                        match share_data.lock() {
                            Ok(mut share_data) => {
                                share_data.state = DhcpState::Done;
                            }
                            Err(e) => {
                                break Err::<(), NipartError>(NipartError::new(
                                    ErrorKind::Bug,
                                    format!("Unhandled DHCPv4 error: {e}"),
                                ));
                            }
                        }
                        if let Err(e) = apply_lease(
                            &base_iface,
                            &lease,
                            share_data.clone(),
                            msg_to_daemon.as_ref(),
                        ).await {
                            break Err(e);
                        }
                    }
                    Ok(dhcp_state) => {
                        log::info!(
                            "DHCPv4 on {}({}) reach {} state",
                            base_iface.name,
                            base_iface.iface_type,
                            dhcp_state
                        );
                    }
                    Err(e) => {
                        break Err(NipartError::new(
                            ErrorKind::Bug,
                            format!("Unhandled DHCPv4 error: {e}"),
                        ));
                    }
                }
            }
            _ = quit_indicator.next() => {
                log::info!(
                    "Stopped DHCPv4 on {}({})",
                    base_iface.name,
                    base_iface.iface_type,
                );
                return Ok(());
            }
        }
    };

    if let Err(e) = result {
        log::error!(
            "DHCPv4 client on {}({}) stopped: {e}",
            base_iface.name,
            base_iface.iface_type,
        );
        match share_data.lock() {
            Ok(mut share_data) => {
                share_data.state = DhcpState::Error(e.to_string());
            }
            Err(e) => {
                return Err(NipartError::new(
                    ErrorKind::Bug,
                    format!(
                        "Failed to lock DHCPv4 {}({}) share data: {e}",
                        base_iface.name, base_iface.iface_type,
                    ),
                ));
            }
        }
    }
    Ok(())
}

async fn apply_lease(
    base_iface: &BaseInterface,
    lease: &DhcpV4Lease,
    // TODO: Support hostname, systemd-resolved
    share_data: Arc<Mutex<NipartDhcpShareData>>,
    msg_to_daemon: Option<&UnboundedSender<NipartManagerCmd>>,
) -> Result<(), NipartError> {
    log::debug!(
        "Applying DHCPv4 lease {}/{} to interface {}({})",
        lease.yiaddr,
        lease.prefix_length(),
        base_iface.name,
        base_iface.iface_type
    );

    // Remember the nameservers of the current lease: the DNS cache uses
    // them as `auto-dns` upstream.
    match share_data.lock() {
        Ok(mut share_data) => {
            share_data.nameservers = lease
                .dns_srvs
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|srv| srv.to_string())
                .collect();
        }
        Err(e) => {
            log::warn!(
                "Failed to store DHCPv4 nameservers for interface {}: {e}",
                base_iface.name
            );
        }
    }

    let mut ip_addr =
        InterfaceIpAddr::new(lease.yiaddr.into(), lease.prefix_length());
    ip_addr.preferred_life_time = Some(format!("{}sec", lease.lease_time_sec));
    ip_addr.valid_life_time = Some(format!("{}sec", lease.lease_time_sec));

    let mut ipv4_conf = InterfaceIpv4::default();
    ipv4_conf.enabled = Some(true);
    ipv4_conf.dhcp = Some(true);
    ipv4_conf.addresses = Some(vec![ip_addr]);

    let mut apply_base_iface = base_iface.clone_name_type_only();

    apply_base_iface.ipv4 = Some(ipv4_conf);
    if let Some(mtu) = lease.mtu {
        apply_base_iface.mtu = Some(mtu.into());
    }

    let iface_state: Interface = apply_base_iface.into();
    let mut net_state = NetworkState::new();
    net_state.ifaces.push(iface_state);

    let cur_routes =
        NipartNoDaemon::query_network_state(NipartQueryOption::running())
            .await?
            .routes;
    // The lease routes are applied here instead of the daemon apply path,
    // so the daemon cannot compare the default routes itself: remember the
    // gateway of the path in use before this lease and that of the lease.
    let gateway_before = iface_default_gateway_fingerprint(
        cur_routes.running.iter().flatten(),
        base_iface.name.as_str(),
    );
    let mut routes = gen_routes(lease, base_iface);
    let gateway_after =
        default_gateway_fingerprint(routes.config.iter().flatten());
    mark_replaced_routes_absent(&mut routes, &cur_routes);
    net_state.routes = routes;

    let apply_opt = NipartApplyOption::new().memory_only().no_verify();
    NipartNoDaemon::apply_network_state(net_state, apply_opt).await?;
    notify_daemon_on_gateway_change(
        base_iface,
        gateway_before,
        gateway_after,
        msg_to_daemon,
    );
    Ok(())
}

/// Tell the daemon when this lease changed the default gateway.
///
/// The daemon then notifies the DNS cache so the upstream groups which
/// failed while the old gateway was in use are retried at once instead of
/// failing fast until their retry cooldown elapsed.  A failure to notify
/// is logged only: the lease is applied and the cache keeps its own retry
/// cooldown as fallback.
fn notify_daemon_on_gateway_change(
    base_iface: &BaseInterface,
    gateway_before: Vec<String>,
    gateway_after: Vec<String>,
    msg_to_daemon: Option<&UnboundedSender<NipartManagerCmd>>,
) {
    let Some(msg_to_daemon) = msg_to_daemon else {
        return;
    };
    if gateway_before == gateway_after {
        return;
    }
    log::debug!(
        "DHCPv4 lease on {} changed the default gateway from \
         {gateway_before:?} to {gateway_after:?}, notifying the daemon",
        base_iface.name
    );
    if msg_to_daemon
        .unbounded_send(NipartManagerCmd::GatewayChanged)
        .is_err()
    {
        log::debug!("Failed to notify the daemon about the gateway change");
    }
}

/// Fingerprint of the default routes of `iface_name` in `routes`.
///
/// Only the routes of the interface getting the new lease can change while
/// a lease is applied, so comparing its default routes before and after the
/// apply detects a replaced default gateway without querying the kernel a
/// second time.
fn iface_default_gateway_fingerprint<'a>(
    routes: impl IntoIterator<Item = &'a RouteEntry>,
    iface_name: &str,
) -> Vec<String> {
    default_gateway_fingerprint(
        routes.into_iter().filter(|route| {
            route.next_hop_iface.as_deref() == Some(iface_name)
        }),
    )
}

/// Mark the installed routes which the new lease replaces as absent.
///
/// The gateway route of a DHCP lease uses a metric derived from the
/// interface index, so the gateway route of a lease learned from another
/// network (e.g. before a daemon restart) carries the same destination
/// and metric.  Without removing it first, the route apply refuses the
/// new gateway route (`Multiple routes to 0.0.0.0/0 are sharing the same
/// metric`) and the interface is left without any default gateway.
fn mark_replaced_routes_absent(routes: &mut Routes, cur_routes: &Routes) {
    let Some(desired_routes) = routes.config.clone() else {
        return;
    };
    let mut absent_routes: Vec<RouteEntry> = Vec::new();
    for cur_route in cur_routes
        .running
        .iter()
        .chain(cur_routes.config.iter())
        .flatten()
    {
        if cur_route.is_absent() {
            continue;
        }
        for desired_route in desired_routes.iter() {
            if !route_is_replaced_by(cur_route, desired_route) {
                continue;
            }
            let mut absent_route = cur_route.clone();
            absent_route.state = Some(RouteState::Absent);
            absent_routes.push(absent_route);
        }
    }
    if let Some(config_routes) = routes.config.as_mut() {
        config_routes.extend(absent_routes);
    }
}

/// Whether `desired_route` replaces the installed `cur_route`: same next
/// hop interface, destination, metric and table, but another gateway.
fn route_is_replaced_by(
    cur_route: &RouteEntry,
    desired_route: &RouteEntry,
) -> bool {
    cur_route.next_hop_iface.is_some()
        && cur_route.next_hop_iface == desired_route.next_hop_iface
        && cur_route.destination == desired_route.destination
        && cur_route.metric == desired_route.metric
        && route_table_id(cur_route) == route_table_id(desired_route)
        && cur_route.next_hop_addr != desired_route.next_hop_addr
}

fn route_table_id(route: &RouteEntry) -> u32 {
    route
        .table_id
        .unwrap_or(RouteEntry::USE_DEFAULT_ROUTE_TABLE)
}

// TODO:
//  * Handle `classless_routes` (DHCP option 121 and 249)
fn gen_routes(lease: &DhcpV4Lease, base_iface: &BaseInterface) -> Routes {
    let mut conf_routes: Vec<RouteEntry> = Vec::new();

    if let Some(gateways) = lease.gateways.as_ref()
        && base_iface
            .ipv4
            .as_ref()
            .map(|i| i.auto_gateway.unwrap_or(true))
            != Some(false)
    {
        for (index, gateway) in gateways.iter().enumerate() {
            let mut route = RouteEntry::default();
            route.destination = Some("0.0.0.0/0".to_string());
            route.next_hop_iface = Some(base_iface.name.to_string());
            route.next_hop_addr = Some(gateway.to_string());
            route.table_id = Some(DEFAULT_ROUTE_TABLE_ID);
            route.metric = base_iface.ipv4.as_ref().and_then(|ipv4| {
                ipv4.dhcp_route_metric(base_iface.iface_index, index)
            });
            conf_routes.push(route);
        }
    }

    let mut routes = Routes::default();
    routes.config = Some(conf_routes);
    routes
}

#[cfg(test)]
#[path = "../unit_tests/dhcp_worker.rs"]
mod tests;
