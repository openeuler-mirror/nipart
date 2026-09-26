// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use futures_channel::{mpsc::UnboundedReceiver, oneshot::Sender};
use mudz::{MudzNotifier, MudzServer};
use nipart::{ErrorKind, NipartError};
use tokio::{sync::oneshot as tokio_oneshot, task::JoinHandle};

use super::NipartDnsServerConfig;
use crate::TaskWorker;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NipartDnsCmd {
    Start(NipartDnsServerConfig),
    RefreshAutoDns(Vec<IpAddr>),
    /// The network path of the upstream nameservers changed, e.g. the
    /// default gateway was replaced by a route apply, a DHCP lease or the
    /// boot-up state restore. The running cache server keeps its cached
    /// replies but clears the upstream failure state and retries the
    /// upstream groups which were marked dead. No-op when no cache server
    /// is running: a cache started later has no failure state to clear.
    NotifyNetworkChange,
    Stop,
    /// Query whether the cache server is running.  Kept for status
    /// reporting of future `npt` DNS commands.
    #[allow(dead_code)]
    Query,
}

impl std::fmt::Display for NipartDnsCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start(config) => write!(f, "start:{}", config.bind),
            Self::RefreshAutoDns(servers) => {
                write!(f, "refresh-auto-dns:{}", servers.len())
            }
            Self::NotifyNetworkChange => write!(f, "notify-network-change"),
            Self::Stop => write!(f, "stop"),
            Self::Query => write!(f, "query"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NipartDnsReply {
    None,
    Running(bool),
}

type FromManager = (NipartDnsCmd, Sender<Result<NipartDnsReply, NipartError>>);

/// A running DNS cache server task.
#[derive(Debug)]
struct RunningDnsServer {
    config: NipartDnsServerConfig,
    /// Handle reporting host environment changes which the embedded cache
    /// server cannot observe through its own sockets, e.g. a new default
    /// gateway learned from DHCP.
    notifier: MudzNotifier,
    shutdown: tokio_oneshot::Sender<()>,
    handle: JoinHandle<()>,
}

#[derive(Debug)]
pub(crate) struct NipartDnsWorker {
    running: Option<RunningDnsServer>,
    receiver: UnboundedReceiver<FromManager>,
}

impl TaskWorker for NipartDnsWorker {
    type Cmd = NipartDnsCmd;
    type Reply = NipartDnsReply;

    async fn new(
        receiver: UnboundedReceiver<(
            Self::Cmd,
            Sender<Result<Self::Reply, NipartError>>,
        )>,
    ) -> Result<Self, NipartError> {
        Ok(Self {
            running: None,
            receiver,
        })
    }

    fn receiver(&mut self) -> &mut UnboundedReceiver<FromManager> {
        &mut self.receiver
    }

    async fn process_cmd(
        &mut self,
        cmd: NipartDnsCmd,
    ) -> Result<NipartDnsReply, NipartError> {
        match cmd {
            NipartDnsCmd::Start(config) => {
                self.stop_server().await;
                self.start_server(config).await?;
                Ok(NipartDnsReply::None)
            }
            NipartDnsCmd::RefreshAutoDns(servers) => {
                if let Some(running) = self.running.as_mut()
                    && running.config.auto_dns_servers != servers
                {
                    let mut config = running.config.clone();
                    config.set_auto_dns_servers(&servers);
                    // Auto-DNS changes only affect upstream selection;
                    // restarting the server is the simplest way to apply
                    // them without a shared mutable config.
                    self.stop_server().await;
                    self.start_server(config).await?;
                }
                Ok(NipartDnsReply::None)
            }
            NipartDnsCmd::NotifyNetworkChange => {
                if let Some(running) = self.running.as_ref() {
                    running
                        .notifier
                        .notify_network_change()
                        .map_err(mudz_error)?;
                }
                Ok(NipartDnsReply::None)
            }
            NipartDnsCmd::Stop => {
                self.stop_server().await;
                Ok(NipartDnsReply::None)
            }
            NipartDnsCmd::Query => {
                Ok(NipartDnsReply::Running(self.running.is_some()))
            }
        }
    }
}

impl NipartDnsWorker {
    async fn start_server(
        &mut self,
        config: NipartDnsServerConfig,
    ) -> Result<(), NipartError> {
        // `MudzServer::new()` validates the configuration, binds the UDP
        // and TCP sockets and resolves the DoH bootstrap hostnames.
        let server = MudzServer::new(config.mudz_config())
            .await
            .map_err(mudz_error)?;
        // Create the notifier before the server is moved into the serving
        // task: a new default gateway is reported through it while the
        // server runs.
        let notifier = server.notifier();
        let (shutdown, shutdown_rx) = tokio_oneshot::channel::<()>();
        let bind = config.bind;
        let handle = tokio::spawn(async move {
            if let Err(e) = server
                .run_with_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
            {
                log::error!("DNS cache server on {bind} failed: {e}");
            }
        });
        self.running = Some(RunningDnsServer {
            config,
            notifier,
            shutdown,
            handle,
        });
        log::info!("DNS cache server started on {bind}");
        Ok(())
    }

    async fn stop_server(&mut self) {
        if let Some(running) = self.running.take() {
            let bind = running.config.bind;
            let _ = running.shutdown.send(());
            if let Err(e) = running.handle.await {
                log::error!("DNS cache server task on {bind} panicked: {e}");
            } else {
                log::info!("DNS cache server stopped on {bind}");
            }
        }
    }
}

impl Drop for NipartDnsWorker {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            // The daemon is exiting: signal the server task and let the
            // runtime drop it.  We cannot await in Drop.
            let _ = running.shutdown.send(());
            running.handle.abort();
        }
    }
}

/// Convert a `mudz` error into the daemon error type.
fn mudz_error(error: mudz::MudzError) -> NipartError {
    let kind = match error.kind {
        mudz::ErrorKind::Bug => ErrorKind::Bug,
        mudz::ErrorKind::Timeout => ErrorKind::Timeout,
        mudz::ErrorKind::InvalidArgument
        | mudz::ErrorKind::InvalidConfig
        | mudz::ErrorKind::InvalidPacket => ErrorKind::InvalidArgument,
        mudz::ErrorKind::Rejected => ErrorKind::DaemonFailure,
        // `mudz::ErrorKind` is `#[non_exhaustive]`: treat kinds added by a
        // newer mudz as daemon failures rather than failing to build.
        _ => ErrorKind::DaemonFailure,
    };
    NipartError::new(kind, error.message)
}
