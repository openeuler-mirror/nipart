// SPDX-License-Identifier: Apache-2.0

use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use futures_channel::mpsc::{UnboundedReceiver, unbounded};
use futures_util::stream::StreamExt;
use nipart::{
    ErrorKind, InterfaceLinkEvent, NipartClient, NipartError,
    NipartIpcConnection, NipartIpcListener,
};
use tokio::{
    signal::unix::{Signal, SignalKind},
    sync::SetOnce,
};

use super::{
    api::process_api_connection, commander::NipartCommander,
    lock::NipartLockManager,
};

pub(crate) static DAEMON_IS_ONLINE: SetOnce<()> = SetOnce::const_new();
const DAEMON_PID_FILE: &str = "/var/run/nipart/nipart.pid";
/// How often the daemon checks DHCP learned nameservers for the DNS cache
/// `auto-dns` upstream.
const DNS_AUTO_REFRESH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5);

#[derive(Debug, Clone)]
pub(crate) enum NipartManagerCmd {
    LinkEvent(Box<InterfaceLinkEvent>),
}

#[derive(Debug)]
pub(crate) struct NipartDaemon {
    api_ipc: NipartIpcListener,
    // For command send from managers of daemon.
    managers_ipc: UnboundedReceiver<NipartManagerCmd>,
    // Daemon will fork(tokio is controlling maximum threads) new thread for
    // each client connection, this commander will be cloned and move to all
    // forked threads.
    commander: NipartCommander,
    pid_file: String,
    sigterm: Signal,
    sigint: Signal,
    dns_auto_timer: tokio::time::Interval,
    last_auto_dns_servers: Vec<std::net::IpAddr>,
}

impl Drop for NipartDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.pid_file);
    }
}

impl NipartDaemon {
    pub(crate) async fn new() -> Result<Self, NipartError> {
        let sigterm = tokio::signal::unix::signal(SignalKind::terminate())
            .map_err(|e| {
                NipartError::new(
                    ErrorKind::DaemonFailure,
                    format!("Failed to register SIGTERM handler: {e}"),
                )
            })?;
        let sigint = tokio::signal::unix::signal(SignalKind::interrupt())
            .map_err(|e| {
                NipartError::new(
                    ErrorKind::DaemonFailure,
                    format!("Failed to register SIGINT handler: {e}"),
                )
            })?;

        let api_ipc =
            NipartIpcListener::new(NipartClient::DEFAULT_SOCKET_PATH)?;
        // Make the API IPC globally read and writable for non-root user to
        // query and ping
        std::fs::set_permissions(
            NipartClient::DEFAULT_SOCKET_PATH,
            Permissions::from_mode(0o0666),
        )
        .map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Failed to set permission of {} to 0666: {e}",
                    NipartClient::DEFAULT_SOCKET_PATH
                ),
            )
        })?;

        let (sender, receiver) = unbounded::<NipartManagerCmd>();

        let commander = NipartCommander::new(sender).await?;
        // The boot pass pauses the interface monitor and applies the saved
        // state, so it must not interleave with a client transaction
        // (`apply`, `up`, `down` or `wifi`). Acquire the transaction lock
        // before spawning the task: `NipartDaemon::new()` returns, and API
        // connections get accepted, only after the lock is held, so a
        // client applying right after `npt ping` succeeds waits for the
        // boot pass instead of racing it (the race made the client's link
        // events fall into the boot pass' monitor pause window).
        let boot_lock =
            NipartLockManager::lock(std::process::id() as i32).await;
        // Start a thread to load saved state instead of hanging
        let mut new_commander = commander.clone();
        tokio::spawn(async move {
            let _boot_lock = boot_lock;
            match new_commander.load_saved_state().await {
                Ok(()) => log::info!("Saved state load finished"),
                Err(e) => {
                    log::error!(
                        "Failed to load saved state: {e}, starting with empty \
                         state"
                    );
                }
            }
        });

        std::fs::create_dir_all(
            std::path::Path::new(DAEMON_PID_FILE)
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/var/run")),
        )
        .map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!("Failed to create pid file dir: {e}"),
            )
        })?;
        std::fs::write(DAEMON_PID_FILE, format!("{}\n", std::process::id()))
            .map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!("Failed to write pid file {DAEMON_PID_FILE}: {e}"),
                )
            })?;

        Ok(Self {
            api_ipc,
            commander,
            managers_ipc: receiver,
            pid_file: DAEMON_PID_FILE.to_string(),
            sigterm,
            sigint,
            dns_auto_timer: tokio::time::interval(DNS_AUTO_REFRESH_INTERVAL),
            last_auto_dns_servers: Vec::new(),
        })
    }

    /// Please run this function in a thread
    pub(crate) async fn run(&mut self) {
        loop {
            tokio::select! {
                result = self.api_ipc.accept() => {
                    self.handle_api_connection(result).await;
                },
                cmd = self.managers_ipc.next() => {
                    if let Some(cmd) = cmd {
                        self.handle_manager_cmd(cmd).await;
                    }
                },
                _ = self.sigterm.recv() => {
                    log::info!("Received SIGTERM, shutting down");
                    break;
                },
                _ = self.sigint.recv() => {
                    log::info!("Received SIGINT, shutting down");
                    break;
                },
                _ = self.dns_auto_timer.tick() => {
                    self.refresh_dns_cache_auto_dns().await;
                }
                else => break,
            }
        }
        log::info!("Shutting down workers");
        self.commander.shutdown().await;
    }

    /// Refresh the DNS cache `auto-dns` upstream when the DHCP learned
    /// nameservers changed.  The DNS cache worker ignores the refresh when
    /// no cache server is running.
    async fn refresh_dns_cache_auto_dns(&mut self) {
        let servers = match self.commander.auto_dns_servers().await {
            Ok(s) => s,
            Err(e) => {
                log::debug!("Failed to query DHCP nameservers: {e}");
                return;
            }
        };
        if servers == self.last_auto_dns_servers {
            return;
        }
        self.last_auto_dns_servers = servers;
        if let Err(e) = self.commander.refresh_dns_cache_auto_dns().await {
            log::debug!("Failed to refresh DNS cache upstreams: {e}");
        }
    }

    async fn handle_api_connection(
        &mut self,
        result: Result<NipartIpcConnection, NipartError>,
    ) {
        match result {
            Ok(conn) => {
                let commander = self.commander.clone();
                tokio::spawn(async move {
                    process_api_connection(conn, commander).await
                });
            }
            Err(e) => {
                log::info!("Ignoring failure of accepting API connection: {e}");
            }
        }
    }

    async fn handle_manager_cmd(&mut self, cmd: NipartManagerCmd) {
        // Since event worker is single thread, the event will be processed
        // as the order of its arrival.
        log::trace!("Got command from manager {cmd:?}");
        match cmd {
            NipartManagerCmd::LinkEvent(event) => {
                if let Err(e) =
                    self.commander.event_manager.handle_event(*event).await
                {
                    log::error!("{e}");
                }
            }
        }
    }
}
