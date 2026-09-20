// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use nipart::{DnsCacheConfig, NipartError};

use super::{NipartDnsCmd, NipartDnsReply, NipartDnsServerConfig};
use crate::TaskManager;

/// Manager of the embedded DNS cache task.
///
/// The worker owns the cache server. Applying a new cache configuration
/// stops the old server before starting the new one, so the bind port is
/// always released before the new server tries to bind it.
#[derive(Debug, Clone)]
pub(crate) struct NipartDnsManager {
    mgr: TaskManager<NipartDnsCmd, NipartDnsReply>,
}

impl NipartDnsManager {
    pub(crate) async fn new() -> Result<Self, NipartError> {
        Ok(Self {
            mgr: TaskManager::new::<super::NipartDnsWorker>("dns-cache")
                .await?,
        })
    }

    pub(crate) async fn shutdown(&self) {
        self.mgr.shutdown().await
    }

    /// Start, reconfigure or stop the DNS cache according to `cache`.
    ///
    /// `auto_dns_servers` carries nameservers learned from DHCP/IPv6-RA/VPN
    /// used when `cache.fallback.auto-dns` is true.
    pub(crate) async fn apply_config(
        &mut self,
        cache: Option<&DnsCacheConfig>,
        auto_dns_servers: &[IpAddr],
    ) -> Result<(), NipartError> {
        let cache = match cache {
            Some(cache) => cache,
            None => {
                // `dns-resolver` not mentioned in desired state: keep the
                // current cache as is.
                return Ok(());
            }
        };
        if !cache.enabled {
            return self.stop().await;
        }
        let config = NipartDnsServerConfig::new(cache, auto_dns_servers)?;
        self.mgr.exec(NipartDnsCmd::Start(config)).await?;
        Ok(())
    }

    /// Refresh the upstream nameservers of a running cache without
    /// restarting it, e.g. after a DHCP lease changed the dynamic
    /// nameservers. No-op when the cache is not running.
    pub(crate) async fn refresh_auto_dns(
        &mut self,
        auto_dns_servers: &[IpAddr],
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartDnsCmd::RefreshAutoDns(auto_dns_servers.to_vec()))
            .await?;
        Ok(())
    }

    /// Notify the running cache that the network path of its upstream
    /// nameservers changed, e.g. the default gateway was replaced by a
    /// route apply, a DHCP lease or the boot-up state restore.
    ///
    /// The cache keeps its cached replies but retries the upstream groups
    /// which were marked dead instead of waiting out their retry backoff.
    /// A stopped cache is not an error: a cache started later has no
    /// failure state to clear.
    pub(crate) async fn notify_network_change(
        &mut self,
    ) -> Result<(), NipartError> {
        self.mgr.exec(NipartDnsCmd::NotifyNetworkChange).await?;
        Ok(())
    }

    pub(crate) async fn stop(&mut self) -> Result<(), NipartError> {
        self.mgr.exec(NipartDnsCmd::Stop).await?;
        Ok(())
    }

    /// Whether the DNS cache server task is currently running.
    #[allow(dead_code)]
    pub(crate) async fn is_running(&mut self) -> Result<bool, NipartError> {
        match self.mgr.exec(NipartDnsCmd::Query).await? {
            NipartDnsReply::Running(running) => Ok(running),
            NipartDnsReply::None => Ok(false),
        }
    }
}
