// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{DnsCacheConfig, DnsResolver, DnsResolverClient, NipartError};

/// Merged DNS resolver state.
///
/// The `config` of [Self::current] holds the effective host resolver
/// configuration (e.g. read from `/etc/resolv.conf`).  [Self::servers],
/// [Self::searches] and [Self::options] hold the static configuration to
/// persist after this apply: nmstate-like partial editing means an
/// undefined desired `config` property preserves the current static
/// value, while `config: {}` purges all static entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MergedDnsResolver {
    pub desired: Option<DnsResolver>,
    pub current: DnsResolver,
    /// Effective resolver of the host before this apply (e.g. the parsed
    /// `/etc/resolv.conf`), used to preserve dynamic entries.
    pub running: Option<DnsResolverClient>,
    pub servers: Vec<String>,
    pub searches: Vec<String>,
    pub options: Vec<String>,
    /// Dynamic nameservers learned from DHCP/IPv6-RA/VPN which must be
    /// preserved in the final resolver configuration.
    pub dynamic_servers: Vec<String>,
    /// Nameservers nipart wrote into `/etc/resolv.conf` in the previous
    /// apply: the previous static configuration plus the bind address of
    /// the previous cache.  They are told apart from the dynamic ones so
    /// that a removed static nameserver is not preserved as if it was
    /// learned from DHCP.
    #[serde(default)]
    pub previous_static_servers: Vec<String>,
    /// Cache configuration to persist after a successful apply.
    ///
    /// An undefined cache in the desired state preserves the previously
    /// saved cache. [Self::cache] remains the explicitly desired cache used
    /// by the apply path, so an omitted DNS section does not restart the
    /// running cache.
    #[serde(default)]
    pub cache_for_save: Option<DnsCacheConfig>,
}

impl MergedDnsResolver {
    pub(crate) fn new(
        desired: DnsResolver,
        mut current: DnsResolver,
        saved: Option<DnsResolver>,
    ) -> Result<Self, NipartError> {
        if let Some(saved_config) =
            saved.as_ref().and_then(|s| s.config.as_ref())
        {
            // The static configuration of the running state is the saved
            // one: the daemon persists `config` and re-applies it.
            current.config = Some(saved_config.clone());
        }
        let running = current.running.clone();
        let mut servers = current
            .config
            .as_ref()
            .and_then(|c| c.server.clone())
            .unwrap_or_default();
        let mut searches = current
            .config
            .as_ref()
            .and_then(|c| c.search.clone())
            .unwrap_or_default();
        let mut options = current
            .config
            .as_ref()
            .and_then(|c| c.options.clone())
            .unwrap_or_default();
        let dynamic_servers = running
            .as_ref()
            .and_then(|r| r.server.clone())
            .unwrap_or_default();
        // `current.config` is the previous static configuration: either
        // the saved static configuration (daemon apply) or the parsed
        // `/etc/resolv.conf` (no saved state).
        let previous_static_servers = current
            .config
            .as_ref()
            .and_then(|c| c.server.clone())
            .unwrap_or_default();

        let desired_is_empty = desired.is_empty();
        let cache_for_save = desired
            .cache
            .clone()
            .or_else(|| saved.as_ref().and_then(|s| s.cache.clone()));
        let config = desired.config.clone();
        if let Some(conf) = config.as_ref()
            && !conf.is_empty()
        {
            if let Some(des_servers) = conf.server.as_ref() {
                servers = des_servers.clone();
            }
            if let Some(des_searches) = conf.search.as_ref() {
                searches = des_searches.clone();
            }
            if let Some(des_options) = conf.options.as_ref() {
                options = des_options.clone();
            }
        } else if config.is_some() {
            // `config: {}`: purge all static DNS configuration.
            servers.clear();
            searches.clear();
            options.clear();
        }

        Ok(Self {
            desired: if desired_is_empty {
                None
            } else {
                Some(desired)
            },
            current,
            running,
            servers,
            searches,
            options,
            dynamic_servers,
            previous_static_servers,
            cache_for_save,
        })
    }

    /// Dynamic nameservers to keep after this apply: entries of the host
    /// resolver which nipart did not write in the previous apply nor is
    /// going to write in this one, i.e. nameservers learned from
    /// DHCP/IPv6-RA/VPN or managed by other tools.
    pub fn apply_dynamic_servers(&self) -> Vec<String> {
        self.dynamic_servers
            .iter()
            .filter(|srv| {
                !self.servers.contains(srv)
                    && !self.previous_static_servers.contains(srv)
            })
            .cloned()
            .collect()
    }

    /// Whether the desired state did not mention `dns-resolver` at all.
    pub fn is_unchanged(&self) -> bool {
        self.desired.is_none()
    }

    /// The static client configuration to persist.
    pub fn config(&self) -> DnsResolverClient {
        DnsResolverClient {
            server: Some(self.servers.clone()),
            search: Some(self.searches.clone()),
            options: Some(self.options.clone()),
        }
    }

    /// The cache configuration to apply.
    pub fn cache(&self) -> Option<&DnsCacheConfig> {
        self.desired.as_ref().and_then(|d| d.cache.as_ref())
    }

    /// The DNS resolver state to save.
    pub(crate) fn gen_state_for_save(&self) -> DnsResolver {
        DnsResolver {
            running: None,
            config: Some(self.config()),
            cache: self.cache_for_save.clone(),
        }
    }

    /// The DNS resolver diff to report to the client.
    pub(crate) fn gen_state_for_apply(&self) -> DnsResolver {
        let mut ret = self.desired.clone().unwrap_or_default();
        ret.running = Some(DnsResolverClient {
            server: Some(
                self.servers
                    .iter()
                    .cloned()
                    .chain(self.dynamic_servers.iter().cloned())
                    .collect(),
            ),
            search: Some(self.searches.clone()),
            options: Some(self.options.clone()),
        });
        ret
    }
}
