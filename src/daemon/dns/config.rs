// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use mudz::{
    MudzConfig, MudzDohConfig, MudzFallbackConfig, MudzGroupConfig,
    MudzMainConfig,
};
use nipart::{DnsCacheConfig, DnsUpstreamServer, NipartDnsUpstreamGroup};

/// Runtime configuration of the embedded DNS cache server.
///
/// It carries the schema level [DnsCacheConfig] plus the effective
/// nameservers resolved by the daemon (e.g. DHCP/RA learned servers for
/// `fallback.auto-dns: true`), and converts them into the [`MudzConfig`]
/// consumed by the embedded `mudz` server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NipartDnsServerConfig {
    pub(crate) bind: SocketAddr,
    pub(crate) max_cache_size: usize,
    pub(crate) load_etc_hosts: bool,
    /// Dynamic nameservers learned from DHCP/IPv6-RA/VPN. Kept separately
    /// so they can be refreshed without a full re-apply.
    pub(crate) auto_dns_servers: Vec<IpAddr>,
    pub(crate) fallback: DnsUpstreamConfig,
    pub(crate) doh: Option<DnsDohConfig>,
    pub(crate) groups: Vec<DnsGroupConfig>,
}

impl NipartDnsServerConfig {
    /// Build the runtime config from schema config.
    ///
    /// `auto_dns_servers` carries the dynamic nameservers learned from
    /// DHCP/IPv6-RA/VPN.  They are used only when
    /// `cache.fallback.auto-dns` is true and are placed before the static
    /// fallback nameservers so dynamic upstreams are preferred.
    pub(crate) fn new(
        cache: &DnsCacheConfig,
        auto_dns_servers: &[IpAddr],
    ) -> Result<Self, nipart::NipartError> {
        let bind = cache.bind_addr().ok_or_else(|| {
            nipart::NipartError::new(
                nipart::ErrorKind::InvalidArgument,
                format!("Invalid DNS cache bind address: {}", cache.bind),
            )
        })?;

        let fallback_servers = cache
            .fallback
            .nameservers
            .iter()
            .map(|srv| DnsUpstreamServer::parse(srv))
            .collect::<Result<Vec<_>, _>>()?;
        let auto_dns_servers = if cache.fallback.auto_dns {
            auto_dns_servers.to_vec()
        } else {
            Vec::new()
        };

        let groups = cache
            .groups
            .iter()
            .map(DnsGroupConfig::new)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            bind,
            max_cache_size: cache.max_cache_size,
            load_etc_hosts: cache.load_etc_hosts,
            auto_dns_servers,
            fallback: DnsUpstreamConfig {
                static_servers: fallback_servers,
                disable_ipv6: cache.fallback.disable_ipv6,
            },
            doh: cache.doh.as_ref().map(|doh| DnsDohConfig {
                nameservers: doh.nameservers.clone(),
                disable_ipv6: doh.disable_ipv6,
            }),
            groups,
        })
    }

    /// Build the configuration of the embedded `mudz` server.
    ///
    /// The dynamic nameservers learned from DHCP/IPv6-RA/VPN are placed
    /// before the static fallback nameservers, so dynamic upstreams are
    /// preferred. `log_level` keeps its default because it only applies to
    /// the standalone `mudzd` binary; nipart installs its own logger.
    pub(crate) fn mudz_config(&self) -> MudzConfig {
        let mut groups = HashMap::with_capacity(self.groups.len());
        for group in &self.groups {
            groups.insert(
                group.name.clone(),
                MudzGroupConfig {
                    // A group without nameservers means "reply NXDOMAIN"
                    // to mudz as well.
                    nameservers: group
                        .upstream
                        .static_servers
                        .iter()
                        .map(upstream_server_string)
                        .collect(),
                    domains: group.domains.clone(),
                    disable_ipv6: group.upstream.disable_ipv6,
                },
            );
        }

        MudzConfig {
            main: MudzMainConfig {
                // TCP listens on the same address, like the daemon did
                // before: `tcp_bind` defaults to `None` in mudz.
                udp_bind: self.bind.to_string(),
                max_cache_size: self.max_cache_size,
                load_etc_hosts: self.load_etc_hosts,
                ..Default::default()
            },
            fallback: MudzFallbackConfig {
                nameservers: self
                    .fallback
                    .servers(&self.auto_dns_servers)
                    .iter()
                    .map(upstream_server_string)
                    .collect(),
                disable_ipv6: self.fallback.disable_ipv6,
            },
            doh: self.doh.as_ref().map(|doh| MudzDohConfig {
                nameservers: doh.nameservers.clone(),
                disable_ipv6: doh.disable_ipv6,
                ..Default::default()
            }),
            groups,
        }
    }

    /// Replace the dynamic nameservers.  The fallback upstream list is
    /// rebuilt as dynamic servers first, then static ones.
    pub(crate) fn set_auto_dns_servers(&mut self, servers: &[IpAddr]) {
        self.auto_dns_servers = servers.to_vec();
    }
}

/// Nameserver string accepted by mudz: plain IP, `IP:port` or DoH URL.
fn upstream_server_string(server: &DnsUpstreamServer) -> String {
    match server {
        DnsUpstreamServer::Ip(addr) => addr.to_string(),
        DnsUpstreamServer::Doh(url) => url.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsUpstreamConfig {
    /// Static upstream servers from schema config.
    pub(crate) static_servers: Vec<DnsUpstreamServer>,
    pub(crate) disable_ipv6: bool,
}

impl DnsUpstreamConfig {
    /// Effective upstream server list: dynamic servers first, then static
    /// ones. Groups only have static servers.
    pub(crate) fn servers(
        &self,
        auto_dns_servers: &[IpAddr],
    ) -> Vec<DnsUpstreamServer> {
        auto_dns_servers
            .iter()
            .copied()
            .map(|ip| DnsUpstreamServer::Ip(SocketAddr::new(ip, 53)))
            .chain(self.static_servers.iter().cloned())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsDohConfig {
    pub(crate) nameservers: Vec<IpAddr>,
    pub(crate) disable_ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsGroupConfig {
    pub(crate) name: String,
    pub(crate) domains: Vec<String>,
    pub(crate) upstream: DnsUpstreamConfig,
}

impl DnsGroupConfig {
    fn new(
        group: &NipartDnsUpstreamGroup,
    ) -> Result<Self, nipart::NipartError> {
        let servers = group
            .nameservers
            .iter()
            .map(|srv| DnsUpstreamServer::parse(srv))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            name: group.name.clone(),
            domains: group.domains.iter().map(|d| d.to_lowercase()).collect(),
            upstream: DnsUpstreamConfig {
                static_servers: servers,
                disable_ipv6: group.disable_ipv6,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use nipart::DnsCacheConfig;

    use super::*;

    #[test]
    fn test_dynamic_auto_dns_prepended() {
        let mut cache = DnsCacheConfig::default();
        cache.fallback.nameservers = vec!["192.0.2.53".to_string()];
        let config = NipartDnsServerConfig::new(
            &cache,
            &["198.51.100.53".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(
            config.fallback.servers(&config.auto_dns_servers),
            vec![
                DnsUpstreamServer::Ip("198.51.100.53:53".parse().unwrap()),
                DnsUpstreamServer::Ip("192.0.2.53:53".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn test_auto_dns_disabled() {
        let mut cache = DnsCacheConfig::default();
        cache.fallback.auto_dns = false;
        let config = NipartDnsServerConfig::new(
            &cache,
            &["198.51.100.53".parse().unwrap()],
        )
        .unwrap();
        assert!(config.fallback.servers(&config.auto_dns_servers).is_empty());
    }

    #[test]
    fn test_mudz_config_maps_schema() {
        let mut cache = DnsCacheConfig::default();
        cache.enabled = true;
        cache.bind = "127.0.0.1:5353".to_string();
        cache.max_cache_size = 0;
        cache.load_etc_hosts = false;
        cache.fallback.nameservers =
            vec!["https://dns.example.org/dns-query".to_string()];
        cache.fallback.disable_ipv6 = true;
        cache.doh = Some(Default::default());
        cache.doh.as_mut().unwrap().nameservers =
            vec!["192.0.2.53".parse().unwrap()];
        let mut home = nipart::NipartDnsUpstreamGroup::default();
        home.name = "home".to_string();
        home.domains = vec!["Sweat.Home".to_string()];
        home.nameservers = vec!["192.0.2.1".to_string()];
        home.disable_ipv6 = true;
        let mut blocked = nipart::NipartDnsUpstreamGroup::default();
        blocked.name = "blocked".to_string();
        blocked.domains = vec!["ads.example".to_string()];
        cache.groups = vec![home, blocked];

        let config = NipartDnsServerConfig::new(
            &cache,
            &["198.51.100.53".parse().unwrap()],
        )
        .unwrap();
        let mudz_config = config.mudz_config();

        assert_eq!(mudz_config.main.udp_bind, "127.0.0.1:5353");
        assert_eq!(mudz_config.main.max_cache_size, 0);
        assert!(!mudz_config.main.load_etc_hosts);
        // Dynamic nameservers come before the static ones.
        assert_eq!(
            mudz_config.fallback.nameservers,
            vec![
                "198.51.100.53:53".to_string(),
                "https://dns.example.org/dns-query".to_string(),
            ]
        );
        assert!(mudz_config.fallback.disable_ipv6);
        assert_eq!(
            mudz_config.doh.as_ref().unwrap().nameservers,
            vec!["192.0.2.53".parse::<IpAddr>().unwrap()]
        );

        let home = mudz_config.groups.get("home").unwrap();
        assert_eq!(home.nameservers, vec!["192.0.2.1:53".to_string()]);
        assert_eq!(home.domains, vec!["sweat.home".to_string()]);
        assert!(home.disable_ipv6);
        // A group without nameservers means "reply NXDOMAIN" in mudz too.
        assert!(
            mudz_config
                .groups
                .get("blocked")
                .unwrap()
                .nameservers
                .is_empty()
        );

        mudz_config.validate().unwrap();
    }
}
