// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use serde::{Deserialize, Serialize};

use crate::{ErrorKind, JsonDisplay, NipartError};

const DNS_OPTS_NO_VALUE: [&str; 15] = [
    "debug",
    "edns0",
    "inet6",
    "ip6-bytestring",
    "ip6-dotint",
    "no-aaaa",
    "no-check-names",
    "no-ip6-dotint",
    "no-reload",
    "no-tld-query",
    "rotate",
    "single-request",
    "single-request-reopen",
    "trust-ad",
    "use-vc",
];

const DNS_OPTS_WITH_VALUE: [&str; 3] = ["ndots", "timeout", "attempts"];

/// DNS resolver state.
///
/// Example YAML:
/// ```yaml
/// ---
/// dns-resolver:
///   config:
///     search:
///     - example.org
///     server:
///     - 192.0.2.250
///   cache:
///     enabled: true
///     bind: 127.0.0.1:53
///     fallback:
///       auto-dns: true
///       nameservers:
///         - https://dns.example.org/dns-query
///     doh:
///       nameservers:
///         - 192.0.2.53
///     groups:
///       - name: home
///         domains:
///           - sweat.example.org
///         nameservers:
///           - 192.0.2.1
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize, JsonDisplay,
)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct DnsResolver {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The running effective DNS client configuration. It is the
    /// combination of static configuration and dynamic configuration
    /// learned from DHCP or IPv6-RA. Ignored when applying.
    pub running: Option<DnsResolverClient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Static saved DNS resolver configuration.
    /// When applying, `None` means preserve the current static DNS
    /// configuration. `Some` overrides it: an empty [DnsResolverClient]
    /// purges all static DNS settings.
    pub config: Option<DnsResolverClient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// DNS cache configuration. The cache is a daemon task listening on
    /// [DnsCacheConfig::bind], forwarding queries to upstream nameservers.
    pub cache: Option<DnsCacheConfig>,
}

impl DnsResolver {
    pub fn is_empty(&self) -> bool {
        self.running.is_none() && self.config.is_none() && self.cache.is_none()
    }

    /// Merge `new_state` into `self`, preferring the new values.
    pub(crate) fn merge(
        &mut self,
        new_state: &Self,
    ) -> Result<(), NipartError> {
        if new_state.is_empty() {
            return Ok(());
        }
        if new_state.running.is_some() {
            self.running = new_state.running.clone();
        }
        if new_state.config.is_some() {
            self.config = new_state.config.clone();
        }
        if new_state.cache.is_some() {
            self.cache = new_state.cache.clone();
        }
        Ok(())
    }

    /// Diff against `old`, keeping only the properties explicitly set in
    /// this state.
    pub(crate) fn gen_diff(&self, old: &Self) -> Self {
        Self {
            // `running` is queried, never applied.
            running: None,
            config: self.config.clone().or_else(|| old.config.clone()),
            cache: self.cache.clone().or_else(|| old.cache.clone()),
        }
    }

    /// Validate the desired DNS resolver configuration.
    pub(crate) fn validate(&self) -> Result<(), NipartError> {
        if let Some(config) = self.config.as_ref() {
            config.validate()?;
        }
        if let Some(cache) = self.cache.as_ref() {
            cache.validate()?;
            // DNS cache is only reachable when the host resolver points to
            // its bind address. Requiring it to be the first nameserver of
            // `config.server` turns a silent "cache is running but no query
            // reaches it" mismatch into an apply error.
            if cache.enabled
                && let Some(cache_addr) = cache.bind_addr()
            {
                let first_server = self
                    .config
                    .as_ref()
                    .and_then(|c| c.server.as_ref())
                    .and_then(|s| s.first());
                match first_server {
                    Some(srv) => {
                        let first_addr = parse_dns_server(srv)?;
                        // `config.server` holds plain addresses while
                        // `cache.bind` carries a port: only the address part
                        // can match. A nameserver without a port uses the
                        // default DNS port 53, same as an explicit
                        // `127.0.0.1:53`.
                        let first_is_cache = first_addr == cache_addr.ip()
                            || SocketAddr::new(first_addr, 53) == cache_addr;
                        if !first_is_cache {
                            return Err(NipartError::new(
                                ErrorKind::InvalidArgument,
                                format!(
                                    "DNS cache bind address {cache_addr} must \
                                     be the first entry of \
                                     dns-resolver.config.server, but got {srv}"
                                ),
                            ));
                        }
                    }
                    None => {
                        return Err(NipartError::new(
                            ErrorKind::InvalidArgument,
                            "DNS cache is enabled but \
                             dns-resolver.config.server is not defined"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// DNS client configuration: nameservers, search domains and options.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize, JsonDisplay,
)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct DnsResolverClient {
    /// Nameserver IP addresses. IPv6 link-local address could carry
    /// interface name, e.g. `fe80::1%eth1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<Vec<String>>,
    /// Search list for host-name lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<Vec<String>>,
    /// DNS resolver options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

impl DnsResolverClient {
    pub fn is_empty(&self) -> bool {
        self.server.is_none() && self.search.is_none() && self.options.is_none()
    }

    pub(crate) fn validate(&self) -> Result<(), NipartError> {
        if let Some(servers) = self.server.as_ref() {
            for srv in servers {
                parse_dns_server(srv)?;
            }
        }
        if let Some(options) = self.options.as_ref() {
            for opt in options {
                match opt.split_once(':') {
                    Some((name, _value)) => {
                        if !DNS_OPTS_WITH_VALUE.contains(&name) {
                            return Err(NipartError::new(
                                ErrorKind::InvalidArgument,
                                format!(
                                    "DNS option '{name}' is not supported to \
                                     hold a value, only support these without \
                                     value: {} and these with values: {}",
                                    DNS_OPTS_NO_VALUE.join(", "),
                                    DNS_OPTS_WITH_VALUE.join(":"),
                                ),
                            ));
                        }
                    }
                    None => {
                        if !DNS_OPTS_NO_VALUE.contains(&opt.as_str()) {
                            return Err(NipartError::new(
                                ErrorKind::InvalidArgument,
                                format!(
                                    "Unsupported DNS option {opt}, only \
                                     support these without value: {} and \
                                     these with values: {}",
                                    DNS_OPTS_NO_VALUE.join(", "),
                                    DNS_OPTS_WITH_VALUE.join(":"),
                                ),
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// DNS cache configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonDisplay)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct DnsCacheConfig {
    /// Whether caching is enabled. Default is false.
    #[serde(default)]
    pub enabled: bool,
    /// Address (both UDP and TCP) the DNS cache listens on.
    /// Default is `127.0.0.1:53`.
    #[serde(default = "default_dns_cache_bind")]
    pub bind: String,
    /// Maximum number of cache entries. Zero disables response caching
    /// while keeping the forwarding resolver running.
    #[serde(default = "default_dns_cache_size")]
    pub max_cache_size: usize,
    /// Whether to load `/etc/hosts` as static records. Default is true.
    #[serde(default = "default_true")]
    pub load_etc_hosts: bool,
    /// Upstream for domains not matched by any group.
    #[serde(default)]
    pub fallback: NipartDnsFallback,
    /// Plain IP nameservers used to resolve DoH hostnames. Mandatory when a
    /// DoH nameserver is configured and its hostname is not in
    /// `/etc/hosts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh: Option<NipartDnsDoh>,
    /// Domain routed upstream groups. Longest suffix match wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<NipartDnsUpstreamGroup>,
}

fn default_dns_cache_bind() -> String {
    DnsCacheConfig::DEFAULT_BIND.to_string()
}

fn default_dns_cache_size() -> usize {
    DnsCacheConfig::DEFAULT_MAX_CACHE_SIZE
}

fn default_true() -> bool {
    true
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_dns_cache_bind(),
            max_cache_size: default_dns_cache_size(),
            load_etc_hosts: true,
            fallback: NipartDnsFallback::default(),
            doh: None,
            groups: Vec::new(),
        }
    }
}

impl DnsCacheConfig {
    pub const DEFAULT_BIND: &'static str = "127.0.0.1:53";
    pub const DEFAULT_MAX_CACHE_SIZE: usize = 4096;

    /// Parsed listen address.
    pub fn bind_addr(&self) -> Option<SocketAddr> {
        self.bind.parse::<SocketAddr>().ok()
    }

    pub(crate) fn validate(&self) -> Result<(), NipartError> {
        let bind_addr = self.bind_addr().ok_or_else(|| {
            NipartError::new(
                ErrorKind::InvalidArgument,
                format!("Invalid DNS cache bind address: {}", self.bind),
            )
        })?;
        if !bind_addr.ip().is_loopback() && self.enabled {
            // A non-loopback bind exposes the cache to the network. This is
            // legitimate (e.g. a container gateway address), so only warn.
            log::warn!(
                "DNS cache is bound to non-loopback address {}",
                bind_addr
            );
        }

        self.fallback.validate("dns-resolver.cache.fallback")?;
        if let Some(doh) = self.doh.as_ref() {
            doh.validate()?;
        }

        let mut group_names: HashSet<&str> = HashSet::new();
        for group in &self.groups {
            if group.name.is_empty() {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    "DNS cache group name cannot be empty".to_string(),
                ));
            }
            if !group_names.insert(&group.name) {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!("Duplicate DNS cache group name: {}", group.name),
                ));
            }
            group.validate()?;
        }
        // Two groups sharing a domain would be ambiguous: runtime picks by
        // longest suffix and a tie is resolved by iteration order.
        for (i, group_a) in self.groups.iter().enumerate() {
            for group_b in self.groups.iter().skip(i + 1) {
                for domain_a in &group_a.domains {
                    for domain_b in &group_b.domains {
                        if domain_a.eq_ignore_ascii_case(domain_b) {
                            return Err(NipartError::new(
                                ErrorKind::InvalidArgument,
                                format!(
                                    "DNS cache domain '{domain_a}' of group \
                                     '{}' overlaps with domain '{domain_b}' \
                                     of group '{}'",
                                    group_a.name, group_b.name
                                ),
                            ));
                        }
                    }
                }
            }
        }

        use_doh_validation(self)?;
        Ok(())
    }
}

/// Upstream nameservers used for domains not matched by any group.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonDisplay)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct NipartDnsFallback {
    /// Use nameservers learned from DHCP, IPv6-RA, VPN etc. Default is true.
    /// They are prepended to [Self::nameservers], dynamic nameservers are
    /// used first.
    #[serde(default = "default_true")]
    pub auto_dns: bool,
    /// Static fallback nameservers. Plain IP addresses or DoH URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
    /// Whether to suppress AAAA queries to these nameservers.
    #[serde(default)]
    pub disable_ipv6: bool,
}

impl Default for NipartDnsFallback {
    fn default() -> Self {
        Self {
            auto_dns: true,
            nameservers: Vec::new(),
            disable_ipv6: false,
        }
    }
}

impl NipartDnsFallback {
    pub(crate) fn validate(&self, path: &str) -> Result<(), NipartError> {
        validate_nameservers(&self.nameservers, path)
    }
}

/// Plain IP nameservers used to resolve DoH server hostnames.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize, JsonDisplay,
)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct NipartDnsDoh {
    #[serde(default)]
    pub nameservers: Vec<IpAddr>,
    /// Whether to suppress AAAA queries to these nameservers.
    #[serde(default)]
    pub disable_ipv6: bool,
}

impl NipartDnsDoh {
    pub(crate) fn validate(&self) -> Result<(), NipartError> {
        if self.nameservers.is_empty() {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                "dns-resolver.cache.doh.nameservers must contain at least one \
                 plain IP nameserver"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// A named group of upstream nameservers serving a set of domains.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize, JsonDisplay,
)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct NipartDnsUpstreamGroup {
    pub name: String,
    /// Domains routed to this group. A domain matches itself and its
    /// subdomains (suffix match); the longest match wins.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Upstream nameservers. Plain IP addresses or DoH URLs. An empty list
    /// means reply NXDOMAIN for matched domains.
    #[serde(default)]
    pub nameservers: Vec<String>,
    /// Whether to suppress AAAA queries to this group.
    #[serde(default)]
    pub disable_ipv6: bool,
}

impl NipartDnsUpstreamGroup {
    pub(crate) fn validate(&self) -> Result<(), NipartError> {
        for domain in &self.domains {
            validate_domain_pattern(domain)?;
        }
        validate_nameservers(
            &self.nameservers,
            &format!("dns-resolver.cache.groups.{}.nameservers", self.name),
        )
    }
}

/// A parsed upstream nameserver: a plain IP address (with an optional port)
/// or a DNS-over-HTTPS URL.
///
/// Accepted forms of the plain IP upstream:
///  * `192.0.2.53` (plaintext on 53, opportunistic DoT probe on 853)
///  * `192.0.2.53:5353` (port pinned for every attempt, DoT included)
///  * `2001:db8::53` (plaintext on 53, opportunistic DoT probe on 853)
///  * `[2001:db8::53]:5353` (port pinned for every attempt, DoT included)
///  * `[fe80::1%2]:53` (IPv6 with numeric scope id)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsUpstreamServer {
    /// Plain DNS nameserver.
    ///
    /// `addr` is the plaintext endpoint: port 53 when the configuration
    /// wrote no port. `port_explicit` records whether that port was written
    /// in the configuration. `mudz` pins every attempt, including the
    /// opportunistic DNS-over-TLS probe, to an explicit port, so an
    /// implicit port must be handed over as a bare address to keep the
    /// probe on 853.
    Ip {
        addr: SocketAddr,
        port_explicit: bool,
    },
    Doh(String),
}

impl DnsUpstreamServer {
    /// A nameserver without an explicit port: plaintext queries use 53 and
    /// DNS over TLS is probed on 853.
    pub fn from_ip(ip: IpAddr) -> Self {
        Self::Ip {
            addr: SocketAddr::new(ip, 53),
            port_explicit: false,
        }
    }

    pub fn parse(srv: &str) -> Result<Self, NipartError> {
        if let Some(url) = doh_url(srv) {
            return Ok(Self::Doh(url));
        }
        if let Ok(addr) = srv.parse::<SocketAddr>() {
            return Ok(Self::Ip {
                addr,
                port_explicit: true,
            });
        }
        // An interface name instead of the numeric scope id cannot be
        // used to open a socket: reject it instead of silently dropping
        // the scope and sending the query to the wrong link.
        if srv.contains('%') {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid DNS cache upstream server {srv}: interface name \
                     is not supported, please use a numeric scope id, e.g. \
                     [fe80::1%2]:53"
                ),
            ));
        }
        // Plain IP address without a port.
        let ip = parse_dns_server(srv)?;
        Ok(Self::from_ip(ip))
    }

    pub fn is_doh(&self) -> bool {
        matches!(self, Self::Doh(_))
    }
}

impl std::fmt::Display for DnsUpstreamServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip {
                addr,
                port_explicit: true,
            } => write!(f, "{addr}"),
            // Dropping the implicit port lets mudz probe DNS over TLS on
            // 853 before falling back to plaintext on 53.
            Self::Ip {
                addr,
                port_explicit: false,
            } => write!(f, "{}", addr.ip()),
            Self::Doh(url) => write!(f, "{url}"),
        }
    }
}

/// Parse a DNS nameserver string into an [IpAddr].
///
/// Accepted formats:
///  * IPv4 address, e.g. `192.0.2.53`
///  * IPv6 address, e.g. `2001:db8::53`
///  * IPv6 link-local address with interface name, e.g. `fe80::1%eth1`
fn parse_dns_server(srv: &str) -> Result<IpAddr, NipartError> {
    if let Ok(ip) = srv.parse::<IpAddr>() {
        return Ok(ip);
    }
    if let Some((addr, iface_name)) = srv.split_once('%')
        && !iface_name.is_empty()
        && iface_name
            .find(|c: char| c.is_whitespace() || c == '/')
            .is_none()
        && let Ok(IpAddr::V6(ip)) = addr.parse::<IpAddr>()
        && is_ipv6_link_local(&ip)
    {
        return Ok(IpAddr::V6(ip));
    }
    Err(NipartError::new(
        ErrorKind::InvalidArgument,
        format!("Invalid DNS server string {srv}"),
    ))
}

/// Return the DoH URL if `srv` is an HTTPS URL.
fn doh_url(srv: &str) -> Option<String> {
    if srv.starts_with("https://") && srv.len() > "https://".len() {
        Some(srv.to_string())
    } else {
        None
    }
}

fn validate_nameservers(
    nameservers: &[String],
    path: &str,
) -> Result<(), NipartError> {
    for srv in nameservers {
        DnsUpstreamServer::parse(srv).map_err(|e| {
            NipartError::new(
                e.kind(),
                format!("Invalid nameserver at {path}: {}", e.msg()),
            )
        })?;
    }
    Ok(())
}

fn validate_domain_pattern(domain: &str) -> Result<(), NipartError> {
    if domain.is_empty() {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            "DNS cache group domain cannot be empty".to_string(),
        ));
    }
    if domain.contains(char::is_whitespace) {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!("Invalid DNS cache group domain '{domain}'"),
        ));
    }
    Ok(())
}

/// DoH nameservers require plain IP nameservers to resolve their hostnames
/// unless the hostnames are present in `/etc/hosts`.
fn use_doh_validation(cache: &DnsCacheConfig) -> Result<(), NipartError> {
    let doh_hostnames = cache.doh_hostnames();
    if doh_hostnames.is_empty() {
        return Ok(());
    }
    match cache.doh.as_ref() {
        Some(doh) if !doh.nameservers.is_empty() => Ok(()),
        Some(_) => Err(NipartError::new(
            ErrorKind::InvalidArgument,
            "DoH nameserver is configured but \
             dns-resolver.cache.doh.nameservers is empty"
                .to_string(),
        )),
        None => {
            let unresolved: Vec<&str> = doh_hostnames
                .iter()
                .filter(|host| !host_in_etc_hosts(host))
                .map(|s| s.as_str())
                .collect();
            if unresolved.is_empty() {
                Ok(())
            } else {
                Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "DoH nameservers {unresolved:?} are configured but \
                         dns-resolver.cache.doh.nameservers is not defined \
                         and their hostnames are not in /etc/hosts"
                    ),
                ))
            }
        }
    }
}

impl DnsCacheConfig {
    /// Hostnames of all configured DoH nameservers, lowercased, deduplicated.
    pub(crate) fn doh_hostnames(&self) -> Vec<String> {
        let mut ret = Vec::new();
        let mut seen = HashSet::new();
        let all = self
            .fallback
            .nameservers
            .iter()
            .chain(self.groups.iter().flat_map(|g| g.nameservers.iter()));
        for srv in all {
            if let Some(hostname) = doh_url_hostname(srv)
                && seen.insert(hostname.clone())
            {
                ret.push(hostname);
            }
        }
        ret
    }
}

/// Extract the lowercase hostname of a DoH URL, e.g.
/// `https://dns.example.org/dns-query` -> `dns.example.org`.
pub fn doh_url_hostname(url: &str) -> Option<String> {
    let without_scheme = url.strip_prefix("https://")?;
    let authority = without_scheme.split('/').next()?;
    let hostname = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let hostname = hostname
        .strip_prefix('[')
        .and_then(|h| h.split_once(']').map(|(h, _)| h))
        .unwrap_or_else(|| hostname.split(':').next().unwrap_or(hostname));
    if hostname.is_empty() {
        None
    } else {
        Some(hostname.to_lowercase())
    }
}

fn host_in_etc_hosts(hostname: &str) -> bool {
    host_in_hosts_file(hostname, "/etc/hosts")
}

fn host_in_hosts_file(hostname: &str, path: &str) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    content.lines().any(|line| {
        let line = line.split('#').next().unwrap_or_default();
        let mut parts = line.split_whitespace();
        parts.next().is_some()
            && parts.any(|name| name.eq_ignore_ascii_case(hostname))
    })
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}
