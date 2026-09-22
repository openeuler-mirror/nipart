// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    DnsCacheConfig, DnsResolver, DnsUpstreamServer, ErrorKind,
    MergedNetworkState, NetworkState, NipartApplyOption, doh_url_hostname,
};

const DOC_EXAMPLE_YAML: &str = r#"---
version: 1
dns-resolver:
  config:
    search:
      - example.org
      - example.net
    server:
      - 127.0.0.1
  cache:
    enabled: true
    bind: "127.0.0.1:53"
    max-cache-size: 1048576
    load-etc-hosts: false
    fallback:
      auto-dns: true
      nameservers:
        - "https://dns.example.org/dns-query"
        - "https://doh.example.net/dns-query"
      disable-ipv6: false
    doh:
      nameservers:
        - 192.0.2.53
        - 198.51.100.53
      disable-ipv6: true
    groups:
      - name: home
        domains:
          - home.example.org
          - 2.0.192.in-addr.arpa
        nameservers:
          - 203.0.113.1
      - name: corp
        disable-ipv6: true
        domains:
          - corp.example.net
          - 113.0.203.in-addr.arpa
        nameservers:
          - 203.0.113.254
          - 203.0.113.253
"#;

fn parse(yaml: &str) -> DnsResolver {
    NetworkState::new_from_yaml(yaml).unwrap().dns_resolver
}

fn validate(yaml: &str) -> Result<(), crate::NipartError> {
    NetworkState::new_from_yaml(yaml).unwrap().validate()
}

/// Assert `yaml` is rejected by the schema validation with an error message
/// containing `msg`.
fn assert_invalid(yaml: &str, msg: &str) {
    let result = validate(yaml);
    let err = match result {
        Ok(()) => panic!("Expected {yaml} to be rejected with '{msg}'"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    assert!(
        err.msg().contains(msg),
        "Error message '{}' does not contain '{msg}'",
        err.msg()
    );
}

#[test]
fn test_dns_resolver_doc_example() {
    let dns = parse(DOC_EXAMPLE_YAML);
    assert!(dns.running.is_none());
    let config = dns.config.as_ref().unwrap();
    assert_eq!(
        config.search.as_ref().unwrap(),
        &vec!["example.org".to_string(), "example.net".to_string()]
    );
    assert_eq!(
        config.server.as_ref().unwrap(),
        &vec!["127.0.0.1".to_string()]
    );
    let cache = dns.cache.as_ref().unwrap();
    assert!(cache.enabled);
    assert_eq!(cache.bind, "127.0.0.1:53");
    assert_eq!(cache.max_cache_size, 1048576);
    assert!(!cache.load_etc_hosts);
    assert!(cache.fallback.auto_dns);
    assert_eq!(
        cache.fallback.nameservers,
        vec![
            "https://dns.example.org/dns-query".to_string(),
            "https://doh.example.net/dns-query".to_string(),
        ]
    );
    let doh = cache.doh.as_ref().unwrap();
    assert_eq!(
        doh.nameservers,
        vec![
            "192.0.2.53".parse::<IpAddr>().unwrap(),
            "198.51.100.53".parse::<IpAddr>().unwrap(),
        ]
    );
    assert!(doh.disable_ipv6);
    assert_eq!(cache.groups.len(), 2);
    assert_eq!(cache.groups[0].name, "home");
    assert_eq!(
        cache.groups[0].domains,
        vec![
            "home.example.org".to_string(),
            "2.0.192.in-addr.arpa".to_string(),
        ]
    );
    assert_eq!(cache.groups[0].nameservers, vec!["203.0.113.1"]);
    assert_eq!(cache.groups[1].name, "corp");
    assert!(cache.groups[1].disable_ipv6);
    assert!(validate(DOC_EXAMPLE_YAML).is_ok());
}

#[test]
fn test_dns_resolver_yaml_round_trip() {
    let state = NetworkState::new_from_yaml(DOC_EXAMPLE_YAML).unwrap();
    let yaml = rmsd_yaml::to_string(&state).unwrap();
    let reparsed = NetworkState::new_from_yaml(&yaml).unwrap();
    assert_eq!(state, reparsed);
}

#[test]
fn test_dns_cache_defaults() {
    let dns = parse(
        r#"---
        dns-resolver:
          config:
            server:
              - 127.0.0.1
          cache:
            enabled: true
        "#,
    );
    let cache = dns.cache.as_ref().unwrap();
    assert!(cache.enabled);
    assert_eq!(cache.bind, DnsCacheConfig::DEFAULT_BIND);
    assert_eq!(cache.max_cache_size, DnsCacheConfig::DEFAULT_MAX_CACHE_SIZE);
    assert!(cache.load_etc_hosts);
    assert!(cache.fallback.auto_dns);
    assert!(cache.fallback.nameservers.is_empty());
    assert!(cache.doh.is_none());
    assert!(cache.groups.is_empty());
    assert_eq!(cache.bind_addr().unwrap().to_string(), "127.0.0.1:53");
}

#[test]
fn test_dns_resolver_running_and_config_are_optional() {
    let dns = parse(
        r#"---
        dns-resolver:
          running:
            search:
              - example.org
        "#,
    );
    assert!(dns.config.is_none());
    assert!(dns.cache.is_none());
    assert_eq!(
        dns.running.as_ref().unwrap().search.as_ref().unwrap(),
        &vec!["example.org".to_string()]
    );
}

#[test]
fn test_dns_empty_state_is_skipped_in_yaml() {
    let state = NetworkState::new_from_yaml(
        r#"---
        interfaces:
          - name: dummy0
            type: dummy
            state: up
        "#,
    )
    .unwrap();
    assert!(state.dns_resolver.is_empty());
    let yaml = rmsd_yaml::to_string(&state).unwrap();
    assert!(!yaml.contains("dns-resolver"), "Got {yaml}");
}

#[test]
fn test_dns_cache_zero_size_is_valid() {
    assert!(
        validate(
            r#"---
            dns-resolver:
              config:
                server:
                  - 127.0.0.1
              cache:
                enabled: true
                max-cache-size: 0
            "#,
        )
        .is_ok()
    );
}

#[test]
fn test_dns_cache_enabled_requires_config_server() {
    // A cache that nothing points to is a silent failure: the schema
    // requires the cache bind address to be the first static nameserver.
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            enabled: true
        "#,
        "dns-resolver.config.server is not defined",
    );
}

#[test]
fn test_dns_cache_bind_must_be_first_nameserver() {
    assert_invalid(
        r#"---
        dns-resolver:
          config:
            server:
              - 192.0.2.53
              - 127.0.0.1
          cache:
            enabled: true
            bind: "127.0.0.1:53"
        "#,
        "must be the first entry",
    );
    // Reversing the order fixes it.
    assert!(
        validate(
            r#"---
            dns-resolver:
              config:
                server:
                  - 127.0.0.1
                  - 192.0.2.53
              cache:
                enabled: true
                bind: "127.0.0.1:53"
            "#,
        )
        .is_ok()
    );
}

#[test]
fn test_dns_cache_disabled_does_not_require_config_server() {
    assert!(
        validate(
            r#"---
            dns-resolver:
              cache:
                enabled: false
            "#,
        )
        .is_ok()
    );
}

#[test]
fn test_dns_cache_invalid_bind() {
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            enabled: true
            bind: "127.0.0.1"
        "#,
        "Invalid DNS cache bind address",
    );
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            bind: "not-an-address"
        "#,
        "Invalid DNS cache bind address",
    );
}

#[test]
fn test_dns_cache_group_name_empty_and_duplicated() {
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            groups:
              - name: ""
        "#,
        "group name cannot be empty",
    );
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            groups:
              - name: home
                domains:
                  - home.example.org
              - name: home
                domains:
                  - corp.example.net
        "#,
        "Duplicate DNS cache group name: home",
    );
}

#[test]
fn test_dns_cache_domain_overlap_rejected() {
    // Same domain in two groups is ambiguous: the runtime resolves the
    // longest suffix match first and ties by iteration order. Comparison is
    // case insensitive.
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            groups:
              - name: home
                domains:
                  - home.example.org
              - name: corp
                domains:
                  - HOME.EXAMPLE.ORG
        "#,
        "overlaps with domain",
    );
    // Subdomains of another group are fine: longest suffix match wins.
    assert!(
        validate(
            r#"---
            dns-resolver:
              cache:
                groups:
                  - name: home
                    domains:
                      - example.org
                  - name: corp
                    domains:
                      - home.example.org
            "#,
        )
        .is_ok()
    );
}

#[test]
fn test_dns_cache_group_domain_invalid() {
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            groups:
              - name: home
                domains:
                  - ""
        "#,
        "domain cannot be empty",
    );
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            groups:
              - name: home
                domains:
                  - "bad domain"
        "#,
        "Invalid DNS cache group domain",
    );
}

#[test]
fn test_dns_cache_invalid_nameserver() {
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            fallback:
              nameservers:
                - "192.0.2.999"
        "#,
        "Invalid nameserver at dns-resolver.cache.fallback",
    );
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            groups:
              - name: home
                nameservers:
                  - "dns.example.org"
        "#,
        "Invalid nameserver at dns-resolver.cache.groups.home.nameservers",
    );
}

#[test]
fn test_dns_cache_group_without_nameserver_blocks_domain() {
    // An empty nameserver list is the documented way to NXDOMAIN a domain.
    assert!(
        validate(
            r#"---
            dns-resolver:
              cache:
                groups:
                  - name: block-list
                    domains:
                      - ads.example.org
            "#,
        )
        .is_ok()
    );
}

#[test]
fn test_dns_cache_doh_requires_plain_nameservers() {
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            fallback:
              nameservers:
                - "https://dns.example.org/dns-query"
        "#,
        "dns-resolver.cache.doh.nameservers is not defined",
    );
    assert_invalid(
        r#"---
        dns-resolver:
          cache:
            fallback:
              nameservers:
                - "https://dns.example.org/dns-query"
            doh:
              nameservers: []
        "#,
        "must contain at least one plain IP nameserver",
    );
    assert!(
        validate(
            r#"---
            dns-resolver:
              cache:
                fallback:
                  nameservers:
                    - "https://dns.example.org/dns-query"
                doh:
                  nameservers:
                    - 192.0.2.53
            "#,
        )
        .is_ok()
    );
}

#[test]
fn test_dns_resolver_client_server_validation() {
    // Plain IPv4/IPv6 and IPv6 link-local with interface name are accepted,
    // same as `/etc/resolv.conf` supports.
    assert!(
        validate(
            r#"---
            dns-resolver:
              config:
                server:
                  - 192.0.2.53
                  - 2001:db8::53
                  - "fe80::1%eth1"
            "#,
        )
        .is_ok()
    );
    assert_invalid(
        r#"---
        dns-resolver:
          config:
            server:
              - "dns.example.org"
        "#,
        "Invalid DNS server string dns.example.org",
    );
    // A non link-local address cannot carry an interface name.
    assert_invalid(
        r#"---
        dns-resolver:
          config:
            server:
              - "2001:db8::1%eth1"
        "#,
        "Invalid DNS server string",
    );
    // An empty interface name is invalid.
    assert_invalid(
        r#"---
        dns-resolver:
          config:
            server:
              - "fe80::1%"
        "#,
        "Invalid DNS server string",
    );
}

#[test]
fn test_dns_resolver_client_options_validation() {
    assert!(
        validate(
            r#"---
            dns-resolver:
              config:
                options:
                  - trust-ad
                  - rotate
                  - ndots:2
                  - timeout:5
                  - attempts:3
            "#,
        )
        .is_ok()
    );
    // `ndots` requires a value.
    assert_invalid(
        r#"---
        dns-resolver:
          config:
            options:
              - ndots
        "#,
        "Unsupported DNS option ndots",
    );
    // `rotate` does not take a value.
    assert_invalid(
        r#"---
        dns-resolver:
          config:
            options:
              - rotate:1
        "#,
        "not supported to hold a value",
    );
    assert_invalid(
        r#"---
        dns-resolver:
          config:
            options:
              - not-an-option
        "#,
        "Unsupported DNS option not-an-option",
    );
}

#[test]
fn test_dns_resolver_unknown_field_rejected() {
    let result = NetworkState::new_from_yaml(
        "dns-resolver:\n  cache:\n    unknown: 1\n",
    );
    assert!(result.is_err(), "Unknown cache field must be rejected");
    let result = NetworkState::new_from_yaml("dns-resolver:\n  unknown: 1\n");
    assert!(
        result.is_err(),
        "Unknown dns-resolver field must be rejected"
    );
}

#[test]
fn test_dns_resolver_merge_prefers_new_state() {
    let mut old = parse(
        r#"---
        dns-resolver:
          config:
            server:
              - 192.0.2.53
          cache:
            enabled: true
        "#,
    );
    let new = parse(
        r#"---
        dns-resolver:
          running:
            server:
              - 198.51.100.53
        "#,
    );
    old.merge(&new).unwrap();
    // Only the property present in the new state is replaced.
    assert_eq!(
        old.running.as_ref().unwrap().server.as_ref().unwrap(),
        &vec!["198.51.100.53".to_string()]
    );
    assert!(old.config.is_some());
    assert!(old.cache.is_some());

    let empty = DnsResolver::default();
    let mut keep = old.clone();
    keep.merge(&empty).unwrap();
    assert_eq!(keep, old);
}

#[test]
fn test_dns_cache_saved_when_desired_state_omits_dns() {
    let saved = NetworkState::new_from_yaml(
        r#"---
        version: 1
        dns-resolver:
          config:
            server:
              - 127.0.0.1
          cache:
            enabled: true
            bind: "127.0.0.1:53"
        "#,
    )
    .unwrap();
    let desired = NetworkState::new_from_yaml(
        r#"---
        version: 1
        interfaces:
          - name: test-dns0
            type: ethernet
            state: saved
        "#,
    )
    .unwrap();

    let merged = MergedNetworkState::new(
        desired,
        NetworkState::default(),
        Some(saved),
        NipartApplyOption::default(),
    )
    .unwrap();

    let state_to_save = merged.gen_state_for_save();
    let cache = state_to_save.dns_resolver.cache.clone();
    assert!(
        cache.is_some(),
        "DNS cache must survive an apply that omits `dns-resolver`"
    );
    let cache = cache.unwrap();
    assert!(cache.enabled);
    assert_eq!(cache.bind, "127.0.0.1:53");

    // An omitted DNS section must not apply or restart the cache.
    assert!(merged.dns.cache().is_none());
}

#[test]
fn test_dns_resolver_gen_diff_only_keeps_explicit_properties() {
    let old = parse(
        r#"---
        dns-resolver:
          config:
            server:
              - 192.0.2.53
          cache:
            enabled: false
        "#,
    );
    // Desired state only alters `config`: `cache` falls back to the old
    // value and `running` is never part of a desired state.
    let desired = parse(
        r#"---
        dns-resolver:
          config:
            search:
              - example.org
        "#,
    );
    let diff = desired.gen_diff(&old);
    assert!(diff.running.is_none());
    assert_eq!(
        diff.config.as_ref().unwrap().search.as_ref().unwrap(),
        &vec!["example.org".to_string()]
    );
    assert!(!diff.cache.as_ref().unwrap().enabled);
}

#[test]
fn test_dns_upstream_server_parse() {
    assert_eq!(
        DnsUpstreamServer::parse("192.0.2.53").unwrap(),
        DnsUpstreamServer::from_ip("192.0.2.53".parse().unwrap())
    );
    assert_eq!(
        DnsUpstreamServer::parse("192.0.2.53:5353").unwrap(),
        DnsUpstreamServer::Ip {
            addr: "192.0.2.53:5353".parse().unwrap(),
            port_explicit: true,
        }
    );
    assert_eq!(
        DnsUpstreamServer::parse("2001:db8::53").unwrap(),
        DnsUpstreamServer::from_ip("2001:db8::53".parse().unwrap())
    );
    assert_eq!(
        DnsUpstreamServer::parse("[2001:db8::53]:5353").unwrap(),
        DnsUpstreamServer::Ip {
            addr: "[2001:db8::53]:5353".parse().unwrap(),
            port_explicit: true,
        }
    );
    assert_eq!(
        DnsUpstreamServer::parse("[fe80::1%2]:53").unwrap(),
        DnsUpstreamServer::Ip {
            addr: "[fe80::1%2]:53".parse().unwrap(),
            port_explicit: true,
        }
    );
    assert_eq!(
        DnsUpstreamServer::parse("https://dns.example.org/dns-query").unwrap(),
        DnsUpstreamServer::Doh("https://dns.example.org/dns-query".to_string())
    );
    assert!(!DnsUpstreamServer::parse("192.0.2.53").unwrap().is_doh());
    assert!(
        DnsUpstreamServer::parse("https://dns.example.org/dns-query")
            .unwrap()
            .is_doh()
    );
    assert!(DnsUpstreamServer::parse("http://dns.example.org").is_err());
    assert!(DnsUpstreamServer::parse("https://").is_err());
    // Interface name cannot be used as socket scope.
    assert!(DnsUpstreamServer::parse("fe80::1%eth1").is_err());
    assert!(DnsUpstreamServer::parse("[fe80::1%eth1]:53").is_err());
}

/// The string handed to mudz must keep an explicitly configured port and
/// drop an implicit one: mudz treats any port it is given as pinned, which
/// would send the opportunistic DoT probe to 53 instead of 853.
#[test]
fn test_dns_upstream_server_upstream_string() {
    for (input, expected) in [
        ("192.0.2.53", "192.0.2.53"),
        ("2001:db8::53", "2001:db8::53"),
        ("192.0.2.53:5353", "192.0.2.53:5353"),
        ("[2001:db8::53]:5353", "[2001:db8::53]:5353"),
        ("[fe80::1%2]:53", "[fe80::1%2]:53"),
        (
            "https://dns.example.org/dns-query",
            "https://dns.example.org/dns-query",
        ),
    ] {
        assert_eq!(
            DnsUpstreamServer::parse(input).unwrap().to_string(),
            expected,
            "upstream string for {input}"
        );
    }
}

#[test]
fn test_doh_url_hostname() {
    assert_eq!(
        doh_url_hostname("https://dns.example.org/dns-query"),
        Some("dns.example.org".to_string())
    );
    // Lowercased, port and userinfo stripped.
    assert_eq!(
        doh_url_hostname("https://DNS.Example.ORG:443/dns-query"),
        Some("dns.example.org".to_string())
    );
    assert_eq!(
        doh_url_hostname("https://user@dns.example.org/dns-query"),
        Some("dns.example.org".to_string())
    );
    // Bracketed IPv6 host.
    assert_eq!(
        doh_url_hostname("https://[2001:db8::1]/dns-query"),
        Some("2001:db8::1".to_string())
    );
    assert_eq!(doh_url_hostname("http://dns.example.org"), None);
    assert_eq!(doh_url_hostname("https:///dns-query"), None);
}

#[test]
fn test_dns_cache_load_etc_hosts_and_ipv6_flags() {
    let dns = parse(
        r#"---
        dns-resolver:
          cache:
            enabled: true
            load-etc-hosts: false
            fallback:
              disable-ipv6: true
            groups:
              - name: corp
                domains:
                  - corp.example.net
                disable-ipv6: true
                nameservers:
                  - 2001:db8::53
        "#,
    );
    let cache = dns.cache.as_ref().unwrap();
    assert!(!cache.load_etc_hosts);
    assert!(cache.fallback.disable_ipv6);
    assert!(cache.groups[0].disable_ipv6);
}

#[test]
fn test_dns_cache_doh_hostnames_collected() {
    let dns = parse(DOC_EXAMPLE_YAML);
    let cache = dns.cache.as_ref().unwrap();
    assert_eq!(
        cache.doh_hostnames(),
        vec!["dns.example.org".to_string(), "doh.example.net".to_string(),]
    );
}

#[test]
fn test_dns_cache_bind_ipv6_address() {
    let dns = parse(
        r#"---
        dns-resolver:
          config:
            server:
              - "::1"
          cache:
            enabled: true
            bind: "[::1]:5353"
        "#,
    );
    let cache = dns.cache.as_ref().unwrap();
    assert_eq!(
        cache.bind_addr().unwrap(),
        "[::1]:5353".parse::<std::net::SocketAddr>().unwrap()
    );
    assert!(
        validate(
            r#"---
            dns-resolver:
              config:
                server:
                  - "::1"
              cache:
                enabled: true
                bind: "[::1]:5353"
            "#,
        )
        .is_ok()
    );
}

#[test]
fn test_dns_cache_bind_non_loopback_is_allowed() {
    // Binding a gateway address is legitimate (container use case), so it
    // must not be rejected.
    assert!(
        validate(
            r#"---
            dns-resolver:
              config:
                server:
                  - 192.0.2.53
              cache:
                enabled: true
                bind: "192.0.2.53:53"
            "#,
        )
        .is_ok()
    );
}

#[test]
fn test_dns_resolver_client_is_empty() {
    use crate::DnsResolverClient;

    assert!(DnsResolverClient::default().is_empty());
    assert!(
        !DnsResolverClient {
            search: Some(vec!["example.org".to_string()]),
            ..Default::default()
        }
        .is_empty()
    );
}

#[test]
fn test_dns_resolver_is_empty() {
    assert!(DnsResolver::default().is_empty());
    assert!(
        !DnsResolver {
            config: Some(crate::DnsResolverClient {
                server: Some(vec![Ipv4Addr::new(192, 0, 2, 53).to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        }
        .is_empty()
    );
    assert!(
        !DnsResolver {
            cache: Some(DnsCacheConfig {
                enabled: true,
                ..Default::default()
            }),
            ..Default::default()
        }
        .is_empty()
    );
    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
    assert_eq!(IpAddr::V6(ipv6).to_string(), "2001:db8::53");
}

/// The `docs/english/features/dns.md` cache example must stay parseable and
/// valid; it is the user facing contract of the cache schema.
#[test]
fn test_dns_cache_doc_example_is_valid() {
    let yaml = r#"---
version: 1
dns-resolver:
  config:
    search:
      - example.org
      - example.net
    server:
      - 127.0.0.1
  cache:
    enabled: true
    bind: "127.0.0.1:53"
    max-cache-size: 4096
    load-etc-hosts: true
    fallback:
      auto-dns: true
      nameservers:
        - "https://dns.example.org/dns-query"
        - "https://doh.example.com/dns-query"
      disable-ipv6: false
    doh:
      nameservers:
        - 198.51.100.53
        - 203.0.113.53
      disable-ipv6: true
    groups:
      - name: home
        domains:
          - sweat.example.org
          - 2.0.192.in-addr.arpa
        nameservers:
          - 192.0.2.1
      - name: corp
        disable-ipv6: true
        domains:
          - rich.example.org
          - 0.51.100.in-addr.arpa
        nameservers:
          - 192.0.2.254
          - 192.0.2.253
"#;
    let state = NetworkState::new_from_yaml(yaml).unwrap();
    state.validate().unwrap();
    let cache = state.dns_resolver.cache.as_ref().unwrap();
    assert!(cache.enabled);
    assert_eq!(cache.max_cache_size, 4096);
    assert_eq!(cache.groups.len(), 2);
    assert!(cache.groups[1].disable_ipv6);
    assert!(cache.doh.is_some());
}
