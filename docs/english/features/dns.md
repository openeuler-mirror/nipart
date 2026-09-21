<!-- vim-markdown-toc GFM -->

* [DNS resolver](#dns-resolver)
    * [Standard DNS resolver](#standard-dns-resolver)
    * [Cached DNS](#cached-dns)

<!-- vim-markdown-toc -->

# DNS resolver

Nipart supports two types of DNS resolver:
 * Standard DNS resolver: modifying `/etc/resolv.conf` directly
 * Cached DNS resolver: nipart start DNS cache thread and redirect DNS query to
   different DNS name servers based on configurations

## Standard DNS resolver

Example YAML of static DNS resolver:

```yaml
version: 1
dns-resolver:
  running:
     search:
     - example.org
     - example.net
     server:
     - 2001:db8:1::250
     - 192.0.2.250
     options:
     - trust-ad
     - rotate
  config:
     search:
     - example.org
     - example.net
     server:
     - 2001:db8:1::250
     - 192.0.2.250
     options:
     - trust-ad
     - rotate
```

The `running` section holds DNS config of current host, it could be
the combination of static DNS config and dynamic DNS configuration learn from
DHCP or IPv6-RA.
The `config` section holds the static configuration, when using with
`auto-dns: true`, static DNS configuration is appended to dynamic ones.

## Cached DNS

Example YAML of cached DNS:
 1. Use DoH of `dns.example.org` and `doh.example.com` as fallback DNS
    upstream name server.
 2. Use `198.51.100.53` and `203.0.113.53` to resolve `dns.example.org` and
    `doh.example.com`.
 3. Use `192.0.2.1` to resolve `sweat.example.org` domain.
 4. Use `192.0.2.254` and `192.0.2.253` to resolve `rich.example.org`
    domain.
 5. Domain matching are longest prefix match.


```yaml
version: 1
dns-resolver:
  config:
     search:
       - example.org
       - example.net
     server:
       # will fail if cache enabled and bind address is not first here
       - 127.0.0.1
  cache:
    # default is false, no caching.
    enabled: true
    # which this cache serive should listen to, will bind both UDP/TCP
    bind: "127.0.0.1:53"
    # Maximum number of cached responses. Set to 0 to keep forwarding
    # upstream queries without caching.
    max-cache-size: 4096
    # read /etc/hosts or not, default true
    load-etc-hosts: true
    # fallback is the group of DNS nameservers for unmatched DNS domains query
    fallback:
      # Use nameserver from DHCP, IPv6-RA, VPN etc or not. Default if true.
      auto-dns: true
      nameservers:
        - "https://dns.example.org/dns-query"
        - "https://doh.example.com/dns-query"
      disable-ipv6: false
    # when using DNS-over-Https(DoH), IP nameserver is required to resolve
    # DoH hostname. `doh` section is mandatory when DoH nameserver in use and
    # doh hostnames are not defined in /etc/hosts.
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
```

## Notes

- Every nameserver entry accepts a plain IP address, an `IP:PORT` pair or a
  DNS-over-HTTPS URL (`https://server/dns-query`). A plain IP address uses
  the default DNS port 53.
- When the cache is enabled, its `bind` address must be the first entry of
  `dns-resolver.config.server`, otherwise the host resolver would never
  send a query to the cache. Such an apply is rejected instead of silently
  leaving the cache unused.
- A group with an empty `nameservers` list is a blocking group: matching
  queries get `NXDOMAIN` without any upstream query.
- Domain matching is longest suffix match, so a more specific domain in one
  group wins over a parent domain in another group.
- The cache retries the upstream groups which failed while the previous
  network path was in use when the default gateway changes: a route apply,
  a DHCP lease or the boot-up state restore notifies the cache, so the
  next query probes a previously dead upstream instead of failing fast
  until its retry backoff elapsed. Cached replies are kept.
- The cache is a daemon task. `npt` without the daemon only supports the
  standard resolver (`dns-resolver.config`); a cache configuration needs
  the `nipart` daemon.
