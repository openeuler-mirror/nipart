<!-- vim-markdown-toc GFM -->

* [DNS 解析器](#dns-解析器)
    * [标准 DNS 解析器](#标准-dns-解析器)
    * [缓存 DNS](#缓存-dns)

<!-- vim-markdown-toc -->

# DNS 解析器

Nipart 支持两种类型的 DNS 解析器：
 * 标准 DNS 解析器：直接修改 `/etc/resolv.conf`
 * 缓存 DNS 解析器：nipart 启动 DNS 缓存线程，并根据配置将 DNS 查询转发到
   不同的 DNS 名称服务器

## 标准 DNS 解析器

静态 DNS 解析器的 YAML 示例：

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

`running` 部分保存当前主机的 DNS 配置，它可能是静态 DNS 配置与从 DHCP 或
IPv6-RA 学习到的动态 DNS 配置的组合。

`config` 部分保存静态配置；当与 `auto-dns: true` 一起使用时，静态 DNS 配置
会追加到动态配置之后。

## 缓存 DNS

缓存 DNS 的 YAML 示例：
 1. 使用 `dns.alidns.com` 和 `doh.pub` 的 DoH 作为回退 DNS 上游名称服务器。
 2. 使用 `223.5.5.5` 和 `119.29.29.29` 解析 `dns.alidns.com` 和 `doh.pub`。
 3. 使用 `192.0.2.1` 解析 `sweat.example.org` 域。
 4. 使用 `198.51.100.254` 和 `198.51.100.253` 解析 `rich.example.org`
    域。
 5. 域匹配采用最长前缀匹配。

```yaml
version: 1
dns-resolver:
  config:
     search:
       - example.org
       - example.net
     server:
       # 若启用缓存且绑定地址不是此处的第一项，将报错
       - 127.0.0.1
  cache:
    # 默认为 false，即不缓存。
    enabled: true
    # 此缓存服务监听的地址，将同时绑定 UDP/TCP
    bind: "127.0.0.1:53"
    # 最大缓存条数，设为 0 表示不缓存
    max-cache-size: 1048576
    # 是否读取 /etc/hosts，默认为 true
    load-etc-hosts: true
    # fallback 是未匹配任何 DNS 域的查询所使用的名称服务器组
    fallback:
      # 是否使用来自 DHCP、IPv6-RA、VPN 等的名称服务器。默认为 true。
      auto-dns: true
      nameservers:
        - "https://dns.alidns.com/dns-query"
        - "https://doh.pub/dns-query"
      disable-ipv6: false
    # 使用 DNS-over-HTTPS(DoH) 时，需要 IP 名称服务器来解析 DoH 主机名。
    # 当使用 DoH 名称服务器且其主机名未定义于 /etc/hosts 时，doh 部分是
    # 必填项。
    doh:
      nameservers:
        - 223.5.5.5
        - 119.29.29.29
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
          - 198.51.100.254
          - 198.51.100.253
```
