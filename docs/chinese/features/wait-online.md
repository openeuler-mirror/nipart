<!-- vim-markdown-toc GFM -->

* [网络就绪等待](#网络就绪等待)
    * [配置](#配置)
    * [行为](#行为)
    * [有效条件](#有效条件)

<!-- vim-markdown-toc -->

# 网络就绪等待

`npt wait-online` 等待 `nipart` 配置网络并达到 `online` 状态。
供 `nipart-wait-online.service` 用于 systemd 的 `network-online.target`。

## 配置

```yaml
wait-online:
  timeout-sec: 30
  conditions:
  - gateway4
  - gateway6
```


`wait-online` 不使用部分更新——如果定义了，会覆盖之前的任何配置。
要保留现有设置，请使用之前保存的配置。

## 行为

* 当所有条件都满足时，守护进程认为网络已在线，`npt wait-online` 以状态码 0 退出。
* 默认网关只有在它出口的接口链路可用时才有效：链路（例如 wifi）断开后静态默认
  路由可能仍留在内核中，不能将其误判为网络已在线。无 carrier 的虚拟链路
  （隧道、wireguard、dummy 等）只要处于 up 状态即视为可用。
* 超时时，`npt wait-online` 以状态码 124 退出（与 `/usr/bin/timeout` 一致）。
* 一旦守护进程达到在线状态，将停止跟踪后续的网络变更，**不会**重新检查条件
  是否仍然满足。

## 有效条件

| 条件 | 描述 |
|---|---|
| `saved-config-applied` | 所有已保存的配置已应用（不包括条件操作） |
| `gateway` | 链路可用的接口上存在 IPv4 或 IPv6 默认网关 |
| `gateway4` | 链路可用的接口上存在 IPv4 默认网关 |
| `gateway6` | 链路可用的接口上存在 IPv6 默认网关 |

