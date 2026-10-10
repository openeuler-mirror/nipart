<!-- vim-markdown-toc GFM -->

* [接口监视器与启动激活](#接口监视器与启动激活)
    * [背景与动机](#背景与动机)
    * [目标](#目标)
    * [非目标](#非目标)
    * [设计概览](#设计概览)
    * [监视器生命周期](#监视器生命周期)
        * [`started` 标志与 `Start` 命令](#started-标志与-start-命令)
        * [初始链路转储作为一个批次](#初始链路转储作为一个批次)
        * [应用期间暂停/恢复](#应用期间暂停恢复)
    * [通过事件批次进行启动激活](#通过事件批次进行启动激活)
        * [移除启动配置加载器](#移除启动配置加载器)
        * [udev 就绪](#udev-就绪)
        * [DHCP 客户端恢复](#dhcp-客户端恢复)
        * [DNS resolver 恢复](#dns-resolver-恢复)
        * [虚拟接口与没有链路事件的状态](#虚拟接口与没有链路事件的状态)
        * [wait-online 与守护进程 online 状态](#wait-online-与守护进程-online-状态)
            * [谁驱动 online 标志](#谁驱动-online-标志)
        * [缺失 NIC 与剩余已保存状态](#缺失-nic-与剩余已保存状态)
    * [WIFI 插件激活门控](#wifi-插件激活门控)
        * [匹配规则](#匹配规则)
        * [新 phy 与热插拔](#新-phy-与热插拔)
        * [链路 up 应用 wifi-cfg IP 栈](#链路-up-应用-wifi-cfg-ip-栈)
    * [兜底对账查询](#兜底对账查询)
        * [节奏](#节奏)
        * [算法](#算法)
        * [SSID 处理](#ssid-处理)
        * [与延迟队列的交互](#与延迟队列的交互)
    * [API 与数据结构变更](#api-与数据结构变更)
    * [代码移除](#代码移除)
    * [故障模式](#故障模式)

<!-- vim-markdown-toc -->

# 接口监视器与启动激活

本文档描述 nipart 接口监视器（interface monitor）与启动期激活路径的
设计。它取代了 `src/daemon/commander.rs` 中临时的启动加载器，以及围绕
它构建的缓解措施（`MarkWifiPhysKnown`、`is_stale_link_down_event`）。

## 背景与动机

目前守护进程启动时会做两件相互独立的事：

1. `NipartDaemon::new()` 派生 `NipartCommander::load_saved_state()`
   （`src/daemon/commander.rs:91-331`）：暂停监视器，按接口逐个应用
   已保存状态（带 NIC 就绪重试循环），恢复 DNS resolver 与 DHCP
   客户端，把已应用的 wifi phy 标记为已知，然后恢复监视器。
2. 恢复时，由于 `paused_state` 是在任何事件发出之前捕获的（空快照），
   监视器会发出所有接口的链路转储（link dump）。事件 worker 把每个
   转储事件当作实时事件处理，重新应用启动流程刚刚应用过的已保存配置。

第二步是一系列启动期竞态的根因：

* 处于关联过程中的 wifi-phy 会被转储报告为 carrier-down；事件 worker
  在 shuli 的 4 次握手（4-way handshake）进行中把该 phy 重新下发给
  wifi 插件，导致握手中断并付出重试退避的代价。`MarkWifiPhysKnown`
  缓解措施（`commander.rs:289-301`、`monitor_worker.rs:344-348`）只清除
  `is_new_wifi_phy`；带 auto-connect 应用的 down 事件仍会继续流动。
* 在转储期间短暂 carrier-down 的以太网 NIC 会被删除路由再重新添加，
  导致 DHCP 客户端重启。
* 启动路径需要一个 5 秒的 NIC/udev 就绪循环（`BOOTUP_NIC_CHECK_*`、
  `commander.rs:35-36,131-281`）、一个专门处理守护进程重启后仍存活的
  租约的 `restore_saved_dhcp_clients()`（`commander.rs:464-545`），以及
  wifi-cfg 延迟应用逻辑（`commander.rs:144-173`）—— 这些都是因为加载器
  在监视器与插件完成对账（reconcile）之前就应用状态。

另外，链路状态变化只通过 netlink 组播 socket 获知。如果内核 socket
缓冲区溢出，通知就会丢失，守护进程再也不会对受影响的接口进行对账。

## 目标

* 单一激活路径：由监视器观察到的当前内核链路状态驱动所有启动激活，
  与运行期热插拔完全一致。
* 在插件完成注册并且监视器被显式启动之前，任何事件都不能到达事件
  worker。
* 瞬时转储状态（关联中的 wifi、去抖窗口、udev 重命名）绝不能触发对
  守护进程正在应用的状态的重复应用。
* 通过周期性对账查询，从丢失的 netlink 通知中恢复。
* 仅当 wifi NIC 存在且已保存配置确实绑定到该 NIC 时，才把 wifi 配置
  下发给 wifi 插件。

## 非目标

* 不改变 `npt apply`、`npt up/down`、`npt wifi` 或回滚（rollback）的
  行为。它们在应用期间仍然暂停监视器。
* 不改变 shuli 的连接逻辑。"首次认证被丢弃，随后 45 秒重传/退避后才
  重新扫描"的问题（`shuli/src/lib/client/wifi_iface.rs:716-733`）是独立
  的修复。
* 不以轮询取代 netlink。实时通知仍是主要来源；周期查询只是安全网。

## 设计概览

```
                 NipartCommander::new()
                 插件启动并完成注册
                          |
                          v
   setup_saved_state_monitors(saved, watch_active=true)
   （注册 iface/mac 监视与 wifi 监视，监视器仍处于空闲）
                          |
                          v
                 NipartMonitorCmd::Start
                          |
              初始 RTM_GETLINK 转储
              - 初始化 `emited` 与 `wifi_phys_emited`
              - 把事件收集为一个批次
                          |
                          v
   NipartManagerCmd::LinkEvents { events, boot }
                          |
                          v
   事件 worker：一个期望状态 -> 一次应用（监视器已暂停）
                          |
              +-----------+-------------+
              |                         |
        实时 netlink 事件          周期性对账
        （单事件/批次应用）        （online 前 5 秒，之后 30 秒）
```

监视器 worker 拥有全部链路状态知识。事件 worker 是唯一把链路状态
转化为应用的组件，启动与运行期皆然。

## 监视器生命周期

### `started` 标志与 `Start` 命令

`NipartMonitorWorker` 新增 `started: bool`（初始为 `false`）以及一个
新命令：

```rust
pub(crate) enum NipartMonitorCmd {
    ...
    /// 开始监视：打开 netlink 会话并把初始链路转储作为一个批次发出。
    /// 幂等。
    Start,
}
```

当 `started == false` 时，worker 会处理命令但绝不打开 netlink 会话；
`should_start_netlink()` 额外要求 `started`。因此
`AddIface`/`AddMacWatch`/`EnableWifiMonitor` 只注册监视对象，不会启动
转储（当前实现会立即调用 `resume()`，`monitor_worker.rs:308-337`）。

`NipartMonitorManager` 新增 `start()`，与 `pause()`/`resume()` 对应。
commander 在 `setup_saved_state_monitors()` 注册完所有监视对象之后
调用它。

### 初始链路转储作为一个批次

`Start` 执行与 `resume()` 相同的 RTM_GETLINK 转储
（`monitor_worker.rs:668-710`），但有两点不同：

1. 发出的事件被收集到 `Vec<InterfaceLinkEvent>` 中，而不是逐个发送；
   转储结束后作为一条 `NipartManagerCmd::LinkEvents(...)` 消息发送。
2. 转储会初始化跟踪状态：`notify()` 仍会计算 `is_new_wifi_phy` 并填充
   `wifi_phys_emited`，因此初始转储既向插件通告物理接口，又避免之后的
   对账再次通告它们。

被删除的接口（`handle_resume_deleted_ifaces`）会包含在批次中；首次启动
时由于尚无任何跟踪状态，因此不存在这类接口。

`NipartManagerCmd` 新增：

```rust
/// 一次转储产生的链路状态事件批次。事件 worker 会把它们合并为一次
/// 应用。`boot` 标记守护进程启动时的初始转储，其应用执行启动激活
/// （`memory_only` 并重启 DHCP 客户端）。
LinkEvents { events: Box<[InterfaceLinkEvent]>, boot: bool },
```

### 应用期间暂停/恢复

事件 worker 在它发起的每次应用前后暂停/恢复监视器（启动批次与运行期
事件），与 `apply_network_state_with_saved_config()` 的做法相同
（`src/daemon/apply.rs:309-322`）。具体来说，批次路径必须经过一个
commander 辅助函数：在 `apply_merged_state()` 之前暂停，并在所有退出
路径上恢复，而不是像当前的 `event_worker.rs:333` 那样直接调用
`apply_merged_state()`。

由于初始批次是在监视器运行时发出的，它的应用会暂停监视器；恢复时的
转储只发出在应用期间状态发生变化的接口（`paused_state` 比较已经实现
了这一点，`monitor_worker.rs:484-490`）。例如，批次拉起的一个
wifi-phy 随后会以带 SSID 的 carrier-up 事件上报，该 up 事件会应用
wifi-cfg 的 IP 栈 —— 这是真正的新状态，而不是重复事件。

### 应用重试

每次应用有两层重试：

* **内层验证重试**重试应用后的状态校验（`apply_merged_state()`，
  `RETRY_COUNT`/`WIFI_RETRY_COUNT` × 500 ms）；
* **顶层应用重试**包裹整个应用（内核、插件、DHCP 与校验），失败后等待
  2 秒重试一次（`src/daemon/apply.rs` 中的 `APPLY_RETRY_MAX = 2`、
  `APPLY_RETRY_INTERVAL_SEC = 2`）。不可重试的错误
  （`ErrorKind::retriable()`：参数非法、不支持、认证/权限失败、Bug 等）
  立即上报。

无守护进程模式（`NipartNoDaemon::apply_network_state()`，
`src/lib/no_daemon/apply.rs`）具有相同的两层重试。

顶层重试仍以可重试错误失败时，事件 worker 会清除失败接口的已发送状态
（`NipartMonitorCmd::ForgetEmitted`），下一次协调会重新发送它们并再次
尝试应用；wifi-phy 的“已知”标记也会被清除，从而再次把保存的 WIFI 配置
交给插件。

即使加载启动状态失败，`boot_apply()` 也会启动监视器，避免守护进程此后
对链路事件失聪；`Start` 是幂等的，在没有监听项时发送空初始批次，因此
启动事务锁一定被释放。守护进程根据初始批次结果打印 "Boot saved state
applied" 或 "Failed to apply boot saved state:"。

## 通过事件批次进行启动激活

### 移除启动配置加载器

`NipartCommander::load_saved_state()` 与 `load_saved_state_inner()` 被
移除。`NipartDaemon::new()` 不再派生后台启动任务
（`src/daemon/daemon.rs:103-126`）。启动激活变为：

```
NipartDaemon::new():
    commander = NipartCommander::new()        # 插件已注册
    saved     = conf_manager.query_state()
    remove_manual_activation(&mut saved)      # auto-connect: false 保持关闭
    restore_saved_dns_resolver(&saved)        # 仅用户空间，见下文
    apply_non_nic_saved_state(&saved)         # 虚拟 NIC、全局状态
    monitor_manager.setup_saved_state_monitors(&saved, true)
    monitor_manager.start()                   # 初始批次 -> 事件 worker
    ... 事务锁保持到批次应用完成
```

当前由启动任务持有的事务锁（`daemon.rs:103-113`）必须持有到第一个
批次应用完成，这样在 `npt ping` 成功后立即发起的客户端 `npt apply`
不会与启动激活交错。事件 worker / commander 在初始批次应用完成
（或失败）时释放该锁。

旧加载器的职责与新设计的对应关系如下：

| 旧加载器职责 | 新归属 |
|---|---|
| NIC/udev 就绪重试循环 | 批次中的逐 NIC udev 门控 + 5 秒对账 |
| 同轮次 wifi-phy 与 wifi-cfg 顺序 | 批次转换把 wifi-cfg 绑定到 phy（见下文） |
| `memory_only` 已保存状态语义 | 批次应用使用 `memory_only` |
| `restore_saved_dhcp_clients()` | 启动批次上的 `restart_auto_ip` |
| `restore_saved_dns_resolver()` | 在 `Start` 之前显式调用（DNS 属于用户空间） |
| 虚拟接口与非 NIC 已保存状态 | 在 `Start` 之前直接应用（见下文） |
| 缺失 NIC 的剩余已保存配置 | `Start` 之前的 `setup_saved_state_monitors(saved, true)` |
| `MarkWifiPhysKnown` | 初始转储初始化 `wifi_phys_emited` |
| `try_set_daemon_online()` | 共享的 `update_daemon_online_state()`（见下文） |

### udev 就绪

旧加载器仅在内核接口与已保存配置匹配且
`udev_net_device_is_initialized(iface_index)` 为真时才应用接口
（`commander.rs:697-734`）。udev 门控位于**监视器**的转储转换中
（启动转储期间的 `handle_resume_event()` 以及对账 `reconcile()`），
在事件被记录为已发出之前生效：

* 内核接口尚未被 udev 初始化的事件不会被发送，也不会记录到
  `emited`/`wifi_phys_emited`。它仍被监视
  （`setup_saved_state_monitors`），udev 的改名/newlink 事件或 5 秒
  对账会在 udev 写入记录后再次发出它 —— 被延迟的 wifi-phy 仍会带上
  `is_new_wifi_phy`。
* 如果 NIC 在我们已经看到它之后才被 udev 改名，改名会产生链路事件，
  旧名称的 `emited` 条目会以删除事件完成对账。

这取代了 `BOOTUP_NIC_CHECK_MAX_QUICK` /
`BOOTUP_NIC_CHECK_INTERVAL_MS_QUICK`。

### DHCP 客户端恢复

DHCP 客户端是守护进程拥有的进程，会随守护进程退出而终止，但内核中的
租约与地址仍然存活。单纯的合并看不到差异，因此不会重启它们。启动批次
因此使用 `NipartApplyOption::restart_auto_ip()` 应用，并且 DHCP manager
已扩展为：该选项还会遍历内核状态**没有**变化的接口：对已启用 DHCP 的
未变化接口，停止并重新启动其客户端，而不是跳过它。未变化的非 DHCP
接口绝不会被停止。这取代了 `restore_saved_dhcp_clients()`。

说明：

* 只有第一个批次（启动）设置 `restart_auto_ip`；热插拔应用不需要它，
  也不能重启无关客户端。
* wifi-cfg 的 `wait_wifi_ssid()` 路径（`dhcp/mod.rs:170-223`）不受影响：
  wifi-cfg 仅存在于用户空间，其 DHCP 从 SSID 链路 up 事件开始，而不是
  从这个批次开始。

### DNS resolver 恢复

DNS resolver 不是内核链路状态，当内核侧状态已匹配时，事件应用不会重建
它。保留在 `Start` 之前显式调用 `restore_saved_dns_resolver()`，与旧
加载器一致（`commander.rs:111-122`），包括以下规则：只重写 nipart 自己
写入的静态服务器与 DNS cache 绑定地址，保留动态获取的 nameserver。

批次应用内部的 `apply_dns()` 仍会在守护进程停机期间已保存 DNS 配置
发生变化时处理差异。

### 虚拟接口与没有链路事件的状态

有些已保存状态不依附于内核 NIC，因此无法由链路事件触发：

* 由 nipart 创建的虚拟接口（bond、VLAN、Linux bridge、veth、vxlan、
  wireguard 等）：它们只因某次 apply 而存在，永远不会有链路事件要求
  事件 worker 重建它们；
* 没有 `next-hop-interface` 的路由（例如 blackhole/unreachable 路由，
  或未指定出口 NIC 的路由）；
* 路由规则（route rules）：它们匹配地址、端口或防火墙标记，而非链路；
* 静态 DNS resolver 配置（nameserver、搜索列表、选项与 DNS cache），
  由上文 `restore_saved_dns_resolver()` 恢复；
* 由 nipart 管理的系统主机名（hostname），它同样没有链路事件。

守护进程在启动时、启动监视器之前直接应用这些状态，因此初始链路转储
已经能看到虚拟接口被创建、全局状态被安装。它们都不属于事件驱动的
激活批次。

在此启动应用中，只有当路由或路由规则的目标虚拟接口当前已存在、或可被
本次应用创建时（对当前内核接口与每个虚拟接口的 parent/ports 做依赖
不动点计算）才会包含它。对无法创建的目标应用路由/规则会失败并回滚整个
启动状态；其余交给事件路径稍后应用。

当虚拟接口的端口（控制器）或 parent（VLAN、VXLAN 等）在启动时不存在
时，事件 worker 会在其稍后出现时创建它：物理接口的链路事件会把缺失的
依赖虚拟接口配置一并放入目标状态，从而创建 bond/bridge/VRF 并接入其
端口，或在 parent 出现后创建 VLAN。端口列表与 parent 的匹配同时使用
内核名、保存的逻辑/内核名与 MAC 地址，因此逻辑名（例如
MAC-identified NIC）也能匹配。

物理接口（包括 wifi）保持单一的事件驱动路径。

### wait-online 与守护进程 online 状态

按照约定，`DAEMON_IS_ONLINE` 是一次性锁存（one-shot latch）：schema
文档说明一旦守护进程进入 online，就停止跟踪条件是否仍然满足
（`src/lib/schema/wait_online.rs:12-18`），这与 `systemd` 的
`network-online.target` 语义一致。因此该标志永远不需要*清除*。

#### 谁驱动 online 标志

一个共享辅助函数 `update_daemon_online_state()` 拥有该标志
（`wait_online.rs`）。所有可能改变网络 online 状态（`npt apply`、
`npt up/down`、`npt wifi on/off` 等）或观察到它的守护进程路径都会调用
该辅助函数：

* 事件 worker 在每次批次或实时应用之后，携带应用后的状态；
* DHCP manager 通知 `DhcpV4LeaseApplied` 与 `GatewayChanged`
  （`daemon.rs:29-40`），它们在没有链路事件的情况下安装租约或默认
  路由；
* 标志未置位时的监视器对账（5 秒节奏，见下文）：它总是发送一个批次
  （可能为空），事件 worker 的辅助函数调用会重新评估条件 —— 当
  netlink 与 manager 通知都丢失时，这是有保证的驱动者。

辅助函数会重新查询已保存的 `wait-online` 条件与当前网络状态
（`NipartWaitOnlineCondition::is_met()`），在条件满足时锁存标志，并在
锁存已置位后立即返回。`npt wait-online` 仍然只是等待者，不是评估者。
对于 `saved-config-applied` 类型的 wait-online 条件，在已保存配置应用
之后不需要再更新 online 状态。

### 缺失 NIC 与剩余已保存状态

`Start` 之前会调用 `setup_saved_state_monitors(&saved_state, true)`，
因此：

* 缺失 NIC 的 `identifier: mac-address` 已保存配置会获得 MAC 监视；
* 缺失内核名 NIC 的已保存配置会获得接口名监视；
* 存在已保存 wifi 配置时会启用 wifi 监视；
* `auto-connect: false` 的配置被完全排除：不获得接口名/MAC 监视，也不
  会触发 wifi 激活，只等待显式的 `npt apply`、`npt up` 或 `npt wifi`
  请求。

之后出现的 NIC 会通过其 newlink 事件（或对账）被通告，事件 worker 会
应用已保存配置。不再需要旧加载器的"剩余已保存状态"交接。

## WIFI 插件激活门控

当前启动加载器即使在没有 phy 就绪时也会把每个 wifi-cfg 配置强制下发给
wifi 插件，而事件 worker 会在每个新 phy 出现时重发整份已保存 wifi
图景。新规则：只有当链路事件指向的 wifi NIC 至少匹配一个已保存 wifi
配置时，才会联系 wifi 插件。

### 匹配规则

当满足以下条件之一时，一个已保存 wifi 配置匹配某个 wifi-phy：

* 它是一个 `wifi-phy`，且其已保存标识（内核名或 MAC）与事件的内核
  接口匹配；或
* 它是一个 `wifi-cfg`，且其 `base-iface` 是 phy 名称/内核名；或
* 它是一个不带 `base-iface` 的 `wifi-cfg`（未绑定：适用于每个合格
  phy，`wifi_cfg_phy_names()` 已如此实现，
  `src/plugin-wifi/apply.rs:772-787`）。

`auto-connect: false` 的配置会被排除。结果是一个 `NetworkState`，其中
包含匹配的 wifi-phy 与 wifi-cfg 条目，并带上该 phy 的完整已保存网络
列表（shuli 在同一个 client 中管理一个 phy 的所有 SSID）。

如果没有配置匹配，则事件在不产生任何插件请求的情况下被处理：以太网与
其他内核接口保持正常的应用路径。

### 新 phy 与热插拔

`is_new_wifi_phy`（由 `notify()` 对不在 `wifi_phys_emited` 中的 phy
设置）表示插件进程尚未见过该 phy：批次/运行期处理函数会用
`memory_only` 下发匹配的 wifi 状态，从而为该 phy 启动或重建 shuli
client。已经已知的 phy 只在其自身状态或 wifi-cfg 集合确实发生变化时
才产生插件请求（例如 `npt apply` 添加了一个 SSID）。

这使 `NipartMonitorCmd::MarkWifiPhysKnown` 变得不再必要：初始转储在
批次应用之前就自己初始化了 `wifi_phys_emited`。

### 链路 up 应用 wifi-cfg IP 栈

当 wifi-phy 的链路 up 事件携带的 SSID 与某个已保存 `wifi-cfg` 匹配时，
现有的 `handle_wifi_phy_event()` 路径（`event_worker.rs:616-642`）会把
该配置转换为 wifi-phy 的 IP 配置。批次与实时事件共用这段代码。批次的
wifi 门控决定是否联系插件；IP 部分由链路事件驱动。

## 兜底对账查询

当内核 socket 缓冲区溢出时（例如恢复后或驱动复位时的载波状态突变），
netlink 组播消息可能丢失。因此监视器会定期使用完整网络状态查询
（nispor）与内核进行对账，该查询也携带 wifi SSID。

### 节奏

从 `DAEMON_IS_ONLINE` 选择两个间隔之一：

```rust
/// 守护进程尚未进入 `online`（启动中，等待链路/DHCP）时的对账间隔。
const RECONCILE_INTERVAL_NOT_ONLINE_SECS: u64 = 5;
/// 进入 `online` 之后的对账间隔：仅作为丢失 netlink 消息的安全网。
const RECONCILE_INTERVAL_ONLINE_SECS: u64 = 30;
```

`DAEMON_IS_ONLINE` 是 `src/daemon/daemon.rs:21` 中的 `SetOnce`；监视器
worker 读取 `DAEMON_IS_ONLINE.initialized()`。5 秒节奏覆盖了旧加载器
每 500 毫秒重试、最长 5 秒的启动窗口；网络进入 online 后查询虽然便宜
但不再必要，因此为 30 秒。

对账仅在 `started && manual_pause_count == 0` 且 netlink 会话活跃时
运行。它随监视器一起暂停；下一次间隔在恢复后重新开始。

### 算法

`reconcile()` 使用完整内核网络状态查询
（`NipartNoDaemon::query_network_state(NipartQueryOption::running())`），
而不是 `resume()` 使用的 RTM_GETLINK 转储：链路转储不携带关联 IE，
而完整查询在内核发布后即可提供 wifi SSID。

1. 查询完整的运行中网络状态。
2. 对每个被跟踪的接口（位于 `iface_monitor_list`、`mac_watch_list` 或
   `emited`），构造与 netlink 路径相同形态的 `InterfaceLinkEvent`：
   `link-state: up` 与 `link-state: dormant`（载波已起、等待认证器）
   视为 up，无载波的虚拟链路（`link-state: unknown`）在管理上 up 时
   视为 up；wifi-phy 得到 `ssid`。未被跟踪的接口会被忽略，除非其 MAC
   匹配某个 MAC 监视。
3. **只发出发生变化的**接口：`emited` 中没有条目或其
   `is_same_state()` 不同的接口。变化的事件走正常的 `try_notify()`
   路径（包含去抖），因此抖动的接口不会在每一轮都被重新应用；未变化
   的接口绝不会送入 `try_notify()`，否则其 5 分钟的
   `EVENT_EXPIRE_TIME_SEC` 规则会把它们重新发出。
4. 对状态中缺失的被跟踪接口，像
   `handle_resume_deleted_ifaces()` 那样合成删除事件
   （`monitor_worker.rs:527-552`），并从最后状态恢复 MAC，使 MAC 监视
   仍能匹配。接口存在但已不再被关注时不会报告为消失，而是直接丢弃其
   过期跟踪记录，避免每轮重试一个无人关注的删除事件。
5. 立即发出的事件作为一个 `LinkEvents { boot: false }` 批次发送；
   被去抖的 down 事件稍后通过正常的延迟队列路径触发。

应用失败会由协调重试驱动：事件 worker 在可重试错误上放弃后，会对失败
接口调用 `NipartMonitorCmd::ForgetEmitted`，下一轮协调便会重新发出它们
（第 3 步）并再次尝试应用；wifi-phy 会被重新宣告为 new，从而把保存的
WIFI 配置再次发送给插件。

`run()` 中的调度器（`monitor_worker.rs:393-448`）保留其延迟队列 tick，
但把下一次唤醒时间上限压到对账截止时间，因此空闲监视器不会空转。

### SSID 处理

实时关联通知在其 IE 中携带 SSID，`parse_link_msg()` 会提取它。初始与
resume 的 RTM_GETLINK 转储不携带关联 IE，因此它们的 up 事件以
`ssid = None` 到达事件 worker；事件 worker 随后轮询 nispor
（10 次 × 500 毫秒），并回退到 wifi 插件的实时（shuli）状态
（`event_worker.rs:185-243`），因为某些驱动不会及时通过 nispor 发布
关联 SSID（提交 `efe82fc` "dhcp: query wifi plugin when waiting for
SSID" 与 `4bfb8be` "monitor: avoid duplicate up reapplies and spurious
DHCP restarts"）。

`reconcile()` 避免了该盲区：它查询完整网络状态（nispor），因此一旦
内核发布 SSID，丢失的关联会连同其 SSID 一起被恢复。如果查询仍然没有
SSID，事件 worker 的 nispor 重试与插件回退照常生效；对账本身从不查询
插件。

发生在两次对账之间并且已经恢复的快速 down/up 抖动仍可能被漏掉。
实时 netlink 仍是主要来源；查询只是限制丢失通知造成的损害。

### 与延迟队列的交互

对账与 `emited`（最后一次实际发出的状态）比较，不会把未变化事件送入
10 秒去抖队列（`DOWN_WAIT_SEC`）。变化的 down 事件经 `try_notify()`
去抖；如果期间对账触发，该接口的队列条目会被更新的事件替换。

`pause()` 保留延迟队列（只清除 `iface_mac`）：一次 apply 的暂停/恢复
绝不能丢弃恰好在它之前入队的 down 事件。恢复时的链路转储看到状态已经
被记录为 down 而不发出任何事件，因此清空队列会永久丢失被去抖的事件。
同一接口的 resume 事件会替换或移除队列条目。

## API 与数据结构变更

| 项 | 变更 | 文件 |
|---|---|---|
| `NipartMonitorCmd::Start` | 新增 | `src/daemon/monitor/monitor_worker.rs` |
| `NipartMonitorWorker::started` | 新增字段 | 同上 |
| `should_start_netlink()` | 需要 `started` | 同上 |
| 初始转储收集器 | `notify()` 缓冲为一个批次 | 同上 |
| udev 门控 | 启动转储 + 对账跳过没有 udev 记录的 NIC | 同上 |
| `reconcile()` + 间隔常量 | 新增；完整 nispor 状态查询（含 SSID） | 同上 |
| `pause()` 保留延迟队列 | 被去抖的 down 事件在 apply 后仍存活 | 同上 |
| `NipartMonitorManager::start()` | 新增 | `src/daemon/monitor/monitor_manager.rs` |
| `NipartManagerCmd::LinkEvents { events, boot }` | 新增 | `src/daemon/daemon.rs` |
| `boot_applied` Notify | 第一批次后释放启动事务锁 | 同上 |
| `NipartEventCmd::HandleEvents { events, boot }` | 新增（取代 `HandleEvent`） | `src/daemon/event/event_worker.rs` |
| `NipartEventManager::handle_events()` | 新增；`handle_event()` 委托给它 | `src/daemon/event/event_manager.rs` |
| `handle_events()` | 在一个循环中折叠整个批次，只应用一次 | `src/daemon/event/event_worker.rs` |
| `gen_wifi_plugin_state_for_phy()` | 取代 `gen_wifi_plugin_state()`；按 phy 门控 | 同上 |
| `boot_apply()` | 取代 `load_saved_state()` | `src/daemon/commander.rs` |
| `gen_non_nic_state()` | 虚拟接口 + 全局路由/规则 | 同上 |
| `update_daemon_online_state()` | 共享的一次性 online 锁存更新 | `src/daemon/wait_online.rs` |
| 未变化接口上的 `restart_auto_ip` | DHCP manager 为无内核差异的接口重启客户端 | `src/daemon/dhcp/dhcp*_manager.rs` |
| 顶层应用重试 | 可重试错误等 2 秒重试一次 | `src/daemon/apply.rs`、`src/lib/no_daemon/apply.rs` |
| `ErrorKind::retriable()` | 按错误类型决定重试策略 | `src/lib/error.rs` |
| `gen_non_nic_state()` 依赖不动点 | 只保留可创建虚拟接口的路由/规则 | `src/daemon/commander.rs` |
| `gen_missing_virtual_dependents()` | 端口/parent 事件创建缺失的虚拟接口 | `src/daemon/event/event_worker.rs` |
| `NipartMonitorCmd::ForgetEmitted` | 失败接口由对账重新发出 | `src/daemon/monitor/monitor_worker.rs` |

## 代码移除

* `NipartCommander::load_saved_state()` / `load_saved_state_inner()`
  （`commander.rs:91-331`）以及 `daemon.rs:103-126` 中的派生任务。
* `NipartCommander::restore_saved_dhcp_clients()`（`commander.rs:464-545`），
  因为 `restart_auto_ip` 已覆盖守护进程重启场景。
* `NipartMonitorCmd::MarkWifiPhysKnown` 与
  `NipartMonitorManager::mark_wifi_phys_known()`
  （`monitor_worker.rs:344-348`、`monitor_manager.rs:294-309`）。
* `BOOTUP_NIC_CHECK_MAX_QUICK` / `BOOTUP_NIC_CHECK_INTERVAL_MS_QUICK`
  （`commander.rs:35-36`）。
* 保留 `is_stale_link_down_event()`（`event_worker.rs:390-399`）：应用
  期间排队的实时 down 事件仍需要它。它现在把当前 `dormant` 链路状态
  视为 up，与实时 netlink 路径一致。

## 故障模式

* **插件注册缓慢**：`NipartCommander::new()` 已经等待每个插件 socket
  应答（有界重试循环，`plugin_worker.rs:118-128`），因此 `Start` 只在
  已发现的插件就绪时发出；始终不应答的插件会像今天一样被视为不存在。
  之后死亡的插件由现有的插件错误路径处理，而不是由启动顺序处理。
* **批次应用部分失败**：事件 worker 记录失败，顶层重试会把整个应用
  再运行一次。若仍以可重试错误失败，则清除失败接口的已发送状态，使
  下一轮对账重新发出它们并重试应用；不可重试的错误直接上报，不重试。
* **守护进程在已连接的 wifi 关联上重启**：守护进程重启后 wifi 插件是
  全新进程，因此 WIFI 总是从头开始；不存在对内核关联的特殊接管。初始
  批次把重启当作普通启动：把已保存配置交给插件，由 shuli 扫描/连接。
  未来的快速启动文件（`wifi_quick_boot.yml`，见 [plan.md](plan.md)）
  可能缩短这一过程。
* **对账风暴**：抖动的接口每个间隔最多产生一个批次；10 秒的
  `DOWN_WAIT_SEC` 去抖仍适用于实时事件。
* **事务锁永不释放**：在第一批次运行期间发出的 `npt apply`、`npt up`、
  `npt wifi up` 等请求会等待应用锁（不会被拒绝）。如果批次应用挂起，
  客户端会阻塞；锁必须在第一批次的每个退出路径（包括 `Start` 转储
  失败）上释放，并在失败时记录日志。
