<!-- vim-markdown-toc GFM -->

* [Interface Monitor and Boot Activation](#interface-monitor-and-boot-activation)
    * [Motivation](#motivation)
    * [Goals](#goals)
    * [Non-Goals](#non-goals)
    * [Design Overview](#design-overview)
    * [Monitor Lifecycle](#monitor-lifecycle)
        * [Started flag and `Start` command](#started-flag-and-start-command)
        * [Initial link dump as a batch](#initial-link-dump-as-a-batch)
        * [Pause/resume during apply](#pauseresume-during-apply)
    * [Boot Activation Via Event Batch](#boot-activation-via-event-batch)
        * [Removing the boot config loader](#removing-the-boot-config-loader)
        * [udev readiness](#udev-readiness)
        * [DHCP client restore](#dhcp-client-restore)
        * [DNS resolver restore](#dns-resolver-restore)
        * [Virtual interfaces and state without a link event](#virtual-interfaces-and-state-without-a-link-event)
        * [wait-online and daemon online state](#wait-online-and-daemon-online-state)
            * [Who drives the online flag](#who-drives-the-online-flag)
        * [Absent NICs and leftover saved state](#absent-nics-and-leftover-saved-state)
    * [WIFI Plugin Activation Gating](#wifi-plugin-activation-gating)
        * [Matching rule](#matching-rule)
        * [New phy and hotplug](#new-phy-and-hotplug)
        * [Link-up applies the wifi-cfg IP stack](#link-up-applies-the-wifi-cfg-ip-stack)
    * [Fallback Reconciliation Query](#fallback-reconciliation-query)
        * [Cadence](#cadence)
        * [Algorithm](#algorithm)
        * [SSID handling](#ssid-handling)
        * [Interaction with the delay queue](#interaction-with-the-delay-queue)
    * [API and Data Structure Changes](#api-and-data-structure-changes)
    * [Code Removals](#code-removals)
    * [Failure Modes](#failure-modes)

<!-- vim-markdown-toc -->

# Interface Monitor and Boot Activation

This document describes the design of the nipart interface monitor and
boot-time activation path. It replaces the ad-hoc boot loader in
`src/daemon/commander.rs` and the mitigations built around it
(`MarkWifiPhysKnown`, `is_stale_link_down_event`).

## Motivation

Today the daemon boot does two independent things:

1. `NipartDaemon::new()` spawns `NipartCommander::load_saved_state()`
   (`src/daemon/commander.rs:91-331`): it pauses the monitor, applies the
   saved state per interface with a NIC-readiness retry loop, restores the
   DNS resolver and DHCP clients, marks applied wifi phys as known and
   resumes the monitor.
2. On resume, the monitor emits a link dump of every interface because
   `paused_state` was captured before any event had been emitted (an empty
   snapshot). The event worker processes each dump event as if it were a
   live event and re-applies the saved config that the boot pass just
   applied.

The second step is the root cause of a family of boot races:

* A wifi-phy that is mid-association is reported carrier-down by the dump;
  the event worker re-applies the phy to the wifi plugin while shuli's
  4-way handshake is in flight, resetting it and paying the retry backoff.
  The `MarkWifiPhysKnown` mitigation (`commander.rs:289-301`,
  `monitor_worker.rs:344-348`) only clears `is_new_wifi_phy`; the down
  event with its auto-connect apply still flows.
* An ethernet NIC that is briefly carrier-down during the dump has its
  routes removed and re-added, restarting DHCP clients.
* The boot path needs a 5-second NIC/udev readiness loop
  (`BOOTUP_NIC_CHECK_*`, `commander.rs:35-36,131-281`), a special
  `restore_saved_dhcp_clients()` for leases that survived the daemon
  restart (`commander.rs:464-545`), and wifi-cfg deferral logic
  (`commander.rs:144-173`) - all because the loader applies state before
  the monitor and plugins are reconciled.

Separately, link state changes are learned only from the netlink multicast
socket. If the kernel socket buffer overflows the notification is lost and
the daemon never reconciles the affected interface.

## Goals

* One activation path: the monitor's view of the current kernel link state
  drives all boot activation, exactly like hotplug does at runtime.
* No event can reach the event worker before the plugins are registered and
  the monitor is explicitly started.
* A transient dump state (mid-association wifi, debounce window, udev
  rename) must never trigger an apply of a state that the daemon is
  already applying.
* Recover from dropped netlink notifications with a periodic
  reconciliation dump.
* Only hand wifi config to the wifi plugin when a wifi NIC is present and
  the saved config actually binds to that NIC.

## Non-Goals

* Changing how `npt apply`, `npt up/down`, `npt wifi` or rollback behave.
  They keep pausing the monitor during their apply.
* Changing shuli's connection logic. The "first auth dropped, then 45 s of
  retransmission/backoff before rescan" issue
  (`shuli/src/lib/client/wifi_iface.rs:716-733`) is a separate fix.
* Replacing netlink with polling. Live notifications stay the primary
  source; the periodic query is only a safety net.

## Design Overview

```
                 NipartCommander::new()
                 plugins spawned and registered
                          |
                          v
   setup_saved_state_monitors(saved, watch_active=true)
   (register iface/mac watches and the wifi monitor, monitor still idle)
                          |
                          v
                 NipartMonitorCmd::Start
                          |
              initial RTM_GETLINK dump
              - seed `emited` and `wifi_phys_emited`
              - collect events into one batch
                          |
                          v
   NipartManagerCmd::LinkEvents { events, boot }
                          |
                          v
   event worker: one desired state -> one apply (monitor paused)
                          |
              +-----------+-------------+
              |                         |
        live netlink events     periodic reconciliation
        (single/batched apply)  (5 s until online, then 30 s)
```

The monitor worker owns all link-state knowledge. The event worker is the
only component that turns a link state into an apply, for boot and runtime
alike.

## Monitor Lifecycle

### Started flag and `Start` command

`NipartMonitorWorker` gets a `started: bool` (initial `false`) and a new
command:

```rust
pub(crate) enum NipartMonitorCmd {
    ...
    /// Begin monitoring: open the netlink session and emit the initial
    /// link dump as one batch. Idempotent.
    Start,
}
```

While `started == false` the worker processes commands but never opens a
netlink session; `should_start_netlink()` additionally requires `started`.
`AddIface`/`AddMacWatch`/`EnableWifiMonitor` therefore register watches
without starting the dump (today they call `resume()` immediately,
`monitor_worker.rs:308-337`).

`NipartMonitorManager` gets `start()` mirroring `pause()`/`resume()`. It is
called by the commander after `setup_saved_state_monitors()` has registered
all watches.

### Initial link dump as a batch

`Start` performs the same RTM_GETLINK dump as `resume()`
(`monitor_worker.rs:668-710`) with two differences:

1. The emitted events are collected into `Vec<InterfaceLinkEvent>` instead
   of being sent one by one, and sent as one
   `NipartManagerCmd::LinkEvents(...)` message when the dump is finished.
2. The dump seeds the tracking state: `notify()` still computes
   `is_new_wifi_phy` and fills `wifi_phys_emited`, so the initial dump both
   announces the pilot phys to the plugin and prevents a later reconcile
   from re-announcing them.

Deleted interfaces (`handle_resume_deleted_ifaces`) are included in the
batch; on the first start there are none because nothing is tracked yet.

`NipartManagerCmd` gains:

```rust
/// A batch of link-state events produced by one dump. The event worker
/// coalesces them into a single apply. `boot` marks the initial
/// daemon-start dump whose apply performs boot activation (`memory_only`
/// and DHCP clients restarted).
LinkEvents { events: Box<[InterfaceLinkEvent]>, boot: bool },
```

### Pause/resume during apply

The event worker pauses the monitor around every apply that it initiates
(boot batch and runtime events), the same way
`apply_network_state_with_saved_config()` does
(`src/daemon/apply.rs:309-322`). Concretely, the batch path must go through
a commander helper that pauses before `apply_merged_state()` and resumes in
all exits, not call `apply_merged_state()` directly like
`event_worker.rs:333` does today.

Because the initial batch is emitted while the monitor is live, its apply
pauses the monitor; the resume dump only emits interfaces whose state
changed during the apply (the `paused_state` comparison already does this,
`monitor_worker.rs:484-490`). For example, a wifi-phy brought up by the
batch is later reported carrier-up with an SSID, and that up event applies
the wifi-cfg IP stack - a genuinely new state, not a duplicate.

## Boot Activation Via Event Batch

### Removing the boot config loader

`NipartCommander::load_saved_state()` and `load_saved_state_inner()` are
removed. `NipartDaemon::new()` no longer spawns the background boot task
(`src/daemon/daemon.rs:103-126`). Boot activation becomes:

```
NipartDaemon::new():
    commander = NipartCommander::new()        # plugins registered
    saved     = conf_manager.query_state()
    remove_manual_activation(&mut saved)      # auto-connect: false stays off
    restore_saved_dns_resolver(&saved)        # userspace-only, see below
    apply_non_nic_saved_state(&saved)         # virtual NICs, global state
    monitor_manager.setup_saved_state_monitors(&saved, true)
    monitor_manager.start()                   # initial batch -> event worker
    ... transaction lock is held until the batch apply finishes
```

The transaction lock currently held by the boot task
(`daemon.rs:103-113`) must be held until the first batch apply completes,
so a client `npt apply` issued right after `npt ping` does not interleave
with boot activation. The lock is released by the event worker / commander
when the initial batch apply finishes (or fails).

Responsibilities of the old loader map to the new design as follows:

| Old loader responsibility | New owner |
|---|---|
| NIC/udev readiness retry loop | per-NIC udev gate in the batch + 5 s reconciliation |
| same-round wifi-phy + wifi-cfg ordering | batch conversion binds wifi-cfg to phys (see below) |
| `memory_only` saved-state semantics | batch apply uses `memory_only` |
| `restore_saved_dhcp_clients()` | `restart_auto_ip` on the boot batch |
| `restore_saved_dns_resolver()` | explicit call before `Start` (DNS is userspace) |
| virtual interfaces and non-NIC saved state | applied directly before `Start` (see below) |
| leftover saved configs for absent NICs | `setup_saved_state_monitors(saved, true)` before `Start` |
| `MarkWifiPhysKnown` | `wifi_phys_emited` seeded by the initial dump |
| `try_set_daemon_online()` | shared `update_daemon_online_state()` (see below) |

### udev readiness

The old loader only applied an interface when the kernel interface matched
the saved config and `udev_net_device_is_initialized(iface_index)` was
true (`commander.rs:697-734`). The udev gate lives in the **monitor** dump
conversion (`handle_resume_event()` during the boot dump and
`reconcile()`), before an event is recorded as emitted:

* An event whose kernel interface is not udev-initialized is not sent and
  not recorded in `emited`/`wifi_phys_emited`. It stays watched
  (`setup_saved_state_monitors`), and either the udev rename/newlink event
  or the 5 s reconciliation emits it again once udev has written the
  record - with `is_new_wifi_phy` still set for a deferred wifi-phy.
* If a NIC is renamed by udev after we already saw it, the rename produces
  a link event and the old name's `emited` entry is reconciled as a
  delete.

This replaces `BOOTUP_NIC_CHECK_MAX_QUICK` / `BOOTUP_NIC_CHECK_INTERVAL_MS_QUICK`.

### DHCP client restore

DHCP clients are daemon-owned processes that die with the daemon, but the
kernel lease and address survive. A plain merge sees no diff and would not
restart them. The boot batch therefore applies with
`NipartApplyOption::restart_auto_ip()`, and the DHCP managers were
extended so that option also iterates interfaces whose kernel state did
**not** change: an unchanged interface with DHCP enabled has its client
stopped and started again instead of being skipped. Unchanged non-DHCP
interfaces are never stopped. This replaces
`restore_saved_dhcp_clients()`.

Notes:

* Only the first batch (boot) sets `restart_auto_ip`; hotplug applies do
  not need it and must not restart unrelated clients.
* The wifi-cfg `wait_wifi_ssid()` path (`dhcp/mod.rs:170-223`) is not
  affected: wifi-cfg is userspace-only and its DHCP starts from the
  SSID link-up event, not from this batch.

### DNS resolver restore

The DNS resolver is not kernel link state and is not rebuilt by an event
apply when the kernel-side state already matches. Keep the explicit
`restore_saved_dns_resolver()` call before `Start`, exactly as the loader
did (`commander.rs:111-122`), including the rule that only nipart's own
static servers and the cache bind address are rewritten while dynamic
nameservers are preserved.

`apply_dns()` inside the batch apply still handles a diff when the saved
DNS config changed while the daemon was down.

### Virtual interfaces and state without a link event

Some saved state is not attached to a kernel NIC and therefore cannot be
triggered by a link event:

* virtual interfaces created by nipart (bond, VLAN, Linux bridge, veth,
  vxlan, wireguard, ...): they exist only because an apply created them,
  and no link event will ever ask the event worker to recreate them;
* routes without `next-hop-interface` (e.g. blackhole/unreachable routes,
  or routes installed without an egress NIC);
* route rules, which match addresses, ports or firewall marks, not a link;
* the static DNS resolver configuration (nameservers, search list,
  options and the DNS cache), restored by `restore_saved_dns_resolver()`
  above;
* the system hostname, when managed by nipart, which also has no link
  event.

The daemon applies this state directly during boot, before the monitor
is started, so the initial link dump already sees the virtual interfaces
created and the global state installed. None of it is part of the
event-driven activation batch.

Physical interfaces, including wifi, keep the single event-driven path.

### wait-online and daemon online state

`DAEMON_IS_ONLINE` is a one-shot latch by contract: the schema documents
that once the daemon reaches online it stops tracking whether the
conditions still hold (`src/lib/schema/wait_online.rs:12-18`), matching
`systemd`'s `network-online.target` semantics. The flag therefore never
needs to be *cleared*.

#### Who drives the online flag

A single shared helper, `update_daemon_online_state()`, owns the flag
(`wait_online.rs`). Every daemon path that can change the network online
state (`npt apply`, `npt up/down`, `npt wifi on/off`, ...) or that notices
it calls the helper:

* the event worker after every batch or live apply, with the post-apply
  state;
* the DHCP manager notifications `DhcpV4LeaseApplied` and `GatewayChanged`
  (`daemon.rs:29-40`), which install a lease or default route without a
  link event;
* the monitor reconcile pass while the flag is unset (5 s cadence, below):
  it always sends a batch (possibly empty), and the event worker's helper
  call re-evaluates the conditions - the guaranteed driver when both
  netlink and the manager notifications are lost.

The helper re-queries the saved `wait-online` conditions and the current
network state (`NipartWaitOnlineCondition::is_met()`), latches the flag
when they are met, and returns immediately once the latch is set. `npt
wait-online` stays a waiter, not the evaluator. For a
`saved-config-applied` wait-online condition, no online-state update is
needed after the saved config has been applied.

### Absent NICs and leftover saved state

`setup_saved_state_monitors(&saved_state, true)` is called before `Start`,
so:

* saved `identifier: mac-address` configs for absent NICs get MAC watches;
* saved configs for absent kernel-name NICs get iface watches;
* the wifi monitor is enabled when a saved wifi config exists;
* `auto-connect: false` configs are excluded completely: they get no
  iface/MAC watch and no wifi activation, and wait for an explicit
  `npt apply`, `npt up` or `npt wifi` request.

A NIC that appears later is announced by its newlink event (or by
reconciliation) and the event worker applies the saved config. Nothing
needs the boot loader's "leftover saved state" hand-off.

## WIFI Plugin Activation Gating

Today the boot loader force-applies every wifi-cfg profile to the wifi
plugin even when no phy is ready, and the event worker re-sends the whole
saved wifi picture on every new phy. The new rule: the wifi plugin is only
contacted when a link event names a wifi NIC for which at least one saved
wifi config matches.

### Matching rule

A saved wifi config matches a wifi-phy when:

* it is a `wifi-phy` whose saved identifier (kernel name or MAC) matches
  the event's kernel interface, or
* it is a `wifi-cfg` whose `base-iface` is the phy name/kernel name, or
* it is a `wifi-cfg` without `base-iface` (unbound: applies to every
  eligible phy, as `wifi_cfg_phy_names()` already implements,
  `src/plugin-wifi/apply.rs:772-787`).

Configs with `auto-connect: false` are excluded. The result is one
`NetworkState` containing the matching wifi-phy and wifi-cfg entries,
including the full saved network list for that phy (shuli manages all
SSIDs of a phy in one client).

If no config matches, the event is handled without any plugin request:
ethernet and other kernel interfaces keep their normal apply path.

### New phy and hotplug

`is_new_wifi_phy` (set by `notify()` for a phy not in `wifi_phys_emited`)
means the plugin process has not seen this phy: the batch/runtime handler
sends the matching wifi state with `memory_only`, which starts or rebuilds
the shuli client for the phy. A phy that is already known only gets a
plugin request when its own state or the wifi-cfg set actually changed
(e.g. an SSID was added by `npt apply`).

This makes `NipartMonitorCmd::MarkWifiPhysKnown` unnecessary: the initial
dump seeds `wifi_phys_emited` itself, before the batch apply.

### Link-up applies the wifi-cfg IP stack

When a wifi-phy link-up event carries an SSID matching a saved
`wifi-cfg`, the existing `handle_wifi_phy_event()` path
(`event_worker.rs:616-642`) converts the profile into a wifi-phy IP
config. Batch and live events share that code. The batch's wifi gate
determines whether the plugin is contacted at all; the IP part is driven
by the link event.

## Fallback Reconciliation Query

Netlink multicast messages can be lost when the kernel socket buffer
overflows (e.g. a burst of carrier transitions after resume or a driver
reset). The monitor therefore reconciles its tracked state with the
kernel periodically using a full network state query (nispor), which
also carries the wifi SSID.

### Cadence

Two intervals, selected from `DAEMON_IS_ONLINE`:

```rust
/// Reconciliation interval while the daemon has not reached `online`
/// (boot, waiting for link/DHCP).
const RECONCILE_INTERVAL_NOT_ONLINE_SECS: u64 = 5;
/// Reconciliation interval after `online`: only a safety net for dropped
/// netlink messages.
const RECONCILE_INTERVAL_ONLINE_SECS: u64 = 30;
```

`DAEMON_IS_ONLINE` is a `SetOnce` in `src/daemon/daemon.rs:21`; the monitor
worker reads `DAEMON_IS_ONLINE.initialized()`. The 5 s cadence covers the
boot window where the old loader retried every 500 ms for up to 5 s; once
the network is online the query is cheap but unnecessary, hence 30 s.

Reconciliation only runs when `started && manual_pause_count == 0` and the
netlink session is active. It pauses with the monitor; the next interval
restarts after resume.

### Algorithm

`reconcile()` uses a full kernel network state query
(`NipartNoDaemon::query_network_state(NipartQueryOption::running())`),
not the RTM_GETLINK dump used by `resume()`: the link dump carries no
association IEs, while the full query provides the wifi SSID once the
kernel publishes it.

1. Query the full running network state.
2. For every tracked interface (in `iface_monitor_list`, `mac_watch_list`
   or `emited`), build the same `InterfaceLinkEvent` shape the netlink
   path produces: `is_up` from the link state and `ssid` for a wifi-phy.
   An untracked interface is ignored unless its MAC matches a MAC watch.
3. Emit **only changed** interfaces: an interface whose `emited` entry is
   missing or whose `is_same_state()` differs. Changed events go through
   the normal `try_notify()` path (debounce included), so a flapping
   interface is not applied again on every pass; unchanged interfaces are
   never fed into `try_notify()`, because its 5-minute
   `EVENT_EXPIRE_TIME_SEC` rule would re-emit them.
4. For tracked interfaces missing from the state, synthesize delete
   events as `handle_resume_deleted_ifaces()` does
   (`monitor_worker.rs:527-552`), restoring the MAC from the last state so
   a MAC watch still matches.
5. Events emitted immediately are sent as one `LinkEvents { boot: false }`
   batch; debounced down events fire later through the normal delay-queue
   path.

The scheduler in `run()` (`monitor_worker.rs:393-448`) keeps its
delay-queue ticker but caps the next wake-up at the reconciliation
deadline, so an idle monitor does not spin.

### SSID handling

Live association notifications carry the SSID in their IEs and
`parse_link_msg()` extracts it. The initial and resume RTM_GETLINK dumps
carry no association IEs, so their up events reach the event worker with
`ssid = None`; the event worker then polls nispor (10 x 500 ms) and falls
back to the wifi plugin's live (shuli) state
(`event_worker.rs:185-243`) because some drivers do not publish the
associated SSID through nispor in time (commits `efe82fc` "dhcp: query
wifi plugin when waiting for SSID" and `4bfb8be` "monitor: avoid
duplicate up reapplies and spurious DHCP restarts").

`reconcile()` avoids that blind spot: it queries the full network state
(nispor), so a missed association is recovered together with its SSID
once the kernel publishes it. If the query still reports no SSID, the
event worker's nispor retry and plugin fallback apply as usual;
reconciliation itself never queries the plugin.

A rapid down/up flap that both happens and recovers between two
reconciliations can still be missed. Live netlink remains the primary
source; the query only bounds the damage of dropped notifications.

### Interaction with the delay queue

Reconciliation compares against `emited` (the last state actually sent) and
does not feed unchanged events into the 10-second debounce queue
(`DOWN_WAIT_SEC`). A changed down event is debounced through
`try_notify()`; if the reconcile fires meanwhile, the queue entry for the
same interface is replaced by the newer event.

`pause()` keeps the delay queue (it only clears `iface_mac`): an apply's
pause/resume must not drop a down event queued just before it. The resume
link dump sees the state already recorded as down and emits nothing, so
clearing the queue would lose the debounced event permanently. A resume
event for the same interface replaces or removes the queued entry.

## API and Data Structure Changes

| Item | Change | File |
|---|---|---|
| `NipartMonitorCmd::Start` | new | `src/daemon/monitor/monitor_worker.rs` |
| `NipartMonitorWorker::started` | new field | same |
| `should_start_netlink()` | requires `started` | same |
| initial dump collector | `notify()` buffers into a batch | same |
| udev gate | boot dump + reconcile skip NICs without a udev record | same |
| `reconcile()` + interval constants | new; full nispor state query (SSID included) | same |
| `pause()` keeps the delay queue | debounced down events survive an apply | same |
| `NipartMonitorManager::start()` | new | `src/daemon/monitor/monitor_manager.rs` |
| `NipartManagerCmd::LinkEvents { events, boot }` | new | `src/daemon/daemon.rs` |
| `boot_applied` Notify | releases the boot transaction lock after the first batch | same |
| `NipartEventCmd::HandleEvents { events, boot }` | new (replaces `HandleEvent`) | `src/daemon/event/event_worker.rs` |
| `NipartEventManager::handle_events()` | new; `handle_event()` delegates | `src/daemon/event/event_manager.rs` |
| `handle_events()` | folds the whole batch in one loop, one apply | `src/daemon/event/event_worker.rs` |
| `gen_wifi_plugin_state_for_phy()` | replaces `gen_wifi_plugin_state()`; per-phy gating | same |
| `boot_apply()` | replaces `load_saved_state()` | `src/daemon/commander.rs` |
| `gen_non_nic_state()` | virtual ifaces + global routes/rules | same |
| `update_daemon_online_state()` | shared one-shot online latch update | `src/daemon/wait_online.rs` |
| `restart_auto_ip` on unchanged ifaces | DHCP managers restart clients with no kernel diff | `src/daemon/dhcp/dhcp*_manager.rs` |

## Code Removals

* `NipartCommander::load_saved_state()` / `load_saved_state_inner()`
  (`commander.rs:91-331`) and the spawn in `daemon.rs:103-126`.
* `NipartCommander::restore_saved_dhcp_clients()` (`commander.rs:464-545`)
  once `restart_auto_ip` covers the daemon-restart case.
* `NipartMonitorCmd::MarkWifiPhysKnown` and
  `NipartMonitorManager::mark_wifi_phys_known()`
  (`monitor_worker.rs:344-348`, `monitor_manager.rs:294-309`).
* `BOOTUP_NIC_CHECK_MAX_QUICK` / `BOOTUP_NIC_CHECK_INTERVAL_MS_QUICK`
  (`commander.rs:35-36`).
* Evaluate `is_stale_link_down_event()` (`event_worker.rs:390-399`): keep
  it only if queued live down events during an apply still need it; the
  batch and reconcile comparisons should make it redundant.

## Failure Modes

* **Plugin slow to register**: `NipartCommander::new()` already waits for
  every plugin socket to answer (bounded retry loop,
  `plugin_worker.rs:118-128`), so `Start` is only issued with the plugins
  it found; a plugin that never answers is treated as absent, as today.
  A plugin that dies later is handled by the existing plugin error paths,
  not by boot ordering.
* **Batch apply fails partially**: the event worker must log and continue
  with the interfaces that did apply, then mark the daemon online only for
  the states that verified it, same as today's boot loader
  (`commander.rs:203-235`). The failed interfaces stay watched and are
  retried by reconciliation.
* **Daemon restart on a live wifi association**: the wifi plugin is a
  fresh process after a daemon restart, so WIFI is always started from
  scratch; there is no special adoption of the kernel association. The
  initial batch treats the restart as a normal boot: it hands the saved
  profiles to the plugin and shuli scans/connects. A future quick-boot
  file (`wifi_quick_boot.yml`, see [plan.md](plan.md)) may shorten this.
* **Reconciliation storm**: a flapping interface produces at most one
  batch per interval; the 10 s `DOWN_WAIT_SEC` debounce still applies to
  live events.
* **Transaction lock never released**: `npt apply`, `npt up`, `npt wifi
  up` and similar requests issued while the first batch runs wait on the
  apply lock (they are not rejected). If the batch apply hangs, clients
  block; the lock must be released on every exit path of the first batch
  (including `Start` dump failure), with a log on failure.

