// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, time::Duration};

use futures_channel::{mpsc::UnboundedReceiver, oneshot::Sender};
use nipart::{
    BaseInterface, ErrorKind, Interface, InterfaceAutoConnect,
    InterfaceIdentifier, InterfaceIpv4, InterfaceIpv6, InterfaceLinkEvent,
    InterfaceLinkState, InterfaceState, InterfaceType, MergedNetworkState,
    NetworkState, NipartApplyOption, NipartError, NipartInterface,
    NipartNoDaemon, NipartQueryOption, RouteEntry, RouteRuleEntry, RouteState,
};

use super::super::{commander::NipartCommander, task::TaskWorker};

// When a wifi-phy up event arrives without SSID (e.g. the kernel does not
// emit the `IFLA_WIRELESS` notification carrying the association IEs), retry
// querying the current state for the SSID before giving up.  This covers the
// window between carrier up and the kernel completing its connect bookkeeping.
const WIFI_SSID_QUERY_RETRY_TIMES: usize = 10;
const WIFI_SSID_QUERY_RETRY_INTERVAL_MS: u64 = 500;

#[derive(Debug, Clone)]
pub(crate) enum NipartEventCmd {
    SetCommander(Box<NipartCommander>),
    /// One or more link-state events from a single dump or a single live
    /// notification.  The worker coalesces them into one apply.  `boot`
    /// marks the initial daemon-start dump whose apply performs boot
    /// activation.
    HandleEvents {
        events: Box<[InterfaceLinkEvent]>,
        boot: bool,
    },
}

impl std::fmt::Display for NipartEventCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetCommander(_) => {
                write!(f, "set-commander")
            }
            Self::HandleEvents { events, boot } => {
                write!(f, "handle-events:{}:boot={boot}", events.len())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NipartEventReply {
    None,
}

type FromManager = (
    NipartEventCmd,
    Sender<Result<NipartEventReply, NipartError>>,
);

#[derive(Debug)]
pub(crate) struct NipartEventWorker {
    receiver: UnboundedReceiver<FromManager>,
    commander: Option<NipartCommander>,
}

impl TaskWorker for NipartEventWorker {
    type Cmd = NipartEventCmd;
    type Reply = NipartEventReply;

    async fn new(
        receiver: UnboundedReceiver<FromManager>,
    ) -> Result<Self, NipartError> {
        Ok(Self {
            receiver,
            commander: None,
        })
    }

    fn receiver(&mut self) -> &mut UnboundedReceiver<FromManager> {
        &mut self.receiver
    }

    async fn process_cmd(
        &mut self,
        cmd: NipartEventCmd,
    ) -> Result<NipartEventReply, NipartError> {
        log::debug!("Processing event command: {cmd}");
        match cmd {
            NipartEventCmd::SetCommander(commander) => {
                self.commander = Some(*commander);
            }
            NipartEventCmd::HandleEvents { events, boot } => {
                if let Err(e) =
                    self.handle_events(events.into_vec(), boot).await
                {
                    log::error!("{e}");
                }
            }
        }
        Ok(NipartEventReply::None)
    }
}

impl NipartEventWorker {
    async fn handle_events(
        &mut self,
        events: Vec<InterfaceLinkEvent>,
        boot: bool,
    ) -> Result<(), NipartError> {
        let Some(commander) = self.commander.as_mut() else {
            return Err(NipartError::new(
                ErrorKind::Bug,
                "NipartEventWorker::handle_events() invoked without commander \
                 set"
                .to_string(),
            ));
        };
        for event in events.iter() {
            log::trace!("Handle link event {event}");
        }
        let event_count = events.len();
        let saved_state = commander.conf_manager.query_state().await?;
        let mut cur_state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;
        // The kernel-only query cannot know about persisted `state: ignore`
        // profiles: mark their NICs as ignored before the merge, otherwise
        // `post_merge_sanitize_wifi()` would bring such a phy up and bind
        // the saved WIFI profiles to it.
        mark_saved_ignored_phys(&mut cur_state, &saved_state);
        let mut desired_state = NetworkState::default();
        let mut rearm_monitors = false;
        // Virtual interfaces already added to `desired_state` because a
        // physical port/parent of them appeared in this batch.  Several
        // events can name ports of the same missing controller.
        let mut added_virtual_dependents: HashSet<String> = HashSet::new();
        // Saved `wifi-cfg` profiles already added to `desired_state` for a
        // newly appeared wifi-phy.  Several events can name the same phy.
        let mut added_wifi_cfgs: HashSet<String> = HashSet::new();

        for mut event in events {
            // Kernel event is always for kernel interface
            let mut cur_iface =
                cur_state.ifaces.kernel_ifaces.get(&event.iface_name);
            // An auto-connect entry for this event's NIC already disables the
            // IP stack on a link-down event, making the standalone purge
            // below redundant.
            let mut auto_connect_covers_ip_purge = false;

            // Skip stale link-down events: when the interface's current link
            // state is already up, a queued down event is a leftover of an
            // earlier transient state (e.g. the device driver initialization
            // burst at boot, or the monitor emitting the link dump on resume).
            // Processing it would purge the IP and routes that the boot apply
            // has just configured, and the later up event does not reliably
            // restore them (the partial merge may drop routes of interfaces
            // that are temporarily IP-disabled).
            if is_stale_link_down_event(&event, cur_iface) {
                log::trace!(
                    "Ignoring stale link-down event {event}: current link \
                     state is up"
                );
                continue;
            }

            // A NIC whose saved config is `state: ignore` is unmanaged: no
            // auto-connect, no WIFI profile handoff, no IP purge.
            if saved_state_ignores_event(&saved_state, &event, &cur_state) {
                log::trace!(
                    "Ignoring event {event}: the interface is marked `state: \
                     ignore`"
                );
                continue;
            }

            if nic_is_gone(&event, cur_iface) {
                // The kernel interface is already gone (delete event, or a
                // link-down event processed after the device disappeared).
                // There is nothing to purge in the kernel, and applying the
                // saved MAC-identified config now would only fail.  Re-arm the
                // saved-profile watches so the config is applied when the same
                // NIC appears again, possibly under a different kernel name
                // (e.g. a USB dock replug).
                log::trace!(
                    "Interface {event} is gone, re-arming saved monitors"
                );
                rearm_monitors = true;
                continue;
            }

            // A new wifi-phy appeared (hotplug or the daemon's initial link
            // dump): add the saved `wifi-cfg` profiles targeting it to this
            // batch so the normal apply path hands them to the wifi plugin.
            // The apply runs the kernel part first (including a rename
            // requested by the saved `wifi-phy` config), hence the plugin
            // receives the post-apply interface name.
            if event.is_new_wifi_phy
                && event.iface_type == InterfaceType::WifiPhy
            {
                for wifi_cfg in
                    gen_wifi_cfg_for_new_phy(&event.iface_name, &saved_state)
                {
                    let name = wifi_cfg.name().to_string();
                    if added_wifi_cfgs.insert(name.clone()) {
                        log::info!(
                            "Handing saved WIFI config {name} to plugin for \
                             new wifi-phy {}",
                            event.iface_name
                        );
                        desired_state.ifaces.push(wifi_cfg);
                    }
                }
            }

            if let Some(cur_iface) = cur_iface.as_ref() {
                log::trace!("Current interface state: {cur_iface}");
            }

            // A wifi-phy up event may reach us before the kernel has finished
            // publishing the associated SSID (especially on drivers using
            // `NL80211_CMD_ASSOCIATE`).  Retry the query for a short while so
            // the wifi-cfg IP config is not lost just because the first
            // snapshot was taken too early.
            if event.ssid.is_none()
                && event.is_up
                && event.iface_type == InterfaceType::WifiPhy
            {
                for retry_count in 1..=WIFI_SSID_QUERY_RETRY_TIMES {
                    if let Some(ssid) = wifi_phy_ssid(cur_iface) {
                        event.ssid = Some(ssid);
                        break;
                    }
                    if retry_count == WIFI_SSID_QUERY_RETRY_TIMES {
                        log::trace!(
                            "{}: SSID still unavailable after {} attempts",
                            event.iface_name,
                            retry_count
                        );
                        break;
                    }
                    log::trace!(
                        "{}: wifi-phy up without SSID, retrying query \
                         ({retry_count}/{WIFI_SSID_QUERY_RETRY_TIMES})",
                        event.iface_name
                    );
                    tokio::time::sleep(Duration::from_millis(
                        WIFI_SSID_QUERY_RETRY_INTERVAL_MS,
                    ))
                    .await;
                    cur_state = NipartNoDaemon::query_network_state(
                        NipartQueryOption::running(),
                    )
                    .await?;
                    cur_iface =
                        cur_state.ifaces.kernel_ifaces.get(&event.iface_name);
                }
                if event.ssid.is_none() {
                    // nispor still cannot see the SSID although the wifi plugin
                    // may already know from its shuli connection state machine
                    // (e.g. the kernel has not yet published the authorized
                    // station).  Query the plugins and merge their live state.
                    log::trace!(
                        "{}: SSID not visible via nispor, querying wifi plugin",
                        event.iface_name
                    );
                    let plugin_states = commander
                        .plugin_manager
                        .query_network_state(
                            NipartQueryOption::running(),
                            &cur_state,
                        )
                        .await?;
                    for plugin_state in plugin_states {
                        cur_state.merge(&plugin_state)?;
                    }
                    cur_iface =
                        cur_state.ifaces.kernel_ifaces.get(&event.iface_name);
                    if let Some(ssid) = wifi_phy_ssid(cur_iface) {
                        event.ssid = Some(ssid);
                    }
                }
            }

            for saved_iface in saved_state.ifaces.iter() {
                if event.iface_type == InterfaceType::WifiPhy
                    && let Some(new_iface) =
                        handle_wifi_phy_event(&event, saved_iface)
                {
                    log::trace!("Pending apply config: {new_iface}");
                    desired_state.ifaces.push(new_iface);
                    let config_routes =
                        desired_state.routes.config.get_or_insert_default();
                    for route in
                        gen_routes_for_wifi_cfg_up(saved_iface, &saved_state)
                    {
                        log::trace!("Pending apply route {route}");
                        config_routes.push(route);
                    }
                    let config_rules = desired_state
                        .route_rules
                        .config
                        .get_or_insert_default();
                    for rule in
                        gen_route_rules_for_iface_up(saved_iface, &saved_state)
                    {
                        log::trace!("Pending apply route rule {rule}");
                        config_rules.push(rule);
                    }
                }

                // `auto-connect` defaults to `true` when not defined, hence
                // interfaces without `auto-connect` are handled here as well.
                if let Some((new_iface, routes)) = handle_event_auto_connect(
                    &event,
                    saved_iface,
                    &saved_state,
                    &cur_state,
                ) {
                    if auto_connect_targets_event_nic(
                        &new_iface, &event, cur_iface,
                    ) {
                        auto_connect_covers_ip_purge = true;
                    }
                    desired_state.ifaces.push(new_iface);
                    let config_routes =
                        desired_state.routes.config.get_or_insert_default();
                    for route in routes {
                        log::trace!("Pending apply route {route}");
                        config_routes.push(route);
                    }
                    // Route rules only need the interface to exist, not to
                    // have carrier: apply them on a down event too, otherwise
                    // a rule deferred from boot (e.g. `iif: eth0` with the
                    // cable unplugged) would never be installed.
                    let config_rules = desired_state
                        .route_rules
                        .config
                        .get_or_insert_default();
                    for rule in
                        gen_route_rules_for_iface_up(saved_iface, &saved_state)
                    {
                        log::trace!("Pending apply route rule {rule}");
                        config_rules.push(rule);
                    }
                }
            }

            let wifi_phy_purge = gen_wifi_phy_ip_purge(
                &event,
                cur_iface,
                auto_connect_covers_ip_purge,
            );
            let purge_wifi_phy = wifi_phy_purge.is_some();
            if let Some(purge_iface) = wifi_phy_purge {
                log::trace!(
                    "{}: link down on wifi-phy, purging IP stack: \
                     {purge_iface}",
                    event.iface_name
                );
                desired_state.ifaces.push(purge_iface);
            }
            // A WiFi link-down purge must also remove the running routes of
            // the previous connection (e.g. the IPv6 default gateway learned
            // from RA), not only the saved static routes.
            if event.iface_type == InterfaceType::WifiPhy
                && !event.is_up
                && (purge_wifi_phy || auto_connect_covers_ip_purge)
            {
                let running_routes =
                    gen_running_route_purge(&event.iface_name, &cur_state);
                if !running_routes.is_empty() {
                    log::trace!(
                        "{}: link down on wifi-phy, purging running routes: \
                         {running_routes:?}",
                        event.iface_name
                    );
                    desired_state
                        .routes
                        .config
                        .get_or_insert_default()
                        .extend(running_routes);
                }
            }

            // The event may be the first time the kernel interface exists:
            // create the saved virtual interfaces depending on it (a
            // controller whose port it is, a VLAN on top of it, ...).
            for saved_iface in
                gen_missing_virtual_dependents(&event, &saved_state, &cur_state)
            {
                if !added_virtual_dependents
                    .insert(saved_iface.name().to_string())
                {
                    continue;
                }
                log::info!(
                    "Creating saved virtual interface {}/{} because its \
                     parent/port {} appeared",
                    saved_iface.name(),
                    saved_iface.iface_type(),
                    event.iface_name
                );
                let (new_iface, routes) =
                    gen_desired_iface_up(&saved_iface, &saved_state);
                let is_up = new_iface.base_iface().state.is_up();
                desired_state.ifaces.push(new_iface);
                let config_routes =
                    desired_state.routes.config.get_or_insert_default();
                for route in routes {
                    log::trace!("Pending apply route {route}");
                    config_routes.push(route);
                }
                if is_up {
                    let config_rules = desired_state
                        .route_rules
                        .config
                        .get_or_insert_default();
                    for rule in
                        gen_route_rules_for_iface_up(&saved_iface, &saved_state)
                    {
                        log::trace!("Pending apply route rule {rule}");
                        config_rules.push(rule);
                    }
                }
            }
        } // end of the events loop

        if rearm_monitors {
            commander
                .monitor_manager
                .setup_saved_state_monitors(&saved_state, true)
                .await?;
        }

        if !desired_state.is_empty() {
            log::trace!("Applying desired state {desired_state}");
            let opt = if boot {
                NipartApplyOption::new()
                    .no_verify()
                    .memory_only()
                    .restart_auto_ip()
            } else {
                NipartApplyOption::new().no_verify()
            };
            let merged_state =
                MergedNetworkState::new(desired_state, cur_state, None, opt)?;
            // Suppress the monitor during the apply so the self-generated
            // link events cannot re-trigger an apply.
            commander.monitor_manager.pause().await?;
            let apply_result =
                commander.apply_merged_state(None, &merged_state).await;
            let setup_result = if apply_result.is_ok() {
                // The event path applies the saved config directly (no
                // `apply_network_state`), so refresh the monitor setup
                // here: the applied interface gets its kernel-name watch,
                // and a stale MAC watch of an interface that has just
                // become active is dropped.
                commander
                    .monitor_manager
                    .setup_monitor(&merged_state, &saved_state)
                    .await
            } else {
                Ok(())
            };
            commander.monitor_manager.resume().await?;
            if let Err(e) = apply_result {
                // Re-drive a retriable failure from reconciliation: drop the
                // emitted state of the failed interfaces so the next
                // reconcile pass emits them again instead of treating their
                // unchanged link state as already handled.
                if e.kind().retriable() {
                    let retry_ifaces: Vec<String> = merged_state
                        .ifaces
                        .iter()
                        .map(|i| i.merged.kernel_iface_name().to_string())
                        .filter(|name| !name.is_empty())
                        .collect();
                    log::info!(
                        "Apply failed, requesting link events to retry \
                         {retry_ifaces:?}: {e}"
                    );
                    commander
                        .monitor_manager
                        .forget_emitted(&retry_ifaces)
                        .await?;
                }
                return Err(e);
            }
            setup_result?;
        } else {
            log::trace!("No change required for {event_count} event(s)");
        }

        // Shared online-state evaluation: a link or DHCP change may have
        // made the wait-online conditions true without a client apply.
        commander.update_daemon_online_state().await?;

        Ok(())
    }
}

/// Saved `wifi-cfg` profiles which a newly appeared wifi-phy should carry.
///
/// A profile targets the event's phy when its `base-iface` is undefined or
/// empty, or names the phy; a profile bound to another interface is left
/// alone.  Configs with `auto-connect: false` are only activated by an
/// explicit request.
fn gen_wifi_cfg_for_new_phy(
    phy_name: &str,
    saved_state: &NetworkState,
) -> Vec<Interface> {
    saved_state
        .ifaces
        .iter()
        .filter(|iface| match iface {
            Interface::WifiCfg(_) => {
                iface.base_iface().auto_connect.as_ref()
                    != Some(&InterfaceAutoConnect::Manual)
                    && wifi_cfg_base_iface(iface).is_none_or(|base_iface| {
                        base_iface.is_empty() || base_iface == phy_name
                    })
            }
            _ => false,
        })
        .cloned()
        .collect()
}

fn wifi_cfg_base_iface(iface: &Interface) -> Option<&str> {
    match iface {
        Interface::WifiCfg(wifi_iface) => wifi_iface
            .wifi
            .as_ref()
            .and_then(|wifi| wifi.base_iface.as_deref()),
        _ => None,
    }
}

/// Saved virtual interfaces which depend on the event's kernel interface but
/// do not exist in the kernel yet, so the event is the first chance to
/// create them.
///
/// A controller (bond, bridge, VRF, ...) whose port list names the event
/// interface is included when the controller is absent: the port's own saved
/// config carries its `controller`, but that can only attach to an existing
/// controller.  A virtual interface whose parent is the event interface
/// (VLAN, VXLAN, ...) is included the same way, so it is created once its
/// parent exists.
///
/// `auto-connect: false` and `state: absent` configs are never created
/// implicitly.
fn gen_missing_virtual_dependents(
    event: &InterfaceLinkEvent,
    saved_state: &NetworkState,
    cur_state: &NetworkState,
) -> Vec<Interface> {
    let event_names = event_identity_names(event, saved_state, cur_state);
    let mut ret: Vec<Interface> = Vec::new();
    for saved_iface in saved_state.ifaces.iter() {
        if !saved_iface.is_virtual()
            || saved_iface.is_userspace()
            || saved_iface.is_absent()
            || saved_iface.is_ignore()
            || saved_iface.base_iface().auto_connect.as_ref()
                == Some(&InterfaceAutoConnect::Manual)
        {
            continue;
        }
        if !virtual_depends_on_event(
            saved_iface,
            &event_names,
            saved_state,
            cur_state,
            event,
        ) {
            continue;
        }
        if cur_state
            .ifaces
            .kernel_ifaces
            .contains_key(saved_iface.kernel_iface_name())
        {
            continue;
        }
        ret.push(saved_iface.clone());
    }
    ret
}

/// Every saved name identifying the event's kernel interface: the kernel
/// name itself plus the logical/kernel/profile names of the saved interfaces
/// matching the event (by name or MAC address).  A virtual interface
/// referencing its parent/port by a logical name (e.g. a MAC-identified NIC)
/// therefore still matches.
fn event_identity_names(
    event: &InterfaceLinkEvent,
    saved_state: &NetworkState,
    cur_state: &NetworkState,
) -> HashSet<String> {
    let mut ret: HashSet<String> = HashSet::new();
    ret.insert(event.iface_name.clone());
    for saved_iface in saved_state.ifaces.iter() {
        if !saved_iface_matches_event(saved_iface, event, cur_state) {
            continue;
        }
        ret.insert(saved_iface.name().to_string());
        if !saved_iface.kernel_iface_name().is_empty() {
            ret.insert(saved_iface.kernel_iface_name().to_string());
        }
        if let Some(profile) = saved_iface.base_iface().profile_name.as_deref()
        {
            ret.insert(profile.to_string());
        }
    }
    ret
}

/// Whether the saved virtual interface is built on the event's kernel
/// interface: a controller with it in the port list, a controller named by
/// the port's saved `controller` property, or a child (VLAN, VXLAN, ...)
/// whose parent it is.
fn virtual_depends_on_event(
    saved_iface: &Interface,
    event_names: &HashSet<String>,
    saved_state: &NetworkState,
    cur_state: &NetworkState,
    event: &InterfaceLinkEvent,
) -> bool {
    if saved_iface.ports().is_some_and(|ports| {
        ports.iter().any(|port| event_names.contains(*port))
    }) {
        return true;
    }
    // A port may identify its controller while the port's own saved name is
    // a logical one (e.g. a MAC-identified NIC): match those through the
    // port config.
    if saved_state.ifaces.iter().any(|port_iface| {
        port_iface.base_iface().controller.as_deref()
            == Some(saved_iface.name())
            && saved_iface_matches_event(port_iface, event, cur_state)
    }) {
        return true;
    }
    saved_iface
        .parent()
        .is_some_and(|parent| event_names.contains(parent))
}

/// Mark the kernel interfaces matched by a saved `state: ignore` profile as
/// ignored, mirroring the daemon's running query.
fn mark_saved_ignored_phys(
    cur_state: &mut NetworkState,
    saved_state: &NetworkState,
) {
    let ignored_ifaces: Vec<&Interface> = saved_state
        .ifaces
        .iter()
        .filter(|iface| iface.is_ignore())
        .collect();
    if ignored_ifaces.is_empty() {
        return;
    }
    for cur_iface in cur_state.ifaces.kernel_ifaces.values_mut() {
        if ignored_ifaces
            .iter()
            .any(|ignored| ignored.is_match(cur_iface))
        {
            cur_iface.base_iface_mut().state = InterfaceState::Ignore;
        }
    }
}

/// Whether the saved state marks the event's NIC as `state: ignore`.
fn saved_state_ignores_event(
    saved_state: &NetworkState,
    event: &InterfaceLinkEvent,
    cur_state: &NetworkState,
) -> bool {
    saved_state.ifaces.iter().any(|iface| {
        iface.is_ignore() && saved_iface_matches_event(iface, event, cur_state)
    })
}

/// Whether the saved interface is the kernel interface the event reports:
/// same kernel/logical name, or same MAC address for a MAC-identified
/// profile.
fn saved_iface_matches_event(
    iface: &Interface,
    event: &InterfaceLinkEvent,
    cur_state: &NetworkState,
) -> bool {
    if iface.kernel_iface_name() == event.iface_name
        || iface.name() == event.iface_name
    {
        return true;
    }
    if iface.base_iface().identifier != Some(InterfaceIdentifier::MacAddress) {
        return false;
    }
    let Some(saved_mac) = iface.base_iface().mac_address.as_deref() else {
        return false;
    };
    cur_state
        .ifaces
        .kernel_ifaces
        .get(&event.iface_name)
        .and_then(|cur_iface| cur_iface.base_iface().mac_address.as_deref())
        .is_some_and(|cur_mac| cur_mac.eq_ignore_ascii_case(saved_mac))
}

pub(crate) fn is_route_matching_iface(
    rt: &RouteEntry,
    iface: &Interface,
) -> bool {
    match rt.next_hop_iface.as_deref() {
        Some(name) if name == iface.kernel_iface_name() => true,
        Some(name)
            if Some(name) == iface.base_iface().profile_name.as_deref() =>
        {
            true
        }
        Some(name) if name == iface.name() => true,
        _ => false,
    }
}

/// Whether a link-down event is stale, i.e. the interface's current kernel
/// link state is already up so the down event can only be a leftover of an
/// earlier transient state (e.g. the boot-time device initialization burst
/// or the monitor link dump emitted on resume).
///
/// Stale down events must not be processed: doing so purges the IP and
/// routes that the boot apply has just configured, and the subsequent up
/// event does not reliably restore them.
fn is_stale_link_down_event(
    event: &InterfaceLinkEvent,
    cur_iface: Option<&Interface>,
) -> bool {
    !event.is_up
        && !event.is_delete
        && cur_iface.is_some_and(|iface| {
            // `dormant` (carrier up, waiting for a supplicant) is up on the
            // live netlink path (`IFF_LOWER_UP`) and must be treated the
            // same here, otherwise the stale down event would purge the IP
            // stack of a link which is not actually down.
            matches!(
                iface.base_iface().link_state,
                Some(InterfaceLinkState::Up)
                    | Some(InterfaceLinkState::Dormant)
            )
        })
}

/// Whether the kernel interface is gone: either the netlink event is a
/// delete, or the current query no longer contains the interface (e.g. the
/// device was removed before the link-down event was processed).
fn nic_is_gone(
    event: &InterfaceLinkEvent,
    cur_iface: Option<&Interface>,
) -> bool {
    event.is_delete || cur_iface.is_none()
}

/// The SSID of the current kernel wifi-phy, if it is a wifi interface and
/// the kernel already reports the association.
fn wifi_phy_ssid(cur_iface: Option<&Interface>) -> Option<String> {
    cur_iface.and_then(|iface| {
        if let Interface::WifiPhy(wifi_iface) = iface {
            wifi_iface.ssid().map(|s| s.to_string())
        } else {
            None
        }
    })
}

/// Gather saved routes whose next-hop is the given saved interface.
fn gen_routes_for_iface_up(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> Vec<RouteEntry> {
    let mut ret_routes: Vec<RouteEntry> = Vec::new();
    // Include routes to this interface also
    if !saved_iface.is_userspace()
        && let Some(config_rts) = saved_state.routes.config.as_ref()
    {
        for rt in config_rts
            .iter()
            .filter(|rt| is_route_matching_iface(rt, saved_iface))
        {
            ret_routes.push(rt.clone());
        }
    }
    ret_routes
}

/// Gather saved routes whose next-hop is the given `wifi-cfg` profile.
/// The routes are applied when the wifi-phy carrying the profile's SSID
/// comes up; `MergedRoutes` resolves the profile name to that kernel phy.
fn gen_routes_for_wifi_cfg_up(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> Vec<RouteEntry> {
    if saved_iface.iface_type() != &InterfaceType::WifiCfg {
        return Vec::new();
    }
    let Some(config_rts) = saved_state.routes.config.as_ref() else {
        return Vec::new();
    };
    let mut ret_routes: Vec<RouteEntry> = Vec::new();
    for rt in config_rts
        .iter()
        .filter(|rt| is_route_matching_iface(rt, saved_iface))
    {
        ret_routes.push(rt.clone());
    }
    ret_routes
}

/// Gather saved route rules whose `iif` is the given saved interface. The
/// rules are applied when the interface comes up through the event path.
fn gen_route_rules_for_iface_up(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> Vec<RouteRuleEntry> {
    let Some(config_rules) = saved_state.route_rules.config.as_ref() else {
        return Vec::new();
    };
    let mut ret_rules: Vec<RouteRuleEntry> = Vec::new();
    for rule in config_rules.iter().filter(|rule| {
        rule.iif.as_ref().is_some_and(|iif| {
            iif.as_str() == saved_iface.kernel_iface_name()
                || iif.as_str() == saved_iface.name()
                || Some(iif.as_str())
                    == saved_iface.base_iface().profile_name.as_deref()
        })
    }) {
        ret_rules.push(rule.clone());
    }
    ret_rules
}

fn gen_desired_iface_up(
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> (Interface, Vec<RouteEntry>) {
    let mut new_iface = saved_iface.clone();
    new_iface.base_iface_mut().state = InterfaceState::Up;
    new_iface.base_iface_mut().auto_connect = None;

    let ret_routes = gen_routes_for_iface_up(saved_iface, saved_state);

    (new_iface, ret_routes)
}

fn gen_desired_iface_down(
    auto_connect: &InterfaceAutoConnect,
    saved_iface: &Interface,
    saved_state: &NetworkState,
) -> (Interface, Vec<RouteEntry>) {
    let mut new_iface = saved_iface.clone();
    let mut ret_routes: Vec<RouteEntry> = Vec::new();
    // We cannot bring interface down when `auto-connect` is `true`,
    // otherwise that interface will never up again.
    if auto_connect != &InterfaceAutoConnect::AutoConnect
        && saved_iface.iface_type() != &InterfaceType::WifiCfg
    {
        new_iface.base_iface_mut().state = if saved_iface.is_virtual() {
            InterfaceState::Absent
        } else {
            InterfaceState::Down
        };
    }
    new_iface.base_iface_mut().auto_connect = None;
    new_iface.base_iface_mut().ipv4 = Some(InterfaceIpv4::new_disabled());
    // A WiFi link-down purge keeps IPv6 enabled so the kernel-generated
    // link-local address survives; only the addresses and routes learned
    // from the previous connection are removed.
    new_iface.base_iface_mut().ipv6 =
        Some(if saved_iface.iface_type() == &InterfaceType::WifiPhy {
            InterfaceIpv6::new_purge_keep_link_local()
        } else {
            InterfaceIpv6::new_disabled()
        });
    // A link-down purge must not carry the saved SSID back to the wifi
    // plugin: the plugin would treat it as an explicit wifi up request and
    // re-enable WIFI while `npt wifi off` is in effect.
    if let Interface::WifiPhy(wifi_iface) = &mut new_iface {
        wifi_iface.wifi = None;
    }

    // Remove routes to this interface also
    if !new_iface.is_userspace()
        && let Some(config_rts) = saved_state.routes.config.as_ref()
    {
        for rt in config_rts
            .iter()
            .filter(|rt| is_route_matching_iface(rt, saved_iface))
        {
            let mut new_route = rt.clone();
            new_route.state = Some(RouteState::Absent);
            ret_routes.push(new_route);
        }
    }

    (new_iface, ret_routes)
}

fn wifi_cfg_to_wifi_phy(
    iface_name: &str,
    saved_iface: &Interface,
) -> Interface {
    let mut desired = saved_iface.base_iface().clone();
    desired.name = iface_name.to_string();
    desired.kernel_iface_name = iface_name.to_string();
    desired.iface_type = InterfaceType::WifiPhy;
    if desired.profile_name.is_none() {
        desired.profile_name = saved_iface
            .base_iface()
            .profile_name
            .clone()
            .or_else(|| Some(saved_iface.name().to_string()));
    }

    desired.into()
}

fn handle_event_auto_connect(
    event: &InterfaceLinkEvent,
    saved_iface: &Interface,
    saved_state: &NetworkState,
    cur_state: &NetworkState,
) -> Option<(Interface, Vec<RouteEntry>)> {
    // `auto-connect` defaults to `true` when not defined.
    let auto_connect = saved_iface
        .base_iface()
        .auto_connect
        .clone()
        .unwrap_or_default();
    let mut saved_iface = saved_iface.clone();
    saved_iface.base_iface_mut().auto_connect = Some(auto_connect.clone());

    match saved_iface.process_auto_connect(event, &cur_state.ifaces) {
        None => {
            log::trace!("No auto-connect action for {event}");
            None
        }
        Some(false) => {
            let (new_iface, routes) = gen_desired_iface_down(
                &auto_connect,
                &saved_iface,
                saved_state,
            );
            log::trace!(
                "Pending apply action to bring {} down",
                event.iface_name
            );
            if !routes.is_empty() {
                log::trace!("Pending route changes: {routes:?}");
            }
            Some((new_iface, routes))
        }
        Some(true) => {
            let (new_iface, routes) =
                gen_desired_iface_up(&saved_iface, saved_state);
            log::trace!(
                "Pending apply action to bring {} up",
                event.iface_name
            );
            if !routes.is_empty() {
                log::trace!("Pending route changes: {routes:?}");
            }
            Some((new_iface, routes))
        }
    }
}

/// Whether the auto-connect desired state `iface` targets the NIC named by
/// `event`: matched by kernel name or, for MAC-identified configs, by MAC
/// address. Mirrors the matching in
/// [`Interface::process_auto_connect()`].
fn auto_connect_targets_event_nic(
    iface: &Interface,
    event: &InterfaceLinkEvent,
    cur_iface: Option<&Interface>,
) -> bool {
    if iface.kernel_iface_name() == event.iface_name {
        return true;
    }
    let Some(cur_iface) = cur_iface else {
        return false;
    };
    iface.base_iface().identifier == Some(InterfaceIdentifier::MacAddress)
        && iface
            .base_iface()
            .mac_address
            .as_deref()
            .is_some_and(|saved_mac| {
                let saved_mac = saved_mac.to_ascii_uppercase();
                let cur_base = cur_iface.base_iface();
                cur_base
                    .permanent_mac_address
                    .as_deref()
                    .is_some_and(|m| m.to_ascii_uppercase() == saved_mac)
                    || cur_base
                        .mac_address
                        .as_deref()
                        .is_some_and(|m| m.to_ascii_uppercase() == saved_mac)
            })
}

/// Generate the desired state which purges the IP stack of the wifi-phy a
/// link-down event refers to.
///
/// Returns `None` when the event is not a wifi-phy link-down, or when an
/// auto-connect entry for the same NIC already purges the IP stack
/// (`gen_desired_iface_down()` disables both IP stacks). The latter matters
/// when a saved config renames the NIC at boot: pushing this standalone
/// purge under the current kernel name would leave a second merged entry
/// whose name no longer exists after the rename, failing the nispor batch
/// with `EOPNOTSUPP` and handing the wifi plugin a non-existent interface.
///
/// `None` is also returned when the current kernel interface exists but is
/// not a wifi-phy: the event was classified from sysfs while nispor still
/// sees the old non-WIFI interface (e.g. a wiphy moving back to the root
/// netns while the nl80211 interface dump lags).  Merging a wifi-phy
/// desired state against another interface type is a bug, and a stale
/// event has no IP stack to purge.
fn gen_wifi_phy_ip_purge(
    event: &InterfaceLinkEvent,
    cur_iface: Option<&Interface>,
    auto_connect_covers_ip_purge: bool,
) -> Option<Interface> {
    if event.is_up
        || event.iface_type != InterfaceType::WifiPhy
        || auto_connect_covers_ip_purge
    {
        return None;
    }
    if let Some(cur_iface) = cur_iface
        && !matches!(cur_iface, Interface::WifiPhy(_))
    {
        log::debug!(
            "{}: wifi-phy link event but current interface is {}, ignoring \
             the stale event",
            event.iface_name,
            cur_iface.iface_type(),
        );
        return None;
    }
    let mut desired_iface = BaseInterface::new(
        event.iface_name.to_string(),
        event.iface_type.clone(),
    );
    desired_iface.state = if cur_iface.is_some() {
        InterfaceState::Up
    } else {
        // WIFI PHY interface removed.
        InterfaceState::Absent
    };
    // Purge IP. IPv6 stays enabled so the kernel-generated link-local
    // address is kept; only the addresses learned from the previous
    // connection are removed.
    desired_iface.ipv4 = Some(InterfaceIpv4::new_disabled());
    desired_iface.ipv6 = Some(InterfaceIpv6::new_purge_keep_link_local());
    Some(desired_iface.into())
}

/// Build absent route entries for every running route egressing through
/// `iface_name`, so a WiFi link-down purge also removes routes learned from
/// the previous connection (e.g. the IPv6 default gateway from RA).
fn gen_running_route_purge(
    iface_name: &str,
    cur_state: &NetworkState,
) -> Vec<RouteEntry> {
    cur_state
        .routes
        .running
        .iter()
        .flatten()
        .filter(|rt| rt.next_hop_iface.as_deref() == Some(iface_name))
        .cloned()
        .map(|mut rt| {
            rt.state = Some(RouteState::Absent);
            rt
        })
        .collect()
}

fn handle_wifi_phy_event(
    event: &InterfaceLinkEvent,
    saved_iface: &Interface,
) -> Option<Interface> {
    if !event.is_up && saved_iface.iface_type() == &InterfaceType::WifiPhy {
        // The IP purge of a wifi-phy link-down is handled by the event
        // worker's dedicated purge entry, not by this helper.
        None
    } else if event.is_up
        && event.ssid.is_some()
        && let Interface::WifiCfg(saved_wifi_iface) = saved_iface
    {
        if event.ssid.as_deref() == saved_wifi_iface.ssid() {
            let new_iface =
                wifi_cfg_to_wifi_phy(event.iface_name.as_str(), saved_iface);
            log::debug!("Pending apply wifi-cfg config: {new_iface}");
            Some(new_iface)
        } else {
            // The wifi-phy is already up with another SSID, so the saved
            // wifi-cfg does not match this association.  The SSID config
            // is sent to the plugin at boot/apply time, so there is
            // nothing to (re)configure here.
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
#[path = "../unit_tests/event_worker.rs"]
mod tests;
