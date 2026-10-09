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
        let mut desired_state = NetworkState::default();
        let mut wifi_plugin_state = NetworkState::default();
        let mut rearm_monitors = false;
        // Virtual interfaces already added to `desired_state` because a
        // physical port/parent of them appeared in this batch.  Several
        // events can name ports of the same missing controller.
        let mut added_virtual_dependents: HashSet<String> = HashSet::new();

        for mut event in events {
            // Kernel event is always for kernel interface
            let mut cur_iface =
                cur_state.ifaces.kernel_ifaces.get(&event.iface_name);

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

            // A new wifi-phy appeared after the boot grace period: the wifi
            // plugin is a fresh process (or never saw this phy), so give it the
            // saved WIFI config matching this phy.  Its apply worker will start
            // a new shuli client covering the phy.
            if event.is_new_wifi_phy
                && event.iface_type == InterfaceType::WifiPhy
            {
                let wifi_state = gen_wifi_plugin_state_for_phy(
                    &event.iface_name,
                    &saved_state,
                );
                if wifi_state.is_empty() {
                    log::debug!(
                        "No saved WIFI config for new wifi-phy {}",
                        event.iface_name
                    );
                } else {
                    log::info!(
                        "Handing saved WIFI config to plugin for new wifi-phy \
                         {}: {wifi_state}",
                        event.iface_name
                    );
                    for iface in wifi_state.ifaces.iter() {
                        wifi_plugin_state.ifaces.push(iface.clone());
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

            // Purge IP if WIFI PHY interface is down or removed
            if !event.is_up && event.iface_type == InterfaceType::WifiPhy {
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
                // Purge IP
                desired_iface.ipv4 = Some(InterfaceIpv4::new_disabled());
                desired_iface.ipv6 = Some(InterfaceIpv6::new_disabled());
                log::trace!(
                    "{}: link down on wifi-phy, purging IP stack: \
                     {desired_iface}",
                    event.iface_name
                );
                desired_state.ifaces.push(desired_iface.into());
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

        if !wifi_plugin_state.is_empty()
            && let Err(e) = commander
                .plugin_manager
                .apply_network_state(
                    &wifi_plugin_state,
                    &NipartApplyOption::new().memory_only(),
                )
                .await
        {
            // A retriable failure is re-driven by reconciliation: forget
            // the phys so they are announced as new again and the saved
            // WIFI profiles are handed to the plugin again.
            if e.kind().retriable() {
                let phy_names: Vec<String> = wifi_plugin_state
                    .ifaces
                    .iter()
                    .map(|iface| iface.kernel_iface_name().to_string())
                    .filter(|name| !name.is_empty())
                    .collect();
                log::info!(
                    "WIFI plugin apply failed, requesting link events to \
                     retry {phy_names:?}: {e}"
                );
                commander.monitor_manager.forget_emitted(&phy_names).await?;
            }
            return Err(e);
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

/// Extract the saved WIFI interfaces matching `phy_name` so the plugin can
/// rebuild the network list for a newly appeared wifi-phy.
///
/// Only the `wifi-phy` entries identifying `phy_name` and the `wifi-cfg`
/// profiles bound to it (explicit `base-iface` or unbound) are included;
/// configs with `auto-connect: false` are left for an explicit request.
/// An empty result means the wifi plugin must not be contacted for this
/// phy at all.
fn gen_wifi_plugin_state_for_phy(
    phy_name: &str,
    saved_state: &NetworkState,
) -> NetworkState {
    let mut phy_ifaces: Vec<Interface> = Vec::new();
    let mut cfg_ifaces: Vec<Interface> = Vec::new();
    let mut phy_has_ssid = false;
    for iface in saved_state.ifaces.iter() {
        let base = iface.base_iface();
        if base.auto_connect.as_ref() == Some(&InterfaceAutoConnect::Manual) {
            continue;
        }
        match iface {
            Interface::WifiPhy(wifi_iface) => {
                if wifi_iface.base.kernel_iface_name == phy_name
                    || wifi_iface.base.name == phy_name
                    || wifi_iface.base.profile_name.as_deref() == Some(phy_name)
                {
                    phy_has_ssid |= wifi_iface.ssid().is_some();
                    phy_ifaces.push(iface.clone());
                }
            }
            Interface::WifiCfg(wifi_iface) => {
                let base_iface = wifi_iface
                    .wifi
                    .as_ref()
                    .and_then(|wifi| wifi.base_iface.as_deref());
                if base_iface.is_none_or(|base_iface| base_iface == phy_name) {
                    cfg_ifaces.push(iface.clone());
                }
            }
            _ => {}
        }
    }
    let mut ret = NetworkState::default();
    // A wifi-phy alone (no saved SSID on the phy, no wifi-cfg profile) is
    // not a wifi config: do not contact the plugin for it.
    if cfg_ifaces.is_empty() && !phy_has_ssid {
        return ret;
    }
    for iface in phy_ifaces.into_iter().chain(cfg_ifaces) {
        ret.ifaces.push(iface);
    }
    ret
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
    new_iface.base_iface_mut().ipv6 = Some(InterfaceIpv6::new_disabled());
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

fn handle_wifi_phy_event(
    event: &InterfaceLinkEvent,
    saved_iface: &Interface,
) -> Option<Interface> {
    if !event.is_up && saved_iface.iface_type() == &InterfaceType::WifiPhy {
        // Already processed above to purge IP on this wifi-phy interface.
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
