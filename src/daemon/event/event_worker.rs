// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use futures_channel::{mpsc::UnboundedReceiver, oneshot::Sender};
use nipart::{
    BaseInterface, ErrorKind, Interface, InterfaceAutoConnect, InterfaceIpv4,
    InterfaceIpv6, InterfaceLinkEvent, InterfaceLinkState, InterfaceState,
    InterfaceType, MergedNetworkState, NetworkState, NipartApplyOption,
    NipartError, NipartInterface, NipartNoDaemon, NipartQueryOption,
    RouteEntry, RouteRuleEntry, RouteState,
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
    HandleEvent(Box<InterfaceLinkEvent>),
}

impl std::fmt::Display for NipartEventCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetCommander(_) => {
                write!(f, "set-commander")
            }
            Self::HandleEvent(event) => {
                write!(f, "handle-event:{event}")
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
            NipartEventCmd::HandleEvent(event) => {
                if let Err(e) = self.handle_event(*event).await {
                    log::error!("{e}");
                }
            }
        }
        Ok(NipartEventReply::None)
    }
}

impl NipartEventWorker {
    async fn handle_event(
        &mut self,
        mut event: InterfaceLinkEvent,
    ) -> Result<(), NipartError> {
        let Some(commander) = self.commander.as_mut() else {
            return Err(NipartError::new(
                ErrorKind::Bug,
                "NipartEventWorker::handle_event() invoked without commander \
                 set"
                .to_string(),
            ));
        };
        log::trace!("Handle link event {event}");
        let saved_state = commander.conf_manager.query_state().await?;
        let mut cur_state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;

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
                "Ignoring stale link-down event {event}: current link state \
                 is up"
            );
            return Ok(());
        }

        if nic_is_gone(&event, cur_iface) {
            // The kernel interface is already gone (delete event, or a
            // link-down event processed after the device disappeared).
            // There is nothing to purge in the kernel, and applying the
            // saved MAC-identified config now would only fail.  Re-arm the
            // saved-profile watches so the config is applied when the same
            // NIC appears again, possibly under a different kernel name
            // (e.g. a USB dock replug).
            log::trace!("Interface {event} is gone, re-arming saved monitors");
            commander
                .monitor_manager
                .setup_saved_state_monitors(&saved_state, true)
                .await?;
            return Ok(());
        }

        // A new wifi-phy appeared after the boot grace period: the wifi
        // plugin is a fresh process (or never saw this phy), so give it the
        // complete saved WIFI picture. Its apply worker will start a new
        // shuli client covering this phy.
        if event.is_new_wifi_phy && event.iface_type == InterfaceType::WifiPhy {
            let wifi_state = gen_wifi_plugin_state(&saved_state);
            if wifi_state.is_empty() {
                log::debug!(
                    "No saved WIFI config for new wifi-phy {}",
                    event.iface_name
                );
            } else {
                log::info!(
                    "Applying saved WIFI config to plugin for new wifi-phy \
                     {}: {wifi_state}",
                    event.iface_name
                );
                commander
                    .plugin_manager
                    .apply_network_state(
                        &wifi_state,
                        &NipartApplyOption::new().memory_only(),
                    )
                    .await?;
            }
        }

        if let Some(cur_iface) = cur_iface.as_ref() {
            log::trace!("Current interface state: {cur_iface}");
        }

        // A wifi-phy up event may reach us before the kernel has finished
        // publishing the associated SSID (especially on drivers using
        // `NL80211_CMD_ASSOCIATE`).  Retry the query for a short while so
        // the wifi-cfg IP config is not lost just because the first snapshot
        // was taken too early.
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

        let mut desired_state = NetworkState::default();

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
                "{}: link down on wifi-phy, purging IP stack: {desired_iface}",
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
                let config_rules =
                    desired_state.route_rules.config.get_or_insert_default();
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
                        gen_route_rules_for_iface_up(saved_iface, &saved_state)
                    {
                        log::trace!("Pending apply route rule {rule}");
                        config_rules.push(rule);
                    }
                }
            }
        }

        if !desired_state.is_empty() {
            log::trace!("Applying desired state {desired_state}");
            let merged_state = MergedNetworkState::new(
                desired_state,
                cur_state,
                None,
                NipartApplyOption::new().no_verify(),
            )?;
            commander.apply_merged_state(None, &merged_state).await?;
            // The event path applies the saved config directly (no
            // `apply_network_state`), so refresh the monitor setup here:
            // the applied interface gets its kernel-name watch, and a stale
            // MAC watch of an interface that has just become active is
            // dropped.
            commander
                .monitor_manager
                .setup_monitor(&merged_state, &saved_state)
                .await?;
        } else {
            log::trace!("No change required for event {event}");
        }

        Ok(())
    }
}

/// Extract every saved WIFI interface so the plugin can rebuild its full
/// network list when a new wifi-phy shows up.
fn gen_wifi_plugin_state(saved_state: &NetworkState) -> NetworkState {
    let mut ret = NetworkState::default();
    for iface in saved_state.ifaces.iter() {
        if matches!(
            iface.iface_type(),
            InterfaceType::WifiCfg | InterfaceType::WifiPhy
        ) {
            ret.ifaces.push(iface.clone());
        }
    }
    ret
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
            iface.base_iface().link_state == Some(InterfaceLinkState::Up)
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
