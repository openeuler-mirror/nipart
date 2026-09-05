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

fn is_route_matching_iface(rt: &RouteEntry, iface: &Interface) -> bool {
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
mod tests {
    use std::time::SystemTime;

    use nipart::{
        Interface, InterfaceAutoConnect, InterfaceIpv4, InterfaceLinkEvent,
        InterfaceState, InterfaceType, MergedNetworkState, NetworkState,
        NipartInterface,
    };

    use super::{
        gen_desired_iface_down, gen_routes_for_iface_up,
        gen_routes_for_wifi_cfg_up, gen_wifi_plugin_state,
        handle_event_auto_connect, handle_wifi_phy_event,
        is_route_matching_iface, is_stale_link_down_event, nic_is_gone,
        wifi_cfg_to_wifi_phy, wifi_phy_ssid,
    };

    fn gen_wifi_cfg_iface() -> Interface {
        rmsd_yaml::from_str(
            r#"---
            name: Test-WIFI
            type: wifi-cfg
            state: up
            ipv4:
              enabled: true
              dhcp: true
            wifi:
              ssid: Test-WIFI
              base-iface: wlan0
            "#,
        )
        .unwrap()
    }

    fn gen_wifi_phy_event(
        is_up: bool,
        ssid: Option<&str>,
    ) -> InterfaceLinkEvent {
        InterfaceLinkEvent {
            iface_name: "wlan0".to_string(),
            iface_index: 18,
            iface_type: InterfaceType::WifiPhy,
            is_up,
            is_delete: false,
            time_stamp: SystemTime::now(),
            ssid: ssid.map(|s| s.to_string()),
            is_new_wifi_phy: false,
        }
    }

    fn gen_saved_state() -> NetworkState {
        rmsd_yaml::from_str(
            r#"---
version: 1
routes:
  config:
  - destination: 0.0.0.0/0
    next-hop-interface: wan0
    next-hop-address: 192.0.2.254
    metric: 100
    table-id: 254
  - destination: 198.51.100.0/24
    next-hop-interface: eth2
    next-hop-address: 198.51.100.254
    metric: 103
    table-id: 254
  - destination: 203.0.113.0/24
    next-hop-interface: wifi0
    next-hop-address: 203.0.113.254
    metric: 102
    table-id: 254
  - destination: 203.0.113.128/25
    next-hop-interface: wifi0
    next-hop-address: 203.0.113.254
    metric: 104
    table-id: 254
  - destination: 192.0.2.0/24
    next-hop-interface: vpn0
    next-hop-address: 192.0.2.1
    metric: 100
    table-id: 254
interfaces:
- name: wan0
  type: ethernet
  kernel-iface-name: eth0
  state: up
  profile-name: wan0
  identifier: mac-address
  mac-address: 02:00:00:00:00:01
- name: lan0
  type: ethernet
  kernel-iface-name: eth2
  state: up
  profile-name: lan0
  identifier: mac-address
  mac-address: 02:00:00:00:00:02
- name: wifi0
  type: ethernet
  kernel-iface-name: wlan0
  state: up
  profile-name: wifi0
  identifier: mac-address
  mac-address: 02:00:00:00:00:03
"#,
        )
        .unwrap()
    }

    fn gen_wifi_cfg_state_with_route() -> NetworkState {
        rmsd_yaml::from_str(
            r#"---
            version: 1
            routes:
              config:
              - destination: 203.0.113.0/24
                next-hop-interface: Test-WIFI
                next-hop-address: 203.0.113.254
                metric: 102
                table-id: 254
            interfaces:
              - name: Test-WIFI
                type: wifi-cfg
                state: up
                ipv4:
                  enabled: true
                  dhcp: true
                wifi:
                  ssid: Test-WIFI
                  base-iface: wlan0
            "#,
        )
        .unwrap()
    }

    fn find_iface<'a>(state: &'a NetworkState, name: &str) -> &'a Interface {
        state.ifaces.iter().find(|i| i.name() == name).unwrap()
    }

    #[test]
    fn test_route_matching_by_profile_name() {
        let state = gen_saved_state();
        let wan0 = find_iface(&state, "wan0");
        let routes = gen_routes_for_iface_up(wan0, &state);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination.as_deref(), Some("0.0.0.0/0"));
    }

    #[test]
    fn test_route_matching_by_kernel_iface_name() {
        let state = gen_saved_state();
        let red = find_iface(&state, "lan0");
        let routes = gen_routes_for_iface_up(red, &state);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination.as_deref(), Some("198.51.100.0/24"));
    }

    #[test]
    fn test_route_matching_by_iface_name() {
        let state = gen_saved_state();
        let wifi0 = find_iface(&state, "wifi0");
        let routes = gen_routes_for_iface_up(wifi0, &state);
        let mut dests: Vec<_> = routes
            .iter()
            .filter_map(|rt| rt.destination.as_deref())
            .collect();
        dests.sort_unstable();
        assert_eq!(dests, vec!["203.0.113.0/24", "203.0.113.128/25"]);
    }

    #[test]
    fn test_route_not_matching_iface_excluded() {
        let state = gen_saved_state();
        for name in ["wan0", "lan0", "wifi0"] {
            let iface = find_iface(&state, name);
            assert!(
                !gen_routes_for_iface_up(iface, &state)
                    .iter()
                    .any(
                        |rt| rt.destination.as_deref() == Some("192.0.2.0/24")
                    ),
                "{name} should not pick up the vpn0 route"
            );
        }
    }

    #[test]
    fn test_wifi_cfg_routes_included_on_wifi_phy_up() {
        let state = gen_wifi_cfg_state_with_route();
        let wifi_cfg = find_iface(&state, "Test-WIFI");
        let routes = gen_routes_for_wifi_cfg_up(wifi_cfg, &state);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(routes[0].next_hop_iface.as_deref(), Some("Test-WIFI"));
    }

    #[test]
    fn test_is_route_matching_iface() {
        let state = gen_saved_state();
        let wan0 = find_iface(&state, "wan0");
        let vpn0_rt = state
            .routes
            .config
            .as_ref()
            .unwrap()
            .iter()
            .find(|rt| rt.destination.as_deref() == Some("192.0.2.0/24"))
            .unwrap();
        assert!(!is_route_matching_iface(vpn0_rt, wan0));
    }

    #[test]
    fn test_gen_wifi_plugin_state_filters_non_wifi_ifaces() {
        let state: NetworkState = rmsd_yaml::from_str(
            r#"---
            interfaces:
              - name: eth0
                type: ethernet
                state: up
              - name: Test-WIFI
                type: wifi-cfg
                state: up
                wifi:
                  ssid: Test-WIFI
              - name: wlan0
                type: wifi-phy
                state: up
            "#,
        )
        .unwrap();

        let wifi_state = gen_wifi_plugin_state(&state);
        assert_eq!(wifi_state.ifaces.iter().count(), 2);
        assert!(wifi_state.ifaces.iter().all(|iface| {
            matches!(
                iface.iface_type(),
                InterfaceType::WifiCfg | InterfaceType::WifiPhy
            )
        }));
    }

    fn gen_link_event(iface_name: &str, is_up: bool) -> InterfaceLinkEvent {
        InterfaceLinkEvent {
            iface_name: iface_name.to_string(),
            iface_index: 18,
            iface_type: InterfaceType::Ethernet,
            is_up,
            is_delete: false,
            time_stamp: SystemTime::now(),
            ssid: None,
            is_new_wifi_phy: false,
        }
    }

    #[test]
    fn test_stale_link_down_event_skipped_when_current_up() {
        // A down event processed while the interface is already up is a
        // leftover of the boot-time transient state: it must be skipped so
        // the boot apply result (IP + routes) is not torn down.
        let saved_state = gen_saved_state();
        let wan0 = find_iface(&saved_state, "wan0");
        let mut cur_iface = wan0.clone();
        cur_iface.base_iface_mut().link_state =
            Some(nipart::InterfaceLinkState::Up);

        assert!(is_stale_link_down_event(
            &gen_link_event("eth0", false),
            Some(&cur_iface)
        ));
    }

    #[test]
    fn test_link_down_event_processed_when_current_down() {
        // A real link-down event: the current kernel link state is down, so
        // the event reflects a genuine state change and must be processed
        // (purge IP and routes).
        let saved_state = gen_saved_state();
        let wan0 = find_iface(&saved_state, "wan0");
        let mut cur_iface = wan0.clone();
        cur_iface.base_iface_mut().link_state =
            Some(nipart::InterfaceLinkState::Down);

        assert!(!is_stale_link_down_event(
            &gen_link_event("eth0", false),
            Some(&cur_iface)
        ));
    }

    #[test]
    fn test_up_event_never_stale() {
        // Up events always go through: they are the mechanism to (re)apply
        // the saved config, and skipping them would break hotplug (e.g.
        // wifi association or veth re-plug).
        let saved_state = gen_saved_state();
        let wan0 = find_iface(&saved_state, "wan0");
        let mut cur_iface = wan0.clone();
        cur_iface.base_iface_mut().link_state =
            Some(nipart::InterfaceLinkState::Up);

        assert!(!is_stale_link_down_event(
            &gen_link_event("eth0", true),
            Some(&cur_iface)
        ));
        // Interface already gone: delete event is handled separately.
        assert!(!is_stale_link_down_event(
            &gen_link_event("eth0", false),
            None
        ));
    }

    #[test]
    fn test_nic_is_gone() {
        let saved_state = gen_saved_state();
        let wan0 = find_iface(&saved_state, "wan0");
        let mut delete_event = gen_link_event("eth0", false);
        delete_event.is_delete = true;

        assert!(nic_is_gone(&delete_event, Some(wan0)));
        assert!(nic_is_gone(&gen_link_event("eth0", false), None));
        assert!(!nic_is_gone(&gen_link_event("eth0", false), Some(wan0)));
        assert!(!nic_is_gone(&gen_link_event("eth0", true), Some(wan0)));
    }

    #[test]
    fn test_wifi_phy_ssid_extraction() {
        let phy: Interface = rmsd_yaml::from_str(
            r#"---
            name: wlan0
            type: wifi-phy
            state: up
            wifi:
              ssid: Test-WIFI
            "#,
        )
        .unwrap();

        assert_eq!(wifi_phy_ssid(Some(&phy)).as_deref(), Some("Test-WIFI"));
        assert_eq!(wifi_phy_ssid(None), None);

        let eth: Interface = rmsd_yaml::from_str(
            r#"---
            name: eth0
            type: ethernet
            state: up
            "#,
        )
        .unwrap();
        assert_eq!(wifi_phy_ssid(Some(&eth)), None);
    }

    #[test]
    fn test_auto_connect_defaults_to_true_on_link_up() {
        // Interface without `auto-connect` defaults to `auto-connect: true`,
        // hence link up should apply the interface along with its routes.
        let saved_state = gen_saved_state();
        let wan0 = find_iface(&saved_state, "wan0");
        let event = gen_link_event("eth0", true);

        let (new_iface, routes) = handle_event_auto_connect(
            &event,
            wan0,
            &saved_state,
            &NetworkState::default(),
        )
        .expect("auto-connect defaults to true");

        assert_eq!(new_iface.name(), "wan0");
        assert_eq!(new_iface.base_iface().state, InterfaceState::Up);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination.as_deref(), Some("0.0.0.0/0"));
    }

    #[test]
    fn test_auto_connect_defaults_to_true_on_link_down() {
        // On link down, the default auto-connect purges IP and marks routes
        // absent, but does not bring the interface down.
        let saved_state = gen_saved_state();
        let wan0 = find_iface(&saved_state, "wan0");
        let event = gen_link_event("eth0", false);

        let (new_iface, routes) = handle_event_auto_connect(
            &event,
            wan0,
            &saved_state,
            &NetworkState::default(),
        )
        .expect("auto-connect defaults to true");

        assert_eq!(new_iface.base_iface().state, InterfaceState::Up);
        assert_eq!(
            new_iface.base_iface().ipv4,
            Some(InterfaceIpv4::new_disabled())
        );
        assert_eq!(routes.len(), 1);
        assert!(routes[0].is_absent());
    }

    #[test]
    fn test_wifi_phy_link_down_purge_drops_wifi_section() {
        let saved_iface: Interface = rmsd_yaml::from_str(
            r#"---
            name: wlan0
            type: wifi-phy
            state: up
            wifi:
              ssid: Test-WIFI
              base-iface: wlan0
            "#,
        )
        .unwrap();

        let (new_iface, _) = gen_desired_iface_down(
            &InterfaceAutoConnect::AutoConnect,
            &saved_iface,
            &NetworkState::default(),
        );
        let Interface::WifiPhy(new_iface) = new_iface else {
            panic!("expected wifi-phy interface");
        };
        assert!(new_iface.wifi.is_none());
    }

    #[test]
    fn test_wifi_phy_down_event_does_not_reapply_wifi_cfg() {
        // The SSID config is already sent to the plugin at boot/apply
        // time: a wifi-phy link-down event must only purge IP (handled
        // elsewhere), not re-apply the wifi-cfg, which would make the
        // plugin switch away from its current connection.
        let saved_iface = gen_wifi_cfg_iface();
        let event = gen_wifi_phy_event(false, None);

        assert!(handle_wifi_phy_event(&event, &saved_iface).is_none());
    }

    #[test]
    fn test_wifi_phy_down_event_does_not_return_saved_wifi_phy() {
        // A saved wifi-phy itself is not re-applied on link down: the IP
        // purge is handled by the event worker before this helper.
        let saved_iface: Interface = rmsd_yaml::from_str(
            r#"---
            name: wlan0
            type: wifi-phy
            state: up
            "#,
        )
        .unwrap();
        let event = gen_wifi_phy_event(false, None);

        assert!(handle_wifi_phy_event(&event, &saved_iface).is_none());
    }

    #[test]
    fn test_wifi_phy_up_event_applies_ip_config_of_matching_wifi_cfg() {
        // On wifi-phy link up with the matching SSID, the IP config of
        // the saved wifi-cfg is applied to the kernel wifi-phy.
        let saved_iface = gen_wifi_cfg_iface();
        let event = gen_wifi_phy_event(true, Some("Test-WIFI"));

        let new_iface = handle_wifi_phy_event(&event, &saved_iface)
            .expect("matching SSID should apply IP config");
        assert_eq!(new_iface.iface_type(), &InterfaceType::WifiPhy);
        assert_eq!(new_iface.kernel_iface_name(), "wlan0");
        assert_eq!(new_iface.name(), "wlan0");
        assert!(new_iface.base_iface().ipv4.is_some());
    }

    #[test]
    fn test_wifi_cfg_event_route_resolves_to_connected_phy() {
        let saved_state = gen_wifi_cfg_state_with_route();
        let saved_iface = find_iface(&saved_state, "Test-WIFI");
        let mut desired_state = NetworkState::default();
        desired_state
            .ifaces
            .push(wifi_cfg_to_wifi_phy("wlan0", saved_iface));
        desired_state.routes = saved_state.routes.clone();

        let current_state: NetworkState = rmsd_yaml::from_str(
            r#"---
            interfaces:
              - name: wlan0
                type: wifi-phy
                state: up
                link-state: up
                wifi:
                  ssid: Test-WIFI
            "#,
        )
        .unwrap();

        let merged = MergedNetworkState::new(
            desired_state,
            current_state,
            None,
            Default::default(),
        )
        .unwrap();
        let changed: Vec<&str> = merged
            .routes
            .changed_routes
            .iter()
            .filter_map(|rt| rt.next_hop_iface.as_deref())
            .collect();
        assert_eq!(changed, vec!["wlan0"]);
    }

    #[test]
    fn test_wifi_phy_up_event_with_other_ssid_ignores_wifi_cfg() {
        // A wifi-phy already up with a different SSID must not be
        // reconfigured: the plugin decides which SSID to connect at
        // boot/apply time.
        let saved_iface = gen_wifi_cfg_iface();
        let event = gen_wifi_phy_event(true, Some("Other-SSID"));

        assert!(handle_wifi_phy_event(&event, &saved_iface).is_none());
    }
}
