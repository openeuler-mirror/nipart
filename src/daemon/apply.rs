// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use nipart::{
    DnsResolver, ErrorKind, Interface, InterfaceAutoConnect, InterfaceType,
    MergedNetworkState, NetworkState, NipartApplyOption, NipartError,
    NipartInterface, NipartIpcConnection, NipartNoDaemon, NipartQueryOption,
    NipartWifiConnectErrorOption,
};

use super::{commander::NipartCommander, dhcp::is_fatal_wifi_connect_error};
use crate::{log_debug, log_error, log_info, log_trace, log_warn};

const RETRY_COUNT: usize = 10;
// WIFI association can legitimately take longer than a kernel link change:
// shuli's first host-side scan may miss the AP and retry after its scan
// backoff (10s on mac80211_hwsim), so give wifi applies a longer window
// before verification gives up.
const WIFI_RETRY_COUNT: usize = 60;
const RETRY_INTERVAL_MS: u64 = 500;
// A `npt wifi connect` must not return before the association completed:
// bound the wait for the explicitly requested SSIDs. Failures the plugin
// already diagnosed (wrong password, unsupported security) end the wait
// immediately.
const WIFI_CONNECT_WAIT_TIMEOUT_SECS: u64 = 60;
// Top-level apply retry: the inner verification retry only absorbs
// post-apply propagation delays, so a transient failure of the apply itself
// (a plugin or DHCP worker still starting, a NIC/link not ready yet) would
// abort the whole action. Every apply entry - user request, boot activation
// and link event - retries the full apply with this interval until it
// succeeds or the attempts are exhausted. Errors whose kind is not
// retriable (`ErrorKind::retriable()`) are reported immediately.
const APPLY_RETRY_MAX: u32 = 5;
const APPLY_RETRY_INTERVAL_SEC: u64 = 2;

/// A WIFI association explicitly requested by an apply.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WifiConnectRequest {
    ssid: String,
    /// `base-iface` of the request: the kernel or profile name of the
    /// wifi-phy to bind to; `None` means any eligible wifi-phy.
    base_iface: Option<String>,
}

/// The SSIDs one wifi-phy is asked to connect to.
///
/// The wifi plugin hands a phy's whole network list to shuli, which picks
/// the best available network: a phy carrying several requested SSIDs is
/// satisfied when at least one of them is connected.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WifiConnectGroup {
    /// Kernel name of the target phy when it is present; `None` when the
    /// request's `base-iface` is a profile name and has to be matched
    /// against the live phy at check time.
    phy_name: Option<String>,
    base_iface: Option<String>,
    ssids: Vec<String>,
}

/// Kernel name of the wifi-phy a desired `wifi-phy` interface resolves
/// to.
///
/// The desired state is the raw user input: a MAC-identified profile
/// keeps its logical name there, so look up the resolved kernel name
/// through the merged interfaces before falling back to the raw
/// `kernel-iface-name`/name.
fn wifi_phy_kernel_name(
    merged_state: &MergedNetworkState,
    iface: &Interface,
) -> Option<String> {
    for merged_iface in merged_state.ifaces.kernel_ifaces.values() {
        if merged_iface.desired.as_ref().map(|desired| desired.name())
            != Some(iface.name())
            || merged_iface.merged.iface_type() != &InterfaceType::WifiPhy
        {
            continue;
        }
        let kernel_name = merged_iface.merged.kernel_iface_name();
        if !kernel_name.is_empty() {
            return Some(kernel_name.to_string());
        }
    }
    if iface.kernel_iface_name().is_empty() {
        Some(iface.name().to_string())
    } else {
        Some(iface.kernel_iface_name().to_string())
    }
}

/// Collect the WIFI SSIDs this apply explicitly asks to connect to.
///
/// Only up `wifi-phy`/`wifi-cfg` interfaces carrying an SSID count: an
/// apply without a WIFI connection request (e.g. an IP-only re-apply of
/// an already connected phy, or a removal) must not wait for anything.
fn wifi_connect_requests(
    merged_state: &MergedNetworkState,
) -> Vec<WifiConnectRequest> {
    let mut ret = Vec::new();
    for iface in merged_state.desired.ifaces.iter() {
        if !iface.is_up() {
            continue;
        }
        match iface {
            Interface::WifiPhy(phy) => {
                if let Some(ssid) = phy.ssid().filter(|ssid| !ssid.is_empty()) {
                    ret.push(WifiConnectRequest {
                        ssid: ssid.to_string(),
                        base_iface: wifi_phy_kernel_name(merged_state, iface),
                    });
                }
            }
            Interface::WifiCfg(cfg) => {
                if let Some(ssid) = cfg.ssid().filter(|ssid| !ssid.is_empty()) {
                    ret.push(WifiConnectRequest {
                        ssid: ssid.to_string(),
                        base_iface: cfg
                            .wifi
                            .as_ref()
                            .and_then(|wifi| wifi.base_iface.clone()),
                    });
                }
            }
            _ => {}
        }
    }
    ret
}

/// Group the connect requests by the wifi-phy they target.
///
/// An unbound request (no `base-iface`) is handed to every present
/// wifi-phy, exactly like the wifi plugin binds it. A `base-iface`
/// matching a present kernel name selects that phy; an unresolved one
/// (e.g. a profile name) is matched against the live state later.
fn wifi_connect_groups(
    requests: &[WifiConnectRequest],
    phy_names: &[String],
) -> Vec<WifiConnectGroup> {
    let mut groups: Vec<WifiConnectGroup> = Vec::new();
    let mut push = |phy_name: Option<String>,
                    base_iface: Option<String>,
                    ssid: &str| {
        // A resolved phy is the group identity even when the requests
        // reached it through different `base-iface` values (an unbound
        // profile is handed to every phy).
        let existing = groups.iter_mut().find(|group| match &phy_name {
            Some(phy_name) => group.phy_name.as_ref() == Some(phy_name),
            None => group.phy_name.is_none() && group.base_iface == base_iface,
        });
        if let Some(group) = existing {
            if !group.ssids.iter().any(|existing| existing == ssid) {
                group.ssids.push(ssid.to_string());
            }
        } else {
            groups.push(WifiConnectGroup {
                phy_name,
                base_iface,
                ssids: vec![ssid.to_string()],
            });
        }
    };
    for request in requests {
        match request.base_iface.as_deref() {
            None => {
                for phy_name in phy_names {
                    push(Some(phy_name.clone()), None, &request.ssid);
                }
            }
            Some(base) => match phy_names.iter().find(|phy| *phy == base) {
                Some(phy_name) => push(
                    Some(phy_name.clone()),
                    Some(base.to_string()),
                    &request.ssid,
                ),
                None => push(None, Some(base.to_string()), &request.ssid),
            },
        }
    }
    groups
}

/// Whether `group` is satisfied by the plugin's live connection state.
fn wifi_group_is_connected(
    state: &NetworkState,
    group: &WifiConnectGroup,
) -> bool {
    state.ifaces.iter().any(|iface| {
        let Interface::WifiPhy(phy) = iface else {
            return false;
        };
        if !group
            .ssids
            .iter()
            .any(|ssid| phy.ssid() == Some(ssid.as_str()))
        {
            return false;
        }
        match (&group.phy_name, group.base_iface.as_deref()) {
            (Some(phy_name), _) => phy.kernel_iface_name() == phy_name,
            (None, Some(base)) => {
                base == phy.kernel_iface_name()
                    || base == phy.name()
                    || phy.base_iface().profile_name.as_deref() == Some(base)
            }
            (None, None) => true,
        }
    })
}

/// Kernel names and SSIDs of the wifi-phys a state reports connected.
fn connected_wifi_phys(state: &NetworkState) -> HashSet<(String, String)> {
    let mut ret = HashSet::new();
    for iface in state.ifaces.iter() {
        if let Interface::WifiPhy(phy) = iface
            && let Some(ssid) = phy.ssid()
        {
            ret.insert((
                iface.kernel_iface_name().to_string(),
                ssid.to_string(),
            ));
        }
    }
    ret
}

/// Kernel names of every wifi-phy in `state`.
fn wifi_phy_names(state: &NetworkState) -> Vec<String> {
    let mut ret = Vec::new();
    for iface in state.ifaces.iter() {
        let name = iface.kernel_iface_name();
        if iface.iface_type() == &InterfaceType::WifiPhy
            && !name.is_empty()
            && !ret.iter().any(|existing| existing == name)
        {
            ret.push(name.to_string());
        }
    }
    ret
}

/// DNS resolver state captured before an apply, used by rollback.
#[derive(Debug, Clone)]
struct RevertDns {
    resolver: DnsResolver,
    dynamic_servers: Vec<String>,
}

impl NipartCommander {
    pub(crate) async fn apply_network_state(
        &mut self,
        conn: Option<&mut NipartIpcConnection>,
        desired_state: NetworkState,
        opt: NipartApplyOption,
    ) -> Result<NetworkState, NipartError> {
        let saved_config = self.conf_manager.query_state().await?;
        self.apply_network_state_with_saved_config(
            conn,
            desired_state,
            opt,
            Some(saved_config),
        )
        .await
    }

    /// Apply desired state using an explicit saved state.
    ///
    /// `None` is used by explicit `npt up`/`npt down` actions: their desired
    /// state already contains the full saved profile, and passing the saved
    /// state here would re-inherit properties such as `auto-connect` and
    /// prevent the explicit action from overriding conditional activation.
    pub(crate) async fn apply_network_state_with_saved_config(
        &mut self,
        mut conn: Option<&mut NipartIpcConnection>,
        desired_state: NetworkState,
        opt: NipartApplyOption,
        saved_config: Option<NetworkState>,
    ) -> Result<NetworkState, NipartError> {
        if desired_state.is_empty() {
            log_info(
                conn.as_deref_mut(),
                "Desired state is empty, no action required".to_string(),
            )
            .await;
        }
        log_trace(
            conn.as_deref_mut(),
            format!("Apply {desired_state} with option {opt}"),
        )
        .await;

        let mut pre_apply_current_state = self
            .query_network_state(conn.as_deref_mut(), Default::default())
            .await?;
        pre_apply_current_state.dns_resolver =
            NipartNoDaemon::query_dns_resolver().await?;
        let revert_dns_resolver = pre_apply_current_state.dns_resolver.clone();

        let merged_state = MergedNetworkState::new(
            desired_state,
            pre_apply_current_state,
            saved_config,
            opt.clone(),
        )?;

        let state_to_save = merged_state.gen_state_for_save();
        log::debug!("State to save: {state_to_save}");

        let revert_state = merged_state.generate_revert()?;
        let revert_dns = RevertDns {
            resolver: revert_dns_resolver,
            dynamic_servers: merged_state.dns.apply_dynamic_servers(),
        };

        // TODO(Gris Ge): discard auto IPs

        // Suppress the monitor during applying
        self.monitor_manager.pause().await?;
        let result = self
            .apply_network_state_inner(
                conn.as_deref_mut(),
                merged_state,
                state_to_save,
                revert_state,
                revert_dns,
            )
            .await;
        // Always resume the monitor, even when the apply failed: a pause
        // left behind here would make the daemon deaf to link events (e.g.
        // wifi re-association) for the rest of its life.
        self.monitor_manager.resume().await?;
        let (merged_state, saved_state) = result?;

        // A changed default gateway makes upstreams which were unreachable
        // reachable again: let the DNS cache retry the upstream groups it
        // marked dead instead of waiting out their retry backoff.
        self.notify_dns_cache_on_gateway_change(&merged_state).await;

        let mut diff_state = match merged_state.gen_diff() {
            Ok(s) => s,
            Err(e) => {
                log_warn(
                    conn,
                    format!("Returning full state instead of diff state: {e}"),
                )
                .await;
                merged_state.gen_state_for_apply()
            }
        };
        diff_state.hide_secrets();

        self.try_set_daemon_online(Some(&saved_state), None).await?;

        Ok(diff_state)
    }

    /// Apply `merged_state` with the interface monitor paused.
    ///
    /// The caller pauses the monitor and resumes it on every code path, so
    /// this function only has to report the state needed afterwards: the
    /// `merged_state` for the diff state and the saved state for
    /// `try_set_daemon_online()`.
    async fn apply_network_state_inner(
        &mut self,
        mut conn: Option<&mut NipartIpcConnection>,
        merged_state: MergedNetworkState,
        state_to_save: NetworkState,
        revert_state: NetworkState,
        revert_dns: RevertDns,
    ) -> Result<(MergedNetworkState, NetworkState), NipartError> {
        if let Err(e) = self
            .apply_merged_state(conn.as_deref_mut(), &merged_state)
            .await
        {
            log_warn(
                conn.as_deref_mut(),
                format!("Failed to apply desired state: {e}"),
            )
            .await;
            log_debug(
                conn.as_deref_mut(),
                format!("Failed to apply merged state: {merged_state}"),
            )
            .await;
            log_warn(
                conn.as_deref_mut(),
                "Rollback to state before apply".to_string(),
            )
            .await;
            log_trace(
                conn.as_deref_mut(),
                format!("Rollback to state before apply {revert_state}"),
            )
            .await;
            if let Err(e) = self
                .rollback(conn.as_deref_mut(), revert_state, revert_dns)
                .await
            {
                log_error(conn, format!("Failed to rollback: {e}")).await;
            }
            return Err(e);
        }

        if !merged_state.option.memory_only
            && let Err(e) = self.conf_manager.save_state(state_to_save).await
        {
            log_warn(
                conn,
                format!("BUG: Failed to persistent desired state: {e}"),
            )
            .await;
        }

        let saved_state = self.conf_manager.query_state().await?;

        self.monitor_manager
            .setup_monitor(&merged_state, &saved_state)
            .await?;

        Ok((merged_state, saved_state))
    }

    async fn rollback(
        &mut self,
        mut conn: Option<&mut NipartIpcConnection>,
        revert_state: NetworkState,
        revert_dns: RevertDns,
    ) -> Result<(), NipartError> {
        let mut opt = NipartApplyOption::default();
        opt.no_verify = true;

        // A failed partial apply that carried WIFI profiles (e.g.
        // `npt wifi connect` to an AP with an unsupported security mode)
        // made the wifi plugin replace its runtime network list with just
        // the requested profile. The generic revert below only removes
        // that profile, which would leave shuli with no network at all
        // and drop the previous connection until a manual `npt up`; hand
        // the saved profiles back after the revert so shuli reconnects to
        // the best remaining network by itself.
        let revert_touches_wifi = revert_state.ifaces.iter().any(|iface| {
            matches!(
                iface.iface_type(),
                InterfaceType::WifiCfg | InterfaceType::WifiPhy
            )
        });

        let current_state = self
            .query_network_state(conn.as_deref_mut(), Default::default())
            .await?;
        let mut merged_state = MergedNetworkState::new(
            revert_state,
            current_state,
            None,
            opt.clone(),
        )?;

        let apply_state = merged_state.gen_state_for_apply();

        NipartNoDaemon::apply_merged_state(&mut merged_state).await?;
        apply_dns_resolver(
            &mut self.dns_manager,
            &revert_dns.resolver,
            &revert_dns.dynamic_servers,
        )
        .await?;
        self.plugin_manager
            .apply_network_state(&apply_state, &opt)
            .await?;
        if revert_touches_wifi {
            self.restore_saved_wifi_profiles().await?;
        }

        self.dhcpv4_manager
            .apply_dhcp_config(
                conn.as_deref_mut(),
                &merged_state,
                &mut self.plugin_manager,
            )
            .await?;
        self.dhcpv6_manager
            .apply_dhcp_config(conn, &merged_state, &mut self.plugin_manager)
            .await?;

        // The rollback restored the routes of the state before the failed
        // apply, which may have changed the default gateway as well.
        self.notify_dns_cache_on_gateway_change(&merged_state).await;

        Ok(())
    }

    /// Hand the saved WIFI profiles back to the wifi plugin after a
    /// rollback.
    ///
    /// A successful apply persists the desired profiles and the plugin
    /// rebuilds its runtime network list from the applied state. A failed
    /// partial apply (e.g. `npt wifi connect` to an AP shuli cannot
    /// join) already replaced that runtime list with just the requested
    /// profile, and reverting only removes the profile: without this
    /// restore shuli would be left with no network and the previous
    /// connection would only return with a manual `npt up`.
    ///
    /// The restore is `memory-only` (the saved state is unchanged) and
    /// applies only to the plugin: the link-up event path configures the
    /// IP stack again once shuli associates.
    async fn restore_saved_wifi_profiles(&mut self) -> Result<(), NipartError> {
        let saved_state = self.conf_manager.query_state().await?;
        let wifi_state = saved_wifi_restore_state(&saved_state);
        if wifi_state.is_empty() {
            return Ok(());
        }
        log::info!("Restoring saved WIFI profiles after rollback");
        let opt = NipartApplyOption::new().memory_only().no_verify();
        self.plugin_manager
            .apply_network_state(&wifi_state, &opt)
            .await
    }

    async fn verify(
        &mut self,
        mut conn: Option<&mut NipartIpcConnection>,
        merged_state: &MergedNetworkState,
    ) -> Result<(), NipartError> {
        let mut post_apply_current_state = self
            .query_network_state(conn.as_deref_mut(), Default::default())
            .await?;
        pretend_config_is_saved(&mut post_apply_current_state, merged_state);

        log_trace(
            conn,
            format!("Post apply network state: {post_apply_current_state}"),
        )
        .await;
        merged_state.verify(&post_apply_current_state)?;
        verify_dns(merged_state, &post_apply_current_state)?;
        self.try_set_daemon_online(None, Some(&post_apply_current_state))
            .await?;
        Ok(())
    }

    // Apply state to plugin/dhcp/kernel and verify, but don't do these tasks:
    //  * Checkpoint rollback
    //  * Config save
    //  * Setup monitor session
    //
    // Every apply (user request, boot activation and link event) goes through
    // the top-level retry: a retriable failure retries the full apply after
    // [APPLY_RETRY_INTERVAL_SEC] until [APPLY_RETRY_MAX] attempts are used.
    pub(crate) async fn apply_merged_state(
        &mut self,
        mut conn: Option<&mut NipartIpcConnection>,
        merged_state: &MergedNetworkState,
    ) -> Result<(), NipartError> {
        let mut last_err: Option<NipartError> = None;
        for attempt in 1..=APPLY_RETRY_MAX {
            match self
                .apply_merged_state_once(conn.as_deref_mut(), merged_state)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !e.kind().retriable() {
                        log_warn(
                            conn.as_deref_mut(),
                            format!(
                                "Apply failed with non-retriable error: {e}"
                            ),
                        )
                        .await;
                        return Err(e);
                    }
                    log_warn(
                        conn.as_deref_mut(),
                        format!(
                            "Apply failed (attempt \
                             {attempt}/{APPLY_RETRY_MAX}), retrying in \
                             {APPLY_RETRY_INTERVAL_SEC} seconds: {e}"
                        ),
                    )
                    .await;
                    last_err = Some(e);
                    if attempt < APPLY_RETRY_MAX {
                        tokio::time::sleep(std::time::Duration::from_secs(
                            APPLY_RETRY_INTERVAL_SEC,
                        ))
                        .await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            NipartError::new(
                ErrorKind::Bug,
                "BUG: apply retry loop finished without an error".to_string(),
            )
        }))
    }

    async fn apply_merged_state_once(
        &mut self,
        mut conn: Option<&mut NipartIpcConnection>,
        merged_state: &MergedNetworkState,
    ) -> Result<(), NipartError> {
        let apply_state = merged_state.gen_state_for_apply();

        log_trace(conn.as_deref_mut(), format!("apply_state {apply_state}"))
            .await;

        let mut merged_state_for_no_daemon = merged_state.clone();
        // Remove interfaces for conditional activating
        merged_state_for_no_daemon.remove_conditional_activation();

        NipartNoDaemon::apply_merged_state(&mut merged_state_for_no_daemon)
            .await?;
        self.apply_dns(merged_state).await?;
        self.plugin_manager
            .apply_network_state(&apply_state, &merged_state.option)
            .await?;

        // An explicit WIFI connect request must not be reported as
        // applied before the association finished: the generic
        // verification cannot see a `wifi-cfg` profile (it is
        // userspace-only and the post-apply state is synthesized from the
        // saved config), so a wrong password would otherwise surface only
        // as a background retry loop while the apply reports success. A
        // failure here triggers the normal rollback.
        if !merged_state.option.no_verify {
            self.wait_wifi_connect_requests(&wifi_connect_requests(
                merged_state,
            ))
            .await?;
        }

        self.dhcpv4_manager
            .apply_dhcp_config(
                conn.as_deref_mut(),
                merged_state,
                &mut self.plugin_manager,
            )
            .await?;
        self.dhcpv6_manager
            .apply_dhcp_config(
                conn.as_deref_mut(),
                merged_state,
                &mut self.plugin_manager,
            )
            .await?;

        let mut result: Result<(), NipartError> = Ok(());
        if !merged_state.option.no_verify {
            let retry_count = if merged_state.ifaces.iter().any(|iface| {
                matches!(
                    iface.merged.iface_type(),
                    InterfaceType::WifiPhy | InterfaceType::WifiCfg
                )
            }) {
                WIFI_RETRY_COUNT
            } else {
                RETRY_COUNT
            };
            for cur_retry_count in 1..(retry_count + 1) {
                result = self
                    .verify(conn.as_deref_mut(), &merged_state_for_no_daemon)
                    .await;
                if let Err(e) = &result {
                    log_info(
                        conn.as_deref_mut(),
                        format!(
                            "Retrying({cur_retry_count}/{retry_count}) on \
                             verification error: {e}"
                        ),
                    )
                    .await;
                    tokio::time::sleep(std::time::Duration::from_millis(
                        RETRY_INTERVAL_MS,
                    ))
                    .await;
                } else {
                    break;
                }
            }
        }
        result
    }

    /// Wait until every WIFI SSID this apply explicitly requested is
    /// connected.
    ///
    /// Only the wifi plugin's live connection state counts: the kernel
    /// reports the SSID as soon as the association completed, which
    /// happens before the 4-way handshake, so a wrong password would
    /// otherwise look connected during the failed handshake. While
    /// waiting, the plugin's latched connection errors are polled so a
    /// wrong password or an unsupported security fails the apply with
    /// the real reason instead of a timeout.
    async fn wait_wifi_connect_requests(
        &mut self,
        requests: &[WifiConnectRequest],
    ) -> Result<(), NipartError> {
        if requests.is_empty() {
            return Ok(());
        }
        // A profile applied before any wifi-phy exists (e.g. boot config
        // for a hot-plugged NIC) is only saved: the plugin has no device
        // to connect on, and the monitor worker hands the profile to the
        // plugin when the phy appears later. Waiting here would fail the
        // apply for a connection which is not expected yet.
        let kernel_state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;
        let phy_names = wifi_phy_names(&kernel_state);
        if phy_names.is_empty() {
            log::debug!(
                "No WIFI phy present, skipping the WIFI connection wait"
            );
            return Ok(());
        }
        let groups = wifi_connect_groups(requests, &phy_names);
        let initial_state = self.wifi_plugin_live_state(&kernel_state).await?;
        let initial_connected = connected_wifi_phys(&initial_state);
        log::debug!(
            "Waiting for WIFI connection to {:?}",
            requests.iter().map(|r| &r.ssid).collect::<Vec<_>>()
        );
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(WIFI_CONNECT_WAIT_TIMEOUT_SECS);
        loop {
            let kernel_state = NipartNoDaemon::query_network_state(
                NipartQueryOption::running(),
            )
            .await?;
            let live_state = self.wifi_plugin_live_state(&kernel_state).await?;
            let pending: Vec<&WifiConnectGroup> = groups
                .iter()
                .filter(|group| !wifi_group_is_connected(&live_state, group))
                .collect();
            if pending.is_empty() {
                // The association happened while the monitor was paused:
                // its resume link dump carries no SSID, so the monitor
                // would drop the event as "unchanged" and the wifi-cfg
                // IP and routes would never be applied. Ask it to emit
                // the event for the phys this apply connected.
                self.forget_changed_wifi_phys(&initial_connected, &live_state)
                    .await?;
                return Ok(());
            }
            for group in &pending {
                let candidates: Vec<&String> = match group.phy_name.as_ref() {
                    Some(phy_name) => vec![phy_name],
                    None => phy_names.iter().collect(),
                };
                for phy_name in candidates {
                    for ssid in &group.ssids {
                        if let Err(e) = self
                            .plugin_manager
                            .wifi_connect_error(
                                &NipartWifiConnectErrorOption::new(
                                    phy_name, ssid,
                                ),
                            )
                            .await
                        {
                            if is_fatal_wifi_connect_error(e.kind()) {
                                return Err(e);
                            }
                            log::debug!(
                                "wifi connection error query on \
                                 {phy_name}/{ssid}: {e}"
                            );
                        }
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(NipartError::new(
                    ErrorKind::Timeout,
                    format!(
                        "Timed out waiting for WIFI connection to {}",
                        pending
                            .iter()
                            .map(|group| format!(
                                "SSID '{}'",
                                group.ssids.join("' or '")
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(
                RETRY_INTERVAL_MS,
            ))
            .await;
        }
    }

    /// The wifi plugin's live connection state, merged into one
    /// `NetworkState`.
    async fn wifi_plugin_live_state(
        &mut self,
        kernel_state: &NetworkState,
    ) -> Result<NetworkState, NipartError> {
        let mut live_state = NetworkState::default();
        for plugin_state in self
            .plugin_manager
            .query_network_state(NipartQueryOption::running(), kernel_state)
            .await?
        {
            live_state.merge(&plugin_state)?;
        }
        Ok(live_state)
    }

    /// Tell the monitor which wifi-phys this apply connected.
    ///
    /// The monitor was paused while the plugin connected, so its resume
    /// link dump cannot tell the SSID changed (the dump carries no
    /// SSID). Without this the event would be dropped as unchanged and
    /// the `wifi-cfg` IP config and routes would never be applied.
    async fn forget_changed_wifi_phys(
        &mut self,
        initial_connected: &HashSet<(String, String)>,
        current: &NetworkState,
    ) -> Result<(), NipartError> {
        let mut changed_phys: Vec<String> = connected_wifi_phys(current)
            .difference(initial_connected)
            .map(|(iface_name, _)| iface_name.clone())
            .collect();
        changed_phys.sort_unstable();
        changed_phys.dedup();
        if !changed_phys.is_empty() {
            log::debug!(
                "WIFI associated while monitor paused, requesting link events \
                 for {changed_phys:?}"
            );
            self.monitor_manager
                .forget_paused_state(&changed_phys)
                .await?;
        }
        Ok(())
    }

    /// Apply DNS resolver configuration: `/etc/resolv.conf` and the DNS
    /// cache daemon task.
    async fn apply_dns(
        &mut self,
        merged_state: &MergedNetworkState,
    ) -> Result<(), NipartError> {
        if merged_state.dns.is_unchanged() {
            // `dns-resolver` not mentioned: preserve both the host
            // resolver configuration and the running cache.
            return Ok(());
        }
        let auto_dns_servers = self.auto_dns_servers().await?;
        NipartNoDaemon::apply_dns_resolver_conf(
            merged_state
                .dns
                .cache()
                .filter(|cache| cache.enabled)
                .and_then(|cache| cache.bind_addr())
                .map(|addr| addr.ip()),
            &merged_state.dns.servers,
            &merged_state.dns.searches,
            &merged_state.dns.options,
            &merged_state.dns.apply_dynamic_servers(),
        )
        .await?;
        self.dns_manager
            .apply_config(merged_state.dns.cache(), &auto_dns_servers)
            .await
    }
}

/// Apply a previous DNS resolver state during rollback.
async fn apply_dns_resolver(
    dns_manager: &mut super::dns::NipartDnsManager,
    resolver: &DnsResolver,
    dynamic_servers: &[String],
) -> Result<(), NipartError> {
    let config = resolver.config.clone().unwrap_or_default();
    let servers = config.server.clone().unwrap_or_default();
    let searches = config.search.clone().unwrap_or_default();
    let options = config.options.clone().unwrap_or_default();
    let cache_bind_ip = resolver
        .cache
        .as_ref()
        .filter(|cache| cache.enabled)
        .and_then(|cache| cache.bind_addr())
        .map(|addr| addr.ip());
    NipartNoDaemon::apply_dns_resolver_conf(
        cache_bind_ip,
        &servers,
        &searches,
        &options,
        dynamic_servers,
    )
    .await?;
    dns_manager.apply_config(resolver.cache.as_ref(), &[]).await
}

/// Make the daemon-only config visible to the verification.
///
/// The wifi config and the `auto-connect` property are stored into config
/// manager by the daemon only: the kernel never reports them and the config
/// manager is only updated after this verification passed, hence the queried
/// post-apply state cannot carry them. In order to pass the verification,
/// pretend the config is stored already: adjust the post-apply state to the
/// state which is going to be saved.
///
/// The `for_apply` state cannot be used for the `auto-connect`: it is a diff
/// which only holds properties requiring changes, hence an unchanged
/// `auto-connect` is absent there and pretending it would erase the queried
/// value (e.g. re-applying an unchanged config with `auto-connect: false`).
fn pretend_config_is_saved(
    post_apply_state: &mut NetworkState,
    merged_state: &MergedNetworkState,
) {
    // An absent/down wifi-cfg must not be injected: it is a virtual
    // interface, so the verification would reject it as still present after
    // the removal.
    for merged_iface in merged_state.ifaces.user_ifaces.values() {
        let Some(Interface::WifiCfg(iface)) = merged_iface.desired.as_ref()
        else {
            continue;
        };
        if iface.is_up() {
            post_apply_state
                .ifaces
                .push(Interface::WifiCfg(Box::new(*iface.clone())));
        } else {
            // The saved profile is only replaced after verification, so drop
            // it from the post-apply view when it is being removed.
            post_apply_state
                .ifaces
                .user_ifaces
                .remove(&(iface.name().to_string(), InterfaceType::WifiCfg));
        }
    }

    for merged_iface in merged_state.ifaces.iter() {
        let Some(auto_connect) = merged_iface
            .for_save
            .as_ref()
            .and_then(|iface| iface.base_iface().auto_connect.clone())
        else {
            continue;
        };
        if let Some(post_apply_iface) = post_apply_state
            .ifaces
            .get_mut(merged_iface.merged.base_iface())
        {
            post_apply_iface.base_iface_mut().auto_connect = Some(auto_connect);
        }
    }
}

/// Verify the applied DNS resolver state.
///
/// The daemon cannot query a cache server through the plugin path, so it
/// checks the `/etc/resolv.conf` view: the static servers, search domains,
/// options and the cache bind address must all be present.
fn verify_dns(
    merged_state: &MergedNetworkState,
    post_apply_state: &NetworkState,
) -> Result<(), NipartError> {
    if merged_state.dns.is_unchanged() {
        return Ok(());
    }
    let running = match post_apply_state.dns_resolver.running.as_ref() {
        Some(running) => running,
        None => {
            return Err(NipartError::new(
                ErrorKind::VerificationError,
                "DNS resolver running state is not available after apply"
                    .to_string(),
            ));
        }
    };
    let servers = running.server.as_deref().unwrap_or_default();
    let searches = running.search.as_deref().unwrap_or_default();
    let options = running.options.as_deref().unwrap_or_default();

    for srv in &merged_state.dns.servers {
        if !servers.contains(srv) {
            return Err(NipartError::new(
                ErrorKind::VerificationError,
                format!(
                    "DNS server {srv} is not present in /etc/resolv.conf \
                     after apply"
                ),
            ));
        }
    }
    for search in &merged_state.dns.searches {
        if !searches.contains(search) {
            return Err(NipartError::new(
                ErrorKind::VerificationError,
                format!(
                    "DNS search domain {search} is not present in \
                     /etc/resolv.conf after apply"
                ),
            ));
        }
    }
    for opt in &merged_state.dns.options {
        if !options.contains(opt) {
            return Err(NipartError::new(
                ErrorKind::VerificationError,
                format!(
                    "DNS option {opt} is not present in /etc/resolv.conf \
                     after apply"
                ),
            ));
        }
    }
    if let Some(cache_ip) = merged_state
        .dns
        .cache()
        .filter(|cache| cache.enabled)
        .and_then(|cache| cache.bind_addr())
        .map(|addr| addr.ip().to_string())
    {
        match servers.first() {
            Some(first) if first == &cache_ip => (),
            _ => {
                return Err(NipartError::new(
                    ErrorKind::VerificationError,
                    format!(
                        "DNS cache bind address {cache_ip} is not the first \
                         nameserver in /etc/resolv.conf after apply"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// The subset of a saved state that hands the WIFI profiles back to the
/// plugin after a rollback: the wifi-phy and every auto-connectable
/// wifi-cfg profile.
///
/// `auto-connect: false` profiles are only activated by an explicit apply
/// action and absent profiles were removed, so neither may come back
/// implicitly.
fn saved_wifi_restore_state(saved_state: &NetworkState) -> NetworkState {
    let mut wifi_state = NetworkState::default();
    for iface in saved_state.ifaces.iter() {
        if iface.is_absent()
            || iface.base_iface().auto_connect
                == Some(InterfaceAutoConnect::Manual)
        {
            continue;
        }
        if matches!(
            iface.iface_type(),
            InterfaceType::WifiCfg | InterfaceType::WifiPhy
        ) {
            wifi_state.ifaces.push(iface.clone());
        }
    }
    wifi_state
}

#[cfg(test)]
#[path = "unit_tests/apply.rs"]
mod tests;
