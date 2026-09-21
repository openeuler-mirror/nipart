// SPDX-License-Identifier: Apache-2.0

use nipart::{
    DnsResolver, ErrorKind, Interface, InterfaceType, MergedNetworkState,
    NetworkState, NipartApplyOption, NipartError, NipartInterface,
    NipartIpcConnection, NipartNoDaemon,
};

use super::commander::NipartCommander;
use crate::{log_debug, log_error, log_info, log_trace, log_warn};

const RETRY_COUNT: usize = 10;
// WIFI association can legitimately take longer than a kernel link change:
// shuli's first host-side scan may miss the AP and retry after its scan
// backoff (10s on mac80211_hwsim), so give wifi applies a longer window
// before verification gives up.
const WIFI_RETRY_COUNT: usize = 60;
const RETRY_INTERVAL_MS: u64 = 500;

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
    pub(crate) async fn apply_merged_state(
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

#[cfg(test)]
#[path = "unit_tests/apply.rs"]
mod tests;
