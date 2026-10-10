// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use futures_channel::mpsc::UnboundedSender;
use nipart::{
    BaseInterface, DnsResolver, Interface, InterfaceIdentifier, InterfaceIpv4,
    InterfaceIpv6, InterfaceState, InterfaceType, NetworkState,
    NipartApplyOption, NipartError, NipartInterface, NipartNoDaemon,
    NipartQueryOption, NipartWifiControl, NipartWifiScanOption, WifiScanResult,
};

use super::{
    conf::NipartConfManager,
    daemon::NipartManagerCmd,
    dhcp::{NipartDhcpV4Manager, NipartDhcpV6Manager},
    dns::NipartDnsManager,
    event::{NipartEventManager, is_route_matching_iface},
    monitor::NipartMonitorManager,
    plugin::NipartPluginManager,
};

/// Commander manages all the task managers.
/// This struct is safe to clone and move to threads
#[derive(Debug, Clone)]
pub(crate) struct NipartCommander {
    pub(crate) dhcpv4_manager: NipartDhcpV4Manager,
    pub(crate) dhcpv6_manager: NipartDhcpV6Manager,
    pub(crate) dns_manager: NipartDnsManager,
    pub(crate) monitor_manager: NipartMonitorManager,
    pub(crate) conf_manager: NipartConfManager,
    pub(crate) plugin_manager: NipartPluginManager,
    pub(crate) event_manager: NipartEventManager,
}

impl NipartCommander {
    pub(crate) async fn new(
        sender: UnboundedSender<NipartManagerCmd>,
    ) -> Result<Self, NipartError> {
        let mut ret = Self {
            dhcpv4_manager: NipartDhcpV4Manager::new(sender.clone()).await?,
            dhcpv6_manager: NipartDhcpV6Manager::new().await?,
            dns_manager: NipartDnsManager::new().await?,
            monitor_manager: NipartMonitorManager::new(sender.clone()).await?,
            conf_manager: NipartConfManager::new().await?,
            plugin_manager: NipartPluginManager::new().await?,
            event_manager: NipartEventManager::new().await?,
        };
        ret.event_manager.set_commander(ret.clone()).await?;

        Ok(ret)
    }

    /// Shut down all task workers, waiting for each to finish so that
    /// their Drop-based cleanup (e.g. killing plugin child processes)
    /// completes before the daemon exits.
    pub(crate) async fn shutdown(&self) {
        self.plugin_manager.shutdown().await;
        self.monitor_manager.shutdown().await;
        self.dhcpv4_manager.shutdown().await;
        self.dhcpv6_manager.shutdown().await;
        self.dns_manager.shutdown().await;
        self.conf_manager.shutdown().await;
        self.event_manager.shutdown().await;
    }

    /// Apply the boot saved state and start the interface monitor.
    ///
    /// The non-NIC saved state (virtual interfaces, global routes and route
    /// rules) is applied directly: no link event will ever announce those.
    /// The interface monitor is then started; its initial link dump is
    /// applied by the event worker as one batch, which performs the boot
    /// activation of the physical interfaces (including wifi).
    ///
    /// The monitor is started even when loading the boot state fails,
    /// otherwise the daemon would stay deaf to link events for the rest of
    /// its life.  `Start` is idempotent and emits an empty initial batch
    /// when there is no watch, so the boot transaction lock is still
    /// released.
    pub(crate) async fn boot_apply(&mut self) -> Result<(), NipartError> {
        match self.boot_apply_inner().await {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Err(start_err) = self.monitor_manager.start().await {
                    log::error!(
                        "Failed to start interface monitor after boot \
                         failure: {start_err}"
                    );
                }
                Err(e)
            }
        }
    }

    async fn boot_apply_inner(&mut self) -> Result<(), NipartError> {
        let mut saved_state = self.conf_manager.query_state().await?;
        // Interfaces with `auto-connect: false` are only activated upon
        // explicit apply action, not at boot.
        remove_manual_activation(&mut saved_state);
        // The DNS resolver is not tied to a kernel NIC: the cache server is
        // a daemon task and `/etc/resolv.conf` is not part of the kernel
        // state, so it is restored once here.  Do not abort boot on a DNS
        // failure: the interfaces still need to be applied and a later
        // `npt apply` can retry the DNS configuration.
        let saved_dns_resolver = saved_state.dns_resolver.clone();
        if !saved_dns_resolver.is_empty()
            && let Err(e) =
                self.restore_saved_dns_resolver(&saved_dns_resolver).await
        {
            log::warn!(
                "Failed to restore saved DNS resolver configuration: {e}"
            );
        }
        let cur_state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;
        let non_nic_state = gen_non_nic_state(&saved_state, &cur_state);
        if !non_nic_state.is_empty() {
            log::debug!("Applying non-NIC saved state: {non_nic_state}");
            if let Err(e) = self
                .apply_network_state_with_saved_config(
                    None,
                    non_nic_state,
                    NipartApplyOption::new()
                        .no_verify()
                        .memory_only()
                        .restart_auto_ip(),
                    Some(saved_state.clone()),
                )
                .await
            {
                // Do not abort boot: the monitor still needs to start so
                // the physical interfaces get applied.
                log::warn!(
                    "Failed to apply non-NIC saved state, will continue: {e}"
                );
            }
        }
        // Register the watches before starting the monitor: no event can
        // reach the event worker before `start()` emits the initial dump.
        self.monitor_manager
            .setup_saved_state_monitors(&saved_state, true)
            .await?;
        self.monitor_manager.start().await?;
        Ok(())
    }

    /// Restore the saved DNS resolver configuration at daemon startup.
    ///
    /// Start the DNS cache when the saved configuration enables it and
    /// rewrite `/etc/resolv.conf` with the saved static configuration.
    /// Nameservers which nipart never wrote (e.g. learned from
    /// DHCP/IPv6-RA/VPN) are kept.
    async fn restore_saved_dns_resolver(
        &mut self,
        saved: &DnsResolver,
    ) -> Result<(), NipartError> {
        let auto_dns_servers = self.auto_dns_servers().await?;
        let config = saved.config.clone().unwrap_or_default();
        let static_servers = config.server.clone().unwrap_or_default();
        let cache_bind_ip = saved
            .cache
            .as_ref()
            .filter(|cache| cache.enabled)
            .and_then(|cache| cache.bind_addr())
            .map(|addr| addr.ip());
        let cache_bind_str = cache_bind_ip.map(|ip| ip.to_string());

        // The static configuration of the saved state is what nipart
        // wrote into `/etc/resolv.conf` before; every other nameserver in
        // the file was learned dynamically or added by another tool and
        // must be kept.
        let dynamic_servers: Vec<String> = NipartNoDaemon::query_dns_resolver()
            .await?
            .running
            .and_then(|running| running.server)
            .unwrap_or_default()
            .into_iter()
            .filter(|srv| {
                !static_servers.contains(srv)
                    && cache_bind_str.as_deref() != Some(srv.as_str())
            })
            .collect();

        NipartNoDaemon::apply_dns_resolver_conf(
            cache_bind_ip,
            &static_servers,
            &config.search.clone().unwrap_or_default(),
            &config.options.clone().unwrap_or_default(),
            &dynamic_servers,
        )
        .await?;
        log::info!(
            "Restored saved DNS resolver configuration: {} static \
             nameserver(s), cache {}",
            static_servers.len(),
            if cache_bind_ip.is_some() {
                "enabled"
            } else {
                "disabled"
            }
        );
        self.dns_manager
            .apply_config(saved.cache.as_ref(), &auto_dns_servers)
            .await
    }

    pub(crate) async fn wifi_scan(
        &mut self,
        opt: NipartWifiScanOption,
    ) -> Result<Vec<WifiScanResult>, NipartError> {
        // Hidden-SSID probe targets (`opt.hidden_ssids`) are filled by the
        // CLI (--with-hidden) and the currently connected SSID (added by
        // the wifi plugin from live network state); a hidden SSID is only
        // reported when it is explicitly probed for.
        self.plugin_manager.wifi_scan(opt).await
    }

    pub(crate) async fn wifi_control(
        &mut self,
        control: NipartWifiControl,
    ) -> Result<(), NipartError> {
        self.plugin_manager.wifi_control(control).await?;
        if control == NipartWifiControl::Off {
            self.purge_wifi_phy_ip_stack().await?;
        }
        Ok(())
    }

    /// Notify every plugin that the host resumed from suspend.
    ///
    /// The wifi plugin forwards this to shuli so a connection that was
    /// lost during suspend is re-established without waiting out the
    /// retry backoff.  Plugins without resume support are ignored by the
    /// plugin manager.
    pub(crate) async fn notify_system_resume(
        &mut self,
    ) -> Result<(), NipartError> {
        self.plugin_manager.system_resume().await
    }

    /// Purge IP and routes of every active wifi-phy interface.
    ///
    /// Disabling WIFI only tells the plugin to disconnect; the kernel
    /// keeps the addresses and routes unless the daemon disables the IP
    /// stack explicitly.  The apply is memory-only so the saved profiles
    /// stay intact and `npt wifi on` can restore them through the normal
    /// link-event path.
    async fn purge_wifi_phy_ip_stack(&mut self) -> Result<(), NipartError> {
        let cur_state =
            self.query_network_state(None, Default::default()).await?;
        let desired_state = gen_wifi_off_purge_state(&cur_state);
        if desired_state.is_empty() {
            return Ok(());
        }
        let opt = NipartApplyOption::new().memory_only();
        self.apply_network_state_with_saved_config(
            None,
            desired_state,
            opt,
            None,
        )
        .await?;
        Ok(())
    }

    /// Re-apply the saved routes of a DHCPv4 interface after its lease was
    /// applied by the DHCP worker.
    ///
    /// When a DHCP address expires, the kernel removes the connected route
    /// of its prefix and every route whose next hop belongs to that prefix,
    /// even when the route has the `onlink` flag.  The DHCP worker then
    /// installs the new address, but it has no knowledge of the saved
    /// static routes, so without this reconciliation the routes stay missing
    /// until an unrelated link event or apply restores them.
    pub(crate) async fn reconcile_saved_routes_for_dhcpv4_iface(
        &mut self,
        kernel_iface_name: &str,
    ) -> Result<(), NipartError> {
        let saved_state = self.conf_manager.query_state().await?;
        let cur_state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;
        let desired_state = gen_saved_route_reconcile_state(
            &saved_state,
            &cur_state,
            kernel_iface_name,
        );
        if desired_state
            .routes
            .config
            .as_ref()
            .is_none_or(|routes| routes.is_empty())
        {
            return Ok(());
        }
        log::debug!(
            "Re-applying saved routes for interface {kernel_iface_name} after \
             DHCPv4 lease change: {desired_state}"
        );
        NipartNoDaemon::apply_network_state(
            desired_state,
            NipartApplyOption::new().memory_only().no_verify(),
        )
        .await?;
        Ok(())
    }
}

/// Build the state needed to restore the saved routes of a DHCPv4 kernel
/// interface.
///
/// The matching saved interface is included so the merged route state can
/// resolve profile names and set the `onlink` flag for DHCP interfaces.
/// Routes of other interfaces are deliberately left out: this apply only
/// repairs what the DHCP worker may have lost.
fn gen_saved_route_reconcile_state(
    saved_state: &NetworkState,
    cur_state: &NetworkState,
    kernel_iface_name: &str,
) -> NetworkState {
    let mut ret = NetworkState::default();
    let mut added_ifaces: HashSet<String> = HashSet::new();
    for saved_iface in saved_state.ifaces.iter() {
        let Some(cur_iface) =
            match_kernel_iface_for_saved_iface(saved_iface, cur_state)
        else {
            continue;
        };
        if cur_iface.kernel_iface_name() != kernel_iface_name {
            continue;
        }
        let mut has_route = false;
        if let Some(saved_routes) = saved_state.routes.config.as_ref() {
            for route in saved_routes
                .iter()
                .filter(|route| is_route_matching_iface(route, saved_iface))
            {
                ret.routes
                    .config
                    .get_or_insert_default()
                    .push(route.clone());
                has_route = true;
            }
        }
        if has_route && added_ifaces.insert(saved_iface.name().to_string()) {
            ret.ifaces.push(saved_iface.clone());
        }
    }
    if let Some(routes) = ret.routes.config.as_mut() {
        routes.sort_unstable();
        routes.dedup();
    }
    ret
}

/// Find the kernel interface a saved config applies its DHCP to: a
/// wifi-cfg maps to the wifi-phy carrying its SSID, all other configs
/// match by kernel name or MAC address.
fn match_kernel_iface_for_saved_iface<'a>(
    saved_iface: &Interface,
    cur_state: &'a NetworkState,
) -> Option<&'a Interface> {
    if let Interface::WifiCfg(wifi_cfg) = saved_iface {
        let ssid = wifi_cfg.ssid()?;
        return cur_state.ifaces.kernel_ifaces.values().find(|cur_iface| {
            cur_iface.iface_type() == &InterfaceType::WifiPhy
                && matches!(
                    cur_iface,
                    Interface::WifiPhy(wifi_phy)
                        if wifi_phy.ssid() == Some(ssid)
                )
        });
    }
    let base = saved_iface.base_iface();
    let saved_mac = if base.identifier == Some(InterfaceIdentifier::MacAddress)
    {
        base.mac_address.as_deref().map(|m| m.to_ascii_uppercase())
    } else {
        None
    };
    cur_state.ifaces.kernel_ifaces.values().find(|cur_iface| {
        let cur_base = cur_iface.base_iface();
        saved_iface.kernel_iface_name() == cur_iface.kernel_iface_name()
            || saved_iface.name() == cur_iface.kernel_iface_name()
            || saved_mac.as_deref().is_some_and(|saved_mac| {
                cur_base
                    .mac_address
                    .as_deref()
                    .map(|m| m.to_ascii_uppercase() == saved_mac)
                    .unwrap_or(false)
            })
    })
}

/// Remove interfaces with `auto-connect: false` from the state applied at
/// boot: those interfaces are only activated upon explicit apply action.
/// Interfaces depending on an excluded interface(ports of excluded
/// controller or children of excluded parent) and routes pointing to them
/// are also removed, otherwise the boot retry loop would never terminate.
fn remove_manual_activation(state: &mut NetworkState) {
    let mut excluded: Vec<String> = state
        .ifaces
        .iter()
        .filter(|i| {
            i.base_iface()
                .auto_connect
                .as_ref()
                .is_some_and(|a| a.is_manual())
        })
        .map(|i| i.name().to_string())
        .collect();

    // Interfaces depending on an excluded interface cannot be activated at
    // boot either.
    let mut changed = true;
    while changed {
        changed = false;
        for iface in state.ifaces.iter() {
            if excluded.iter().any(|n| n == iface.name()) {
                continue;
            }
            if let Some(dependency) = iface
                .base_iface()
                .controller
                .as_deref()
                .or_else(|| iface.parent())
                && excluded.iter().any(|n| n == dependency)
            {
                excluded.push(iface.name().to_string());
                changed = true;
            }
        }
    }

    if excluded.is_empty() {
        return;
    }

    for iface_name in excluded.as_slice() {
        if state.ifaces.kernel_ifaces.remove(iface_name).is_some() {
            log::info!(
                "Skipping interface {iface_name} at boot due to \
                 `auto-connect: false`"
            );
        }
    }
    state
        .ifaces
        .user_ifaces
        .retain(|(iface_name, _), _| !excluded.iter().any(|n| n == iface_name));

    if let Some(rts) = state.routes.config.as_mut() {
        rts.retain(|rt| {
            rt.next_hop_iface
                .as_ref()
                .is_none_or(|n| !excluded.iter().any(|e| e == n))
        });
    }
    if let Some(rules) = state.route_rules.config.as_mut() {
        rules.retain(|rule| {
            rule.iif
                .as_ref()
                .is_none_or(|n| !excluded.iter().any(|e| e == n))
        });
    }
}

fn gen_wifi_off_purge_state(cur_state: &NetworkState) -> NetworkState {
    let mut desired_state = NetworkState::default();
    for iface in cur_state.ifaces.kernel_ifaces.values().filter(|iface| {
        iface.iface_type() == &InterfaceType::WifiPhy
            && iface.base_iface().state.is_up()
    }) {
        let mut base = BaseInterface::new(
            iface.kernel_iface_name().to_string(),
            InterfaceType::WifiPhy,
        );
        base.state = InterfaceState::Up;
        base.ipv4 = Some(InterfaceIpv4::new_disabled());
        base.ipv6 = Some(InterfaceIpv6::new_disabled());
        desired_state.ifaces.push(base.into());
    }
    desired_state
}

/// Build the saved state which is not attached to a physical NIC and can
/// therefore not be activated by a link event: virtual interfaces and the
/// routes/route-rules that belong to them or are global.
///
/// `cur_state` decides which virtual interfaces this apply can actually
/// create: a virtual interface whose parent/ports exist now (directly or
/// through another creatable virtual) is ready.  The routes and route rules
/// referencing a virtual interface which cannot be created are left to the
/// event path: installing them now would fail because the interface does not
/// exist, and that failure would roll back the whole boot state.
fn gen_non_nic_state(
    saved_state: &NetworkState,
    cur_state: &NetworkState,
) -> NetworkState {
    let mut ret = NetworkState::default();
    for iface in saved_state.ifaces.iter() {
        if iface.is_virtual() {
            ret.ifaces.push(iface.clone());
        }
    }
    let creatable_names = gen_creatable_virtual_names(saved_state, cur_state);
    if let Some(routes) = saved_state.routes.config.as_ref() {
        for route in routes {
            let non_nic = match route.next_hop_iface.as_deref() {
                None => true,
                Some(next_hop) => creatable_names.contains(next_hop),
            };
            if non_nic {
                ret.routes
                    .config
                    .get_or_insert_default()
                    .push(route.clone());
            }
        }
    }
    // Route rules match selectors, not a link.  Only the global rules (no
    // `iif`) and the rules whose `iif` is a virtual interface this apply can
    // create are applied here; a rule naming a physical interface or a
    // virtual whose parent is absent is deferred to the event path.
    if let Some(rules) = saved_state.route_rules.config.as_ref() {
        ret.route_rules.config = Some(
            rules
                .iter()
                .filter(|rule| {
                    rule.iif
                        .as_deref()
                        .is_none_or(|iif| creatable_names.contains(iif))
                })
                .cloned()
                .collect(),
        );
    }
    ret
}

/// Names of the saved virtual interfaces which can exist after this apply: a
/// virtual interface already present in the kernel, or whose parent/ports all
/// belong to this set.  Userspace interfaces (e.g. OVS bridge, wifi-cfg) are
/// created by their plugin and count as ready.
fn gen_creatable_virtual_names(
    saved_state: &NetworkState,
    cur_state: &NetworkState,
) -> HashSet<String> {
    let mut ready: HashSet<String> =
        cur_state.ifaces.kernel_ifaces.keys().cloned().collect();
    let mut ret: HashSet<String> = HashSet::new();
    // Iterate to a fixpoint so a chain (VLAN over bond over eth0) is only
    // ready once its whole dependency chain is.
    loop {
        let mut changed = false;
        for iface in saved_state
            .ifaces
            .iter()
            .filter(|i| i.is_virtual() && !i.is_absent())
        {
            let names = virtual_iface_identity_names(iface);
            if names.iter().any(|name| ready.contains(name)) {
                ret.extend(names);
                continue;
            }
            let dependencies = if iface.is_userspace() {
                Vec::new()
            } else if iface.is_controller() {
                iface.ports().unwrap_or_default()
            } else if let Some(parent) = iface.parent() {
                vec![parent]
            } else {
                Vec::new()
            };
            if dependencies.iter().all(|dep| ready.contains(*dep)) {
                ret.extend(names.iter().cloned());
                ready.extend(names);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    ret
}

fn virtual_iface_identity_names(iface: &Interface) -> Vec<String> {
    let mut ret = vec![iface.name().to_string()];
    if !iface.kernel_iface_name().is_empty() {
        ret.push(iface.kernel_iface_name().to_string());
    }
    if let Some(profile) = iface.base_iface().profile_name.as_deref() {
        ret.push(profile.to_string());
    }
    ret
}

#[cfg(test)]
#[path = "unit_tests/commander.rs"]
mod tests;
