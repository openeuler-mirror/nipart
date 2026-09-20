// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

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
    event::NipartEventManager,
    monitor::NipartMonitorManager,
    plugin::NipartPluginManager,
    udev::udev_net_device_is_initialized,
};

// The boot apply retries for `BOOTUP_NIC_CHECK_MAX_QUICK` rounds of
// `BOOTUP_NIC_CHECK_INTERVAL_MS_QUICK` (5 seconds total) to give udev time
// to finish initializing NICs that exist but are still enumerating when the
// daemon first polls.  After that grace period the remaining saved configs
// (e.g. `identifier: mac-address` profiles whose NIC is not present) are
// left for the monitor worker: it emits a link event when the NIC appears
// and the event worker then applies the saved config.  We must not keep
// retrying indefinitely: a saved config whose NIC does not exist would
// otherwise delay the whole boot apply (and thus wait-online) for the full
// retry window.
const BOOTUP_NIC_CHECK_MAX_QUICK: u64 = 10;
const BOOTUP_NIC_CHECK_INTERVAL_MS_QUICK: u64 = 500;

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

    // Workflow:
    //  1. Query current network state.
    //  2. For each non-virtual interface mentioned in saved state, if udev has
    //     it initialized, apply its config.
    //  3. Retry for a short grace period so NICs that are still enumerating
    //     (udev not finished) get applied in the same boot pass.
    //  4. Leave the remaining saved configs (their NIC is not present) for the
    //     monitor worker: it emits a link event when the NIC appears and the
    //     event worker then applies the saved config.
    pub(crate) async fn load_saved_state(&mut self) -> Result<(), NipartError> {
        self.monitor_manager.pause().await?;
        let result = self.load_saved_state_inner().await;
        // Always resume the monitor even when loading failed, otherwise the
        // daemon would stop reacting to interface link events (e.g. wifi
        // reconnect) for the rest of its life.
        self.monitor_manager.resume().await?;
        result
    }

    async fn load_saved_state_inner(&mut self) -> Result<(), NipartError> {
        let mut saved_state = self.conf_manager.query_state().await?;
        // Interfaces with `auto-connect: false` are only activated upon
        // explicit apply action, not at boot.
        remove_manual_activation(&mut saved_state);
        // The DNS resolver state is not tied to a kernel NIC: the cache
        // server is a daemon task and `/etc/resolv.conf` is not part of
        // the kernel state, so both are restored once here.  Removing it
        // from the pending saved state also lets the interface retry loop
        // below terminate.
        let saved_dns_resolver = std::mem::take(&mut saved_state.dns_resolver);
        if !saved_dns_resolver.is_empty()
            && let Err(e) =
                self.restore_saved_dns_resolver(&saved_dns_resolver).await
        {
            // Do not abort the boot apply on a DNS failure: the
            // interfaces still need to be applied and a later `npt
            // apply` can retry the DNS configuration.
            log::warn!(
                "Failed to restore saved DNS resolver configuration: {e}"
            );
        }
        if saved_state.is_empty() {
            log::info!("Saved state is empty");
        } else {
            log::trace!("Loading saved state: {saved_state}");
            // Accumulate the saved interfaces successfully applied at
            // boot: after the loop their DHCP clients are restored (see
            // `restore_saved_dhcp_clients`).
            let mut boot_applied_ifaces: Vec<Interface> = Vec::new();
            for _ in 0..BOOTUP_NIC_CHECK_MAX_QUICK {
                let kernel_iface_names =
                    get_initialized_nics(&saved_state).await?;

                let nic_ready_state =
                    remove_ready_state(&mut saved_state, &kernel_iface_names);

                // `wifi-cfg` profiles must be applied together with a
                // wifi-phy: the plugin binds them to the phy when the client
                // starts, so applying them before the phy is ready leaves the
                // network list behind when the phy is later applied/renamed.
                // Defer them to a later boot round (or the monitor worker)
                // when no wifi-phy is ready yet.
                let mut nic_ready_state = nic_ready_state;
                let has_ready_wifi_phy = nic_ready_state
                    .ifaces
                    .iter()
                    .any(|iface| iface.iface_type() == &InterfaceType::WifiPhy);
                if !has_ready_wifi_phy
                    && nic_ready_state.ifaces.iter().any(|iface| {
                        iface.iface_type() == &InterfaceType::WifiCfg
                    })
                {
                    let mut wifi_cfg_state = NetworkState::default();
                    let mut non_wifi_cfg_state = NetworkState::default();
                    non_wifi_cfg_state.routes = nic_ready_state.routes.clone();
                    non_wifi_cfg_state.route_rules =
                        nic_ready_state.route_rules.clone();
                    for iface in nic_ready_state.ifaces.iter() {
                        if iface.iface_type() == &InterfaceType::WifiCfg {
                            wifi_cfg_state.ifaces.push(iface.clone());
                        } else {
                            non_wifi_cfg_state.ifaces.push(iface.clone());
                        }
                    }
                    log::debug!(
                        "Deferring {} wifi-cfg profile(s) until a wifi-phy is \
                         ready",
                        wifi_cfg_state.ifaces.iter().count()
                    );
                    saved_state.merge(&wifi_cfg_state)?;
                    nic_ready_state = non_wifi_cfg_state;
                }

                // `wifi-cfg` profiles are userspace-only and the wifi plugin
                // is a fresh process after a daemon restart, so they must be
                // (re)applied even when the saved profile already appears in
                // the running state. Apply them with `force` after the
                // wifi-phy itself has been brought up.
                let mut wifi_cfg_state = NetworkState::default();
                let mut non_wifi_cfg_state = NetworkState::default();
                non_wifi_cfg_state.routes = nic_ready_state.routes.clone();
                non_wifi_cfg_state.route_rules =
                    nic_ready_state.route_rules.clone();
                for iface in nic_ready_state.ifaces.iter() {
                    if iface.iface_type() == &InterfaceType::WifiCfg {
                        wifi_cfg_state.ifaces.push(iface.clone());
                    } else {
                        non_wifi_cfg_state.ifaces.push(iface.clone());
                    }
                }

                let mut boot_round_applied: Vec<Interface> = Vec::new();
                if !non_wifi_cfg_state.is_empty() {
                    for iface in non_wifi_cfg_state.ifaces.iter() {
                        log::debug!(
                            "Applying saved state for interface {}/{}",
                            iface.name(),
                            iface.iface_type()
                        );
                    }
                    log::debug!("Applying saved state: {non_wifi_cfg_state}");
                    if let Err(e) = self
                        .apply_network_state(
                            None,
                            non_wifi_cfg_state.clone(),
                            NipartApplyOption::new().no_verify().memory_only(),
                        )
                        .await
                    {
                        // Do not abort the whole boot apply on failure (e.g.
                        // wifi plugin not ready for wpa_supplicant yet).
                        // Put the state back so the retry loop can try again.
                        log::warn!(
                            "Failed to apply saved state, will retry: {e}"
                        );
                        if let Err(e) = saved_state.merge(&non_wifi_cfg_state) {
                            log::error!(
                                "BUG: Failed to merge back unapplied saved \
                                 state: {e}"
                            );
                        }
                        if !wifi_cfg_state.is_empty()
                            && let Err(e) = saved_state.merge(&wifi_cfg_state)
                        {
                            log::error!(
                                "BUG: Failed to merge back unapplied wifi-cfg \
                                 saved state: {e}"
                            );
                        }
                        wifi_cfg_state = NetworkState::default();
                    } else {
                        boot_round_applied
                            .extend(non_wifi_cfg_state.ifaces.iter().cloned());
                    }
                }

                if !wifi_cfg_state.is_empty() {
                    log::debug!(
                        "Applying saved wifi-cfg state with force: \
                         {wifi_cfg_state}"
                    );
                    if let Err(e) = self
                        .apply_network_state(
                            None,
                            wifi_cfg_state.clone(),
                            NipartApplyOption::new()
                                .no_verify()
                                .memory_only()
                                .force(),
                        )
                        .await
                    {
                        log::warn!(
                            "Failed to apply saved wifi-cfg state, will \
                             retry: {e}"
                        );
                        if let Err(e) = saved_state.merge(&wifi_cfg_state) {
                            log::error!(
                                "BUG: Failed to merge back unapplied wifi-cfg \
                                 saved state: {e}"
                            );
                        }
                    } else {
                        boot_round_applied
                            .extend(wifi_cfg_state.ifaces.iter().cloned());
                    }
                }

                log::debug!("Remaining saved state: {saved_state}");
                boot_applied_ifaces.extend(boot_round_applied);
                if saved_state.is_empty() {
                    log::info!("All saved state applied successfully");
                    break;
                }

                tokio::time::sleep(std::time::Duration::from_millis(
                    BOOTUP_NIC_CHECK_INTERVAL_MS_QUICK,
                ))
                .await;
            }
            // A DHCP-enabled interface whose lease survived the daemon
            // restart still carries its address in the kernel (reported
            // with `dhcp: true`), so the boot apply sees no diff and
            // never restarts the DHCP client - which is a userspace
            // process that died with the daemon.  The lease would then
            // expire without renewal.  Restore the DHCP clients now.
            self.restore_saved_dhcp_clients(&boot_applied_ifaces)
                .await?;
            if !saved_state.is_empty() {
                // The remaining saved configs target NICs that are not
                // present in the kernel (e.g. `identifier: mac-address`
                // profiles for NICs that are not installed on this host).
                // They are not applied at boot: register their monitor
                // watches so the monitor worker emits a link event when
                // such a NIC appears and the event worker then applies the
                // saved config.  Keep them in the saved state for that
                // path.
                self.monitor_manager
                    .setup_saved_state_monitors(&saved_state, true)
                    .await?;
                log::info!(
                    "Saved config for {} interface(s) without a present NIC \
                     is left for monitor worker to activate when the NIC \
                     appears: {saved_state}",
                    saved_state.ifaces.iter().count()
                );
            }
        }
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

    /// Restore the DHCP clients for the saved interfaces applied at boot.
    ///
    /// [`Self::apply_network_state`] only (re)starts DHCP for interfaces
    /// whose kernel state changed.  A DHCP-enabled interface whose lease
    /// survived the daemon restart still carries its address in the
    /// kernel (reported with `dhcp: true`), so the merge sees no diff and
    /// the DHCP client - a userspace process that died with the daemon -
    /// is never restarted; the lease then expires without renewal.  This
    /// starts the DHCP client for every applied saved interface that has
    /// DHCP enabled and whose kernel interface already carries a DHCP
    /// address (i.e. the no-diff case; a cold boot has no address and is
    /// handled by the normal apply path).
    async fn restore_saved_dhcp_clients(
        &mut self,
        applied_ifaces: &[Interface],
    ) -> Result<(), NipartError> {
        let cur_state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;
        // Interfaces the boot apply already started a DHCP client for
        // (kernel state changed) must not be started again.
        let v4_running = self.dhcpv4_manager.running_ifaces().await?;
        let v6_running = self.dhcpv6_manager.running_ifaces().await?;
        for saved_iface in applied_ifaces {
            let base = saved_iface.base_iface();
            if base.state != InterfaceState::Up {
                continue;
            }
            // The DHCP client runs on the kernel interface the config
            // binds to: a wifi-cfg maps to the wifi-phy carrying its
            // SSID, all other configs to the interface matched by kernel
            // name or MAC address.
            let Some(cur_iface) =
                match_kernel_iface_for_saved_iface(saved_iface, &cur_state)
            else {
                continue;
            };
            let cur_base = cur_iface.base_iface();
            let iface_name = cur_iface.name().to_string();
            if base.ipv4.as_ref().is_some_and(|i| i.is_auto())
                && cur_base.ipv4.as_ref().is_some_and(|i| i.dhcp == Some(true))
                && !v4_running.contains(&iface_name)
            {
                log::info!(
                    "Restoring DHCPv4 client on interface {}({}) after daemon \
                     restart",
                    iface_name,
                    cur_iface.iface_type()
                );
                // The kernel state (`cur_base`) never carries the
                // config-only `auto_gateway` and `auto_route_metric`
                // properties, so inherit them from the saved config,
                // otherwise the restored client would ignore
                // `auto-gateway: false` / `auto-route-metric` and add the
                // DHCP gateway routes with wrong settings again.
                let dhcp_base_iface =
                    base_iface_for_dhcp_restore(cur_base, base);
                if let Err(e) =
                    self.dhcpv4_manager.start_iface_dhcp(&dhcp_base_iface).await
                {
                    // Do not abort the whole boot apply on a transient
                    // DHCP failure; the interface keeps its lease until
                    // it expires and a later apply can retry.
                    log::warn!(
                        "Failed to restore DHCPv4 client on interface \
                         {iface_name}: {e}"
                    );
                }
            }
            if base
                .ipv6
                .as_ref()
                .is_some_and(|i| i.is_enabled() && i.dhcp == Some(true))
                && cur_base.ipv6.as_ref().is_some_and(|i| i.dhcp == Some(true))
                && !v6_running.contains(&iface_name)
            {
                log::info!(
                    "Restoring DHCPv6 client on interface {}({}) after daemon \
                     restart",
                    iface_name,
                    cur_iface.iface_type()
                );
                if let Err(e) =
                    self.dhcpv6_manager.start_iface_dhcp(cur_base).await
                {
                    log::warn!(
                        "Failed to restore DHCPv6 client on interface \
                         {iface_name}: {e}"
                    );
                }
            }
        }
        Ok(())
    }
}

/// Build the base interface used to start the DHCPv4 client after a daemon
/// restart: the kernel state (which carries the MAC address and interface
/// index the client needs), but with the config-only `auto_gateway` and
/// `auto_route_metric` properties inherited from the saved config — the
/// kernel never reports them, so without this the restored client would
/// ignore `auto-gateway: false` or the configured `auto-route-metric` and
/// re-add the DHCP gateway routes with wrong settings on the first renewal.
fn base_iface_for_dhcp_restore(
    kernel_base: &BaseInterface,
    saved_base: &BaseInterface,
) -> BaseInterface {
    let mut ret = kernel_base.clone();
    if let Some(ipv4) = ret.ipv4.as_mut() {
        ipv4.auto_gateway =
            saved_base.ipv4.as_ref().and_then(|i| i.auto_gateway);
        ipv4.auto_route_metric =
            saved_base.ipv4.as_ref().and_then(|i| i.auto_route_metric);
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

async fn get_initialized_nics(
    saved_state: &NetworkState,
) -> Result<Vec<String>, NipartError> {
    let cur_state =
        NipartNoDaemon::query_network_state(NipartQueryOption::running())
            .await?;

    let mut ret = Vec::new();

    // The `kernel_ifaces` HashMap is keyed by the interface profile name for
    // MAC-address-matching interfaces whose kernel name is not resolved yet.
    // Use this key so `remove_ready_state()` can locate the interface.
    for (iface_key, iface) in saved_state
        .ifaces
        .kernel_ifaces
        .iter()
        .filter(|(_, i)| !i.is_virtual())
    {
        let cur_iface = cur_state
            .ifaces
            .kernel_ifaces
            .values()
            .find(|cur_iface| iface.is_match(cur_iface));

        if let Some(cur_iface) = cur_iface
            && let Some(cur_iface_index) = cur_iface.base_iface().iface_index
            && udev_net_device_is_initialized(cur_iface_index)
        {
            log::debug!(
                "Got Initialized NIC: {}/{}",
                cur_iface.name(),
                cur_iface.iface_type()
            );
            ret.push(iface_key.to_string());
        }
    }
    Ok(ret)
}

/// Return state for ready interfaces, and remove them from the original state.
fn remove_ready_state(
    state: &mut NetworkState,
    ready_kernel_iface_names: &[String],
) -> NetworkState {
    let mut ret = NetworkState::default();
    // HashMap of `<kernel_iface_name, iface_type>` for interface move
    // from old state to new state.
    let mut pending_ifaces: HashMap<String, Option<InterfaceType>> =
        HashMap::new();
    for kernel_iface_name in ready_kernel_iface_names {
        if let Some(iface) =
            state.ifaces.kernel_ifaces.get(kernel_iface_name.as_str())
            && iface.base_iface().controller.is_none()
        {
            // Use the HashMap key instead of `iface.kernel_iface_name()`
            // which is empty for unresolved MAC-address-matching interfaces.
            pending_ifaces.insert(kernel_iface_name.to_string(), None);
        }
    }

    // Include all virtual interface if not controller or controller has all
    // ports ready
    for iface in state.ifaces.iter().filter(|i| i.is_virtual()) {
        if iface.is_controller() {
            if let Some(ports) = iface.ports()
                && is_all_virtual_or_ready(
                    &ports,
                    ready_kernel_iface_names,
                    state,
                )
            {
                pending_ifaces.insert(
                    iface.kernel_iface_name().to_string(),
                    Some(iface.iface_type().clone()),
                );
                for port in ports {
                    pending_ifaces.insert(port.to_string(), None);
                }
            }
        } else {
            pending_ifaces.insert(
                iface.kernel_iface_name().to_string(),
                Some(iface.iface_type().clone()),
            );
        }
    }

    // Include routes of pending up interfaces
    ret.routes = state.routes.clone();
    ret.routes.config.get_or_insert_default().retain(|r| {
        if let Some(kernel_iface_name) = r.next_hop_iface.as_ref() {
            pending_ifaces.contains_key(kernel_iface_name)
        } else {
            false
        }
    });
    // Remove the ready routes from the original state so the retry loop can
    // terminate once all saved state has been extracted for apply.
    if let Some(state_rts) = state.routes.config.as_mut() {
        state_rts.retain(|r| {
            r.next_hop_iface
                .as_ref()
                .map(|n| !pending_ifaces.contains_key(n))
                .unwrap_or(true)
        });
    }

    // Global route rules (no `iif`) can be applied at boot immediately.
    // Rules with an `iif` are deferred until the referenced interface is
    // ready, just like routes are deferred until their next-hop interface is
    // ready.
    ret.route_rules = state.route_rules.clone();
    if let Some(config_rules) = ret.route_rules.config.as_mut() {
        config_rules.retain(|rule| {
            rule.iif
                .as_ref()
                .is_none_or(|iif| pending_ifaces.contains_key(iif))
        });
    }
    if let Some(state_rules) = state.route_rules.config.as_mut() {
        state_rules.retain(|rule| {
            rule.iif
                .as_ref()
                .is_some_and(|iif| !pending_ifaces.contains_key(iif))
        });
    }

    for (iface_name, iface_type) in pending_ifaces.drain() {
        if let Some(iface) =
            state.ifaces.kernel_ifaces.remove(iface_name.as_str())
        {
            ret.ifaces.push(iface);
        } else if let Some(iface_type) = iface_type
            && let Some(iface) = state
                .ifaces
                .user_ifaces
                .remove(&(iface_name.clone(), iface_type))
        {
            // Userspace interfaces (e.g. `wifi-cfg`, OVS bridge) are moved
            // here so the boot retry loop can terminate after applying them
            // instead of keeping them as "remaining saved state" forever.
            ret.ifaces.push(iface);
        }
    }
    ret
}

fn is_all_virtual_or_ready(
    ports: &[&str],
    ready_kernel_iface_names: &[String],
    saved_state: &NetworkState,
) -> bool {
    for port in ports {
        let port = port.to_string();
        if !ready_kernel_iface_names.contains(&port)
            && saved_state
                .ifaces
                .kernel_ifaces
                .get(&port)
                .map(|i| i.is_virtual())
                != Some(true)
        {
            return false;
        }
    }
    true
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

#[cfg(test)]
#[path = "unit_tests/commander.rs"]
mod tests;
