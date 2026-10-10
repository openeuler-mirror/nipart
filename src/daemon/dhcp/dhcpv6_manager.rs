// SPDX-License-Identifier: Apache-2.0

use nipart::{
    BaseInterface, Interface, MergedNetworkState, NetworkState, NipartError,
    NipartInterface, NipartIpcConnection, NipartNoDaemon,
};

use super::{
    NipartDhcpV6Cmd, NipartDhcpV6Reply, NipartDhcpV6Worker, should_touch_dhcp,
    wait_wifi_ssid, wifi_ssid_changed,
};
use crate::{TaskManager, log_debug, plugin::NipartPluginManager};

#[derive(Debug, Clone)]
pub(crate) struct NipartDhcpV6Manager {
    mgr: TaskManager<NipartDhcpV6Cmd, NipartDhcpV6Reply>,
}

// Do not add `async` function to NipartDhcpV6Manager because it will be stored
// into Mutex protected `NipartDaemonShareData`. The
// `MutexGuard` will cause function not `Send`.
impl NipartDhcpV6Manager {
    pub(crate) async fn new() -> Result<Self, NipartError> {
        Ok(Self {
            mgr: TaskManager::new::<NipartDhcpV6Worker>("dhcpv6").await?,
        })
    }

    pub(crate) async fn shutdown(&self) {
        self.mgr.shutdown().await
    }

    /// Fill the NetworkState with DHCPv6 states
    pub(crate) async fn fill_dhcp_states(
        &mut self,
        net_state: &mut NetworkState,
    ) -> Result<(), NipartError> {
        if let NipartDhcpV6Reply::QueryReply(mut dhcp_states) =
            self.mgr.exec(NipartDhcpV6Cmd::Query).await?
        {
            for (kernel_iface_name, dhcp_state) in dhcp_states.drain() {
                if let Some(iface) = net_state
                    .ifaces
                    .kernel_ifaces
                    .get_mut(kernel_iface_name.as_str())
                {
                    let ipv6_conf = iface
                        .base_iface_mut()
                        .ipv6
                        .get_or_insert(Default::default());
                    ipv6_conf.enabled = Some(true);
                    ipv6_conf.dhcp = Some(true);
                    ipv6_conf.dhcp_state = Some(dhcp_state);
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn start_iface_dhcp(
        &mut self,
        base_iface: &BaseInterface,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartDhcpV6Cmd::StartIfaceDhcp(Box::new(
                base_iface.clone(),
            )))
            .await?;
        Ok(())
    }

    async fn stop_iface_dhcp(
        &mut self,
        kernel_iface_name: &str,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartDhcpV6Cmd::StopIfaceDhcp(
                kernel_iface_name.to_string(),
            ))
            .await?;
        Ok(())
    }

    // The reason we take full share_data instead of `&mut self` is because
    // Mutex cannot be Send, so it cannot work with async function.
    pub(crate) async fn apply_dhcp_config(
        &mut self,
        mut conn: Option<&mut NipartIpcConnection>,
        merged_state: &MergedNetworkState,
        plugin_manager: &mut NipartPluginManager,
    ) -> Result<(), NipartError> {
        for merged_iface in merged_state
            .ifaces
            .iter()
            .filter(|i| !i.merged.is_userspace())
        {
            // `restart_auto_ip` (the boot hand-off) must restart the DHCP
            // client even for an interface whose kernel state already
            // matches: the client process died with the previous daemon.
            if !merged_iface.is_changed()
                && !merged_state.option.restart_auto_ip
            {
                continue;
            }
            let mut apply_iface = match merged_iface.for_apply.as_ref() {
                Some(i) => i.clone(),
                // No diff: only the `restart_auto_ip` path reaches here.
                None => merged_iface.merged.clone(),
            };
            if apply_iface.base_iface().mac_address.is_none() {
                apply_iface.base_iface_mut().mac_address =
                    merged_iface.merged.base_iface().mac_address.clone();
            }
            apply_iface.base_iface_mut().iface_index =
                merged_iface.merged.base_iface().iface_index;
            // A diff touching only saved-only fields (e.g.
            // `profile-name`) must not restart a healthy DHCPv6 client.
            let ipv6_changed = apply_iface.base_iface().ipv6.is_some();
            // `for_apply` is a diff against the current state, so unchanged
            // DHCP settings may be omitted even when the SSID changed and
            // the DHCP client must be restarted. Fall back to the merged
            // IP configuration to decide whether DHCP is enabled.
            if apply_iface.base_iface().ipv6.is_none() {
                apply_iface.base_iface_mut().ipv6 =
                    merged_iface.merged.base_iface().ipv6.clone();
            }
            let ssid_changed = wifi_ssid_changed(
                merged_iface.current.as_ref(),
                merged_iface.desired.as_ref(),
            );
            if !should_touch_dhcp(
                merged_state.option.restart_auto_ip,
                ssid_changed,
                ipv6_changed,
                apply_iface.is_up(),
            ) {
                continue;
            }
            // The restart-only path must never stop DHCP on an unchanged
            // interface (e.g. a static-IP interface in the same boot batch).
            if !merged_iface.is_changed()
                && apply_iface
                    .base_iface()
                    .ipv6
                    .as_ref()
                    .map(|i| i.dhcp == Some(true))
                    != Some(true)
            {
                continue;
            }
            if apply_iface.is_up() {
                if let Some(dhcp_enabled) = apply_iface
                    .base_iface()
                    .ipv6
                    .as_ref()
                    .map(|i| i.dhcp == Some(true))
                {
                    if dhcp_enabled {
                        if merged_state.option.restart_auto_ip || ssid_changed {
                            log_debug(
                                conn.as_deref_mut(),
                                format!(
                                    "Restarting DHCPv6 on interface {}({}){}",
                                    apply_iface.name(),
                                    apply_iface.iface_type(),
                                    if ssid_changed {
                                        " due to SSID change"
                                    } else {
                                        ""
                                    },
                                ),
                            )
                            .await;
                            self.stop_iface_dhcp(
                                apply_iface.kernel_iface_name(),
                            )
                            .await?;
                            if ssid_changed {
                                NipartNoDaemon::purge_iface_ip(
                                    merged_iface.merged.base_iface(),
                                    merged_iface
                                        .current
                                        .as_ref()
                                        .map(|i| i.base_iface()),
                                )
                                .await?;
                                if let Some(Interface::WifiPhy(des_iface)) =
                                    merged_iface.desired.as_ref()
                                    && let Some(ssid) = des_iface.ssid()
                                {
                                    wait_wifi_ssid(
                                        apply_iface.kernel_iface_name(),
                                        ssid,
                                        plugin_manager,
                                    )
                                    .await?;
                                }
                            }
                        } else {
                            log_debug(
                                conn.as_deref_mut(),
                                format!(
                                    "Starting DHCPv6 on interface {}({})",
                                    apply_iface.name(),
                                    apply_iface.iface_type()
                                ),
                            )
                            .await;
                        }
                        self.start_iface_dhcp(apply_iface.base_iface()).await?;
                    } else {
                        log_debug(
                            conn.as_deref_mut(),
                            format!(
                                "Stopping DHCPv6 on interface {}({})",
                                apply_iface.name(),
                                apply_iface.iface_type()
                            ),
                        )
                        .await;
                        self.stop_iface_dhcp(apply_iface.kernel_iface_name())
                            .await?;
                        log_debug(
                            conn.as_deref_mut(),
                            format!(
                                "Stopped DHCPv6 on interface {}({})",
                                apply_iface.name(),
                                apply_iface.iface_type()
                            ),
                        )
                        .await;
                    }
                }
            } else {
                self.stop_iface_dhcp(apply_iface.kernel_iface_name())
                    .await?;
            }
        }

        Ok(())
    }
}
