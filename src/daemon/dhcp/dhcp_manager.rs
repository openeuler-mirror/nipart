// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use futures_channel::mpsc::UnboundedSender;
use nipart::{
    BaseInterface, MergedNetworkState, NetworkState, NipartError,
    NipartInterface, NipartIpcConnection, NipartNoDaemon,
};

use super::{
    NipartDhcpCmd, NipartDhcpReply, NipartDhcpV4Worker, desired_ssid_for_phy,
    should_touch_dhcp, wait_wifi_ssid, wifi_cfg_ssid_changed,
    wifi_ssid_changed,
};
use crate::{
    TaskManager, daemon::NipartManagerCmd, log_debug,
    plugin::NipartPluginManager,
};

#[derive(Debug, Clone)]
pub(crate) struct NipartDhcpV4Manager {
    mgr: TaskManager<NipartDhcpCmd, NipartDhcpReply>,
}

// Do not add `async` function to NipartDhcpV4Manager because it will be stored
// into Mutex protected `NipartDaemonShareData`. The
// `MutexGuard` will cause function not `Send`.
impl NipartDhcpV4Manager {
    pub(crate) async fn new(
        msg_to_daemon: UnboundedSender<NipartManagerCmd>,
    ) -> Result<Self, NipartError> {
        let mut ret = Self {
            mgr: TaskManager::new::<NipartDhcpV4Worker>("dhcp").await?,
        };
        // The worker applies DHCP leases outside of the daemon apply path,
        // hence it needs the daemon sender to report a changed default
        // gateway of a new lease.
        ret.mgr
            .exec(NipartDhcpCmd::SetCommanderSender(msg_to_daemon))
            .await?;
        Ok(ret)
    }

    pub(crate) async fn shutdown(&self) {
        self.mgr.shutdown().await
    }

    /// Fill the NetworkState with DHCP states
    pub(crate) async fn fill_dhcp_states(
        &mut self,
        net_state: &mut NetworkState,
    ) -> Result<(), NipartError> {
        if let NipartDhcpReply::QueryReply(mut dhcp_states) =
            self.mgr.exec(NipartDhcpCmd::Query).await?
        {
            for (kernel_iface_name, dhcp_state) in dhcp_states.drain() {
                if let Some(iface) = net_state
                    .ifaces
                    .kernel_ifaces
                    .get_mut(kernel_iface_name.as_str())
                {
                    let ipv4_conf = iface
                        .base_iface_mut()
                        .ipv4
                        .get_or_insert(Default::default());
                    ipv4_conf.enabled = Some(true);
                    ipv4_conf.dhcp = Some(true);
                    ipv4_conf.dhcp_state = Some(dhcp_state);
                }
            }
        }
        Ok(())
    }

    /// The kernel interface names that currently have a DHCP client
    /// thread running.
    pub(crate) async fn running_ifaces(
        &mut self,
    ) -> Result<std::collections::HashSet<String>, NipartError> {
        let mut ret = std::collections::HashSet::new();
        if let NipartDhcpReply::QueryReply(threads) =
            self.mgr.exec(NipartDhcpCmd::Query).await?
        {
            ret.extend(threads.into_keys());
        }
        Ok(ret)
    }

    /// Nameservers learned from the current DHCPv4 leases, keyed by
    /// interface name.
    pub(crate) async fn nameservers(
        &mut self,
    ) -> Result<HashMap<String, Vec<String>>, NipartError> {
        if let NipartDhcpReply::NameserverReply(nameservers) =
            self.mgr.exec(NipartDhcpCmd::Nameservers).await?
        {
            Ok(nameservers)
        } else {
            Ok(HashMap::new())
        }
    }

    pub(crate) async fn start_iface_dhcp(
        &mut self,
        base_iface: &BaseInterface,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartDhcpCmd::StartIfaceDhcp(Box::new(base_iface.clone())))
            .await?;
        Ok(())
    }

    async fn stop_iface_dhcp(
        &mut self,
        kernel_iface_name: &str,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartDhcpCmd::StopIfaceDhcp(kernel_iface_name.to_string()))
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
            .filter(|i| i.is_changed() && !i.merged.is_userspace())
        {
            let mut apply_iface = match merged_iface.for_apply.as_ref() {
                Some(i) => i.clone(),
                None => {
                    continue;
                }
            };
            if apply_iface.base_iface().mac_address.is_none() {
                apply_iface.base_iface_mut().mac_address =
                    merged_iface.merged.base_iface().mac_address.clone();
            }
            apply_iface.base_iface_mut().iface_index =
                merged_iface.merged.base_iface().iface_index;
            // `for_apply` is a diff against the current state.  A changed
            // interface caused only by saved-only fields (e.g.
            // `profile-name`) must not restart a healthy DHCP client, so
            // remember whether this diff actually touched IPv4 before the
            // fallback below adds the merged config.
            let ipv4_changed = apply_iface.base_iface().ipv4.is_some();
            // `for_apply` is a diff against the current state, so unchanged
            // DHCP settings may be omitted even when the SSID changed and
            // the DHCP client must be restarted. Fall back to the merged
            // IP configuration to decide whether DHCP is enabled.
            if apply_iface.base_iface().ipv4.is_none() {
                apply_iface.base_iface_mut().ipv4 =
                    merged_iface.merged.base_iface().ipv4.clone();
            }
            let ssid_changed =
                wifi_ssid_changed(
                    merged_iface.current.as_ref(),
                    merged_iface.desired.as_ref(),
                ) || wifi_cfg_ssid_changed(&merged_state.ifaces, merged_iface);
            if !should_touch_dhcp(
                merged_state.option.restart_auto_ip,
                ssid_changed,
                ipv4_changed,
                apply_iface.is_up(),
            ) {
                continue;
            }
            if apply_iface.is_up() {
                if let Some(dhcp_enabled) =
                    apply_iface.base_iface().ipv4.as_ref().map(|i| i.is_auto())
                {
                    if dhcp_enabled {
                        if merged_state.option.restart_auto_ip || ssid_changed {
                            log_debug(
                                conn.as_deref_mut(),
                                format!(
                                    "Restarting DHCPv4 on interface {}({}){}",
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
                                if let Some(ssid) = desired_ssid_for_phy(
                                    &merged_state.ifaces,
                                    merged_iface,
                                ) {
                                    wait_wifi_ssid(
                                        apply_iface.kernel_iface_name(),
                                        &ssid,
                                        plugin_manager,
                                    )
                                    .await?;
                                }
                            }
                        } else {
                            log_debug(
                                conn.as_deref_mut(),
                                format!(
                                    "Starting DHCPv4 on interface {}({})",
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
                                "Stopping DHCPv4 on interface {}({})",
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
                                "Stopped DHCPv4 on interface {}({})",
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
