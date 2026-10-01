// SPDX-License-Identifier: Apache-2.0

use futures_channel::mpsc::UnboundedSender;
use nipart::{
    Interface, InterfaceAutoConnect, InterfaceIdentifier, MergedNetworkState,
    NetworkState, NipartError, NipartInterface, NipartNoDaemon,
    NipartQueryOption,
};

use super::{
    super::daemon::NipartManagerCmd, NipartMonitorCmd, NipartMonitorReply,
    NipartMonitorWorker, iface_identity_names,
};
use crate::TaskManager;

// Responsibilities of NipartMonitorManager:
//  * Parse `MergedNetworkState` into a list of interface/SSID to start/stop
//    monitor

#[derive(Debug, Clone)]
pub(crate) struct NipartMonitorManager {
    mgr: TaskManager<NipartMonitorCmd, NipartMonitorReply>,
    msg_to_commander: UnboundedSender<NipartManagerCmd>,
}

impl NipartMonitorManager {
    pub(crate) async fn new(
        msg_to_commander: UnboundedSender<NipartManagerCmd>,
    ) -> Result<Self, NipartError> {
        let mut ret = Self {
            mgr: TaskManager::new::<NipartMonitorWorker>("monitor").await?,
            msg_to_commander,
        };
        ret.mgr
            .exec(NipartMonitorCmd::SetCommanderSender(
                ret.msg_to_commander.clone(),
            ))
            .await?;
        Ok(ret)
    }

    pub(crate) async fn shutdown(&self) {
        self.mgr.shutdown().await
    }

    pub(crate) async fn pause(&mut self) -> Result<(), NipartError> {
        self.mgr.exec(NipartMonitorCmd::Pause).await?;
        Ok(())
    }

    pub(crate) async fn resume(&mut self) -> Result<(), NipartError> {
        self.mgr.exec(NipartMonitorCmd::Resume).await?;
        Ok(())
    }

    /// Record the interface/profile as explicitly downed by `npt down` so
    /// its link events are not forwarded to the event worker.
    pub(crate) async fn mark_explicitly_down(
        &mut self,
        iface: &Interface,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartMonitorCmd::MarkExplicitlyDown(iface_identity_names(
                iface,
            )))
            .await?;
        Ok(())
    }

    /// Forget that the interface/profile was explicitly downed.  Used by
    /// `npt up` so the saved config can be activated again.
    pub(crate) async fn clear_explicitly_down(
        &mut self,
        iface: &Interface,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartMonitorCmd::ClearExplicitlyDown(iface_identity_names(
                iface,
            )))
            .await?;
        Ok(())
    }

    // Setup monitor for desired state
    // Use `full_saved_state` to determine whether we should enable or disable
    // WIFI SSID monitoring
    pub(crate) async fn setup_monitor(
        &mut self,
        merged_state: &MergedNetworkState,
        full_saved_state: &NetworkState,
    ) -> Result<(), NipartError> {
        if wifi_monitor_is_needed(full_saved_state) {
            self.enable_wifi_monitor().await?;
        } else {
            self.disable_wifi_monitor().await?;
        }

        for iface in merged_state
            .ifaces
            .iter()
            .filter_map(|m| m.for_apply.as_ref())
        {
            if iface.is_absent() {
                if let Some(mac) = iface.base_iface().mac_address.as_deref()
                    && iface.base_iface().identifier
                        == Some(InterfaceIdentifier::MacAddress)
                {
                    self.del_mac_watch(mac).await?;
                }
                self.del_iface_from_monitor(iface.kernel_iface_name())
                    .await?;
            } else if iface.base_iface().auto_connect.as_ref()
                == Some(&InterfaceAutoConnect::AutoConnect)
                || iface.base_iface().identifier
                    == Some(InterfaceIdentifier::MacAddress)
            {
                self.add_iface_to_monitor(iface.kernel_iface_name()).await?;
            }
        }

        self.setup_saved_state_monitors(full_saved_state, false)
            .await?;
        Ok(())
    }

    // Register the monitor watches for the saved interfaces whose NIC is
    // not yet active, so that when the NIC appears (hotplug) the monitor
    // worker emits the link event and the event worker applies the saved
    // config.  Interfaces with `auto-connect: false` are excluded: they are
    // only activated upon explicit apply action.
    //
    // When `watch_active` is `false` (normal apply-time setup), saved
    // interfaces whose NIC is already active are skipped: their config was
    // just applied and is managed via the apply-time monitor setup;
    // watching them would make the event worker re-apply their config on
    // every link event (e.g. restarting DHCP).  A stale MAC watch of an
    // activated NIC is dropped at the same time.
    //
    // When `watch_active` is `true` (the boot hand-off of configs that
    // could not be applied, e.g. their NIC is absent or a transient apply
    // failure), every leftover config is watched: the monitor's post-boot
    // link dump (or a later NIC-appear event) then lets the event worker
    // apply it, so no config is silently dropped in the boot hand-off race
    // window.
    pub(crate) async fn setup_saved_state_monitors(
        &mut self,
        saved_state: &NetworkState,
        watch_active: bool,
    ) -> Result<(), NipartError> {
        // Wifi-cfg profiles are userspace-only and are not registered with a
        // kernel name or MAC watch below, but their auto-connect still needs
        // the wifi monitor: it emits the first event of a wifi-phy so the
        // event worker can hand the saved profiles to the plugin.
        if wifi_monitor_is_needed(saved_state) {
            self.enable_wifi_monitor().await?;
        } else {
            self.disable_wifi_monitor().await?;
        }

        let cur_state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;
        for iface in saved_state.ifaces.iter().filter(|i| !i.is_absent()) {
            let base = iface.base_iface();
            if base.auto_connect.as_ref() == Some(&InterfaceAutoConnect::Manual)
            {
                continue;
            }
            if iface.is_userspace() {
                // Userspace interfaces (e.g. wifi-cfg) are activated via
                // their own event path (wifi monitor), not via a kernel
                // NIC name or MAC address watch.
                continue;
            }
            let active = self.nic_is_active(iface, &cur_state);
            if base.identifier == Some(InterfaceIdentifier::MacAddress) {
                // The kernel name of a MAC-address-matching NIC is unknown
                // until the NIC appears, so watch its MAC address instead.
                let Some(mac) = base.mac_address.as_deref() else {
                    continue;
                };
                if active && !watch_active {
                    // The NIC is present and has a name watch from the
                    // apply-time setup: drop the stale MAC watch.
                    self.del_mac_watch(mac).await?;
                } else {
                    self.add_mac_watch(mac).await?;
                }
            } else if !iface.kernel_iface_name().is_empty()
                && (watch_active || !active)
            {
                self.add_iface_to_monitor(iface.kernel_iface_name()).await?;
            }
        }
        Ok(())
    }

    /// Whether the saved interface already has a matching NIC in the
    /// kernel that is udev-initialized (i.e. its config is applied, or will
    /// be applied by the boot pass).  Matches by kernel name or MAC
    /// address, same as the event worker's `handle_event_auto_connect()`.
    fn nic_is_active(
        &self,
        saved_iface: &Interface,
        cur_state: &NetworkState,
    ) -> bool {
        let base = saved_iface.base_iface();
        let saved_mac =
            if base.identifier == Some(InterfaceIdentifier::MacAddress) {
                base.mac_address.as_deref().map(|m| m.to_ascii_uppercase())
            } else {
                None
            };
        cur_state.ifaces.kernel_ifaces.values().any(|cur_iface| {
            let cur_base = cur_iface.base_iface();
            let name_matched = saved_iface.kernel_iface_name()
                == cur_iface.kernel_iface_name()
                || saved_iface.name() == cur_iface.kernel_iface_name();
            let mac_matched = saved_mac.as_deref().is_some_and(|saved_mac| {
                cur_base
                    .permanent_mac_address
                    .as_deref()
                    .map(|m| m.to_ascii_uppercase() == saved_mac)
                    .unwrap_or(false)
                    || cur_base
                        .mac_address
                        .as_deref()
                        .map(|m| m.to_ascii_uppercase() == saved_mac)
                        .unwrap_or(false)
            });
            (name_matched || mac_matched)
                && cur_base
                    .iface_index
                    .is_some_and(crate::udev::udev_net_device_is_initialized)
        })
    }

    /// Start monitoring on specified interface.
    async fn add_iface_to_monitor(
        &mut self,
        kernel_iface_name: &str,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartMonitorCmd::AddIface(kernel_iface_name.to_string()))
            .await?;
        Ok(())
    }

    /// Stop monitoring on specified interface.
    async fn del_iface_from_monitor(
        &mut self,
        kernel_iface_name: &str,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartMonitorCmd::DelIface(kernel_iface_name.to_string()))
            .await?;
        Ok(())
    }

    /// Start monitoring on specified MAC address.
    async fn add_mac_watch(
        &mut self,
        mac_address: &str,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartMonitorCmd::AddMacWatch(mac_address.to_string()))
            .await?;
        Ok(())
    }

    /// Stop monitoring on specified MAC address.
    async fn del_mac_watch(
        &mut self,
        mac_address: &str,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartMonitorCmd::DelMacWatch(mac_address.to_string()))
            .await?;
        Ok(())
    }

    /// Enable WIFI SSID monitoring.
    async fn enable_wifi_monitor(&mut self) -> Result<(), NipartError> {
        self.mgr.exec(NipartMonitorCmd::EnableWifiMonitor).await?;
        Ok(())
    }

    /// Disable WIFI SSID monitoring.
    async fn disable_wifi_monitor(&mut self) -> Result<(), NipartError> {
        self.mgr.exec(NipartMonitorCmd::DisableWifiMonitor).await?;
        Ok(())
    }

    /// Record wifi-phy kernel names the daemon has already handed to the
    /// wifi plugin (the boot pass does this for every phy it applied).
    ///
    /// Without it, the first link event after the boot pass would be
    /// announced as a new phy and the event worker would re-apply the
    /// saved wifi-cfg set to a plugin that is already connecting with
    /// exactly those networks.
    pub(crate) async fn mark_wifi_phys_known(
        &mut self,
        iface_names: &[String],
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartMonitorCmd::MarkWifiPhysKnown(iface_names.to_vec()))
            .await?;
        Ok(())
    }
}

fn wifi_monitor_is_needed(full_saved_state: &NetworkState) -> bool {
    for iface in full_saved_state.ifaces.iter().filter(|i| !i.is_absent()) {
        if let Interface::WifiCfg(wifi_iface) = iface
            && wifi_iface.ssid().is_some()
        {
            return true;
        } else if let Interface::WifiPhy(wifi_iface) = iface
            && wifi_iface.ssid().is_some()
        {
            // A saved wifi-phy profile carries its own SSID config (e.g.
            // an older style `state: up` wifi-phy apply).  Its link-up
            // event must be monitored so `npt wifi on` can restore the
            // IP stack after `npt wifi off` purged it.
            return true;
        } else if let Some(auto_connect) =
            iface.base_iface().auto_connect.as_ref()
            && auto_connect.is_wifi()
        {
            return true;
        }
    }
    false
}
