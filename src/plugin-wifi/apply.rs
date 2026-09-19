// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use nipart::{
    ErrorKind, Interface, InterfaceType, NipartError, NipartInterface,
    NipartWifiControl, WifiConfig,
};
use shuli::{
    NetworkConfig as ShuliNetworkConfig, WifiClient,
    WifiConfig as ShuliWifiConfig, WifiState,
};

/// Per-interface metadata kept by the plugin while the single shuli
/// `WifiClient` owns the actual connection state machines.
#[derive(Debug, Default)]
pub(crate) struct WifiIfaceState {
    /// Kernel if_index of the phy the client was bound to at creation.
    /// When the phy is recreated (e.g. wifi driver module reload), the
    /// cached client targets a device that no longer exists, so this
    /// value is compared against the current kernel if_index on each
    /// apply and the single client is recreated on mismatch.
    if_index: u32,
    desired_networks: Vec<ShuliNetworkConfig>,
}

/// Live connection state of one wifi-phy, updated by the apply worker and
/// read by `query_network_state()`.
#[derive(Debug, Clone, Default)]
pub(crate) struct WifiLiveState {
    pub(crate) ssid: String,
    pub(crate) bssid: Option<String>,
}

/// The plugin-side wifi state: one shuli `WifiClient` for all wifi-phy
/// interfaces plus the per-interface metadata the apply flow needs.
pub(crate) struct WifiClientState {
    client: Option<WifiClient>,
    ifaces: HashMap<String, WifiIfaceState>,
    live_ifaces: Arc<Mutex<HashMap<String, WifiLiveState>>>,
    enabled: bool,
    enabled_flag: Arc<AtomicBool>,
    connected: bool,
}

impl WifiClientState {
    pub(crate) fn new(
        enabled_flag: Arc<AtomicBool>,
        live_ifaces: Arc<Mutex<HashMap<String, WifiLiveState>>>,
    ) -> Self {
        Self {
            client: None,
            ifaces: HashMap::new(),
            live_ifaces,
            enabled: true,
            enabled_flag,
            connected: false,
        }
    }

    fn clear_live_ifaces(&self) {
        if let Ok(mut live_ifaces) = self.live_ifaces.lock() {
            live_ifaces.clear();
        }
    }

    fn set_live_connected(&mut self, iface_name: &str, live: WifiLiveState) {
        if let Ok(mut live_ifaces) = self.live_ifaces.lock() {
            live_ifaces.insert(iface_name.to_string(), live);
            self.connected = true;
        }
    }

    fn clear_live_iface(&mut self, iface_name: &str) {
        if let Ok(mut live_ifaces) = self.live_ifaces.lock() {
            live_ifaces.remove(iface_name);
            self.connected = !live_ifaces.is_empty();
        }
    }

    pub(crate) fn has_client(&self) -> bool {
        self.client.is_some()
    }

    /// Notify the live shuli client that the host resumed from suspend.
    ///
    /// The notification only bumps an internal generation counter; the
    /// client re-checks the kernel association on its next drive cycle,
    /// so a connection lost over suspend is retried without waiting out
    /// the retry backoff.
    pub(crate) fn notify_resume(&self) {
        if let Some(client) = self.client.as_ref() {
            client.notify_resume();
        }
    }

    /// Enable or disable all WIFI actions.
    ///
    /// Disabling disconnects the shuli client and prevents future scans,
    /// connects, and client-driven passive scans.  Enabling only re-enables
    /// the WIFI function; the next explicit wifi apply (`npt wifi connect`
    /// or `npt up` on a wifi interface) starts the client again with the
    /// saved desired networks.
    pub(crate) async fn set_control(
        &mut self,
        control: NipartWifiControl,
    ) -> Result<(), NipartError> {
        match control {
            NipartWifiControl::Off => {
                log::info!("Disabling WIFI");
                // TODO: Also block the radio via rfkill when supported.
                // The `enabled` state should then reflect the actual
                // rfkill state, and `npt wifi on` must unblock the radio
                // before the shuli client is started.
                self.enabled = false;
                self.enabled_flag.store(false, Ordering::Release);
                self.connected = false;
                self.shutdown().await;
                self.clear_live_ifaces();
                self.client = None;
            }
            NipartWifiControl::On => {
                let was_enabled = self.enabled;
                log::info!("Enabling WIFI");
                // TODO: Unblock the radio via rfkill when supported and
                // keep `enabled` in sync with the actual radio state.
                self.enabled = true;
                self.enabled_flag.store(true, Ordering::Release);
                // An explicit wifi-on after WIFI was off must not wait for
                // a long shuli backoff (e.g. `Failed` with 300s retry):
                // restart the client so the saved networks are scanned
                // immediately.  Idempotent wifi-on while already enabled
                // keeps the current connection.
                if !was_enabled || self.client.is_none() {
                    self.restart_client().await;
                }
            }
            _ => {
                return Err(NipartError::new(
                    ErrorKind::Bug,
                    format!("Unsupported WIFI control {control}"),
                ));
            }
        }
        Ok(())
    }

    /// Drive the single client until one interface reports a state
    /// change. Returns immediately when no client exists yet.
    pub(crate) async fn run_once(&mut self) -> Result<(), NipartError> {
        let Some(client) = self.client.as_mut() else {
            return Ok(());
        };
        let result = client.run().await.map_err(|e| {
            NipartError::new(
                ErrorKind::PluginFailure,
                format!("WIFI client run failed: {e}"),
            )
        })?;
        let iface_name = &result.iface_name;
        match result.state {
            WifiState::ConnectedWithoutOffloadRekey
            | WifiState::ConnectedWithOffloadRekey => {
                let ssid = client
                    .current_ssid(iface_name)
                    .unwrap_or("unknown")
                    .to_string();
                let bssid = client
                    .current_bssid(iface_name)
                    .filter(|mac| *mac != [0; 6])
                    .map(|mac| mac_to_string(&mac));
                log::info!(
                    "WIFI connected on {iface_name}: SSID {ssid}, BSSID {}",
                    bssid.as_deref().unwrap_or("00:00:00:00:00:00")
                );
                self.set_live_connected(
                    iface_name,
                    WifiLiveState { ssid, bssid },
                );
            }
            WifiState::Failed => {
                self.clear_live_iface(iface_name);
                log::warn!("WIFI {iface_name} connection failed, retrying");
            }
            WifiState::FailedAuthentication => {
                self.clear_live_iface(iface_name);
                log::error!(
                    "WIFI {iface_name} authentication failed, retrying"
                );
            }
            state => {
                self.clear_live_iface(iface_name);
                log::trace!("WIFI {iface_name} state: {state:?}");
            }
        }
        Ok(())
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.connected
    }

    /// Cleanly disconnect every managed interface.
    pub(crate) async fn shutdown(&mut self) {
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        self.connected = false;
        self.clear_live_ifaces();
    }

    /// Drop the current shuli client and start a fresh one with the
    /// desired networks. Used when the client is known to be stuck
    /// (e.g. `run_once()` timeout) or when an explicit wifi-on must not
    /// wait for a long backoff.
    pub(crate) async fn restart_client(&mut self) {
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        self.client = None;
        self.connected = false;
        self.clear_live_ifaces();
        self.start_client().await;
    }

    pub(crate) async fn apply(
        &mut self,
        ifaces: &[Interface],
        force: bool,
    ) -> Result<(), NipartError> {
        // An explicit wifi up request carrying an SSID (e.g.
        // `npt wifi connect` or `npt up <wifi-phy|wifi-cfg>`)
        // automatically restores WIFI even when it was previously turned
        // off.  Down/absent-only applies and background wifi-phy IP
        // applies must not silently re-enable it.
        let has_wifi_up_request = has_wifi_ssid_up_request(ifaces);
        if !self.enabled && has_wifi_up_request {
            log::info!("WIFI is off; explicit wifi up request restores WIFI");
            self.enabled = true;
            self.enabled_flag.store(true, Ordering::Release);
        }

        let mut available_wifi_phys: Vec<String> = Vec::new();
        // Map of wifi-phy name to its current kernel if_index, used to
        // detect a phy that was recreated (e.g. wifi driver module
        // reload): the cached shuli client is then bound to a dead
        // device and must be restarted.
        let mut wifi_phys_if_index: HashMap<String, u32> = HashMap::new();
        {
            let mut filter = nispor::NetStateFilter::minimum();
            filter.iface = Some(nispor::NetStateIfaceFilter::minimum());
            if let Ok(np_state) =
                nispor::NetState::retrieve_with_filter_async(&filter).await
            {
                for np_iface in np_state.ifaces.values() {
                    if np_iface.iface_type == nispor::IfaceType::Wifi {
                        available_wifi_phys.push(np_iface.name.to_string());
                        wifi_phys_if_index
                            .insert(np_iface.name.to_string(), np_iface.index);
                    }
                }
            }
        }

        // Group every desired wifi config by the phy it binds to. All
        // SSIDs of one phy go into a single shuli network list.
        let mut desired: HashMap<String, Vec<&WifiConfig>> = HashMap::new();
        let mut iface_names_to_delete: HashSet<&str> = HashSet::new();
        let mut ssids_to_delete: HashSet<&str> = HashSet::new();

        for iface in ifaces {
            let wifi_cfg = match iface {
                Interface::WifiCfg(iface) => iface.wifi.as_ref(),
                Interface::WifiPhy(iface) => iface.wifi.as_ref(),
                _ => continue,
            };
            if iface.is_absent() || iface.is_down() {
                if iface.iface_type() == &InterfaceType::WifiPhy {
                    iface_names_to_delete.insert(iface.kernel_iface_name());
                } else if let Some(wifi_cfg) = wifi_cfg {
                    // wifi-cfg removal: drop the SSID from every phy
                    // that currently has it configured.
                    ssids_to_delete.insert(wifi_cfg.ssid.as_str());
                } else {
                    // An absent wifi-cfg strips its wifi section; the
                    // profile name is the SSID it was created for.
                    ssids_to_delete.insert(iface.name());
                }
                continue;
            } else if !iface.is_up() {
                return Err(NipartError::new(
                    ErrorKind::Bug,
                    format!(
                        "NipartWpaConn::apply(): Got invalid interface state: \
                         {iface}"
                    ),
                ));
            }
            let Some(wifi_cfg) = wifi_cfg else {
                continue;
            };
            log::trace!("Applying {wifi_cfg}");
            let iface_name = if iface.iface_type() == &InterfaceType::WifiPhy {
                iface.kernel_iface_name().to_string()
            } else if let Some(iface_name) = wifi_cfg.base_iface.as_ref() {
                iface_name.clone()
            } else if let Some(iface_name) = available_wifi_phys.first() {
                iface_name.clone()
            } else {
                log::warn!(
                    "WifiCfg interface {} has no base_iface specified, no \
                     wifi-phy available to bind to",
                    iface.name()
                );
                continue;
            };
            desired.entry(iface_name).or_default().push(wifi_cfg);
        }

        let mut recreate = false;

        // Remove clients for phys explicitly absent/down in this apply.
        for iface_name in &iface_names_to_delete {
            if self.ifaces.remove(*iface_name).is_some() {
                log::info!("Disconnecting WIFI on {iface_name}");
                recreate = true;
            }
        }

        // Update the per-interface desired state. A phy that was
        // recreated (or is gone) forces the single client to be rebuilt.
        let iface_names: Vec<String> = self.ifaces.keys().cloned().collect();
        let mut pending_networks: HashMap<String, Vec<ShuliNetworkConfig>> =
            HashMap::new();
        for iface_name in iface_names {
            let Some(iface_state) = self.ifaces.get_mut(&iface_name) else {
                continue;
            };
            if wifi_phys_if_index
                .get(&iface_name)
                .is_none_or(|if_index| *if_index != iface_state.if_index)
            {
                log::warn!(
                    "WIFI {iface_name} device changed or gone, restarting \
                     client"
                );
                self.ifaces.remove(&iface_name);
                recreate = true;
                continue;
            }
            // An apply that does not mention this phy (e.g. the daemon
            // re-applying the IP config of a wifi-phy after link up)
            // must not tear the connection down: only explicit
            // absent/down wifi-cfg entries remove SSIDs.
            // An explicit `npt up <SSID>` (a forced apply carrying exactly
            // one up wifi-cfg) must not drop the other saved networks from
            // the shuli client.  Keep the existing in-memory list and only
            // mark the requested SSID as preferred, so shuli tries it first
            // but can still fall back to the remaining saved networks when
            // it is unavailable or too weak.  Non-forced applies (boot's
            // full saved wifi-cfg set, `npt apply`) still replace the list
            // with exactly the requested set.
            let networks = match desired.get(&iface_name) {
                Some(wifi_cfgs) if force && wifi_cfgs.len() == 1 => {
                    merge_preferred_networks(
                        &iface_state.desired_networks,
                        wifi_cfgs,
                    )?
                }
                Some(wifi_cfgs) => build_shuli_networks(wifi_cfgs)?,
                None => {
                    let mut networks = iface_state.desired_networks.clone();
                    networks.retain(|network| {
                        !ssids_to_delete.contains(network.ssid.as_str())
                    });
                    networks
                }
            };
            // A forced single-SSID apply (e.g. `npt up`) records the
            // requested network as preferred. A later non-forced re-apply of
            // the same saved profile (e.g. the boot new-phy event) must not
            // clear that preference and restart the client.
            let network_list_changed = if force {
                iface_state.desired_networks != networks
            } else {
                !same_saved_networks_ignoring_prefered(
                    &iface_state.desired_networks,
                    &networks,
                )
            };
            if network_list_changed || (force && !networks.is_empty()) {
                pending_networks.insert(iface_name.clone(), networks);
            }
        }

        // Start managing phys that appear in the desired state for the
        // first time.
        for (iface_name, wifi_cfgs) in &desired {
            if self.ifaces.contains_key(iface_name) {
                continue;
            }
            let networks = if force && wifi_cfgs.len() == 1 {
                merge_preferred_networks(&[], wifi_cfgs)?
            } else {
                build_shuli_networks(wifi_cfgs)?
            };
            let if_index =
                wifi_phys_if_index.get(iface_name).copied().unwrap_or(0);
            self.ifaces.insert(
                iface_name.clone(),
                WifiIfaceState {
                    if_index,
                    desired_networks: networks,
                },
            );
            recreate = true;
        }

        // While WIFI is disabled, keep the desired network bookkeeping up
        // to date (so `npt wifi on` or a later explicit up can restore the
        // right profiles) but never start or drive the shuli client.
        if !self.enabled {
            for (iface_name, networks) in pending_networks.drain() {
                if let Some(iface_state) = self.ifaces.get_mut(&iface_name) {
                    iface_state.desired_networks = networks;
                }
            }
            return Ok(());
        }

        if self.client.is_none() && !self.ifaces.is_empty() {
            recreate = true;
        }

        if recreate {
            for (iface_name, networks) in pending_networks.drain() {
                if let Some(iface_state) = self.ifaces.get_mut(&iface_name) {
                    iface_state.desired_networks = networks;
                }
            }
            if let Some(client) = self.client.as_mut() {
                client.shutdown().await;
            }
            self.start_client().await;
            return Ok(());
        }

        // Update the existing client in place when no interface was
        // added, removed, or recreated.
        let preferred_ssids: HashMap<String, Option<String>> = desired
            .iter()
            .filter(|(_, wifi_cfgs)| force && wifi_cfgs.len() == 1)
            .map(|(iface_name, wifi_cfgs)| {
                (iface_name.clone(), Some(wifi_cfgs[0].ssid.clone()))
            })
            .collect();
        let force_reconnects: HashMap<String, bool> = pending_networks
            .iter()
            .map(|(iface_name, networks)| {
                let live_ssid = self.live_ssid(iface_name);
                let preferred_ssid = preferred_ssids
                    .get(iface_name)
                    .and_then(|ssid| ssid.as_deref());
                (
                    iface_name.clone(),
                    should_reconnect_to_networks(
                        live_ssid.as_deref(),
                        networks,
                        force,
                        preferred_ssid,
                    ),
                )
            })
            .collect();
        if let Some(client) = self.client.as_mut() {
            for (iface_name, networks) in pending_networks {
                if force_reconnects.get(&iface_name).copied().unwrap_or(false) {
                    log::info!(
                        "Restarting WIFI on {iface_name} to force connection"
                    );
                    if let Err(e) =
                        client.update_networks(&iface_name, Vec::new()).await
                    {
                        log::warn!(
                            "WIFI {iface_name} failed to update networks: {e}"
                        );
                        continue;
                    }
                }
                if networks.is_empty() {
                    log::info!(
                        "No WIFI network desired on {iface_name}, \
                         disconnecting"
                    );
                }
                if let Err(e) =
                    client.update_networks(&iface_name, networks.clone()).await
                {
                    log::warn!(
                        "WIFI {iface_name} failed to update networks: {e}"
                    );
                    continue;
                }
                if let Some(iface_state) = self.ifaces.get_mut(&iface_name) {
                    iface_state.desired_networks = networks;
                }
            }
        }

        Ok(())
    }

    fn live_ssid(&self, iface_name: &str) -> Option<String> {
        if let Ok(live_ifaces) = self.live_ifaces.lock() {
            live_ifaces.get(iface_name).map(|live| live.ssid.clone())
        } else {
            None
        }
    }

    async fn start_client(&mut self) {
        self.connected = false;
        self.clear_live_ifaces();
        if self.ifaces.is_empty() {
            self.client = None;
            return;
        }
        // A fresh client starts disconnected; keep the watchdog on the
        // short timeout until the first connect state is reported.
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        let configs: Vec<ShuliWifiConfig> = self
            .ifaces
            .iter()
            .map(|(iface_name, iface_state)| {
                let mut config = ShuliWifiConfig::new(iface_name);
                config.networks = iface_state.desired_networks.clone();
                config
            })
            .collect();
        log::info!(
            "Starting WIFI client on {}",
            configs
                .iter()
                .map(|config| config.iface_name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        match WifiClient::init(configs).await {
            Ok(client) => self.client = Some(client),
            Err(e) => {
                log::error!("WIFI init failed: {e}");
                self.client = None;
            }
        }
    }
}

fn has_wifi_ssid_up_request(ifaces: &[Interface]) -> bool {
    ifaces.iter().any(|iface| {
        if !iface.is_up() {
            return false;
        }
        let wifi_cfg = match iface {
            Interface::WifiCfg(iface) => iface.wifi.as_ref(),
            Interface::WifiPhy(iface) => iface.wifi.as_ref(),
            _ => None,
        };
        wifi_cfg.is_some_and(|cfg| !cfg.ssid.is_empty())
    })
}

fn mac_to_string(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Convert nipart wifi configs into one shuli network list, keeping the
/// order of the desired interfaces and de-duplicating SSIDs. Conflicting
/// credentials for the same SSID on the same phy are an error.
fn build_shuli_networks(
    wifi_cfgs: &[&WifiConfig],
) -> Result<Vec<ShuliNetworkConfig>, NipartError> {
    let mut ret: Vec<ShuliNetworkConfig> = Vec::new();
    for wifi_cfg in wifi_cfgs {
        if let Some(existing) = ret.iter().find(|n| n.ssid == wifi_cfg.ssid) {
            if existing.password.as_deref() != wifi_cfg.password.as_deref() {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "Conflicting WIFI config for SSID {} on the same \
                         interface",
                        wifi_cfg.ssid
                    ),
                ));
            }
            log::debug!("Ignoring duplicate WIFI SSID {}", wifi_cfg.ssid);
            continue;
        }
        ret.push(build_shuli_network(wifi_cfg));
    }
    Ok(ret)
}

/// Whether two network lists carry the same saved configuration.
///
/// `prefered` is a per-connection hint, not a saved property: nipart may
/// mark the requested SSID of a forced `npt up` as preferred, and a later
/// re-apply of the same saved profiles must not treat that as a change.
fn same_saved_networks_ignoring_prefered(
    current: &[ShuliNetworkConfig],
    desired: &[ShuliNetworkConfig],
) -> bool {
    current.len() == desired.len()
        && current.iter().zip(desired).all(|(cur, des)| {
            let mut cur = cur.clone();
            let mut des = des.clone();
            cur.prefered = false;
            des.prefered = false;
            cur == des
        })
}

/// Whether a forced apply must restart shuli's scan selection by clearing
/// and re-adding the network list.
///
/// A forced single-SSID request (e.g. `npt up <SSID>`) always restarts
/// scan selection so shuli re-scans and can pick a better BSSID, even when
/// the current SSID is already the requested one.  Full-list and unrelated
/// forced applies keep an existing connection when the phy is already on
/// one of the desired networks: `update_networks()` refreshes the list
/// without dropping it.
fn should_reconnect_to_networks(
    live_ssid: Option<&str>,
    networks: &[ShuliNetworkConfig],
    force: bool,
    preferred_ssid: Option<&str>,
) -> bool {
    if !force || networks.is_empty() {
        return false;
    }
    if preferred_ssid.is_some() {
        // Deliberately ignore `live_ssid` here: an explicit up of one SSID
        // must rescan even when it is already the connected SSID.
        return true;
    }
    !live_ssid
        .is_some_and(|ssid| networks.iter().any(|network| network.ssid == ssid))
}

fn build_shuli_network(wifi_cfg: &WifiConfig) -> ShuliNetworkConfig {
    let mut network = ShuliNetworkConfig::new(&wifi_cfg.ssid);
    network.set_hidden(wifi_cfg.hidden);
    if let Some(password) = wifi_cfg.password.as_deref() {
        network.set_password(password);
    }
    network
}

/// Merge an explicit single-SSID `npt up` request into the existing shuli
/// network list instead of replacing it: the requested SSID becomes
/// `prefered`, every other configured network is kept and demoted to
/// non-preferred (the latest request wins), and new SSIDs are appended.
fn merge_preferred_networks(
    existing: &[ShuliNetworkConfig],
    wifi_cfgs: &[&WifiConfig],
) -> Result<Vec<ShuliNetworkConfig>, NipartError> {
    let mut requested: Vec<ShuliNetworkConfig> = Vec::new();
    for wifi_cfg in wifi_cfgs {
        if let Some(existing) =
            requested.iter().find(|n| n.ssid == wifi_cfg.ssid)
        {
            if existing.password.as_deref() != wifi_cfg.password.as_deref() {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "Conflicting WIFI config for SSID {} on the same \
                         interface",
                        wifi_cfg.ssid
                    ),
                ));
            }
            continue;
        }
        let mut network = build_shuli_network(wifi_cfg);
        network.set_prefered(true);
        requested.push(network);
    }

    let mut ret: Vec<ShuliNetworkConfig> = Vec::new();
    for network in existing {
        match requested.iter().position(|n| n.ssid == network.ssid) {
            Some(idx) => ret.push(requested.remove(idx)),
            None => {
                let mut network = network.clone();
                network.prefered = false;
                ret.push(network);
            }
        }
    }
    ret.extend(requested);
    Ok(ret)
}

#[cfg(test)]
#[path = "unit_tests/apply.rs"]
mod tests;
