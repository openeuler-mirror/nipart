// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{
    JsonDisplayHideSecrets, NetworkState, NipartApplyOption, NipartCanIpc,
    NipartError, NipartIpcConnection, NipartQueryOption, NipartWifiControl,
    NipartWifiScanOption, WifiScanResult,
};

impl NipartCanIpc for NetworkState {
    fn ipc_kind(&self) -> String {
        "network_state".to_string()
    }
}

#[derive(Debug)]
pub struct NipartClient {
    pub(crate) ipc: NipartIpcConnection,
}

#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, JsonDisplayHideSecrets,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NipartClientCmd {
    Ping,
    QueryNetworkState(Box<NipartQueryOption>),
    ApplyNetworkState(Box<(NetworkState, NipartApplyOption)>),
    UpInterface(String),
    DownInterface(String),
    WaitOnline,
    WifiScan(Box<NipartWifiScanOption>),
    WifiControl(NipartWifiControl),
}

impl NipartCanIpc for Vec<WifiScanResult> {
    fn ipc_kind(&self) -> String {
        "wifi-scan-result".to_string()
    }
}

impl NipartCanIpc for NipartClientCmd {
    fn ipc_kind(&self) -> String {
        match self {
            Self::Ping => "ping".to_string(),
            Self::QueryNetworkState(_) => "query-network-state".to_string(),
            Self::ApplyNetworkState(_) => "apply-network-state".to_string(),
            Self::UpInterface(_) => "up-interface".to_string(),
            Self::DownInterface(_) => "down-interface".to_string(),
            Self::WaitOnline => "wait-online".to_string(),
            Self::WifiScan(_) => "wifi-scan".to_string(),
            Self::WifiControl(_) => "wifi-control".to_string(),
        }
    }
}

impl NipartClientCmd {
    pub fn hide_secrets(&mut self) {
        if let NipartClientCmd::ApplyNetworkState(state) = self {
            state.0.hide_secrets();
        }
    }
}

impl NipartClient {
    pub const DEFAULT_SOCKET_PATH: &'static str =
        "/var/run/nipart/sockets/daemon";

    // The daemon is authoritative on how long `wait-online` should wait
    // (configurable via the saved state `wait-online.timeout-sec`, default
    // 30 seconds). Use a generous IPC timeout so the client doesn't race
    // the daemon's wait with our shorter 30s default IPC timeout. This is a
    // ceiling: a saved `timeout-sec` larger than this (10 minutes) is still
    // capped by this IPC timeout.
    const WAIT_ONLINE_IPC_TIMEOUT_MS: u32 = 10 * 60 * 1000;
    // Explicit up/down actions may wait for WIFI association and DHCP lease
    // acquisition, which can exceed the default 30 second IPC timeout.
    const IFACE_ACTION_IPC_TIMEOUT_MS: u32 = 10 * 60 * 1000;
    // An apply can wait for WIFI association (e.g. `npt wifi connect` or
    // `npt apply` of a wifi profile) and DHCP, which may exceed the
    // default 30 second IPC timeout; the daemon's own waits are bounded.
    const APPLY_IPC_TIMEOUT_MS: u32 = 10 * 60 * 1000;

    /// Create IPC connect to nipart daemon
    pub async fn new() -> Result<Self, NipartError> {
        Self::new_with_name("client").await
    }

    pub async fn new_with_name(name: &str) -> Result<Self, NipartError> {
        Ok(Self {
            ipc: NipartIpcConnection::new_with_path(
                Self::DEFAULT_SOCKET_PATH,
                name,
                "daemon",
            )
            .await?,
        })
    }

    pub async fn ping(&mut self) -> Result<String, NipartError> {
        self.ipc.send(Ok(NipartClientCmd::Ping)).await?;
        self.ipc.recv::<String>().await
    }

    pub async fn query_network_state(
        &mut self,
        option: NipartQueryOption,
    ) -> Result<NetworkState, NipartError> {
        self.ipc
            .send(Ok(NipartClientCmd::QueryNetworkState(Box::new(option))))
            .await?;
        self.ipc.recv::<NetworkState>().await
    }

    pub async fn apply_network_state(
        &mut self,
        desired_state: NetworkState,
        option: NipartApplyOption,
    ) -> Result<NetworkState, NipartError> {
        let original_timeout = self.ipc.timeout_ms;
        self.ipc.set_timeout(Self::APPLY_IPC_TIMEOUT_MS);
        self.ipc
            .send(Ok(NipartClientCmd::ApplyNetworkState(Box::new((
                desired_state,
                option,
            )))))
            .await?;
        let ret = self.ipc.recv::<NetworkState>().await;
        self.ipc.set_timeout(original_timeout);
        ret
    }

    pub async fn up_interface(
        &mut self,
        name: &str,
    ) -> Result<NetworkState, NipartError> {
        let original_timeout = self.ipc.timeout_ms;
        self.ipc.set_timeout(Self::IFACE_ACTION_IPC_TIMEOUT_MS);
        self.ipc
            .send(Ok(NipartClientCmd::UpInterface(name.to_string())))
            .await?;
        let ret = self.ipc.recv::<NetworkState>().await;
        self.ipc.set_timeout(original_timeout);
        ret
    }

    pub async fn down_interface(
        &mut self,
        name: &str,
    ) -> Result<NetworkState, NipartError> {
        let original_timeout = self.ipc.timeout_ms;
        self.ipc.set_timeout(Self::IFACE_ACTION_IPC_TIMEOUT_MS);
        self.ipc
            .send(Ok(NipartClientCmd::DownInterface(name.to_string())))
            .await?;
        let ret = self.ipc.recv::<NetworkState>().await;
        self.ipc.set_timeout(original_timeout);
        ret
    }

    pub async fn wait_online(&mut self) -> Result<(), NipartError> {
        self.ipc.send(Ok(NipartClientCmd::WaitOnline)).await?;
        let original_timeout = self.ipc.timeout_ms;
        self.ipc.set_timeout(Self::WAIT_ONLINE_IPC_TIMEOUT_MS);
        let ret = self.ipc.recv::<()>().await;
        self.ipc.set_timeout(original_timeout);
        ret
    }

    pub async fn wifi_scan(
        &mut self,
        option: NipartWifiScanOption,
    ) -> Result<Vec<WifiScanResult>, NipartError> {
        self.ipc
            .send(Ok(NipartClientCmd::WifiScan(Box::new(option))))
            .await?;
        self.ipc.recv::<Vec<WifiScanResult>>().await
    }

    pub async fn wifi_control(
        &mut self,
        control: NipartWifiControl,
    ) -> Result<(), NipartError> {
        self.ipc
            .send(Ok(NipartClientCmd::WifiControl(control)))
            .await?;
        self.ipc.recv::<()>().await
    }
}
