// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{
    JsonDisplayHideSecrets, NetworkState, NipartApplyOption, NipartCanIpc,
    NipartError, NipartIpcConnection, NipartPluginInfo, NipartQueryOption,
    NipartWifiControl, NipartWifiScanOption, WifiScanResult,
};

#[derive(Debug)]
pub struct NipartPluginClient {
    pub(crate) ipc: NipartIpcConnection,
}

/// Command send from daemon to plugin
#[derive(
    Debug, Clone, Serialize, Deserialize, PartialEq, JsonDisplayHideSecrets,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NipartPluginCmd {
    /// Query plugin info, should reply with [NipartPluginInfo]
    QueryPluginInfo,
    /// Query network state, should reply with [NetworkState]
    /// The `NipartQueryOption` and current kernel [NetworkState] are
    /// provided so plugins can use them instead of querying nispor again.
    QueryNetworkState(Box<(NipartQueryOption, NetworkState)>),
    ApplyNetworkState(Box<(NetworkState, NipartApplyOption)>),
    WifiScan(Box<NipartWifiScanOption>),
    WifiControl(NipartWifiControl),
    /// The host resumed from system suspend. Plugins should re-check the
    /// state they manage in the kernel and cancel any retry backoff that
    /// was armed before the suspend.
    SystemResume,
    Quit,
}

impl NipartCanIpc for NipartPluginCmd {
    fn ipc_kind(&self) -> String {
        match self {
            Self::QueryPluginInfo => "query-plugin-info".to_string(),
            Self::QueryNetworkState(_) => "query-network-state".to_string(),
            Self::ApplyNetworkState(_) => "apply-network-state".to_string(),
            Self::WifiScan(_) => "wifi-scan".to_string(),
            Self::WifiControl(_) => "wifi-control".to_string(),
            Self::SystemResume => "system-resume".to_string(),
            Self::Quit => "quit".to_string(),
        }
    }
}

impl NipartPluginCmd {
    pub fn hide_secrets(&mut self) {
        if let Self::ApplyNetworkState(state) = self {
            state.0.hide_secrets();
        }
    }
}

impl NipartPluginClient {
    /// Create IPC connect from daemon to plugin
    pub async fn new(socket_path: &str) -> Result<Self, NipartError> {
        let dst_name = std::path::Path::new(socket_path)
            .file_name()
            .and_then(|p| p.to_str())
            .unwrap_or("plugin");
        Ok(Self {
            ipc: NipartIpcConnection::new_with_path(
                socket_path,
                "daemon",
                dst_name,
            )
            .await?,
        })
    }

    pub async fn query_plugin_info(
        &mut self,
    ) -> Result<NipartPluginInfo, NipartError> {
        self.ipc.send(Ok(NipartPluginCmd::QueryPluginInfo)).await?;
        self.ipc.recv::<NipartPluginInfo>().await
    }

    pub async fn query_network_state(
        &mut self,
        opt: NipartQueryOption,
        cur_net_state: &NetworkState,
    ) -> Result<NetworkState, NipartError> {
        self.ipc
            .send(Ok(NipartPluginCmd::QueryNetworkState(Box::new((
                opt,
                cur_net_state.clone(),
            )))))
            .await?;
        self.ipc.recv::<NetworkState>().await
    }

    pub async fn apply_network_state(
        &mut self,
        desired_state: NetworkState,
        opt: NipartApplyOption,
    ) -> Result<(), NipartError> {
        self.ipc
            .send(Ok(NipartPluginCmd::ApplyNetworkState(Box::new((
                desired_state,
                opt,
            )))))
            .await?;
        self.ipc.recv::<()>().await
    }

    pub async fn wifi_scan(
        &mut self,
        option: NipartWifiScanOption,
    ) -> Result<Vec<WifiScanResult>, NipartError> {
        self.ipc
            .send(Ok(NipartPluginCmd::WifiScan(Box::new(option))))
            .await?;
        self.ipc.recv::<Vec<WifiScanResult>>().await
    }

    pub async fn wifi_control(
        &mut self,
        control: NipartWifiControl,
    ) -> Result<(), NipartError> {
        self.ipc
            .send(Ok(NipartPluginCmd::WifiControl(control)))
            .await?;
        self.ipc.recv::<()>().await
    }

    pub async fn system_resume(&mut self) -> Result<(), NipartError> {
        self.ipc.send(Ok(NipartPluginCmd::SystemResume)).await?;
        self.ipc.recv::<()>().await
    }

    pub async fn send<T>(
        &mut self,
        data: Result<T, NipartError>,
    ) -> Result<(), NipartError>
    where
        T: NipartCanIpc,
    {
        self.ipc.send::<T>(data).await
    }

    pub async fn recv<T>(&mut self) -> Result<T, NipartError>
    where
        T: NipartCanIpc,
    {
        self.ipc.recv::<T>().await
    }
}
