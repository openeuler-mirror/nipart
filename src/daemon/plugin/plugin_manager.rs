// SPDX-License-Identifier: Apache-2.0

use nipart::{
    ErrorKind, NetworkState, NipartApplyOption, NipartError, NipartQueryOption,
    NipartWifiControl, NipartWifiScanOption, WifiScanResult,
};

use super::{NipartPluginCmd, NipartPluginReply, NipartPluginWorker};
use crate::TaskManager;

#[derive(Debug, Clone)]
pub(crate) struct NipartPluginManager {
    mgr: TaskManager<NipartPluginCmd, NipartPluginReply>,
}

impl NipartPluginManager {
    pub(crate) async fn new() -> Result<Self, NipartError> {
        Ok(Self {
            mgr: TaskManager::new::<NipartPluginWorker>("plugin").await?,
        })
    }

    pub(crate) async fn shutdown(&self) {
        self.mgr.shutdown().await
    }

    // TODO: Support redirect logs from plugin to user
    pub(crate) async fn wifi_scan(
        &mut self,
        opt: NipartWifiScanOption,
    ) -> Result<Vec<WifiScanResult>, NipartError> {
        let reply = self
            .mgr
            .exec(NipartPluginCmd::WifiScan(Box::new(opt)))
            .await?;
        if let NipartPluginReply::WifiScanResult(r) = reply {
            Ok(r)
        } else {
            Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "NipartPluginCmd::WifiScan is not replying with \
                     NipartPluginReply::WifiScanResult, but {reply:?}"
                ),
            ))
        }
    }

    // TODO: Support redirect logs from plugin to user
    pub(crate) async fn query_network_state(
        &mut self,
        opt: NipartQueryOption,
        cur_net_state: &NetworkState,
    ) -> Result<Vec<NetworkState>, NipartError> {
        let reply = self
            .mgr
            .exec(NipartPluginCmd::QueryNetworkState(Box::new((
                opt,
                cur_net_state.clone(),
            ))))
            .await?;
        if let NipartPluginReply::States(s) = reply {
            Ok(s)
        } else {
            Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "NipartPluginCmd::QueryNetworkState is not replying with \
                     NipartPluginReply::States, but {reply:?}"
                ),
            ))
        }
    }

    // TODO: Support redirect logs from plugin to user
    pub(crate) async fn apply_network_state(
        &mut self,
        state: &NetworkState,
        opt: &NipartApplyOption,
    ) -> Result<(), NipartError> {
        self.mgr
            .exec(NipartPluginCmd::ApplyNetworkState(Box::new((
                state.clone(),
                opt.clone(),
            ))))
            .await?;
        Ok(())
    }

    // TODO: Support redirect logs from plugin to user
    pub(crate) async fn wifi_control(
        &mut self,
        control: NipartWifiControl,
    ) -> Result<(), NipartError> {
        let reply =
            self.mgr.exec(NipartPluginCmd::WifiControl(control)).await?;
        if let NipartPluginReply::None = reply {
            Ok(())
        } else {
            Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "NipartPluginCmd::WifiControl is not replying with \
                     NipartPluginReply::None, but {reply:?}"
                ),
            ))
        }
    }

    /// Notify every plugin that the host resumed from system suspend.
    pub(crate) async fn system_resume(&mut self) -> Result<(), NipartError> {
        let reply = self.mgr.exec(NipartPluginCmd::SystemResume).await?;
        if let NipartPluginReply::None = reply {
            Ok(())
        } else {
            Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "NipartPluginCmd::SystemResume is not replying with \
                     NipartPluginReply::None, but {reply:?}"
                ),
            ))
        }
    }
}
