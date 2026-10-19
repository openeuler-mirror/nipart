// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use nipart::{
    ErrorKind, Interface, InterfaceType, NetworkState, NipartApplyOption,
    NipartError, NipartInterface, NipartIpcConnection, NipartPlugin,
    NipartPluginInfo, NipartQueryOption,
};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::apply::{ApplyRequest, MkaWorker};

#[derive(Debug)]
pub(crate) struct NipartPlugin8021x {
    worker_tx: UnboundedSender<ApplyRequest>,
}

impl NipartPlugin for NipartPlugin8021x {
    const PLUGIN_NAME: &'static str = "8021x";

    async fn init() -> Result<Self, NipartError> {
        let (worker_tx, worker_rx) = unbounded_channel();
        tokio::spawn(MkaWorker::new().run(worker_rx));
        Ok(Self { worker_tx })
    }

    async fn plugin_info(
        _plugin: &Arc<Self>,
    ) -> Result<NipartPluginInfo, NipartError> {
        Ok(NipartPluginInfo::new(
            "8021x".to_string(),
            "0.1.0".to_string(),
            vec![InterfaceType::MacSec],
        ))
    }

    async fn query_network_state(
        _plugin: &Arc<Self>,
        _opt: NipartQueryOption,
        _cur_net_state: &NetworkState,
        conn: &mut NipartIpcConnection,
    ) -> Result<NetworkState, NipartError> {
        conn.log_trace("802.1X plugin query_network_state".to_string())
            .await;
        // The kernel MACsec state is queried by nispor; MKA keys and the
        // live key agreement state are not kernel properties.
        Ok(NetworkState::default())
    }

    async fn apply_network_state(
        plugin: &Arc<Self>,
        desired_state: NetworkState,
        opt: NipartApplyOption,
        conn: &mut NipartIpcConnection,
    ) -> Result<(), NipartError> {
        conn.log_trace(format!(
            "802.1X plugin apply_network_state with state {desired_state}"
        ))
        .await;
        // Never block: the worker starts/stops the shuli MKA sessions and
        // the daemon verification stage only checks the kernel state.
        let ifaces: Vec<Interface> = desired_state
            .ifaces
            .iter()
            .filter(|iface| iface.iface_type() == &InterfaceType::MacSec)
            .cloned()
            .collect();
        plugin
            .worker_tx
            .send(ApplyRequest {
                ifaces,
                force: opt.force,
            })
            .map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!("Failed to enqueue 802.1X apply request: {e}"),
                )
            })
    }
}
