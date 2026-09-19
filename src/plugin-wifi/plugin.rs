// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use nipart::{
    ErrorKind, Interface, InterfaceType, NetworkState, NipartApplyOption,
    NipartError, NipartIpcConnection, NipartPlugin, NipartPluginInfo,
    NipartQueryOption, NipartWifiControl, NipartWifiScanOption, WifiScanResult,
};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::{
    NipartWpaConn,
    apply::{WifiClientState, WifiLiveState},
};

/// Maximum time a single shuli client cycle may run before the plugin
/// assumes the client is stuck and restarts it.  This prevents a long
/// shuli backoff (or a wedged PNO/host-scan state) from silently
/// disabling auto-connect forever.
const WIFI_RUN_ONCE_TIMEOUT_SECS: u64 = 120;
/// Timeout used while shuli is connected: the client legitimately waits
/// for events with no deadline, so only an extremely long stall should be
/// treated as stuck.
const WIFI_CONNECTED_RUN_ONCE_TIMEOUT_SECS: u64 = 24 * 60 * 60;

#[derive(Debug)]
pub(crate) struct NipartPluginWifi {
    worker_tx: tokio::sync::mpsc::UnboundedSender<WifiWorkerRequest>,
    wifi_enabled: Arc<AtomicBool>,
    wifi_live: Arc<Mutex<HashMap<String, WifiLiveState>>>,
}

#[derive(Debug)]
enum WifiWorkerRequest {
    Apply(Vec<Interface>, NipartApplyOption),
    Control(
        NipartWifiControl,
        tokio::sync::oneshot::Sender<Result<(), NipartError>>,
    ),
    Resume,
}

/// Dedicated worker processing wifi apply requests serially in arrival
/// order. Slow operations (connecting via shuli) are
/// performed here so that `apply_network_state()` never blocks the daemon
/// connection handling, and `query_network_state()` is never stalled by an
/// on-going apply.  The worker also owns every live wifi connection
/// ([`WifiClientState`]): when the daemon connection is gone it tears
/// the single client down.  WIFI on/off control is also serialized here
/// so a disable always runs after any queued apply and before any later
/// one.
async fn apply_worker(
    mut rx: UnboundedReceiver<WifiWorkerRequest>,
    wifi_enabled: Arc<AtomicBool>,
    wifi_live: Arc<Mutex<HashMap<String, WifiLiveState>>>,
) {
    let mut wifi_state = WifiClientState::new(wifi_enabled, wifi_live);
    loop {
        let run_once_timeout_secs = if wifi_state.is_connected() {
            WIFI_CONNECTED_RUN_ONCE_TIMEOUT_SECS
        } else {
            WIFI_RUN_ONCE_TIMEOUT_SECS
        };
        tokio::select! {
            biased;
            maybe = rx.recv() => {
                match maybe {
                    Some(WifiWorkerRequest::Apply(ifaces, opt)) => {
                        if let Err(e) = wifi_state
                            .apply(ifaces.as_slice(), opt.force)
                            .await
                        {
                            log::error!(
                                "WIFI plugin failed to apply state: {e}"
                            );
                        }
                    }
                    Some(WifiWorkerRequest::Control(control, reply)) => {
                        let result = wifi_state.set_control(control).await;
                        if let Err(e) = &result {
                            log::error!(
                                "WIFI plugin failed to set control \
                                 {control}: {e}"
                            );
                        }
                        let _ = reply.send(result);
                    }
                    Some(WifiWorkerRequest::Resume) => {
                        wifi_state.notify_resume();
                    }
                    None => {
                        wifi_state.shutdown().await;
                        break;
                    }
                }
            }
            result = tokio::time::timeout(
                Duration::from_secs(run_once_timeout_secs),
                wifi_state.run_once(),
            ), if wifi_state.has_client() => {
                match result {
                    Ok(result) => {
                        if let Err(e) = result {
                            log::error!(
                                "WIFI plugin failed to drive client: {e}"
                            );
                        }
                    }
                    Err(_) => {
                        log::error!(
                            "WIFI client stalled for {}s; restarting it",
                            run_once_timeout_secs
                        );
                        wifi_state.restart_client().await;
                    }
                }
            }
        }
    }
}

impl NipartPlugin for NipartPluginWifi {
    const PLUGIN_NAME: &'static str = "wifi";

    async fn init() -> Result<Self, NipartError> {
        let (worker_tx, worker_rx) = unbounded_channel();
        let wifi_enabled = Arc::new(AtomicBool::new(true));
        let wifi_live = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(apply_worker(
            worker_rx,
            wifi_enabled.clone(),
            wifi_live.clone(),
        ));
        Ok(Self {
            worker_tx,
            wifi_enabled,
            wifi_live,
        })
    }

    async fn plugin_info(
        _plugin: &Arc<Self>,
    ) -> Result<NipartPluginInfo, NipartError> {
        Ok(NipartPluginInfo::new(
            "wifi".to_string(),
            "0.1.0".to_string(),
            vec![InterfaceType::WifiCfg, InterfaceType::WifiPhy],
        ))
    }

    async fn query_network_state(
        plugin: &Arc<Self>,
        _opt: NipartQueryOption,
        _cur_net_state: &NetworkState,
        conn: &mut NipartIpcConnection,
    ) -> Result<NetworkState, NipartError> {
        conn.log_trace("WIFI plugin query_network_state".to_string())
            .await;
        // Query only reads the shuli live connection state kept by the
        // apply worker; it never triggers a scan or blocks the worker.
        let live_ifaces = plugin.wifi_live.lock().map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!("Failed to lock wifi live state: {e}"),
            )
        })?;
        Ok(NipartWpaConn::network_state_from_live_ifaces(&live_ifaces))
    }

    async fn apply_network_state(
        plugin: &Arc<Self>,
        mut desired_state: NetworkState,
        _opt: NipartApplyOption,
        conn: &mut NipartIpcConnection,
    ) -> Result<(), NipartError> {
        conn.log_trace(format!(
            "WIFI plugin apply_network_state with state {desired_state}"
        ))
        .await;
        let ifaces: Vec<Interface> = desired_state.ifaces.drain().collect();
        // Never block: enqueue the request to the dedicated apply worker
        // and return immediately. The daemon verification stage waits and
        // retries until the applied state matches the desired state.
        plugin
            .worker_tx
            .send(WifiWorkerRequest::Apply(ifaces, _opt.clone()))
            .map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!("Failed to enqueue wifi apply request: {e}"),
                )
            })
    }

    async fn wifi_scan(
        plugin: &Arc<Self>,
        opt: NipartWifiScanOption,
        conn: &mut NipartIpcConnection,
    ) -> Result<Vec<WifiScanResult>, NipartError> {
        conn.log_trace(format!("WIFI plugin wifi_scan with option {opt}"))
            .await;
        if !plugin.wifi_enabled.load(Ordering::Acquire) {
            return Err(NipartError::new(
                ErrorKind::PluginFailure,
                "WIFI is off; run `npt wifi on`, `npt wifi connect`, or `npt \
                 up` on a wifi interface to restore it"
                    .to_string(),
            ));
        }
        let NipartWifiScanOption {
            iface_name,
            hidden_ssids,
            ..
        } = opt;
        NipartWpaConn::wifi_scan(iface_name.as_deref(), hidden_ssids).await
    }

    async fn wifi_control(
        plugin: &Arc<Self>,
        control: NipartWifiControl,
        conn: &mut NipartIpcConnection,
    ) -> Result<(), NipartError> {
        conn.log_trace(format!("WIFI plugin wifi_control with {control}"))
            .await;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        plugin
            .worker_tx
            .send(WifiWorkerRequest::Control(control, reply_tx))
            .map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!("Failed to enqueue wifi control request: {e}"),
                )
            })?;
        reply_rx.await.map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!("Failed to receive wifi control reply: {e}"),
            )
        })?
    }

    async fn system_resume(
        plugin: &Arc<Self>,
        conn: &mut NipartIpcConnection,
    ) -> Result<(), NipartError> {
        conn.log_debug("WIFI plugin system_resume".to_string())
            .await;
        if !plugin.wifi_enabled.load(Ordering::Acquire) {
            log::debug!("Ignoring system resume because WIFI is off");
            return Ok(());
        }
        // Never block: the apply worker owns the live shuli client and
        // forwards the notification to it, which re-checks the kernel
        // association and cancels any pending retry backoff.
        plugin
            .worker_tx
            .send(WifiWorkerRequest::Resume)
            .map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!("Failed to enqueue wifi resume request: {e}"),
                )
            })
    }
}
