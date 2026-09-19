// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    ErrorKind, NetworkState, NipartApplyOption, NipartError,
    NipartIpcConnection, NipartIpcListener, NipartPluginCmd, NipartPluginInfo,
    NipartQueryOption, NipartWifiControl, NipartWifiScanOption, WifiScanResult,
};

pub trait NipartPlugin: Send + Sync + Sized + 'static {
    const PLUGIN_NAME: &'static str;

    fn init() -> impl Future<Output = Result<Self, NipartError>> + Send;

    /// Default implementation is `std::process::exit(0)`
    fn quit(_plugin: &Arc<Self>) -> impl Future<Output = ()> + Send {
        async {
            std::process::exit(0);
        }
    }

    fn plugin_info(
        plugin: &Arc<Self>,
    ) -> impl Future<Output = Result<NipartPluginInfo, NipartError>> + Send;

    /// The `&self` will cloned and move to forked thread for each connection.
    fn run() -> impl Future<Output = Result<(), NipartError>> + Send {
        // TODO(Gris Ge): Do we need to ping daemon to make sure daemon is
        // still alive?
        async {
            let plugin = Arc::new(Self::init().await?);

            let socket_path = format!(
                "{}/{}",
                "/var/run/nipart/sockets/plugin",
                Self::PLUGIN_NAME
            );
            let ipc = NipartIpcListener::new(&socket_path)?;
            log::debug!("Listening on {socket_path}");

            loop {
                if let Ok(conn) = ipc.accept().await {
                    log::debug!("Got daemon connection");
                    let plugin_clone = plugin.clone();
                    tokio::spawn(async move {
                        Self::process_connection(plugin_clone, conn).await
                    });
                }
            }
        }
    }

    fn process_connection(
        plugin: Arc<Self>,
        mut conn: NipartIpcConnection,
    ) -> impl Future<Output = Result<(), NipartError>> + Send {
        async move {
            loop {
                let cmd = conn.recv::<NipartPluginCmd>().await?;
                log::debug!("Got {cmd} from daemon");
                match cmd {
                    NipartPluginCmd::QueryPluginInfo => {
                        conn.send(Self::plugin_info(&plugin).await).await?
                    }
                    NipartPluginCmd::Quit => {
                        Self::quit(&plugin).await;
                    }
                    NipartPluginCmd::QueryNetworkState(cmd) => {
                        let (opt, cur_net_state) = *cmd;
                        let result = Self::query_network_state(
                            &plugin,
                            opt,
                            &cur_net_state,
                            &mut conn,
                        )
                        .await;
                        conn.send(result).await?
                    }
                    NipartPluginCmd::ApplyNetworkState(opt) => {
                        let (desired_state, opt) = *opt;
                        let result = Self::apply_network_state(
                            &plugin,
                            desired_state,
                            opt,
                            &mut conn,
                        )
                        .await;
                        conn.send(result).await?
                    }
                    NipartPluginCmd::WifiScan(opt) => {
                        let result =
                            Self::wifi_scan(&plugin, *opt, &mut conn).await;
                        conn.send(result).await?
                    }
                    NipartPluginCmd::WifiControl(control) => {
                        let result =
                            Self::wifi_control(&plugin, control, &mut conn)
                                .await;
                        conn.send(result).await?
                    }
                    NipartPluginCmd::SystemResume => {
                        let result =
                            Self::system_resume(&plugin, &mut conn).await;
                        conn.send(result).await?
                    }
                }
            }
        }
    }

    /// Return network state managed by this plugin only.
    /// Optionally, you may send log via `conn::log_debug()` and etc.
    /// The `cur_net_state` is the current kernel network state queried by
    /// the daemon via nispor. Plugins can use it instead of querying nispor
    /// themselves.
    /// Default implementation is return no support error.
    ///
    /// This function must never block: it should only read the live
    /// configuration of the managed service (e.g. wpa_supplicant over
    /// D-Bus) and return quickly. It must not trigger slow actions such
    /// as wifi scan.
    fn query_network_state(
        _plugin: &Arc<Self>,
        _opt: NipartQueryOption,
        _cur_net_state: &NetworkState,
        _conn: &mut NipartIpcConnection,
    ) -> impl Future<Output = Result<NetworkState, NipartError>> + Send {
        async {
            Err(NipartError::new(
                ErrorKind::NoSupport,
                format!(
                    "Plugin {} has not implemented query_network_state()",
                    Self::PLUGIN_NAME
                ),
            ))
        }
    }

    /// Apply network state managed by this plugin only.
    /// Optionally, you may send log via `conn::log_debug()` and etc.
    ///
    /// This function must never block: slow work (e.g. wifi active scan)
    /// must be off-loaded to a dedicated worker thread taking requests via
    /// an `UnboundedReceiver`, and this function only enqueues the request
    /// and returns immediately. Errors detected in the worker thread should
    /// be logged instead of returned, since the reply may already have been
    /// sent. The daemon verification stage will wait and retry until the
    /// applied state matches the desired state.
    fn apply_network_state(
        _plugin: &Arc<Self>,
        _desired_state: NetworkState,
        _opt: NipartApplyOption,
        _conn: &mut NipartIpcConnection,
    ) -> impl Future<Output = Result<(), NipartError>> + Send {
        async {
            Err(NipartError::new(
                ErrorKind::NoSupport,
                format!(
                    "Plugin {} has not implemented apply_network_state()",
                    Self::PLUGIN_NAME
                ),
            ))
        }
    }

    /// Perform wifi active scan.
    /// Default implementation returns unsupported error.
    fn wifi_scan(
        _plugin: &Arc<Self>,
        _opt: NipartWifiScanOption,
        _conn: &mut NipartIpcConnection,
    ) -> impl Future<Output = Result<Vec<WifiScanResult>, NipartError>> + Send
    {
        async {
            Err(NipartError::new(
                ErrorKind::NoSupport,
                format!(
                    "Plugin {} has not implemented wifi_scan()",
                    Self::PLUGIN_NAME
                ),
            ))
        }
    }

    /// Enable or disable the WIFI function of the plugin.
    ///
    /// `Off` must stop all WIFI actions (scanning, connecting, and any
    /// ongoing shuli client work) and `On` must restore them. The default
    /// implementation returns an unsupported error.
    fn wifi_control(
        _plugin: &Arc<Self>,
        _control: NipartWifiControl,
        _conn: &mut NipartIpcConnection,
    ) -> impl Future<Output = Result<(), NipartError>> + Send {
        async {
            Err(NipartError::new(
                ErrorKind::NoSupport,
                format!(
                    "Plugin {} has not implemented wifi_control()",
                    Self::PLUGIN_NAME
                ),
            ))
        }
    }

    /// Notify the plugin that the host resumed from system suspend.
    ///
    /// A plugin must re-check the state it manages in the kernel: a
    /// connection that did not survive the suspend has to be
    /// re-established, and a retry backoff armed before the suspend must
    /// not delay the first attempt after wake. The default
    /// implementation returns an unsupported error.
    fn system_resume(
        _plugin: &Arc<Self>,
        _conn: &mut NipartIpcConnection,
    ) -> impl Future<Output = Result<(), NipartError>> + Send {
        async {
            Err(NipartError::new(
                ErrorKind::NoSupport,
                format!(
                    "Plugin {} has not implemented system_resume()",
                    Self::PLUGIN_NAME
                ),
            ))
        }
    }
}
