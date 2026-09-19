// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    env::current_exe,
    os::unix::fs::{FileTypeExt, PermissionsExt},
};

use futures_channel::{mpsc::UnboundedReceiver, oneshot::Sender};
use futures_util::{StreamExt, stream::FuturesUnordered};
use nipart::{
    ErrorKind, InterfaceType, NetworkState, NipartApplyOption, NipartError,
    NipartInterface, NipartNoDaemon, NipartPluginClient, NipartQueryOption,
    NipartWifiControl, NipartWifiScanOption, WifiScanResult,
};

const NPT_PLUGIN_SOCK_DIR: &str = "/var/run/nipart/sockets/plugin";

use super::plugin_exec::NipartDaemonPlugin;
use crate::TaskWorker;

const NPT_PLUGIN_PREFIX: &str = "nipart-plugin-";
const NPT_PLUGIN_CONN_RETRY: i8 = 50;
const NPT_PLUGIN_CONN_RETRY_INTERVAL_MS: u64 = 200;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NipartPluginCmd {
    QueryNetworkState(Box<(NipartQueryOption, NetworkState)>),
    ApplyNetworkState(Box<(NetworkState, NipartApplyOption)>),
    WifiScan(Box<NipartWifiScanOption>),
    WifiControl(NipartWifiControl),
    SystemResume,
}

impl std::fmt::Display for NipartPluginCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueryNetworkState(_) => {
                write!(f, "query-network-state")
            }
            Self::ApplyNetworkState(_) => {
                write!(f, "apply-network-state")
            }
            Self::WifiScan(_) => {
                write!(f, "wifi-scan")
            }
            Self::WifiControl(_) => {
                write!(f, "wifi-control")
            }
            Self::SystemResume => {
                write!(f, "system-resume")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NipartPluginReply {
    None,
    States(Vec<NetworkState>),
    WifiScanResult(Vec<WifiScanResult>),
}

type FromManager = (
    NipartPluginCmd,
    Sender<Result<NipartPluginReply, NipartError>>,
);

#[derive(Debug)]
pub(crate) struct NipartPluginWorker {
    receiver: UnboundedReceiver<FromManager>,
    plugins: HashMap<String, NipartDaemonPlugin>,
    children: Vec<std::process::Child>,
    supported_types: HashSet<InterfaceType>,
}

impl TaskWorker for NipartPluginWorker {
    type Cmd = NipartPluginCmd;
    type Reply = NipartPluginReply;

    async fn new(
        receiver: UnboundedReceiver<FromManager>,
    ) -> Result<Self, NipartError> {
        if let Err(e) = std::fs::create_dir_all(NPT_PLUGIN_SOCK_DIR) {
            log::info!("Failed to create {}: {e}", NPT_PLUGIN_SOCK_DIR);
        }

        let plugin_paths = get_plugin_files();

        let mut expected_plugin_count = 0;
        let mut children: Vec<std::process::Child> = Vec::new();
        for plugin_path in plugin_paths {
            if std::path::Path::new(&plugin_path)
                .file_name()
                .and_then(|p| p.to_str())
                == Some("nipart-plugin-demo")
            {
                log::debug!("Ignored demo plugin");
                continue;
            }
            log::debug!("Starting nipart plugin {}", plugin_path);
            match std::process::Command::new(&plugin_path).spawn() {
                Ok(child) => children.push(child),
                Err(e) => {
                    log::info!(
                        "Ignoring plugin {plugin_path} due to error: {e}"
                    );
                }
            }
            expected_plugin_count += 1;
        }

        let mut plugins: HashMap<String, NipartDaemonPlugin> = HashMap::new();
        let mut retry_left = NPT_PLUGIN_CONN_RETRY;

        while plugins.len() < expected_plugin_count && retry_left >= 0 {
            retry_left -= 1;
            connect_plugins(&mut plugins).await;
            tokio::time::sleep(std::time::Duration::from_millis(
                NPT_PLUGIN_CONN_RETRY_INTERVAL_MS,
            ))
            .await;
        }

        let mut supported_types = NipartNoDaemon::supported_iface_types();
        for plugin in plugins.values() {
            supported_types.extend(plugin.plugin_info.iface_types.clone());
        }

        Ok(Self {
            receiver,
            plugins,
            children,
            supported_types,
        })
    }

    fn receiver(&mut self) -> &mut UnboundedReceiver<FromManager> {
        &mut self.receiver
    }

    async fn process_cmd(
        &mut self,
        cmd: NipartPluginCmd,
    ) -> Result<NipartPluginReply, NipartError> {
        log::debug!("Processing plugin command: {cmd}");
        match cmd {
            NipartPluginCmd::QueryNetworkState(cmd) => {
                let (opt, cur_net_state) = *cmd;
                let mut ret = Vec::new();
                // TODO(Gris Ge): Should querying all plugin at the same time
                // instead of one by one.
                for plugin in self.plugins.values() {
                    match plugin.query_network_state(&opt, &cur_net_state).await
                    {
                        Ok(net_state) => ret.push(net_state),
                        Err(e) => {
                            log::info!("{e}");
                        }
                    }
                }

                Ok(NipartPluginReply::States(ret))
            }
            NipartPluginCmd::ApplyNetworkState(v) => {
                let (apply_state, opt) = *v;
                // TODO(Gris Ge): Should request all plugin at the same time
                // instead of one by one.
                let mut result_futures = FuturesUnordered::new();
                for plugin in self.plugins.values() {
                    let result_future =
                        plugin.apply_network_state(&apply_state, &opt);
                    result_futures.push(result_future);
                }

                while let Some(result) = result_futures.next().await {
                    match result {
                        Err(e) if e.kind() == ErrorKind::DependencyError => {
                            return Err(e);
                        }
                        Err(e) => {
                            log::warn!("{e}");
                        }
                        Ok(()) => {}
                    }
                }
                for iface in apply_state.ifaces.iter() {
                    if !self.supported_types.contains(iface.iface_type()) {
                        return Err(NipartError::new(
                            ErrorKind::DependencyError,
                            format!(
                                "Plugin for interface type {} is not loaded, \
                                 unable to apply state for {}",
                                iface.iface_type(),
                                iface.name()
                            ),
                        ));
                    }
                }
                Ok(NipartPluginReply::None)
            }
            NipartPluginCmd::WifiScan(opt) => {
                let mut ret = Vec::new();
                let mut first_error = None;
                for plugin in self.plugins.values() {
                    if !plugin.is_wifi_plugin() {
                        continue;
                    }
                    match plugin.wifi_scan(&opt).await {
                        Ok(r) => ret.extend(r),
                        Err(e) => {
                            log::info!("{e}");
                            if first_error.is_none() {
                                first_error = Some(e);
                            }
                        }
                    }
                }
                if ret.is_empty()
                    && let Some(e) = first_error
                {
                    return Err(e);
                }
                Ok(NipartPluginReply::WifiScanResult(ret))
            }
            NipartPluginCmd::WifiControl(control) => {
                for plugin in self.plugins.values() {
                    if !plugin.is_wifi_plugin() {
                        continue;
                    }
                    if let Err(e) = plugin.wifi_control(control).await {
                        log::info!("{e}");
                    }
                }
                Ok(NipartPluginReply::None)
            }
            NipartPluginCmd::SystemResume => {
                // Plugins without resume support reply with a NoSupport
                // error: that is expected, only a real failure is
                // reported back to the daemon.
                let mut first_error = None;
                for plugin in self.plugins.values() {
                    match plugin.system_resume().await {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NoSupport => {
                            log::debug!("{e}");
                        }
                        Err(e) => {
                            log::warn!("{e}");
                            if first_error.is_none() {
                                first_error = Some(e);
                            }
                        }
                    }
                }
                match first_error {
                    Some(e) => Err(e),
                    None => Ok(NipartPluginReply::None),
                }
            }
        }
    }
}

impl Drop for NipartPluginWorker {
    fn drop(&mut self) {
        for mut child in self.children.drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
        for plugin in self.plugins.values() {
            let _ = std::fs::remove_file(&plugin.socket_path);
        }
    }
}

fn get_plugin_files() -> Vec<String> {
    let mut plugins: Vec<String> = Vec::new();

    let search_dir = if let Some(p) = current_exe().ok().and_then(|p| {
        p.parent().and_then(|s| s.to_str()).map(|s| s.to_string())
    }) {
        p
    } else {
        return plugins;
    };

    for file_path in get_file_paths_in_dir(&search_dir) {
        let path = std::path::Path::new(&file_path);
        if is_executable(path)
            && path
                .strip_prefix(&search_dir)
                .ok()
                .and_then(|p| p.to_str())
                .map(|p| p.starts_with(NPT_PLUGIN_PREFIX))
                .unwrap_or_default()
        {
            plugins.push(file_path);
        }
    }

    plugins
}

fn is_executable(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .map(|meta| (meta.permissions().mode() & 0o100) > 0)
        .unwrap_or_default()
}

fn is_socket(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .map(|meta| meta.file_type().is_socket())
        .unwrap_or_default()
}

fn get_file_paths_in_dir(dir: &str) -> Vec<String> {
    let mut ret: Vec<String> = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        log::debug!("Failed to read dir {dir}: {e}");
                        continue;
                    }
                };
                if !entry.path().is_dir()
                    && let Some(p) = entry.path().to_str()
                {
                    ret.push(p.to_string());
                }
            }
        }
        Err(e) => {
            log::debug!("Failed to read dir {dir}: {e}");
        }
    }
    ret
}

async fn connect_plugins(plugins: &mut HashMap<String, NipartDaemonPlugin>) {
    for file_path in get_file_paths_in_dir(NPT_PLUGIN_SOCK_DIR) {
        let path = std::path::Path::new(&file_path);
        if is_socket(path)
            && let Ok(mut client) = NipartPluginClient::new(&file_path).await
        {
            match client.query_plugin_info().await {
                Ok(info) => {
                    log::info!(
                        "Plugin {} version {} connected",
                        info.name,
                        info.version,
                    );
                    plugins.insert(
                        info.name.to_string(),
                        NipartDaemonPlugin {
                            name: info.name.to_string(),
                            plugin_info: info,
                            socket_path: file_path,
                        },
                    );
                }
                Err(e) => {
                    log::debug!("{e}");
                }
            }
        }
    }
}
