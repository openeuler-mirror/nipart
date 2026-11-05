// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, time::Duration};

use nipart::{
    ErrorKind, Interface, MacSecInterface, NipartError, NipartInterface,
};
use shuli_wired::{MacsecConfig, WiredAuth, WiredClient, WiredState};
use tokio::{sync::mpsc::UnboundedReceiver, task::JoinHandle};

/// Delay before re-creating a failed MKA session.
const MKA_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Apply request received from the daemon.
#[derive(Debug)]
pub(crate) struct ApplyRequest {
    pub(crate) ifaces: Vec<Interface>,
    pub(crate) force: bool,
}

/// MKA settings derived from one nipart MACsec interface.
#[derive(Debug, Clone)]
struct MkaConfig {
    base_iface: String,
    cak: Vec<u8>,
    ckn: Vec<u8>,
    encrypt: bool,
}

impl MkaConfig {
    /// Parse the MKA settings of `iface`. `Ok(None)` means the interface
    /// does not request MKA.
    fn from_iface(
        iface: &MacSecInterface,
    ) -> Result<Option<Self>, NipartError> {
        let Some(conf) = iface.macsec.as_ref() else {
            return Ok(None);
        };
        let (Some(mka_cak), Some(mka_ckn)) = (&conf.mka_cak, &conf.mka_ckn)
        else {
            return Ok(None);
        };
        if conf.base_iface.is_empty() {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "MACsec {} has MKA keys but no `macsec.base-iface`",
                    iface.name()
                ),
            ));
        }
        Ok(Some(Self {
            base_iface: conf.base_iface.clone(),
            cak: decode_hex("mka-cak", mka_cak)?,
            ckn: decode_hex("mka-ckn", mka_ckn)?,
            // The kernel default when `encrypt` is omitted is false. This
            // value is only used if the MACsec netdev has to be created by
            // shuli; normally no_daemon already created it.
            encrypt: conf.encrypt.unwrap_or(false),
        }))
    }

    /// Whether the running MKA session must be restarted for `self`.
    ///
    /// `encrypt` is a MACsec netdev property owned by the kernel apply
    /// path: changing it does not require a new MKA session.
    fn requires_new_session(&self, old: &Self) -> bool {
        self.base_iface != old.base_iface
            || self.cak != old.cak
            || self.ckn != old.ckn
    }
}

struct Session {
    config: MkaConfig,
    handle: JoinHandle<()>,
}

/// Worker owning every live MKA session.
pub(crate) struct MkaWorker {
    sessions: HashMap<String, Session>,
}

impl MkaWorker {
    pub(crate) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub(crate) async fn run(mut self, mut rx: UnboundedReceiver<ApplyRequest>) {
        while let Some(request) = rx.recv().await {
            self.apply(request).await;
        }
        self.stop_all().await;
    }

    async fn apply(&mut self, request: ApplyRequest) {
        for iface in &request.ifaces {
            let Interface::MacSec(macsec_iface) = iface else {
                continue;
            };
            let iface_name = kernel_iface_name(iface);

            if iface.is_absent() || iface.is_down() {
                self.stop_iface(&iface_name).await;
                continue;
            }
            if !iface.is_up() {
                continue;
            }

            let desired = match MkaConfig::from_iface(macsec_iface) {
                Ok(Some(desired)) => desired,
                Ok(None) => {
                    // No MKA requested: drop a session left from a
                    // previous apply (e.g. the interface was recreated
                    // without MKA keys).
                    self.stop_iface(&iface_name).await;
                    continue;
                }
                Err(e) => {
                    log::warn!("{e}");
                    self.stop_iface(&iface_name).await;
                    continue;
                }
            };

            let restart = request.force
                || self.sessions.get(&iface_name).is_none_or(|session| {
                    session.handle.is_finished()
                        || desired.requires_new_session(&session.config)
                });
            if restart {
                self.stop_iface(&iface_name).await;
                log::info!(
                    "Starting MKA on {iface_name} over {}",
                    desired.base_iface
                );
                let config = desired.clone();
                let handle =
                    tokio::spawn(run_mka_session(iface_name.clone(), desired));
                self.sessions.insert(iface_name, Session { config, handle });
            }
        }
    }

    async fn stop_iface(&mut self, iface_name: &str) {
        let Some(session) = self.sessions.remove(iface_name) else {
            return;
        };
        log::debug!("Stopping MKA on {iface_name}");
        session.handle.abort();
        let _ = session.handle.await;
    }

    async fn stop_all(&mut self) {
        let sessions: Vec<(String, Session)> = self.sessions.drain().collect();
        for (iface_name, session) in sessions {
            log::debug!("Stopping MKA on {iface_name}");
            session.handle.abort();
            let _ = session.handle.await;
        }
    }
}

impl Drop for MkaWorker {
    fn drop(&mut self) {
        for session in self.sessions.values() {
            session.handle.abort();
        }
    }
}

fn kernel_iface_name(iface: &Interface) -> String {
    let name = iface.kernel_iface_name();
    if name.is_empty() {
        iface.name().to_string()
    } else {
        name.to_string()
    }
}

fn build_macsec_config(iface_name: &str, config: &MkaConfig) -> MacsecConfig {
    let mut ret = MacsecConfig::new(config.cak.clone(), config.ckn.clone());
    ret.macsec_iface = Some(iface_name.to_string());
    // Either side of the point-to-point link may become the key server;
    // the election picks the lowest (priority, SCI) pair.
    ret.can_be_key_server = true;
    ret.key_server_priority = 0xff;
    ret.encrypt = config.encrypt;
    ret
}

async fn run_mka_session(iface_name: String, config: MkaConfig) {
    loop {
        let auth = WiredAuth::Macsec(build_macsec_config(&iface_name, &config));
        match WiredClient::init_with_auth(&config.base_iface, auth) {
            Ok(mut client) => {
                log::debug!(
                    "MKA client on {iface_name} over {} started",
                    config.base_iface
                );
                let mut secured = false;
                loop {
                    match client.run().await {
                        Ok(WiredState::Connected) => {
                            if !secured {
                                secured = true;
                                log::info!(
                                    "MACsec {iface_name} secured by MKA over \
                                     {}",
                                    config.base_iface
                                );
                            }
                        }
                        Ok(WiredState::Failed) => {
                            log::warn!(
                                "MKA on {iface_name} failed, restarting"
                            );
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!(
                                "MKA on {iface_name} failed: {e}, restarting"
                            );
                            break;
                        }
                    }
                }
                // Dropping the client leaves the kernel MACsec netdev and
                // its SAs alone: their lifecycle is owned by no_daemon.
            }
            Err(e) => {
                log::warn!(
                    "Failed to start MKA on {iface_name} over {}: {e}",
                    config.base_iface
                );
            }
        }
        tokio::time::sleep(MKA_RETRY_INTERVAL).await;
    }
}

#[cfg(test)]
#[path = "unit_tests.rs"]
mod tests;

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>, NipartError> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return Err(NipartError::new(
            ErrorKind::InvalidArgument,
            format!("{field} must be an even number of hexadecimal digits"),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|e| {
                NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!("Invalid hexadecimal digit in {field}: {e}"),
                )
            })
        })
        .collect()
}
