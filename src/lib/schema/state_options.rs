// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{CUR_SCHEMA_VERSION, JsonDisplay};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonDisplay)]
#[non_exhaustive]
pub struct NipartQueryOption {
    /// Schema version for output
    #[serde(default)]
    pub version: u32,
    /// Whether to include current kernel interfaces and activated saved
    /// profiles. Default to true.
    #[serde(default = "default_true")]
    pub running: bool,
    /// Whether to include saved profiles. Inactive profiles are marked as
    /// `state: saved`; activated profiles as `state: up`. Default to false.
    #[serde(default)]
    pub saved: bool,
    /// Whether include secrets/passwords, default to false.
    #[serde(default)]
    pub include_secrets: bool,
}

impl Default for NipartQueryOption {
    fn default() -> Self {
        Self {
            version: CUR_SCHEMA_VERSION,
            running: true,
            saved: false,
            include_secrets: false,
        }
    }
}

impl NipartQueryOption {
    pub fn running() -> Self {
        Self::default()
    }

    pub fn saved() -> Self {
        Self {
            running: false,
            saved: true,
            ..Default::default()
        }
    }

    pub fn running_and_saved() -> Self {
        Self {
            running: true,
            saved: true,
            ..Default::default()
        }
    }

    pub fn include_secrets(mut self, value: bool) -> Self {
        self.include_secrets = value;
        self
    }
}

fn default_true() -> bool {
    true
}

#[derive(
    Debug, Default, Clone, PartialEq, Serialize, Deserialize, JsonDisplay,
)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub struct NipartApplyOption {
    /// Do not verify whether post applied state matches with desired state.
    #[serde(default)]
    pub no_verify: bool,
    /// When set to true, the desire state will not be persistent after OS
    /// reboot. Default to false.
    #[serde(default)]
    pub memory_only: bool,
    /// Whether to invoke DHCP in no-daemon mode. Default to false.
    /// This option makes no effect in daemon mode(via NipartClient).
    #[serde(default)]
    pub dhcp_in_no_daemon: bool,
    /// When set to true, DHCP clients are restarted even when the IP
    /// configuration is already applied. Default to false.
    #[serde(default)]
    pub restart_auto_ip: bool,
    /// When set to true, the full desired interface state is sent to the
    /// backend even when it is identical to the current state. Saved state
    /// is not modified unless `memory_only` is false.
    #[serde(default)]
    pub force: bool,
}

impl NipartApplyOption {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn no_verify(mut self) -> Self {
        self.no_verify = true;
        self
    }

    pub fn memory_only(mut self) -> Self {
        self.memory_only = true;
        self
    }

    pub fn dhcp_in_no_daemon(mut self) -> Self {
        self.memory_only = true;
        self
    }

    pub fn restart_auto_ip(mut self) -> Self {
        self.restart_auto_ip = true;
        self
    }

    pub fn force(mut self) -> Self {
        self.force = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonDisplay)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub struct NipartWifiScanOption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface_name: Option<String>,
    /// SSIDs to probe explicitly so hidden networks can be discovered
    /// (e.g. `--with-hidden`); the currently connected SSID is always
    /// added as well.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hidden_ssids: Vec<String>,
    /// Dump the scan results already stored in the kernel instead of
    /// triggering a new scan (the `iw dev <iface> scan dump`
    /// equivalent).
    #[serde(default, skip_serializing_if = "is_false")]
    pub dump: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl NipartWifiScanOption {
    pub fn new() -> Self {
        Self::default()
    }

    /// Dump the kernel's cached scan results instead of scanning.
    pub fn dump() -> Self {
        Self {
            dump: true,
            ..Default::default()
        }
    }
}

/// Query the WIFI plugin for a latched connection error.
///
/// The daemon's waits (e.g. DHCP waiting for the associated SSID) use it
/// to distinguish "the SSID is not there yet" from "the plugin already
/// knows the connection cannot succeed" - for example an AP whose group
/// cipher is TKIP, which shuli reports as
/// `ErrorKind::NoSupport: TKIP WPA2 is not supported`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonDisplay)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub struct NipartWifiConnectErrorOption {
    /// Kernel name of the WIFI interface (e.g. `wlan0`).
    pub iface_name: String,
    /// SSID the pending connection attempt is for. An error latched for
    /// another SSID is not reported.
    pub ssid: String,
}

impl NipartWifiConnectErrorOption {
    pub fn new(iface_name: &str, ssid: &str) -> Self {
        Self {
            iface_name: iface_name.to_string(),
            ssid: ssid.to_string(),
        }
    }
}

/// WIFI radio/function control requested through `npt wifi on|off`.
///
/// For now this only tells the WIFI plugin to stop (or resume) all WIFI
/// actions such as scanning and connecting.  When rfkill support is added,
/// [`NipartWifiControl::Off`] should also block the radio and
/// [`NipartWifiControl::On`] should unblock it.  The setting is currently
/// plugin-runtime only and resets to `On` when the daemon restarts.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonDisplay,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NipartWifiControl {
    On,
    Off,
}
