// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use super::super::{
    deserializer::{number_as_string, option_number_as_string},
    value::copy_undefined_value,
};
use crate::{
    BaseInterface, DebugHideSecrets, ErrorKind, InterfaceType, JsonDisplay,
    JsonDisplayHideSecrets, NipartError, NipartInterface,
};

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonDisplayHideSecrets,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
/// WiFi physical interface
pub struct WifiPhyInterface {
    #[serde(flatten)]
    pub base: BaseInterface,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wifi: Option<WifiConfig>,
}

impl WifiPhyInterface {
    pub fn new(name: String, wifi: WifiConfig) -> Self {
        Self {
            base: BaseInterface {
                name: name.to_string(),
                iface_type: InterfaceType::WifiPhy,
                ..Default::default()
            },
            wifi: Some(wifi),
        }
    }

    pub fn ssid(&self) -> Option<&str> {
        self.wifi.as_ref().map(|w| w.ssid.as_str())
    }
}

impl Default for WifiPhyInterface {
    fn default() -> Self {
        Self {
            base: BaseInterface {
                iface_type: InterfaceType::WifiPhy,
                ..Default::default()
            },
            wifi: None,
        }
    }
}

impl NipartInterface for WifiPhyInterface {
    fn base_iface(&self) -> &BaseInterface {
        &self.base
    }

    fn base_iface_mut(&mut self) -> &mut BaseInterface {
        &mut self.base
    }

    fn is_virtual(&self) -> bool {
        false
    }

    fn sanitize(
        &self,
        _current: Option<&Self>,
        for_save: &mut Self,
        for_apply: &mut Self,
        for_verify: &mut Self,
        merged: &mut Self,
    ) -> Result<(), NipartError> {
        let desired = self;
        let iface_name = desired.name();
        if let Some(wifi_cfg) = for_apply.wifi.as_mut() {
            wifi_cfg.sanitize();
            if let Some(base_iface_name) = wifi_cfg.base_iface.as_ref()
                && base_iface_name != iface_name
            {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "The wifi-phy interface {iface_name} is holding WIFI \
                         configuration with base-iface pointing to other \
                         interface {base_iface_name}",
                    ),
                ));
            } else {
                wifi_cfg.base_iface = Some(iface_name.to_string());
            }
        }
        if for_apply.wifi.is_some() {
            if let Some(for_save_wifi) = for_save.wifi.as_mut() {
                for_save_wifi.sanitize();
                for_verify.wifi = Some(for_save_wifi.clone());
                merged.wifi = Some(for_save_wifi.clone());
            } else {
                for_save.wifi = for_apply.wifi.clone();
                for_verify.wifi = for_apply.wifi.clone();
                merged.wifi = for_apply.wifi.clone();
            }
        }
        Ok(())
    }

    fn hide_secrets(&mut self) {
        if let Some(wifi_cfg) = self.wifi.as_mut() {
            wifi_cfg.hide_secrets();
        }
    }

    fn sanitize_before_verify(&mut self, current: &mut Self) {
        let desired = self;
        // base_iface is an internal field set by sanitize() but not
        // available from kernel query, so strip it before verification.
        if let Some(wifi_cfg) = desired.wifi.as_mut() {
            wifi_cfg.base_iface = None;
            wifi_cfg.remove_secrets();
            wifi_cfg.hidden = false;
        }
        current.hide_secrets()
    }

    /// Always include SSID if changed
    fn include_diff_context(&mut self, desired: &Self, current: &Self) {
        let diff = self;
        if let Some(desired_wifi) = desired.wifi.as_ref()
            && let Some(current_wifi) = current.wifi.as_ref()
            && !desired_wifi.ssid.is_empty()
            && desired_wifi != current_wifi
        {
            if let Some(diff_wifi) = diff.wifi.as_mut() {
                diff_wifi.ssid = desired_wifi.ssid.to_string();
            } else {
                diff.wifi = Some(desired_wifi.clone());
            }
        }
    }

    fn post_merge(
        &mut self,
        new: &Self,
        old: &Self,
    ) -> Result<(), NipartError> {
        let merged = self;
        if let Some(wifi) = merged.wifi.as_mut()
            && let Some(old_wifi) = old.wifi.as_ref()
        {
            wifi.post_merge(new.wifi.as_ref(), old_wifi);
        }
        Ok(())
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    JsonDisplay,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum WifiState {
    /// BSS disconnected
    Disconnected,
    /// Scanning SSID
    Scanning,
    /// SSID Found, trying to associate and authenticate with a BSS/SSID
    Connecting,
    /// Data connection is fully configured
    Completed,
    #[default]
    Unknown,
}

/// Simplified authentication type, for user to apply and query.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Default,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonDisplay,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum WifiAuthType {
    /// No authentication
    #[serde(rename = "OPEN")]
    Open,
    /// WPA 2 Pre-shared Key
    #[serde(rename = "WPA2-PSK")]
    Wpa2Personal,
    /// WPA 3 Pre-shared Key using SAE(Simultaneous Authentication of Equals)
    #[serde(rename = "WPA3-PSK")]
    Wpa3Personal,
    #[default]
    Unknown,
}

/// Detailed authentication type with AKM and cipher suite details, used in
/// wifi scan results.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonDisplay,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub struct WifiAuthTypeDetailed {
    /// Simplified authentication type
    pub auth_type: WifiAuthType,
    /// AKM (Authentication and Key Management) suites advertised by the AP,
    /// e.g. `PSK`, `SAE`, `802.1X`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub akm: Vec<String>,
    /// Cipher suites advertised by the AP, e.g. `CCMP`, `GCMP`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cipher: Vec<String>,
}

impl WifiAuthTypeDetailed {
    pub fn new(
        auth_type: WifiAuthType,
        akm: Vec<String>,
        cipher: Vec<String>,
    ) -> Self {
        Self {
            auth_type,
            akm,
            cipher,
        }
    }
}

/// WiFi active scan result of a single scanned network.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonDisplay,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub struct WifiScanResult {
    pub ssid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_iface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_mhz: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u32>,
    /// Authentication types supported by the scanned network.
    pub auth_types: Vec<WifiAuthTypeDetailed>,
}

impl WifiScanResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ssid: String,
        base_iface: Option<String>,
        bssid: Option<String>,
        frequency_mhz: Option<u32>,
        signal_dbm: Option<i16>,
        signal_percent: Option<u8>,
        generation: Option<u32>,
        auth_types: Vec<WifiAuthTypeDetailed>,
    ) -> Self {
        Self {
            ssid,
            base_iface,
            bssid,
            frequency_mhz,
            signal_dbm,
            signal_percent,
            generation,
            auth_types,
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonDisplayHideSecrets,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
/// Pseudo Interface for WiFi Configuration
pub struct WifiCfgInterface {
    #[serde(flatten)]
    pub base: BaseInterface,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wifi: Option<WifiConfig>,
}

impl WifiCfgInterface {
    pub fn new(base: BaseInterface) -> Self {
        Self {
            base,
            ..Default::default()
        }
    }

    pub fn parent(&self) -> Option<&str> {
        self.wifi.as_ref().and_then(|w| w.base_iface.as_deref())
    }

    pub fn ssid(&self) -> Option<&str> {
        self.wifi.as_ref().map(|w| w.ssid.as_str())
    }
}

impl From<WifiConfig> for WifiCfgInterface {
    fn from(config: WifiConfig) -> Self {
        Self {
            base: BaseInterface::new(
                config.ssid.to_string(),
                InterfaceType::WifiCfg,
            ),
            wifi: Some(config),
        }
    }
}

impl Default for WifiCfgInterface {
    fn default() -> Self {
        Self {
            base: BaseInterface {
                iface_type: InterfaceType::WifiCfg,
                ..Default::default()
            },
            wifi: None,
        }
    }
}

impl NipartInterface for WifiCfgInterface {
    fn base_iface(&self) -> &BaseInterface {
        &self.base
    }

    fn base_iface_mut(&mut self) -> &mut BaseInterface {
        &mut self.base
    }

    fn is_virtual(&self) -> bool {
        true
    }

    fn sanitize(
        &self,
        _current: Option<&Self>,
        for_save: &mut Self,
        for_apply: &mut Self,
        for_verify: &mut Self,
        merged: &mut Self,
    ) -> Result<(), NipartError> {
        if let Some(wifi_cfg) = for_apply.wifi.as_mut() {
            wifi_cfg.sanitize();
        }
        if for_apply.wifi.is_some() {
            if let Some(for_save_wifi) = for_save.wifi.as_mut() {
                for_save_wifi.sanitize();
                for_verify.wifi = Some(for_save_wifi.clone());
                merged.wifi = Some(for_save_wifi.clone());
            } else {
                for_save.wifi = for_apply.wifi.clone();
                for_verify.wifi = for_apply.wifi.clone();
                merged.wifi = for_apply.wifi.clone();
            }
        }
        Ok(())
    }

    fn hide_secrets(&mut self) {
        if let Some(wifi_cfg) = self.wifi.as_mut() {
            wifi_cfg.hide_secrets();
        }
    }

    fn sanitize_before_verify(&mut self, current: &mut Self) {
        let desired = self;
        // The IP stack and WIFI password is for daemon storage only and cannot
        // be query during applying(only stored after apply succeeded), hence
        // we remove ipv4 and ipv6 for `wifi-cfg` interface.
        desired.base.ipv4 = None;
        desired.base.ipv6 = None;
        if let Some(wifi_cfg) = desired.wifi.as_mut() {
            wifi_cfg.remove_secrets();
            wifi_cfg.hidden = false;
        }
        current.hide_secrets()
    }

    /// Always include SSID if changed
    fn include_diff_context(&mut self, desired: &Self, current: &Self) {
        let diff = self;
        if let Some(desired_wifi) = desired.wifi.as_ref()
            && let Some(current_wifi) = current.wifi.as_ref()
            && !desired_wifi.ssid.is_empty()
            && desired_wifi != current_wifi
        {
            if let Some(diff_wifi) = diff.wifi.as_mut() {
                diff_wifi.ssid = desired_wifi.ssid.to_string();
            } else {
                diff.wifi = Some(desired_wifi.clone());
            }
        }
    }

    fn post_merge(
        &mut self,
        new: &Self,
        old: &Self,
    ) -> Result<(), NipartError> {
        let merged = self;
        if let Some(wifi) = merged.wifi.as_mut()
            && let Some(old_wifi) = old.wifi.as_ref()
        {
            wifi.post_merge(new.wifi.as_ref(), old_wifi);
        }
        Ok(())
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    DebugHideSecrets,
    JsonDisplayHideSecrets,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct WifiConfig {
    /// SSID (Service Set Identifier)
    #[serde(default, deserialize_with = "number_as_string")]
    pub ssid: String,
    /// WiFi state. For query only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<WifiState>,
    /// Authentication type
    /// When querying network state, it contains the current authentication
    /// type.
    /// Ignored when applying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<WifiAuthType>,
    /// WiFi generation, e.g. 6 for WiFi-6. For query only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u32>,
    /// BSSID (Basic Service Set Identifier), if defined, will only connect to
    /// desired AP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    /// Password for authentication
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "option_number_as_string"
    )]
    pub password: Option<String>,
    /// Hidden network: the AP does not include its SSID in beacons.
    /// Requires a directed probe request to discover and connect.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    /// Whether this WiFi configuration only for specified interface or not.
    /// If undefined, it means any WiFi network interface can be used for
    /// connecting this WiFi.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_iface: Option<String>,
    /// WiFi frequency in MHz. For query only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_mhz: Option<u32>,
    /// Receive bitrate in 1mb/s. For query only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bitrate_mb: Option<u32>,
    /// Transmit bitrate in 1mb/s. For query only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bitrate_mb: Option<u32>,
    /// Signal in dBm. For query only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i16>,
    /// Signal in percentage. For query only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_percent: Option<u8>,
}

// Align with Microsoft `WLAN_ASSOCIATION_ATTRIBUTES`
const NOISE_FLOOR_DBM: i16 = -100;
const SIGNAL_MAX_DBM: i16 = -50;

fn is_false(value: &bool) -> bool {
    !*value
}

impl WifiConfig {
    /// Use `signal_dbm` to calculate out `signal_percent`
    pub fn sanitize_signal(&mut self) {
        if let Some(s) = self.signal_dbm {
            self.signal_percent = Some(Self::signal_dbm_to_percent(s));
        }
    }

    pub fn signal_dbm_to_percent(dbm: i16) -> u8 {
        let dbm = dbm.clamp(NOISE_FLOOR_DBM, SIGNAL_MAX_DBM);
        (100.0f64 * (NOISE_FLOOR_DBM - dbm) as f64
            / (NOISE_FLOOR_DBM - SIGNAL_MAX_DBM) as f64) as u8
    }

    /// Set all query only properties to None
    /// Change BSSID to upper case
    pub(crate) fn sanitize(&mut self) {
        self.state = None;
        self.generation = None;
        self.auth_type = None;
        self.frequency_mhz = None;
        self.tx_bitrate_mb = None;
        self.rx_bitrate_mb = None;
        self.signal_dbm = None;
        self.signal_percent = None;
        if let Some(mac) = self.bssid.as_ref() {
            self.bssid = Some(mac.to_uppercase());
        }
        // An empty `base-iface` means the profile is not bound to any phy,
        // same as an undefined one.
        if self.base_iface.as_deref() == Some("") {
            self.base_iface = None;
        }
    }

    pub fn hide_secrets(&mut self) {
        if self.password.is_some() {
            self.password =
                Some(crate::NetworkState::HIDE_SECRET_STR.to_string());
        }
    }

    pub fn remove_secrets(&mut self) {
        self.password = None;
    }

    pub fn merge(&self, new: &Self) -> Result<Self, NipartError> {
        let mut new_value = serde_json::to_value(new)?;
        let old_value = serde_json::to_value(self)?;
        copy_undefined_value(&mut new_value, &old_value);

        let mut merged: Self = serde_json::from_value(new_value)?;
        merged.post_merge(Some(new), self);

        Ok(merged)
    }

    pub(crate) fn post_merge(&mut self, new: Option<&Self>, old: &Self) {
        let ssid_changed =
            new.is_some_and(|new| !new.ssid.is_empty() && new.ssid != old.ssid);
        if self.ssid.is_empty() {
            self.ssid = old.ssid.to_string();
        }
        if ssid_changed {
            // A different SSID must not inherit the old network's secret or
            // BSSID pin: the password belongs to the previous SSID and the
            // pin points at an AP of that SSID. An undefined password stays
            // undefined so shuli can join an open network, and a hidden
            // secret marker cannot be resolved for the new SSID.
            let new_password = new.and_then(|new| new.password.as_deref());
            if new_password.is_none()
                || new_password == Some(crate::NetworkState::HIDE_SECRET_STR)
            {
                self.password = None;
            }
            if new.is_none_or(|new| new.bssid.is_none()) {
                self.bssid = None;
            }
            self.hidden = new.is_some_and(|new| new.hidden);
        }
    }
}

#[cfg(test)]
#[path = "../unit_tests/ifaces_wifi.rs"]
mod test;
