// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file are:
//  * Gris Ge <fge@redhat.com>

use serde::{Deserialize, Serialize};

use crate::{
    BaseInterface, DebugHideSecrets, ErrorKind, InterfaceType, JsonDisplay,
    JsonDisplayHideSecrets, NipartError, NipartInterface,
};

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonDisplayHideSecrets,
)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
/// MACsec interface. The example YAML output of a [crate::NetworkState] with
/// a MACsec interface would be:
/// ```yaml
/// ---
/// interfaces:
///   - name: macsec0
///     type: macsec
///     state: up
///     macsec:
///       encrypt: true
///       base-iface: eth1
///       mka-cak: 50b71a8ef0bd5751ea76de6d6c98c03a
///       mka-ckn: f2b4297d39da7330910a74abc0449feb45b5c0b9fc23df1430e1898fcf1c4550
///       port: 1
///       validation: strict
///       send-sci: true
/// ```
pub struct MacSecInterface {
    #[serde(flatten)]
    pub base: BaseInterface,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Deserialize and serialize to `macsec`.
    pub macsec: Option<MacSecConfig>,
}

impl MacSecInterface {
    pub fn new(name: String, macsec: MacSecConfig) -> Self {
        Self {
            base: BaseInterface {
                name,
                iface_type: InterfaceType::MacSec,
                ..Default::default()
            },
            macsec: Some(macsec),
        }
    }
}

impl Default for MacSecInterface {
    fn default() -> Self {
        Self {
            base: BaseInterface {
                iface_type: InterfaceType::MacSec,
                ..Default::default()
            },
            macsec: None,
        }
    }
}

impl NipartInterface for MacSecInterface {
    fn base_iface(&self) -> &BaseInterface {
        &self.base
    }

    fn base_iface_mut(&mut self) -> &mut BaseInterface {
        &mut self.base
    }

    fn is_virtual(&self) -> bool {
        true
    }

    fn hide_secrets(&mut self) {
        if let Some(macsec_conf) = self.macsec.as_mut() {
            macsec_conf.hide_secrets();
        }
    }

    fn parent(&self) -> Option<&str> {
        self.macsec
            .as_ref()
            .map(|macsec| macsec.base_iface.as_str())
            .filter(|base_iface| !base_iface.is_empty())
    }

    /// * `macsec` configuration is mandatory for creating new MACsec.
    /// * `macsec.base-iface` is mandatory for creating new MACsec.
    /// * `mka-cak` and `mka-ckn` must be all missing or all present.
    /// * `mka-cak` must be a string of 32 hexadecimal characters.
    /// * `mka-ckn` must be a string of even size between 2 and 64 hexadecimal
    ///   characters.
    /// * With MKA keys, `port` must be 1 and `sci` cannot be defined.
    fn sanitize(
        &self,
        current: Option<&Self>,
        for_save: &mut Self,
        for_apply: &mut Self,
        for_verify: &mut Self,
        merged: &mut Self,
    ) -> Result<(), NipartError> {
        let desired = self;

        if desired.is_absent() {
            return Ok(());
        }

        if desired.macsec.is_none() && current.is_none() {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "`macsec` configuration is mandatory for creating new \
                     MACsec {}",
                    desired.name()
                ),
            ));
        }

        if current.is_none()
            && let Some(des_macsec_conf) = desired.macsec.as_ref()
            && des_macsec_conf.base_iface.is_empty()
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "`macsec.base-iface` is mandatory for creating new MACsec \
                     {}",
                    desired.name()
                ),
            ));
        }

        if let Some(des_conf) = desired.macsec.as_ref() {
            if let (Some(sci), Some(port)) = (des_conf.sci, des_conf.port)
                && (sci & 0xffff) as u32 != port
            {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "Invalid MACsec config for interface {}: `port` {} \
                         does not match the port component {} of `sci`",
                        desired.name(),
                        port,
                        sci & 0xffff
                    ),
                ));
            }
            // An explicit SCI takes precedence over `port`, and an explicit
            // `port` takes precedence over a previously saved SCI.
            for target in [
                &mut *for_save,
                &mut *for_apply,
                &mut *for_verify,
                &mut *merged,
            ] {
                if let Some(conf) = target.macsec.as_mut() {
                    if let Some(sci) = des_conf.sci {
                        conf.sci = Some(sci);
                        conf.port = Some((sci & 0xffff) as u32);
                    } else if let Some(port) = des_conf.port {
                        conf.sci = None;
                        conf.port = Some(port);
                    }
                }
            }
        }

        if let Some(conf) = for_apply.macsec.as_mut() {
            conf.sanitize(desired.name())?;
        }

        // The MKA CAK/CKN are not kernel properties and are not reported by
        // nispor, hence they cannot be verified against the current state.
        if let Some(conf) = for_verify.macsec.as_mut() {
            conf.mka_cak = None;
            conf.mka_ckn = None;
        }

        Ok(())
    }

    fn sanitize_before_verify(&mut self, _current: &mut Self) {
        // The MKA CAK/CKN are not kernel properties and are not reported by
        // nispor, hence they cannot be verified against the current state.
        if let Some(macsec_conf) = self.macsec.as_mut() {
            macsec_conf.mka_cak = None;
            macsec_conf.mka_ckn = None;
        }
    }

    /// Include `base-iface` as context when the MACsec configuration changed.
    fn include_diff_context(&mut self, desired: &Self, current: &Self) {
        let diff = self;
        if let Some(des_macsec_conf) = desired.macsec.as_ref()
            && let Some(cur_macsec_conf) = current.macsec.as_ref()
            && des_macsec_conf != cur_macsec_conf
        {
            let mut diff_macsec_conf = des_macsec_conf.clone();
            if diff_macsec_conf.base_iface.is_empty() {
                diff_macsec_conf
                    .base_iface
                    .clone_from(&cur_macsec_conf.base_iface);
            }
            diff.macsec = Some(diff_macsec_conf);
        }
    }

    /// The kernel does not allow changing the parent interface or the SCI
    /// port of an existing MACsec interface, delete and recreate it instead.
    fn need_delete_before_change(&self, current: &Self) -> bool {
        let desired = self;
        if let Some(des) = desired.macsec.as_ref()
            && let Some(cur) = current.macsec.as_ref()
        {
            if !des.base_iface.is_empty()
                && !cur.base_iface.is_empty()
                && des.base_iface != cur.base_iface
            {
                return true;
            }
            if let Some(des_port) = des.port
                && let Some(cur_port) = cur.port
                && des_port != cur_port
            {
                return true;
            }
            if let Some(des_sci) = des.sci
                && let Some(cur_sci) = cur.sci
                && des_sci != cur_sci
            {
                return true;
            }
        }
        false
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
#[non_exhaustive]
pub struct MacSecConfig {
    /// Whether the transmitted traffic must be encrypted.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "crate::deserializer::option_bool_or_string"
    )]
    pub encrypt: Option<bool>,
    /// The parent interface used by the MACsec interface. Changing it on an
    /// existing MACsec interface will cause the interface to be deleted and
    /// recreated.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_iface: String,
    /// The pre-shared CAK (Connectivity Association Key) for MACsec Key
    /// Agreement. Must be a string of 32 hexadecimal characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mka_cak: Option<String>,
    /// The pre-shared CKN (Connectivity-association Key Name) for MACsec Key
    /// Agreement. Must be a string of hexadecimal characters with an even
    /// length between 2 and 64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mka_ckn: Option<String>,
    /// The SCI (Secure Channel Identifier) as a 64-bit hexadecimal value,
    /// e.g. `0x0011223344550001`. The upper 48 bits are the MAC address and
    /// the lower 16 bits are the port.
    /// When defined it takes precedence over `port`. Changing it on an
    /// existing MACsec interface will cause the interface to be deleted and
    /// recreated.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "crate::deserializer::option_u64_hex_or_string",
        serialize_with = "crate::serializer::option_u64_as_hex"
    )]
    pub sci: Option<u64>,
    /// The port component of the SCI (Secure Channel Identifier).
    /// Changing it on an existing MACsec interface will cause the interface
    /// to be deleted and recreated.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "crate::deserializer::option_u32_or_string"
    )]
    pub port: Option<u32>,
    /// Specifies the validation mode for incoming frames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<MacSecValidate>,
    /// Specifies whether the SCI (Secure Channel Identifier) is included in
    /// every packet.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "crate::deserializer::option_bool_or_string"
    )]
    pub send_sci: Option<bool>,
    /// Specifies the hardware offload mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offload: Option<MacSecOffload>,
}

impl MacSecConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn hide_secrets(&mut self) {
        if self.mka_cak.is_some() {
            self.mka_cak =
                Some(crate::NetworkState::HIDE_SECRET_STR.to_string());
        }
    }

    fn sanitize(&mut self, iface_name: &str) -> Result<(), NipartError> {
        if self.mka_cak.is_none() ^ self.mka_ckn.is_none() {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid MACsec config for interface {iface_name}: \
                     `mka-cak` and `mka-ckn` must be all missing or present"
                ),
            ));
        }
        if let Some(mka_cak) = &self.mka_cak
            && mka_cak.len() != 32
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid MACsec config for interface {iface_name}: \
                     `mka-cak` must be a string of 32 characters"
                ),
            ));
        }
        if let Some(mka_cak) = &self.mka_cak
            && !mka_cak.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid MACsec config for interface {iface_name}: \
                     `mka-cak` must be a hexadecimal string"
                ),
            ));
        }
        if let Some(mka_ckn) = &self.mka_ckn
            && (mka_ckn.len() > 64
                || mka_ckn.len() < 2
                || mka_ckn.len() % 2 == 1)
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid MACsec config for interface {iface_name}: \
                     `mka-ckn` must be a string of even size between 2 and 64 \
                     characters"
                ),
            ));
        }
        if let Some(mka_ckn) = &self.mka_ckn
            && !mka_ckn.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid MACsec config for interface {iface_name}: \
                     `mka-ckn` must be a hexadecimal string"
                ),
            ));
        }
        // The MKA implementation uses the base interface MAC address and
        // SCI port 1 (the kernel default), because that is the SCI the MKA
        // session advertises and installs SAs for.
        if self.mka_cak.is_some() {
            if self.sci.is_some() {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "Invalid MACsec config for interface {iface_name}: \
                         `sci` cannot be defined when `mka-cak`/`mka-ckn` are \
                         defined, MKA uses the base interface MAC address and \
                         port 1"
                    ),
                ));
            }
            if let Some(port) = self.port
                && port != 1
            {
                return Err(NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "Invalid MACsec config for interface {iface_name}: \
                         `port` must be 1 when `mka-cak`/`mka-ckn` are \
                         defined, MKA uses SCI port 1"
                    ),
                ));
            }
        }
        if self.sci.is_some() && self.send_sci == Some(false) {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid MACsec config for interface {iface_name}: \
                     `send-sci` must be true when `sci` is defined"
                ),
            ));
        }
        if let Some(port) = self.port
            && port > u16::MAX as u32
        {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "Invalid MACsec config for interface {iface_name}: `port` \
                     must be between 0 and {}",
                    u16::MAX
                ),
            ));
        }
        Ok(())
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    JsonDisplay,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum MacSecValidate {
    #[default]
    Disabled,
    Check,
    Strict,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    JsonDisplay,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum MacSecOffload {
    #[default]
    Off,
    Phy,
    Mac,
}
