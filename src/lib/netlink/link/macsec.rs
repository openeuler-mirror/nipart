// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use rtnetlink::{
    Handle, LinkMacSec, LinkMessageBuilder,
    packet_route::link::{
        InfoData, InfoMacSec, MacSecOffload as RtnlMacSecOffload,
        MacSecValidate as RtnlMacSecValidate,
    },
};

use super::get_iface_index;
use crate::{
    ErrorKind, MacSecConfig, MacSecInterface, MacSecOffload, MacSecValidate,
    NipartError,
};

impl From<RtnlMacSecValidate> for MacSecValidate {
    fn from(value: RtnlMacSecValidate) -> Self {
        match value {
            RtnlMacSecValidate::Disabled => Self::Disabled,
            RtnlMacSecValidate::Check => Self::Check,
            RtnlMacSecValidate::Strict => Self::Strict,
            value => {
                log::warn!("Unknown MACsec validation mode {value:?}");
                Self::default()
            }
        }
    }
}

impl From<MacSecValidate> for RtnlMacSecValidate {
    fn from(value: MacSecValidate) -> Self {
        match value {
            MacSecValidate::Disabled => Self::Disabled,
            MacSecValidate::Check => Self::Check,
            MacSecValidate::Strict => Self::Strict,
        }
    }
}

impl From<RtnlMacSecOffload> for MacSecOffload {
    fn from(value: RtnlMacSecOffload) -> Self {
        match value {
            RtnlMacSecOffload::Off => Self::Off,
            RtnlMacSecOffload::Phy => Self::Phy,
            RtnlMacSecOffload::Mac => Self::Mac,
            value => {
                log::warn!("Unknown MACsec offload mode {value:?}");
                Self::default()
            }
        }
    }
}

impl From<MacSecOffload> for RtnlMacSecOffload {
    fn from(value: MacSecOffload) -> Self {
        match value {
            MacSecOffload::Off => Self::Off,
            MacSecOffload::Phy => Self::Phy,
            MacSecOffload::Mac => Self::Mac,
        }
    }
}

impl From<MacSecOffload> for nl_macsec::MacSecOffload {
    fn from(value: MacSecOffload) -> Self {
        match value {
            MacSecOffload::Off => Self::Off,
            MacSecOffload::Phy => Self::Phy,
            MacSecOffload::Mac => Self::Mac,
        }
    }
}

pub(crate) fn parse_macsec(data: &InfoData) -> Option<MacSecConfig> {
    let InfoData::MacSec(nlas) = data else {
        return None;
    };
    let mut config = MacSecConfig::default();
    let mut sci = None;
    let mut port = None;
    for nla in nlas {
        match nla {
            InfoMacSec::Sci(value) => {
                // The kernel stores the SCI as the in-memory big-endian
                // representation, the user-facing value is the one printed
                // by `ip` (`ntohll`).
                sci = Some(value.to_be());
            }
            InfoMacSec::Port(value) => port = Some(u32::from(*value)),
            InfoMacSec::Encrypt(value) => {
                config.encrypt = Some(*value != 0);
            }
            InfoMacSec::IncSci(value) => {
                config.send_sci = Some(*value != 0);
            }
            InfoMacSec::Validation(value) => {
                config.validation = Some((*value).into());
            }
            InfoMacSec::Offload(value) => {
                config.offload = Some((*value).into());
            }
            _ => (),
        }
    }
    config.sci = sci;
    // The kernel dumps the SCI but not always IFLA_MACSEC_PORT; the lower
    // 16 bits of the SCI are the port.
    config.port = sci.map(|sci| (sci & 0xffff) as u32).or(port);
    Some(config)
}

/// Build the link message of a MACsec interface. The caller applies the
/// resulting messages through [rtnetlink].
pub(crate) async fn macsec_link_builder(
    handle: &Handle,
    des_iface: &MacSecInterface,
    exists: bool,
) -> Result<LinkMessageBuilder<LinkMacSec>, NipartError> {
    let name = des_iface.base.name.as_str();
    let mut builder = if exists {
        let index = get_iface_index(handle, name).await?;
        // Link kind specific data (IFLA_INFO_DATA) is only processed by
        // the RTM_NEWLINK handler, which calls the kind's `changelink`
        // callback. RTM_SETLINK silently ignores it.
        LinkMessageBuilder::<LinkMacSec>::new(name).index(index)
    } else {
        let Some(config) = des_iface.macsec.as_ref() else {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!("MACsec {name} requires `macsec` configuration"),
            ));
        };
        if config.base_iface.is_empty() {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!("MACsec {name} requires `macsec.base-iface`"),
            ));
        }
        let base_index = get_iface_index(handle, &config.base_iface).await?;
        LinkMacSec::new(name, base_index)
    };

    let Some(config) = des_iface.macsec.as_ref() else {
        return Ok(builder);
    };

    if let Some(encrypt) = config.encrypt {
        builder = builder.encrypt(encrypt);
    }

    if exists {
        // The SCI and port cannot be changed on a live interface, the
        // schema deletes and recreates it instead.
        if let Some(send_sci) = config.send_sci {
            builder = builder.inc_sci(send_sci);
        }
        if let Some(validation) = config.validation {
            builder = builder.validation(validation.into());
        }
    } else {
        if let Some(sci) = config.sci {
            // Like the kernel, an explicit SCI takes precedence over the
            // port.
            builder = builder.sci(sci.to_be());
        } else if let Some(port) = config.port {
            let port = u16::try_from(port).map_err(|_| {
                NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!("MACsec {name} port {port} exceeds {}", u16::MAX),
                )
            })?;
            builder = builder.port(port);
        }
        if let Some(send_sci) = config.send_sci {
            builder = builder.inc_sci(send_sci);
        }
        if let Some(validation) = config.validation {
            builder = builder.validation(validation.into());
        }
        if let Some(offload) = config.offload {
            builder = builder.offload(offload.into());
        }
    }

    Ok(builder)
}

/// The offload mode is a SecY property maintained by the MACsec generic
/// netlink family, which `nl-macsec` wraps.
pub(crate) async fn apply_macsec_offload(
    handle: &Handle,
    iface_name: &str,
    offload: MacSecOffload,
) -> Result<(), NipartError> {
    let Some(index) = super::get_iface_index_opt(handle, iface_name).await?
    else {
        return Ok(());
    };

    let (conn, mut macsec_handle, _) =
        nl_macsec::new_connection().map_err(|e| {
            NipartError::new(
                ErrorKind::Bug,
                format!("Failed to create MACsec netlink connection: {e}"),
            )
        })?;
    tokio::spawn(conn);

    let mut config = nl_macsec::MacsecConfig::new(index);
    config.secy.offload = Some(offload.into());
    macsec_handle.apply(&config).await.map_err(|e| {
        NipartError::new(
            ErrorKind::Bug,
            format!("Failed to update MACsec {iface_name} offload mode: {e}"),
        )
    })
}
