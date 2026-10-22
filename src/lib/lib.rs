// SPDX-License-Identifier: Apache-2.0

mod client;
mod dns;
mod error;
mod ipc;
mod logging;
mod no_daemon;
mod plugin;
mod schema;
mod uuid;

pub use nipart_derive::{
    DebugHideSecrets, JsonDisplay, JsonDisplayHideSecrets,
};

pub use self::{
    client::{NipartClient, NipartClientCmd},
    dns::{
        DnsClass, DnsDomainName, DnsHeader, DnsNameCompressionMap, DnsPacket,
        DnsQuestion, DnsResourceRecord, DnsResponseCode, DnsType, DnsUdpClient,
    },
    error::{ErrorKind, NipartError},
    ipc::{NipartCanIpc, NipartIpcConnection},
    logging::{NipartLogEntry, NipartLogLevel},
    no_daemon::NipartNoDaemon,
    plugin::{
        NipartIpcListener, NipartPlugin, NipartPluginClient, NipartPluginCmd,
        NipartPluginInfo,
    },
    schema::*,
    uuid::NipartUuid,
};
