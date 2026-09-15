// SPDX-License-Identifier: Apache-2.0

//! DNS cache server task.
//!
//! The cache server itself is the `mudz` crate (same author, Apache-2.0);
//! the daemon converts the schema config into [`mudz::MudzConfig`] and
//! starts/updates/stops the server through [`NipartDnsManager`] instead of
//! running the standalone `mudzd` daemon.

mod config;
mod manager;
mod worker;

pub(crate) use self::{
    config::NipartDnsServerConfig,
    manager::NipartDnsManager,
    worker::{NipartDnsCmd, NipartDnsReply, NipartDnsWorker},
};
