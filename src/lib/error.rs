// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{JsonDisplay, NipartCanIpc};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonDisplay,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ErrorKind {
    /// Please report this as bug to upstream
    Bug,
    /// Inter-process communication remote end closed
    IpcClosed,
    /// Inter-process communication failure
    IpcFailure,
    /// Data send through NipartIpcConnection exceeded the maximum size
    IpcMessageTooLarge,
    /// Invalid log level
    InvalidLogLevel,
    /// Invalid UUID format
    InvalidUuid,
    /// Invalid schema version
    InvalidSchemaVersion,
    /// Invalid argument
    InvalidArgument,
    /// Timeout
    Timeout,
    /// Not supported
    NoSupport,
    /// Authentication failure, e.g. wrong WIFI password
    AuthenticationError,
    /// Plugin failure
    PluginFailure,
    /// Daemon failure
    DaemonFailure,
    /// Post applied state does not match with desired state
    VerificationError,
    /// Permission deny
    PermissionDeny,
    /// Missing dependency
    DependencyError,
}

impl ErrorKind {
    /// Whether an operation failed with this error kind may succeed when it
    /// is retried.
    ///
    /// Deterministic errors (bad input, unsupported request, authentication
    /// or permission failure, programming bug) will fail again, so retrying
    /// them only delays the error report.  Everything else (a closed IPC
    /// connection, a timeout, a plugin/daemon failure, a failed
    /// verification, a missing dependency which may appear later) is
    /// considered transient.
    pub fn retriable(&self) -> bool {
        !matches!(
            self,
            Self::Bug
                | Self::IpcMessageTooLarge
                | Self::InvalidLogLevel
                | Self::InvalidUuid
                | Self::InvalidSchemaVersion
                | Self::InvalidArgument
                | Self::NoSupport
                | Self::AuthenticationError
                | Self::PermissionDeny
        )
    }
}

// Try not implement From for NipartError here unless you are sure this
// error should always convert to certain type of ErrorKind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NipartError {
    pub kind: ErrorKind,
    pub msg: String,
}

impl std::fmt::Display for NipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}

impl NipartError {
    pub const IPC_KIND: &'static str = "error";

    pub fn new(kind: ErrorKind, msg: String) -> Self {
        Self { kind, msg }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn msg(&self) -> &str {
        self.msg.as_str()
    }
}

impl std::error::Error for NipartError {}

impl From<serde_json::Error> for NipartError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(ErrorKind::Bug, format!("serde_json::Error: {e}"))
    }
}

impl NipartCanIpc for NipartError {
    fn ipc_kind(&self) -> String {
        Self::IPC_KIND.to_string()
    }
}

impl From<std::io::Error> for NipartError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::Bug, format!("std::io::Error: {e}"))
    }
}

impl From<std::net::AddrParseError> for NipartError {
    fn from(e: std::net::AddrParseError) -> Self {
        Self::new(
            ErrorKind::InvalidArgument,
            format!("Invalid IP address: {e}"),
        )
    }
}

// TODO: Properly handle cases like:
//  * Permission deny
//  * Invalid argument
impl From<nispor::NisporError> for NipartError {
    fn from(e: nispor::NisporError) -> Self {
        Self::new(ErrorKind::Bug, format!("{}: {}", e.kind, e.msg))
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorKind;

    #[test]
    fn test_retriable_error_kinds() {
        // Bad input and other deterministic failures are not retried.
        for kind in [
            ErrorKind::Bug,
            ErrorKind::InvalidArgument,
            ErrorKind::NoSupport,
            ErrorKind::AuthenticationError,
            ErrorKind::PermissionDeny,
        ] {
            assert!(!kind.retriable(), "{kind} should not be retriable");
        }
        // Transient failures are retried.
        for kind in [
            ErrorKind::IpcClosed,
            ErrorKind::IpcFailure,
            ErrorKind::Timeout,
            ErrorKind::PluginFailure,
            ErrorKind::DaemonFailure,
            ErrorKind::VerificationError,
            ErrorKind::DependencyError,
        ] {
            assert!(kind.retriable(), "{kind} should be retriable");
        }
    }
}
