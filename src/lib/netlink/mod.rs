// SPDX-License-Identifier: Apache-2.0

pub(crate) mod link;
mod mac;
pub(crate) mod route;
pub(crate) mod rule;
mod sysfs;

#[cfg(test)]
mod unit_tests;

use crate::{ErrorKind, NipartError};

pub(crate) async fn new_connection() -> Result<rtnetlink::Handle, NipartError> {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| {
        map_io_error("Failed to create rtnetlink connection", e)
    })?;
    tokio::spawn(connection);
    Ok(handle)
}

pub(crate) async fn new_connection_with_strict_check()
-> Result<rtnetlink::Handle, NipartError> {
    let (connection, handle, _) = rtnetlink::new_connection_with_strict_check()
        .map_err(|e| {
            map_io_error("Failed to create strict rtnetlink connection", e)
        })?;
    tokio::spawn(connection);
    Ok(handle)
}

#[allow(dead_code)]
pub(crate) fn map_rtnetlink_error(
    context: &str,
    error: rtnetlink::Error,
) -> NipartError {
    NipartError::new(ErrorKind::Bug, format!("{context}: {error}"))
}

#[allow(dead_code)]
pub(crate) fn map_netlink_proto_error<T: std::fmt::Debug>(
    context: &str,
    error: rtnetlink::proto::Error<T>,
) -> NipartError {
    NipartError::new(ErrorKind::Bug, format!("{context}: {error}"))
}

#[allow(dead_code)]
pub(crate) fn map_decode_error(
    context: &str,
    error: rtnetlink::packet_core::DecodeError,
) -> NipartError {
    NipartError::new(ErrorKind::Bug, format!("{context}: {error}"))
}

#[allow(dead_code)]
pub(crate) fn map_io_error(
    context: &str,
    error: std::io::Error,
) -> NipartError {
    NipartError::new(ErrorKind::Bug, format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        map_decode_error, map_io_error, map_netlink_proto_error,
        map_rtnetlink_error,
    };
    use crate::ErrorKind;

    #[test]
    fn test_map_rtnetlink_error() {
        let error = map_rtnetlink_error(
            "Failed to dump links",
            rtnetlink::Error::RequestFailed,
        );
        assert_eq!(error.kind(), ErrorKind::Bug);
        assert!(error.msg().contains("Failed to dump links"));
        assert!(error.msg().contains("A netlink request failed"));
    }

    #[test]
    fn test_map_netlink_proto_error() {
        let error = map_netlink_proto_error(
            "Failed to receive route",
            rtnetlink::proto::Error::<
                rtnetlink::packet_route::RouteNetlinkMessage,
            >::ConnectionClosed,
        );
        assert_eq!(error.kind(), ErrorKind::Bug);
        assert!(error.msg().contains("Failed to receive route"));
        assert!(error.msg().contains("connection is closed"));
    }

    #[test]
    fn test_map_decode_error() {
        let error = map_decode_error(
            "Failed to parse address message",
            rtnetlink::packet_core::DecodeError::from("truncated message"),
        );
        assert_eq!(error.kind(), ErrorKind::Bug);
        assert!(error.msg().contains("Failed to parse address message"));
        assert!(error.msg().contains("truncated message"));
    }

    #[test]
    fn test_map_io_error() {
        let error = map_io_error(
            "Failed to open socket",
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "permission denied",
            ),
        );
        assert_eq!(error.kind(), ErrorKind::Bug);
        assert!(error.msg().contains("Failed to open socket"));
        assert!(error.msg().contains("permission denied"));
    }
}
