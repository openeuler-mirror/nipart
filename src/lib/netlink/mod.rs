// SPDX-License-Identifier: Apache-2.0

use crate::{ErrorKind, NipartError};

#[allow(dead_code)]
pub(crate) async fn new_connection() -> Result<rtnetlink::Handle, NipartError> {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| {
        NipartError::new(
            ErrorKind::Bug,
            format!("Failed to create rtnetlink connection: {e}"),
        )
    })?;
    tokio::spawn(connection);
    Ok(handle)
}
