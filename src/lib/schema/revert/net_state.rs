// SPDX-License-Identifier: Apache-2.0

use crate::{MergedNetworkState, NetworkState, NipartError};

impl MergedNetworkState {
    /// Generate revert state of MergedNetworkState which holds desired state,
    /// pre-apply current state.
    /// The returned state could be applied to restore network config back to
    /// pre-apply state.
    pub fn generate_revert(&self) -> Result<NetworkState, NipartError> {
        Ok(NetworkState {
            ifaces: self.ifaces.generate_revert()?,
            routes: self.routes.generate_revert()?,
            route_rules: self.route_rules.generate_revert()?,
            ..Default::default()
        })
    }
}
