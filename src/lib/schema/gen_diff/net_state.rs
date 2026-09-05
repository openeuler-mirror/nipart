// SPDX-License-Identifier: Apache-2.0

use crate::{MergedNetworkState, NetworkState, NipartError};

impl MergedNetworkState {
    pub fn gen_diff(&self) -> Result<NetworkState, NipartError> {
        Ok(NetworkState {
            version: self.version,
            description: self.description.clone(),
            ifaces: self.ifaces.gen_diff()?,
            routes: self.routes.gen_diff(),
            route_rules: self.route_rules.gen_diff(),
            wait_online: if self.wait_online == Default::default() {
                None
            } else {
                Some(self.wait_online.clone())
            },
        })
    }
}

impl NetworkState {
    /// Generate NetworkState containing only the properties changed comparing
    /// to `old_state`.
    pub fn gen_diff(&self, old: &Self) -> Result<Self, NipartError> {
        Ok(Self {
            version: self.version,
            description: self
                .description
                .clone()
                .or_else(|| old.description.clone()),
            ifaces: self.ifaces.gen_diff(&old.ifaces)?,
            routes: self.routes.gen_diff(&old.routes),
            route_rules: self.route_rules.gen_diff(&old.route_rules),
            wait_online: self
                .wait_online
                .clone()
                .or_else(|| old.wait_online.clone()),
        })
    }
}
