// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{Interface, NipartInterface};

/// Search cache for kernel interfaces
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct IfaceSearch {
    profiles: HashMap<String, String>,
    kernel_names: HashSet<String>,
    permanent_mac_addresses: HashMap<String, Vec<String>>,
    mac_addresses: HashMap<String, Vec<String>>,
}

impl IfaceSearch {
    pub(crate) fn new<'a>(iter: impl Iterator<Item = &'a Interface>) -> Self {
        let mut ret = Self::default();
        for iface in iter {
            ret.push(iface);
        }
        ret
    }

    pub(crate) fn push(&mut self, iface: &Interface) {
        if iface.is_userspace() {
            return;
        }
        let kernel_iface_name = iface.kernel_iface_name().to_string();
        if kernel_iface_name.is_empty() {
            return;
        }
        if let Some(profile_name) = iface.base_iface().profile_name.as_ref()
            && !profile_name.is_empty()
        {
            self.profiles
                .insert(profile_name.to_string(), kernel_iface_name.clone());
        }
        if let Some(mac) = iface.base_iface().permanent_mac_address.as_ref()
            && !mac.is_empty()
        {
            self.permanent_mac_addresses
                .entry(mac.to_ascii_uppercase())
                .or_default()
                .push(kernel_iface_name.clone());
        }

        if let Some(mac) = iface.base_iface().mac_address.as_ref()
            && !mac.is_empty()
        {
            self.mac_addresses
                .entry(mac.to_ascii_uppercase())
                .or_default()
                .push(kernel_iface_name.clone());
        }

        self.kernel_names.insert(kernel_iface_name);
    }

    pub(crate) fn search_name(&self, name: &str) -> Option<String> {
        if self.kernel_names.contains(name) {
            Some(name.to_string())
        } else {
            self.profiles.get(name).cloned()
        }
    }

    pub(crate) fn search_mac(&self, mac: &str) -> Vec<String> {
        let mac = mac.to_ascii_uppercase();
        self.permanent_mac_addresses
            .get(&mac)
            .or_else(|| self.mac_addresses.get(&mac))
            .cloned()
            .unwrap_or_default()
    }
}
