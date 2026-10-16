// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq,
};

use crate::{
    BaseInterface, ErrorKind, IfaceSearch, Interface, InterfaceIdentifier,
    InterfaceType, JsonDisplayHideSecrets, NipartError, NipartInterface,
};

/// Represent a list of [Interface].
///
/// When applying complex nested interface(e.g. Bridge over bond over vlan of
/// eth1), the supported maximum nest level is 4. For 5+ nested level, you need
/// to place controller interface before its ports.
#[derive(Clone, Debug, Default, PartialEq, Eq, JsonDisplayHideSecrets)]
#[non_exhaustive]
pub struct Interfaces {
    /// HashMap key is kernel_iface_name, if no kernel_iface_name,
    /// use interface.name instead
    pub kernel_ifaces: HashMap<String, Interface>,
    pub user_ifaces: HashMap<(String, InterfaceType), Interface>,
    pub insert_order: Vec<(String, InterfaceType)>,
    pub(crate) iface_search: IfaceSearch,
}

impl<'de> Deserialize<'de> for Interfaces {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::new(<Vec<Interface> as Deserialize>::deserialize(
            deserializer,
        )?))
    }
}

impl Serialize for Interfaces {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ifaces = self.iter();
        let mut seq = serializer.serialize_seq(None)?;
        for iface in ifaces {
            seq.serialize_element(iface)?;
        }
        seq.end()
    }
}

impl Interfaces {
    pub fn new(ifaces: Vec<Interface>) -> Self {
        let mut ret = Self::default();
        for iface in ifaces {
            ret.push(iface)
        }
        ret
    }

    pub fn is_empty(&self) -> bool {
        self.kernel_ifaces.is_empty() && self.user_ifaces.is_empty()
    }

    pub fn push(&mut self, mut iface: Interface) {
        self.iface_search.push(&iface);
        // Ensure kernel_iface_name field is set for name-matching
        // kernel interfaces so that merge/sanitize can use it.
        if iface.base_iface().kernel_iface_name.is_empty()
            && iface.is_name_matching()
            && !iface.is_userspace()
        {
            iface.base_iface_mut().kernel_iface_name = iface.name().to_string();
        }
        let iface_name = if iface.kernel_iface_name().is_empty() {
            iface.name().to_string()
        } else {
            iface.kernel_iface_name().to_string()
        };
        self.insert_order
            .push((iface_name.clone(), iface.iface_type().clone()));
        if iface.is_userspace() {
            self.user_ifaces
                .insert((iface_name, iface.iface_type().clone()), iface);
        } else {
            self.kernel_ifaces.insert(iface_name, iface);
        }
    }

    /// Unlike get_matched_iface_from_current(), this function does not
    /// search MAC identifier, just simply search kernel_iface_name or
    /// interface.name.
    pub fn get(&self, base_iface: &BaseInterface) -> Option<&Interface> {
        if base_iface.is_userspace() {
            self.user_ifaces.get(&(
                base_iface.name.to_string(),
                base_iface.iface_type.clone(),
            ))
        } else if base_iface.kernel_iface_name.is_empty() {
            self.kernel_ifaces.get(base_iface.name.as_str())
        } else {
            self.kernel_ifaces
                .get(base_iface.kernel_iface_name.as_str())
        }
    }

    pub fn get_mut(
        &mut self,
        base_iface: &BaseInterface,
    ) -> Option<&mut Interface> {
        if base_iface.is_userspace() {
            self.user_ifaces.get_mut(&(
                base_iface.name.to_string(),
                base_iface.iface_type.clone(),
            ))
        } else if base_iface.kernel_iface_name.is_empty() {
            self.kernel_ifaces.get_mut(base_iface.name.as_str())
        } else {
            self.kernel_ifaces
                .get_mut(base_iface.kernel_iface_name.as_str())
        }
    }

    /// Iterate interfaces in the order they got inserted.
    pub fn iter(&self) -> impl Iterator<Item = &Interface> {
        let mut seen_kernel: HashSet<&str> = HashSet::new();
        let mut seen_user: HashSet<&(String, InterfaceType)> = HashSet::new();
        self.insert_order.iter().filter_map(move |key| {
            let (name, iface_type) = key;
            if iface_type.is_userspace() {
                if seen_user.insert(key) {
                    self.user_ifaces.get(&(name.clone(), iface_type.clone()))
                } else {
                    None
                }
            } else if seen_kernel.insert(name.as_str()) {
                self.kernel_ifaces.get(name)
            } else {
                None
            }
        })
    }

    /// Iterate mutable interfaces.
    ///
    /// Unlike `iter()`, the order is not guaranteed since ordered mutable
    /// access into the interface hash maps is not possible in safe Rust.
    /// The only consumer, `hide_secrets()`, does not rely on ordering.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Interface> {
        self.kernel_ifaces
            .values_mut()
            .chain(self.user_ifaces.values_mut())
    }

    pub fn drain(&mut self) -> impl Iterator<Item = Interface> {
        self.kernel_ifaces
            .drain()
            .map(|(_, iface)| iface)
            .chain(self.user_ifaces.drain().map(|(_, iface)| iface))
    }

    pub(crate) fn hide_secrets(&mut self) {
        for iface in self.iter_mut() {
            // for now BaseInterface has no secret to hide
            iface.hide_secrets();
        }
    }

    /// Assuming self is current interfaces, search on matching interface of
    /// desired.
    pub(crate) fn get_matched_iface_from_current(
        &self,
        des_iface: &BaseInterface,
    ) -> Result<Option<&Interface>, NipartError> {
        match des_iface.identifier {
            None | Some(InterfaceIdentifier::Name) => {
                if des_iface.is_userspace() {
                    Ok(self.user_ifaces.get(&(
                        des_iface.name.to_string(),
                        des_iface.iface_type.clone(),
                    )))
                } else {
                    let kernel_name = if !des_iface.kernel_iface_name.is_empty()
                    {
                        des_iface.kernel_iface_name.to_string()
                    } else {
                        self.iface_search
                            .search_name(des_iface.name.as_str())
                            .unwrap_or_else(|| des_iface.name.to_string())
                    };
                    Ok(self.kernel_ifaces.get(&kernel_name))
                }
            }
            Some(InterfaceIdentifier::MacAddress) => {
                let Some(search_mac) = des_iface.mac_address.as_deref() else {
                    return Err(NipartError::new(
                        ErrorKind::InvalidArgument,
                        format!(
                            "Interface {}/{} with identifier: mac but no MAC \
                             address defined",
                            des_iface.name, des_iface.iface_type
                        ),
                    ));
                };
                let kernel_iface_names =
                    self.iface_search.search_mac(search_mac);
                // TODO: For now, we raise error for not found, but we might
                //       need to allow user store config without apply.
                if kernel_iface_names.is_empty() {
                    if des_iface.state.is_absent()
                        || des_iface.state.is_ignore()
                    {
                        // Removing a saved MAC-identified profile does not
                        // need a live NIC: the NIC may already be gone
                        // (e.g. dock unplug), and the absent apply only
                        // needs to drop the saved config.  A
                        // `state: ignore` entry must be persistable even
                        // when the NIC is currently absent.
                        Ok(None)
                    } else {
                        Err(NipartError::new(
                            ErrorKind::InvalidArgument,
                            format!(
                                "Failed to find interface with mac address \
                                 {search_mac} for interface {}/{}",
                                des_iface.name, des_iface.iface_type
                            ),
                        ))
                    }
                } else {
                    Ok(self.kernel_ifaces.get(&kernel_iface_names[0]))
                }
            }
        }
    }

    /// Assuming self is saved config, search on first match interface matching
    /// desired.
    pub(crate) fn get_matched_iface_from_save(
        &self,
        des_iface: &BaseInterface,
    ) -> Option<&Interface> {
        match des_iface.identifier {
            None | Some(InterfaceIdentifier::Name) => {
                if des_iface.is_userspace() {
                    self.user_ifaces.get(&(
                        des_iface.name.to_string(),
                        des_iface.iface_type.clone(),
                    ))
                } else {
                    let kernel_name = if !des_iface.kernel_iface_name.is_empty()
                    {
                        des_iface.kernel_iface_name.to_string()
                    } else {
                        self.iface_search
                            .search_name(des_iface.name.as_str())
                            .unwrap_or_else(|| des_iface.name.to_string())
                    };
                    self.kernel_ifaces.get(&kernel_name)
                }
            }
            Some(InterfaceIdentifier::MacAddress) => {
                let mut ret = None;
                if let Some(search_mac) = des_iface.mac_address.as_deref() {
                    // search if any saved config holds this MAC address
                    // and also for identifier:mac
                    ret = self.iter().find(|i| {
                        i.base_iface().identifier
                            == Some(InterfaceIdentifier::MacAddress)
                            && i.base_iface().mac_address.as_deref()
                                == Some(search_mac)
                    });
                }
                if ret.is_none()
                    && let Some(search_profile_name) =
                        des_iface.profile_name.as_deref()
                {
                    // search interface profile_name
                    ret = self.iter().find(|i| {
                        i.base_iface().identifier
                            == Some(InterfaceIdentifier::MacAddress)
                            && i.base_iface().profile_name.as_deref()
                                == Some(search_profile_name)
                    })
                }

                if ret.is_none() {
                    // search interface name equal to saved interface profile
                    // name
                    ret = self.iter().find(|i| {
                        i.base_iface().identifier
                            == Some(InterfaceIdentifier::MacAddress)
                            && i.base_iface().profile_name.as_deref()
                                == Some(des_iface.name.as_str())
                    })
                }

                if ret.is_none() {
                    // search interface name equal to saved interface name
                    ret = self.iter().find(|i| {
                        i.base_iface().identifier
                            == Some(InterfaceIdentifier::MacAddress)
                            && i.base_iface().name.as_str()
                                == des_iface.name.as_str()
                    })
                }
                ret
            }
        }
    }
}
