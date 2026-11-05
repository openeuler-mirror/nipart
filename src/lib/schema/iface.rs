// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nmstate project(https://nmstate.io/) which
// is under license of Apache 2.0, authors of original file is:
//  * Gris Ge <fge@redhat.com>
//  * Fernando Fernandez Mancera <ffmancera@riseup.net>
//  * Ales Musil <amusil@redhat.com>
//  * Quique Llorente <ellorent@redhat.com>
//  * Wen Liang <liangwen12year@gmail.com>
//  * Íñigo Huguet <ihuguet@redhat.com>

use serde::{Deserialize, Deserializer, Serialize};

use super::value::get_json_value_difference;
use crate::{
    BaseInterface, BondInterface, DummyInterface, ErrorKind, EthernetInterface,
    InterfaceIdentifier, InterfaceState, InterfaceType, JsonDisplayHideSecrets,
    LinuxBridgeInterface, LoopbackInterface, MacSecInterface, NipartError,
    NipartInterface, OvsBridgeInterface, OvsInterface, UnknownInterface,
    VlanInterface, VrfInterface, VxlanInterface, WifiCfgInterface,
    WifiPhyInterface, WireguardInterface,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonDisplayHideSecrets)]
#[serde(rename_all = "kebab-case", untagged)]
#[non_exhaustive]
/// Represent a kernel or user space network interface.
pub enum Interface {
    /// Ethernet interface.
    Ethernet(Box<EthernetInterface>),
    /// OVS Bridge
    OvsBridge(Box<OvsBridgeInterface>),
    /// OVS System Interface
    OvsInterface(Box<OvsInterface>),
    /// Loopback Interface
    Loopback(Box<LoopbackInterface>),
    /// WiFi Interface
    WifiPhy(Box<WifiPhyInterface>),
    /// Pseudo Interface for WiFi configuration
    WifiCfg(Box<WifiCfgInterface>),
    /// Dummy Interface
    Dummy(Box<DummyInterface>),
    /// VLAN Interface
    Vlan(Box<VlanInterface>),
    /// VRF Interface
    Vrf(Box<VrfInterface>),
    /// VxLAN Interface
    Vxlan(Box<VxlanInterface>),
    /// Bond Interface
    Bond(Box<BondInterface>),
    /// Linux Bridge Interface
    LinuxBridge(Box<LinuxBridgeInterface>),
    /// MACsec Interface
    MacSec(Box<MacSecInterface>),
    /// Wireguard Interface
    Wireguard(Box<WireguardInterface>),
    /// Unknown interface.
    Unknown(Box<UnknownInterface>),
}

impl Default for Interface {
    fn default() -> Self {
        Self::Unknown(Box::default())
    }
}

impl<'de> Deserialize<'de> for Interface {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut v = serde_json::Value::deserialize(deserializer)?;

        // It is safe to do `v["state"]` here as serde_json will
        // return `json!(null)` for undefined property
        if matches!(
            Option::deserialize(&v["state"])
                .map_err(serde::de::Error::custom)?,
            Some(InterfaceState::Absent)
        ) {
            // Ignore all properties except type if state: absent
            let mut new_value = serde_json::map::Map::new();
            if let Some(n) = v.get("name") {
                new_value.insert("name".to_string(), n.clone());
            }
            if let Some(t) = v.get("type") {
                new_value.insert("type".to_string(), t.clone());
            }
            if let Some(s) = v.get("state") {
                new_value.insert("state".to_string(), s.clone());
            }
            // If "veth" section is defined, we need to delete a veth peer
            if let Some(s) = v.get("veth") {
                new_value.insert("veth".to_string(), s.clone());
            }
            if let Some(s) = v.get("identifier") {
                new_value.insert("identifier".to_string(), s.clone());
            }
            if let Some(s) = v.get("mac-address") {
                new_value.insert("mac-address".to_string(), s.clone());
            }
            if let Some(s) = v.get("kernel-iface-name") {
                new_value.insert("kernel-iface-name".to_string(), s.clone());
            }
            if let Some(s) = v.get("profile-name") {
                new_value.insert("profile-name".to_string(), s.clone());
            }
            v = serde_json::value::Value::Object(new_value);
        }

        match Option::deserialize(&v["type"])
            .map_err(serde::de::Error::custom)?
        {
            Some(InterfaceType::Ethernet) | Some(InterfaceType::Veth) => {
                let inner = EthernetInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Ethernet(Box::new(inner)))
            }
            Some(InterfaceType::OvsBridge) => {
                let inner = OvsBridgeInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::OvsBridge(Box::new(inner)))
            }
            Some(InterfaceType::OvsInterface) => {
                let inner = OvsInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::OvsInterface(Box::new(inner)))
            }
            Some(InterfaceType::Loopback) => {
                let inner = LoopbackInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Loopback(Box::new(inner)))
            }
            Some(InterfaceType::WifiPhy) => {
                let inner = WifiPhyInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::WifiPhy(Box::new(inner)))
            }
            Some(InterfaceType::WifiCfg) => {
                let inner = WifiCfgInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::WifiCfg(Box::new(inner)))
            }
            Some(InterfaceType::Dummy) => {
                let inner = DummyInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Dummy(Box::new(inner)))
            }
            Some(InterfaceType::Vlan) => {
                let inner = VlanInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Vlan(Box::new(inner)))
            }
            Some(InterfaceType::Vrf) => {
                let inner = VrfInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Vrf(Box::new(inner)))
            }
            Some(InterfaceType::Vxlan) => {
                let inner = VxlanInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Vxlan(Box::new(inner)))
            }
            Some(InterfaceType::Bond) => {
                let inner = BondInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Bond(Box::new(inner)))
            }
            Some(InterfaceType::LinuxBridge) => {
                let inner = LinuxBridgeInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::LinuxBridge(Box::new(inner)))
            }
            Some(InterfaceType::Wireguard) => {
                let inner = WireguardInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Wireguard(Box::new(inner)))
            }
            Some(InterfaceType::MacSec) => {
                let inner = MacSecInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::MacSec(Box::new(inner)))
            }
            _ => {
                let inner = UnknownInterface::deserialize(v)
                    .map_err(serde::de::Error::custom)?;
                Ok(Interface::Unknown(Box::new(inner)))
            }
        }
    }
}

macro_rules! gen_sanitize {
    ( $desired:ident,
      $current:ident,
      $for_save:ident,
      $for_apply:ident,
      $for_verify:ident,
      $merged:ident,
      $($variant:path,)+ ) => {
        match $desired {
            $(
                $variant(desired) => {
                    let cur_iface = if let Some($variant(c)) = $current
                    {
                        Some(&**c)
                    } else {
                        if let Some(current) = $current {
                            return Err(NipartError::new(
                                ErrorKind::Bug,
                                format!(
                                    "current interface holding the different \
                                    interface type as as desired, current {}, \
                                    desired {}", desired.iface_type(),
                                    current.iface_type(),
                                ),
                            ));
                        }
                        None
                    };
                    let (for_save, for_apply, for_verify, merged) =
                        if let $variant(save) = $for_save &&
                           let $variant(apply) = $for_apply &&
                           let $variant(verify) = $for_verify &&
                           let $variant(merged) = $merged
                    {
                        (save, apply, verify, merged)
                    } else {
                        return Err(NipartError::new(
                            ErrorKind::Bug,
                            format!(
                                "merged interface holding the different \
                                interface type as as desired, for_saved {}, \
                                for_apply {} , for_verify {}, merged {},
                                desired {}",
                                desired.iface_type(),
                                $for_save.iface_type(),
                                $for_apply.iface_type(),
                                $for_verify.iface_type(),
                                $merged.iface_type(),
                            ),
                        ));
                    };

                    desired.sanitize(
                        cur_iface,
                        for_save,
                        for_apply,
                        for_verify,
                        merged,
                    )
                }
            )+
        }
    };
}

macro_rules! gen_sanitize_before_verify {
    ( $desired:ident, $current:ident, $($variant:path,)+ ) => {
        match $desired {
            $(
                $variant(i) => {
                    if let $variant(cur_iface) = $current {
                        i.sanitize_before_verify(cur_iface);
                    };
                }
            )+
        }
    };
}

macro_rules! gen_include_diff_context {
    ( $diff:ident, $desired:ident, $current:ident, $($variant:path,)+ ) => {
        match ($diff, $desired, $current) {
            $(
                (
                    $variant(i),
                    $variant(desired),
                    $variant(current),
                ) => i.include_diff_context(desired, current),
            )+
            (_, desired, current) => {
                log::error!(
                    "BUG: Interface::include_diff_context() \
                     Unexpected desired {:?} current {:?}",
                     desired, current,
                );
            }
        }
    };
}

macro_rules! gen_include_revert_context{
    ( $revert:ident, $desired:ident, $pre_apply:ident, $($variant:path,)+ ) => {
        match ($revert, $desired, $pre_apply) {
            $(
                (
                    $variant(i),
                    $variant(desired),
                    $variant(pre_apply),
                ) => i.include_revert_context(
                    desired,
                    pre_apply,
                ),
            )+
            _ => {
                log::error!(
                    "BUG: Interface::include_revert_context() \
                     Unexpected input desired {:?} pre_apply {:?}",
                     $desired, $pre_apply
                );
            }
        }
    };
}

macro_rules! gen_post_merge{
    ( $merged:ident, $new:ident, $old:ident, $($variant:path,)+ ) => {
        match ($merged, $new, $old) {
            $(
                ($variant(i), $variant(n), $variant(o)) =>
                    i.post_merge(n, o),
            )+
            (merged, new, old) => {
                log::error!(
                    "BUG: Interface::post_merge() \
                     Unexpected input merged {merged:?} new_state {new:?}, \
                     old_state {old:?}"
                );
                Ok(())
            }
        }
    };
}

macro_rules! gen_need_delete_before_change {
    ( $desired:ident, $current:ident, $($variant:path,)+ ) => {
        match ($desired, $current) {
            $(
                ($variant(d), $variant(c)) => d.need_delete_before_change(c),
            )+
            (desired, current) => {
                log::error!(
                    "BUG: Interface::include_revert_context() \
                     Unexpected input merged {desired:?} old_state {current:?}"
                );
                false
            }
        }
    };
}

macro_rules! gen_iface_no_arg {
    ( $self:ident, $func:ident, $($variant:path,)+ ) => {
        match $self {
            $(
                $variant(i) => i.$func(),
            )+
        }
    };
}

macro_rules! gen_iface_trait_impl {
    ( $(($func:ident, $return:ty),)+ ) => {
        $(
            fn $func(&self) -> $return {
                gen_iface_no_arg!(
                    self,
                    $func,
                    Self::Ethernet,
                    Self::OvsBridge,
                    Self::OvsInterface,
                    Self::Loopback,
                    Self::WifiPhy,
                    Self::WifiCfg,
                    Self::Dummy,
                    Self::Vlan,
                    Self::Vrf,
                    Self::Vxlan,
                    Self::Bond,
                    Self::LinuxBridge,
                    Self::Wireguard,
                    Self::MacSec,
                    Self::Unknown,
                )
            }
        )+
    }
}

macro_rules! gen_iface_trait_impl_mut {
    ( $(($func:ident, $return:ty),)+ ) => {
        $(
            fn $func(&mut self) -> $return {
                gen_iface_no_arg!(
                    self,
                    $func,
                    Self::Ethernet,
                    Self::OvsBridge,
                    Self::OvsInterface,
                    Self::Loopback,
                    Self::WifiPhy,
                    Self::WifiCfg,
                    Self::Dummy,
                    Self::Vlan,
                    Self::Vrf,
                    Self::Vxlan,
                    Self::Bond,
                    Self::LinuxBridge,
                    Self::Wireguard,
                    Self::MacSec,
                    Self::Unknown,
                )
            }
        )+
    }
}

impl NipartInterface for Interface {
    gen_iface_trait_impl!(
        (is_virtual, bool),
        (base_iface, &BaseInterface),
        (is_controller, bool),
        (ports, Option<Vec<&str>>),
        (parent, Option<&str>),
    );

    gen_iface_trait_impl_mut!(
        (base_iface_mut, &mut BaseInterface),
        (hide_secrets, ()),
    );

    fn sanitize(
        &self,
        current: Option<&Self>,
        for_save: &mut Self,
        for_apply: &mut Self,
        for_verify: &mut Self,
        merged: &mut Self,
    ) -> Result<(), NipartError> {
        gen_sanitize!(
            self,
            current,
            for_save,
            for_apply,
            for_verify,
            merged,
            Interface::Ethernet,
            Interface::OvsBridge,
            Interface::OvsInterface,
            Interface::Loopback,
            Interface::WifiPhy,
            Interface::WifiCfg,
            Interface::Dummy,
            Interface::Vlan,
            Interface::Vrf,
            Interface::Vxlan,
            Interface::Bond,
            Interface::LinuxBridge,
            Interface::Wireguard,
            Interface::MacSec,
            Interface::Unknown,
        )
    }

    fn sanitize_before_verify(&mut self, current: &mut Self) {
        gen_sanitize_before_verify!(
            self,
            current,
            Interface::Ethernet,
            Interface::OvsBridge,
            Interface::OvsInterface,
            Interface::Loopback,
            Interface::WifiPhy,
            Interface::WifiCfg,
            Interface::Dummy,
            Interface::Vlan,
            Interface::Vrf,
            Interface::Vxlan,
            Interface::Bond,
            Interface::LinuxBridge,
            Interface::Wireguard,
            Interface::MacSec,
            Interface::Unknown,
        );
    }

    fn include_diff_context(&mut self, desired: &Self, current: &Self) {
        gen_include_diff_context!(
            self,
            desired,
            current,
            Interface::Ethernet,
            Interface::OvsBridge,
            Interface::OvsInterface,
            Interface::Loopback,
            Interface::WifiPhy,
            Interface::WifiCfg,
            Interface::Dummy,
            Interface::Vlan,
            Interface::Vrf,
            Interface::Vxlan,
            Interface::Bond,
            Interface::LinuxBridge,
            Interface::Wireguard,
            Interface::MacSec,
            Interface::Unknown,
        )
    }

    fn include_revert_context(&mut self, desired: &Self, pre_apply: &Self) {
        gen_include_revert_context!(
            self,
            desired,
            pre_apply,
            Interface::Ethernet,
            Interface::OvsBridge,
            Interface::OvsInterface,
            Interface::Loopback,
            Interface::WifiPhy,
            Interface::WifiCfg,
            Interface::Dummy,
            Interface::Vlan,
            Interface::Vrf,
            Interface::Vxlan,
            Interface::Bond,
            Interface::LinuxBridge,
            Interface::Wireguard,
            Interface::MacSec,
            Interface::Unknown,
        )
    }

    fn post_merge(
        &mut self,
        new_state: &Self,
        old_state: &Self,
    ) -> Result<(), NipartError> {
        gen_post_merge!(
            self,
            new_state,
            old_state,
            Interface::Ethernet,
            Interface::OvsBridge,
            Interface::OvsInterface,
            Interface::Loopback,
            Interface::WifiPhy,
            Interface::WifiCfg,
            Interface::Dummy,
            Interface::Vlan,
            Interface::Vrf,
            Interface::Vxlan,
            Interface::Bond,
            Interface::LinuxBridge,
            Interface::Wireguard,
            Interface::MacSec,
            Interface::Unknown,
        )
    }

    fn need_delete_before_change(&self, current: &Self) -> bool {
        gen_need_delete_before_change!(
            self,
            current,
            Interface::Ethernet,
            Interface::OvsBridge,
            Interface::OvsInterface,
            Interface::Loopback,
            Interface::WifiPhy,
            Interface::WifiCfg,
            Interface::Dummy,
            Interface::Vlan,
            Interface::Vrf,
            Interface::Vxlan,
            Interface::Bond,
            Interface::LinuxBridge,
            Interface::Wireguard,
            Interface::MacSec,
            Interface::Unknown,
        )
    }
}

impl From<BaseInterface> for Interface {
    fn from(mut base_iface: BaseInterface) -> Self {
        // The kernel reports veth NICs as `Veth` while nipart
        // treats them as ethernet (see
        // `Interfaces::unify_veth_and_ethernet()`): normalize before
        // matching, otherwise this conversion panics for veth NICs.
        if base_iface.iface_type == InterfaceType::Veth {
            base_iface.iface_type = InterfaceType::Ethernet;
        }
        let mut iface = match &base_iface.iface_type {
            InterfaceType::Ethernet => Interface::Ethernet(Default::default()),
            InterfaceType::Hsr => todo!(),
            InterfaceType::Bond => Interface::Bond(Default::default()),
            InterfaceType::LinuxBridge => {
                Interface::LinuxBridge(Default::default())
            }
            InterfaceType::Dummy => Interface::Dummy(Default::default()),
            InterfaceType::Loopback => Interface::Loopback(Default::default()),
            InterfaceType::MacVlan => todo!(),
            InterfaceType::MacVtap => todo!(),
            InterfaceType::OvsBridge => {
                Interface::OvsBridge(Default::default())
            }
            InterfaceType::OvsInterface => {
                Interface::OvsInterface(Default::default())
            }
            InterfaceType::Veth => todo!(),
            InterfaceType::Vlan => Interface::Vlan(Default::default()),
            InterfaceType::Vrf => Interface::Vrf(Default::default()),
            InterfaceType::Vxlan => Interface::Vxlan(Default::default()),
            InterfaceType::InfiniBand => todo!(),
            InterfaceType::Tun => todo!(),
            InterfaceType::MacSec => Interface::MacSec(Default::default()),
            InterfaceType::Ipsec => todo!(),
            InterfaceType::Xfrm => todo!(),
            InterfaceType::IpVlan => todo!(),
            InterfaceType::WifiPhy => Interface::WifiPhy(Default::default()),
            InterfaceType::WifiCfg => Interface::WifiCfg(Default::default()),
            InterfaceType::Wireguard => {
                Interface::Wireguard(Default::default())
            }
            InterfaceType::Unknown(_) => Interface::Unknown(Default::default()),
        };
        *iface.base_iface_mut() = base_iface;
        iface
    }
}

impl Interface {
    pub fn is_match(&self, cur_iface: &Self) -> bool {
        if !is_same_type(self.iface_type(), cur_iface.iface_type()) {
            return false;
        }
        let base = self.base_iface();
        match &base.identifier {
            None | Some(InterfaceIdentifier::Name) => {
                self.kernel_iface_name() == cur_iface.kernel_iface_name()
                    || self.name() == cur_iface.kernel_iface_name()
            }
            Some(InterfaceIdentifier::MacAddress) => {
                if let Some(saved_mac) = base.mac_address.as_deref() {
                    let saved_mac = saved_mac.to_ascii_uppercase();
                    let cur_base = cur_iface.base_iface();
                    cur_base
                        .permanent_mac_address
                        .as_deref()
                        .map(|m| m.to_ascii_uppercase() == saved_mac)
                        .unwrap_or(false)
                        || cur_base
                            .mac_address
                            .as_deref()
                            .map(|m| m.to_ascii_uppercase() == saved_mac)
                            .unwrap_or(false)
                } else {
                    false
                }
            }
        }
    }

    pub fn clone_name_type_only(&self) -> Self {
        self.base_iface().clone_name_type_only().into()
    }

    pub(crate) fn change_port_name(
        &mut self,
        org_port_name: &str,
        new_port_name: String,
    ) -> Result<(), NipartError> {
        if let Interface::LinuxBridge(iface) = self {
            iface.change_port_name(org_port_name, new_port_name)
        } else if let Interface::OvsBridge(iface) = self {
            iface.change_port_name(org_port_name, new_port_name)
        } else if let Interface::Bond(iface) = self {
            iface.change_port_name(org_port_name, new_port_name)
        } else if let Interface::Vrf(iface) = self {
            iface.change_port_name(org_port_name, new_port_name);
            Ok(())
        } else {
            Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Interface type {} does not support changing port names",
                    self.iface_type()
                ),
            ))
        }
    }

    pub(crate) fn verify(&self, current: &Self) -> Result<(), NipartError> {
        let self_value = serde_json::to_value(self.clone())?;
        let current_value = serde_json::to_value(current.clone())?;

        if let Some((reference, desire, current)) = get_json_value_difference(
            format!("{}.interface", self.name()),
            &self_value,
            &current_value,
        ) {
            Err(NipartError::new(
                ErrorKind::VerificationError,
                format!(
                    "Verification failure: {reference} desire '{desire}', \
                     current '{current}'"
                ),
            ))
        } else {
            Ok(())
        }
    }
}

const VETH_AND_ETHERNET_TYPES: [&InterfaceType; 2] =
    [&InterfaceType::Veth, &InterfaceType::Ethernet];

fn is_same_type(a: &InterfaceType, b: &InterfaceType) -> bool {
    if a == b {
        return true;
    }
    VETH_AND_ETHERNET_TYPES.contains(&a) && VETH_AND_ETHERNET_TYPES.contains(&b)
}
