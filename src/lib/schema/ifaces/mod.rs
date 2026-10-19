// SPDX-License-Identifier: Apache-2.0

mod alt_name;
mod base;
mod bond;
mod bridge_vlan;
mod dummy;
mod ethernet;
mod inter_ifaces;
mod linux_bridge;
mod loopback;
mod macsec;
mod ovs_bridge;
mod ovs_iface;
mod unknown;
mod vlan;
mod vrf;
mod vxlan;
mod wifi;
mod wireguard;

pub use self::{
    alt_name::{AltNameEntry, AltNameState},
    base::BaseInterface,
    bond::{
        BondAdSelect, BondAllPortActive, BondArpAllTargets, BondArpValidate,
        BondConfig, BondFailOverMac, BondInterface, BondLacpRate, BondMode,
        BondOptions, BondPortConfig, BondPrimaryReselect, BondXmitHashPolicy,
    },
    bridge_vlan::{
        BridgeVlanConfig, BridgeVlanMode, BridgeVlanRange, BridgeVlanTrunkTag,
    },
    dummy::DummyInterface,
    ethernet::{EthernetConfig, EthernetDuplex, EthernetInterface, VethConfig},
    inter_ifaces::Interfaces,
    linux_bridge::{
        LinuxBridgeConfig, LinuxBridgeInterface,
        LinuxBridgeMulticastRouterType, LinuxBridgeOptions,
        LinuxBridgePortConfig, LinuxBridgeStpOptions,
    },
    loopback::LoopbackInterface,
    macsec::{MacSecConfig, MacSecInterface, MacSecOffload, MacSecValidate},
    ovs_bridge::{OvsBridgeConfig, OvsBridgeInterface, OvsBridgePortConfig},
    ovs_iface::OvsInterface,
    unknown::UnknownInterface,
    vlan::{
        VlanConfig, VlanInterface, VlanProtocol, VlanQosMapping,
        VlanRegistrationProtocol,
    },
    vrf::{VrfConfig, VrfInterface},
    vxlan::{VxlanConfig, VxlanInterface},
    wifi::{
        WifiAuthType, WifiAuthTypeDetailed, WifiCfgInterface, WifiConfig,
        WifiPhyInterface, WifiScanResult, WifiState,
    },
    wireguard::{
        WireguardConfig, WireguardInterface, WireguardIpAddress,
        WireguardPeerConfig,
    },
};
