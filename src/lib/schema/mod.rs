// SPDX-License-Identifier: Apache-2.0

mod auto_connect;
mod gen_diff;
mod iface;
mod iface_identifier;
mod iface_search;
mod iface_state;
mod iface_trait;
mod iface_type;
mod ifaces;
mod ip;
mod link_event;
mod link_state;
mod merged;
mod net_state;
mod revert;
mod route;
mod route_rule;
mod state_options;
mod value;
mod version;
mod wait_online;

#[allow(dead_code)]
pub(crate) mod deserializer;
#[allow(dead_code)]
pub(crate) mod serializer;

pub(crate) use iface_search::IfaceSearch;

pub use self::{
    auto_connect::InterfaceAutoConnect,
    iface::Interface,
    iface_identifier::InterfaceIdentifier,
    iface_state::InterfaceState,
    iface_trait::NipartInterface,
    iface_type::InterfaceType,
    ifaces::{
        AltNameEntry, AltNameState, BaseInterface, BondAdSelect,
        BondAllPortActive, BondArpAllTargets, BondArpValidate, BondConfig,
        BondFailOverMac, BondInterface, BondLacpRate, BondMode, BondOptions,
        BondPortConfig, BondPrimaryReselect, BondXmitHashPolicy,
        BridgeVlanConfig, BridgeVlanMode, BridgeVlanRange, BridgeVlanTrunkTag,
        DummyInterface, EthernetConfig, EthernetDuplex, EthernetInterface,
        Interfaces, LinuxBridgeConfig, LinuxBridgeInterface,
        LinuxBridgeMulticastRouterType, LinuxBridgeOptions,
        LinuxBridgePortConfig, LinuxBridgeStpOptions, LoopbackInterface,
        OvsBridgeConfig, OvsBridgeInterface, OvsBridgePortConfig, OvsInterface,
        UnknownInterface, VethConfig, VlanConfig, VlanInterface, VlanProtocol,
        VlanQosMapping, VlanRegistrationProtocol, VrfConfig, VrfInterface,
        VxlanConfig, VxlanInterface, WifiAuthType, WifiAuthTypeDetailed,
        WifiCfgInterface, WifiConfig, WifiPhyInterface, WifiScanResult,
        WifiState, WireguardConfig, WireguardInterface, WireguardIpAddress,
        WireguardPeerConfig,
    },
    ip::{DhcpState, InterfaceIpAddr, InterfaceIpv4, InterfaceIpv6},
    link_event::InterfaceLinkEvent,
    link_state::InterfaceLinkState,
    merged::{
        MergedInterface, MergedInterfaces, MergedNetworkState,
        MergedRouteRules, MergedRoutes,
    },
    net_state::NetworkState,
    route::{RouteEntry, RouteState, RouteType, Routes},
    route_rule::{
        AddressFamily, RouteRuleAction, RouteRuleEntry, RouteRuleState,
        RouteRules,
    },
    state_options::{
        NipartApplyOption, NipartQueryOption, NipartWifiControl,
        NipartWifiScanOption,
    },
    version::CUR_SCHEMA_VERSION,
    wait_online::{NipartWaitOnline, NipartWaitOnlineCondition},
};

#[cfg(test)]
mod unit_tests;
