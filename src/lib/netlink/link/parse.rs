// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use rtnetlink::packet_route::link::{
    InfoData, InfoKind, InfoPortData, InfoPortKind, LinkAttribute, LinkFlags,
    LinkInfo, LinkLayerType, LinkMessage, Prop, State,
};

use super::{
    LinkIndexMap,
    bond::parse_bond,
    bridge::{self, BridgeVlanEntry, parse_bridge},
    macsec::parse_macsec,
    vlan::parse_vlan,
    vrf::parse_vrf,
    vxlan::parse_vxlan,
};
use crate::{
    BaseInterface, BondConfig, BondPortConfig, EthernetConfig,
    InterfaceLinkState, InterfaceState, InterfaceType, LinuxBridgeConfig,
    LinuxBridgePortConfig, MacSecConfig, VethConfig, VlanConfig, VrfConfig,
    VxlanConfig, WifiConfig, WireguardConfig,
    netlink::{mac::format_mac_address, sysfs},
};

#[derive(Debug, Default, Clone)]
pub(crate) struct LinkIface {
    pub(crate) base: BaseInterface,
    pub(crate) veth: Option<VethConfig>,
    pub(crate) vlan: Option<VlanConfig>,
    pub(crate) vrf: Option<VrfConfig>,
    pub(crate) vxlan: Option<VxlanConfig>,
    pub(crate) bond: Option<BondConfig>,
    pub(crate) bond_port: Option<BondPortConfig>,
    pub(crate) bridge: Option<LinuxBridgeConfig>,
    pub(crate) bridge_port: Option<LinuxBridgePortConfig>,
    pub(crate) ethernet: Option<EthernetConfig>,
    pub(crate) wireguard: Option<WireguardConfig>,
    pub(crate) macsec: Option<MacSecConfig>,
    pub(crate) wifi: Option<WifiConfig>,
    pub(crate) is_wifi: bool,
    pub(crate) bond_port_perm_mac: Option<String>,
    pub(crate) bond_primary_index: Option<u32>,
    pub(crate) controller_type: Option<InfoPortKind>,
    pub(crate) veth_peer_index: Option<u32>,
    pub(crate) vlan_base_index: Option<u32>,
    pub(crate) vxlan_base_index: Option<u32>,
    pub(crate) macsec_base_index: Option<u32>,
    pub(crate) link_netnsid: Option<i32>,
    pub(crate) bridge_filtering: Option<bool>,
    pub(crate) bridge_default_pvid: Option<u16>,
    pub(crate) bridge_vlans: Option<Vec<BridgeVlanEntry>>,
    pub(crate) bridge_port_vlans: Option<Vec<BridgeVlanEntry>>,
}

#[derive(Debug, Default)]
pub(crate) struct ParsedLinkInfo {
    kind: Option<InfoKind>,
    data: Option<InfoData>,
    port_kind: Option<InfoPortKind>,
    port_data: Option<InfoPortData>,
}

pub(crate) fn parsed_link_info(attributes: &[LinkAttribute]) -> ParsedLinkInfo {
    let mut ret = ParsedLinkInfo::default();
    for attribute in attributes {
        let LinkAttribute::LinkInfo(infos) = attribute else {
            continue;
        };
        for info in infos {
            match info {
                LinkInfo::Kind(kind) => ret.kind = Some(kind.clone()),
                LinkInfo::Data(data) => ret.data = Some(data.clone()),
                LinkInfo::PortKind(kind) => ret.port_kind = Some(kind.clone()),
                LinkInfo::PortData(data) => ret.port_data = Some(data.clone()),
                _ => (),
            }
        }
    }
    ret
}

pub(crate) fn parse_link(
    message: &LinkMessage,
    index_map: &LinkIndexMap,
) -> Option<LinkIface> {
    let name = link_name(message)?;
    let link_info = parsed_link_info(&message.attributes);
    let iface_type = link_iface_type(message, link_info.kind.as_ref());
    let mut af_spec_bridge = Vec::new();
    let mut ret = LinkIface::default();
    ret.base.name = name.clone();
    ret.base.kernel_iface_name = name.clone();
    ret.base.iface_index = Some(message.header.index);
    ret.base.iface_type = iface_type.clone();
    ret.base.mac_address = Some(String::new());
    ret.controller_type = link_info.port_kind.clone();

    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::IfName(name) => ret.base.name = name.to_string(),
            LinkAttribute::Mtu(mtu) => ret.base.mtu = Some(*mtu as u64),
            LinkAttribute::MinMtu(mtu) => {
                if *mtu != 0 {
                    ret.base.min_mtu = Some(*mtu as u64);
                }
            }
            LinkAttribute::MaxMtu(mtu) => {
                if *mtu != 0 {
                    ret.base.max_mtu = Some(*mtu as u64);
                }
            }
            LinkAttribute::Address(mac) => {
                ret.base.mac_address =
                    Some(format_mac_address(mac).unwrap_or_default());
            }
            LinkAttribute::PermAddress(mac) => {
                if let Some(mac) = format_mac_address(mac) {
                    ret.base.permanent_mac_address = Some(mac);
                }
            }
            LinkAttribute::OperState(state) => {
                ret.base.link_state = Some(link_state_from_nl80211(*state));
                ret.base.state =
                    state_from_nl80211(*state, message.header.flags);
            }
            LinkAttribute::Controller(index) => {
                ret.base.controller = Some(
                    index_map
                        .name(*index)
                        .map(str::to_string)
                        .unwrap_or_else(|| index.to_string()),
                );
            }
            LinkAttribute::PropList(props) => {
                let mut alt_names: Vec<crate::AltNameEntry> = props
                    .iter()
                    .filter_map(|prop| {
                        if let Prop::AltIfName(name) = prop {
                            Some(crate::AltNameEntry {
                                name: name.to_string(),
                                state: None,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
                alt_names.sort_unstable();
                if !alt_names.is_empty() {
                    ret.base.alt_names = Some(alt_names);
                }
            }
            LinkAttribute::ParentDevName(dev_name) => {
                if message.attributes.iter().any(|attribute| {
                    matches!(
                        attribute,
                        LinkAttribute::ParentDevBusName(bus_name)
                            if bus_name == "pci"
                    )
                }) {
                    ret.base.pci_address = sysfs::format_pci_address(dev_name);
                }
            }
            LinkAttribute::Link(index) => match iface_type {
                InterfaceType::Veth => ret.veth_peer_index = Some(*index),
                InterfaceType::Vlan => ret.vlan_base_index = Some(*index),
                InterfaceType::Vxlan => ret.vxlan_base_index = Some(*index),
                InterfaceType::MacSec => ret.macsec_base_index = Some(*index),
                _ => (),
            },
            LinkAttribute::LinkNetNsId(id) => ret.link_netnsid = Some(*id),
            LinkAttribute::AfSpecBridge(nlas) => {
                af_spec_bridge.extend(nlas.iter().cloned());
            }
            _ => (),
        }
    }

    if ret.base.state != InterfaceState::Ignore {
        ret.base.state =
            state_from_nl80211(oper_state(message), message.header.flags);
    }
    ret.base.link_state = Some(link_state_from_nl80211(oper_state(message)));

    if ret.base.driver.is_none() {
        ret.base.driver = sysfs::iface_driver(name.as_str());
    }
    if ret.base.pci_address.is_none() {
        ret.base.pci_address = sysfs::iface_pci_address(name.as_str());
    }
    if ret.base.mtu.is_none() {
        ret.base.mtu = Some(0);
    }

    if let Some(port_data) = link_info.port_data.as_ref() {
        match port_data {
            InfoPortData::BondPort(nlas) => {
                let port = super::bond::parse_bond_port(nlas);
                ret.bond_port = Some(port.config);
                ret.bond_port_perm_mac = port.permanent_mac;
            }
            InfoPortData::BridgePort(nlas) => {
                ret.bridge_port = Some(super::bridge::parse_bridge_port(nlas));
            }
            _ => (),
        }
    }

    if ret.base.permanent_mac_address.is_none() {
        ret.base.permanent_mac_address = ret.bond_port_perm_mac.clone();
    }

    if !af_spec_bridge.is_empty() {
        let vlans = bridge::parse_af_spec_bridge(&af_spec_bridge);
        if ret.bridge_port.is_some() {
            ret.bridge_port_vlans = vlans;
        } else if ret.base.iface_type == InterfaceType::LinuxBridge {
            ret.bridge_vlans = vlans;
        }
    }

    if let Some(data) = link_info.data.as_ref() {
        match ret.base.iface_type {
            InterfaceType::Vlan => {
                ret.vlan = parse_vlan(data);
            }
            InterfaceType::Vrf => {
                ret.vrf = parse_vrf(data);
            }
            InterfaceType::Vxlan => {
                ret.vxlan = parse_vxlan(data);
            }
            InterfaceType::MacSec => {
                ret.macsec = parse_macsec(data);
            }
            InterfaceType::Bond => {
                if let Some((config, primary_index)) = parse_bond(data) {
                    ret.bond = Some(config);
                    ret.bond_primary_index = primary_index;
                }
            }
            InterfaceType::LinuxBridge => {
                if let Some((config, filtering, default_pvid)) =
                    parse_bridge(data)
                {
                    ret.bridge = Some(config);
                    ret.bridge_filtering = filtering;
                    ret.bridge_default_pvid = default_pvid;
                }
            }
            _ => (),
        }
    }

    if ret.base.iface_type == InterfaceType::Veth
        && ret.veth.is_none()
        && let Some(peer_index) = ret.veth_peer_index.or({
            // The kernel does not fill IFLA_INFO_DATA for veth dumps, but
            // keep the peer from a create/echo message as fallback.
            if let Some(InfoData::Veth(
                rtnetlink::packet_route::link::InfoVeth::Peer(peer),
            )) = link_info.data.as_ref()
            {
                Some(peer.header.index)
            } else {
                None
            }
        })
    {
        ret.veth_peer_index = Some(peer_index);
    }

    if !ret.base.iface_type.is_supported() {
        log::trace!(
            "Got unsupported interface type {}: {}, ignoring",
            ret.base.iface_type,
            ret.base.name
        );
        ret.base.state = InterfaceState::Ignore;
    }
    Some(ret)
}

pub(crate) fn link_name(message: &LinkMessage) -> Option<String> {
    message
        .attributes
        .iter()
        .find_map(|attribute| {
            if let LinkAttribute::IfName(name) = attribute {
                Some(name.to_string())
            } else {
                None
            }
        })
        .filter(|name| !name.is_empty())
}

fn link_iface_type(
    message: &LinkMessage,
    kind: Option<&InfoKind>,
) -> InterfaceType {
    let mut iface_type = match message.header.link_layer_type {
        LinkLayerType::Ether => InterfaceType::Ethernet,
        LinkLayerType::Loopback => InterfaceType::Loopback,
        LinkLayerType::Infiniband => InterfaceType::InfiniBand,
        link_layer_type => {
            InterfaceType::Unknown(link_layer_type.to_string().to_lowercase())
        }
    };
    if let Some(kind) = kind {
        let kind_type = iface_type_from_kind(kind);
        if iface_type == InterfaceType::Loopback
            || (iface_type == InterfaceType::InfiniBand
                && kind_type.is_unknown())
        {
            return iface_type;
        }
        iface_type = kind_type;
    }
    iface_type
}

fn iface_type_from_kind(kind: &InfoKind) -> InterfaceType {
    match kind {
        InfoKind::Bond => InterfaceType::Bond,
        InfoKind::Bridge => InterfaceType::LinuxBridge,
        InfoKind::Dummy => InterfaceType::Dummy,
        InfoKind::Hsr => InterfaceType::Hsr,
        InfoKind::IpVlan => InterfaceType::IpVlan,
        InfoKind::Ipoib => InterfaceType::InfiniBand,
        InfoKind::MacSec => InterfaceType::MacSec,
        InfoKind::MacVlan => InterfaceType::MacVlan,
        InfoKind::MacVtap => InterfaceType::MacVtap,
        InfoKind::Tun => InterfaceType::Tun,
        InfoKind::Veth => InterfaceType::Veth,
        InfoKind::Vlan => InterfaceType::Vlan,
        InfoKind::Vrf => InterfaceType::Vrf,
        InfoKind::Vxlan => InterfaceType::Vxlan,
        InfoKind::Wireguard => InterfaceType::Wireguard,
        InfoKind::Xfrm => InterfaceType::Xfrm,
        InfoKind::Vti | InfoKind::Vti6 => {
            InterfaceType::Unknown("vti".to_string())
        }
        InfoKind::Other(kind) if kind == "openvswitch" => {
            InterfaceType::OvsInterface
        }
        InfoKind::Other(kind) => InterfaceType::Unknown(kind.to_lowercase()),
        kind => InterfaceType::Unknown(format!("{kind:?}").to_lowercase()),
    }
}

fn oper_state(message: &LinkMessage) -> State {
    message
        .attributes
        .iter()
        .find_map(|attribute| {
            if let LinkAttribute::OperState(state) = attribute {
                Some(*state)
            } else {
                None
            }
        })
        .unwrap_or(State::Unknown)
}

pub(crate) fn state_from_nl80211(
    state: State,
    flags: LinkFlags,
) -> InterfaceState {
    // An operationally up link reports `State::Up`. A link with the
    // Running flag is also considered operationally up, and `state: up` in
    // nipart also means administratively up.
    // https://www.kernel.org/doc/Documentation/networking/operstates.txt
    if state == State::Up
        || flags.contains(LinkFlags::Running)
        || flags.contains(LinkFlags::Up)
    {
        InterfaceState::Up
    } else if state == State::Down {
        InterfaceState::Down
    } else {
        InterfaceState::Unknown
    }
}

pub(crate) fn link_state_from_nl80211(state: State) -> InterfaceLinkState {
    match state {
        State::Up => InterfaceLinkState::Up,
        State::Dormant => InterfaceLinkState::Dormant,
        State::Down => InterfaceLinkState::Down,
        State::LowerLayerDown => InterfaceLinkState::LowerLayerDown,
        State::Testing => InterfaceLinkState::Testing,
        _ => InterfaceLinkState::Unknown,
    }
}
