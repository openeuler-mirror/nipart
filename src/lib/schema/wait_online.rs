// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{
    InterfaceLinkState, JsonDisplay, NetworkState, NipartInterface, RouteEntry,
};

const GATEWAY4: &str = "0.0.0.0/0";
const GATEWAY6: &str = "::/0";

/// Daemon wait online configuration
///
/// Configuration instructing when daemon should consider the network is
/// online on boot.
/// Once daemon reaches online state, it stop tracking whether online
/// conditions still met. This is purely designed for systemd
/// network-online.target.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonDisplay)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct NipartWaitOnline {
    /// Maximum wait time in seconds to wait network state to be online.
    /// Default is 30 seconds. Setting to 0 means mark as online once daemon
    /// starts.
    #[serde(default = "default_tmo")]
    pub timeout_sec: u32,
    /// The network is considered as online when all of these conditions met.
    /// If undefined, defaults to [NipartWaitOnlineCondition::Gateway], i.e.
    /// wait for an IPv4 or IPv6 default gateway to appear in the running
    /// network state on an interface whose link is usable.
    /// If set to empty list explicitly, daemon will mark online once started.
    #[serde(default = "default_conditions")]
    pub conditions: Vec<NipartWaitOnlineCondition>,
}

fn default_tmo() -> u32 {
    NipartWaitOnline::DEFAULT_TIMEOUT_SEC
}

fn default_conditions() -> Vec<NipartWaitOnlineCondition> {
    vec![NipartWaitOnlineCondition::default()]
}

impl NipartWaitOnline {
    pub const DEFAULT_TIMEOUT_SEC: u32 = 30;
}

impl Default for NipartWaitOnline {
    fn default() -> Self {
        Self {
            timeout_sec: default_tmo(),
            conditions: default_conditions(),
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize, JsonDisplay,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NipartWaitOnlineCondition {
    /// IPv4 or IPv6 default gateway present on an interface whose link is
    /// usable.
    #[default]
    Gateway,
    /// IPv4 default gateway present on an interface whose link is usable.
    /// (TODO: reachable via ARP?)
    Gateway4,
    /// IPv6 default gateway present on an interface whose link is usable.
    /// (TODO: reachable via Neighbor Discovery?)
    Gateway6,
}

impl NipartWaitOnlineCondition {
    pub fn is_met(&self, cur_state: &NetworkState) -> bool {
        let Some(routes) = cur_state.routes.running.as_ref() else {
            return false;
        };
        routes.iter().any(|rt| {
            self.route_matches(rt) && route_iface_link_usable(cur_state, rt)
        })
    }

    fn route_matches(&self, rt: &RouteEntry) -> bool {
        match self {
            Self::Gateway => matches!(
                rt.destination.as_deref(),
                Some(GATEWAY4) | Some(GATEWAY6)
            ),
            Self::Gateway4 => rt.destination.as_deref() == Some(GATEWAY4),
            Self::Gateway6 => rt.destination.as_deref() == Some(GATEWAY6),
        }
    }
}

/// Whether the interface a default gateway egresses through is usable.
///
/// A default route can outlive its link: the kernel keeps a static default
/// route when the interface (e.g. wifi) disconnects, so matching only the
/// route table would report the network online before the link is usable.
///
/// A link is usable when its `link-state` is `up` (physical link with
/// carrier) or `unknown` (a carrier-less virtual link such as a tunnel,
/// wireguard or dummy interface that is administratively up). A default
/// route without a resolved next-hop interface (e.g. a blackhole route) is
/// not usable either.
fn route_iface_link_usable(cur_state: &NetworkState, rt: &RouteEntry) -> bool {
    rt.next_hop_iface
        .as_deref()
        .and_then(|name| cur_state.ifaces.kernel_ifaces.get(name))
        .map(|iface| {
            matches!(
                iface.base_iface().link_state,
                Some(InterfaceLinkState::Up)
                    | Some(InterfaceLinkState::Unknown)
            )
        })
        .unwrap_or(false)
}
