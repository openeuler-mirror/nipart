// SPDX-License-Identifier: Apache-2.0

// This file is based on the work of nispor project
// (https://github.com/nispor/nispor) and nmstate project
// (https://nmstate.io/) which are under license of Apache 2.0.

use std::net::IpAddr;

use futures_util::TryStreamExt;
use rtnetlink::{
    IpVersion,
    packet_route::{
        AddressFamily,
        route::{RouteHeader, RouteProtocol as NetlinkRouteProtocol},
        rule::{RuleAction, RuleAttribute, RuleMessage},
    },
};

use crate::{
    AddressFamily as NipartAddressFamily, ErrorKind, NipartError,
    RouteRuleAction, RouteRuleEntry, RouteRules,
    netlink::{map_rtnetlink_error, new_connection},
};

// The kernel adds `ip rule` entries with protocol boot by default, while
// NetworkManager used protocol unspec historically.  Include both plus the
// static protocol when presenting rules as manageable configuration.
const SUPPORTED_STATIC_ROUTE_RULE_PROTOCOL: [NetlinkRouteProtocol; 3] = [
    NetlinkRouteProtocol::Boot,
    NetlinkRouteProtocol::Static,
    NetlinkRouteProtocol::Unspec,
];

