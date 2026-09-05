// SPDX-License-Identifier: Apache-2.0

mod base_iface;
mod controller;
mod ethernet;
mod iface;
mod inter_iface;
mod ip;
mod net_state;
mod route;
mod route_rule;
mod wifi;

pub use self::{
    iface::MergedInterface, inter_iface::MergedInterfaces,
    net_state::MergedNetworkState, route::MergedRoutes,
    route_rule::MergedRouteRules,
};
