// SPDX-License-Identifier: Apache-2.0

use crate::{
    BaseInterface, InterfaceIpv4, InterfaceIpv6, RouteEntry, RouteRules,
    no_daemon,
};

pub(super) fn nispor_iface_from_json(json: &str) -> nispor::Iface {
    serde_json::from_str(json).expect("Invalid nispor Iface fixture")
}

pub(super) fn nispor_route_from_json(json: &str) -> nispor::Route {
    serde_json::from_str(json).expect("Invalid nispor Route fixture")
}

pub(super) fn nispor_route_rule_from_json(json: &str) -> nispor::RouteRule {
    serde_json::from_str(json).expect("Invalid nispor RouteRule fixture")
}

pub(super) fn base_iface_from_nispor_json(json: &str) -> BaseInterface {
    no_daemon::np_iface_to_base_iface(&nispor_iface_from_json(json))
}

pub(super) fn ipv4_from_nispor_json(json: &str) -> Option<InterfaceIpv4> {
    no_daemon::np_ipv4_to_nipart(&nispor_iface_from_json(json))
}

pub(super) fn ipv6_from_nispor_json(json: &str) -> Option<InterfaceIpv6> {
    no_daemon::np_ipv6_to_nipart(&nispor_iface_from_json(json))
}

pub(super) fn route_entry_from_nispor_json(json: &str) -> RouteEntry {
    no_daemon::np_route_to_nipart(&nispor_route_from_json(json))
}

pub(super) fn route_entry_for_type_from_nispor_json(json: &str) -> RouteEntry {
    no_daemon::np_routetype_to_nipart(&nispor_route_from_json(json))
}

pub(super) fn route_rules_from_nispor_json(json: &str) -> RouteRules {
    no_daemon::get_route_rules(&[nispor_route_rule_from_json(json)])
}

pub(super) fn route_rules_from_nispor_json_array(json: &str) -> RouteRules {
    let rules: Vec<nispor::RouteRule> =
        serde_json::from_str(json).expect("Invalid nispor RouteRule fixtures");
    no_daemon::get_route_rules(&rules)
}

#[cfg(test)]
mod tests {
    use super::{
        base_iface_from_nispor_json, route_entry_from_nispor_json,
        route_rules_from_nispor_json,
    };
    use crate::{
        InterfaceIpv4, InterfaceIpv6, InterfaceLinkState, InterfaceState,
        InterfaceType, RouteType,
    };

    const MINIMAL_IFACE: &str = r#"{
        "name": "dummy0",
        "index": 3,
        "type": "dummy",
        "state": "up",
        "mtu": 1500,
        "flags": ["up", "running"],
        "alt-names": [],
        "mac-address": "02:00:00:00:00:01",
        "permanent-mac-address": ""
    }"#;

    const MINIMAL_ROUTE: &str = r#"{
        "address-family": "ipv4",
        "tos": 0,
        "table": 254,
        "protocol": "static",
        "scope": "universe",
        "route-type": "unicast",
        "flags": [],
        "dst": "192.0.2.0/24",
        "oif": "dummy0"
    }"#;

    const MINIMAL_RULE: &str = r#"{
        "action": "table",
        "address-family": "ipv4",
        "flags": [],
        "tos": 0,
        "table": 100,
        "src": "192.0.2.0/24",
        "priority": 1000
    }"#;

    #[test]
    fn test_parity_harness_iface_fixture() {
        let iface = base_iface_from_nispor_json(MINIMAL_IFACE);
        assert_eq!(iface.name, "dummy0");
        assert_eq!(iface.kernel_iface_name, "dummy0");
        assert_eq!(iface.iface_index, Some(3));
        assert_eq!(iface.iface_type, InterfaceType::Dummy);
        assert_eq!(iface.state, InterfaceState::Up);
        assert_eq!(iface.link_state, Some(InterfaceLinkState::Up));
        assert_eq!(iface.mtu, Some(1500));
        assert_eq!(iface.mac_address.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(iface.ipv4, Some(InterfaceIpv4::default()));
        assert_eq!(iface.ipv6, Some(InterfaceIpv6::default()));
    }

    #[test]
    fn test_parity_harness_route_fixture() {
        let route = route_entry_from_nispor_json(MINIMAL_ROUTE);
        assert_eq!(route.destination.as_deref(), Some("192.0.2.0/24"));
        assert_eq!(route.next_hop_iface.as_deref(), Some("dummy0"));
        assert_eq!(route.next_hop_addr.as_deref(), Some("0.0.0.0"));
        assert_eq!(route.table_id, Some(254));
        assert_eq!(route.route_type, None);
    }

    #[test]
    fn test_parity_harness_route_type_fixture() {
        let route = super::route_entry_for_type_from_nispor_json(
            r#"{
                "address-family": "ipv6",
                "tos": 0,
                "table": 254,
                "protocol": "boot",
                "scope": "universe",
                "route-type": "black-hole",
                "flags": [],
                "dst": "2001:db8::/32"
            }"#,
        );
        assert_eq!(route.destination.as_deref(), Some("2001:db8::/32"));
        assert_eq!(route.route_type, Some(RouteType::Blackhole));
    }

    #[test]
    fn test_parity_harness_rule_fixture() {
        let rules = route_rules_from_nispor_json(MINIMAL_RULE);
        let rules = rules.config.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip_from.as_deref(), Some("192.0.2.0/24"));
        assert_eq!(rules[0].table_id, Some(100));
        assert_eq!(rules[0].priority, Some(1000));
    }
}
