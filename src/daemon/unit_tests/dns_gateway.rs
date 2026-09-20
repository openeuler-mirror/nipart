// SPDX-License-Identifier: Apache-2.0

use nipart::{RouteEntry, RouteState, RouteType};

use crate::dns_gateway::default_gateway_fingerprint;

const IFACE: &str = "test0";
const IPV4_DEFAULT: &str = "0.0.0.0/0";
const IPV6_DEFAULT: &str = "::/0";

fn default_route(gateway: &str, metric: Option<i64>) -> RouteEntry {
    // `RouteEntry` is non-exhaustive, so it is built field by field.
    let mut ret = RouteEntry::default();
    ret.destination = Some(IPV4_DEFAULT.to_string());
    ret.next_hop_iface = Some(IFACE.to_string());
    ret.next_hop_addr = Some(gateway.to_string());
    ret.metric = metric;
    ret
}

fn fingerprint(routes: &[RouteEntry]) -> Vec<String> {
    default_gateway_fingerprint(routes.iter())
}

#[test]
fn test_replaced_default_gateway_is_detected() {
    let before = [default_route("192.0.2.1", None)];
    let after = [default_route("192.0.2.254", None)];
    assert_ne!(fingerprint(&before), fingerprint(&after));
}

#[test]
fn test_added_and_removed_default_gateway_are_detected() {
    let none: [RouteEntry; 0] = [];
    let one = [default_route("192.0.2.1", None)];
    let two = [
        default_route("192.0.2.1", None),
        default_route("192.0.2.254", None),
    ];
    assert_ne!(fingerprint(&none), fingerprint(&one));
    assert_ne!(fingerprint(&one), fingerprint(&two));
}

#[test]
fn test_metric_and_table_change_of_default_route_is_detected() {
    let before = [default_route("192.0.2.1", Some(100))];
    let after = [default_route("192.0.2.1", Some(200))];
    assert_ne!(fingerprint(&before), fingerprint(&after));

    let before = [default_route("192.0.2.1", None)];
    let mut after = [default_route("192.0.2.1", None)];
    after[0].table_id = Some(1000);
    assert_ne!(fingerprint(&before), fingerprint(&after));
}

#[test]
fn test_non_default_route_change_is_ignored() {
    let mut before = [default_route("192.0.2.1", None)];
    before[0].destination = Some("198.51.100.0/24".to_string());
    let mut after = [default_route("192.0.2.1", None)];
    after[0].destination = Some("203.0.113.0/24".to_string());
    assert_eq!(fingerprint(&before), fingerprint(&after));
    assert!(fingerprint(&before).is_empty());
}

#[test]
fn test_ipv6_default_route_is_included() {
    let mut route = default_route("2001:db8:1::1", None);
    route.destination = Some(IPV6_DEFAULT.to_string());
    assert_eq!(fingerprint(&[route]).len(), 1);
}

#[test]
fn test_absent_default_route_is_ignored() {
    let mut route = default_route("192.0.2.1", None);
    route.state = Some(RouteState::Absent);
    assert!(fingerprint(&[route]).is_empty());
}

#[test]
fn test_non_unicast_default_route_is_ignored() {
    for route_type in [
        RouteType::Blackhole,
        RouteType::Unreachable,
        RouteType::Prohibit,
    ] {
        let mut route = default_route("192.0.2.1", None);
        route.route_type = Some(route_type);
        assert!(
            fingerprint(&[route]).is_empty(),
            "{route_type:?} default route must be ignored"
        );
    }
}

#[test]
fn test_fingerprint_is_order_independent_and_deduplicated() {
    let first = default_route("192.0.2.1", None);
    let second = default_route("192.0.2.254", None);
    assert_eq!(
        fingerprint(&[first.clone(), second.clone()]),
        fingerprint(&[second, first.clone()])
    );
    assert_eq!(fingerprint(&[first.clone(), first]).len(), 1);
}
