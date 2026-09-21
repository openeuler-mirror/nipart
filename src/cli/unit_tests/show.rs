// SPDX-License-Identifier: Apache-2.0

use nipart::{
    BaseInterface, EthernetInterface, Interface, InterfaceType, Interfaces,
};

use super::*;

fn new_show_matches(args: &[&str]) -> clap::ArgMatches {
    CommandShow::new_cmd().try_get_matches_from(args).unwrap()
}

fn new_route(destination: &str, next_hop_iface: &str) -> RouteEntry {
    let mut rt = RouteEntry::default();
    rt.destination = Some(destination.to_string());
    rt.next_hop_iface = Some(next_hop_iface.to_string());
    rt
}

fn new_iface(name: &str) -> Interface {
    Interface::Ethernet(Box::new(EthernetInterface::new(
        BaseInterface::new(name.to_string(), InterfaceType::Ethernet),
        None,
    )))
}

fn new_iface_with_profile(name: &str, profile_name: &str) -> Interface {
    let mut iface = new_iface(name);
    iface.base_iface_mut().profile_name = Some(profile_name.to_string());
    iface
}

fn net_state_with_two_ifaces_and_routes() -> NetworkState {
    let mut net_state = NetworkState::new();
    net_state.ifaces =
        Interfaces::new(vec![new_iface("mynet"), new_iface("eth1")]);
    net_state.routes.running = Some(vec![
        new_route("0.0.0.0/0", "mynet"),
        new_route("192.0.2.0/24", "eth1"),
        new_route("198.51.100.0/24", "mynet"),
    ]);
    net_state.routes.config = Some(vec![
        new_route("10.0.0.0/8", "mynet"),
        new_route("172.16.0.0/12", "eth1"),
    ]);
    net_state
}

#[test]
fn test_filter_net_state_keeps_iface_and_its_routes() {
    let net_state = net_state_with_two_ifaces_and_routes();
    let filtered = filter_net_state(&net_state, "mynet");

    assert_eq!(filtered.ifaces.iter().count(), 1);
    assert_eq!(
        filtered.ifaces.iter().next().unwrap().kernel_iface_name(),
        "mynet"
    );

    let running = filtered.routes.running.unwrap();
    assert_eq!(running.len(), 2);
    assert!(
        running
            .iter()
            .all(|rt| rt.next_hop_iface.as_deref() == Some("mynet"))
    );

    let config = filtered.routes.config.unwrap();
    assert_eq!(config.len(), 1);
    assert_eq!(config[0].destination.as_deref(), Some("10.0.0.0/8"));
}

#[test]
fn test_filter_net_state_no_routes_yields_none() {
    let mut net_state = NetworkState::new();
    net_state.ifaces = Interfaces::new(vec![new_iface("mynet")]);
    net_state.routes.config = Some(vec![new_route("0.0.0.0/0", "eth1")]);

    let filtered = filter_net_state(&net_state, "mynet");

    assert_eq!(filtered.ifaces.iter().count(), 1);
    assert!(filtered.routes.running.is_none());
    assert!(filtered.routes.config.is_none());
}

#[test]
fn test_filter_net_state_by_profile_name() {
    let mut net_state = NetworkState::new();
    net_state.ifaces =
        Interfaces::new(vec![new_iface_with_profile("eth0", "mynet")]);
    net_state.routes.running = Some(vec![
        new_route("0.0.0.0/0", "eth0"),
        new_route("192.0.2.0/24", "eth1"),
    ]);
    net_state.routes.config = Some(vec![new_route("10.0.0.0/8", "mynet")]);

    let filtered = filter_net_state(&net_state, "mynet");

    assert_eq!(filtered.ifaces.iter().count(), 1);
    assert_eq!(filtered.ifaces.iter().next().unwrap().name(), "eth0");

    let running = filtered.routes.running.unwrap();
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].next_hop_iface.as_deref(), Some("eth0"));

    let config = filtered.routes.config.unwrap();
    assert_eq!(config.len(), 1);
    assert_eq!(config[0].next_hop_iface.as_deref(), Some("mynet"));
}

#[test]
fn test_filter_routes_empty_input() {
    assert!(filter_routes(None, "mynet", &[]).is_none());
    assert!(filter_routes(Some(&[]), "mynet", &[]).is_none());
}

#[test]
fn test_show_selection_keywords() {
    let matches = new_show_matches(&["show", "dns"]);
    assert_eq!(
        ShowSelection::from_matches(&matches),
        ShowSelection::Section(ShowSection::Dns)
    );

    let matches = new_show_matches(&["show", "route"]);
    assert_eq!(
        ShowSelection::from_matches(&matches),
        ShowSelection::Section(ShowSection::Route)
    );
}

#[test]
fn test_show_selection_iface() {
    let matches = new_show_matches(&["show", "eth1"]);
    assert_eq!(
        ShowSelection::from_matches(&matches),
        ShowSelection::Iface("eth1".to_string())
    );

    let matches = new_show_matches(&["show", "--iface", "route"]);
    assert_eq!(
        ShowSelection::from_matches(&matches),
        ShowSelection::Iface("route".to_string())
    );

    let matches = new_show_matches(&["show"]);
    assert_eq!(ShowSelection::from_matches(&matches), ShowSelection::All);
}

#[test]
fn test_iface_option_conflicts_with_positional_name() {
    assert!(
        CommandShow::new_cmd()
            .try_get_matches_from(["show", "dns", "--iface", "dns"])
            .is_err()
    );
}

#[test]
fn test_section_to_yaml_dns_only() {
    let net_state = net_state_with_two_ifaces_and_routes();
    let yaml = section_to_yaml(&net_state, ShowSection::Dns).unwrap();
    let value: rmsd_yaml::Value = rmsd_yaml::from_str(&yaml).unwrap();
    let map = value.as_mapping().unwrap();

    assert!(map.contains_key(&rmsd_yaml::Value::from("dns-resolver")));
    assert!(!map.contains_key(&rmsd_yaml::Value::from("routes")));
    assert!(!map.contains_key(&rmsd_yaml::Value::from("interfaces")));
    assert!(!map.contains_key(&rmsd_yaml::Value::from("version")));
}

#[test]
fn test_section_to_yaml_route_only() {
    let net_state = net_state_with_two_ifaces_and_routes();
    let yaml = section_to_yaml(&net_state, ShowSection::Route).unwrap();
    let value: rmsd_yaml::Value = rmsd_yaml::from_str(&yaml).unwrap();
    let map = value.as_mapping().unwrap();

    assert!(map.contains_key(&rmsd_yaml::Value::from("routes")));
    assert!(!map.contains_key(&rmsd_yaml::Value::from("dns-resolver")));
    assert!(!map.contains_key(&rmsd_yaml::Value::from("interfaces")));
    assert!(!map.contains_key(&rmsd_yaml::Value::from("version")));
}
