// SPDX-License-Identifier: Apache-2.0

use super::parity::base_iface_from_nispor_json;
use crate::{
    AltNameEntry, BaseInterface, InterfaceIpv4, InterfaceIpv6,
    InterfaceLinkState, InterfaceState, InterfaceType,
};

struct BaseLinkFixture {
    name: &'static str,
    nispor_json: &'static str,
    expected: BaseInterface,
}

fn expected_base_iface(
    name: &str,
    iface_type: InterfaceType,
    state: InterfaceState,
    link_state: InterfaceLinkState,
    mtu: u64,
) -> BaseInterface {
    BaseInterface {
        name: name.to_string(),
        kernel_iface_name: name.to_string(),
        state,
        link_state: Some(link_state),
        iface_type,
        mtu: Some(mtu),
        ipv4: Some(InterfaceIpv4::default()),
        ipv6: Some(InterfaceIpv6::default()),
        ..Default::default()
    }
}

fn base_link_fixtures() -> Vec<BaseLinkFixture> {
    let mut ethernet = expected_base_iface(
        "eth1",
        InterfaceType::Ethernet,
        InterfaceState::Up,
        InterfaceLinkState::Up,
        9000,
    );
    ethernet.iface_index = Some(2);
    ethernet.min_mtu = Some(68);
    ethernet.max_mtu = Some(9216);
    ethernet.mac_address = Some("02:00:00:00:01:AA".to_string());
    ethernet.permanent_mac_address = Some("02:00:00:00:01:BB".to_string());
    ethernet.controller = Some("br0".to_string());
    ethernet.pci_address = Some("0000:02:00.0".to_string());
    ethernet.driver = Some("e1000e".to_string());
    ethernet.alt_names = Some(vec![
        AltNameEntry {
            name: "aa-alt".to_string(),
            state: None,
        },
        AltNameEntry {
            name: "zz-alt".to_string(),
            state: None,
        },
    ]);

    let mut loopback = expected_base_iface(
        "lo",
        InterfaceType::Loopback,
        InterfaceState::Unknown,
        InterfaceLinkState::Unknown,
        65536,
    );
    loopback.iface_index = Some(1);
    loopback.mac_address = Some("00:00:00:00:00:00".to_string());

    let mut dummy = expected_base_iface(
        "dummy0",
        InterfaceType::Dummy,
        InterfaceState::Down,
        InterfaceLinkState::Down,
        1500,
    );
    dummy.iface_index = Some(3);
    dummy.mac_address = Some("02:00:00:00:00:01".to_string());

    let mut tun = expected_base_iface(
        "tun0",
        InterfaceType::Tun,
        InterfaceState::Ignore,
        InterfaceLinkState::Up,
        1500,
    );
    tun.iface_index = Some(4);
    tun.mac_address = Some("02:00:00:00:00:02".to_string());

    vec![
        BaseLinkFixture {
            name: "ethernet",
            nispor_json: r#"{
                "name": "eth1",
                "index": 2,
                "type": "ethernet",
                "state": "up",
                "mtu": 9000,
                "min-mtu": 68,
                "max-mtu": 9216,
                "flags": ["up", "lower-up", "running"],
                "alt-names": ["zz-alt", "aa-alt"],
                "mac-address": "02:00:00:00:01:aa",
                "permanent-mac-address": "02:00:00:00:01:bb",
                "controller": "br0",
                "pci-address": "0000:02:00.0",
                "driver": "e1000e"
            }"#,
            expected: ethernet,
        },
        BaseLinkFixture {
            name: "loopback",
            nispor_json: r#"{
                "name": "lo",
                "index": 1,
                "type": "loopback",
                "state": "unknown",
                "mtu": 65536,
                "flags": ["loopback"],
                "alt-names": [],
                "mac-address": "00:00:00:00:00:00",
                "permanent-mac-address": ""
            }"#,
            expected: loopback,
        },
        BaseLinkFixture {
            name: "dummy",
            nispor_json: r#"{
                "name": "dummy0",
                "index": 3,
                "type": "dummy",
                "state": "down",
                "mtu": 1500,
                "flags": [],
                "alt-names": [],
                "mac-address": "02:00:00:00:00:01",
                "permanent-mac-address": ""
            }"#,
            expected: dummy,
        },
        BaseLinkFixture {
            name: "unsupported",
            nispor_json: r#"{
                "name": "tun0",
                "index": 4,
                "type": "tun",
                "state": "up",
                "mtu": 1500,
                "flags": ["up"],
                "alt-names": [],
                "mac-address": "02:00:00:00:00:02",
                "permanent-mac-address": ""
            }"#,
            expected: tun,
        },
    ]
}

#[test]
fn test_base_link_parity_fixtures() {
    for fixture in base_link_fixtures() {
        assert_eq!(
            base_iface_from_nispor_json(fixture.nispor_json),
            fixture.expected,
            "base link parity fixture '{}'",
            fixture.name
        );
    }
}
