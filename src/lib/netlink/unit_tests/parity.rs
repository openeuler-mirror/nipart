// SPDX-License-Identifier: Apache-2.0

use crate::{BaseInterface, InterfaceIpv4, InterfaceIpv6, no_daemon};

pub(super) fn nispor_iface_from_json(json: &str) -> nispor::Iface {
    serde_json::from_str(json).expect("Invalid nispor Iface fixture")
}

pub(super) fn base_iface_from_nispor_json(json: &str) -> BaseInterface {
    let mut iface = no_daemon::np_iface_to_base_iface(&nispor_iface_from_json(json));
    iface.ipv4 = Some(InterfaceIpv4::default());
    iface.ipv6 = Some(InterfaceIpv6::default());
    iface
}

#[cfg(test)]
mod tests {
    use super::base_iface_from_nispor_json;
    use crate::{
        InterfaceIpv4, InterfaceIpv6, InterfaceLinkState, InterfaceState,
        InterfaceType,
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
}
