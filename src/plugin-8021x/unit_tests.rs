// SPDX-License-Identifier: Apache-2.0

use nipart::{
    BaseInterface, Interface, InterfaceState, InterfaceType, MacSecConfig,
    MacSecInterface,
};

use super::*;

const VALID_CAK: &str = "50b71a8ef0bd5751ea76de6d6c98c03a";
const VALID_CKN: &str =
    "f2b4297d39da7330910a74abc0449feb45b5c0b9fc23df1430e1898fcf1c4550";

fn macsec_iface(macsec: MacSecConfig) -> Interface {
    let mut base =
        BaseInterface::new("macsec0".to_string(), InterfaceType::MacSec);
    base.kernel_iface_name = "macsec0".to_string();
    base.state = InterfaceState::Up;
    let mut iface = MacSecInterface::default();
    iface.base = base;
    iface.macsec = Some(macsec);
    Interface::MacSec(Box::new(iface))
}

fn base_config() -> MacSecConfig {
    let mut config = MacSecConfig::default();
    config.base_iface = "eth1".to_string();
    config.encrypt = Some(true);
    config
}

fn mka_config(cak: &str, ckn: &str) -> MacSecConfig {
    let mut config = base_config();
    config.mka_cak = Some(cak.to_string());
    config.mka_ckn = Some(ckn.to_string());
    config
}

#[test]
fn test_decode_hex() {
    assert_eq!(decode_hex("mka-cak", "00ff10").unwrap(), [0, 255, 16]);
    assert!(decode_hex("mka-cak", "0").is_err());
    assert!(decode_hex("mka-cak", "zz").is_err());
}

#[test]
fn test_mka_config_requires_both_keys() {
    let mut config = base_config();
    config.mka_cak = Some(VALID_CAK.to_string());
    let iface = macsec_iface(config);
    let Interface::MacSec(iface) = iface else {
        unreachable!()
    };
    assert!(MkaConfig::from_iface(&iface).unwrap().is_none());
}

#[test]
fn test_mka_config_requires_base_iface() {
    let mut config = mka_config(VALID_CAK, VALID_CKN);
    config.base_iface = String::new();
    let iface = macsec_iface(config);
    let Interface::MacSec(iface) = iface else {
        unreachable!()
    };
    let result = MkaConfig::from_iface(&iface);
    assert!(result.is_err());
    assert!(result.unwrap_err().msg().contains("base-iface"));
}

#[test]
fn test_mka_config_from_iface() {
    let iface = macsec_iface(mka_config(VALID_CAK, VALID_CKN));
    let Interface::MacSec(iface) = iface else {
        unreachable!()
    };
    let config = MkaConfig::from_iface(&iface).unwrap().unwrap();
    assert_eq!(config.base_iface, "eth1");
    assert_eq!(config.cak.len(), 16);
    assert_eq!(config.ckn.len(), 32);
    assert!(config.encrypt);
}

#[test]
fn test_mka_session_restart_only_for_key_or_base_change() {
    let iface = macsec_iface(mka_config(VALID_CAK, VALID_CKN));
    let Interface::MacSec(iface) = iface else {
        unreachable!()
    };
    let config = MkaConfig::from_iface(&iface).unwrap().unwrap();

    let mut changed = config.clone();
    assert!(!changed.requires_new_session(&config));

    changed.encrypt = false;
    assert!(!changed.requires_new_session(&config));

    changed.base_iface = "eth2".to_string();
    assert!(changed.requires_new_session(&config));

    let mut changed = config.clone();
    changed.cak[0] ^= 0xff;
    assert!(changed.requires_new_session(&config));

    let mut changed = config.clone();
    changed.ckn[0] ^= 0xff;
    assert!(changed.requires_new_session(&config));
}

#[test]
fn test_build_macsec_config() {
    let iface = macsec_iface(mka_config(VALID_CAK, VALID_CKN));
    let Interface::MacSec(iface) = iface else {
        unreachable!()
    };
    let config = MkaConfig::from_iface(&iface).unwrap().unwrap();
    let shuli = build_macsec_config("macsec0", &config);
    assert_eq!(shuli.macsec_iface_name(), "macsec0");
    assert!(shuli.can_be_key_server);
    assert_eq!(shuli.key_server_priority, 0xff);
    assert!(shuli.encrypt);
    assert_eq!(shuli.cak, config.cak);
    assert_eq!(shuli.ckn, config.ckn);
}
