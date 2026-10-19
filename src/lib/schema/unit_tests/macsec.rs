// SPDX-License-Identifier: Apache-2.0

use crate::{
    BaseInterface, ErrorKind, Interface, InterfaceState, InterfaceType,
    MacSecConfig, MacSecInterface, MacSecOffload, MacSecValidate, NetworkState,
    NipartError, NipartInterface,
};

const VALID_CAK: &str = "50b71a8ef0bd5751ea76de6d6c98c03a";
const VALID_CKN: &str =
    "f2b4297d39da7330910a74abc0449feb45b5c0b9fc23df1430e1898fcf1c4550";

fn macsec_iface(macsec: MacSecConfig) -> MacSecInterface {
    MacSecInterface {
        base: BaseInterface {
            name: "macsec0".to_string(),
            iface_type: InterfaceType::MacSec,
            state: InterfaceState::Up,
            ..Default::default()
        },
        macsec: Some(macsec),
    }
}

fn base_macsec_config() -> MacSecConfig {
    MacSecConfig {
        base_iface: "eth1".to_string(),
        encrypt: Some(true),
        send_sci: Some(true),
        validation: Some(MacSecValidate::Strict),
        ..Default::default()
    }
}

fn sanitize_macsec(
    iface: &MacSecInterface,
    current: Option<&MacSecInterface>,
) -> Result<MacSecInterface, NipartError> {
    let mut for_save = iface.clone();
    let mut for_apply = iface.clone();
    let mut for_verify = iface.clone();
    let mut merged = iface.clone();
    iface.sanitize(
        current,
        &mut for_save,
        &mut for_apply,
        &mut for_verify,
        &mut merged,
    )?;
    Ok(for_verify)
}

fn gen_macsec_state(mka_cak: &str) -> NetworkState {
    NetworkState::new_from_yaml(&format!(
        r#"---
        interfaces:
          - name: macsec0
            type: macsec
            state: up
            macsec:
              base-iface: eth1
              encrypt: true
              port: 0
              validation: strict
              send-sci: true
              mka-cak: {mka_cak}
              mka-ckn: {VALID_CKN}"#
    ))
    .unwrap()
}

fn gen_macsec_state_without_mka() -> NetworkState {
    NetworkState::new_from_yaml(
        r#"---
        interfaces:
          - name: macsec0
            type: macsec
            state: up
            macsec:
              base-iface: eth1
              encrypt: true
              port: 0
              validation: strict
              send-sci: true"#,
    )
    .unwrap()
}

fn macsec_from_state(state: &NetworkState) -> &MacSecInterface {
    state
        .ifaces
        .kernel_ifaces
        .get("macsec0")
        .and_then(|iface| {
            if let Interface::MacSec(macsec_iface) = iface {
                Some(macsec_iface.as_ref())
            } else {
                None
            }
        })
        .expect("macsec0 should be a MACsec interface")
}

#[test]
fn test_deserialize_macsec_interface() {
    let iface: Interface = rmsd_yaml::from_str(
        r#"---
        name: macsec0
        type: macsec
        state: up
        macsec:
          encrypt: true
          base-iface: eth1
          mka-cak: 50b71a8ef0bd5751ea76de6d6c98c03a
          mka-ckn: f2b4297d39da7330910a74abc0449feb45b5c0b9fc23df1430e1898fcf1c4550
          port: 0
          validation: strict
          send-sci: true
          offload: off
        "#,
    )
    .unwrap();
    let Interface::MacSec(iface) = iface else {
        panic!("Expected MACsec interface");
    };
    let macsec = iface.macsec.as_ref().unwrap();
    assert_eq!(macsec.base_iface, "eth1");
    assert_eq!(macsec.encrypt, Some(true));
    assert_eq!(macsec.send_sci, Some(true));
    assert_eq!(macsec.port, Some(0));
    assert_eq!(macsec.validation, Some(MacSecValidate::Strict));
    assert_eq!(macsec.offload, Some(MacSecOffload::Off));
}

#[test]
fn test_deserialize_macsec_sci_hex() {
    for sci_value in ["0x3e042ef52d910007", "3e042ef52d910007"] {
        let iface: Interface = rmsd_yaml::from_str(&format!(
            r#"---
            name: macsec0
            type: macsec
            state: up
            macsec:
              base-iface: eth1
              sci: {sci_value}
            "#
        ))
        .unwrap();
        let Interface::MacSec(iface) = iface else {
            panic!("Expected MACsec interface");
        };
        assert_eq!(
            iface.macsec.as_ref().unwrap().sci,
            Some(0x3e04_2ef5_2d91_0007)
        );
    }
}

#[test]
fn test_serialize_macsec_sci_as_hex() {
    let iface = macsec_iface(MacSecConfig {
        sci: Some(0x3e04_2ef5_2d91_0007),
        ..base_macsec_config()
    });
    let value = serde_json::to_value(&iface).unwrap();
    assert_eq!(value["macsec"]["sci"].as_str(), Some("3e042ef52d910007"));
}

#[test]
fn test_sanitize_macsec_sci_port_mismatch() {
    let iface = macsec_iface(MacSecConfig {
        sci: Some(0x3e04_2ef5_2d91_0007),
        port: Some(8),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().msg().contains("does not match"));
}

#[test]
fn test_sanitize_macsec_sci_port_match() {
    let iface = macsec_iface(MacSecConfig {
        sci: Some(0x3e04_2ef5_2d91_0007),
        port: Some(7),
        ..base_macsec_config()
    });
    assert!(sanitize_macsec(&iface, None).is_ok());
}

#[test]
fn test_sanitize_macsec_sci_requires_send_sci() {
    let iface = macsec_iface(MacSecConfig {
        sci: Some(0x3e04_2ef5_2d91_0007),
        send_sci: Some(false),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .msg()
            .contains("`send-sci` must be true when `sci` is defined")
    );
}

#[test]
fn test_sanitize_macsec_valid() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        ..base_macsec_config()
    });
    assert!(sanitize_macsec(&iface, None).is_ok());
}

#[test]
fn test_sanitize_macsec_only_cak() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    let e = result.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidArgument);
    assert!(e.msg().contains("must be all missing or present"));
}

#[test]
fn test_sanitize_macsec_only_ckn() {
    let iface = macsec_iface(MacSecConfig {
        mka_ckn: Some(VALID_CKN.to_string()),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .msg()
            .contains("must be all missing or present")
    );
}

#[test]
fn test_sanitize_macsec_invalid_cak_len() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some("50b71a8ef0bd5751ea76de6d6c98c0".to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .msg()
            .contains("string of 32 characters")
    );
}

#[test]
fn test_sanitize_macsec_invalid_ckn_odd_len() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some("f2b".to_string()),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .msg()
            .contains("even size between 2 and 64")
    );
}

#[test]
fn test_sanitize_macsec_invalid_ckn_too_long() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some("ab".repeat(33)),
        ..base_macsec_config()
    });
    assert!(sanitize_macsec(&iface, None).is_err());
}

#[test]
fn test_sanitize_macsec_invalid_cak_hex() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some("zz".repeat(16)),
        mka_ckn: Some(VALID_CKN.to_string()),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().msg().contains("hexadecimal string"));
}

#[test]
fn test_sanitize_macsec_invalid_ckn_hex() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some("zz".to_string()),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().msg().contains("hexadecimal string"));
}

#[test]
fn test_sanitize_macsec_mka_requires_port_one() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        port: Some(0),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().msg().contains("`port` must be 1"));
}

#[test]
fn test_sanitize_macsec_mka_allows_port_one() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        port: Some(1),
        ..base_macsec_config()
    });
    assert!(sanitize_macsec(&iface, None).is_ok());
}

#[test]
fn test_sanitize_macsec_mka_rejects_explicit_sci() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        sci: Some(0x3e04_2ef5_2d91_0001),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .msg()
            .contains("`sci` cannot be defined")
    );
}

#[test]
fn test_sanitize_macsec_missing_config_for_new_iface() {
    let iface = MacSecInterface {
        base: BaseInterface {
            name: "macsec0".to_string(),
            iface_type: InterfaceType::MacSec,
            state: InterfaceState::Up,
            ..Default::default()
        },
        macsec: None,
    };
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .msg()
            .contains("configuration is mandatory")
    );
}

#[test]
fn test_sanitize_macsec_missing_base_iface_for_new_iface() {
    let iface = macsec_iface(MacSecConfig::default());
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .msg()
            .contains("base-iface` is mandatory")
    );
}

#[test]
fn test_sanitize_macsec_port_too_large() {
    let iface = macsec_iface(MacSecConfig {
        port: Some(u16::MAX as u32 + 1),
        ..base_macsec_config()
    });
    let result = sanitize_macsec(&iface, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().msg().contains("`port` must be between"));
}

#[test]
fn test_sanitize_macsec_existing_without_config() {
    let current = macsec_iface(base_macsec_config());
    let iface = MacSecInterface {
        base: BaseInterface {
            name: "macsec0".to_string(),
            iface_type: InterfaceType::MacSec,
            state: InterfaceState::Absent,
            ..Default::default()
        },
        macsec: None,
    };
    assert!(sanitize_macsec(&iface, Some(&current)).is_ok());
}

#[test]
fn test_sanitize_macsec_strips_mka_from_verify() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        ..base_macsec_config()
    });
    let for_verify = sanitize_macsec(&iface, None).unwrap();
    let macsec = for_verify.macsec.unwrap();
    assert!(macsec.mka_cak.is_none());
    assert!(macsec.mka_ckn.is_none());
}

#[test]
fn test_sanitize_before_verify_strips_hidden_mka() {
    let mut iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        ..base_macsec_config()
    });
    iface.hide_secrets();
    let mut current = macsec_iface(base_macsec_config());
    iface.sanitize_before_verify(&mut current);
    let macsec = iface.macsec.unwrap();
    assert!(macsec.mka_cak.is_none());
    assert!(macsec.mka_ckn.is_none());
}

#[test]
fn test_need_delete_before_change_port() {
    let cur = macsec_iface(MacSecConfig {
        port: Some(0),
        ..base_macsec_config()
    });
    let des = macsec_iface(MacSecConfig {
        port: Some(1),
        ..base_macsec_config()
    });
    assert!(des.need_delete_before_change(&cur));
    assert!(!des.need_delete_before_change(&des));
}

#[test]
fn test_need_delete_before_change_sci() {
    let cur = macsec_iface(MacSecConfig {
        sci: Some(0x3e04_2ef5_2d91_0007),
        ..base_macsec_config()
    });
    let des = macsec_iface(MacSecConfig {
        sci: Some(0x3e04_2ef5_2d91_0008),
        ..base_macsec_config()
    });
    assert!(des.need_delete_before_change(&cur));
}

#[test]
fn test_need_delete_before_change_base_iface() {
    let cur = macsec_iface(base_macsec_config());
    let des = macsec_iface(MacSecConfig {
        base_iface: "eth2".to_string(),
        ..base_macsec_config()
    });
    assert!(des.need_delete_before_change(&cur));
}

#[test]
fn test_macsec_hide_secrets() {
    let mut iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        ..base_macsec_config()
    });
    iface.hide_secrets();
    let macsec = iface.macsec.unwrap();
    assert_eq!(
        macsec.mka_cak.as_deref(),
        Some(crate::NetworkState::HIDE_SECRET_STR)
    );
    assert_eq!(macsec.mka_ckn.as_deref(), Some(VALID_CKN));
}

#[test]
fn test_macsec_debug_and_display_hide_cak() {
    let iface = macsec_iface(MacSecConfig {
        mka_cak: Some(VALID_CAK.to_string()),
        mka_ckn: Some(VALID_CKN.to_string()),
        ..base_macsec_config()
    });
    for output in [format!("{iface:?}"), format!("{iface}")] {
        assert!(!output.contains(VALID_CAK));
        assert!(output.contains(NetworkState::HIDE_SECRET_STR));
        assert!(output.contains(VALID_CKN));
    }
}

#[test]
fn test_macsec_parent() {
    let iface = macsec_iface(base_macsec_config());
    assert_eq!(iface.parent(), Some("eth1"));
    assert!(macsec_iface(MacSecConfig::default()).parent().is_none());
}

#[test]
fn test_macsec_mka_cak_in_merge() {
    let mut safe_state = gen_macsec_state(NetworkState::HIDE_SECRET_STR);
    let secret_state = gen_macsec_state(VALID_CAK);

    safe_state.merge(&secret_state).unwrap();

    let macsec = macsec_from_state(&safe_state).macsec.as_ref().unwrap();
    assert_eq!(macsec.mka_cak.as_deref(), Some(VALID_CAK));
    assert_eq!(macsec.mka_ckn.as_deref(), Some(VALID_CKN));
}

#[test]
fn test_macsec_hidden_mka_cak_in_merge_keeps_old_secret() {
    let mut safe_state = gen_macsec_state(VALID_CAK);
    let hidden_state = gen_macsec_state(NetworkState::HIDE_SECRET_STR);

    safe_state.merge(&hidden_state).unwrap();

    let macsec = macsec_from_state(&safe_state).macsec.as_ref().unwrap();
    assert_eq!(macsec.mka_cak.as_deref(), Some(VALID_CAK));
    assert_eq!(macsec.mka_ckn.as_deref(), Some(VALID_CKN));
}

#[test]
fn test_macsec_hidden_mka_cak_in_gen_diff_no_diff() {
    let plain_state = gen_macsec_state(VALID_CAK);
    let hidden_state = gen_macsec_state(NetworkState::HIDE_SECRET_STR);

    let diff_state = hidden_state.gen_diff(&plain_state).unwrap();

    assert!(
        !diff_state.ifaces.kernel_ifaces.contains_key("macsec0"),
        "Hidden mka-cak should not generate a diff, but got: {:?}",
        diff_state.ifaces.kernel_ifaces.get("macsec0")
    );
}

#[test]
fn test_macsec_omitted_mka_cak_in_merge_keeps_old_secret() {
    let mut safe_state = gen_macsec_state(VALID_CAK);
    let new_state = gen_macsec_state_without_mka();

    safe_state.merge(&new_state).unwrap();

    let macsec = macsec_from_state(&safe_state).macsec.as_ref().unwrap();
    assert_eq!(macsec.mka_cak.as_deref(), Some(VALID_CAK));
    assert_eq!(macsec.mka_ckn.as_deref(), Some(VALID_CKN));
}
