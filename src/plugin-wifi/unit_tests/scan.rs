// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Build a valid RSNE(Robust Security Network Element) with group/pairwise
/// cipher CCMP and the given AKM suites.
fn rsn_ie(akm: &[u8]) -> Vec<u8> {
    let mut payload = vec![0x01, 0x00]; // version
    payload.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]); // group CCMP
    payload.extend_from_slice(&[0x01, 0x00]); // pairwise count
    payload.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]); // pairwise CCMP
    payload.extend_from_slice(&[(akm.len() / 4) as u8, 0x00]); // akm count
    payload.extend_from_slice(akm);
    payload.extend_from_slice(&[0x00, 0x00]); // rsn capabilities
    let mut ret = vec![0x30, payload.len() as u8];
    ret.extend_from_slice(&payload);
    ret
}

#[test]
fn test_detect_auth_type_wpa2_psk() {
    let auth = detect_auth_type(&rsn_ie(&[0x00, 0x0f, 0xac, 0x02]));
    assert_eq!(auth.auth_type, WifiAuthType::Wpa2Personal);
    assert_eq!(auth.akm, vec!["PSK"]);
    assert_eq!(auth.cipher, vec!["CCMP"]);
}

#[test]
fn test_detect_auth_type_wpa3_sae() {
    let auth = detect_auth_type(&rsn_ie(&[0x00, 0x0f, 0xac, 0x08]));
    assert_eq!(auth.auth_type, WifiAuthType::Wpa3Personal);
    assert_eq!(auth.akm, vec!["SAE"]);
    assert_eq!(auth.cipher, vec!["CCMP"]);
}

#[test]
fn test_detect_auth_type_transition_mode_prefers_sae() {
    // WPA2/WPA3 transition mode: PSK + SAE.
    let auth = detect_auth_type(&rsn_ie(&[
        0x00, 0x0f, 0xac, 0x02, 0x00, 0x0f, 0xac, 0x08,
    ]));
    assert_eq!(auth.auth_type, WifiAuthType::Wpa3Personal);
    assert_eq!(auth.akm, vec!["PSK", "SAE"]);
}

#[test]
fn test_detect_auth_type_eap_is_unknown() {
    // EAP(Enterprise) is not supported yet, report as Unknown. The AKM
    // details are still listed in the detailed result.
    let auth = detect_auth_type(&rsn_ie(&[0x00, 0x0f, 0xac, 0x01]));
    assert_eq!(auth.auth_type, WifiAuthType::Unknown);
    assert_eq!(auth.akm, vec!["802.1X"]);
    // Suite B(802.1X-SHA384) too.
    let auth = detect_auth_type(&rsn_ie(&[0x00, 0x0f, 0xac, 0x0b]));
    assert_eq!(auth.auth_type, WifiAuthType::Unknown);
    assert_eq!(auth.akm, vec!["802.1X-SUITE-B"]);
}

#[test]
fn test_detect_auth_type_open_without_rsne() {
    // SSID element only: open network.
    let auth = detect_auth_type(&[0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
    assert_eq!(auth.auth_type, WifiAuthType::Open);
    assert!(auth.akm.is_empty());
    assert!(auth.cipher.is_empty());
}

#[test]
fn test_detect_auth_type_wpa1_vendor_ie() {
    // WPA IE: vendor element with OUI 00:50:F2 and OUI type 1.
    let wpa_ie = [0xdd, 0x08, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00, 0x00, 0x50];
    let auth = detect_auth_type(&wpa_ie);
    assert_eq!(auth.auth_type, WifiAuthType::Unknown);
}

#[test]
fn test_merge_scan_results_keeps_signal_dbm() {
    // shuli reports `BssInfo::signal_dbm` in dBm already, the scan
    // result must not scale it down again.
    let ies = [0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
    let mut bss = BssInfo::default();
    bss.bssid = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    bss.freq_mhz = 2412;
    bss.signal_dbm = -55;
    let mut ret = HashMap::new();
    merge_scan_results(&mut ret, "wlan0", &[(bss, ies.to_vec())], None);
    let result = ret.get("hello").unwrap();
    assert_eq!(result.signal_dbm, Some(-55));
    assert_eq!(
        result.signal_percent,
        Some(WifiConfig::signal_dbm_to_percent(-55))
    );
}

#[test]
fn test_scan_dump_reports_hidden_bss() {
    // A kernel scan dump (`hidden_ssids: None`) reports hidden BSSes
    // whose SSID is cached, while an active scan without probing skips
    // them.
    let ies = [0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
    let mut bss = BssInfo::default();
    bss.bssid = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    bss.freq_mhz = 2412;
    bss.signal_dbm = -55;
    bss.hidden = true;

    let mut ret = HashMap::new();
    merge_scan_results(&mut ret, "wlan0", &[(bss.clone(), ies.to_vec())], None);
    assert!(ret.contains_key("hello"));

    let mut ret = HashMap::new();
    merge_scan_results(&mut ret, "wlan0", &[(bss, ies.to_vec())], Some(&[]));
    assert!(ret.is_empty());
}
