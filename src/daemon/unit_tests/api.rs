// SPDX-License-Identifier: Apache-2.0

use nipart::{ErrorKind, NipartClientCmd, NipartWifiScanOption};

use super::permission_check;

#[test]
fn test_non_root_wifi_scan_dump_is_allowed() {
    let cmd = NipartClientCmd::WifiScan(Box::new(NipartWifiScanOption::dump()));

    assert!(permission_check(&cmd, 1000).is_ok());
}

#[test]
fn test_non_root_wifi_active_scan_is_denied() {
    let cmd = NipartClientCmd::WifiScan(Box::new(NipartWifiScanOption::new()));

    let err = permission_check(&cmd, 1000).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PermissionDeny);
}

#[test]
fn test_root_wifi_active_scan_is_allowed() {
    let cmd = NipartClientCmd::WifiScan(Box::new(NipartWifiScanOption::new()));

    assert!(permission_check(&cmd, 0).is_ok());
}
