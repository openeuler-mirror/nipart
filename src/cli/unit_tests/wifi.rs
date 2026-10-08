// SPDX-License-Identifier: Apache-2.0

use nipart::WifiAuthTypeDetailed;

use super::*;

fn new_scan_result(
    ssid: &str,
    bssid: &str,
    frequency_mhz: u32,
    signal_percent: u8,
    auth_type: WifiAuthType,
) -> WifiScanResult {
    WifiScanResult::new(
        ssid.to_string(),
        Some("wlan0".to_string()),
        Some(bssid.to_string()),
        Some(frequency_mhz),
        Some(-50),
        Some(signal_percent),
        None,
        vec![WifiAuthTypeDetailed::new(auth_type, Vec::new(), Vec::new())],
    )
}

#[test]
fn test_wifi_without_subcommand_dumps_kernel_scan_result() {
    let matches = CommandWifi::new_cmd()
        .try_get_matches_from(["wifi"])
        .unwrap();

    assert!(matches.subcommand_name().is_none());
}

#[test]
fn test_wifi_down_is_alias_of_off() {
    let matches = CommandWifi::new_cmd()
        .try_get_matches_from(["wifi", "down"])
        .unwrap();

    assert!(matches.subcommand_matches("off").is_some());
}

#[test]
fn test_wifi_up_is_alias_of_on() {
    let matches = CommandWifi::new_cmd()
        .try_get_matches_from(["wifi", "up"])
        .unwrap();

    assert!(matches.subcommand_matches("on").is_some());
}

#[test]
fn test_wifi_scan_table_has_nmcli_style_columns() {
    let wifi_cfgs = vec![
        new_scan_result(
            "Home",
            "02:00:00:00:00:03",
            2437,
            78,
            WifiAuthType::Wpa2Personal,
        ),
        new_scan_result(
            "Office",
            "02:00:00:00:00:0c",
            5180,
            42,
            WifiAuthType::Wpa3Personal,
        ),
    ];
    let active_ssids = HashSet::from(["Home".to_string()]);

    let table = wifi_scan_table(&wifi_cfgs, &active_ssids);
    let lines = table.lines().collect::<Vec<_>>();

    assert_eq!(
        lines[0],
        "IN-USE  BSSID              SSID              CHAN  BAND     SIGNAL  \
         BARS  SECURITY"
    );
    assert_eq!(
        lines[1],
        "*       02:00:00:00:00:03  Home              6     2.4 GHz  78      \
         ▂▄▆_  WPA2"
    );
    assert_eq!(
        lines[2],
        "        02:00:00:00:00:0C  Office            36    5 GHz    42      \
         ▂▄__  WPA3"
    );
}

#[test]
fn test_wifi_scan_table_aligns_cjk_ssid() {
    let wifi_cfgs = vec![new_scan_result(
        "网网网网网",
        "02:00:00:00:00:03",
        2437,
        78,
        WifiAuthType::Wpa2Personal,
    )];

    let table = wifi_scan_table(&wifi_cfgs, &HashSet::new());

    assert_eq!(
        table.lines().nth(1).unwrap(),
        "        02:00:00:00:00:03  网网网网网        6     2.4 GHz  78      \
         ▂▄▆_  WPA2"
    );
}

#[test]
fn test_wifi_scan_table_marks_whitespace_ssid_as_hidden() {
    let wifi_cfgs = vec![
        new_scan_result(
            "          ",
            "02:00:00:00:00:12",
            2462,
            42,
            WifiAuthType::Open,
        ),
        new_scan_result("", "02:00:00:00:00:13", 2462, 42, WifiAuthType::Open),
        new_scan_result(
            "\0\0\0\0",
            "02:00:00:00:00:14",
            2462,
            42,
            WifiAuthType::Open,
        ),
    ];

    let table = wifi_scan_table(&wifi_cfgs, &HashSet::new());
    let lines = table.lines().collect::<Vec<_>>();

    assert!(lines[1].contains("02:00:00:00:00:12  --"));
    assert!(lines[2].contains("02:00:00:00:00:13  --"));
    assert!(lines[3].contains("02:00:00:00:00:14  --"));
    // Both rows must place the channel column at the same position.
    assert_eq!(
        lines[1].find("11"),
        lines[2].find("11"),
        "channel column misaligned:\n{lines:?}"
    );
    assert_eq!(
        lines[2].find("11"),
        lines[3].find("11"),
        "channel column misaligned:\n{lines:?}"
    );
}

#[test]
fn test_wifi_scan_table_expands_ssid_column_for_long_ssid() {
    let wifi_cfgs = vec![
        new_scan_result(
            &"A".repeat(32),
            "02:00:00:00:00:0c",
            2462,
            42,
            WifiAuthType::Open,
        ),
        new_scan_result(
            "short",
            "02:00:00:00:00:0d",
            2462,
            42,
            WifiAuthType::Open,
        ),
    ];

    let table = wifi_scan_table(&wifi_cfgs, &HashSet::new());
    let lines = table.lines().collect::<Vec<_>>();

    assert!(lines[1].contains(&"A".repeat(32)));
    assert_eq!(
        lines[1].find("11"),
        lines[2].find("11"),
        "channel column misaligned:\n{lines:?}"
    );
}

#[test]
fn test_display_ssid_replaces_control_characters() {
    assert_eq!(display_ssid("foo\0bar"), "foo?bar");
    assert_eq!(display_ssid("\0\0"), "--");
    assert_eq!(display_ssid("   "), "--");
    assert_eq!(display_ssid("Home Network"), "Home Network");
}

#[test]
fn test_wifi_signal_color_matches_nmcli() {
    assert_eq!(wifi_signal_color(Some(90)), COLOR_GREEN);
    assert_eq!(wifi_signal_color(Some(78)), COLOR_YELLOW);
    assert_eq!(wifi_signal_color(Some(42)), COLOR_MAGENTA);
    assert_eq!(wifi_signal_color(Some(20)), COLOR_CYAN);
    assert_eq!(wifi_signal_color(Some(0)), COLOR_DIM);
    assert_eq!(wifi_signal_color(None), COLOR_DIM);
}

#[test]
fn test_colorize_wifi_scan_table() {
    let wifi_cfgs = vec![new_scan_result(
        "Home",
        "02:00:00:00:00:03",
        2437,
        78,
        WifiAuthType::Wpa2Personal,
    )];
    let table = "header\nrow\n";

    assert_eq!(colorize_wifi_scan_table(table, &wifi_cfgs, false), table);
    assert_eq!(
        colorize_wifi_scan_table(table, &wifi_cfgs, true),
        "header\n\x1b[33mrow\x1b[0m\n"
    );
}

#[test]
fn test_freq_to_channel() {
    assert_eq!(freq_to_channel(2412), Some(1));
    assert_eq!(freq_to_channel(2437), Some(6));
    assert_eq!(freq_to_channel(2484), Some(14));
    assert_eq!(freq_to_channel(5180), Some(36));
    assert_eq!(freq_to_channel(5825), Some(165));
    assert_eq!(freq_to_channel(5955), Some(1));
    assert_eq!(freq_to_channel(0), None);
}

#[test]
fn test_freq_to_band() {
    assert_eq!(freq_to_band(2412), Some("2.4 GHz"));
    assert_eq!(freq_to_band(5180), Some("5 GHz"));
    assert_eq!(freq_to_band(5955), Some("6 GHz"));
    assert_eq!(freq_to_band(0), None);
}

#[test]
fn test_security_string() {
    assert_eq!(security_string(&[]), "--");
    assert_eq!(
        security_string(&[WifiAuthTypeDetailed::new(
            WifiAuthType::Wpa2Personal,
            Vec::new(),
            Vec::new(),
        )]),
        "WPA2"
    );
    assert_eq!(
        security_string(&[
            WifiAuthTypeDetailed::new(
                WifiAuthType::Wpa2Personal,
                Vec::new(),
                Vec::new(),
            ),
            WifiAuthTypeDetailed::new(
                WifiAuthType::Wpa3Personal,
                Vec::new(),
                Vec::new(),
            ),
        ]),
        "WPA2 WPA3"
    );
}
