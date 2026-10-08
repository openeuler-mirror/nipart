// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashSet,
    io::{IsTerminal, Write, stdin, stdout},
};

use nipart::{
    Interface, NetworkState, NipartClient, NipartQueryOption,
    NipartWifiControl, NipartWifiScanOption, WifiAuthType, WifiScanResult,
};
use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::CliError;

const WIFI_TABLE_HEADERS: [&str; 8] = [
    "IN-USE", "BSSID", "SSID", "CHAN", "BAND", "SIGNAL", "BARS", "SECURITY",
];
const WIFI_SSID_MIN_WIDTH: usize = 16;
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_YELLOW: &str = "\x1b[33m";
const COLOR_MAGENTA: &str = "\x1b[35m";
const COLOR_CYAN: &str = "\x1b[36m";
const COLOR_DIM: &str = "\x1b[2m";
const COLOR_CLEAR: &str = "\x1b[0m";

pub(crate) struct CommandWifi;

impl CommandWifi {
    pub(crate) const CMD: &str = "wifi";

    pub(crate) fn new_cmd() -> clap::Command {
        clap::Command::new("wifi")
            .about(
                "WIFI actions: without subcommand, show the scan results \
                 stored in kernel",
            )
            .subcommand(
                clap::Command::new("scan")
                    .about("WIFI active scan")
                    .alias("s")
                    .arg(
                        clap::Arg::new("IFACE")
                            .required(false)
                            .index(1)
                            .help("Scan on specified interface only"),
                    )
                    .arg(
                        clap::Arg::new("YAML")
                            .short('y')
                            .long("yaml")
                            .action(clap::ArgAction::SetTrue)
                            .help("Show scan result in YAML format"),
                    )
                    .arg(
                        clap::Arg::new("WITH_HIDDEN")
                            .long("with-hidden")
                            .action(clap::ArgAction::Append)
                            .value_name("SSID")
                            .help("Probe for a hidden SSID; repeatable"),
                    ),
            )
            .subcommand(
                clap::Command::new("connect")
                    .alias("c")
                    .about("Connect WIFI")
                    .arg(
                        clap::Arg::new("SSID")
                            .required(true)
                            .index(1)
                            .help("SSID to connect"),
                    )
                    .arg(
                        clap::Arg::new("NO_PASS")
                            .long("no-pass")
                            .action(clap::ArgAction::SetTrue)
                            .help(
                                "Do not ask for password(SSID does not \
                                 require password to connect)",
                            ),
                    ),
            )
            .subcommand(
                clap::Command::new("off").alias("down").about(
                    "Disable WIFI: disconnect and stop all WIFI actions",
                ),
            )
            .subcommand(clap::Command::new("on").alias("up").about(
                "Enable WIFI actions; use connect or up to restore connections",
            ))
    }

    pub(crate) async fn handle(
        matches: &clap::ArgMatches,
    ) -> Result<(), CliError> {
        if let Some(matches) = matches.subcommand_matches("scan") {
            let mut opt = NipartWifiScanOption::new();
            opt.iface_name = matches.get_one::<String>("IFACE").cloned();
            opt.hidden_ssids = matches
                .get_many::<String>("WITH_HIDDEN")
                .unwrap_or_default()
                .cloned()
                .collect();
            show_scan_result(opt, matches.get_flag("YAML")).await?;
        } else if let Some(matches) = matches.subcommand_matches("connect") {
            // It is safe to unwrap because of clap `required: true`
            let ssid = matches.get_one::<String>("SSID").unwrap();
            let state_str = if matches.get_flag("NO_PASS") {
                format!(
                    r#"---
                    interfaces:
                    - name: {ssid}
                      type: wifi-cfg
                      state: up
                      ipv4:
                        enabled: true
                        dhcp: true
                      wifi:
                        ssid: {ssid}
                    "#
                )
            } else {
                let pass = getpass()?;
                format!(
                    r#"---
                    interfaces:
                    - name: {ssid}
                      type: wifi-cfg
                      state: up
                      ipv4:
                        enabled: true
                        dhcp: true
                      wifi:
                        ssid: {ssid}
                        password: {pass}
                    "#
                )
            };

            let desired_state: nipart::NetworkState =
                rmsd_yaml::from_str(&state_str)?;
            let mut desired_state_to_show = desired_state.clone();
            desired_state_to_show.hide_secrets();
            log::info!(
                "Applying desire state:\n{}",
                rmsd_yaml::to_string(&desired_state_to_show)?
            );
            let mut cli = NipartClient::new().await?;
            cli.apply_network_state(desired_state, Default::default())
                .await?;
        } else if matches.subcommand_matches("off").is_some() {
            let mut cli = NipartClient::new().await?;
            cli.wifi_control(NipartWifiControl::Off).await?;
            println!("WIFI is off");
        } else if matches.subcommand_matches("on").is_some() {
            let mut cli = NipartClient::new().await?;
            cli.wifi_control(NipartWifiControl::On).await?;
            println!("WIFI is on");
        } else {
            // `npt wifi` without subcommand dumps the scan results the
            // kernel already has instead of triggering a new scan.
            show_scan_result(NipartWifiScanOption::dump(), false).await?;
        }
        Ok(())
    }
}

/// Query the daemon for WIFI scan results (active scan or kernel dump)
/// and show them in the `npt wifi scan` table/YAML format.
async fn show_scan_result(
    opt: NipartWifiScanOption,
    yaml: bool,
) -> Result<(), CliError> {
    let mut cli = NipartClient::new().await?;
    let active_ssids =
        match cli.query_network_state(NipartQueryOption::running()).await {
            Ok(net_state) => collect_active_ssids(&net_state),
            Err(e) => {
                log::warn!(
                    "Failed to query network state for active SSID markers: \
                     {e}"
                );
                HashSet::new()
            }
        };
    let mut wifi_cfgs = cli.wifi_scan(opt).await?;
    wifi_cfgs.sort_unstable_by_key(|wifi_cfg| wifi_cfg.signal_percent);
    wifi_cfgs.reverse();
    if yaml {
        println!("{}", rmsd_yaml::to_string(&wifi_cfgs)?);
    } else {
        let table = wifi_scan_table(&wifi_cfgs, &active_ssids);
        print!(
            "{}",
            colorize_wifi_scan_table(&table, &wifi_cfgs, color_enabled())
        );
    }
    Ok(())
}

/// Build an `nmcli device wifi list`-style table from scan results.
fn wifi_scan_table(
    wifi_cfgs: &[WifiScanResult],
    active_ssids: &HashSet<String>,
) -> String {
    let rows: Vec<[String; WIFI_TABLE_HEADERS.len()]> = wifi_cfgs
        .iter()
        .map(|wifi_cfg| {
            let in_use = if active_ssids.contains(&wifi_cfg.ssid) {
                "*"
            } else {
                ""
            };
            let channel = wifi_cfg
                .frequency_mhz
                .and_then(freq_to_channel)
                .map(|c| c.to_string())
                .unwrap_or_else(|| "--".to_string());
            let band = wifi_cfg
                .frequency_mhz
                .and_then(freq_to_band)
                .unwrap_or("--")
                .to_string();
            let signal = wifi_cfg
                .signal_percent
                .map(|s| s.to_string())
                .unwrap_or_else(|| "--".to_string());
            let bars = wifi_cfg
                .signal_percent
                .map(wifi_strength_bars)
                .unwrap_or("____");
            let ssid = display_ssid(&wifi_cfg.ssid);
            [
                in_use.to_string(),
                wifi_cfg.bssid.as_deref().unwrap_or("--").to_uppercase(),
                ssid,
                channel,
                band,
                signal,
                bars.to_string(),
                security_string(&wifi_cfg.auth_types),
            ]
        })
        .collect();

    let mut widths = WIFI_TABLE_HEADERS
        .iter()
        .map(|header| header.len())
        .collect::<Vec<_>>();
    for row in &rows {
        for (idx, value) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(value.width());
        }
    }
    widths[2] = widths[2].max(WIFI_SSID_MIN_WIDTH);

    let mut ret = String::new();
    append_table_row(
        &mut ret,
        &WIFI_TABLE_HEADERS
            .iter()
            .map(|header| (*header).to_string())
            .collect::<Vec<_>>(),
        &widths,
    );
    for row in &rows {
        append_table_row(&mut ret, row, &widths);
    }
    ret
}

fn append_table_row(ret: &mut String, row: &[String], widths: &[usize]) {
    for (idx, value) in row.iter().enumerate() {
        if idx + 1 < row.len() {
            ret.push_str(&pad_to_width(value, widths[idx] + 1));
            ret.push(' ');
        } else {
            ret.push_str(value);
        }
    }
    ret.push('\n');
}

fn pad_to_width(value: &str, width: usize) -> String {
    let padding = width.saturating_sub(value.width());
    format!("{value}{}", " ".repeat(padding))
}

/// Render an SSID for the table. Control characters and zero-width
/// characters are replaced with `?` so the terminal display width matches
/// the calculated width; SSIDs without any visible characters (hidden
/// networks) are shown as `--`.
fn display_ssid(ssid: &str) -> String {
    let mut visible = String::new();
    let mut ret = String::new();
    for c in ssid.chars() {
        if c.is_control() || c.width() == Some(0) {
            ret.push('?');
        } else {
            ret.push(c);
            if !c.is_whitespace() {
                visible.push(c);
            }
        }
    }
    if visible.is_empty() {
        "--".to_string()
    } else {
        ret
    }
}

fn collect_active_ssids(net_state: &NetworkState) -> HashSet<String> {
    let mut ret = HashSet::new();
    for iface in net_state.ifaces.iter() {
        if let Interface::WifiPhy(wifi_phy) = iface
            && let Some(wifi_cfg) = wifi_phy.wifi.as_ref()
            && !wifi_cfg.ssid.is_empty()
        {
            ret.insert(wifi_cfg.ssid.clone());
        }
    }
    ret
}

fn freq_to_channel(freq: u32) -> Option<u32> {
    if (2412..=2472).contains(&freq) && (freq - 2412).is_multiple_of(5) {
        Some((freq - 2407) / 5)
    } else if freq == 2484 {
        Some(14)
    } else if (4915..=4980).contains(&freq) && (freq - 4915).is_multiple_of(5) {
        Some((freq - 4000) / 5)
    } else if (5160..=5825).contains(&freq) && (freq - 5160).is_multiple_of(5) {
        Some((freq - 5000) / 5)
    } else if (5955..=7115).contains(&freq) && (freq - 5955).is_multiple_of(5) {
        Some((freq - 5950) / 5)
    } else {
        None
    }
}

fn freq_to_band(freq: u32) -> Option<&'static str> {
    if (2412..=2484).contains(&freq) {
        Some("2.4 GHz")
    } else if (4915..=5825).contains(&freq) {
        Some("5 GHz")
    } else if (5955..=7115).contains(&freq) {
        Some("6 GHz")
    } else {
        None
    }
}

fn wifi_strength_bars(strength: u8) -> &'static str {
    if strength > 80 {
        "▂▄▆█"
    } else if strength > 55 {
        "▂▄▆_"
    } else if strength > 30 {
        "▂▄__"
    } else if strength > 5 {
        "▂___"
    } else {
        "____"
    }
}

fn color_enabled() -> bool {
    if !stdout().is_terminal() {
        return false;
    }
    !matches!(
        std::env::var("NO_COLOR"),
        Ok(value) if !value.is_empty()
    )
}

fn colorize_wifi_scan_table(
    table: &str,
    wifi_cfgs: &[WifiScanResult],
    enabled: bool,
) -> String {
    if !enabled {
        return table.to_string();
    }

    let mut lines = table.lines();
    let mut ret = String::new();
    if let Some(header) = lines.next() {
        ret.push_str(header);
        ret.push('\n');
    }
    for (wifi_cfg, line) in wifi_cfgs.iter().zip(lines) {
        ret.push_str(wifi_signal_color(wifi_cfg.signal_percent));
        ret.push_str(line);
        ret.push_str(COLOR_CLEAR);
        ret.push('\n');
    }
    ret
}

fn wifi_signal_color(signal_percent: Option<u8>) -> &'static str {
    match signal_percent {
        Some(s) if s > 80 => COLOR_GREEN,
        Some(s) if s > 55 => COLOR_YELLOW,
        Some(s) if s > 30 => COLOR_MAGENTA,
        Some(s) if s > 5 => COLOR_CYAN,
        _ => COLOR_DIM,
    }
}

fn security_string(auth_types: &[nipart::WifiAuthTypeDetailed]) -> String {
    let mut labels = Vec::new();
    for auth_type in auth_types {
        let label = match auth_type.auth_type {
            WifiAuthType::Open => "OPEN",
            WifiAuthType::Wpa2Personal => "WPA2",
            WifiAuthType::Wpa3Personal => "WPA3",
            WifiAuthType::Unknown => {
                if auth_type.akm.iter().any(|akm| akm.starts_with("802.1X")) {
                    "802.1X"
                } else if auth_type.akm.iter().any(|akm| akm == "OWE") {
                    "OWE"
                } else if auth_type.akm.is_empty() {
                    "WPA1"
                } else {
                    "UNKNOWN"
                }
            }
            _ => "UNKNOWN",
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        "--".to_string()
    } else {
        labels.join(" ")
    }
}

// No idea why `libc::getpass()` or `nix::getpass()` does not exists, we have to
// it manually here.
fn getpass() -> Result<String, CliError> {
    let fd = stdin();
    let mut password = String::new();
    if fd.is_terminal() {
        let mut term = tcgetattr(&fd).map_err(|errno| {
            CliError::from(format!(
                "Failed to get terminal info from STDIN: {errno}"
            ))
        })?;
        let term_bak = term.clone();
        // Hide input
        term.local_flags.remove(LocalFlags::ECHO);
        // Show newline(user press enter)
        term.local_flags.insert(LocalFlags::ECHONL);

        tcsetattr(&fd, SetArg::TCSANOW, &term).map_err(|errno| {
            CliError::from(format!(
                "Failed to set STDIN terminal info for hiding password: \
                 {errno}"
            ))
        })?;

        print!("Please input password: ");
        stdout().flush().ok();
        let result = fd.read_line(&mut password);
        result?;
        // Restore the STDIN
        if let Err(errno) = tcsetattr(&fd, SetArg::TCSANOW, &term_bak) {
            log::warn!("Failed to restore STDIN terminal info: {errno}");
        };
    } else {
        fd.read_line(&mut password)?;
    }

    // Remove the tailing new line
    Ok(password.trim_end().to_string())
}

#[cfg(test)]
#[path = "unit_tests/wifi.rs"]
mod tests;
