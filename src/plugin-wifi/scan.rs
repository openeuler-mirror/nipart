// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use nipart::{
    ErrorKind, NipartError, WifiAuthType, WifiAuthTypeDetailed, WifiConfig,
    WifiScanResult,
};
use rtnetlink::packet_core::Parseable;
use shuli::BssInfo;
use wl_nl80211::{
    Ieee80211AkmSuite, Ieee80211CipherSuite, Ieee80211Element,
    Ieee80211Elements,
};

use crate::NipartWpaConn;

impl NipartWpaConn {
    pub(crate) async fn wifi_scan(
        iface_name: Option<&str>,
        hidden_ssids: Vec<String>,
    ) -> Result<Vec<WifiScanResult>, NipartError> {
        if let Ok(r) = _wifi_scan(iface_name, hidden_ssids.clone()).await
            && !r.is_empty()
        {
            return Ok(r);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        _wifi_scan(iface_name, hidden_ssids).await
    }

    /// Dump the scan results already stored in the kernel without
    /// triggering a new scan - the `iw dev <iface> scan dump`
    /// equivalent, used by `npt wifi`.
    pub(crate) async fn wifi_scan_dump(
        iface_name: Option<&str>,
    ) -> Result<Vec<WifiScanResult>, NipartError> {
        let (scan_ifaces, _connected_ssids) = wifi_ifaces(iface_name).await?;
        let mut ret: HashMap<String, WifiScanResult> = HashMap::new();
        for iface_name in &scan_ifaces {
            let scan_results = shuli::WifiClient::get_scan_result(iface_name)
                .await
                .map_err(|e| {
                    NipartError::new(
                        ErrorKind::PluginFailure,
                        format!("scan dump failed on {iface_name}: {e}"),
                    )
                })?;
            merge_scan_results(&mut ret, iface_name, &scan_results, None);
        }
        Ok(sorted_scan_results(ret))
    }
}

async fn _wifi_scan(
    iface_name: Option<&str>,
    mut hidden_ssids: Vec<String>,
) -> Result<Vec<WifiScanResult>, NipartError> {
    let (scan_ifaces, connected_ssids) = wifi_ifaces(iface_name).await?;
    // Also probe the SSID we are currently connected to, so a hidden
    // network we are attached to still appears in the results.
    for ssid in connected_ssids {
        if !hidden_ssids.contains(&ssid) {
            hidden_ssids.push(ssid);
        }
    }

    // Keep one entry per SSID, merging auth types from all BSSes of the
    // same SSID and keeping the strongest signal.
    let mut ret: HashMap<String, WifiScanResult> = HashMap::new();
    for iface_name in &scan_ifaces {
        let scan_results =
            shuli::WifiClient::scan(iface_name, hidden_ssids.clone())
                .await
                .map_err(|e| {
                    NipartError::new(
                        ErrorKind::PluginFailure,
                        format!("scan failed on {iface_name}: {e}"),
                    )
                })?;
        merge_scan_results(
            &mut ret,
            iface_name,
            &scan_results,
            Some(&hidden_ssids),
        );
    }
    Ok(sorted_scan_results(ret))
}

/// The WIFI interfaces to scan and the SSIDs they are currently
/// connected to. A requested `iface_name` restricts the result to that
/// single interface and errors when it is not a WIFI interface.
async fn wifi_ifaces(
    iface_name: Option<&str>,
) -> Result<(Vec<String>, Vec<String>), NipartError> {
    let mut filter = nispor::NetStateFilter::minimum();
    filter.iface = Some(nispor::NetStateIfaceFilter::minimum());
    let np_state =
        nispor::NetState::retrieve_with_filter_async(&filter).await?;

    let mut wifi_phys: Vec<String> = Vec::new();
    let mut connected_ssids: Vec<String> = Vec::new();
    for np_iface in np_state.ifaces.values() {
        if np_iface.iface_type != nispor::IfaceType::Wifi {
            continue;
        }
        wifi_phys.push(np_iface.name.clone());
        // Remember the SSID we are currently connected to, so a hidden
        // network we are attached to can still be probed and reported.
        if let Some(ssid) = np_iface.wifi.as_ref().and_then(|w| w.ssid.clone())
            && !ssid.is_empty()
            && !connected_ssids.contains(&ssid)
        {
            connected_ssids.push(ssid);
        }
    }

    if let Some(iface_name) = iface_name {
        if !wifi_phys.iter().any(|name| name == iface_name) {
            return Err(NipartError::new(
                ErrorKind::InvalidArgument,
                format!("WIFI interface {iface_name} not found"),
            ));
        }
        return Ok((vec![iface_name.to_string()], connected_ssids));
    }
    Ok((wifi_phys, connected_ssids))
}

/// Merge `(BssInfo, raw IEs)` entries into `ret`, keeping one
/// [`WifiScanResult`] per SSID: auth types advertised by different BSSes
/// of the same SSID are merged and the strongest signal wins.
///
/// `hidden_ssids` is `Some` for an active scan: hidden BSSes are only
/// reported when the caller probed for their SSID. `None` is a kernel
/// scan dump, which reports every SSID the kernel cached.
fn merge_scan_results(
    ret: &mut HashMap<String, WifiScanResult>,
    iface_name: &str,
    scan_results: &[(BssInfo, Vec<u8>)],
    hidden_ssids: Option<&[String]>,
) {
    for (bss_info, ies) in scan_results {
        let Some(ssid) = extract_ssid(ies) else {
            continue;
        };
        if ssid.is_empty() {
            continue;
        }
        // A network that hides its SSID is only reported when we were
        // asked to probe for it (e.g. --with-hidden, or it is the SSID
        // we are currently connected to).
        if bss_info.hidden
            && let Some(hidden_ssids) = hidden_ssids
            && !hidden_ssids.contains(&ssid)
        {
            continue;
        }

        // shuli reports the scan signal in dBm already.
        let signal_dbm = bss_info.signal_dbm as i16;
        let scan_res = WifiScanResult::new(
            ssid.clone(),
            Some(iface_name.to_string()),
            Some(mac_to_string(&bss_info.bssid)),
            Some(bss_info.freq_mhz),
            Some(signal_dbm),
            Some(WifiConfig::signal_dbm_to_percent(signal_dbm)),
            detect_generation(ies),
            vec![detect_auth_type(ies)],
        );

        if let Some(existing) = ret.get_mut(&ssid) {
            // Merge auth types advertised by different BSSes.
            if !existing.auth_types.contains(&scan_res.auth_types[0]) {
                existing.auth_types.push(scan_res.auth_types[0].clone());
            }
            // Keep the strongest signal per SSID.
            if existing.signal_dbm < scan_res.signal_dbm {
                existing.base_iface = scan_res.base_iface;
                existing.bssid = scan_res.bssid;
                existing.frequency_mhz = scan_res.frequency_mhz;
                existing.signal_dbm = scan_res.signal_dbm;
                existing.signal_percent = scan_res.signal_percent;
                existing.generation = scan_res.generation;
            }
        } else {
            ret.insert(ssid, scan_res);
        }
    }
}

fn sorted_scan_results(
    ret: HashMap<String, WifiScanResult>,
) -> Vec<WifiScanResult> {
    let mut ret: Vec<WifiScanResult> = ret.into_values().collect();
    // Sort by signal strength (strongest first), then SSID for a
    // deterministic output order.
    ret.sort_unstable_by(|a, b| {
        b.signal_percent
            .cmp(&a.signal_percent)
            .then_with(|| a.ssid.cmp(&b.ssid))
    });
    ret
}

fn extract_ssid(ies: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos + 2 <= ies.len() {
        let id = ies[pos];
        let len = ies[pos + 1] as usize;
        if id == 0 && pos + 2 + len <= ies.len() {
            return String::from_utf8(ies[pos + 2..pos + 2 + len].to_vec())
                .ok();
        }
        pos += 2 + len;
    }
    None
}

/// Detect the detailed auth type of the AP from its RSNE(Robust Security
/// Network Element). Returns `OPEN` when the network has no RSNE.
fn detect_auth_type(ies: &[u8]) -> WifiAuthTypeDetailed {
    let Ok(parsed) = Ieee80211Elements::parse(ies) else {
        return open_auth_type();
    };
    let elems = parsed.0;
    let rsn = elems.iter().find_map(|ie| match ie {
        Ieee80211Element::Rsn(rsn) => Some(rsn),
        _ => None,
    });
    let Some(rsn) = rsn else {
        // No RSNE: either an open network, or legacy security(WPA1/WEP)
        // which has no simplified `WifiAuthType`. Detect the WPA1 vendor
        // IE so such networks are not mislabeled as `OPEN`.
        if elems.iter().any(|ie| match ie {
            Ieee80211Element::Vendor(payload) => is_wpa1_vendor_ie(payload),
            _ => false,
        }) {
            // WPA1 is deprecated and has no simplified `WifiAuthType`.
            return WifiAuthTypeDetailed::default();
        }
        return open_auth_type();
    };

    let mut cipher = Vec::new();
    if let Some(group_cipher) = rsn.group_cipher {
        cipher.push(cipher_to_string(group_cipher));
    }
    for pairwise_cipher in &rsn.pairwise_ciphers {
        let c = cipher_to_string(*pairwise_cipher);
        if !cipher.contains(&c) {
            cipher.push(c);
        }
    }

    WifiAuthTypeDetailed::new(
        auth_type_from_akm(&rsn.akm_suits),
        rsn.akm_suits
            .iter()
            .map(|akm| akm_to_string(*akm))
            .collect(),
        cipher,
    )
}

fn open_auth_type() -> WifiAuthTypeDetailed {
    WifiAuthTypeDetailed::new(WifiAuthType::Open, Vec::new(), Vec::new())
}

/// WPA IE: vendor-specific element with OUI 00:50:F2 (Microsoft) and
/// OUI type 1 (WPA). Used by WPA1, which has no RSNE.
fn is_wpa1_vendor_ie(payload: &[u8]) -> bool {
    payload.len() >= 4
        && payload[0] == 0x00
        && payload[1] == 0x50
        && payload[2] == 0xf2
        && payload[3] == 0x01
}

/// Map the AKM suites advertised by the AP to the simplified auth type.
fn auth_type_from_akm(akm_suits: &[Ieee80211AkmSuite]) -> WifiAuthType {
    if akm_suits.iter().any(|akm| {
        matches!(
            akm,
            Ieee80211AkmSuite::Sae
                | Ieee80211AkmSuite::FtSae
                | Ieee80211AkmSuite::SaeGroupDependentHash
                | Ieee80211AkmSuite::FtSaeGroupDependentHash
        )
    }) {
        WifiAuthType::Wpa3Personal
    } else if akm_suits.iter().any(|akm| {
        matches!(
            akm,
            Ieee80211AkmSuite::Psk
                | Ieee80211AkmSuite::FtPsk
                | Ieee80211AkmSuite::PskSha256
                | Ieee80211AkmSuite::PskSha384
                | Ieee80211AkmSuite::FtPskSha384
        )
    }) {
        WifiAuthType::Wpa2Personal
    } else {
        // EAP(Enterprise) networks are not supported yet, report as Unknown.
        WifiAuthType::Unknown
    }
}

fn akm_to_string(akm: Ieee80211AkmSuite) -> String {
    match akm {
        Ieee80211AkmSuite::Ieee8021x => "802.1X".into(),
        Ieee80211AkmSuite::Psk => "PSK".into(),
        Ieee80211AkmSuite::FtIeee8021x => "FT-802.1X".into(),
        Ieee80211AkmSuite::FtPsk => "FT-PSK".into(),
        Ieee80211AkmSuite::Ieee8021xSha256 => "802.1X-SHA256".into(),
        Ieee80211AkmSuite::PskSha256 => "PSK-SHA256".into(),
        Ieee80211AkmSuite::Tdls => "TDLS".into(),
        Ieee80211AkmSuite::Sae => "SAE".into(),
        Ieee80211AkmSuite::FtSae => "FT-SAE".into(),
        Ieee80211AkmSuite::ApPeerKey => "AP-PEER-KEY".into(),
        Ieee80211AkmSuite::Ieee8021xSuiteB => "802.1X-SUITE-B".into(),
        Ieee80211AkmSuite::Ieee8021xCnsa => "802.1X-CNSA".into(),
        Ieee80211AkmSuite::FtIeee8021xSha384 => "FT-802.1X-SHA384".into(),
        Ieee80211AkmSuite::FilsSha256AesSiv256OrIeee8021x => {
            "FILS-SHA256".into()
        }
        Ieee80211AkmSuite::FilsSha384AesSiv512OrIeee8021x => {
            "FILS-SHA384".into()
        }
        Ieee80211AkmSuite::FtFilsSha256AesSiv256OrIeee8021x => {
            "FT-FILS-SHA256".into()
        }
        Ieee80211AkmSuite::FtFilsSha384AesSiv512OrIeee8021x => {
            "FT-FILS-SHA384".into()
        }
        Ieee80211AkmSuite::Owe => "OWE".into(),
        Ieee80211AkmSuite::FtPskSha384 => "FT-PSK-SHA384".into(),
        Ieee80211AkmSuite::PskSha384 => "PSK-SHA384".into(),
        Ieee80211AkmSuite::SaeGroupDependentHash => "SAE-GROUP-HASH".into(),
        Ieee80211AkmSuite::FtSaeGroupDependentHash => {
            "FT-SAE-GROUP-HASH".into()
        }
        Ieee80211AkmSuite::Other(d) => format!("0x{d:08x}"),
        _ => "UNKNOWN".into(),
    }
}

fn cipher_to_string(cipher: Ieee80211CipherSuite) -> String {
    match cipher {
        Ieee80211CipherSuite::UseGroup => "USE-GROUP".into(),
        Ieee80211CipherSuite::Wep40 => "WEP-40".into(),
        Ieee80211CipherSuite::Tkip => "TKIP".into(),
        Ieee80211CipherSuite::Ccmp128 => "CCMP".into(),
        Ieee80211CipherSuite::Wep104 => "WEP-104".into(),
        Ieee80211CipherSuite::BipCmac128 => "BIP-CMAC-128".into(),
        Ieee80211CipherSuite::GroupAddressedTrafficNotAllowed => {
            "GAT-NOT-ALLOWED".into()
        }
        Ieee80211CipherSuite::Gcmp128 => "GCMP".into(),
        Ieee80211CipherSuite::Gcmp256 => "GCMP-256".into(),
        Ieee80211CipherSuite::Ccmp256 => "CCMP-256".into(),
        Ieee80211CipherSuite::BipGmac128 => "BIP-GMAC-128".into(),
        Ieee80211CipherSuite::BipGmac256 => "BIP-GMAC-256".into(),
        Ieee80211CipherSuite::BipCmac256 => "BIP-CMAC-256".into(),
        Ieee80211CipherSuite::Other(d) => format!("0x{d:08x}"),
        _ => "UNKNOWN".into(),
    }
}

fn detect_generation(ies: &[u8]) -> Option<u32> {
    if let Ok(parsed) = Ieee80211Elements::parse(ies) {
        let elems = parsed.0;
        if elems
            .iter()
            .any(|ie| matches!(ie, Ieee80211Element::HeCapability(_)))
        {
            return Some(6);
        } else if elems
            .iter()
            .any(|ie| matches!(ie, Ieee80211Element::VhtCapability(_)))
        {
            return Some(5);
        } else if elems
            .iter()
            .any(|ie| matches!(ie, Ieee80211Element::HtCapability(_)))
        {
            return Some(4);
        }
    }
    None
}

fn mac_to_string(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
#[path = "unit_tests/scan.rs"]
mod test;
