// SPDX-License-Identifier: Apache-2.0

mod dhcp_manager;
mod dhcp_worker;
mod dhcpv6_manager;
mod dhcpv6_worker;

use std::{collections::HashSet, time::Duration};

use nipart::{
    ErrorKind, Interface, MergedInterface, MergedInterfaces, NipartError,
    NipartInterface, NipartNoDaemon, NipartQueryOption,
    NipartWifiConnectErrorOption, WifiCfgInterface, WifiPhyInterface,
};

pub(crate) use self::{
    dhcp_manager::NipartDhcpV4Manager,
    dhcp_worker::{NipartDhcpCmd, NipartDhcpReply, NipartDhcpV4Worker},
    dhcpv6_manager::NipartDhcpV6Manager,
    dhcpv6_worker::{NipartDhcpV6Cmd, NipartDhcpV6Reply, NipartDhcpV6Worker},
};
use crate::plugin::NipartPluginManager;

const WIFI_SSID_WAIT_TIMEOUT_SECS: u64 = 60;

/// Whether the apply changed the SSID of a wifi-phy.
///
/// The link-up event path synthesizes a wifi-phy from a saved wifi-cfg to
/// carry the IP config; that synthetic interface intentionally has no
/// `wifi` section.  Without a desired SSID we cannot claim an SSID change,
/// otherwise every repeated up event would tear down a healthy DHCP lease.
pub(crate) fn wifi_ssid_changed(
    current: Option<&Interface>,
    desired: Option<&Interface>,
) -> bool {
    match (current, desired) {
        (Some(Interface::WifiPhy(cur)), Some(Interface::WifiPhy(des))) => des
            .ssid()
            .is_some_and(|des_ssid| cur.ssid() != Some(des_ssid)),
        _ => false,
    }
}

/// Whether the `wifi-cfg` profiles handed to a wifi-phy switch its SSID.
///
/// A `wifi-cfg` is userspace-only: the kernel phy only receives a
/// name/type up marker, so `wifi_ssid_changed()` cannot see the profile
/// SSID.  When the apply hands a single SSID to this phy through
/// `wifi-cfg` profiles, the plugin will associate the phy with it and a
/// DHCP client still renewing the previous network's lease has to be
/// restarted.  An apply carrying several different SSIDs (e.g. the boot
/// pass handing over all saved profiles) has no single target SSID, hence
/// keeps relying on the link event path.
pub(crate) fn wifi_cfg_ssid_changed(
    ifaces: &MergedInterfaces,
    merged_iface: &MergedInterface,
) -> bool {
    let Some(Interface::WifiPhy(cur_phy)) = merged_iface.current.as_ref()
    else {
        return false;
    };
    // An explicit desired wifi-phy SSID is covered by
    // `wifi_ssid_changed()`.
    if matches!(
        merged_iface.desired.as_ref(),
        Some(Interface::WifiPhy(des_phy)) if des_phy.ssid().is_some()
    ) {
        return false;
    }
    wifi_cfg_apply_ssid(ifaces, cur_phy)
        .is_some_and(|ssid| cur_phy.ssid() != Some(ssid.as_str()))
}

/// The SSID this apply wants on the wifi-phy of `merged_iface`.
///
/// This is the explicit desired wifi-phy `wifi` section when present,
/// otherwise the SSID shared by the `wifi-cfg` profiles handed to the phy.
pub(crate) fn desired_ssid_for_phy(
    ifaces: &MergedInterfaces,
    merged_iface: &MergedInterface,
) -> Option<String> {
    if let Some(Interface::WifiPhy(des_phy)) = merged_iface.desired.as_ref()
        && let Some(ssid) = des_phy.ssid()
    {
        return Some(ssid.to_string());
    }
    let Interface::WifiPhy(cur_phy) = merged_iface.current.as_ref()? else {
        return None;
    };
    wifi_cfg_apply_ssid(ifaces, cur_phy)
}

/// The single SSID this apply hands to `phy` via `wifi-cfg` profiles.
///
/// `None` means the apply does not hand over any profile, or it hands
/// over profiles with different SSIDs, where nipart cannot tell which
/// SSID the phy will end up on.
fn wifi_cfg_apply_ssid(
    ifaces: &MergedInterfaces,
    phy: &WifiPhyInterface,
) -> Option<String> {
    let mut ssids: HashSet<&str> = HashSet::new();
    for merged_iface in ifaces.user_ifaces.values() {
        let Some(Interface::WifiCfg(wifi_cfg)) =
            merged_iface.for_apply.as_ref()
        else {
            continue;
        };
        if !wifi_cfg.is_up() || !wifi_cfg_targets_phy(wifi_cfg, phy) {
            continue;
        }
        if let Some(ssid) = wifi_cfg.ssid() {
            ssids.insert(ssid);
        }
    }
    if ssids.len() == 1 {
        ssids.iter().next().map(|ssid| (*ssid).to_string())
    } else {
        None
    }
}

/// Whether the `wifi-cfg` profile targets `phy`: a profile without
/// `base-iface` is bound to any wifi-phy.
fn wifi_cfg_targets_phy(
    wifi_cfg: &WifiCfgInterface,
    phy: &WifiPhyInterface,
) -> bool {
    let Some(base_iface) = wifi_cfg.parent() else {
        return true;
    };
    base_iface == phy.kernel_iface_name()
        || base_iface == phy.name()
        || phy
            .base
            .mac_address
            .as_deref()
            .is_some_and(|mac| mac.eq_ignore_ascii_case(base_iface))
}

/// Whether an apply should touch the DHCP client of an interface.
///
/// A merge diff can be caused by saved-only fields (e.g. `profile-name`)
/// that do not require any DHCP change. `restart_auto_ip` applies and SSID
/// changes still restart DHCP even when the IP diff omitted the unchanged
/// DHCP settings; interfaces going down always need their DHCP client
/// stopped.
pub(crate) fn should_touch_dhcp(
    restart_auto_ip: bool,
    ssid_changed: bool,
    ip_conf_changed: bool,
    iface_is_up: bool,
) -> bool {
    !iface_is_up || restart_auto_ip || ssid_changed || ip_conf_changed
}

/// Wait until the wifi-phy reports the desired SSID.
///
/// Used when an apply switches a wifi-phy to a different SSID: DHCP must
/// not start until the new association is up, otherwise the client can
/// still receive a lease from the old network.
pub(crate) async fn wait_wifi_ssid(
    iface_name: &str,
    ssid: &str,
    plugin_manager: &mut NipartPluginManager,
) -> Result<(), NipartError> {
    let deadline = std::time::Instant::now()
        + Duration::from_secs(WIFI_SSID_WAIT_TIMEOUT_SECS);
    loop {
        // A plugin-diagnosed failure (e.g. shuli: `NoSupport: TKIP WPA2
        // is not supported`) fails the wait immediately with the real
        // reason instead of polling until the timeout.
        if let Err(e) = plugin_manager
            .wifi_connect_error(&NipartWifiConnectErrorOption::new(
                iface_name, ssid,
            ))
            .await
        {
            if e.kind() == ErrorKind::NoSupport {
                return Err(e);
            }
            log::debug!(
                "wifi connection error query on {iface_name}/{ssid}: {e}"
            );
        }
        let mut state =
            NipartNoDaemon::query_network_state(NipartQueryOption::running())
                .await?;
        if wifi_state_has_ssid(&state, iface_name, ssid) || {
            // mac80211_hwsim and some drivers do not expose the
            // association SSID through nispor in time, while the wifi
            // plugin's shuli client already knows it is connected.
            let plugin_states = plugin_manager
                .query_network_state(NipartQueryOption::running(), &state)
                .await?;
            for plugin_state in plugin_states {
                state.merge(&plugin_state)?;
            }
            wifi_state_has_ssid(&state, iface_name, ssid)
        } {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(NipartError::new(
        ErrorKind::Timeout,
        format!(
            "Timed out waiting for wifi SSID {ssid} on interface {iface_name}"
        ),
    ))
}

fn wifi_state_has_ssid(
    state: &nipart::NetworkState,
    iface_name: &str,
    ssid: &str,
) -> bool {
    state
        .ifaces
        .kernel_ifaces
        .get(iface_name)
        .and_then(|iface| {
            if let Interface::WifiPhy(wifi_iface) = iface {
                wifi_iface.ssid()
            } else {
                None
            }
        })
        == Some(ssid)
}

#[cfg(test)]
#[path = "../unit_tests/dhcp.rs"]
mod tests;
