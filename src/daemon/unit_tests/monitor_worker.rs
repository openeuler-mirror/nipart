// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant, SystemTime},
};

use futures_channel::mpsc::unbounded;
use nipart::{Interface, InterfaceLinkEvent, InterfaceType};
use rtnetlink::{
    packet_core::{Emitable, Parseable},
    packet_route::link::{
        LinkAttribute, LinkHeader, LinkLayerType, LinkMessage, WirelessEvent,
    },
};

use super::{
    EVENT_EXPIRE_TIME_SEC, LastLinkEvent, NipartMonitorCmd,
    NipartMonitorWorker, event_is_explicitly_down, format_mac,
    iface_identity_names, should_ignore_wireless_notification,
};
use crate::{daemon::NipartManagerCmd, task::TaskWorker};

fn gen_event(iface_name: &str) -> InterfaceLinkEvent {
    InterfaceLinkEvent::new(
        iface_name.to_string(),
        10,
        InterfaceType::Ethernet,
        true,
        None,
    )
}

fn gen_worker() -> NipartMonitorWorker {
    let (_tx, rx) = unbounded();
    tokio::runtime::Runtime::new()
        .expect("Failed to create tokio runtime")
        .block_on(NipartMonitorWorker::new(rx))
        .expect("Failed to create monitor worker")
}

fn gen_last_state(is_up: bool) -> LastLinkEvent {
    LastLinkEvent {
        is_up,
        iface_index: 10,
        iface_type: InterfaceType::Ethernet,
        extra_info: None,
        mac_address: None,
        time_stamp: SystemTime::now(),
    }
}

fn gen_expired_last_state(is_up: bool) -> LastLinkEvent {
    LastLinkEvent {
        is_up,
        iface_index: 10,
        iface_type: InterfaceType::Ethernet,
        extra_info: None,
        mac_address: None,
        time_stamp: SystemTime::now()
            - Duration::from_secs(EVENT_EXPIRE_TIME_SEC * 2),
    }
}

fn gen_wireless_link_msg(
    wifi_attr: WirelessEvent,
    with_other_attr: bool,
) -> LinkMessage {
    let header = LinkHeader {
        index: 2,
        link_layer_type: LinkLayerType::Ether,
        ..Default::default()
    };
    let mut attrs = vec![
        LinkAttribute::IfName("wlan0".to_string()),
        LinkAttribute::Wireless(wifi_attr),
    ];
    if with_other_attr {
        attrs.push(LinkAttribute::Address(vec![
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]));
    }
    let mut buf = vec![0; header.buffer_len() + attrs.as_slice().buffer_len()];
    header.emit(&mut buf);
    attrs.as_slice().emit(&mut buf[header.buffer_len()..]);
    LinkMessage::parse(&buf).expect("Failed to parse link message")
}

#[test]
fn test_format_mac() {
    assert_eq!(
        format_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x10]),
        Some("02:00:00:00:00:10".to_string())
    );
    // Addresses of other lengths (e.g. InfiniBand 20 bytes) cannot
    // match an ethernet MAC.
    assert_eq!(format_mac(&[0x00, 0x11]), None);
    assert_eq!(format_mac(&[]), None);
}

#[test]
fn test_ignore_wireless_only_scan_done_notification() {
    // The kernel emits an `IFLA_WIRELESS`-only RTM_NEWLINK carrying
    // `struct iw_event { len=16, cmd=SIOCGIWSCAN(0x8B19) }` when a
    // scan finishes. It is not a link-state change and must not be
    // turned into a link-up event (which would re-apply the saved
    // wifi config and restart DHCP).
    let scan_done = WirelessEvent::Other(vec![
        16, 0, 25, 139, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    assert!(should_ignore_wireless_notification(&gen_wireless_link_msg(
        scan_done.clone(),
        false
    )));

    // A real link message carrying other attributes (e.g. a link dump)
    // is kept even when it also carries a non-association wireless
    // attribute.
    assert!(!should_ignore_wireless_notification(
        &gen_wireless_link_msg(scan_done, true)
    ));
}

#[test]
fn test_keep_wireless_association_ie_notification() {
    // Association IE notifications are wireless-only but carry the
    // SSID of the new association and must be kept.
    let link_msg = gen_wireless_link_msg(
        WirelessEvent::AssociateResponse(vec![
            // SSID IE: element id 0, length 8, "Test-WIFI"
            0, 8, b'T', b'e', b's', b't', b'-', b'W', b'I', b'F', b'I',
        ]),
        false,
    );
    assert!(!should_ignore_wireless_notification(&link_msg));
}

#[test]
fn test_event_is_interested_by_mac_watch() {
    // A NIC matching a saved `identifier: mac-address` config carries a
    // kernel name unknown to the monitor: the event must be emitted
    // when its MAC address is watched.
    let mut worker = gen_worker();
    worker
        .mac_watch_list
        .insert("02:00:00:00:00:10".to_string());
    worker
        .iface_mac
        .insert("enp4s0".to_string(), "02:00:00:00:00:10".to_string());

    assert!(worker.event_is_interested(&gen_event("enp4s0")));

    // Same interface name with a different (unwatched) MAC: not
    // interested unless the name itself is monitored.
    worker
        .iface_mac
        .insert("enp4s0".to_string(), "02:00:00:00:00:03".to_string());
    assert!(!worker.event_is_interested(&gen_event("enp4s0")));

    // Interface without any observed MAC address.
    worker.iface_mac.remove("enp4s0");
    assert!(!worker.event_is_interested(&gen_event("enp4s0")));
}

#[test]
fn test_event_is_interested_by_name_or_wifi() {
    let mut worker = gen_worker();
    // Monitored by kernel name.
    worker.iface_monitor_list.insert("enp1s0".to_string());
    assert!(worker.event_is_interested(&gen_event("enp1s0")));
    assert!(!worker.event_is_interested(&gen_event("enp2s0")));

    // Wifi monitoring passes all wifi-phy events.
    worker.wifi_monitor_enabled = true;
    let wifi_event = InterfaceLinkEvent::new(
        "wlan0".to_string(),
        10,
        InterfaceType::WifiPhy,
        true,
        None,
    );
    assert!(worker.event_is_interested(&wifi_event));
    assert!(!worker.event_is_interested(&gen_event("enp2s0")));
}

#[test]
fn test_should_pause_and_resume_include_mac_watch() {
    let mut worker = gen_worker();
    assert!(worker.should_pause());
    assert!(!worker.should_resume());

    // A MAC watch alone keeps the netlink socket alive.
    worker
        .mac_watch_list
        .insert("02:00:00:00:00:10".to_string());
    assert!(!worker.should_pause());
    assert!(worker.should_resume());

    // Removing the last watch pauses again.
    worker.mac_watch_list.clear();
    assert!(worker.should_pause());
}

#[test]
fn test_pause_keeps_last_state_and_wifi_phys_emited() {
    let mut worker = gen_worker();
    worker
        .emited
        .insert("enp1s0".to_string(), gen_last_state(true));
    worker.wifi_phys_emited.insert("wlan0".to_string());
    worker.delay_queue.insert(
        "enp2s0".to_string(),
        (
            gen_event("enp2s0"),
            Instant::now() + Duration::from_secs(10),
        ),
    );
    worker
        .iface_mac
        .insert("enp3s0".to_string(), "02:00:00:00:00:03".to_string());

    worker.pause();

    assert!(worker.emited.contains_key("enp1s0"));
    assert!(worker.emited["enp1s0"].is_up);
    assert!(worker.delay_queue.is_empty());
    assert!(worker.iface_mac.is_empty());
    // The last link state and the announced wifi-phys survive pause/resume
    // so a fresh link dump is not treated as a new down->up transition.
    assert!(worker.wifi_phys_emited.contains("wlan0"));
}

#[test]
fn test_notify_marks_new_wifi_phy_only_once() {
    let mut worker = gen_worker();
    worker.wifi_monitor_enabled = true;
    let (tx, _rx) = unbounded();
    worker.msg_to_commander = Some(tx);
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut event = InterfaceLinkEvent::new(
        "wlan0".to_string(),
        10,
        InterfaceType::WifiPhy,
        true,
        None,
    );
    rt.block_on(worker.notify(event.clone())).unwrap();
    assert!(worker.wifi_phys_emited.contains("wlan0"));
    assert!(worker.emited["wlan0"].is_up);
    assert!(worker.emited["wlan0"].extra_info.is_none());

    // A later event for the same phy is a normal link event.
    event.is_up = false;
    rt.block_on(worker.notify(event.clone())).unwrap();
    assert!(!worker.emited["wlan0"].is_up);

    // A delete forgets the phy so a reappearance is announced again.
    event.is_delete = true;
    rt.block_on(worker.notify(event)).unwrap();
    assert!(!worker.wifi_phys_emited.contains("wlan0"));
    assert!(!worker.emited.contains_key("wlan0"));
}

#[test]
fn test_try_notify_dedups_duplicate_up_events() {
    let mut worker = gen_worker();
    let (tx, _rx) = unbounded();
    worker.msg_to_commander = Some(tx);
    worker.iface_monitor_list.insert("enp1s0".to_string());
    let rt = tokio::runtime::Runtime::new().unwrap();

    // No previous state: emit immediately.
    let up_event = gen_event("enp1s0");
    rt.block_on(worker.try_notify(up_event.clone())).unwrap();
    assert!(worker.emited["enp1s0"].is_up);
    assert!(!worker.delay_queue.contains_key("enp1s0"));

    // Already up: the duplicate is delayed instead of re-applied.
    rt.block_on(worker.try_notify(up_event)).unwrap();
    assert!(worker.delay_queue.contains_key("enp1s0"));

    // Down->up: emit immediately.
    worker.delay_queue.clear();
    worker
        .emited
        .insert("enp1s0".to_string(), gen_last_state(false));
    rt.block_on(worker.try_notify(gen_event("enp1s0"))).unwrap();
    assert!(worker.emited["enp1s0"].is_up);
    assert!(!worker.delay_queue.contains_key("enp1s0"));
}

#[test]
fn test_pause_stores_last_link_state_snapshot() {
    let mut worker = gen_worker();
    worker.iface_monitor_list.insert("enp1s0".to_string());
    worker
        .emited
        .insert("enp1s0".to_string(), gen_last_state(true));

    worker.pause();
    assert!(worker.paused_state.as_ref().unwrap()["enp1s0"].is_up);

    // A nested pause must keep the state captured before the netlink
    // session was dropped.
    worker
        .emited
        .insert("enp1s0".to_string(), gen_last_state(false));
    worker.pause();
    assert!(worker.paused_state.as_ref().unwrap()["enp1s0"].is_up);
}

#[test]
fn test_emit_on_resume_only_for_changed_links() {
    let mut worker = gen_worker();
    worker.iface_monitor_list.insert("enp1s0".to_string());
    worker.paused_state = Some(HashMap::from([(
        "enp1s0".to_string(),
        gen_last_state(true),
    )]));

    // The link did not change while the monitor was paused.
    assert!(!worker.emit_on_resume(&gen_event("enp1s0")));

    // The link went down while the monitor was paused.
    let down_event = InterfaceLinkEvent::new(
        "enp1s0".to_string(),
        10,
        InterfaceType::Ethernet,
        false,
        None,
    );
    assert!(worker.emit_on_resume(&down_event));

    // An interface unknown at pause time is emitted.
    assert!(worker.emit_on_resume(&gen_event("enp2s0")));

    // No pause snapshot (first link dump after start): emit.
    worker.paused_state = None;
    assert!(worker.emit_on_resume(&gen_event("enp1s0")));
}

#[test]
fn test_resume_event_diffs_against_pause_snapshot() {
    let mut worker = gen_worker();
    let (tx, mut rx) = unbounded();
    worker.msg_to_commander = Some(tx);
    worker.iface_monitor_list.insert("enp1s0".to_string());
    // The link has been up longer than the event expiry time: without the
    // pause snapshot comparison, the resume link dump would re-emit it.
    worker
        .emited
        .insert("enp1s0".to_string(), gen_expired_last_state(true));
    let rt = tokio::runtime::Runtime::new().unwrap();

    worker.pause();

    // Still up: unchanged during the pause, no event is emitted.
    rt.block_on(worker.handle_resume_event(gen_event("enp1s0")))
        .unwrap();
    assert!(rx.try_recv().is_err());

    // Went down during the pause: emitted.
    let down_event = InterfaceLinkEvent::new(
        "enp1s0".to_string(),
        10,
        InterfaceType::Ethernet,
        false,
        None,
    );
    rt.block_on(worker.handle_resume_event(down_event)).unwrap();
    assert!(rx.try_recv().is_ok());
}

#[test]
fn test_resume_emits_delete_for_iface_removed_while_paused() {
    let mut worker = gen_worker();
    let (tx, mut rx) = unbounded();
    worker.msg_to_commander = Some(tx);
    worker.iface_monitor_list.insert("enp1s0".to_string());
    // enp2s0 is tracked only by MAC watch.
    worker
        .mac_watch_list
        .insert("02:00:00:00:00:02".to_string());
    worker
        .emited
        .insert("enp1s0".to_string(), gen_last_state(true));
    worker.emited.insert(
        "enp2s0".to_string(),
        LastLinkEvent {
            is_up: true,
            iface_index: 11,
            iface_type: InterfaceType::Ethernet,
            extra_info: None,
            mac_address: Some("02:00:00:00:00:02".to_string()),
            time_stamp: SystemTime::now(),
        },
    );
    let rt = tokio::runtime::Runtime::new().unwrap();

    worker.pause();

    // enp1s0 is still in the resume link dump, enp2s0 disappeared.
    let seen_ifaces = HashSet::from(["enp1s0".to_string()]);
    rt.block_on(worker.handle_resume_deleted_ifaces(&seen_ifaces))
        .unwrap();

    let NipartManagerCmd::LinkEvent(event) = rx.try_recv().unwrap() else {
        panic!("Expected a link event");
    };
    assert!(event.is_delete);
    assert_eq!(event.iface_name, "enp2s0");
    assert_eq!(event.iface_index, 11);
    assert_eq!(event.iface_type, InterfaceType::Ethernet);
    assert!(rx.try_recv().is_err());

    // The delete cleaned the state of the gone interface; the interface
    // which is still present keeps its state.
    assert!(!worker.emited.contains_key("enp2s0"));
    assert!(worker.emited.contains_key("enp1s0"));
    // The pause snapshot was consumed by the reconciliation.
    assert!(worker.paused_state.is_none());
}

#[test]
fn test_emit_on_resume_wifi_ssid_change() {
    let mut worker = gen_worker();
    worker.wifi_monitor_enabled = true;
    worker.paused_state = Some(HashMap::from([(
        "wlan0".to_string(),
        LastLinkEvent {
            is_up: true,
            iface_index: 10,
            iface_type: InterfaceType::WifiPhy,
            extra_info: Some("Test-WIFI-A".to_string()),
            mac_address: None,
            time_stamp: SystemTime::now(),
        },
    )]));

    // A link dump carries no SSID and cannot prove the SSID changed.
    let no_ssid_event = InterfaceLinkEvent::new(
        "wlan0".to_string(),
        10,
        InterfaceType::WifiPhy,
        true,
        None,
    );
    assert!(!worker.emit_on_resume(&no_ssid_event));

    // Same SSID: unchanged.
    let same_ssid_event = InterfaceLinkEvent::new(
        "wlan0".to_string(),
        10,
        InterfaceType::WifiPhy,
        true,
        Some("Test-WIFI-A".to_string()),
    );
    assert!(!worker.emit_on_resume(&same_ssid_event));

    // A new SSID is a state change even when the link never went down.
    let new_ssid_event = InterfaceLinkEvent::new(
        "wlan0".to_string(),
        10,
        InterfaceType::WifiPhy,
        true,
        Some("Test-WIFI-B".to_string()),
    );
    assert!(worker.emit_on_resume(&new_ssid_event));
}

#[test]
fn test_down_then_quick_up_emits_up_event() {
    let mut worker = gen_worker();
    let (tx, _rx) = unbounded();
    worker.msg_to_commander = Some(tx);
    worker.iface_monitor_list.insert("enp1s0".to_string());
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(worker.try_notify(gen_event("enp1s0"))).unwrap();
    assert!(worker.emited["enp1s0"].is_up);

    // A down event is debounced, but must update the last known state so
    // the reconnect within the debounce window is not dropped as a
    // duplicate up event.
    let down_event = InterfaceLinkEvent::new(
        "enp1s0".to_string(),
        10,
        InterfaceType::Ethernet,
        false,
        None,
    );
    rt.block_on(worker.try_notify(down_event)).unwrap();
    assert!(!worker.emited["enp1s0"].is_up);
    assert!(worker.delay_queue.contains_key("enp1s0"));

    rt.block_on(worker.try_notify(gen_event("enp1s0"))).unwrap();
    assert!(worker.emited["enp1s0"].is_up);
    assert!(!worker.delay_queue.contains_key("enp1s0"));
}

#[test]
fn test_explicit_down_updates_last_state_for_later_up() {
    let mut worker = gen_worker();
    let (tx, _rx) = unbounded();
    worker.msg_to_commander = Some(tx);
    worker.iface_monitor_list.insert("enp1s0".to_string());
    worker.explicitly_down.insert("enp1s0".to_string());
    worker
        .emited
        .insert("enp1s0".to_string(), gen_last_state(true));
    let rt = tokio::runtime::Runtime::new().unwrap();

    // `npt down` suppresses the down event, but the monitor must remember
    // that the interface is down so a later `npt up` link dump is treated
    // as a real down->up transition.
    let down_event = InterfaceLinkEvent::new(
        "enp1s0".to_string(),
        10,
        InterfaceType::Ethernet,
        false,
        None,
    );
    rt.block_on(worker.try_notify(down_event)).unwrap();
    assert!(!worker.emited["enp1s0"].is_up);
    assert!(!worker.delay_queue.contains_key("enp1s0"));

    worker.explicitly_down.clear();
    rt.block_on(worker.try_notify(gen_event("enp1s0"))).unwrap();
    assert!(worker.emited["enp1s0"].is_up);
    assert!(!worker.delay_queue.contains_key("enp1s0"));
}

#[test]
fn test_pause_keeps_explicit_down_list() {
    // The explicit-down marker must survive the monitor pause/resume
    // cycle around `npt down`, otherwise the link dump emitted on resume
    // would re-apply the saved config.
    let mut worker = gen_worker();
    worker.explicitly_down.insert("enp1s0".to_string());

    worker.pause();

    assert!(worker.explicitly_down.contains("enp1s0"));
}

#[test]
fn test_pause_resume_nested_requires_matching_resume() {
    // `load_saved_state()` pauses the monitor for the whole boot pass while
    // every apply inside it pauses again. A nested resume must not start the
    // netlink socket (and emit a fresh link dump) before the outer pause is
    // released.
    let mut worker = gen_worker();
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(worker.process_cmd(NipartMonitorCmd::Pause))
        .unwrap();
    assert_eq!(worker.manual_pause_count, 1);

    rt.block_on(worker.process_cmd(NipartMonitorCmd::Pause))
        .unwrap();
    assert_eq!(worker.manual_pause_count, 2);

    rt.block_on(worker.process_cmd(NipartMonitorCmd::Resume))
        .unwrap();
    assert_eq!(worker.manual_pause_count, 1);
    assert!(worker.netlink_handle.is_none());

    rt.block_on(worker.process_cmd(NipartMonitorCmd::Resume))
        .unwrap();
    assert_eq!(worker.manual_pause_count, 0);
    assert!(worker.netlink_handle.is_none());
}

#[test]
fn test_iface_identity_names_include_profile_and_kernel_names() {
    let iface: Interface = rmsd_yaml::from_str(
        r#"---
            name: eth9
            kernel-iface-name: eth9
            profile-name: wan9
            type: ethernet
            state: up
            "#,
    )
    .unwrap();

    let names = iface_identity_names(&iface);
    assert!(names.iter().any(|name| name == "eth9"));
    assert!(names.iter().any(|name| name == "wan9"));
}

#[test]
fn test_event_is_explicitly_down_matches_iface_and_ssid() {
    let explicitly_down =
        HashSet::from(["eth9".to_string(), "Test-WIFI".to_string()]);

    let iface_event = gen_event("eth9");
    assert!(event_is_explicitly_down(&iface_event, &explicitly_down));

    let mut wifi_event = gen_event("wlan0");
    wifi_event.ssid = Some("Test-WIFI".to_string());
    assert!(event_is_explicitly_down(&wifi_event, &explicitly_down));

    assert!(!event_is_explicitly_down(
        &gen_event("enp1s0"),
        &explicitly_down
    ));
}
