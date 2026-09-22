// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    io::Read,
    time::{Duration, Instant, SystemTime},
};

use futures_channel::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot::Sender,
};
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use nipart::{
    ErrorKind, Interface, InterfaceLinkEvent, InterfaceType, NipartError,
    NipartInterface,
};
use rtnetlink::{
    MulticastGroup, new_multicast_connection,
    packet_core::{NetlinkMessage, NetlinkPayload},
    packet_route::{
        RouteNetlinkMessage,
        link::{
            InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType,
            LinkMessage, WirelessEvent,
        },
    },
    sys::SocketAddr,
};
use wl_nl80211::{Ieee80211Element, Ieee80211Elements, packet_core::Parseable};

use super::super::{daemon::NipartManagerCmd, task::TaskWorker};

// When the same event happens, when should we consider previous event expired.
const EVENT_EXPIRE_TIME_SEC: u64 = 300;

// When the event changed to down, we wait 10 seconds to prevent flipping
const DOWN_WAIT_SEC: u64 = 10;
// Check delay queue event every second if delay_queue is not empty
const DELAY_TICK_SEC_IF_BUSY: u64 = 1;
// Check delay queue event every day if delay_queue is empty, we cannot use
// Duration::MAX which will cause overflow on Interval::reset_after()
const DELAY_TICK_SEC_IF_FREE: u64 = 24 * 60 * 60;

/// Compact last link state kept for pause/resume reconciliation and
/// duplicate event deduplication.
///
/// Unlike the full netlink event, this survives the netlink session being
/// dropped on monitor pause, so the next link dump can distinguish a real
/// state change from a duplicate event of an interface that did not change.
#[derive(Debug, Clone)]
struct LastLinkEvent {
    is_up: bool,
    iface_index: u32,
    iface_type: InterfaceType,
    /// SSID of a wifi-phy association event; `None` when the netlink
    /// message carried no association IEs (e.g. a link dump) or the
    /// interface is not a wifi-phy.
    /// Future: link-local address when DHCPv6 must restart after the
    /// address changes.
    extra_info: Option<String>,
    /// MAC observed for the interface.  Kept so a delete event synthesized
    /// for an interface which disappeared while the monitor was paused can
    /// still match `mac_watch_list`.
    mac_address: Option<String>,
    time_stamp: SystemTime,
}

impl LastLinkEvent {
    fn from_event(
        event: &InterfaceLinkEvent,
        mac_address: Option<String>,
    ) -> Self {
        Self {
            is_up: event.is_up,
            iface_index: event.iface_index,
            iface_type: event.iface_type.clone(),
            extra_info: event_extra_info(event),
            mac_address,
            time_stamp: event.time_stamp,
        }
    }

    /// Whether `event` reports the same link state as this event.
    ///
    /// A wifi-phy event without SSID (e.g. the link dump after a monitor
    /// resume) cannot tell whether the SSID changed, so it counts as
    /// unchanged.  An association event carrying a different SSID is a
    /// change even though the link never went down.
    fn is_same_state(&self, event: &InterfaceLinkEvent) -> bool {
        if self.is_up != event.is_up {
            return false;
        }
        match event_extra_info(event) {
            None => true,
            Some(extra_info) => {
                self.extra_info.as_deref() == Some(extra_info.as_str())
            }
        }
    }

    /// Build the delete event for an interface which disappeared while the
    /// monitor was paused.
    fn to_delete_event(&self, iface_name: &str) -> InterfaceLinkEvent {
        let mut event = InterfaceLinkEvent::new(
            iface_name.to_string(),
            self.iface_index,
            self.iface_type.clone(),
            false,
            self.extra_info.clone(),
        );
        event.is_delete = true;
        event
    }
}

fn event_extra_info(event: &InterfaceLinkEvent) -> Option<String> {
    if event.iface_type == InterfaceType::WifiPhy {
        event.ssid.clone()
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub(crate) enum NipartMonitorCmd {
    /// Set the sender for monitor to contact commander. Must be invoked
    /// right after NipartMonitorWorker started.
    SetCommanderSender(UnboundedSender<NipartManagerCmd>),
    /// Start monitoring on specified interface
    AddIface(String),
    /// Stop monitoring on specified interface
    DelIface(String),
    /// Start monitoring on specified MAC address (uppercase, e.g.
    /// `02:00:00:00:00:03`): link events of interfaces carrying this MAC
    /// are emitted even when their kernel name is not known yet (saved
    /// `identifier: mac-address` configs whose NIC is not present at boot).
    AddMacWatch(String),
    /// Stop monitoring on specified MAC address
    DelMacWatch(String),
    /// Start monitoring on WIFI SSID association
    EnableWifiMonitor,
    /// Stop monitoring on WIFI SSID association
    DisableWifiMonitor,
    /// Stop the monitoring but preserving the internal monitoring list.
    /// Nested pauses require the same number of resumes before monitoring
    /// restarts.
    Pause,
    /// Resume the monitoring, emit current status of monitoring
    /// interface list.
    Resume,
    /// Record that an interface/profile was explicitly brought down by
    /// `npt down`.  Link events of these interfaces must not be forwarded
    /// to the event worker until `npt up` clears the marker.
    MarkExplicitlyDown(Vec<String>),
    /// Forget that an interface/profile was explicitly brought down.
    ClearExplicitlyDown(Vec<String>),
}

impl std::fmt::Display for NipartMonitorCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetCommanderSender(_) => {
                write!(f, "set-commander-sender")
            }
            Self::AddIface(iface) => {
                write!(f, "start-iface-monitor:{iface}")
            }
            Self::DelIface(iface) => {
                write!(f, "stop-iface-monitor:{iface}")
            }
            Self::AddMacWatch(mac) => {
                write!(f, "start-mac-monitor:{mac}")
            }
            Self::DelMacWatch(mac) => {
                write!(f, "stop-mac-monitor:{mac}")
            }
            Self::EnableWifiMonitor => {
                write!(f, "enable-wifi-monitor")
            }
            Self::DisableWifiMonitor => {
                write!(f, "disable-wifi-monitor")
            }
            Self::Pause => {
                write!(f, "pause-monitor")
            }
            Self::Resume => {
                write!(f, "resume-monitor")
            }
            Self::MarkExplicitlyDown(ifaces) => {
                write!(f, "mark-explicitly-down:{ifaces:?}")
            }
            Self::ClearExplicitlyDown(ifaces) => {
                write!(f, "clear-explicitly-down:{ifaces:?}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NipartMonitorReply {
    None,
}

type FromManager = (
    NipartMonitorCmd,
    Sender<Result<NipartMonitorReply, NipartError>>,
);

#[derive(Debug)]
pub(crate) struct NipartMonitorWorker {
    receiver: UnboundedReceiver<FromManager>,
    netlink_handle: Option<rtnetlink::Handle>,
    netlink_msg_receiver: Option<
        UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>,
    >,
    iface_monitor_list: HashSet<String>,
    // MAC addresses (uppercase) of saved `identifier: mac-address` configs
    // whose NIC is not present yet: when a NIC carrying one of these MACs
    // appears, its link events are emitted so the event worker can apply
    // the saved config.
    mac_watch_list: HashSet<String>,
    // Latest MAC address (uppercase) observed per kernel interface name,
    // used to match link events against `mac_watch_list`.
    iface_mac: HashMap<String, String>,
    wifi_monitor_enabled: bool,
    msg_to_commander: Option<UnboundedSender<NipartManagerCmd>>,
    /// Number of outstanding `Pause` requests. `Pause`/`Resume` calls may
    /// nest (e.g. the boot load pauses the monitor while every apply inside
    /// it also pauses), so the monitor stays down until the last matching
    /// `Resume` is issued.
    manual_pause_count: u32,
    /// Interface/profile aliases explicitly brought down by `npt down`.
    /// Link events for these interfaces are dropped at the monitor worker so
    /// the event worker cannot re-apply the saved config and its routes.
    explicitly_down: HashSet<String>,
    emited: HashMap<String, LastLinkEvent>,
    /// Link state captured when the monitor paused, keyed by kernel
    /// interface name.  The link dump of the next `resume()` reconciles
    /// against this snapshot: only interfaces whose state changed while
    /// the monitor was paused are emitted.  `None` means no pause has
    /// been captured yet.
    paused_state: Option<HashMap<String, LastLinkEvent>>,
    /// Wifi-phys whose first event has already been sent to the event
    /// worker. Kept across pause/resume so an existing phy is not announced
    /// as new after every apply; removed on interface delete so a later
    /// reappearance is announced again.
    wifi_phys_emited: HashSet<String>,
    delay_queue: HashMap<String, (InterfaceLinkEvent, Instant)>,
}

impl TaskWorker for NipartMonitorWorker {
    type Cmd = NipartMonitorCmd;
    type Reply = NipartMonitorReply;

    async fn new(
        receiver: UnboundedReceiver<FromManager>,
    ) -> Result<Self, NipartError> {
        Ok(Self {
            receiver,
            iface_monitor_list: HashSet::new(),
            mac_watch_list: HashSet::new(),
            iface_mac: HashMap::new(),
            wifi_monitor_enabled: false,
            netlink_handle: None,
            netlink_msg_receiver: None,
            manual_pause_count: 0,
            msg_to_commander: None,
            explicitly_down: HashSet::new(),
            emited: HashMap::new(),
            paused_state: None,
            wifi_phys_emited: HashSet::new(),
            delay_queue: HashMap::new(),
        })
    }

    fn receiver(&mut self) -> &mut UnboundedReceiver<FromManager> {
        &mut self.receiver
    }

    async fn process_cmd(
        &mut self,
        cmd: NipartMonitorCmd,
    ) -> Result<NipartMonitorReply, NipartError> {
        log::debug!("Processing monitor command: {cmd}");
        match cmd {
            NipartMonitorCmd::SetCommanderSender(sender) => {
                self.msg_to_commander = Some(sender);
            }
            NipartMonitorCmd::AddIface(iface) => {
                self.iface_monitor_list.insert(iface);
                if self.should_start_netlink() {
                    self.resume().await?;
                }
            }
            NipartMonitorCmd::DelIface(iface) => {
                self.iface_monitor_list.remove(&iface);
                if self.should_pause() {
                    self.pause();
                }
            }
            NipartMonitorCmd::AddMacWatch(mac) => {
                self.mac_watch_list.insert(mac.to_ascii_uppercase());
                if self.should_start_netlink() {
                    self.resume().await?;
                }
            }
            NipartMonitorCmd::DelMacWatch(mac) => {
                self.mac_watch_list.remove(&mac.to_ascii_uppercase());
                if self.should_pause() {
                    self.pause();
                }
            }
            NipartMonitorCmd::EnableWifiMonitor => {
                self.wifi_monitor_enabled = true;
                if self.should_start_netlink() {
                    self.resume().await?;
                }
            }
            NipartMonitorCmd::DisableWifiMonitor => {
                self.wifi_monitor_enabled = false;
                if self.should_pause() {
                    self.pause();
                }
            }
            NipartMonitorCmd::Pause => {
                self.manual_pause_count =
                    self.manual_pause_count.saturating_add(1);
                self.pause();
            }
            NipartMonitorCmd::Resume => {
                self.manual_pause_count =
                    self.manual_pause_count.saturating_sub(1);
                if self.manual_pause_count == 0
                    && self.should_resume()
                    && self.should_start_netlink()
                {
                    self.resume().await?;
                }
            }
            NipartMonitorCmd::MarkExplicitlyDown(names) => {
                self.explicitly_down.extend(names);
            }
            NipartMonitorCmd::ClearExplicitlyDown(names) => {
                for name in names {
                    self.explicitly_down.remove(&name);
                }
            }
        }
        Ok(NipartMonitorReply::None)
    }

    async fn run(&mut self) {
        let mut ticker =
            tokio::time::interval(Duration::from_secs(DELAY_TICK_SEC_IF_BUSY));
        // First tick happen immediately
        ticker.tick().await;
        loop {
            if self.delay_queue.is_empty() {
                ticker.reset_after(Duration::from_secs(DELAY_TICK_SEC_IF_FREE));
            } else {
                ticker.reset_after(Duration::from_secs(DELAY_TICK_SEC_IF_BUSY));
            }
            if let Some(mut netlink_msg_receiver) =
                self.netlink_msg_receiver.take()
            {
                tokio::select! {
                    cmd_result = self.recv_cmd() => {
                        if let Some((cmd, sender)) = cmd_result {
                            let cmd_str = cmd.to_string();
                            let result = self.process_cmd(cmd).await;
                            if sender.send(result).is_err() {
                                log::error!(
                                    "Failed to send reply for command {cmd_str}"
                                );
                            }
                        } else {
                            break;
                        }
                    }
                    result = netlink_msg_receiver.next() => {
                        if let Some((nl_msg, _)) = result
                            && let Err(e) = self.process_rtnl_message(
                                nl_msg,
                            ).await {
                                log::error!("{e}");
                            }
                    }
                    _ = ticker.tick() => {
                        if let Err(e) = self.process_delay_queue().await {
                            log::error!("{e}");
                        }
                    }
                }
                if self.manual_pause_count == 0 {
                    self.netlink_msg_receiver = Some(netlink_msg_receiver);
                }
            } else if let Some((cmd, sender)) = self.recv_cmd().await {
                let cmd_str = cmd.to_string();
                let result = self.process_cmd(cmd).await;
                if sender.send(result).is_err() {
                    log::error!("Failed to send reply for command {cmd_str}");
                }
            } else {
                break;
            }
        }
    }
}

impl NipartMonitorWorker {
    /// Whether the netlink socket should be dropped: no interface, no MAC
    /// watch and no wifi monitoring left.
    fn should_pause(&self) -> bool {
        self.iface_monitor_list.is_empty()
            && self.mac_watch_list.is_empty()
            && !self.wifi_monitor_enabled
    }

    /// Whether the netlink socket should be (re)created: at least one
    /// interface, one MAC watch or wifi monitoring is active.
    fn should_resume(&self) -> bool {
        !self.iface_monitor_list.is_empty()
            || !self.mac_watch_list.is_empty()
            || self.wifi_monitor_enabled
    }

    /// Whether a new netlink multicast connection should be created.
    ///
    /// `netlink_msg_receiver` is temporarily moved out of the worker while
    /// `run()` polls it with `tokio::select!`, so it cannot be used as the
    /// "socket is active" check from `process_cmd()`. The handle remains
    /// set for the whole active period.
    fn should_start_netlink(&self) -> bool {
        self.manual_pause_count == 0 && self.netlink_handle.is_none()
    }

    /// Whether the resume link dump must emit `event`.
    ///
    /// [`Self::pause`] captured the link state known at pause time; only
    /// interfaces whose state differs from that snapshot (or were unknown
    /// then) are emitted.  Without a snapshot (e.g. the first link dump
    /// after start), every event is emitted.
    fn emit_on_resume(&self, event: &InterfaceLinkEvent) -> bool {
        self.paused_state.as_ref().is_none_or(|paused_state| {
            paused_state
                .get(&event.iface_name)
                .is_none_or(|last| !last.is_same_state(event))
        })
    }

    /// Build the compact link-state record for `event`, attaching the MAC
    /// observed for the interface when available.
    fn last_link_event(&self, event: &InterfaceLinkEvent) -> LastLinkEvent {
        LastLinkEvent::from_event(
            event,
            self.iface_mac.get(&event.iface_name).cloned(),
        )
    }

    /// Handle one link event from the resume link dump.
    ///
    /// Interfaces which did not change since [`Self::pause`] are dropped;
    /// changed (or previously unknown) interfaces go through the normal
    /// notification path.
    async fn handle_resume_event(
        &mut self,
        event: InterfaceLinkEvent,
    ) -> Result<(), NipartError> {
        if !self.emit_on_resume(&event) {
            log::trace!(
                "{}: link state is unchanged since monitor pause, no event \
                 emitted",
                event.iface_name
            );
            return Ok(());
        }
        self.try_notify(event).await
    }

    /// Emit delete events for interfaces which existed when the monitor
    /// paused but are absent from the resume link dump.
    ///
    /// The event worker uses these to clean up the interface state and to
    /// re-arm the saved monitors, so a NIC which reappears (possibly under
    /// a different kernel name) gets its saved config applied again.
    async fn handle_resume_deleted_ifaces(
        &mut self,
        seen_ifaces: &HashSet<String>,
    ) -> Result<(), NipartError> {
        let Some(paused_state) = self.paused_state.take() else {
            return Ok(());
        };
        for (iface_name, last_event) in paused_state {
            if seen_ifaces.contains(&iface_name) {
                continue;
            }
            // The link dump no longer carries this interface's MAC, so
            // restore it to let the delete event match a MAC watch.
            if let Some(mac) = last_event.mac_address.clone() {
                self.iface_mac.insert(iface_name.clone(), mac);
            }
            log::trace!(
                "{iface_name}: interface disappeared while monitor paused, \
                 emitting delete event"
            );
            let event = last_event.to_delete_event(&iface_name);
            self.try_notify(event).await?;
            self.iface_mac.remove(&iface_name);
        }
        Ok(())
    }

    fn pause(&mut self) {
        // Capture the link state known at pause time.  The next resume
        // link dump is compared against it, so interfaces which did not
        // change while the monitor was paused are not emitted again
        // (otherwise the event worker would re-apply their saved config
        // and restart their DHCP clients after every unrelated apply).
        // Only the outermost pause captures: nested pauses happen while
        // the netlink session is already down and must keep the state
        // from before the whole paused period.
        if self.paused_state.is_none() {
            self.paused_state = Some(self.emited.clone());
        }
        self.netlink_handle = None;
        self.netlink_msg_receiver = None;
        // The netlink session is over, but the last known link state is kept
        // on purpose: after the next resume, the link dump must be able to
        // distinguish a real down->up transition from a duplicate up event.
        // Without this, every managed interface would be re-applied and its
        // DHCP client restarted after each unrelated `npt up`.
        self.delay_queue.clear();
        self.iface_mac.clear();
    }

    async fn notify(
        &mut self,
        mut event: InterfaceLinkEvent,
    ) -> Result<(), NipartError> {
        let is_wifi_phy = self.wifi_monitor_enabled
            && event.iface_type == InterfaceType::WifiPhy;
        if event.is_delete {
            self.wifi_phys_emited.remove(&event.iface_name);
        } else if is_wifi_phy
            && !self.wifi_phys_emited.contains(&event.iface_name)
        {
            event.is_new_wifi_phy = true;
            log::debug!(
                "New wifi-phy {}(ifindex {}) detected, notifying event worker",
                event.iface_name,
                event.iface_index
            );
        }
        log::trace!("NipartMonitorWorker sending out {event:?}");
        if let Some(sender) = self.msg_to_commander.as_mut() {
            let cmd = NipartManagerCmd::LinkEvent(Box::new(event.clone()));
            sender.send(cmd).await.map_err(|e| {
                NipartError::new(
                    ErrorKind::Bug,
                    format!(
                        "NipartMonitorWorker: Failed to send to commander: {e}"
                    ),
                )
            })?;
            // Remove event on delay_queue also
            self.delay_queue.remove(&event.iface_name);
            if event.is_delete {
                self.emited.remove(&event.iface_name);
                self.wifi_phys_emited.remove(&event.iface_name);
            } else {
                if event.is_new_wifi_phy {
                    self.wifi_phys_emited.insert(event.iface_name.to_string());
                }
                let last_event = self.last_link_event(&event);
                self.emited.insert(event.iface_name.to_string(), last_event);
            }
            Ok(())
        } else {
            Err(NipartError::new(
                ErrorKind::Bug,
                format!(
                    "Got NipartMonitorWorker without msg_to_commander: \
                     {self:?}"
                ),
            ))
        }
    }

    async fn process_delay_queue(&mut self) -> Result<(), NipartError> {
        // holding processed interface names
        let mut pending_changes = Vec::new();
        for (iface_name, (_, time)) in self.delay_queue.iter() {
            if time < &Instant::now() {
                pending_changes.push(iface_name.to_string());
            }
        }
        for iface_name in pending_changes {
            log::trace!("Emit delayed event on {iface_name}");
            if let Some((event, _)) = self.delay_queue.remove(&iface_name) {
                if event_is_explicitly_down(&event, &self.explicitly_down) {
                    log::trace!(
                        "Ignoring delayed link event {event}: interface was \
                         explicitly brought down by `npt down`"
                    );
                    continue;
                }
                if let Some(previous_event) =
                    self.emited.get(event.iface_name.as_str())
                    && previous_event.is_up
                    && event.is_up
                {
                    log::trace!("Link is already up, no need to emit event");
                } else {
                    self.notify(event).await?;
                }
            }
        }
        Ok(())
    }

    fn delay_notify(&mut self, event: InterfaceLinkEvent, time: Duration) {
        log::trace!("NipartMonitorWorker delay notify {event:?}");
        self.delay_queue
            .insert(event.iface_name.clone(), (event, Instant::now() + time));
    }

    async fn resume(&mut self) -> Result<(), NipartError> {
        let (conn, handle, msg) =
            new_multicast_connection(&[MulticastGroup::Link]).map_err(|e| {
                NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!(
                        "Failed to create netlink multicast socket for \
                         interface monitor: {e}"
                    ),
                )
            })?;
        tokio::spawn(conn);

        let mut seen_ifaces = HashSet::new();
        let mut link_handle = handle.link().get().execute();
        while let Some(link_msg) =
            link_handle.try_next().await.map_err(|e| {
                NipartError::new(
                    ErrorKind::InvalidArgument,
                    format!("Failed to dump interface link state: {e}"),
                )
            })?
        {
            if let Some((event, mac)) =
                parse_link_msg(&link_msg, self.wifi_monitor_enabled, false)
            {
                if let Some(mac) = mac {
                    self.iface_mac.insert(event.iface_name.clone(), mac);
                }
                seen_ifaces.insert(event.iface_name.clone());
                self.handle_resume_event(event).await?;
            }
        }

        // Interfaces missing from the dump disappeared during the pause.
        self.handle_resume_deleted_ifaces(&seen_ifaces).await?;

        // The link dump reconciled the paused period; later netlink events
        // go through the normal deduplication and debounce path.
        self.netlink_handle = Some(handle);
        self.netlink_msg_receiver = Some(msg);
        Ok(())
    }

    async fn process_rtnl_message(
        &mut self,
        nl_msg: NetlinkMessage<RouteNetlinkMessage>,
    ) -> Result<(), NipartError> {
        if let Some((event, mac)) =
            parse_route_netlink_msg(nl_msg, self.wifi_monitor_enabled)
        {
            if let Some(mac) = mac {
                self.iface_mac.insert(event.iface_name.clone(), mac);
            }
            self.try_notify(event).await?;
        }
        Ok(())
    }

    fn event_is_interested(&self, event: &InterfaceLinkEvent) -> bool {
        self.iface_monitor_list.contains(&event.iface_name)
            // A NIC matching a saved `identifier: mac-address` config may
            // carry a kernel name unknown to us (it was not present at boot):
            // match it by the MAC address instead.
            || self
                .iface_mac
                .get(&event.iface_name)
                .is_some_and(|mac| self.mac_watch_list.contains(mac))
            || (self.wifi_monitor_enabled && event.ssid.is_some())
            || (self.wifi_monitor_enabled
                && event.iface_type == InterfaceType::WifiPhy)
    }

    async fn try_notify(
        &mut self,
        event: InterfaceLinkEvent,
    ) -> Result<(), NipartError> {
        if event_is_explicitly_down(&event, &self.explicitly_down) {
            log::trace!(
                "Ignoring link event {event}: interface was explicitly \
                 brought down by `npt down`"
            );
            // Keep the last known state updated even though the event is
            // suppressed, otherwise a later `npt up` resume link dump would
            // still see the pre-down up state and delay/ignore the up event.
            if event.is_delete {
                self.emited.remove(&event.iface_name);
                self.wifi_phys_emited.remove(&event.iface_name);
            } else {
                let last_event = self.last_link_event(&event);
                self.emited.insert(event.iface_name.to_string(), last_event);
            }
            return Ok(());
        }
        if !self.event_is_interested(&event) {
            log::trace!("Event {event} is not interested");
            return Ok(());
        }

        // When SSID changes, normally it should go through down->up chain,
        // hence no need to handle specially here.  WIFI up notifications
        // carry the SSID in their `WirelessEvent` attribute (see
        // `parse_link_msg()`), so an up event without SSID is either a
        // non-association link event or a duplicate; the normal down->up
        // deduplication below handles both.
        if event.is_delete {
            // delete event, emit now.
            self.notify(event).await?;
        } else if let Some(previous_event) =
            self.emited.get(event.iface_name.as_str())
        {
            if let Ok(elapsed) = previous_event.time_stamp.elapsed()
                && elapsed > Duration::from_secs(EVENT_EXPIRE_TIME_SEC)
            {
                // If previous event expired, emit now.
                self.notify(event).await?;
            } else if !previous_event.is_up && event.is_up {
                // If change from down to up, emit now.
                self.notify(event).await?;
            } else {
                // Delay the event to debounce link flapping.  When a real
                // down is being debounced, record it as the last known
                // state right away: otherwise a quick reconnect (down -> up
                // within the debounce window) is treated as a duplicate up
                // and is dropped, losing saved wifi-cfg routes/IP config
                // that must be applied on the re-association.
                if !event.is_up && previous_event.is_up {
                    let last_event = self.last_link_event(&event);
                    self.emited
                        .insert(event.iface_name.to_string(), last_event);
                }
                // delay emit
                self.delay_notify(event, Duration::from_secs(DOWN_WAIT_SEC));
            }
        } else {
            // If no previous event, emit now.
            self.notify(event).await?;
        }
        Ok(())
    }
}

/// All names which may identify an interface/profile: the logical name,
/// kernel interface name and profile name.  `npt down` may be invoked with
/// any of them, and link events only carry the kernel interface name.
pub(crate) fn iface_identity_names(iface: &Interface) -> Vec<String> {
    let mut names = vec![iface.name().to_string()];
    let kernel_iface_name = iface.kernel_iface_name();
    if !kernel_iface_name.is_empty() && kernel_iface_name != iface.name() {
        names.push(kernel_iface_name.to_string());
    }
    if let Some(profile_name) = iface.base_iface().profile_name.as_deref()
        && profile_name != iface.name()
        && profile_name != kernel_iface_name
    {
        names.push(profile_name.to_string());
    }
    names
}

fn event_is_explicitly_down(
    event: &InterfaceLinkEvent,
    explicitly_down: &HashSet<String>,
) -> bool {
    explicitly_down.contains(&event.iface_name)
        || event
            .ssid
            .as_deref()
            .is_some_and(|ssid| explicitly_down.contains(ssid))
}

fn parse_link_msg(
    link_msg: &LinkMessage,
    wifi_monitor_enabled: bool,
    is_delete: bool,
) -> Option<(InterfaceLinkEvent, Option<String>)> {
    let iface_name = link_msg.attributes.iter().find_map(|attr| {
        if let &LinkAttribute::IfName(iface_name) = &attr {
            Some(iface_name.to_string())
        } else {
            None
        }
    })?;
    let iface_index = link_msg.header.index;
    // The MAC address of the interface, used to match link events against
    // saved `identifier: mac-address` configs whose NIC was not present at
    // boot (their kernel name is unknown until the NIC appears).
    let mac = link_msg.attributes.iter().find_map(|attr| {
        if let LinkAttribute::Address(addr) = attr {
            format_mac(addr)
        } else {
            None
        }
    });
    // TODO: We should return early when event should be ignored(up event for up
    // link, or down event for down link, etc).

    let mut iface_type = parse_iface_type_from_nl_msg(link_msg);
    // The rtnetlink protocol has no information about wireless, so wireless
    // NIC is treated as InterfaceType::Ethernet in rtnetlink.
    if iface_type == InterfaceType::Ethernet && is_wifi_phy_nic(&iface_name) {
        iface_type = InterfaceType::WifiPhy;
    }

    let mut event = InterfaceLinkEvent::new(
        iface_name.clone(),
        iface_index,
        iface_type,
        false,
        None,
    );

    if is_delete {
        event.is_delete = true;
        return Some((event, mac));
    }

    // Unlike `IFLA_OPERSTATE`, the `IFF_*` flags are present in every
    // RTM_NEWLINK message, including the `IFLA_WIRELESS`-only notifications
    // emitted by `wireless_send_event()` on WIFI association. Those
    // notifications carry the SSID in their `WirelessEvent` attribute, so we
    // must accept them to get an up event with SSID included.
    //
    // Use `IFF_LOWER_UP` (carrier up) as the primary signal: on association,
    // `wireless_send_event()` runs after `netif_carrier_on()` but before
    // linkwatch promotes `operstate`, so the SSID-bearing notification has
    // `IFF_LOWER_UP` but not yet `IFF_RUNNING`. Keep `IFF_RUNNING` as well to
    // also accept the "operational state UP/UNKNOWN" notifications used by
    // notification-less drivers (see the DHCP `wait_link_carrier` fix).
    event.is_up = link_msg.header.flags.contains(LinkFlags::LowerUp)
        || link_msg.header.flags.contains(LinkFlags::Running);

    // `wireless_send_event()` sends RTM_NEWLINK with only `IFLA_IFNAME`
    // and `IFLA_WIRELESS`. Only the association IE events carry the SSID
    // of a new association; everything else (e.g. the `SIOCGIWSCAN`
    // scan-done event emitted after every scan) is wireless telemetry,
    // not a link-state change. Dropping those here prevents a background
    // roam scan from re-applying the saved config and restarting DHCP.
    if should_ignore_wireless_notification(link_msg) {
        log::trace!(
            "{iface_name}: ignoring wireless-only RTM_NEWLINK notification \
             without association IEs"
        );
        return None;
    }

    if wifi_monitor_enabled && event.iface_type == InterfaceType::WifiPhy {
        let Some(wifi_ie) = link_msg.attributes.iter().find_map(|attr| {
            if let LinkAttribute::Wireless(wifi_attr) = attr {
                match wifi_attr {
                    WirelessEvent::AssociateResponse(wifi_ie)
                    | WirelessEvent::AssociateRequest(wifi_ie) => Some(wifi_ie),
                    _ => {
                        log::trace!(
                            "{iface_name}: Got unknown \
                             LinkAttribute::Wireless attribute {wifi_attr:?}"
                        );
                        None
                    }
                }
            } else {
                None
            }
        }) else {
            // If we cannot get SSID out of wifi-phy event, we still try to
            // emit it; the event worker checks the current interface state
            // for SSID when processing the event.
            log::trace!(
                "{iface_name}: No SSID out wifi-phy event, event worker will \
                 resolve it from current interface state"
            );
            return Some((event, mac));
        };

        match Ieee80211Elements::parse(wifi_ie.as_slice()) {
            Ok(elements) => {
                log::trace!("{iface_name}: Got WIFI IE: {elements:?}");
                for ie in elements.0.into_iter() {
                    if let Ieee80211Element::Ssid(ssid) = ie
                        && !ssid.is_empty()
                    {
                        event.ssid = Some(ssid);
                        break;
                    }
                }
                if event.is_up && event.ssid.is_none() {
                    log::trace!(
                        "{iface_name}: wifi-phy up event without SSID in up \
                         netlink message"
                    );
                }
            }
            Err(e) => {
                log::trace!(
                    "{iface_name}: unknown wifi information element: {e} \
                     {wifi_ie:?})"
                );
            }
        }
    }

    Some((event, mac))
}

/// Format a raw MAC address (6 bytes) into the uppercase
/// `XX:XX:XX:XX:XX:XX` form used by the saved config and the MAC watch
/// list.  Returns `None` for addresses of any other length (e.g. the
/// 20-byte InfiniBand addresses) which cannot match an ethernet MAC.
fn format_mac(addr: &[u8]) -> Option<String> {
    if addr.len() != 6 {
        return None;
    }
    Some(
        addr.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn parse_route_netlink_msg(
    nl_msg: NetlinkMessage<RouteNetlinkMessage>,
    wifi_monitor_enabled: bool,
) -> Option<(InterfaceLinkEvent, Option<String>)> {
    if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(
        link_msg,
    )) = nl_msg.payload
    {
        parse_link_msg(&link_msg, wifi_monitor_enabled, false)
    } else if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(
        link_msg,
    )) = nl_msg.payload
    {
        parse_link_msg(&link_msg, wifi_monitor_enabled, true)
    } else {
        log::trace!("BUG: Unexpected rtnetlink notification msg: {nl_msg:?}");
        None
    }
}

/// Whether an `RTM_NEWLINK` message is a wireless-only notification
/// emitted by the kernel's `wireless_send_event()` (attributes are only
/// `IFLA_IFNAME` + `IFLA_WIRELESS`) and does not carry association IEs.
///
/// `wireless_send_event()` is also used for non-association telemetry such
/// as the `SIOCGIWSCAN` scan-done event emitted after every scan; those
/// messages are not link-state changes and must not be converted into a
/// link event, otherwise a background roam scan would re-apply the saved
/// config and restart DHCP.
fn should_ignore_wireless_notification(link_msg: &LinkMessage) -> bool {
    let mut has_wireless_attr = false;
    let mut has_association_ie = false;
    let mut has_other_attr = false;
    for attr in &link_msg.attributes {
        match attr {
            LinkAttribute::IfName(_) => {}
            LinkAttribute::Wireless(wifi_attr) => {
                has_wireless_attr = true;
                has_association_ie |= is_wifi_association_event(wifi_attr);
            }
            _ => has_other_attr = true,
        }
    }
    has_wireless_attr && !has_other_attr && !has_association_ie
}

/// Whether the wireless event is an association IE notification carrying
/// the SSID of the new association.
fn is_wifi_association_event(wifi_attr: &WirelessEvent) -> bool {
    matches!(
        wifi_attr,
        WirelessEvent::AssociateRequest(_)
            | WirelessEvent::AssociateResponse(_)
    )
}

fn parse_iface_type_from_nl_msg(link_msg: &LinkMessage) -> InterfaceType {
    if let Some(link_infos) = link_msg.attributes.iter().find_map(|attr| {
        if let LinkAttribute::LinkInfo(infos) = attr {
            Some(infos)
        } else {
            None
        }
    }) && let Some(info_kind) = link_infos.iter().find_map(|info| {
        if let LinkInfo::Kind(k) = info {
            Some(k)
        } else {
            None
        }
    }) {
        match info_kind {
            InfoKind::Bond => InterfaceType::Bond,
            InfoKind::Veth => InterfaceType::Veth,
            InfoKind::Bridge => InterfaceType::LinuxBridge,
            InfoKind::Vlan => InterfaceType::Vlan,
            InfoKind::Vxlan => InterfaceType::Vxlan,
            InfoKind::Dummy => InterfaceType::Dummy,
            InfoKind::Tun => InterfaceType::Tun,
            InfoKind::Vrf => InterfaceType::Vrf,
            InfoKind::MacVlan => InterfaceType::MacVlan,
            InfoKind::MacVtap => InterfaceType::MacVtap,
            InfoKind::Ipoib => InterfaceType::InfiniBand,
            InfoKind::IpVlan => InterfaceType::IpVlan,
            InfoKind::MacSec => InterfaceType::MacSec,
            InfoKind::Hsr => InterfaceType::Hsr,
            InfoKind::Xfrm => InterfaceType::Xfrm,
            v => InterfaceType::Unknown(v.to_string().to_lowercase()),
        }
    } else {
        match link_msg.header.link_layer_type {
            LinkLayerType::Ether => InterfaceType::Ethernet,
            LinkLayerType::Loopback => InterfaceType::Loopback,
            LinkLayerType::Infiniband => InterfaceType::InfiniBand,
            v => InterfaceType::Unknown(v.to_string().to_lowercase()),
        }
    }
}

/// Systemd udev is using `/sys/class/net/{iface_name}/uevent` content
/// `DEVTYPE=wlan` to determine whether wireless or not.
/// And linux kernel code `SET_NETDEV_DEVTYPE(dev, &wiphy_type)` also confirmed
/// so.
fn is_wifi_phy_nic(iface_name: &str) -> bool {
    let mut content = String::new();

    if let Ok(mut fd) =
        std::fs::File::open(format!("/sys/class/net/{iface_name}/uevent"))
        && fd.read_to_string(&mut content).is_ok()
    {
        content.contains("DEVTYPE=wlan")
    } else {
        false
    }
}

#[cfg(test)]
#[path = "../unit_tests/monitor_worker.rs"]
mod tests;
