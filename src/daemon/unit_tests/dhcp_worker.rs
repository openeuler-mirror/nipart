// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
};

use nipart::InterfaceType;

use super::*;

#[derive(Debug)]
struct MockDhcpV4Client {
    results: Arc<Mutex<VecDeque<Result<DhcpV4State, NipartError>>>>,
    run_count: Arc<AtomicUsize>,
    clean_up_count: Arc<AtomicUsize>,
}

impl MockDhcpV4Client {
    fn new(
        results: Vec<Result<DhcpV4State, NipartError>>,
    ) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let run_count = Arc::new(AtomicUsize::new(0));
        let clean_up_count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                results: Arc::new(Mutex::new(results.into())),
                run_count: run_count.clone(),
                clean_up_count: clean_up_count.clone(),
            },
            run_count,
            clean_up_count,
        )
    }

    fn with_shared_counters(
        results: Arc<Mutex<VecDeque<Result<DhcpV4State, NipartError>>>>,
        run_count: Arc<AtomicUsize>,
        clean_up_count: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            results,
            run_count,
            clean_up_count,
        }
    }
}

impl DhcpV4ClientOps for MockDhcpV4Client {
    fn run(&mut self) -> DhcpV4RunFuture<'_> {
        Box::pin(async move {
            self.run_count.fetch_add(1, Ordering::SeqCst);
            self.results.lock().unwrap().pop_front().unwrap()
        })
    }

    fn clean_up(&mut self) {
        self.clean_up_count.fetch_add(1, Ordering::SeqCst);
    }
}

fn mock_lease() -> DhcpV4State {
    DhcpV4State::Done(Box::default())
}

/// A hard `run()` error must not stop DHCPv4 on the interface: the client
/// is cleaned up, re-initialized and kept running.
#[tokio::test]
async fn test_next_dhcpv4_lease_restarts_client_on_error() {
    let (mut client, run_count, clean_up_count) = MockDhcpV4Client::new(vec![
        Err(NipartError::new(
            ErrorKind::Bug,
            "mock DHCPv4 client failure".to_string(),
        )),
        Ok(mock_lease()),
    ]);
    let share_data = Arc::new(Mutex::new(NipartDhcpShareData::default()));
    let (_quit_sender, mut quit_indicator) =
        futures_channel::mpsc::unbounded::<()>();
    let base_iface =
        BaseInterface::new("eth1".to_string(), InterfaceType::Ethernet);
    let init_count = Arc::new(AtomicUsize::new(0));
    let init_count_clone = init_count.clone();
    let results = client.results.clone();
    let run_count_clone = run_count.clone();
    let clean_up_count_clone = clean_up_count.clone();

    let lease = next_dhcpv4_lease(
        &mut client,
        &base_iface,
        &share_data,
        &mut quit_indicator,
        || {
            init_count_clone.fetch_add(1, Ordering::SeqCst);
            let results = results.clone();
            let run_count = run_count_clone.clone();
            let clean_up_count = clean_up_count_clone.clone();
            async move {
                Ok(MockDhcpV4Client::with_shared_counters(
                    results,
                    run_count,
                    clean_up_count,
                ))
            }
        },
    )
    .await
    .unwrap();

    assert!(lease.is_some());
    assert_eq!(run_count.load(Ordering::SeqCst), 2);
    assert_eq!(clean_up_count.load(Ordering::SeqCst), 1);
    assert_eq!(init_count.load(Ordering::SeqCst), 1);
    assert!(matches!(
        share_data.lock().unwrap().state,
        DhcpState::Running
    ));
}

#[tokio::test]
async fn test_next_dhcpv4_lease_does_not_restart_on_success() {
    let (mut client, run_count, clean_up_count) =
        MockDhcpV4Client::new(vec![Ok(mock_lease())]);
    let share_data = Arc::new(Mutex::new(NipartDhcpShareData::default()));
    let (_quit_sender, mut quit_indicator) =
        futures_channel::mpsc::unbounded::<()>();
    let base_iface =
        BaseInterface::new("eth1".to_string(), InterfaceType::Ethernet);
    let init_count = Arc::new(AtomicUsize::new(0));
    let init_count_clone = init_count.clone();

    let lease = next_dhcpv4_lease(
        &mut client,
        &base_iface,
        &share_data,
        &mut quit_indicator,
        || {
            init_count_clone.fetch_add(1, Ordering::SeqCst);
            async {
                Err(NipartError::new(
                    ErrorKind::Bug,
                    "unexpected client restart".to_string(),
                ))
            }
        },
    )
    .await
    .unwrap();

    assert!(lease.is_some());
    assert_eq!(run_count.load(Ordering::SeqCst), 1);
    assert_eq!(clean_up_count.load(Ordering::SeqCst), 0);
    assert_eq!(init_count.load(Ordering::SeqCst), 0);
}

fn base_iface_with_auto_route_metric(
    auto_route_metric: Option<i64>,
) -> BaseInterface {
    let mut base_iface =
        BaseInterface::new("eth1".to_string(), InterfaceType::Ethernet);
    base_iface.iface_index = Some(7);
    let mut ipv4 = InterfaceIpv4::default();
    ipv4.enabled = Some(true);
    ipv4.dhcp = Some(true);
    ipv4.auto_route_metric = auto_route_metric;
    base_iface.ipv4 = Some(ipv4);
    base_iface
}

fn lease_with_gateway() -> DhcpV4Lease {
    let mut lease = DhcpV4Lease::default();
    lease.gateways = Some(vec![std::net::Ipv4Addr::new(192, 0, 2, 1)]);
    lease
}

#[test]
fn test_gen_routes_uses_auto_route_metric() {
    let lease = lease_with_gateway();
    let base_iface = base_iface_with_auto_route_metric(Some(321));
    let routes = gen_routes(&lease, &base_iface);
    assert_eq!(routes.config.unwrap()[0].metric, Some(321));
}

#[test]
fn test_gen_routes_falls_back_to_iface_index_metric() {
    let lease = lease_with_gateway();
    let base_iface = base_iface_with_auto_route_metric(None);
    let routes = gen_routes(&lease, &base_iface);
    assert_eq!(routes.config.unwrap()[0].metric, Some(700));
}

fn routes_from_yaml(yaml: &str) -> Routes {
    rmsd_yaml::from_str(yaml).unwrap()
}

#[test]
fn test_stale_lease_gateway_route_is_marked_absent() {
    // A lease learned from another network left its gateway route behind:
    // it shares destination and metric with the new lease's route, so the
    // route apply would refuse the new route without an explicit removal.
    let cur_routes = routes_from_yaml(
        r#"---
        running:
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 192.0.2.1
            metric: 700
            table-id: 254
        "#,
    );
    let mut routes = routes_from_yaml(
        r#"---
        config:
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 198.51.100.1
            metric: 700
            table-id: 254
        "#,
    );

    mark_replaced_routes_absent(&mut routes, &cur_routes);

    let config_routes = routes.config.unwrap();
    assert_eq!(config_routes.len(), 2);
    let absent_route = config_routes
        .iter()
        .find(|rt| rt.is_absent())
        .expect("stale gateway route was not marked absent");
    assert_eq!(absent_route.next_hop_addr.as_deref(), Some("192.0.2.1"));
}

#[test]
fn test_unchanged_lease_gateway_route_is_kept() {
    let cur_routes = routes_from_yaml(
        r#"---
        running:
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 192.0.2.1
            metric: 700
            table-id: 254
        "#,
    );
    let mut routes = routes_from_yaml(
        r#"---
        config:
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 192.0.2.1
            metric: 700
            table-id: 254
        "#,
    );

    mark_replaced_routes_absent(&mut routes, &cur_routes);

    let config_routes = routes.config.unwrap();
    assert_eq!(config_routes.len(), 1);
    assert!(!config_routes[0].is_absent());
}

#[test]
fn test_iface_default_gateway_fingerprint_is_iface_scoped() {
    let routes = routes_from_yaml(
        r#"---
        running:
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 192.0.2.1
            metric: 700
            table-id: 254
          - destination: 0.0.0.0/0
            next-hop-interface: eth2
            next-hop-address: 198.51.100.1
            metric: 700
            table-id: 254
        "#,
    );
    assert_eq!(
        iface_default_gateway_fingerprint(
            routes.running.iter().flatten(),
            "eth1"
        ),
        vec!["eth1|192.0.2.1|700|254".to_string()]
    );
    // An interface without a default route must not inherit the gateway of
    // another interface, otherwise every lease renewal would notify.
    assert!(
        iface_default_gateway_fingerprint(
            routes.running.iter().flatten(),
            "eth3"
        )
        .is_empty()
    );
}

/// The lease routes are applied by the DHCP worker instead of the daemon
/// apply path, so the worker has to tell the daemon when a lease replaced
/// the default gateway the DNS cache upstreams were using.
#[test]
fn test_lease_gateway_change_notifies_daemon() {
    let cur_routes = routes_from_yaml(
        r#"---
        running:
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 198.51.100.1
            metric: 700
            table-id: 254
        "#,
    );
    let base_iface = base_iface_with_auto_route_metric(Some(700));
    let lease = lease_with_gateway();
    let gateway_before = iface_default_gateway_fingerprint(
        cur_routes.running.iter().flatten(),
        base_iface.name.as_str(),
    );
    let routes = gen_routes(&lease, &base_iface);
    let gateway_after =
        default_gateway_fingerprint(routes.config.iter().flatten());
    assert_ne!(gateway_before, gateway_after);

    let (sender, mut receiver) = futures_channel::mpsc::unbounded();
    notify_daemon_on_gateway_change(
        &base_iface,
        gateway_before,
        gateway_after,
        Some(&sender),
    );

    assert!(matches!(
        receiver.try_recv(),
        Ok(NipartManagerCmd::GatewayChanged)
    ));
}

#[test]
fn test_lease_apply_notifies_daemon_for_saved_route_reconcile() {
    let base_iface = base_iface_with_auto_route_metric(None);
    let (sender, mut receiver) = futures_channel::mpsc::unbounded();

    notify_daemon_on_lease_applied(&base_iface, Some(&sender));

    assert!(matches!(
        receiver.try_recv(),
        Ok(NipartManagerCmd::DhcpV4LeaseApplied(iface_name))
            if iface_name == base_iface.name
    ));
}

#[test]
fn test_lease_apply_without_daemon_sender_is_ignored() {
    let base_iface = base_iface_with_auto_route_metric(None);

    notify_daemon_on_lease_applied(&base_iface, None);
}

#[test]
fn test_same_lease_gateway_does_not_notify_daemon() {
    // A renewal of the same lease (same gateway, metric and table) must not
    // reset the upstream transports of the DNS cache.
    let cur_routes = routes_from_yaml(
        r#"---
        running:
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 192.0.2.1
            metric: 700
            table-id: 254
        "#,
    );
    let base_iface = base_iface_with_auto_route_metric(Some(700));
    let lease = lease_with_gateway();
    let gateway_before = iface_default_gateway_fingerprint(
        cur_routes.running.iter().flatten(),
        base_iface.name.as_str(),
    );
    let routes = gen_routes(&lease, &base_iface);
    let gateway_after =
        default_gateway_fingerprint(routes.config.iter().flatten());
    assert_eq!(gateway_before, gateway_after);

    let (sender, mut receiver) = futures_channel::mpsc::unbounded();
    notify_daemon_on_gateway_change(
        &base_iface,
        gateway_before,
        gateway_after,
        Some(&sender),
    );

    assert!(
        matches!(
            receiver.try_recv(),
            Err(futures_channel::mpsc::TryRecvError::Empty)
        ),
        "a renewal of the same gateway must not notify the daemon"
    );
}

#[test]
fn test_gateway_change_without_daemon_sender_is_ignored() {
    // The worker can be built without a daemon (unit tests, standalone
    // uses): the missing notification must not panic.
    let base_iface = base_iface_with_auto_route_metric(Some(700));
    notify_daemon_on_gateway_change(
        &base_iface,
        vec!["eth1|198.51.100.1|700|254".to_string()],
        Vec::new(),
        None,
    );
}

#[test]
fn test_route_of_other_iface_or_metric_is_kept() {
    let cur_routes = routes_from_yaml(
        r#"---
        running:
          - destination: 0.0.0.0/0
            next-hop-interface: eth2
            next-hop-address: 192.0.2.1
            metric: 700
            table-id: 254
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 192.0.2.1
            metric: 701
            table-id: 254
        "#,
    );
    let mut routes = routes_from_yaml(
        r#"---
        config:
          - destination: 0.0.0.0/0
            next-hop-interface: eth1
            next-hop-address: 198.51.100.1
            metric: 700
            table-id: 254
        "#,
    );

    mark_replaced_routes_absent(&mut routes, &cur_routes);

    let config_routes = routes.config.unwrap();
    assert_eq!(config_routes.len(), 1);
    assert!(!config_routes[0].is_absent());
}
