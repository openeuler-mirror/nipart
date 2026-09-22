# SPDX-License-Identifier: Apache-2.0

import os
import tempfile

import pytest

import nipart

from .conftest import CLI_PATH
from .testlib.cmdlib import exec_cmd
from .testlib.dhcp import DHCP_SRV_IP4
from .testlib.dhcp import DHCP_SRV_IP4_PREFIX
from .testlib.dhcp import DHCP_SRV_NIC
from .testlib.dhcp import start_dhcp_server
from .testlib.dhcp import stop_dhcp_server
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml
from .testlib.statelib import show_only

DHCP_CLI_NIC = "dhcpcli"
TEST_NET_NS = "nipart_dhcp_test"
DEFAULT_TIMEOUT = 20

IPV4_DEFAULT_GATEWAY = "0.0.0.0/0"
STATIC_ROUTE_DST = "203.0.113.0/24"


def _create_veth_pair(ifname, peer, peer_ns):
    exec_cmd(f"ip link add {ifname} type veth peer name {peer}".split())
    exec_cmd(f"ip link set {ifname} up".split())
    exec_cmd(f"ip link set {peer} netns {peer_ns}".split())
    exec_cmd(f"ip netns exec {peer_ns} ip link set {peer} up".split())
    exec_cmd(f"ip netns exec {peer_ns} " f"ip link set lo up".split())


def _remove_veth_pair(ifname, peer_ns):
    exec_cmd(f"ip link del {ifname}".split(), check=False)
    exec_cmd(f"ip netns del {peer_ns}".split(), check=False)


@pytest.fixture(scope="module")
def dhcp_env():
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"sysctl -w net.ipv6.conf.all.disable_ipv6=1".split()
    )
    _create_veth_pair(DHCP_CLI_NIC, DHCP_SRV_NIC, TEST_NET_NS)
    start_dhcp_server(TEST_NET_NS)
    yield
    stop_dhcp_server()
    nipart.apply(load_yaml(f"""---
        interfaces:
        - name: {DHCP_CLI_NIC}
          type: ethernet
          state: absent"""))
    _remove_veth_pair(DHCP_CLI_NIC, TEST_NET_NS)


@pytest.fixture
def dhcp_cli_cleanup():
    yield
    nipart.apply(load_yaml(f"""---
        interfaces:
        - name: {DHCP_CLI_NIC}
          type: ethernet
          state: up
          ipv4:
            enabled: false
        routes:
          config:
          - next-hop-interface: {DHCP_CLI_NIC}
            state: absent"""))


def _get_routes(nic=DHCP_CLI_NIC):
    rc, out, _ = exec_cmd(["ip", "route", "show", "dev", nic])
    return out


def _has_gateway_route():
    routes = _get_routes()
    for line in routes.splitlines():
        if "default" in line or IPV4_DEFAULT_GATEWAY in line:
            return True
    return False


def _has_static_route():
    return STATIC_ROUTE_DST in _get_routes()


def _gateway_route_metric():
    for line in _get_routes().splitlines():
        fields = line.split()
        if not fields or fields[0] != "default":
            continue
        try:
            return int(fields[fields.index("metric") + 1])
        except (IndexError, ValueError):
            continue
    return None


def _has_dhcp_addr():
    iface_state = show_only(DHCP_CLI_NIC)
    if iface_state is None:
        return False
    addrs = iface_state.get("ipv4", {}).get("address", [])
    for addr in addrs:
        if DHCP_SRV_IP4_PREFIX in addr.get("ip", ""):
            return True
    return False


def _ping_dhcp_server():
    try:
        exec_cmd(f"ping {DHCP_SRV_IP4} -c 1 -w 5".split())
        return True
    except Exception:
        return False


def test_dhcpv4_default_behavior(dhcp_env, dhcp_cli_cleanup):
    nipart.apply(load_yaml(f"""---
        interfaces:
        - name: {DHCP_CLI_NIC}
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true"""))
    assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _has_dhcp_addr)
    assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _ping_dhcp_server)
    assert _has_gateway_route()


def test_dhcpv4_auto_gateway_false(dhcp_env, dhcp_cli_cleanup):
    nipart.apply(load_yaml(f"""---
        interfaces:
        - name: {DHCP_CLI_NIC}
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            auto-gateway: false
        routes:
          config:
          - destination: {STATIC_ROUTE_DST}
            next-hop-interface: {DHCP_CLI_NIC}
            next-hop-address: {DHCP_SRV_IP4}"""))
    assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _has_dhcp_addr)
    assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _ping_dhcp_server)
    assert not _has_gateway_route()
    assert STATIC_ROUTE_DST in _get_routes()


def test_dhcpv4_static_route_restored_after_lease_renewal(
    dhcp_env, dhcp_cli_cleanup
):
    stop_dhcp_server()
    start_dhcp_server(TEST_NET_NS, renewal_time=5, rebinding_time=10)
    try:
        nipart.apply(load_yaml(f"""---
            interfaces:
            - name: {DHCP_CLI_NIC}
              type: ethernet
              state: up
              ipv4:
                enabled: true
                dhcp: true
                auto-gateway: false
            routes:
              config:
              - destination: {STATIC_ROUTE_DST}
                next-hop-interface: {DHCP_CLI_NIC}
                next-hop-address: {DHCP_SRV_IP4}"""))
        assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _has_dhcp_addr)
        assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _has_static_route)

        # Simulate the kernel dropping a route whose next hop becomes
        # unreachable, for example when the DHCP address expires.
        exec_cmd(["ip", "route", "del", STATIC_ROUTE_DST])
        assert not _has_static_route()

        # The short renewal timer makes the DHCP worker apply the lease
        # again shortly; the daemon must re-add the saved static route.
        assert retry_till_true_or_timeout(30, _has_static_route)
    finally:
        stop_dhcp_server()
        start_dhcp_server(TEST_NET_NS)


def test_dhcpv4_auto_gateway_true(dhcp_env, dhcp_cli_cleanup):
    nipart.apply(load_yaml(f"""---
        interfaces:
        - name: {DHCP_CLI_NIC}
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            auto-gateway: true"""))
    assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _has_dhcp_addr)
    assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _ping_dhcp_server)
    assert _has_gateway_route()


def test_dhcpv4_auto_route_metric(dhcp_env, dhcp_cli_cleanup):
    nipart.apply(load_yaml(f"""---
        interfaces:
        - name: {DHCP_CLI_NIC}
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            auto-route-metric: 321"""))
    assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _has_dhcp_addr)
    assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _ping_dhcp_server)
    assert _gateway_route_metric() == 321


def test_dhcpv4_auto_gateway_false_no_daemon(dhcp_env, dhcp_cli_cleanup):
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fd:
        fd.write(f"""---
        interfaces:
        - name: {DHCP_CLI_NIC}
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            auto-gateway: false""")
        state_file = fd.name
    try:
        rc, out, err = exec_cmd(
            [CLI_PATH, "apply", "-n", state_file], check=False
        )
        assert rc == 0, f"npt apply -n failed:\n{out}\n{err}"
        assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _has_dhcp_addr)
        assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _ping_dhcp_server)
        assert not _has_gateway_route()
    finally:
        os.unlink(state_file)


def test_dhcpv4_auto_route_metric_no_daemon(dhcp_env, dhcp_cli_cleanup):
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fd:
        fd.write(f"""---
        interfaces:
        - name: {DHCP_CLI_NIC}
          type: ethernet
          state: up
          ipv4:
            enabled: true
            dhcp: true
            auto-route-metric: 321""")
        state_file = fd.name
    try:
        rc, out, err = exec_cmd(
            [CLI_PATH, "apply", "-n", state_file], check=False
        )
        assert rc == 0, f"npt apply -n failed:\n{out}\n{err}"
        assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _has_dhcp_addr)
        assert retry_till_true_or_timeout(DEFAULT_TIMEOUT, _ping_dhcp_server)
        assert _gateway_route_metric() == 321
    finally:
        os.unlink(state_file)
