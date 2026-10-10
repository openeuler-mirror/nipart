# SPDX-License-Identifier: Apache-2.0

import os
import signal

import nipart

from .conftest import DAEMON_LOG, start_daemon, stop_daemon
from .testlib.cmdlib import exec_cmd
from .testlib.dhcp import DHCP_SRV_NIC
from .testlib.dhcp import start_dhcp_server
from .testlib.dhcp import stop_dhcp_server
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml

DHCP_CLI_NIC = "dhcpcli-restore"
TEST_NET_NS = "nipart_dhcp_restore_test"
DEFAULT_TIMEOUT = 30
DHCP_SRV_IP4_PREFIX_2 = "198.51.100"
DHCP_SRV_IP4_2 = f"{DHCP_SRV_IP4_PREFIX_2}.1"
DNSMASQ_CONF_PATH_2 = "/tmp/nipart_test_dnsmasq_restore2.conf"
DNSMASQ_PID_PATH_2 = "/tmp/nipart_test_dnsmasq_restore2.pid"


def _create_veth_pair(ifname, peer, peer_ns):
    exec_cmd(f"ip link add {ifname} type veth peer name {peer}".split())
    exec_cmd(f"ip link set {ifname} up".split())
    exec_cmd(f"ip link set {peer} netns {peer_ns}".split())
    exec_cmd(f"ip netns exec {peer_ns} ip link set {peer} up".split())
    exec_cmd(f"ip netns exec {peer_ns} ip link set lo up".split())


def _remove_veth_pair(ifname, peer_ns):
    exec_cmd(f"ip link del {ifname}".split(), check=False)
    exec_cmd(f"ip netns del {peer_ns}".split(), check=False)


def _has_dhcp_addr():
    rc, out, _ = exec_cmd(
        ["ip", "-4", "addr", "show", "dev", DHCP_CLI_NIC], check=False
    )
    return "192.0.2." in out and "dynamic" in out


def _has_gateway_route():
    rc, out, _ = exec_cmd(
        ["ip", "route", "show", "dev", DHCP_CLI_NIC], check=False
    )
    return any("default" in line for line in out.splitlines())


def _has_ipv4_prefix(prefix):
    rc, out, _ = exec_cmd(
        ["ip", "-4", "addr", "show", "dev", DHCP_CLI_NIC], check=False
    )
    return f"{prefix}." in out and "dynamic" in out


def _has_gateway_route_to(gateway):
    rc, out, _ = exec_cmd(
        ["ip", "route", "show", "dev", DHCP_CLI_NIC], check=False
    )
    return any(
        line.startswith(f"default via {gateway}") for line in out.splitlines()
    )


def _start_dhcp_server_2(net_ns):
    """Serve another network from the same DHCP server NIC."""
    exec_cmd(
        f"ip netns exec {net_ns} "
        f"ip addr add {DHCP_SRV_IP4_2}/24 dev {DHCP_SRV_NIC}".split()
    )
    dnsmasq_conf = (
        "leasefile-ro\n"
        f"interface={DHCP_SRV_NIC}\n"
        f"dhcp-range={DHCP_SRV_IP4_PREFIX_2}.200,"
        f"{DHCP_SRV_IP4_PREFIX_2}.250,255.255.255.0,48h\n"
        f"dhcp-option=option:dns-server,{DHCP_SRV_IP4_2}\n"
    )
    with open(DNSMASQ_CONF_PATH_2, "w") as fd:
        fd.write(dnsmasq_conf)
    exec_cmd(
        f"sudo ip netns exec {net_ns} dnsmasq "
        f"--interface={DHCP_SRV_NIC} --bind-interfaces --log-dhcp "
        f"--pid-file={DNSMASQ_PID_PATH_2} "
        f"--conf-file={DNSMASQ_CONF_PATH_2}".split()
    )


def _stop_dhcp_server_2():
    if not os.path.exists(DNSMASQ_PID_PATH_2):
        return
    with open(DNSMASQ_PID_PATH_2) as fd:
        try:
            os.kill(int(fd.read()), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass


def _log_since(pos, text):
    if not os.path.exists(DAEMON_LOG):
        return False
    with open(DAEMON_LOG) as log_f:
        log_f.seek(pos)
        return text in log_f.read()


def test_dhcp_client_restored_after_daemon_restart():
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())
    _create_veth_pair(DHCP_CLI_NIC, DHCP_SRV_NIC, TEST_NET_NS)
    start_dhcp_server(TEST_NET_NS)

    try:
        nipart.apply(load_yaml(f"""---
                interfaces:
                - name: {DHCP_CLI_NIC}
                  type: ethernet
                  state: up
                  ipv4:
                    enabled: true
                    dhcp: true"""))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_dhcp_addr
        ), f"{DHCP_CLI_NIC} did not get a DHCPv4 lease"

        # Restart the daemon while the lease is still present in the
        # kernel.  The kernel state reports the address with `dhcp: true`,
        # so the boot apply sees no diff - the userspace DHCP client (it
        # died with the daemon) must be restarted by the boot batch
        # (`restart-auto-ip`), otherwise the lease expires without renewal.
        log_pos = 0
        if os.path.exists(DAEMON_LOG):
            log_pos = os.path.getsize(DAEMON_LOG)
        stop_daemon()
        start_daemon()

        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _log_since,
            log_pos,
            f"DHCPv4 on interface {DHCP_CLI_NIC}",
        ), "DHCPv4 client not restarted after daemon restart"
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _log_since, log_pos, "got lease 192.0.2"
        ), "DHCPv4 client did not re-acquire the lease after daemon restart"
    finally:
        nipart.apply(load_yaml(f"""---
                interfaces:
                - name: {DHCP_CLI_NIC}
                  type: ethernet
                  state: absent"""))
        _remove_veth_pair(DHCP_CLI_NIC, TEST_NET_NS)
        stop_dhcp_server()


def test_dhcp_auto_gateway_false_after_daemon_restart():
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())
    _create_veth_pair(DHCP_CLI_NIC, DHCP_SRV_NIC, TEST_NET_NS)
    start_dhcp_server(TEST_NET_NS)

    try:
        nipart.apply(load_yaml(f"""---
                interfaces:
                - name: {DHCP_CLI_NIC}
                  type: ethernet
                  state: up
                  ipv4:
                    enabled: true
                    dhcp: true
                    auto-gateway: false"""))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_dhcp_addr
        ), f"{DHCP_CLI_NIC} did not get a DHCPv4 lease"
        assert not _has_gateway_route()

        # The kernel state carries the DHCP address with `dhcp: true` but
        # never the config-only `auto_gateway` property.  Whatever path
        # restarts the DHCP client after the daemon restart (the boot apply
        # sees a diff because of `auto-gateway`, or the boot batch
        # `restart-auto-ip` restarts it when the state matches), the client
        # must keep honoring `auto-gateway: false`, otherwise the gateway
        # route would be added on the first renewal.
        log_pos = 0
        if os.path.exists(DAEMON_LOG):
            log_pos = os.path.getsize(DAEMON_LOG)
        stop_daemon()
        start_daemon()

        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _log_since, log_pos, "got lease 192.0.2"
        ), "DHCPv4 client did not re-acquire the lease after daemon restart"
        assert not _has_gateway_route()
    finally:
        nipart.apply(load_yaml(f"""---
                interfaces:
                - name: {DHCP_CLI_NIC}
                  type: ethernet
                  state: absent"""))
        _remove_veth_pair(DHCP_CLI_NIC, TEST_NET_NS)
        stop_dhcp_server()


def test_dhcp_restore_replaces_stale_lease_gateway():
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())
    _create_veth_pair(DHCP_CLI_NIC, DHCP_SRV_NIC, TEST_NET_NS)
    start_dhcp_server(TEST_NET_NS)

    try:
        nipart.apply(load_yaml(f"""---
                interfaces:
                - name: {DHCP_CLI_NIC}
                  type: ethernet
                  state: up
                  ipv4:
                    enabled: true
                    dhcp: true"""))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_dhcp_addr
        ), f"{DHCP_CLI_NIC} did not get a DHCPv4 lease"
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_gateway_route
        ), f"{DHCP_CLI_NIC} did not get a default gateway"

        # Move the DHCP server to another network behind the client's back:
        # the kernel keeps the stale lease address and its gateway route
        # while the daemon is restarted, where the restored DHCP client
        # learns the new network's lease.  The new gateway route shares
        # destination and metric with the stale one, so the apply must
        # remove the stale route instead of failing with "Multiple routes
        # to 0.0.0.0/0 are sharing the same metric" and leaving the
        # interface without any gateway.
        stop_dhcp_server()
        _start_dhcp_server_2(TEST_NET_NS)

        stop_daemon()
        start_daemon()

        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _has_ipv4_prefix,
            DHCP_SRV_IP4_PREFIX_2,
        ), f"{DHCP_CLI_NIC} did not get the new network's lease"
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_gateway_route_to, DHCP_SRV_IP4_2
        ), f"{DHCP_CLI_NIC} did not get the new network's gateway"
    finally:
        nipart.apply(load_yaml(f"""---
                interfaces:
                - name: {DHCP_CLI_NIC}
                  type: ethernet
                  state: absent"""))
        _remove_veth_pair(DHCP_CLI_NIC, TEST_NET_NS)
        stop_dhcp_server()
        _stop_dhcp_server_2()
