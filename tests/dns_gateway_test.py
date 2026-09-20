# SPDX-License-Identifier: Apache-2.0

"""The DNS cache retries a dead upstream after a gateway change.

The cache marks an upstream dead after two connection failures and skips
it until its retry cooldown (5 seconds, doubling after every failed probe)
elapsed. When the host default gateway changes, the network path of the
upstreams may work again, hence the daemon notifies the cache so it retries
the failed upstream at once.

The fake upstream lives in a network namespace behind a veth pair, so it is
only reachable once a default route through the veth gateway exists.
Applying that route through npt is the gateway change of this test; a query
right after the apply must succeed within a window shorter than the cache's
own retry cooldown.
"""

import atexit
import os
import shutil
import socket
import struct
import subprocess

import pytest

from nipart import NipartApplyOption
from nipart import NipartClient

from .testlib.cmdlib import exec_cmd
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml

RESOLV_CONF_PATH = "/etc/resolv.conf"
RESOLV_CONF_BACKUP = "/etc/resolv.conf.nipart-dns-gateway-test-backup"

DNS_CACHE_BIND = "127.0.0.1:53"
DNS_CACHE_HOST = "127.0.0.1"
DNS_CACHE_PORT = 53

TEST_NET_NS = "nipart_dns_gateway_test"
HOST_IFACE = "nptdnsgw0"
PEER_IFACE = "nptdnsgwp0"
HOST_PREFIX = "2001:db8:1::1/64"
PEER_PREFIX = "2001:db8:1::2/64"
GATEWAY = "2001:db8:1::2"
UPSTREAM_ADDR = "2001:db8::53"
UPSTREAM_DOMAIN = "dns-gateway-test.example.org"
UPSTREAM_ANSWER = "203.0.113.10"

# The cache skips a dead upstream for its 5 second retry cooldown, so a
# shorter window proves the daemon notified the cache about the new
# default gateway instead of the cooldown simply expiring.
RETRY_WINDOW_SEC = 3
QUERY_TIMEOUT_SEC = 5
DNS_RCODE_SERVFAIL = 2

# Started with `ip netns exec` inside the network namespace: answer one A
# record for every query. Kept as a source string so the fake server needs
# no helper file (and no shell quoting).
_FAKE_DNS_SERVER_CODE = r"""
import socket
import struct
import sys

address, port, answer = sys.argv[1], int(sys.argv[2]), sys.argv[3]
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((address, port))
while True:
    data, peer = sock.recvfrom(4096)
    if len(data) < 12:
        continue
    offset = 12
    while data[offset] != 0:
        offset += 1 + data[offset]
    offset += 1
    question = data[12 : offset + 4]
    header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    reply = (
        header
        + question
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + socket.inet_aton(answer)
    )
    sock.sendto(reply, peer)
"""


def _encode_domain(domain):
    ret = b""
    for label in domain.strip(".").split("."):
        encoded = label.encode("ascii")
        ret += bytes([len(encoded)]) + encoded
    return ret + b"\x00"


def _query_packet(domain, transaction_id, qtype=1):
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + _encode_domain(domain) + struct.pack("!HH", qtype, 1)


def _skip_domain(data, offset):
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def _parse_answers(data):
    """Return list of (rr_type, rdata) answers of a DNS response."""
    if len(data) < 12:
        raise ValueError("DNS response too short")
    qdcount, ancount = struct.unpack("!HH", data[4:8])
    offset = 12
    for _ in range(qdcount):
        offset = _skip_domain(data, offset)
        offset += 4
    answers = []
    for _ in range(ancount):
        offset = _skip_domain(data, offset)
        rr_header_end = offset + 10
        rr_header = data[offset:rr_header_end]
        rr_type, _, _, rdlength = struct.unpack("!HHIH", rr_header)
        offset += 10
        rdata_end = offset + rdlength
        answers.append((rr_type, data[offset:rdata_end]))
        offset = rdata_end
    return answers


def _a_records(data):
    return [
        socket.inet_ntoa(rdata)
        for (rr_type, rdata) in _parse_answers(data)
        if rr_type == 1 and len(rdata) == 4
    ]


def _rcode(data):
    return data[3] & 0x0F


def _query_cache(domain, timeout=QUERY_TIMEOUT_SEC):
    """Return the raw cache reply, or None when the query timed out."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(
            _query_packet(domain, 0x1234), (DNS_CACHE_HOST, DNS_CACHE_PORT)
        )
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def _cache_answers(domain):
    data = _query_cache(domain)
    return [] if data is None else _a_records(data)


def _fake_upstream_running():
    """Whether the fake upstream socket is bound inside the netns."""
    rc, out, _ = exec_cmd(
        ["ip", "netns", "exec", TEST_NET_NS, "ss", "-uln"], check=False
    )
    listening = out.replace("[", "").replace("]", "")
    return rc == 0 and f"{UPSTREAM_ADDR}:53" in listening


def _cleanup_env():
    exec_cmd(["ip", "link", "del", HOST_IFACE], check=False)
    exec_cmd(["ip", "netns", "del", TEST_NET_NS], check=False)


def _stop_dns_cache():
    """Best effort stop of a cache left running by another test file."""
    try:
        NipartClient().apply_network_state(
            load_yaml("""---
                version: 1
                dns-resolver:
                  cache:
                    enabled: false
                """),
            NipartApplyOption(memory_only=True),
        )
    except Exception:  # noqa: BLE001
        pass


@pytest.fixture(scope="module")
def resolv_conf_backup():
    def _restore(_signal=None, _frame=None):
        if os.path.exists(RESOLV_CONF_BACKUP):
            shutil.copy2(RESOLV_CONF_BACKUP, RESOLV_CONF_PATH)
            os.remove(RESOLV_CONF_BACKUP)

    if os.path.exists(RESOLV_CONF_BACKUP):
        # Restore a backup left over from an interrupted earlier run
        # instead of overwriting it with a possibly broken resolv.conf.
        _restore()
    if os.path.exists(RESOLV_CONF_PATH):
        shutil.copy2(RESOLV_CONF_PATH, RESOLV_CONF_BACKUP)
    atexit.register(_restore)
    yield
    _restore()
    atexit.unregister(_restore)


@pytest.fixture(scope="module")
def gateway_env():
    """veth pair with the fake DNS upstream in a network namespace.

    The host side has an IPv6 address but no route towards the upstream;
    only the tested apply creates that route. The namespace addresses are
    added with `nodad` so the fake upstream can bind its address without
    waiting for the duplicate address detection.
    """

    def _peer_addr(addr):
        exec_cmd(
            [
                "ip",
                "netns",
                "exec",
                TEST_NET_NS,
                "ip",
                "addr",
                "add",
                addr,
                "dev",
                PEER_IFACE,
                "nodad",
            ]
        )

    # The cache must reach the upstream through the default route this test
    # adds; when the host already has an IPv6 default route, the new route
    # would not be the one in use (and replacing the host route would cut
    # the host off the IPv6 network for the duration of the test).
    rc, out, _ = exec_cmd(
        ["ip", "-6", "route", "show", "default"], check=False
    )
    if rc == 0 and out.strip():
        pytest.skip(
            "the host already has an IPv6 default route, this test must own "
            "it to prove the gateway change"
        )

    _cleanup_env()
    exec_cmd(["ip", "netns", "add", TEST_NET_NS])
    exec_cmd(
        [
            "ip",
            "link",
            "add",
            HOST_IFACE,
            "type",
            "veth",
            "peer",
            "name",
            PEER_IFACE,
        ]
    )
    exec_cmd(["ip", "addr", "add", HOST_PREFIX, "dev", HOST_IFACE, "nodad"])
    exec_cmd(["ip", "link", "set", HOST_IFACE, "up"])
    exec_cmd(["ip", "link", "set", PEER_IFACE, "netns", TEST_NET_NS])
    exec_cmd(
        ["ip", "netns", "exec", TEST_NET_NS, "ip", "link", "set", "lo", "up"]
    )
    _peer_addr(PEER_PREFIX)
    _peer_addr(f"{UPSTREAM_ADDR}/128")
    exec_cmd(
        [
            "ip",
            "netns",
            "exec",
            TEST_NET_NS,
            "ip",
            "link",
            "set",
            PEER_IFACE,
            "up",
        ]
    )
    upstream = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            TEST_NET_NS,
            "python3",
            "-c",
            _FAKE_DNS_SERVER_CODE,
            UPSTREAM_ADDR,
            "53",
            UPSTREAM_ANSWER,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert retry_till_true_or_timeout(10, _fake_upstream_running)
        yield
    finally:
        upstream.terminate()
        upstream.wait(timeout=10)

        # Stop the cache started by this test: it must not leak into the
        # other DNS tests of the session.
        _stop_dns_cache()
        _cleanup_env()


@pytest.fixture(scope="module", autouse=True)
def free_dns_port():
    """Take over the DNS cache port, failing when another service holds it.

    A cache left running by another test file is stopped first: this test
    applies its own cache configuration on the same port.
    """

    _stop_dns_cache()

    def port_is_free():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((DNS_CACHE_HOST, DNS_CACHE_PORT))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    if not port_is_free():
        holders = exec_cmd(["ss", "-ulnup"], check=False)[1]
        pytest.fail(
            "127.0.0.1:53 is already in use; a leftover nipart "
            f"daemon or another DNS service must be stopped first:\n"
            f"{holders}"
        )
    yield


def test_dns_cache_retries_upstream_after_gateway_change(
    gateway_env, resolv_conf_backup
):
    cli = NipartClient()
    cli.apply_network_state(
        load_yaml(f"""---
            version: 1
            dns-resolver:
              config:
                server:
                  - {DNS_CACHE_HOST}
              cache:
                enabled: true
                bind: "{DNS_CACHE_BIND}"
                fallback:
                  auto-dns: false
                  nameservers:
                    - "{UPSTREAM_ADDR}"
            """),
        NipartApplyOption(memory_only=True),
    )

    # Without the default route the cache cannot reach the upstream: it
    # creates no transport and answers SERVFAIL. Two failed queries mark
    # the upstream dead, so a later query is skipped for the retry cooldown.
    for _ in range(2):
        response = _query_cache(UPSTREAM_DOMAIN)
        assert response is None or (
            _rcode(response) == DNS_RCODE_SERVFAIL
            and _a_records(response) == []
        )

    cli.apply_network_state(
        load_yaml(f"""---
            version: 1
            routes:
              config:
                - destination: "::/0"
                  next-hop-address: "{GATEWAY}"
                  next-hop-interface: "{HOST_IFACE}"
            """),
        NipartApplyOption(memory_only=True),
    )

    rc, out, _ = exec_cmd(
        ["ip", "-6", "route", "show", "default", "dev", HOST_IFACE],
        check=False,
    )
    assert rc == 0 and "default" in out

    # The apply changed the host default gateway, so the cache must retry
    # the dead upstream right away instead of waiting out its cooldown.
    def upstream_recovered():
        return _cache_answers(UPSTREAM_DOMAIN) == [UPSTREAM_ANSWER]

    assert retry_till_true_or_timeout(RETRY_WINDOW_SEC, upstream_recovered), (
        "the DNS cache did not retry its failed upstream after the default "
        f"gateway changed; it kept answering without {UPSTREAM_ANSWER} for "
        f"more than {RETRY_WINDOW_SEC} seconds, which means the cache was "
        "not notified about the new gateway"
    )
