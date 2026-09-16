# SPDX-License-Identifier: Apache-2.0

import atexit
import os
import shutil
import socket
import struct
import subprocess
import threading
import time

import pytest
import yaml

from nipart import NipartClient
from nipart import NipartError
from nipart import NipartApplyOption

from .conftest import start_daemon, stop_daemon
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml

RESOLV_CONF_PATH = "/etc/resolv.conf"
RESOLV_CONF_BACKUP = "/etc/resolv.conf.nipart-dns-test-backup"
APPLIED_STATE_PATH = "/etc/nipart/applied.yml"
APPLIED_SECRETS_PATH = "/etc/nipart/applied.secrets.yml"

DNS_CACHE_BIND = "127.0.0.1:53"
DNS_CACHE_HOST, DNS_CACHE_PORT = DNS_CACHE_BIND.rsplit(":", 1)
DNS_CACHE_PORT = int(DNS_CACHE_PORT)
TEST_SEARCH = "example.org"
TEST_SERVER = "192.0.2.250"
UPSTREAM_SERVER = "198.51.100.53"
UPSTREAM_DOMAIN = "dns-cache-test.invalid"
UPSTREAM_ADDRESS = "203.0.113.10"


def _encode_domain(domain):
    ret = b""
    for label in domain.strip(".").split("."):
        encoded = label.encode("ascii")
        ret += bytes([len(encoded)]) + encoded
    return ret + b"\x00"


def _query_packet(domain, transaction_id, qtype=1):
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + _encode_domain(domain) + struct.pack("!HH", qtype, 1)


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
        rdata = data[offset:rdata_end]
        answers.append((rr_type, rdata))
        offset += rdlength
    return answers


def _skip_domain(data, offset):
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def _a_records(data):
    return [
        socket.inet_ntoa(rdata)
        for (rr_type, rdata) in _parse_answers(data)
        if rr_type == 1 and len(rdata) == 4
    ]


def _ttls(data):
    """Return the minimum TTL of the response."""
    qdcount, ancount = struct.unpack("!HH", data[4:8])
    offset = 12
    for _ in range(qdcount):
        offset = _skip_domain(data, offset)
        offset += 4
    min_ttl = None
    for _ in range(ancount):
        offset = _skip_domain(data, offset)
        rr_header_end = offset + 10
        rr_header = data[offset:rr_header_end]
        _, _, ttl, rdlength = struct.unpack("!HHIH", rr_header)
        offset += 10 + rdlength
        min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
    return min_ttl


class FixedDnsUpstream:
    """Minimal UDP DNS server answering one A record for one domain."""

    def __init__(self, domain, address):
        self._domain = domain
        self._address = address
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self.port = self._socket.getsockname()[1]
        self.query_count = 0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while True:
            try:
                data, peer = self._socket.recvfrom(4096)
            except OSError:
                return
            self.query_count += 1
            try:
                response = self._reply(data)
            except (IndexError, struct.error, ValueError):
                continue
            self._socket.sendto(response, peer)

    def _reply(self, data):
        transaction_id = struct.unpack("!H", data[:2])[0]
        qdcount = struct.unpack("!H", data[4:6])[0]
        offset = 12
        question_end = offset
        for _ in range(qdcount):
            question_end = _skip_domain(data, question_end) + 4
        rdata = socket.inet_aton(self._address)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + rdata
        header = struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
        return header + data[12:question_end] + answer

    def close(self):
        self._socket.close()


def _dns_query(server, port, domain, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(_query_packet(domain, 0x1234), (server, port))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def _dns_cache_port_in_use():
    """Check without binding the port: probing must not race the daemon."""
    addr = f"{DNS_CACHE_HOST}:{DNS_CACHE_PORT}"
    for kind in ("u", "t"):
        output = subprocess.run(
            ["ss", f"-ln{kind}p"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        for line in output.splitlines():
            if addr in line.split():
                return True
    return False


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
def upstream():
    server = FixedDnsUpstream(UPSTREAM_DOMAIN, UPSTREAM_ADDRESS)
    yield server
    server.close()


@pytest.fixture(scope="module", autouse=True)
def free_dns_port():
    """Fail fast when another daemon already holds the DNS cache port."""

    def port_is_free():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", 53))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    if not port_is_free():
        pytest.fail(
            "127.0.0.1:53 is already in use; a leftover nipart "
            "daemon or another DNS service must be stopped first"
        )
    yield


def _running_dns_resolver():
    state = NipartClient().query_network_state()
    return state.get("dns-resolver", {})


def test_dns_cache_forwarding_and_cache(upstream, resolv_conf_backup):
    desired = f"""---
version: 1
dns-resolver:
  config:
    search:
      - {TEST_SEARCH}
    server:
      - 127.0.0.1
  cache:
    enabled: true
    bind: "{DNS_CACHE_BIND}"
    max-cache-size: 4096
    load-etc-hosts: true
    fallback:
      auto-dns: false
      nameservers:
        - "127.0.0.1:{upstream.port}"
"""
    cli = NipartClient()
    # memory-only keeps this cache-only config out of the saved state so
    # the resolver test below starts from a known state.
    cli.apply_network_state(
        load_yaml(desired), NipartApplyOption(memory_only=True)
    )

    running = _running_dns_resolver()
    assert running.get("running", {}).get("server", [])[0] == "127.0.0.1"

    # /etc/hosts lookup is answered without upstream.
    upstream_before = upstream.query_count
    answers = _a_records(_dns_query("127.0.0.1", 53, "localhost"))
    assert "127.0.0.1" in answers
    assert upstream.query_count == upstream_before

    # Unmatched domain is forwarded to the fallback nameserver.
    answers = _a_records(_dns_query("127.0.0.1", 53, UPSTREAM_DOMAIN))
    assert answers == [UPSTREAM_ADDRESS]
    assert upstream.query_count == upstream_before + 1

    # The second query is served from cache: the upstream query count must
    # not increase and the cached reply TTL must never go back up to the
    # upstream value (300s).  The TTL is decremented with a one second
    # granularity, so wait one second before checking it decreased.
    first_ttl = _ttls(_dns_query("127.0.0.1", 53, UPSTREAM_DOMAIN))
    assert 0 < first_ttl <= 300
    time.sleep(1.1)
    answers = _a_records(_dns_query("127.0.0.1", 53, UPSTREAM_DOMAIN))
    assert answers == [UPSTREAM_ADDRESS]
    assert upstream.query_count == upstream_before + 1
    assert _ttls(_dns_query("127.0.0.1", 53, UPSTREAM_DOMAIN)) < first_ttl


def test_dns_cache_recreated_on_config_change(resolv_conf_backup):
    """A changed cache config replaces the running server on the same port.

    The daemon stops the old cache server and starts a new one for the new
    configuration. The new server must be able to bind the port the old one
    held, and it must not serve the old server's cached replies.
    """
    upstream_a = FixedDnsUpstream(UPSTREAM_DOMAIN, "203.0.113.11")
    upstream_b = FixedDnsUpstream(UPSTREAM_DOMAIN, "203.0.113.12")
    try:
        desired = """---
version: 1
dns-resolver:
  config:
    server:
      - 127.0.0.1
  cache:
    enabled: true
    bind: "{bind}"
    fallback:
      auto-dns: false
      nameservers:
        - "127.0.0.1:{port}"
"""
        cli = NipartClient()
        cli.apply_network_state(
            load_yaml(
                desired.format(bind=DNS_CACHE_BIND, port=upstream_a.port)
            ),
            NipartApplyOption(memory_only=True),
        )
        answers = _a_records(_dns_query("127.0.0.1", 53, UPSTREAM_DOMAIN))
        assert answers == ["203.0.113.11"]

        cli.apply_network_state(
            load_yaml(
                desired.format(bind=DNS_CACHE_BIND, port=upstream_b.port)
            ),
            NipartApplyOption(memory_only=True),
        )
        answers = _a_records(_dns_query("127.0.0.1", 53, UPSTREAM_DOMAIN))
        assert answers == ["203.0.113.12"]
        assert upstream_b.query_count > 0
    finally:
        upstream_a.close()
        upstream_b.close()


def test_dns_cache_bind_must_be_first_server(resolv_conf_backup):
    desired = f"""---
version: 1
dns-resolver:
  config:
    server:
      - {TEST_SERVER}
  cache:
    enabled: true
    bind: "{DNS_CACHE_BIND}"
"""
    with pytest.raises(NipartError):
        NipartClient().apply_network_state(
            load_yaml(desired), NipartApplyOption(memory_only=True)
        )


def test_dns_cache_stop(resolv_conf_backup):
    desired = """---
version: 1
dns-resolver:
  cache:
    enabled: false
"""
    NipartClient().apply_network_state(
        load_yaml(desired), NipartApplyOption(memory_only=True)
    )

    def cache_stopped():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        try:
            sock.sendto(
                _query_packet(UPSTREAM_DOMAIN, 0x5678), ("127.0.0.1", 53)
            )
            try:
                sock.recvfrom(4096)
                return False
            except socket.timeout:
                return True
        finally:
            sock.close()

    retry_till_true_or_timeout(10, cache_stopped)

    # The stopped cache must release both its UDP and TCP sockets,
    # otherwise a later apply could not re-bind the same address.
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        udp.bind(("127.0.0.1", 53))
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", 53))
    except OSError as e:
        pytest.fail(f"DNS cache port not released after stop: {e}")
    finally:
        udp.close()
        tcp.close()


def test_dns_standard_resolver(resolv_conf_backup):
    desired = f"""---
version: 1
dns-resolver:
  config:
    search:
      - {TEST_SEARCH}
    server:
      - {TEST_SERVER}
    options:
      - trust-ad
      - rotate
"""
    NipartClient().apply_network_state(load_yaml(desired))

    with open(RESOLV_CONF_PATH, encoding="utf-8") as fd:
        content = fd.read()
    # Nipart managed entries are written under the static marker.
    assert "# nipart: static" in content
    assert f"nameserver {TEST_SERVER}" in content
    assert f"search {TEST_SEARCH}" in content
    assert "options trust-ad rotate" in content

    running = _running_dns_resolver().get("running", {})
    assert TEST_SERVER in running.get("server", [])
    assert TEST_SEARCH in running.get("search", [])
    assert "trust-ad" in running.get("options", [])

    # `config: {}` purges the static configuration.
    purge_desired = """---
version: 1
dns-resolver:
  config: {}
"""
    NipartClient().apply_network_state(load_yaml(purge_desired))
    with open(RESOLV_CONF_PATH, encoding="utf-8") as fd:
        content = fd.read()
    assert TEST_SERVER not in content


def test_dns_cache_restored_after_daemon_restart(upstream, resolv_conf_backup):
    """The DNS cache and `/etc/resolv.conf` survive a daemon restart."""
    # Diagnose a stale port holder before applying: the daemon reports
    # EADDRINUSE otherwise, hiding who holds the socket.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 53))
    except OSError as e:
        holder = subprocess.run(
            ["ss", "-lnup"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        pytest.fail(
            f"127.0.0.1:53 is already bound before the restart test "
            f"({e}):\n{holder}"
        )
    finally:
        probe.close()

    desired = f"""---
version: 1
dns-resolver:
  config:
    search:
      - {TEST_SEARCH}
    server:
      - 127.0.0.1
  cache:
    enabled: true
    bind: "{DNS_CACHE_BIND}"
    fallback:
      auto-dns: false
      nameservers:
        - "127.0.0.1:{upstream.port}"
"""
    NipartClient().apply_network_state(load_yaml(desired))

    stop_daemon()
    start_daemon()

    def cache_restored():
        try:
            answers = _a_records(_dns_query("127.0.0.1", 53, UPSTREAM_DOMAIN))
        except OSError:
            return False
        return answers == [UPSTREAM_ADDRESS]

    assert retry_till_true_or_timeout(15, cache_restored)

    with open(RESOLV_CONF_PATH, encoding="utf-8") as fd:
        content = fd.read()
    assert "nameserver 127.0.0.1" in content
    assert f"search {TEST_SEARCH}" in content

    dns_resolver = _running_dns_resolver()
    assert "127.0.0.1" in dns_resolver.get("running", {}).get("server", [])
    # The static configuration is also reported by the daemon.
    assert dns_resolver.get("config", {}).get("server") == ["127.0.0.1"]


def test_dns_cache_disabled_by_manual_applied_state_edit(resolv_conf_backup):
    """A manual `enabled: false` edit in applied.yml must survive a restart.

    `applied.secrets.yml` must only carry interface secrets. If it also
    carried a copy of `dns-resolver`, the daemon would merge it over
    `applied.yml` on startup and silently re-enable the cache.
    """
    desired = f"""---
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
    """
    NipartClient().apply_network_state(load_yaml(desired))
    assert _dns_cache_port_in_use()

    with open(APPLIED_SECRETS_PATH, encoding="utf-8") as fd:
        secrets = yaml.safe_load(fd) or {}
    assert "dns-resolver" not in secrets

    with open(APPLIED_STATE_PATH, encoding="utf-8") as fd:
        applied_backup = fd.read()
    with open(APPLIED_SECRETS_PATH, encoding="utf-8") as fd:
        secrets_backup = fd.read()

    try:
        stop_daemon()

        applied = yaml.safe_load(applied_backup)
        applied["dns-resolver"]["cache"]["enabled"] = False
        with open(APPLIED_STATE_PATH, "w", encoding="utf-8") as fd:
            yaml.safe_dump(applied, fd)

        start_daemon()

        # The boot restore runs asynchronously after the daemon answers
        # ping: give it a chance to (wrongly) start the cache.
        cache_restarted = retry_till_true_or_timeout(5, _dns_cache_port_in_use)
        assert not cache_restarted, (
            "dns-resolver in applied.secrets.yml overrode cache.enabled: "
            "false in applied.yml"
        )
    finally:
        stop_daemon()
        with open(APPLIED_STATE_PATH, "w", encoding="utf-8") as fd:
            fd.write(applied_backup)
        with open(APPLIED_SECRETS_PATH, "w", encoding="utf-8") as fd:
            fd.write(secrets_backup)
        start_daemon()
