# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the WIFI plugin and the wifi-cfg/wifi-phy schema.

All WIFI integration tests live in this single module. It covers, in order:
WPA2/open/WPA3/hidden security types, wifi-cfg profiles, DHCPv4/DHCPv6,
multiple SSIDs, daemon restart auto-connect and AP/phy appearing later.
"""

import os
import re
import signal
import subprocess
import time

import nipart
import pytest

from .conftest import CLI_PATH
from .conftest import restart_daemon  # noqa: F401
from .conftest import start_daemon
from .conftest import stop_daemon
from .testlib.cmdlib import exec_cmd
from .testlib.dhcp import DHCP_SRV_IP4
from .testlib.dhcp import DHCP_SRV_IP4_PREFIX
from .testlib.dhcp import DHCP_SRV_NIC
from .testlib.dhcp import DNSMASQ_CONF_PATH
from .testlib.dhcp import DNSMASQ_PID_PATH
from .testlib.dhcp import IPV4_CLASSLESS_ROUTE_DST_NET1
from .testlib.dhcp import stop_dhcp_server
from .testlib.env import has_kernel_module
from .testlib.env import npt_path
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml
from .testlib.statelib import show_only
from .testlib.wifi import AP2_NIC
from .testlib.wifi import HOSTAPD_CONF_PATH
from .testlib.wifi import HOSTAPD_CONF_PATH_2
from .testlib.wifi import HOSTAPD_PID_PATH
from .testlib.wifi import HOSTAPD_PID_PATH_2
from .testlib.wifi import HWSIM0_PERM_MAC
from .testlib.wifi import HWSIM1_PERM_MAC
from .testlib.wifi import HWSIM2_PERM_MAC
from .testlib.wifi import TEST_NET_NS
from .testlib.wifi import TEST_WIFI_PSK
from .testlib.wifi import TEST_WIFI_SSID
from .testlib.wifi import TEST_WIFI_SSID_2
from .testlib.wifi import TEST_WIFI_SSID_HIDDEN
from .testlib.wifi import TEST_WIFI_SSID_OPEN
from .testlib.wifi import TEST_WIFI_SSID_WPA3
from .testlib.wifi import TIMEOUT_SECS_SIM_WIFI_NICS
from .testlib.wifi import WIFI_TEST_NIC
from .testlib.wifi import create_sim_wifi_nics
from .testlib.wifi import destroy_sim_wifi_nics
from .testlib.wifi import get_nic_name_by_perm_mac
from .testlib.wifi import get_wifi_phy_name
from .testlib.wifi import hostapd_is_up_2
from .testlib.wifi import ping_wifi_peer
from .testlib.wifi import release_held_extra_wifi_phy
from .testlib.wifi import start_hostapd
from .testlib.wifi import start_hostapd_2
from .testlib.wifi import start_hostapd_hidden
from .testlib.wifi import start_hostapd_open
from .testlib.wifi import start_hostapd_wpa3
from .testlib.wifi import unload_wifi_sim_kernel_module
from .testlib.wifi import wifi_env  # noqa: F401

# Second AP + second DHCP server used by the SSID switch tests.
DHCP_SRV_IP4_PREFIX_2 = "198.51.100"
DHCP_SRV_IP4_2 = f"{DHCP_SRV_IP4_PREFIX_2}.1"
DNSMASQ_CONF_PATH_2 = "/tmp/nipart_test_dnsmasq2.conf"
DNSMASQ_PID_PATH_2 = "/tmp/nipart_test_dnsmasq2.pid"
TEST_NET_NS_2 = "wifi-test-2"
DUMMY_IFACE = "wifi-dhcp-dum0"
HOSTAPD_CONF_2_DS = f"""
interface={AP2_NIC}
driver=nl80211

hw_mode=g
channel=6
ssid={TEST_WIFI_SSID_2}

wpa=0
auth_algs=1
"""

# Multiple SSID environment.
AP_IP = "192.0.2.1"
AP_IPS = {
    TEST_WIFI_SSID: AP_IP,
    TEST_WIFI_SSID_2: AP_IP,
}
STA_IP = "192.0.2.99"

# DHCPv6 server.
DHCPV6_PREFIX = "2001:db8:5"
DHCPV6_SRV_IP6 = f"{DHCPV6_PREFIX}::1"
DHCPV6_LEASE_PATH = "/tmp/nipart_test_dnsmasq_v6_wifi.lease"

# The AP appears only after apply: with host-scan backoff on
# mac80211_hwsim (10 -> 20 -> ... -> 300 seconds between scans), the
# connect may take several backoff cycles, so keep the deadline in line
# with the plugin's bounded hunt.
CONNECT_TIMEOUT = 600


@pytest.fixture
def clean_up():
    yield
    nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {WIFI_TEST_NIC}
                type: wifi-phy
                state: absent"""))


@pytest.fixture(scope="class")
def wifi_open_env():
    create_sim_wifi_nics()
    exec_cmd("killall wpa_supplicant".split(), check=False)
    start_hostapd_open(TEST_NET_NS)
    yield
    destroy_sim_wifi_nics()


@pytest.fixture(scope="class")
def wifi_wpa3_env():
    create_sim_wifi_nics()
    start_hostapd_wpa3(TEST_NET_NS)
    yield
    destroy_sim_wifi_nics()


@pytest.fixture(scope="class")
def wifi_env_ap_later():
    # mac80211_hwsim + netns with both radios present but hostapd NOT
    # running yet: the AP is started inside the test, after the apply.
    create_sim_wifi_nics()
    # nipart.show() may have (re)started wpa_supplicant holding the
    # hwsim NIC; kill it so shuli owns the nl80211 connection.
    exec_cmd("killall wpa_supplicant".split(), check=False)
    yield
    destroy_sim_wifi_nics()


@pytest.fixture(scope="class")
def wifi_hidden_env():
    create_sim_wifi_nics()
    exec_cmd("killall wpa_supplicant".split(), check=False)
    start_hostapd_hidden(TEST_NET_NS)
    yield
    destroy_sim_wifi_nics()


def has_three_sim_wifi_nics():
    exec_cmd("udevadm settle".split())
    state = nipart.show()
    return all(
        get_nic_name_by_perm_mac(state, mac)
        for mac in (HWSIM0_PERM_MAC, HWSIM1_PERM_MAC, HWSIM2_PERM_MAC)
    )


def _start_dhcp_server_2():
    exec_cmd(
        f"ip netns exec {TEST_NET_NS_2} "
        f"ip addr add {DHCP_SRV_IP4_2}/24 dev {AP2_NIC}".split()
    )
    dnsmasq_conf = (
        "leasefile-ro\n"
        f"interface={AP2_NIC}\n"
        f"dhcp-range={DHCP_SRV_IP4_PREFIX_2}.200,"
        f"{DHCP_SRV_IP4_PREFIX_2}.250,255.255.255.0,48h\n"
        f"dhcp-option=option:dns-server,{DHCP_SRV_IP4_2}\n"
    )
    with open(DNSMASQ_CONF_PATH_2, "w") as fd:
        fd.write(dnsmasq_conf)
    exec_cmd(
        f"sudo ip netns exec {TEST_NET_NS_2} dnsmasq "
        f"--interface={AP2_NIC} --log-dhcp "
        f"--pid-file={DNSMASQ_PID_PATH_2} "
        f"--conf-file={DNSMASQ_CONF_PATH_2} ".split()
    )


def _start_dhcp_server():
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"ip addr add {DHCP_SRV_IP4}/24 dev {DHCP_SRV_NIC}".split()
    )
    dnsmasq_conf = (
        "leasefile-ro\n"
        f"interface={DHCP_SRV_NIC}\n"
        f"dhcp-range={DHCP_SRV_IP4_PREFIX}.200,"
        f"{DHCP_SRV_IP4_PREFIX}.250,255.255.255.0,48h\n"
        f"dhcp-option=option:dns-server,{DHCP_SRV_IP4}\n"
    )
    with open(DNSMASQ_CONF_PATH, "w") as fd:
        fd.write(dnsmasq_conf)
    exec_cmd(
        f"sudo ip netns exec {TEST_NET_NS} dnsmasq "
        f"--interface={DHCP_SRV_NIC} --bind-interfaces --log-dhcp "
        f"--pid-file={DNSMASQ_PID_PATH} "
        f"--conf-file={DNSMASQ_CONF_PATH} ".split()
    )


def _stop_dhcp_server_2():
    if not os.path.exists(DNSMASQ_PID_PATH_2):
        return
    with open(DNSMASQ_PID_PATH_2) as fd:
        try:
            os.kill(int(fd.read()), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass


def _pid_alive(pid_path):
    if not os.path.exists(pid_path):
        return False
    with open(pid_path) as fd:
        pid = fd.read().strip()
    if not pid:
        return False
    try:
        with open(f"/proc/{pid}/stat") as fd:
            state = fd.read().split()[2]
        return state != "Z"
    except (FileNotFoundError, ProcessLookupError, ValueError):
        return False


def _dhcp_server_1_running():
    return _pid_alive(DNSMASQ_PID_PATH)


def _dhcp_server_2_running():
    return _pid_alive(DNSMASQ_PID_PATH_2)


def _start_hostapd_2():
    phy_id = get_wifi_phy_name(AP2_NIC)
    assert phy_id
    exec_cmd(f"iw phy#{phy_id} set netns name {TEST_NET_NS_2}".split())
    exec_cmd(f"ip netns exec {TEST_NET_NS_2} ip link set {AP2_NIC} up".split())
    with open(HOSTAPD_CONF_PATH_2, "w") as fd:
        fd.write(HOSTAPD_CONF_2_DS)
    exec_cmd(
        f"ip netns exec {TEST_NET_NS_2} "
        f"hostapd -B -d {HOSTAPD_CONF_PATH_2} "
        f"-P {HOSTAPD_PID_PATH_2}".split(),
    )
    assert retry_till_true_or_timeout(2, hostapd_is_up_2)


@pytest.fixture(scope="class")
def two_dhcp_ap_env():
    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS_2}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())
    exec_cmd(f"ip netns add {TEST_NET_NS_2}".split())

    exec_cmd("modprobe mac80211_hwsim radios=3".split())
    assert retry_till_true_or_timeout(
        TIMEOUT_SECS_SIM_WIFI_NICS, has_three_sim_wifi_nics
    )

    state = nipart.show()
    exec_cmd("killall wpa_supplicant".split(), check=False)
    wlan0 = get_nic_name_by_perm_mac(state, HWSIM0_PERM_MAC)
    exec_cmd(f"ip link set {wlan0} name {WIFI_TEST_NIC}".split())
    wlan1 = get_nic_name_by_perm_mac(state, HWSIM1_PERM_MAC)
    exec_cmd(f"ip link set {wlan1} name {DHCP_SRV_NIC}".split())
    wlan2 = get_nic_name_by_perm_mac(state, HWSIM2_PERM_MAC)
    exec_cmd(f"ip link set {wlan2} name {AP2_NIC}".split())

    start_hostapd(with_dhcp=False)
    _start_hostapd_2()
    _start_dhcp_server()
    _start_dhcp_server_2()
    assert retry_till_true_or_timeout(5, _dhcp_server_2_running)
    yield

    _stop_dhcp_server_2()
    stop_dhcp_server()
    for pid_path in (HOSTAPD_PID_PATH, HOSTAPD_PID_PATH_2):
        if os.path.exists(pid_path):
            with open(pid_path) as fd:
                pid = fd.read()
            if pid:
                os.kill(int(pid), signal.SIGTERM)
    for conf_path in (HOSTAPD_CONF_PATH, HOSTAPD_CONF_PATH_2):
        if os.path.exists(conf_path):
            os.remove(conf_path)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS_2}".split(), check=False)
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


@pytest.fixture(scope="class")
def multi_ap_env():
    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())

    exec_cmd("modprobe mac80211_hwsim radios=3".split())
    assert retry_till_true_or_timeout(
        TIMEOUT_SECS_SIM_WIFI_NICS, has_three_sim_wifi_nics
    )

    state = nipart.show()
    exec_cmd("killall wpa_supplicant".split(), check=False)
    wlan1 = get_nic_name_by_perm_mac(state, HWSIM0_PERM_MAC)
    exec_cmd(f"ip link set {wlan1} name {WIFI_TEST_NIC}".split())
    wlan2 = get_nic_name_by_perm_mac(state, HWSIM1_PERM_MAC)
    exec_cmd(f"ip link set {wlan2} name {DHCP_SRV_NIC}".split())
    wlan3 = get_nic_name_by_perm_mac(state, HWSIM2_PERM_MAC)
    exec_cmd(f"ip link set {wlan3} name {AP2_NIC}".split())
    start_hostapd(with_dhcp=False)
    start_hostapd_2()
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} ip link add name br-test "
        "type bridge".split()
    )
    for nic in (DHCP_SRV_NIC, AP2_NIC):
        exec_cmd(
            f"ip netns exec {TEST_NET_NS} ip link set {nic} "
            "master br-test".split()
        )
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} ip addr add "
        f"{AP_IP}/24 dev br-test".split()
    )
    exec_cmd(f"ip netns exec {TEST_NET_NS} ip link set br-test up".split())
    print(exec_cmd(f"ip netns exec {TEST_NET_NS} ip -br addr show".split())[1])
    yield
    for pid_path in (HOSTAPD_PID_PATH, HOSTAPD_PID_PATH_2):
        if os.path.exists(pid_path):
            with open(pid_path) as fd:
                pid = fd.read()
            os.kill(int(pid), signal.SIGTERM)
    for conf_path in (HOSTAPD_CONF_PATH, HOSTAPD_CONF_PATH_2):
        if os.path.exists(conf_path):
            os.remove(conf_path)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split())
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


def _start_dhcpv6_server():
    stop_dhcp_server()
    exec_cmd(["sudo", "rm", "-f", DHCPV6_LEASE_PATH])
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"ip addr del {DHCPV6_SRV_IP6}/64 dev {DHCP_SRV_NIC}".split(),
        check=False,
    )
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"ip addr add {DHCPV6_SRV_IP6}/64 dev {DHCP_SRV_NIC}".split()
    )
    exec_cmd(
        f"sudo ip netns exec {TEST_NET_NS} dnsmasq "
        f"--log-dhcp --conf-file=/dev/null "
        f"--dhcp-leasefile={DHCPV6_LEASE_PATH} "
        f"--pid-file={DNSMASQ_PID_PATH} --no-hosts "
        f"--dhcp-host=dummy-host,{DHCP_SRV_IP4_PREFIX}.99 "
        f"--dhcp-option=option:dns-server,8.8.8.8,1.1.1.1 "
        f"--dhcp-option=option:mtu,1492 "
        f"--dhcp-option=option:domain-name,example.com "
        f"--dhcp-option=option:ntp-server,{DHCP_SRV_IP4} "
        f"--dhcp-option=option6:ntp-server,"
        f"ntp-a.example.com,ntp-b.example.com "
        f"--dhcp-option=121,203.0.113.0/24,{DHCP_SRV_IP4_PREFIX}.40 "
        f"--dhcp-option=249,203.0.113.0/24,{DHCP_SRV_IP4_PREFIX}.40 "
        f"--interface={DHCP_SRV_NIC} --enable-ra "
        f"--dhcp-range={DHCPV6_PREFIX}::2,{DHCPV6_PREFIX}::fff,ra-names,"
        f"slaac,64,2m "
        f"--dhcp-range={DHCP_SRV_IP4_PREFIX}.2,{DHCP_SRV_IP4_PREFIX}.50,2m "
        f"--no-ping".split()
    )


@pytest.fixture(scope="class")
def dhcpv6_server(wifi_env):  # noqa: F811
    _start_dhcpv6_server()
    yield


def connected_ssid():
    return iface_connected_ssid(WIFI_TEST_NIC)


def iface_connected_ssid(iface_name):
    rc, out, _ = exec_cmd(f"iw dev {iface_name} link".split(), check=False)
    if rc != 0:
        return None
    match = re.search(r"SSID: (.+)", out)
    return match.group(1) if match else None


def connected_bssid(iface_name=WIFI_TEST_NIC):
    rc, out, _ = exec_cmd(f"iw dev {iface_name} link".split(), check=False)
    if rc != 0:
        return None
    match = re.search(r"Connected to ([0-9a-fA-F:]+)", out)
    return match.group(1).upper() if match else None


def _ipv4_addrs():
    rc, out, _ = exec_cmd(
        ["ip", "-4", "-o", "addr", "show", "dev", WIFI_TEST_NIC],
        check=False,
    )
    if rc != 0:
        return []
    addrs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet":
            addrs.append(parts[3].split("/")[0])
    return addrs


def _has_ipv4_prefix(prefix):
    return any(addr.startswith(f"{prefix}.") for addr in _ipv4_addrs())


def _wifi_cfg_profile_yaml(ssid, password=None):
    lines = [
        "---",
        "interfaces:",
        f"  - name: {ssid}",
        "    type: wifi-cfg",
        "    state: up",
        "    wifi:",
        f"      ssid: {ssid}",
    ]
    if password is not None:
        lines.append(f"      password: {password}")
    lines += [
        "    ipv4:",
        "      enabled: true",
        "      dhcp: true",
    ]
    return load_yaml("\n".join(lines))


def _cleanup_wifi_profiles():
    """Drop leftover wifi profiles so the test starts from a known state."""
    nipart.apply(load_yaml(f"""---
        interfaces:
          - name: {WIFI_TEST_NIC}
            type: wifi-phy
            state: absent"""))
    for ssid in (TEST_WIFI_SSID, TEST_WIFI_SSID_2):
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {ssid}
                type: wifi-cfg
                state: absent"""))


def has_wifi_cfg_route():
    output = exec_cmd(
        ["ip", "-4", "route", "show", "dev", WIFI_TEST_NIC],
        check=False,
    )[1]
    return IPV4_CLASSLESS_ROUTE_DST_NET1 in output and DHCP_SRV_IP4 in output


def wifi_cfg_yaml(state):
    return load_yaml(f"""---
    interfaces:
      - name: {TEST_WIFI_SSID}
        type: wifi-cfg
        state: {state}
        wifi:
          ssid: {TEST_WIFI_SSID}
          password: {TEST_WIFI_PSK}
          base-iface: {WIFI_TEST_NIC}""")


def link_is_up():
    output = exec_cmd(
        f"ip -br link show {WIFI_TEST_NIC}".split(), check=False
    )[1]
    return "UP" in output


def get_wifi_ssid():
    state = nipart.show()
    for iface in state["interfaces"]:
        if iface.get("name") == WIFI_TEST_NIC:
            return (iface.get("wifi") or {}).get("ssid")
    return None


def is_wifi_connected():
    return get_wifi_ssid() == TEST_WIFI_SSID


def wait_for_ssid(ssid, timeout=30):
    deadline = time.time() + timeout
    output = ""
    while time.time() < deadline:
        output = exec_cmd(f"iw dev {WIFI_TEST_NIC} link".split(), check=False)[
            1
        ]
        match = re.search(r"SSID: (.+)", output)
        if match and match.group(1) == ssid:
            return True
        time.sleep(1)
    print(f"iw link output while waiting for {ssid}: {output!r}")
    print(
        exec_cmd(f"ip -br addr show {WIFI_TEST_NIC}".split(), check=False)[1]
    )
    return False


def wifi_cfg_state_yaml(*ssid_password_states):
    entries = []
    for ssid, password, state in ssid_password_states:
        password_line = ""
        if password:
            password_line = f"\n        password: {password}"
        entries.append(f"""    - name: {ssid}
      type: wifi-cfg
      state: {state}
      wifi:
        ssid: {ssid}{password_line}
        base-iface: {WIFI_TEST_NIC}
      ipv4:
        enabled: true
        dhcp: false
        address:
          - ip: {STA_IP}
            prefix-length: 24""")
    return "---\n  interfaces:\n" + "\n".join(entries)


def wifi_phy_state_yaml(ssid, password=None):
    password_line = ""
    if password:
        password_line = f"\n                      password: {password}"
    return f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {ssid}{password_line}
                    ipv4:
                      enabled: true
                      dhcp: false
                      address:
                        - ip: {STA_IP}
                          prefix-length: 24"""


def _has_dhcpv6_addr():
    rc, out, _ = exec_cmd(
        ["ip", "-6", "addr", "show", "dev", WIFI_TEST_NIC],
        check=False,
    )
    if rc != 0:
        return False
    return DHCPV6_PREFIX in out and "/128" in out


def _dhcpv6_state_done():
    iface_state = show_only(WIFI_TEST_NIC)
    if iface_state is None:
        return False
    ipv6_conf = iface_state.get("ipv6", {})
    return ipv6_conf.get("dhcp") is True and (
        ipv6_conf.get("dhcp-state") == "done"
    )


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason=("Does not have 'mac80211_hwsim' module "),
)
class TestWifi:
    def has_static_ip_and_route(self):
        rc, out, _ = exec_cmd(
            ["ip", "-4", "-o", "addr", "show", "dev", WIFI_TEST_NIC],
            check=False,
        )
        if rc != 0 or f"{DHCP_SRV_IP4_PREFIX}.99/24" not in out:
            return False
        rc, out, _ = exec_cmd(
            ["ip", "-4", "route", "show", "dev", WIFI_TEST_NIC],
            check=False,
        )
        return rc == 0 and (
            f"{IPV4_CLASSLESS_ROUTE_DST_NET1} via {DHCP_SRV_IP4}" in out
        )

    def has_no_static_ip_and_route(self):
        rc, out, _ = exec_cmd(
            ["ip", "-4", "-o", "addr", "show", "dev", WIFI_TEST_NIC],
            check=False,
        )
        if rc != 0 or f"{DHCP_SRV_IP4_PREFIX}.99/24" in out:
            return False
        rc, out, _ = exec_cmd(
            ["ip", "-4", "route", "show", "dev", WIFI_TEST_NIC],
            check=False,
        )
        return rc == 0 and IPV4_CLASSLESS_ROUTE_DST_NET1 not in out

    def test_wifi_iface_static_ip(self, clean_up, wifi_env):  # noqa: F811
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                    ipv4:
                      enabled: true
                      dhcp: false
                      address:
                        - ip: {DHCP_SRV_IP4_PREFIX}.99
                          prefix-length: 24"""))
        assert retry_till_true_or_timeout(5, ping_wifi_peer)

    def test_wifi_iface_dhcpv4(self, clean_up, wifi_env):  # noqa: F811
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                    ipv4:
                      enabled: true
                      dhcp: true"""))
        assert retry_till_true_or_timeout(5, ping_wifi_peer)

    def test_wifi_scan_dump_without_subcommand(
        self, clean_up, wifi_env  # noqa: F811
    ):
        # `npt wifi` without argument dumps the scan results the kernel
        # already has (like `iw dev <iface> scan dump`) in the same
        # output format as `npt wifi scan`.
        #
        # The previous test's cleanup brought the WIFI interface down;
        # an active scan requires it to be up.
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up"""))
        exec_cmd([npt_path(), "wifi", "scan"])
        rc, out, err = exec_cmd([npt_path(), "wifi"], check=False)
        assert rc == 0, f"npt wifi failed:\n{out}\n{err}"
        assert "IN-USE" in out, out
        assert "SSID" in out, out
        assert "SECURITY" in out, out
        assert TEST_WIFI_SSID in out, out

        # Dumping the kernel scan results needs no root permission: only
        # triggering a new scan does.
        npt_as_nobody = [
            "setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            npt_path(),
            "wifi",
        ]
        rc, out, err = exec_cmd(npt_as_nobody, check=False)
        assert rc == 0, f"npt wifi as non-root failed:\n{out}\n{err}"
        assert TEST_WIFI_SSID in out, out
        rc, _, err = exec_cmd([*npt_as_nobody, "scan"], check=False)
        assert rc != 0, "npt wifi scan should require root permission"
        assert "root permission" in err, err

    def test_wifi_off_scan_fails_and_up_restores(
        self, clean_up, wifi_env  # noqa: F811
    ):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                    ipv4:
                      enabled: true
                      dhcp: false
                      address:
                        - ip: {DHCP_SRV_IP4_PREFIX}.99
                          prefix-length: 24
                routes:
                  config:
                    - destination: {IPV4_CLASSLESS_ROUTE_DST_NET1}
                      next-hop-interface: {WIFI_TEST_NIC}
                      next-hop-address: {DHCP_SRV_IP4}
                      table-id: 254
                """))
        assert retry_till_true_or_timeout(5, ping_wifi_peer)
        assert retry_till_true_or_timeout(
            5, self.has_static_ip_and_route
        ), "WIFI static IP or route missing before `npt wifi off`"
        assert connected_ssid() == TEST_WIFI_SSID
        try:
            rc, out, err = exec_cmd([CLI_PATH, "wifi", "off"], check=False)
            assert rc == 0, f"npt wifi off failed:\n{out}\n{err}"
            assert "WIFI is off" in out, out
            assert retry_till_true_or_timeout(
                5, lambda: connected_ssid() is None
            )
            assert retry_till_true_or_timeout(
                10, self.has_no_static_ip_and_route
            ), "WIFI IP or route was not purged by `npt wifi off`"
            # The connectivity check must not be answered by another
            # interface of the test machine: this ping succeeds only when
            # the traffic leaves through WIFI.
            assert not ping_wifi_peer()

            rc, out, err = exec_cmd([CLI_PATH, "wifi", "scan"], check=False)
            assert rc != 0, "npt wifi scan should fail while WIFI is off"
            assert "WIFI is off" in err, err

            rc, out, err = exec_cmd([CLI_PATH, "wifi", "on"], check=False)
            assert rc == 0, f"npt wifi on failed:\n{out}\n{err}"
            assert "WIFI is on" in out, out

            # `npt wifi on` only re-enables WIFI: the plugin reconnects
            # to the saved profile asynchronously (shuli scans and then
            # completes the handshake), and the daemon restores the
            # saved IP stack when the link-up event is processed.
            assert retry_till_true_or_timeout(
                30, lambda: connected_ssid() == TEST_WIFI_SSID
            ), "WIFI did not reconnect to the saved SSID after `npt wifi on`"
            assert retry_till_true_or_timeout(
                10, ping_wifi_peer
            ), "Cannot ping peer through WIFI after `npt wifi on`"
            assert retry_till_true_or_timeout(
                10, self.has_static_ip_and_route
            ), "WIFI static IP or route not restored by `npt wifi on`"
        finally:
            exec_cmd([CLI_PATH, "wifi", "on"], check=False)


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' module",
)
class TestWifiCfg:
    def test_unrelated_apply_keeps_connection(
        self, clean_up, wifi_env  # noqa: F811
    ):
        nipart.apply(wifi_cfg_yaml("up"))
        assert retry_till_true_or_timeout(
            30, lambda: connected_ssid() == TEST_WIFI_SSID
        )
        nipart.apply(load_yaml("""---
        interfaces:
          - name: lo
            type: loopback
            state: up"""))
        assert retry_till_true_or_timeout(
            10, lambda: connected_ssid() == TEST_WIFI_SSID
        )

    def test_wifi_cfg_down_and_absent_disconnects(
        self, clean_up, wifi_env  # noqa: F811
    ):
        nipart.apply(wifi_cfg_yaml("up"))
        assert retry_till_true_or_timeout(
            30, lambda: connected_ssid() == TEST_WIFI_SSID
        )
        nipart.apply(wifi_cfg_yaml("down"))
        assert retry_till_true_or_timeout(10, lambda: connected_ssid() is None)
        nipart.apply(wifi_cfg_yaml("absent"))
        assert retry_till_true_or_timeout(10, lambda: connected_ssid() is None)

    def test_wifi_cfg_routes_by_profile_name(
        self, clean_up, wifi_env  # noqa: F811
    ):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_WIFI_SSID}
                    type: wifi-cfg
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                      base-iface: {WIFI_TEST_NIC}
                    ipv4:
                      enabled: true
                      dhcp: false
                      address:
                        - ip: {DHCP_SRV_IP4_PREFIX}.99
                          prefix-length: 24
                routes:
                  config:
                    - destination: {IPV4_CLASSLESS_ROUTE_DST_NET1}
                      next-hop-interface: {TEST_WIFI_SSID}
                      next-hop-address: {DHCP_SRV_IP4}
                      table-id: 254
                """))
        assert retry_till_true_or_timeout(
            60, lambda: connected_ssid() == TEST_WIFI_SSID
        )
        assert retry_till_true_or_timeout(
            60, has_wifi_cfg_route
        ), "Route by wifi-cfg profile name was not applied"


def _wifi_connect(ssid, password, hidden=False):
    """Run `npt wifi connect <ssid>` feeding `password` on STDIN."""
    cmd = [CLI_PATH, "wifi", "connect", ssid]
    if hidden:
        cmd.append("--hidden")
    proc = subprocess.run(
        cmd,
        input=f"{password}\n".encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return (
        proc.returncode,
        proc.stdout.decode("utf-8"),
        proc.stderr.decode("utf-8"),
    )


def _saved_wifi_cfg(ssid):
    client = nipart.NipartClient()
    state = client.query_network_state(nipart.NipartQueryOption.saved())
    for iface in state["interfaces"]:
        if iface.get("name") == ssid and iface.get("type") == "wifi-cfg":
            return iface
    return None


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' module",
)
class TestWifiConnectCommand:
    @pytest.fixture(autouse=True)
    def clean_up_connect_profile(self):
        # Start from a clean profile: earlier test classes may have left
        # a saved profile for the same SSID.
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_WIFI_SSID}
                type: wifi-cfg
                state: absent"""))
        yield
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_WIFI_SSID}
                type: wifi-cfg
                state: absent"""))

    def test_wrong_password_fails_and_rolls_back(
        self, clean_up, wifi_env  # noqa: F811
    ):
        assert connected_ssid() != TEST_WIFI_SSID
        rc, out, err = _wifi_connect(TEST_WIFI_SSID, "wrong-password")
        assert rc != 0, (
            "npt wifi connect accepted a wrong password:\n" f"{out}\n{err}"
        )
        assert "wrong password" in (out + err), (out, err)
        assert (
            connected_ssid() != TEST_WIFI_SSID
        ), "the failed connection attempt was left associated"
        # The failed profile must not be persisted: a saved profile
        # would be retried in the background and at boot.
        assert (
            _saved_wifi_cfg(TEST_WIFI_SSID) is None
        ), "the failed npt wifi connect profile was persisted"

    def test_connect_waits_for_authenticated_link(
        self, clean_up, wifi_env  # noqa: F811
    ):
        assert connected_ssid() != TEST_WIFI_SSID
        rc, out, err = _wifi_connect(TEST_WIFI_SSID, TEST_WIFI_PSK)
        assert rc == 0, f"npt wifi connect failed:\n{out}\n{err}"
        # The command must not return before the plugin completed the
        # association and the 4-way handshake.
        assert (
            connected_ssid() == TEST_WIFI_SSID
        ), "npt wifi connect returned before the WIFI link was connected"
        assert retry_till_true_or_timeout(10, ping_wifi_peer)

    def test_killed_client_rolls_back_pending_connect(
        self, clean_up, wifi_env  # noqa: F811
    ):
        # Save and connect a profile first so the rollback has something
        # to restore.
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_WIFI_SSID}
                    type: wifi-cfg
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                      base-iface: {WIFI_TEST_NIC}
                """))
        assert retry_till_true_or_timeout(
            60, lambda: connected_ssid() == TEST_WIFI_SSID
        )

        proc = subprocess.Popen(
            [CLI_PATH, "wifi", "connect", "No-Such-SSID-XY", "--no-pass"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            # Applying the unavailable SSID makes the plugin drop the
            # current connection and scan for the new one.
            assert retry_till_true_or_timeout(
                30, lambda: connected_ssid() != TEST_WIFI_SSID
            ), "plugin never replaced the current SSID with the request"
            # Simulate the user giving up on the connect command.
            proc.kill()
            proc.wait()
            # The daemon must abort the orphaned apply and roll back so
            # the saved profile reconnects without a daemon restart.
            assert wait_for_ssid(TEST_WIFI_SSID, timeout=45), (
                "the saved WIFI profile did not reconnect after the "
                "connect client was killed"
            )
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            # Before the fix the abandoned apply keeps running for up to
            # two WIFI connect timeouts; restart the daemon to unblock
            # the rest of the session.
            stop_daemon()
            start_daemon()


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' module",
)
class TestWifiConnectHiddenCommand:
    @pytest.fixture(autouse=True)
    def clean_up_connect_profile(self):
        # Start from a clean profile: earlier test classes may have left
        # a saved profile for the same SSID.
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_WIFI_SSID_HIDDEN}
                type: wifi-cfg
                state: absent"""))
        yield
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_WIFI_SSID_HIDDEN}
                type: wifi-cfg
                state: absent"""))

    def test_connect_hidden_ssid(
        self, clean_up, wifi_hidden_env  # noqa: F811
    ):
        assert connected_ssid() != TEST_WIFI_SSID_HIDDEN
        rc, out, err = _wifi_connect(
            TEST_WIFI_SSID_HIDDEN, TEST_WIFI_PSK, hidden=True
        )
        assert rc == 0, f"npt wifi connect --hidden failed:\n{out}\n{err}"
        assert connected_ssid() == TEST_WIFI_SSID_HIDDEN, (
            "npt wifi connect --hidden returned before the WIFI link was "
            "connected"
        )
        assert (
            _saved_wifi_cfg(TEST_WIFI_SSID_HIDDEN) is not None
        ), "the connected hidden SSID profile was not persisted"


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' module",
)
class TestWifiHiddenReapply:
    def test_apply_show_state_keeps_hidden_password(
        self, clean_up, wifi_env  # noqa: F811
    ):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_WIFI_SSID}
                    type: wifi-cfg
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                      base-iface: {WIFI_TEST_NIC}"""))
        assert retry_till_true_or_timeout(
            30, lambda: connected_ssid() == TEST_WIFI_SSID
        )

        output = exec_cmd(
            f"{npt_path()} show --saved {TEST_WIFI_SSID}".split()
        )[1]
        shown_state = load_yaml(output)
        shown_wifi = shown_state["interfaces"][0]["wifi"]
        assert shown_wifi["password"] == "<_hidden_>"

        nipart.apply(shown_state)

        assert retry_till_true_or_timeout(
            10, lambda: connected_ssid() == TEST_WIFI_SSID
        )
        client = nipart.NipartClient()
        state = client.query_network_state(
            nipart.NipartQueryOption(saved=True, include_secrets=True)
        )
        wifi = next(
            i for i in state["interfaces"] if i["name"] == TEST_WIFI_SSID
        )
        assert wifi["wifi"]["password"] == TEST_WIFI_PSK


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' module",
)
class TestWifiDhcpV6:
    @pytest.fixture(autouse=True)
    def clean_up_profile(self):
        yield
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_WIFI_SSID}
                type: wifi-cfg
                state: absent"""))

    def test_wifi_phy_dhcpv6(self, clean_up, dhcpv6_server):  # noqa: F811
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                    ipv6:
                      enabled: true
                      dhcp: true"""))
        assert retry_till_true_or_timeout(60, _has_dhcpv6_addr)
        assert retry_till_true_or_timeout(60, _dhcpv6_state_done)

    def test_wifi_cfg_dhcpv6_already_connected(
        self, clean_up, dhcpv6_server  # noqa: F811
    ):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_WIFI_SSID}
                    type: wifi-cfg
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                      base-iface: {WIFI_TEST_NIC}"""))
        assert retry_till_true_or_timeout(
            60, lambda: connected_ssid() == TEST_WIFI_SSID
        )
        nipart.apply(
            load_yaml(f"""---
                interfaces:
                  - name: {TEST_WIFI_SSID}
                    type: wifi-cfg
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                      base-iface: {WIFI_TEST_NIC}
                    ipv6:
                      enabled: true
                      dhcp: true"""),
            verify_change=False,
        )
        assert retry_till_true_or_timeout(60, _has_dhcpv6_addr)

    def test_wifi_cfg_dhcpv6(self, clean_up, dhcpv6_server):  # noqa: F811
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_WIFI_SSID}
                    type: wifi-cfg
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                      base-iface: {WIFI_TEST_NIC}
                    ipv6:
                      enabled: true
                      dhcp: true"""))
        assert retry_till_true_or_timeout(
            60, lambda: connected_ssid() == TEST_WIFI_SSID
        )
        assert retry_till_true_or_timeout(60, _has_dhcpv6_addr)


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' module",
)
class TestWifiOpen:
    def test_wifi_open_iface_static_ip(
        self, clean_up, wifi_open_env
    ):  # noqa: F811
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_OPEN}
                    ipv4:
                      enabled: true
                      dhcp: false
                      address:
                        - ip: {DHCP_SRV_IP4_PREFIX}.99
                          prefix-length: 24"""))
        assert retry_till_true_or_timeout(10, ping_wifi_peer)

    def test_wifi_open_iface_dhcpv4(
        self, clean_up, wifi_open_env
    ):  # noqa: F811
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_OPEN}
                    ipv4:
                      enabled: true
                      dhcp: true"""))
        assert retry_till_true_or_timeout(10, ping_wifi_peer)


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestWifiBootAutoConnect:
    def test_open_wifi_cfg_reconnects_after_daemon_restart(
        self, wifi_open_env, restart_daemon  # noqa: F811
    ):
        try:
            nipart.apply(load_yaml(f"""---
                    interfaces:
                      - name: {WIFI_TEST_NIC}
                        type: wifi-phy
                        state: up
                      - name: {TEST_WIFI_SSID_OPEN}
                        type: wifi-cfg
                        state: up
                        wifi:
                          ssid: {TEST_WIFI_SSID_OPEN}"""))
            assert retry_till_true_or_timeout(
                30, lambda: connected_ssid() == TEST_WIFI_SSID_OPEN
            )

            # The daemon restart must re-apply the saved open wifi-cfg
            # profile: the wifi plugin is a fresh process and has no live
            # connection until the boot apply configures it.
            stop_daemon()
            # A daemon restart alone keeps the kernel association; drop it
            # so the boot apply has to reconnect, like after a real reboot.
            exec_cmd(f"ip link set {WIFI_TEST_NIC} down".split())
            assert retry_till_true_or_timeout(
                10, lambda: connected_ssid() is None
            )
            start_daemon()
            assert retry_till_true_or_timeout(
                60, lambda: connected_ssid() == TEST_WIFI_SSID_OPEN
            ), (
                "open wifi-cfg did not auto-connect after daemon restart: "
                f"{connected_ssid()}"
            )
        finally:
            # Drop the saved profiles so a later module starts clean.
            nipart.apply(load_yaml(f"""---
                    interfaces:
                      - name: {WIFI_TEST_NIC}
                        type: wifi-phy
                        state: absent
                      - name: {TEST_WIFI_SSID_OPEN}
                        type: wifi-cfg
                        state: absent"""))


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestWifiRenameTarget:
    """A saved `kernel-iface-name` is a rename instruction: the daemon must
    rename the NIC to it and the WIFI connection must come up on the new
    name (the pre-rename name is kept as an alt-name)."""

    START_NAME = "wlp-renamed0"
    # Kernel interface names are limited to 15 characters (IFNAMSIZ - 1).
    TARGET_NAME = "wlp-renamed0-t"
    SAVED_STATE_FILE = "/etc/nipart/applied.yml"

    def test_rename_target_boot_connects(self, wifi_env):  # noqa: F811
        try:
            stop_daemon()
            exec_cmd(["ip", "link", "del", self.START_NAME], check=False)
            exec_cmd(["ip", "link", "del", self.TARGET_NAME], check=False)
            exec_cmd(
                f"ip link set {WIFI_TEST_NIC} name {self.START_NAME}".split()
            )
            mac = (
                exec_cmd(
                    f"cat /sys/class/net/{self.START_NAME}/address".split()
                )[1]
                .strip()
                .upper()
            )
            os.makedirs(os.path.dirname(self.SAVED_STATE_FILE), exist_ok=True)
            with open(self.SAVED_STATE_FILE, "w") as state_f:
                state_f.write(f"""---
version: 1
interfaces:
- name: {self.START_NAME}
  kernel-iface-name: {self.TARGET_NAME}
  profile-name: {self.START_NAME}
  type: wifi-phy
  identifier: mac-address
  state: up
  mac-address: {mac}
  alt-names:
  - name: {self.START_NAME}
- name: {TEST_WIFI_SSID}
  type: wifi-cfg
  state: up
  wifi:
    ssid: {TEST_WIFI_SSID}
    password: {TEST_WIFI_PSK}
  ipv4:
    enabled: true
    dhcp: true
""")
            start_daemon()

            assert retry_till_true_or_timeout(
                60,
                lambda: iface_connected_ssid(self.TARGET_NAME)
                == TEST_WIFI_SSID,
            ), (
                "WIFI did not connect on the rename target: "
                f"{iface_connected_ssid(self.TARGET_NAME)}"
            )
            # The target is the primary name, the original name is kept as
            # an alt-name.
            rc, out, _ = exec_cmd(
                ["ip", "-o", "link", "show", self.START_NAME], check=False
            )
            assert rc == 0, f"{self.START_NAME} disappeared"
            primary = out.split(":")[1].strip().split("@")[0]
            assert (
                primary == self.TARGET_NAME
            ), f"NIC was not renamed to {self.TARGET_NAME}: {out}"
            rc, out, _ = exec_cmd(
                ["ip", "link", "show", self.TARGET_NAME], check=False
            )
            assert (
                f"altname {self.START_NAME}" in out
            ), f"original name not kept as alt-name: {out}"
        finally:
            if os.path.exists(self.SAVED_STATE_FILE):
                os.remove(self.SAVED_STATE_FILE)
            stop_daemon()
            start_daemon()


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestWifiPhyLater:
    def test_wifi_cfg_connects_when_phy_appears_after_daemon_start(
        self, restart_daemon  # noqa: F811
    ):
        try:
            # Start with no wifi-phy at all: the daemon only has the saved
            # wifi-cfg profile.  The wifi-phy appears after the boot grace
            # period, so only the monitor worker can notice it and hand the
            # saved profile to the wifi plugin.
            exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
            exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)

            # The wifi-cfg profile is applied before any AP/phy exists: it
            # is only saved, and the monitor/event worker connects it once
            # the wifi-phy appears. Verification would wait for a
            # connection which is not expected yet, so skip it.
            nipart.apply(
                load_yaml(f"""---
                    interfaces:
                      - name: {TEST_WIFI_SSID_OPEN}
                        type: wifi-cfg
                        state: up
                        wifi:
                          ssid: {TEST_WIFI_SSID_OPEN}"""),
                verify_change=False,
            )

            client = nipart.NipartClient()
            saved_state = client.query_network_state(
                nipart.NipartQueryOption.saved()
            )
            assert not any(
                iface.get("type") == "wifi-phy"
                for iface in saved_state["interfaces"]
            ), "test setup should not persist a wifi-phy profile"

            create_sim_wifi_nics()
            exec_cmd("killall wpa_supplicant".split(), check=False)
            start_hostapd_open(TEST_NET_NS)

            assert retry_till_true_or_timeout(
                60, lambda: connected_ssid() == TEST_WIFI_SSID_OPEN
            ), (
                "wifi-cfg did not connect after wifi-phy appeared later: "
                f"{connected_ssid()}"
            )
        finally:
            destroy_sim_wifi_nics()
            nipart.apply(load_yaml(f"""---
                    interfaces:
                      - name: {TEST_WIFI_SSID_OPEN}
                        type: wifi-cfg
                        state: absent"""))

    def test_wifi_cfg_empty_base_iface_connects_when_phy_appears(
        self, restart_daemon  # noqa: F811
    ):
        try:
            exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
            exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)

            # An empty `base-iface` behaves like an undefined one: the saved
            # profile targets whichever wifi-phy appears.
            nipart.apply(
                load_yaml(f"""---
                    interfaces:
                      - name: {TEST_WIFI_SSID_OPEN}
                        type: wifi-cfg
                        state: up
                        wifi:
                          ssid: {TEST_WIFI_SSID_OPEN}
                          base-iface: ''"""),
                verify_change=False,
            )

            create_sim_wifi_nics()
            exec_cmd("killall wpa_supplicant".split(), check=False)
            start_hostapd_open(TEST_NET_NS)

            assert retry_till_true_or_timeout(
                60, lambda: connected_ssid() == TEST_WIFI_SSID_OPEN
            ), (
                "wifi-cfg with empty base-iface did not connect after "
                f"wifi-phy appeared later: {connected_ssid()}"
            )
        finally:
            destroy_sim_wifi_nics()
            nipart.apply(load_yaml(f"""---
                    interfaces:
                      - name: {TEST_WIFI_SSID_OPEN}
                        type: wifi-cfg
                        state: absent"""))

    def test_wifi_cfg_for_other_phy_not_loaded_when_phy_appears(
        self, restart_daemon  # noqa: F811
    ):
        try:
            exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
            exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)

            # The saved profile is bound to a phy which is not the one
            # appearing: the new wifi-phy must not carry it.
            nipart.apply(
                load_yaml(f"""---
                    interfaces:
                      - name: {TEST_WIFI_SSID_OPEN}
                        type: wifi-cfg
                        state: up
                        wifi:
                          ssid: {TEST_WIFI_SSID_OPEN}
                          base-iface: wifi-other-phy9"""),
                verify_change=False,
            )

            create_sim_wifi_nics()
            exec_cmd("killall wpa_supplicant".split(), check=False)
            start_hostapd_open(TEST_NET_NS)

            # Long enough for a wrongly applied profile to connect.
            time.sleep(30)
            assert connected_ssid() != TEST_WIFI_SSID_OPEN, (
                "wifi-cfg bound to another phy was applied to the new "
                f"wifi-phy: {connected_ssid()}"
            )
        finally:
            destroy_sim_wifi_nics()
            nipart.apply(load_yaml(f"""---
                    interfaces:
                      - name: {TEST_WIFI_SSID_OPEN}
                        type: wifi-cfg
                        state: absent"""))


@pytest.fixture(scope="class")
def wifi_extra_phy_env():
    # WIFI_TEST_NIC + AP plus a third radio parked outside the main
    # netns: the test moves it in to simulate the USB dongle.
    create_sim_wifi_nics(hold_extra_phy=True)
    exec_cmd("killall wpa_supplicant".split(), check=False)
    start_hostapd()
    yield
    destroy_sim_wifi_nics()


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestWifiPhyHotplug:
    """A wifi-phy appearing while another one is connected (e.g. a USB
    dongle plugged in) must be added to the running WIFI client without
    dropping the established connection."""

    def test_new_phy_insert_keeps_connection(self, wifi_extra_phy_env):
        try:
            rc, out, err = _wifi_connect(TEST_WIFI_SSID, TEST_WIFI_PSK)
            assert rc == 0, f"npt wifi connect failed:\n{out}\n{err}"
            assert connected_ssid() == TEST_WIFI_SSID

            # "Plug the USB dongle": a new wifi-phy appears.
            release_held_extra_wifi_phy()

            # The established connection must survive the new phy.
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                assert connected_ssid() == TEST_WIFI_SSID, (
                    "established WIFI connection dropped when a new "
                    "wifi-phy appeared"
                )
                time.sleep(0.2)

            assert retry_till_true_or_timeout(
                60, lambda: new_phy_connected_ssid() == TEST_WIFI_SSID
            ), (
                "the new wifi-phy did not connect: "
                f"{new_phy_connected_ssid()}"
            )
            assert connected_ssid() == TEST_WIFI_SSID
        finally:
            nipart.apply(load_yaml(f"""---
                    interfaces:
                      - name: {TEST_WIFI_SSID}
                        type: wifi-cfg
                        state: absent"""))


def _find_nic_by_mac(mac):
    """Kernel NIC name owning `mac`, searched without the daemon."""
    for nic in os.listdir("/sys/class/net"):
        try:
            with open(f"/sys/class/net/{nic}/address") as fd:
                if fd.read().strip() == mac:
                    return nic
        except OSError:
            continue
    return None


def new_phy_connected_ssid():
    """SSID connected on the extra hwsim radio, or None."""
    nic = _find_nic_by_mac(HWSIM2_PERM_MAC)
    return iface_connected_ssid(nic) if nic else None


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason=("Does not have 'mac80211_hwsim' module "),
)
class TestWifiWpa3:
    def test_wifi_wpa3_iface_static_ip(self, clean_up, wifi_wpa3_env):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_WPA3}
                      password: {TEST_WIFI_PSK}
                    ipv4:
                      enabled: true
                      dhcp: false
                      address:
                        - ip: {DHCP_SRV_IP4_PREFIX}.99
                          prefix-length: 24"""))
        assert retry_till_true_or_timeout(10, ping_wifi_peer)

    def test_wifi_wpa3_iface_dhcpv4(self, clean_up, wifi_wpa3_env):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_WPA3}
                      password: {TEST_WIFI_PSK}
                    ipv4:
                      enabled: true
                      dhcp: true"""))
        assert retry_till_true_or_timeout(10, ping_wifi_peer)


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestWifiHidden:
    def test_wifi_hidden_iface_static_ip(
        self, clean_up, wifi_hidden_env  # noqa: F811
    ):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_HIDDEN}
                      password: {TEST_WIFI_PSK}
                      hidden: true
                    ipv4:
                      enabled: true
                      dhcp: false
                      address:
                        - ip: {DHCP_SRV_IP4_PREFIX}.99
                          prefix-length: 24"""))
        assert retry_till_true_or_timeout(10, ping_wifi_peer)

    def test_wifi_hidden_iface_dhcpv4(
        self, clean_up, wifi_hidden_env  # noqa: F811
    ):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_HIDDEN}
                      password: {TEST_WIFI_PSK}
                      hidden: true
                    ipv4:
                      enabled: true
                      dhcp: true"""))
        assert retry_till_true_or_timeout(10, ping_wifi_peer)

    def test_wifi_scan_hides_hidden_ssid(
        self, clean_up, wifi_hidden_env  # noqa: F811
    ):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_HIDDEN}
                      password: {TEST_WIFI_PSK}
                      hidden: true
                    ipv4:
                      enabled: true
                      dhcp: false
                      address:
                        - ip: {DHCP_SRV_IP4_PREFIX}.99
                          prefix-length: 24"""))
        assert retry_till_true_or_timeout(10, ping_wifi_peer)

        # Disconnect the shuli client before scanning: a standalone scan
        # can hit EBUSY while the client is connected.  The kernel BSS
        # cache keeps the hidden SSID from the connection.
        nipart.apply(
            load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: down"""),
            verify_change=False,
        )
        exec_cmd(f"ip link set {WIFI_TEST_NIC} up".split())
        retry_till_true_or_timeout(5, link_is_up)

        output = exec_cmd([npt_path(), "wifi", "scan"])[1]
        assert TEST_WIFI_SSID_HIDDEN not in output

        # A hidden network is only reported once we probe for it.
        output = exec_cmd(
            [
                npt_path(),
                "wifi",
                "scan",
                "--with-hidden",
                TEST_WIFI_SSID_HIDDEN,
            ]
        )[1]
        assert TEST_WIFI_SSID_HIDDEN in output


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestWifiHiddenAutoConnect:
    """Apply hidden SSID state before the AP comes up; verify the daemon
    auto-connects once the hidden AP becomes available."""

    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        create_sim_wifi_nics()
        exec_cmd("killall wpa_supplicant".split(), check=False)
        yield
        destroy_sim_wifi_nics()

    def test_auto_connect_after_ap_starts(self):
        # Apply the hidden SSID config before hostapd is running.
        # The daemon saves the state and holds the connection attempt;
        # the AP is not yet broadcasting.
        try:
            nipart.apply(
                load_yaml(f"""---
                    interfaces:
                      - name: {WIFI_TEST_NIC}
                        type: wifi-phy
                        state: up
                        wifi:
                          ssid: {TEST_WIFI_SSID_HIDDEN}
                          password: {TEST_WIFI_PSK}
                          hidden: true
                        ipv4:
                          enabled: true
                          dhcp: false
                          address:
                            - ip: {DHCP_SRV_IP4_PREFIX}.99
                              prefix-length: 24"""),
                verify_change=False,
            )
        except Exception:
            # Expected: AP not up yet, daemon saves config for retry.
            pass

        # Now bring up the hidden AP.
        start_hostapd_hidden(TEST_NET_NS)

        # Nipart should auto-connect via directed probe (hidden_ssids).
        assert retry_till_true_or_timeout(
            30, ping_wifi_peer
        ), "hidden SSID did not auto-connect after AP came up"


@pytest.mark.skipif(
    os.geteuid() != 0,
    reason="root required (mac80211_hwsim, netns and hostapd)",
)
@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason=("Does not have 'mac80211_hwsim' kernel module "),
)
class TestWifiApStartsLater:
    def test_wifi_connects_after_ap_starts_later(  # noqa: F811
        self, clean_up, wifi_env_ap_later
    ):
        # Apply the WIFI config while no AP is present.  Verification
        # would fail immediately (the SSID cannot be connected yet), so
        # skip it: the plugin keeps hunting in the background and the
        # connection completes once the AP shows up.
        nipart.apply(
            load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}"""),
            verify_change=False,
        )

        # Sanity: with no AP running, nipart must not report the SSID
        # yet.
        assert not is_wifi_connected()

        # Start the AP now: nipart should pick it up on a later
        # background scan and connect on its own.  A longer timeout is
        # needed because `iw scan` on the test NIC returns -EBUSY while
        # shuli's own scan is in flight.
        start_hostapd(timeout=60)
        assert retry_till_true_or_timeout(
            CONNECT_TIMEOUT, is_wifi_connected
        ), (
            f"nipart did not connect to {TEST_WIFI_SSID} after the AP "
            f"appeared; show() = {nipart.show()}"
        )


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' module",
)
class TestWifiMultiSsid:
    @pytest.fixture(autouse=True)
    def clean_up_profiles(self):
        yield
        # Purge the saved profiles this module created.  A saved wifi
        # profile is auto-applied by the event worker when a wifi-phy
        # appears, so a leftover profile would fight with the profile
        # applied by a later wifi test module.
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {WIFI_TEST_NIC}
                type: wifi-phy
                state: absent
              - name: {TEST_WIFI_SSID}
                type: wifi-cfg
                state: absent
              - name: {TEST_WIFI_SSID_2}
                type: wifi-cfg
                state: absent"""))

    def test_wifi_picks_best_of_two_ssids(self, multi_ap_env):
        both = load_yaml(
            wifi_cfg_state_yaml(
                (TEST_WIFI_SSID, TEST_WIFI_PSK, "up"),
                (TEST_WIFI_SSID_2, None, "up"),
            )
        )
        nipart.apply(both)
        assert wait_for_ssid(TEST_WIFI_SSID) or wait_for_ssid(TEST_WIFI_SSID_2)
        ssid = connected_ssid()
        assert ssid in AP_IPS
        assert retry_till_true_or_timeout(
            10, lambda: ping_wifi_peer(AP_IPS[ssid])
        )

    def test_wifi_switch_ssid_reuses_client(self, multi_ap_env):
        # First connect to the WPA2 AP only.
        nipart.apply(
            load_yaml(wifi_phy_state_yaml(TEST_WIFI_SSID, TEST_WIFI_PSK))
        )
        assert wait_for_ssid(TEST_WIFI_SSID)
        assert retry_till_true_or_timeout(
            10, lambda: ping_wifi_peer(AP_IPS[TEST_WIFI_SSID])
        )
        # Switch to the open AP on the same phy; the same shuli client
        # must be reused (only its network list is updated).
        nipart.apply(load_yaml(wifi_phy_state_yaml(TEST_WIFI_SSID_2)))
        assert wait_for_ssid(TEST_WIFI_SSID_2)
        assert retry_till_true_or_timeout(
            10, lambda: ping_wifi_peer(AP_IPS[TEST_WIFI_SSID_2])
        )
        # And back to the WPA2 AP.
        nipart.apply(
            load_yaml(wifi_phy_state_yaml(TEST_WIFI_SSID, TEST_WIFI_PSK))
        )
        assert wait_for_ssid(TEST_WIFI_SSID)
        assert retry_till_true_or_timeout(
            10, lambda: ping_wifi_peer(AP_IPS[TEST_WIFI_SSID])
        )

    def test_npt_up_down_wifi_cfg(self, multi_ap_env):
        both = load_yaml(
            wifi_cfg_state_yaml(
                (TEST_WIFI_SSID, TEST_WIFI_PSK, "up"),
                (TEST_WIFI_SSID_2, None, "up"),
            )
        )
        nipart.apply(both)
        assert wait_for_ssid(TEST_WIFI_SSID) or wait_for_ssid(TEST_WIFI_SSID_2)
        connected = connected_ssid()
        assert connected in (TEST_WIFI_SSID, TEST_WIFI_SSID_2)

        rc, out, err = exec_cmd([CLI_PATH, "down", connected], check=False)
        assert rc == 0, f"npt down failed:\n{out}\n{err}"
        assert (
            connected_ssid() != connected
        ), f"expected wifi to leave {connected} before `npt down` returned"

        rc, out, err = exec_cmd([CLI_PATH, "up", connected], check=False)
        assert rc == 0, f"npt up failed:\n{out}\n{err}"
        assert connected_ssid() == connected, (
            f"expected wifi to reconnect to {connected} before `npt up` "
            "returned"
        )

    def test_npt_down_does_not_wait_for_other_ssid(self, multi_ap_env):
        # `npt down` must return once the target SSID is disconnected. The
        # remaining saved profiles stay eligible and the plugin moves to
        # the best of them in the background; waiting for that association
        # made the command burn the full WIFI connect timeout when the
        # remaining profile was unreachable.
        missing_ssid = "No-Such-SSID-XY"
        both = load_yaml(
            wifi_cfg_state_yaml(
                (TEST_WIFI_SSID, TEST_WIFI_PSK, "up"),
                (missing_ssid, None, "up"),
            )
        )
        try:
            nipart.apply(both)
            assert wait_for_ssid(TEST_WIFI_SSID)
            start = time.time()
            rc, out, err = exec_cmd(
                [CLI_PATH, "down", TEST_WIFI_SSID], check=False
            )
            elapsed = time.time() - start
            assert rc == 0, f"npt down failed:\n{out}\n{err}"
            assert elapsed < 30, (
                f"`npt down {TEST_WIFI_SSID}` took {elapsed:.1f}s: the "
                "daemon waited for the unreachable remaining profile to "
                "associate"
            )
            assert connected_ssid() != TEST_WIFI_SSID, (
                f"expected wifi to leave {TEST_WIFI_SSID} before `npt down` "
                "returned"
            )
        finally:
            nipart.apply(
                load_yaml(wifi_cfg_state_yaml((missing_ssid, None, "absent")))
            )

    def test_wifi_cfg_bssid_pin(self, multi_ap_env):
        # Pin the open profile to AP2's BSSID: nipart must hand the pin
        # to shuli and connect to exactly that AP.
        pinned_bssid = HWSIM2_PERM_MAC.upper()
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_WIFI_SSID_2}
                type: wifi-cfg
                state: up
                wifi:
                  ssid: {TEST_WIFI_SSID_2}
                  bssid: {pinned_bssid}
                  base-iface: {WIFI_TEST_NIC}
                ipv4:
                  enabled: true
                  dhcp: false
                  address:
                    - ip: {STA_IP}
                      prefix-length: 24"""))
        assert wait_for_ssid(TEST_WIFI_SSID_2)
        assert connected_bssid() == pinned_bssid, (
            f"expected to connect to the pinned BSSID {pinned_bssid}, "
            f"got {connected_bssid()}"
        )

    def test_npt_up_connected_profile_keeps_link(self, multi_ap_env):
        # `npt up` of the SSID already connected must be a no-op: the link
        # has to stay up for the whole command instead of being torn down
        # for a rescan which could land on another saved network.
        both = load_yaml(
            wifi_cfg_state_yaml(
                (TEST_WIFI_SSID, TEST_WIFI_PSK, "up"),
                (TEST_WIFI_SSID_2, None, "up"),
            )
        )
        nipart.apply(both)
        assert wait_for_ssid(TEST_WIFI_SSID) or wait_for_ssid(TEST_WIFI_SSID_2)
        connected = connected_ssid()
        assert connected in (TEST_WIFI_SSID, TEST_WIFI_SSID_2)

        proc = subprocess.Popen(
            [CLI_PATH, "up", connected],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        lost = False
        while proc.poll() is None:
            if connected_ssid() != connected:
                lost = True
                break
            time.sleep(0.05)
        out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, f"npt up failed:\n{out}\n{err}"
        assert (
            not lost
        ), f"`npt up {connected}` dropped the existing connection"
        assert connected_ssid() == connected

    def test_npt_up_unavailable_ssid_fails_fast(self, multi_ap_env):
        # An explicit up of an unavailable SSID while another saved profile
        # is reachable: shuli falls back to the reachable network, and the
        # daemon must report the failed request quickly instead of waiting
        # the full WIFI connect timeout on both attempts. The apply
        # rollback then restores the reachable profile.
        missing_ssid = "No-Such-SSID-XY"
        both = load_yaml(
            wifi_cfg_state_yaml(
                (TEST_WIFI_SSID, TEST_WIFI_PSK, "up"),
                (missing_ssid, None, "up"),
            )
        )
        try:
            nipart.apply(both)
            assert wait_for_ssid(TEST_WIFI_SSID)
            start = time.time()
            rc, out, err = exec_cmd(
                [CLI_PATH, "up", missing_ssid], check=False
            )
            elapsed = time.time() - start
            assert (
                rc != 0
            ), f"npt up of an unavailable SSID succeeded:\n{out}\n{err}"
            assert elapsed < 30, (
                f"`npt up {missing_ssid}` took {elapsed:.1f}s: the daemon "
                "did not fail the unreachable SSID wait quickly"
            )
            assert retry_till_true_or_timeout(
                30, lambda: connected_ssid() == TEST_WIFI_SSID
            ), "the reachable saved profile was not restored"
        finally:
            nipart.apply(
                load_yaml(wifi_cfg_state_yaml((missing_ssid, None, "absent")))
            )


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' kernel module",
)
class TestWifiDhcpSwitch:
    def test_switch_ssid_purges_previous_dhcp(
        self, clean_up, two_dhcp_ap_env  # noqa: F811
    ):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID}
                      password: {TEST_WIFI_PSK}
                    ipv4:
                      enabled: true
                      dhcp: true"""))
        assert retry_till_true_or_timeout(
            60, lambda: connected_ssid() == TEST_WIFI_SSID
        )
        assert retry_till_true_or_timeout(
            60, lambda: _has_ipv4_prefix(DHCP_SRV_IP4_PREFIX)
        )

        stop_dhcp_server()
        exec_cmd(
            ["sudo", "pkill", "-9", "-f", "nipart_test_dnsmasq.conf"],
            check=False,
        )
        assert retry_till_true_or_timeout(
            5, lambda: not _dhcp_server_1_running()
        )
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_2}
                    ipv4:
                      enabled: true
                      dhcp: true"""))
        assert retry_till_true_or_timeout(
            60, lambda: connected_ssid() == TEST_WIFI_SSID_2
        )
        assert retry_till_true_or_timeout(
            60, lambda: not _has_ipv4_prefix(DHCP_SRV_IP4_PREFIX)
        ), "previous DHCP address was not purged after SSID switch"

    def test_wifi_cfg_profile_switch_purges_previous_dhcp(
        self, two_dhcp_ap_env  # noqa: F811
    ):
        _cleanup_wifi_profiles()
        try:
            # Start from the second AP: unlike the first one its DHCP
            # server is not stopped by the other tests of this module.
            nipart.apply(_wifi_cfg_profile_yaml(TEST_WIFI_SSID_2))
            assert retry_till_true_or_timeout(
                60, lambda: connected_ssid() == TEST_WIFI_SSID_2
            )
            assert retry_till_true_or_timeout(
                60, lambda: _has_ipv4_prefix(DHCP_SRV_IP4_PREFIX_2)
            )

            # Applying a wifi-cfg profile for another SSID must restart
            # the DHCP client within the apply: the previous network's
            # address is purged before the client is started again.
            nipart.apply(_wifi_cfg_profile_yaml(TEST_WIFI_SSID, TEST_WIFI_PSK))
            assert not _has_ipv4_prefix(DHCP_SRV_IP4_PREFIX_2), (
                "previous DHCP address was not purged by the wifi-cfg "
                "profile switch"
            )
            assert retry_till_true_or_timeout(
                60, lambda: connected_ssid() == TEST_WIFI_SSID
            )
        finally:
            _cleanup_wifi_profiles()

    def test_unrelated_npt_up_does_not_restart_wifi_dhcp(
        self, clean_up, two_dhcp_ap_env  # noqa: F811
    ):
        try:
            nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {DUMMY_IFACE}
                    type: dummy
                    state: up
                """))
            nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {WIFI_TEST_NIC}
                    type: wifi-phy
                    state: up
                    wifi:
                      ssid: {TEST_WIFI_SSID_2}
                    ipv4:
                      enabled: true
                      dhcp: true
                """))
            assert retry_till_true_or_timeout(
                60, lambda: connected_ssid() == TEST_WIFI_SSID_2
            )
            assert retry_till_true_or_timeout(
                60,
                lambda: _has_ipv4_prefix(DHCP_SRV_IP4_PREFIX_2),
            )

            # With no DHCP server available, a spurious DHCP restart caused
            # by the monitor link dump after an unrelated `npt up` purges
            # the lease and leaves the wifi-phy without IPv4.
            _stop_dhcp_server_2()
            rc, out, err = exec_cmd([CLI_PATH, "up", DUMMY_IFACE], check=False)
            assert rc == 0, f"npt up failed:\n{out}\n{err}"
            time.sleep(3)
            assert _has_ipv4_prefix(DHCP_SRV_IP4_PREFIX_2), (
                "unrelated `npt up` restarted the wifi DHCP client and "
                "purged its lease"
            )
        finally:
            _stop_dhcp_server_2()
            nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {DUMMY_IFACE}
                    type: dummy
                    state: absent
                """))


# The second host-side client phy used by the `state: ignore` tests.
IGNORED_TEST_NIC = "test-wlan1"


@pytest.fixture(scope="class")
def wifi_two_client_env():
    """mac80211_hwsim with two host-side client phys and the usual AP.

    `WIFI_TEST_NIC` is the managed phy, `IGNORED_TEST_NIC` is the phy the
    tests mark `state: ignore`, and `DHCP_SRV_NIC` is moved into the test
    netns for hostapd.
    """
    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())

    exec_cmd("modprobe mac80211_hwsim radios=3".split())
    assert retry_till_true_or_timeout(
        TIMEOUT_SECS_SIM_WIFI_NICS, has_three_sim_wifi_nics
    )

    state = nipart.show()
    exec_cmd("killall wpa_supplicant".split(), check=False)
    nic = get_nic_name_by_perm_mac(state, HWSIM0_PERM_MAC)
    exec_cmd(f"ip link set {nic} name {WIFI_TEST_NIC}".split())
    nic = get_nic_name_by_perm_mac(state, HWSIM1_PERM_MAC)
    exec_cmd(f"ip link set {nic} name {IGNORED_TEST_NIC}".split())
    nic = get_nic_name_by_perm_mac(state, HWSIM2_PERM_MAC)
    exec_cmd(f"ip link set {nic} name {DHCP_SRV_NIC}".split())
    start_hostapd()
    yield

    if os.path.exists(HOSTAPD_CONF_PATH):
        os.remove(HOSTAPD_CONF_PATH)
    if os.path.exists(HOSTAPD_PID_PATH):
        with open(HOSTAPD_PID_PATH) as fd:
            pid = fd.read()
        os.kill(int(pid), signal.SIGTERM)
    stop_dhcp_server()
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


@pytest.mark.skipif(
    not has_kernel_module("mac80211_hwsim"),
    reason="Does not have 'mac80211_hwsim' module",
)
class TestWifiIgnore:
    """A wifi-phy marked `state: ignore` is persisted as unmanaged.

    Neither `npt apply` nor a later `npt up` may bind the saved wifi-cfg
    profiles to it; clearing the ignore with `state: up` makes it eligible
    again.
    """

    IGNORE_PROFILE = "ignored-wifi-phy"

    def _phy_mac(self):
        with open(f"/sys/class/net/{IGNORED_TEST_NIC}/address") as fd:
            return fd.read().strip().upper()

    def _phy_yaml(self, mac, state):
        return load_yaml(f"""---
            interfaces:
              - name: {self.IGNORE_PROFILE}
                type: wifi-phy
                identifier: mac-address
                mac-address: {mac}
                state: {state}""")

    def test_ignored_phy_never_gets_wifi_cfg(self, wifi_two_client_env):
        mac = self._phy_mac()
        try:
            nipart.apply(self._phy_yaml(mac, "ignore"), verify_change=False)

            # The persisted ignore shows up in the query.
            assert show_only(IGNORED_TEST_NIC)["state"] == "ignore"
            client = nipart.NipartClient()
            saved = client.query_network_state(
                nipart.NipartQueryOption.saved()
            )
            ignored = next(
                (
                    iface
                    for iface in saved["interfaces"]
                    if iface["name"] == self.IGNORE_PROFILE
                ),
                None,
            )
            assert (
                ignored is not None
            ), "the `state: ignore` profile was not persisted"

            # An unbound wifi-cfg must connect only on the managed phy.
            nipart.apply(_wifi_cfg_profile_yaml(TEST_WIFI_SSID, TEST_WIFI_PSK))
            assert retry_till_true_or_timeout(
                60, lambda: connected_ssid() == TEST_WIFI_SSID
            )
            time.sleep(20)
            assert (
                iface_connected_ssid(IGNORED_TEST_NIC) is None
            ), "the wifi-cfg was activated on the `state: ignore` phy"

            # A later `npt up` must not bind the profile to the ignored phy
            # either (the original bug).
            rc, out, err = exec_cmd(
                [npt_path(), "up", TEST_WIFI_SSID], check=False
            )
            assert rc == 0, f"npt up failed:\n{out}\n{err}"
            time.sleep(20)
            assert (
                iface_connected_ssid(IGNORED_TEST_NIC) is None
            ), "npt up activated the wifi-cfg on the `state: ignore` phy"
            assert connected_ssid() == TEST_WIFI_SSID

            # Clearing the ignore makes the phy eligible again.
            nipart.apply(self._phy_yaml(mac, "up"), verify_change=False)
            rc, out, err = exec_cmd(
                [npt_path(), "up", TEST_WIFI_SSID], check=False
            )
            assert rc == 0, f"npt up failed:\n{out}\n{err}"
            assert retry_till_true_or_timeout(
                60,
                lambda: iface_connected_ssid(IGNORED_TEST_NIC)
                == TEST_WIFI_SSID,
            ), (
                "the wifi-cfg did not connect after the phy ignore was "
                f"cleared: {iface_connected_ssid(IGNORED_TEST_NIC)}"
            )
        finally:
            nipart.apply(self._phy_yaml(mac, "absent"), verify_change=False)
            nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_WIFI_SSID}
                    type: wifi-cfg
                    state: absent"""))

    def test_ignoring_connected_phy_disconnects_it(self, wifi_two_client_env):
        mac = self._phy_mac()
        try:
            # Both phys are eligible, so the unbound wifi-cfg connects on
            # both of them.
            nipart.apply(_wifi_cfg_profile_yaml(TEST_WIFI_SSID, TEST_WIFI_PSK))
            assert retry_till_true_or_timeout(
                60,
                lambda: iface_connected_ssid(IGNORED_TEST_NIC)
                == TEST_WIFI_SSID,
            ), "the second phy did not connect to the SSID"

            # Marking the connected phy `state: ignore` disconnects it;
            # the managed phy keeps its link.
            nipart.apply(self._phy_yaml(mac, "ignore"), verify_change=False)
            assert retry_till_true_or_timeout(
                30, lambda: iface_connected_ssid(IGNORED_TEST_NIC) is None
            ), "the `state: ignore` phy was not disconnected"
            time.sleep(20)
            assert (
                iface_connected_ssid(IGNORED_TEST_NIC) is None
            ), "the `state: ignore` phy reconnected"
            assert connected_ssid() == TEST_WIFI_SSID

            # A WIFI off/on cycle must not re-adopt the ignored phy.
            exec_cmd([npt_path(), "wifi", "down"])
            assert retry_till_true_or_timeout(
                30, lambda: connected_ssid() is None
            ), "wifi down did not disconnect the managed phy"
            exec_cmd([npt_path(), "wifi", "up"])
            assert retry_till_true_or_timeout(
                60, lambda: connected_ssid() == TEST_WIFI_SSID
            ), "the managed phy did not reconnect after wifi up"
            time.sleep(20)
            assert (
                iface_connected_ssid(IGNORED_TEST_NIC) is None
            ), "wifi up re-adopted the `state: ignore` phy"
        finally:
            exec_cmd([npt_path(), "wifi", "up"], check=False)
            nipart.apply(self._phy_yaml(mac, "absent"), verify_change=False)
            nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_WIFI_SSID}
                    type: wifi-cfg
                    state: absent"""))
