# SPDX-License-Identifier: Apache-2.0

import os
import re
import signal

import nipart
import pytest

from .cmdlib import exec_cmd
from .retry import retry_till_true_or_timeout
from .dhcp import start_dhcp_server
from .dhcp import stop_dhcp_server
from .dhcp import DHCP_SRV_NIC
from .dhcp import DHCP_SRV_IP4

HWSIM0_PERM_MAC = "02:00:00:00:00:00"
HWSIM1_PERM_MAC = "02:00:00:00:01:00"
HWSIM2_PERM_MAC = "02:00:00:00:02:00"
TEST_NET_NS = "wifi-test"
TEST_WIFI_SSID = "Test-WIFI"
TEST_WIFI_PSK = "12345678"
TEST_WIFI_SSID_OPEN = "Test-WIFI-NOPASS"
TEST_WIFI_SSID_WPA3 = "Test-WIFI3"
TEST_WIFI_SSID_2 = "Test-WIFI-2"
TEST_WIFI_SSID_HIDDEN = "Test-WIFI-HIDDEN"
HOSTAPD_PID_PATH = "/tmp/nipart_test_hostapd.pid"
HOSTAPD_CONF_PATH = "/tmp/nipart_test_hostapd.conf"
HOSTAPD_PID_PATH_2 = "/tmp/nipart_test_hostapd2.pid"
HOSTAPD_CONF_PATH_2 = "/tmp/nipart_test_hostapd2.conf"
AP2_NIC = "dhcp_srv2"
HOSTAPD_CONF = f"""
interface={DHCP_SRV_NIC}
driver=nl80211

hw_mode=g
channel=1
ssid={TEST_WIFI_SSID}

wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_passphrase={TEST_WIFI_PSK}
"""
HOSTAPD_CONF_OPEN = f"""
interface={DHCP_SRV_NIC}
driver=nl80211

hw_mode=g
channel=1
ssid={TEST_WIFI_SSID_OPEN}

wpa=0
auth_algs=1
"""
HOSTAPD_CONF_2 = f"""
interface={AP2_NIC}
driver=nl80211

hw_mode=g
channel=1
ssid={TEST_WIFI_SSID_2}

wpa=0
auth_algs=1
"""
# WPA3-Personal: SAE only, PMF required.  shuli performs the SAE
# handshake with Hash-to-Element, so H2E is enabled on the AP side.
HOSTAPD_CONF_WPA3 = f"""
interface={DHCP_SRV_NIC}
driver=nl80211

hw_mode=g
channel=1
ssid={TEST_WIFI_SSID_WPA3}

wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
wpa_passphrase={TEST_WIFI_PSK}
ieee80211w=2
sae_pwe=1
"""
HOSTAPD_CONF_HIDDEN = f"""
interface={DHCP_SRV_NIC}
driver=nl80211

hw_mode=g
channel=1
ssid={TEST_WIFI_SSID_HIDDEN}
ignore_broadcast_ssid=1

wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_passphrase={TEST_WIFI_PSK}
"""
TIMEOUT_SECS_SIM_WIFI_NICS = 30
WIFI_TEST_NIC = "test-wlan0"


@pytest.fixture(scope="module")
def wifi_env():
    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())

    exec_cmd("modprobe mac80211_hwsim radios=2".split())
    assert retry_till_true_or_timeout(
        TIMEOUT_SECS_SIM_WIFI_NICS, has_sim_wifi_nics
    )

    state = nipart.show()
    # The nipart.show() has started wpa_supplicant again, we need to
    # kill it so it does not hold outdated information on mac80211_hwsim
    # created temporary WIFI NIC.
    exec_cmd("killall wpa_supplicant".split(), check=False)
    wlan1 = get_nic_name_by_perm_mac(state, HWSIM0_PERM_MAC)
    exec_cmd(f"ip link set {wlan1} name {WIFI_TEST_NIC}".split())
    wlan2 = get_nic_name_by_perm_mac(state, HWSIM1_PERM_MAC)
    exec_cmd(f"ip link set {wlan2} name {DHCP_SRV_NIC}".split())
    start_hostapd()
    yield
    os.remove(HOSTAPD_CONF_PATH)
    if os.path.exists(HOSTAPD_PID_PATH):
        with open(HOSTAPD_PID_PATH) as fd:
            pid = fd.read()
        os.kill(int(pid), signal.SIGTERM)
    stop_dhcp_server()
    exec_cmd(f"ip netns del {TEST_NET_NS}".split())
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


def create_sim_wifi_nics():
    """Create the mac80211_hwsim based wifi test environment: two
    simulated NICs renamed to `WIFI_TEST_NIC` and `DHCP_SRV_NIC`, plus
    the `TEST_NET_NS` netns for the AP side."""
    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())

    exec_cmd("modprobe mac80211_hwsim radios=2".split())
    assert retry_till_true_or_timeout(
        TIMEOUT_SECS_SIM_WIFI_NICS, has_sim_wifi_nics
    )

    state = nipart.show()
    wlan1 = get_nic_name_by_perm_mac(state, HWSIM0_PERM_MAC)
    exec_cmd(f"ip link set {wlan1} name {WIFI_TEST_NIC}".split())
    wlan2 = get_nic_name_by_perm_mac(state, HWSIM1_PERM_MAC)
    exec_cmd(f"ip link set {wlan2} name {DHCP_SRV_NIC}".split())


def destroy_sim_wifi_nics():
    """Teardown the environment created by `create_sim_wifi_nics()`."""
    if os.path.exists(HOSTAPD_CONF_PATH):
        os.remove(HOSTAPD_CONF_PATH)
    if os.path.exists(HOSTAPD_PID_PATH):
        with open(HOSTAPD_PID_PATH) as fd:
            pid = fd.read()
        os.kill(int(pid), signal.SIGTERM)
    stop_dhcp_server()
    exec_cmd(f"ip netns del {TEST_NET_NS}".split())
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


def unload_wifi_sim_kernel_module():
    try:
        exec_cmd("modprobe -r mac80211_hwsim".split())
        return True
    except Exception:
        return False


def get_nic_name_by_perm_mac(state, mac):
    for iface in state["interfaces"]:
        if iface.get("permanent-mac-address") == mac:
            return iface["name"]


def get_wifi_phy_name(nic_name):
    # TODO(Gris Ge): use nipart instead of iw here
    output = exec_cmd(f"iw dev {nic_name} info".split())[1]
    match = re.search(r"[^a-zA-Z]wiphy ([0-9]+)", output)
    assert match
    if match:
        return match.group(1)


def has_sim_wifi_nics():
    exec_cmd("udevadm settle".split())
    state = nipart.show()
    wlan1 = get_nic_name_by_perm_mac(state, HWSIM0_PERM_MAC)
    wlan2 = get_nic_name_by_perm_mac(state, HWSIM1_PERM_MAC)
    return wlan1 and wlan2


def start_hostapd(timeout=2, with_dhcp=True):
    phy_id = get_wifi_phy_name(DHCP_SRV_NIC)
    assert phy_id
    # Move phy2 to namespace with hostpad
    exec_cmd(f"iw phy#{phy_id} set netns name {TEST_NET_NS}".split())
    exec_cmd(f"ip link set {WIFI_TEST_NIC} up".split())
    exec_cmd(
        f"ip netns exec {TEST_NET_NS} ip link set {DHCP_SRV_NIC} up".split()
    )
    with open(HOSTAPD_CONF_PATH, "w") as fd:
        fd.write(HOSTAPD_CONF)

    exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"hostapd -B -d {HOSTAPD_CONF_PATH} -P {HOSTAPD_PID_PATH}".split(),
    )

    assert retry_till_true_or_timeout(timeout, hostapd_is_up)

    if with_dhcp:
        start_dhcp_server(TEST_NET_NS)


def hostapd_is_up():
    output = exec_cmd(f"iw {WIFI_TEST_NIC} scan".split(), check=False)[1]
    return "Test-WIFI" in output


def hostapd_is_up_open():
    output = exec_cmd(f"iw {WIFI_TEST_NIC} scan".split(), check=False)[1]
    return TEST_WIFI_SSID_OPEN in output


def hostapd_is_up_2():
    output = exec_cmd(f"iw {WIFI_TEST_NIC} scan".split(), check=False)[1]
    return TEST_WIFI_SSID_2 in output


def start_hostapd_2():
    """Start a second open AP (`AP2_NIC`) in the test netns, next to the
    AP already started by `start_hostapd()`."""
    phy_id = get_wifi_phy_name(AP2_NIC)
    assert phy_id
    exec_cmd(f"iw phy#{phy_id} set netns name {TEST_NET_NS}".split())
    exec_cmd(f"ip netns exec {TEST_NET_NS} ip link set {AP2_NIC} up".split())
    with open(HOSTAPD_CONF_PATH_2, "w") as fd:
        fd.write(HOSTAPD_CONF_2)

    exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"hostapd -B -d {HOSTAPD_CONF_PATH_2} "
        f"-P {HOSTAPD_PID_PATH_2}".split(),
    )

    assert retry_till_true_or_timeout(2, hostapd_is_up_2)


def start_hostapd_open(net_ns):
    phy_id = get_wifi_phy_name(DHCP_SRV_NIC)
    assert phy_id
    exec_cmd(f"iw phy#{phy_id} set netns name {net_ns}".split())
    exec_cmd(f"ip link set {WIFI_TEST_NIC} up".split())
    exec_cmd(f"ip netns exec {net_ns} ip link set {DHCP_SRV_NIC} up".split())
    with open(HOSTAPD_CONF_PATH, "w") as fd:
        fd.write(HOSTAPD_CONF_OPEN)

    exec_cmd(
        f"ip netns exec {net_ns} "
        f"hostapd -B -d {HOSTAPD_CONF_PATH} -P {HOSTAPD_PID_PATH}".split(),
    )

    assert retry_till_true_or_timeout(2, hostapd_is_up_open)

    start_dhcp_server(net_ns)


def hostapd_is_up_wpa3():
    output = exec_cmd(f"iw {WIFI_TEST_NIC} scan".split(), check=False)[1]
    return TEST_WIFI_SSID_WPA3 in output


def hostapd_is_up_hidden():
    # Check the AP side instead of scanning on the client interface:
    # shuli keeps the test NIC busy with its own scan loop while a
    # hidden network is configured, so `iw scan` on the client either
    # returns -EBUSY or hangs waiting for results.
    output = exec_cmd(
        f"ip netns exec {TEST_NET_NS} "
        f"iw dev {DHCP_SRV_NIC} info".split(),
        check=False,
    )[1]
    return "type AP" in output and TEST_WIFI_SSID_HIDDEN in output


def start_hostapd_wpa3(net_ns):
    phy_id = get_wifi_phy_name(DHCP_SRV_NIC)
    assert phy_id
    exec_cmd(f"iw phy#{phy_id} set netns name {net_ns}".split())
    exec_cmd(f"ip link set {WIFI_TEST_NIC} up".split())
    exec_cmd(f"ip netns exec {net_ns} ip link set {DHCP_SRV_NIC} up".split())
    with open(HOSTAPD_CONF_PATH, "w") as fd:
        fd.write(HOSTAPD_CONF_WPA3)

    exec_cmd(
        f"ip netns exec {net_ns} "
        f"hostapd -B -d {HOSTAPD_CONF_PATH} -P {HOSTAPD_PID_PATH}".split(),
    )

    assert retry_till_true_or_timeout(2, hostapd_is_up_wpa3)

    start_dhcp_server(net_ns)


def start_hostapd_hidden(net_ns, timeout=2):
    phy_id = get_wifi_phy_name(DHCP_SRV_NIC)
    assert phy_id
    exec_cmd(f"iw phy#{phy_id} set netns name {net_ns}".split())
    exec_cmd(f"ip link set {WIFI_TEST_NIC} up".split())
    exec_cmd(f"ip netns exec {net_ns} ip link set {DHCP_SRV_NIC} up".split())
    with open(HOSTAPD_CONF_PATH, "w") as fd:
        fd.write(HOSTAPD_CONF_HIDDEN)

    exec_cmd(
        f"ip netns exec {net_ns} "
        f"hostapd -B -d {HOSTAPD_CONF_PATH} -P {HOSTAPD_PID_PATH}".split(),
    )

    assert retry_till_true_or_timeout(timeout, hostapd_is_up_hidden)

    start_dhcp_server(net_ns)


def ping_wifi_peer(peer_ip=DHCP_SRV_IP4, timeout=5):
    """Whether `peer_ip` is reachable through the tested WIFI interface.

    The ping is bound to `WIFI_TEST_NIC`: the simulated AP network
    (`192.0.2.0/24`) may also exist on a wired interface of the test
    machine, and an unbound ping would then succeed through that wired
    NIC even while WIFI is down or has not reconnected yet.
    """
    rc, _, _ = exec_cmd(
        f"ping {peer_ip} -c 1 -w {timeout} -I {WIFI_TEST_NIC}".split(),
        check=False,
    )
    return rc == 0
