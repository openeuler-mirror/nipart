# SPDX-License-Identifier: Apache-2.0

import os
import re
import signal
import time

import nipart
import pytest

from .conftest import CLI_PATH
from .testlib.cmdlib import exec_cmd
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml
from .testlib.wifi import AP2_NIC
from .testlib.wifi import DHCP_SRV_NIC
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
from .testlib.wifi import TIMEOUT_SECS_SIM_WIFI_NICS
from .testlib.wifi import WIFI_TEST_NIC
from .testlib.wifi import get_nic_name_by_perm_mac
from .testlib.wifi import ping_wifi_peer
from .testlib.wifi import start_hostapd
from .testlib.wifi import start_hostapd_2
from .testlib.wifi import unload_wifi_sim_kernel_module

AP_IP = "192.0.2.1"
AP_IPS = {
    TEST_WIFI_SSID: AP_IP,
    TEST_WIFI_SSID_2: AP_IP,
}
STA_IP = "192.0.2.99"


def has_three_sim_wifi_nics():
    exec_cmd("udevadm settle".split())
    state = nipart.show()
    return all(
        get_nic_name_by_perm_mac(state, mac)
        for mac in (HWSIM0_PERM_MAC, HWSIM1_PERM_MAC, HWSIM2_PERM_MAC)
    )


@pytest.fixture(scope="module")
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


def connected_ssid():
    output = exec_cmd(f"iw dev {WIFI_TEST_NIC} link".split(), check=False)[1]
    match = re.search(r"SSID: (.+)", output)
    return match.group(1) if match else None


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
        assert connected_ssid() != connected, (
            f"expected wifi to leave {connected} before `npt down` returned"
        )

        rc, out, err = exec_cmd([CLI_PATH, "up", connected], check=False)
        assert rc == 0, f"npt up failed:\n{out}\n{err}"
        assert connected_ssid() == connected, (
            f"expected wifi to reconnect to {connected} before `npt up` "
            "returned"
        )
