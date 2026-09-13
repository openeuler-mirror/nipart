# SPDX-License-Identifier: Apache-2.0

import os
import signal

import nipart
import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.dhcp import DHCP_SRV_IP4_PREFIX
from .testlib.dhcp import DHCP_SRV_NIC
from .testlib.dhcp import stop_dhcp_server
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml
from .testlib.wifi import HOSTAPD_CONF_PATH
from .testlib.wifi import HOSTAPD_PID_PATH
from .testlib.wifi import HWSIM0_PERM_MAC
from .testlib.wifi import HWSIM1_PERM_MAC
from .testlib.wifi import TEST_NET_NS
from .testlib.wifi import TEST_WIFI_SSID_OPEN
from .testlib.wifi import TIMEOUT_SECS_SIM_WIFI_NICS
from .testlib.wifi import WIFI_TEST_NIC
from .testlib.wifi import get_nic_name_by_perm_mac
from .testlib.wifi import has_sim_wifi_nics
from .testlib.wifi import ping_wifi_peer
from .testlib.wifi import start_hostapd_open
from .testlib.wifi import unload_wifi_sim_kernel_module


@pytest.fixture(scope="module")
def wifi_open_env():
    exec_cmd("modprobe -r mac80211_hwsim".split(), check=False)
    exec_cmd(f"ip netns del {TEST_NET_NS}".split(), check=False)
    exec_cmd(f"ip netns add {TEST_NET_NS}".split())

    exec_cmd("modprobe mac80211_hwsim radios=2".split())
    assert retry_till_true_or_timeout(
        TIMEOUT_SECS_SIM_WIFI_NICS, has_sim_wifi_nics
    )

    state = nipart.show()
    exec_cmd("killall wpa_supplicant".split(), check=False)
    wlan1 = get_nic_name_by_perm_mac(state, HWSIM0_PERM_MAC)
    exec_cmd(f"ip link set {wlan1} name {WIFI_TEST_NIC}".split())
    wlan2 = get_nic_name_by_perm_mac(state, HWSIM1_PERM_MAC)
    exec_cmd(f"ip link set {wlan2} name {DHCP_SRV_NIC}".split())
    start_hostapd_open(TEST_NET_NS)
    yield
    os.remove(HOSTAPD_CONF_PATH)
    if os.path.exists(HOSTAPD_PID_PATH):
        with open(HOSTAPD_PID_PATH) as fd:
            pid = fd.read()
        os.kill(int(pid), signal.SIGTERM)
    stop_dhcp_server()
    exec_cmd(f"ip netns del {TEST_NET_NS}".split())
    retry_till_true_or_timeout(10, unload_wifi_sim_kernel_module)


@pytest.fixture
def clean_up():
    yield
    nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {WIFI_TEST_NIC}
                type: wifi-phy
                state: absent"""))


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
