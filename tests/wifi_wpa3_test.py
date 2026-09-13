# SPDX-License-Identifier: Apache-2.0

import pytest

import nipart

from .testlib.dhcp import DHCP_SRV_IP4_PREFIX
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml
from .testlib.wifi import TEST_NET_NS
from .testlib.wifi import TEST_WIFI_PSK
from .testlib.wifi import TEST_WIFI_SSID_WPA3
from .testlib.wifi import WIFI_TEST_NIC
from .testlib.wifi import create_sim_wifi_nics
from .testlib.wifi import destroy_sim_wifi_nics
from .testlib.wifi import ping_wifi_peer
from .testlib.wifi import start_hostapd_wpa3


@pytest.fixture(scope="module")
def wifi_wpa3_env():
    create_sim_wifi_nics()
    start_hostapd_wpa3(TEST_NET_NS)
    yield
    destroy_sim_wifi_nics()


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
