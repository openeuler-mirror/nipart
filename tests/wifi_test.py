# SPDX-License-Identifier: Apache-2.0

import re

import pytest

import nipart

from .conftest import CLI_PATH
from .testlib.cmdlib import exec_cmd
from .testlib.dhcp import DHCP_SRV_IP4
from .testlib.dhcp import DHCP_SRV_IP4_PREFIX
from .testlib.dhcp import IPV4_CLASSLESS_ROUTE_DST_NET1
from .testlib.env import has_kernel_module
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml
from .testlib.wifi import TEST_WIFI_PSK
from .testlib.wifi import TEST_WIFI_SSID
from .testlib.wifi import WIFI_TEST_NIC
from .testlib.wifi import ping_wifi_peer
from .testlib.wifi import wifi_env  # noqa: F401


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
class TestWifi:
    def connected_ssid(self):
        output = exec_cmd(f"iw dev {WIFI_TEST_NIC} link".split(), check=False)[
            1
        ]
        match = re.search(r"SSID: (.+)", output)
        return match.group(1) if match else None

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
        assert self.connected_ssid() == TEST_WIFI_SSID
        try:
            rc, out, err = exec_cmd([CLI_PATH, "wifi", "off"], check=False)
            assert rc == 0, f"npt wifi off failed:\n{out}\n{err}"
            assert "WIFI is off" in out, out
            assert retry_till_true_or_timeout(
                5, lambda: self.connected_ssid() is None
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
                30, lambda: self.connected_ssid() == TEST_WIFI_SSID
            ), "WIFI did not reconnect to the saved SSID after `npt wifi on`"
            assert retry_till_true_or_timeout(
                10, ping_wifi_peer
            ), "Cannot ping peer through WIFI after `npt wifi on`"
            assert retry_till_true_or_timeout(
                10, self.has_static_ip_and_route
            ), "WIFI static IP or route not restored by `npt wifi on`"
        finally:
            exec_cmd([CLI_PATH, "wifi", "on"], check=False)
