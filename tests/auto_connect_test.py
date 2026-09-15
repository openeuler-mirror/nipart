# SPDX-License-Identifier: Apache-2.0

"""Tests for the daemon-only `auto-connect` property.

`auto-connect` is a daemon-only property: the kernel never reports it and
the daemon config manager is only updated after a successful apply, hence
re-applying an unchanged config used to fail verification with:
`Verification failure: <name>.interface.auto-connect desire 'false',
current 'null'`.
"""

import pytest

import nipart
from .testlib.statelib import load_yaml, show_only
from .testlib.veth import veth_interface

TEST_VETH = "autocn0"
TEST_VETH_PEER = "autocn1"
TEST_PROFILE = "autocn-prof0"
TEST_IP = "192.0.2.86"


@pytest.fixture
def veth_env():
    with veth_interface(TEST_VETH, TEST_VETH_PEER):
        yield


def _profile_yaml(mac_address):
    return f"""---
        interfaces:
          - name: {TEST_PROFILE}
            type: ethernet
            identifier: mac-address
            mac-address: {mac_address}
            auto-connect: false
            state: up
            ipv4:
              enabled: true
              dhcp: false
              address:
                - ip: {TEST_IP}
                  prefix-length: 24
        """


def _remove_profile_yaml(mac_address):
    return f"""---
        interfaces:
          - name: {TEST_PROFILE}
            type: ethernet
            identifier: mac-address
            mac-address: {mac_address}
            state: absent
        """


def test_auto_connect_false_reapply(veth_env):
    mac_address = show_only(TEST_VETH)["mac-address"]
    desired_state = load_yaml(_profile_yaml(mac_address))

    nipart.apply(desired_state)
    try:
        # The second apply of the unchanged config has no `auto-connect`
        # change in its apply diff, verification must still pass: the
        # property is stored by the daemon, not by the kernel.
        nipart.apply(desired_state)

        iface_state = show_only(TEST_VETH)
        assert iface_state.get("auto-connect") is False, (
            f"Running state of {TEST_VETH} should carry the saved "
            f"`auto-connect: false` value: {iface_state}"
        )
    finally:
        nipart.apply(load_yaml(_remove_profile_yaml(mac_address)))
