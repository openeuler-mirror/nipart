# SPDX-License-Identifier: Apache-2.0

import nipart

from .conftest import start_daemon
from .conftest import stop_daemon
from .testlib.cmdlib import exec_cmd
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml
from .testlib.statelib import show_only
from .testlib.veth import veth_interface

TEST_VETH = "veth-vdep0"
TEST_VETH_PEER = "veth-vdep1"
TEST_VLAN = "vlan-vdep0"
TEST_BOND = "bond-vdep0"
DEFAULT_TIMEOUT = 20


def _iface_is_up(iface_name):
    iface_state = show_only(iface_name)
    return iface_state is not None and iface_state.get("state") == "up"


def _bond_has_port():
    bond_state = show_only(TEST_BOND)
    if bond_state is None or bond_state.get("state") != "up":
        return False
    return any(
        port.get("name") == TEST_VETH
        for port in bond_state.get("bond", {}).get("ports", [])
    )


def _bounce_link(iface_name):
    exec_cmd(["ip", "link", "set", iface_name, "down"])
    exec_cmd(["ip", "link", "set", iface_name, "up"])


def test_vlan_created_when_parent_link_event():
    """A saved VLAN is created by the link event of its parent.

    The boot non-NIC apply cannot create a virtual interface whose parent
    is absent; the parent's link event must include the missing dependent
    virtual config in its desired state.
    """
    with veth_interface(TEST_VETH, TEST_VETH_PEER):
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_VLAN}
                type: vlan
                state: up
                vlan:
                  base-iface: {TEST_VETH}
                  id: 100
            """))
        try:
            assert _iface_is_up(TEST_VLAN), "VLAN was not created"

            # Restart so the boot pass registers a link watch for every
            # saved interface, including the active parent.
            stop_daemon()
            start_daemon()
            assert _iface_is_up(TEST_VLAN), "VLAN was not restored at boot"

            # Simulate the parent appearing after the VLAN config was saved:
            # remove the VLAN and let the parent's link event recreate it.
            exec_cmd(["ip", "link", "del", TEST_VLAN])
            assert not _iface_is_up(TEST_VLAN), "VLAN was not removed"
            _bounce_link(TEST_VETH)

            assert retry_till_true_or_timeout(
                DEFAULT_TIMEOUT, _iface_is_up, TEST_VLAN
            ), "VLAN was not recreated by the parent link event"
        finally:
            nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_VLAN}
                    type: vlan
                    state: absent
                """))


def test_bond_created_when_port_link_event():
    """A saved bond is created by the link event of its port.

    When the controller is missing (e.g. deleted or lost with a driver
    reload) but its port exists, the port's link event must include the
    controller config so the bond is created again and the port attached.
    """
    with veth_interface(TEST_VETH, TEST_VETH_PEER):
        nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_BOND}
                type: bond
                state: up
                bond:
                  mode: active-backup
                  ports:
                    - name: {TEST_VETH}
            """))
        try:
            assert _bond_has_port(), "Bond port was not attached"

            # Restart so the boot pass registers a link watch for every
            # saved interface, including the active port.
            stop_daemon()
            start_daemon()
            assert _bond_has_port(), "Bond was not restored at boot"

            # Simulate the controller missing while the port stays: the
            # port's link event recreates the bond and attaches it.
            exec_cmd(["ip", "link", "del", TEST_BOND])
            assert not _bond_has_port(), "Bond was not removed"
            _bounce_link(TEST_VETH)

            assert retry_till_true_or_timeout(
                DEFAULT_TIMEOUT, _bond_has_port
            ), "Bond was not recreated by the port link event"
        finally:
            nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_BOND}
                    type: bond
                    state: absent
                """))
