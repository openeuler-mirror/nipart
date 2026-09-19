# SPDX-License-Identifier: Apache-2.0

import nipart
import pytest

from .conftest import start_daemon, stop_daemon
from .testlib.cmdlib import exec_cmd
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml, show_only

TEST_VETH = "veth-altname0"
TEST_VETH_PEER = "veth-altname1"
DEFAULT_TIMEOUT = 30


def _gen_veth_state(alt_names, iface_name=TEST_VETH, peer=TEST_VETH_PEER):
    entries = ""
    for name, state in alt_names:
        entries += f"            - name: {name}\n"
        if state:
            entries += f"              state: {state}\n"
    return load_yaml(f"""---
        interfaces:
        - name: {iface_name}
          type: veth
          state: up
          alt-names:
{entries}          veth:
            peer: {peer}
    """)


def _create_veth_pair():
    # An interrupted earlier run may have left the veth pair behind.
    exec_cmd(f"ip link del {TEST_VETH}".split(), check=False)
    exec_cmd(
        f"ip link add {TEST_VETH} type veth peer name {TEST_VETH_PEER}".split()
    )


def _purge_saved_veth_profile():
    # Remove the saved profile as well as the kernel interface: a later
    # daemon restart re-applies the saved state, which would re-create the
    # veth pair and leave test leftovers behind.
    nipart.apply(load_yaml(f"""---
        interfaces:
          - name: {TEST_VETH}
            type: veth
            state: absent
    """))


def _purge_saved_mac_profile(profile_name, mac_address):
    # Purge the MAC-identified saved profile: otherwise a daemon restart
    # re-applies the rename to a NIC carrying this MAC.
    nipart.apply(load_yaml(f"""---
        interfaces:
          - name: {profile_name}
            type: ethernet
            identifier: mac-address
            mac-address: {mac_address}
            state: absent
    """))


def _remove_veth_pair():
    _purge_saved_veth_profile()
    exec_cmd(f"ip link del {TEST_VETH}".split(), check=False)


def _has_alt_names(iface_name, expected):
    iface = show_only(iface_name)
    if iface is None:
        return False
    alt_names = iface.get("alt-names")
    names = {entry["name"] for entry in alt_names} if alt_names else set()
    return names == set(expected)


def _kernel_alt_names(iface_name):
    rc, out, _ = exec_cmd(
        ["ip", "-d", "link", "show", iface_name], check=False
    )
    if rc != 0:
        return set()
    return {
        line.split()[-1]
        for line in out.splitlines()
        if line.strip().startswith("altname")
    }


def test_alt_name_apply_add():
    _create_veth_pair()
    try:
        # The desired order (zebra, alpha) is not kept: alt-names are
        # sorted during sanitization.
        nipart.apply(_gen_veth_state([("zebra", None), ("alpha", None)]))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_alt_names, TEST_VETH, ["alpha", "zebra"]
        ), "Alt-names not applied"
        assert _kernel_alt_names(TEST_VETH) == {"alpha", "zebra"}
    finally:
        _remove_veth_pair()


def test_alt_name_add():
    _create_veth_pair()
    try:
        nipart.apply(_gen_veth_state([("alpha", None)]))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_alt_names, TEST_VETH, ["alpha"]
        )
        # Adding a new alt-name keeps the existing one.
        nipart.apply(_gen_veth_state([("alpha", None), ("beta", None)]))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _has_alt_names,
            TEST_VETH,
            ["alpha", "beta"],
        ), "Added alt-name not applied / existing alt-name lost"
    finally:
        _remove_veth_pair()


def test_alt_name_change():
    _create_veth_pair()
    try:
        nipart.apply(_gen_veth_state([("alpha", None), ("beta", None)]))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _has_alt_names,
            TEST_VETH,
            ["alpha", "beta"],
        )
        # Remove `beta`, add `gamma`.
        nipart.apply(
            _gen_veth_state(
                [("alpha", None), ("beta", "absent"), ("gamma", None)]
            )
        )
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _has_alt_names,
            TEST_VETH,
            ["alpha", "gamma"],
        ), "Changed alt-names (remove beta, add gamma) not applied"
    finally:
        _remove_veth_pair()


def test_alt_name_remove():
    _create_veth_pair()
    try:
        nipart.apply(_gen_veth_state([("alpha", None), ("beta", None)]))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _has_alt_names,
            TEST_VETH,
            ["alpha", "beta"],
        )
        nipart.apply(_gen_veth_state([("beta", "absent")]))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_alt_names, TEST_VETH, ["alpha"]
        ), "Removed alt-name still present"
    finally:
        _remove_veth_pair()


def test_alt_name_conflict_rejected():
    _create_veth_pair()
    try:
        # Two interfaces sharing the same alt-name must be rejected.
        state = load_yaml(f"""---
            interfaces:
            - name: {TEST_VETH}
              type: veth
              state: up
              alt-names:
                - name: shared
              veth:
                peer: {TEST_VETH_PEER}
            - name: {TEST_VETH_PEER}
              type: veth
              state: up
              alt-names:
                - name: shared
            """)
        with pytest.raises(nipart.NipartError) as err:
            nipart.apply(state)
        assert "already used by interface" in str(err.value)
    finally:
        _remove_veth_pair()


def test_boot_load_saved_alt_names():
    _create_veth_pair()
    try:
        nipart.apply(_gen_veth_state([("alpha", None), ("zebra", None)]))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_alt_names, TEST_VETH, ["alpha", "zebra"]
        )
        # Wipe the kernel alt-names, then restart the daemon: the saved
        # config must re-apply the alt-names at boot.
        exec_cmd(
            f"ip link property del dev {TEST_VETH} altname alpha".split(),
            check=False,
        )
        exec_cmd(
            f"ip link property del dev {TEST_VETH} altname zebra".split(),
            check=False,
        )
        assert _kernel_alt_names(TEST_VETH) == set()
        stop_daemon()
        start_daemon()
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _has_alt_names, TEST_VETH, ["alpha", "zebra"]
        ), "Saved alt-names not re-applied at boot"
    finally:
        _remove_veth_pair()


def _iface_has_alt_names(iface_name, expected):
    rc, out, _ = exec_cmd(
        ["ip", "-d", "link", "show", iface_name], check=False
    )
    if rc != 0:
        return False
    alt_names = {
        line.split()[-1]
        for line in out.splitlines()
        if line.strip().startswith("altname")
    }
    return alt_names == set(expected)


REN_VETH = "veth-ren0"
REN_VETH_PEER = "veth-ren1"


def _create_ren_veth_pair():
    # An interrupted earlier run may have left the veth pair behind.
    exec_cmd(f"ip link del {REN_VETH}".split(), check=False)
    exec_cmd("ip link del renamed0".split(), check=False)
    exec_cmd("ip link del renamed1".split(), check=False)
    exec_cmd(
        f"ip link add {REN_VETH} type veth peer name {REN_VETH_PEER}".split()
    )


def _remove_ren_veth_pair():
    exec_cmd(f"ip link del {REN_VETH}".split(), check=False)


def test_mac_id_kernel_iface_name_rename_keeps_original_alt_name():
    # A MAC-identified config with an explicit `kernel-iface-name` renames
    # the matched interface and keeps the original kernel name as an
    # alt-name (no `alt-names` in desired or saved state).
    _create_ren_veth_pair()
    try:
        exec_cmd(f"ip link set {REN_VETH} address 02:00:00:00:00:03".split())
        nipart.apply(load_yaml("""---
                interfaces:
                - name: port1
                  type: ethernet
                  identifier: mac-address
                  mac-address: 02:00:00:00:00:03
                  kernel-iface-name: renamed0
                """))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _iface_has_alt_names,
            "renamed0",
            [REN_VETH],
        ), "Interface not renamed with original name kept as alt-name"
        iface = show_only("renamed0")
        assert iface is not None
        assert iface.get("profile-name") == "port1"
    finally:
        _purge_saved_mac_profile("port1", "02:00:00:00:00:03")
        exec_cmd(["ip", "link", "del", "renamed0"], check=False)
        _remove_ren_veth_pair()


def test_mac_id_kernel_iface_name_no_auto_alt_name_when_defined():
    # When the desired state defines `alt-names` explicitly, the original
    # kernel name is not auto-added.
    _create_ren_veth_pair()
    try:
        exec_cmd(f"ip link set {REN_VETH} address 02:00:00:00:00:04".split())
        nipart.apply(load_yaml("""---
                interfaces:
                - name: port2
                  type: ethernet
                  identifier: mac-address
                  mac-address: 02:00:00:00:00:04
                  kernel-iface-name: renamed1
                  alt-names:
                    - name: renamed-port
                """))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _iface_has_alt_names,
            "renamed1",
            ["renamed-port"],
        ), "Alt-names not applied on renamed interface"
        # The original kernel name must NOT be auto-added.
        assert REN_VETH not in _kernel_alt_names("renamed1")
    finally:
        _purge_saved_mac_profile("port2", "02:00:00:00:00:04")
        exec_cmd(["ip", "link", "del", "renamed1"], check=False)
        _remove_ren_veth_pair()


def test_boot_load_saved_rename_keeps_original_alt_name():
    # The saved config (MAC-identified with `kernel-iface-name`) must
    # re-apply the rename and the auto-kept original alt-name at boot.
    _create_ren_veth_pair()
    try:
        exec_cmd(f"ip link set {REN_VETH} address 02:00:00:00:00:05".split())
        nipart.apply(load_yaml("""---
                interfaces:
                - name: port3
                  type: ethernet
                  identifier: mac-address
                  mac-address: 02:00:00:00:00:05
                  kernel-iface-name: renamed0
                """))
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _iface_has_alt_names,
            "renamed0",
            [REN_VETH],
        ), "Interface not renamed with original name kept as alt-name"

        # Wipe the kernel state: rename back and remove the alt-name.
        exec_cmd(
            f"ip link property del dev renamed0 altname {REN_VETH}".split(),
            check=False,
        )
        exec_cmd(f"ip link set renamed0 name {REN_VETH}".split())
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT, _iface_has_alt_names, REN_VETH, []
        ), "Kernel alt-name not wiped before daemon restart"

        # Restart the daemon: the saved config must re-apply the rename
        # and the auto-kept alt-name.
        stop_daemon()
        start_daemon()
        assert retry_till_true_or_timeout(
            DEFAULT_TIMEOUT,
            _iface_has_alt_names,
            "renamed0",
            [REN_VETH],
        ), "Saved rename + original alt-name not re-applied at boot"
    finally:
        _purge_saved_mac_profile("port3", "02:00:00:00:00:05")
        exec_cmd(["ip", "link", "del", "renamed0"], check=False)
        exec_cmd(["ip", "link", "del", REN_VETH], check=False)
        _remove_ren_veth_pair()
