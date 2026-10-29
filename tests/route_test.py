# SPDX-License-Identifier: Apache-2.0

import nipart
import pytest

from .conftest import start_daemon
from .conftest import stop_daemon
from .testlib.cmdlib import exec_cmd
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml

TEST_IFACE = "route-dummy0"
TEST_TABLE_ID = 100
IPV4_LOCAL = "192.0.2.10"
IPV4_ROUTE_DST = "198.51.100.0/24"
IPV4_ROUTE_GW = "192.0.2.1"
IPV4_ROUTE_GW2 = "192.0.2.2"
IPV6_LOCAL = "2001:db8::10"
IPV6_ROUTE_DST = "2001:db8:1::/64"
IPV6_ROUTE_GW = "2001:db8::1"


def _iface_state():
    return f"""---
        interfaces:
          - name: {TEST_IFACE}
            type: dummy
            state: up
            ipv4:
              enabled: true
              dhcp: false
              address:
                - ip: {IPV4_LOCAL}
                  prefix-length: 24
            ipv6:
              enabled: true
              dhcp: false
              autoconf: false
              address:
                - ip: {IPV6_LOCAL}
                  prefix-length: 64
        """


def _iface_absent_state():
    return f"""---
        interfaces:
          - name: {TEST_IFACE}
            type: dummy
            state: absent
        """


def _flush_test_table():
    exec_cmd(
        ["ip", "route", "flush", "table", str(TEST_TABLE_ID)], check=False
    )
    exec_cmd(
        ["ip", "-6", "route", "flush", "table", str(TEST_TABLE_ID)],
        check=False,
    )


def _add_route(args):
    exec_cmd(["ip", "route", "add"] + args, check=True)


def _add_route_v6(args):
    exec_cmd(["ip", "-6", "route", "add"] + args, check=True)


def _del_route(args):
    exec_cmd(["ip", "route", "del"] + args, check=False)


def _del_route_v6(args):
    exec_cmd(["ip", "-6", "route", "del"] + args, check=False)


def _running_routes():
    state = nipart.NipartClient().query_network_state(
        nipart.NipartQueryOption.running()
    )
    return state.get("routes", {}).get("running", [])


def _find_routes(destination, **properties):
    matches = []
    for route in _running_routes():
        if route.get("destination") != destination:
            continue
        if any(route.get(key) != value for key, value in properties.items()):
            continue
        matches.append(route)
    return matches


@pytest.fixture(scope="module")
def route_iface():
    _flush_test_table()
    exec_cmd(["ip", "link", "del", TEST_IFACE], check=False)
    nipart.apply(load_yaml(_iface_state()))
    yield TEST_IFACE
    _flush_test_table()
    nipart.apply(load_yaml(_iface_absent_state()))


def test_query_ipv4_route(route_iface):
    route_args = [
        IPV4_ROUTE_DST,
        "via",
        IPV4_ROUTE_GW,
        "dev",
        route_iface,
        "table",
        str(TEST_TABLE_ID),
        "metric",
        "50",
        "src",
        IPV4_LOCAL,
        "onlink",
    ]
    _add_route(route_args)
    try:
        matches = _find_routes(
            IPV4_ROUTE_DST,
            **{
                "next-hop-interface": route_iface,
                "next-hop-address": IPV4_ROUTE_GW,
                "table-id": TEST_TABLE_ID,
                "metric": 50,
                "source": IPV4_LOCAL,
                "onlink": True,
            },
        )
        assert matches, _running_routes()
    finally:
        _del_route(
            [
                IPV4_ROUTE_DST,
                "dev",
                route_iface,
                "table",
                str(TEST_TABLE_ID),
            ]
        )


def test_query_ipv6_route(route_iface):
    route_args = [
        IPV6_ROUTE_DST,
        "via",
        IPV6_ROUTE_GW,
        "dev",
        route_iface,
        "table",
        str(TEST_TABLE_ID),
        "metric",
        "50",
        "src",
        IPV6_LOCAL,
    ]
    _add_route_v6(route_args)
    try:
        matches = _find_routes(
            IPV6_ROUTE_DST,
            **{
                "next-hop-interface": route_iface,
                "next-hop-address": IPV6_ROUTE_GW,
                "table-id": TEST_TABLE_ID,
                "metric": 50,
                "source": IPV6_LOCAL,
            },
        )
        assert matches, _running_routes()
    finally:
        _del_route_v6(
            [
                IPV6_ROUTE_DST,
                "dev",
                route_iface,
                "table",
                str(TEST_TABLE_ID),
            ]
        )


def test_query_default_routes(route_iface):
    _add_route(
        [
            "default",
            "via",
            IPV4_ROUTE_GW,
            "dev",
            route_iface,
            "table",
            str(TEST_TABLE_ID),
            "metric",
            "60",
        ]
    )
    _add_route_v6(
        [
            "default",
            "via",
            IPV6_ROUTE_GW,
            "dev",
            route_iface,
            "table",
            str(TEST_TABLE_ID),
            "metric",
            "60",
        ]
    )
    try:
        assert _find_routes(
            "0.0.0.0/0",
            **{
                "next-hop-interface": route_iface,
                "next-hop-address": IPV4_ROUTE_GW,
                "table-id": TEST_TABLE_ID,
                "metric": 60,
            },
        ), _running_routes()
        assert _find_routes(
            "::/0",
            **{
                "next-hop-interface": route_iface,
                "next-hop-address": IPV6_ROUTE_GW,
                "table-id": TEST_TABLE_ID,
                "metric": 60,
            },
        ), _running_routes()
    finally:
        _del_route(
            [
                "default",
                "dev",
                route_iface,
                "table",
                str(TEST_TABLE_ID),
            ]
        )
        _del_route_v6(
            [
                "default",
                "dev",
                route_iface,
                "table",
                str(TEST_TABLE_ID),
            ]
        )


@pytest.mark.parametrize(
    "route_type,destination",
    [
        ("blackhole", "203.0.113.0/24"),
        ("unreachable", "198.51.100.0/24"),
        ("prohibit", "192.0.2.0/24"),
    ],
)
def test_query_route_types(route_iface, route_type, destination):
    _add_route(
        [
            route_type,
            destination,
            "table",
            str(TEST_TABLE_ID),
        ]
    )
    try:
        matches = _find_routes(
            destination,
            **{
                "route-type": route_type,
                "table-id": TEST_TABLE_ID,
            },
        )
        assert matches, _running_routes()
        assert "next-hop-interface" not in matches[0]
    finally:
        _del_route([route_type, destination, "table", str(TEST_TABLE_ID)])


def _kernel_routes(table_id, ipv6=False):
    cmd = (
        ["ip", "-6", "route", "show", "table", str(table_id)]
        if ipv6
        else ["ip", "-4", "route", "show", "table", str(table_id)]
    )
    _, out, _ = exec_cmd(cmd)
    return out


def _saved_routes():
    state = nipart.NipartClient().query_network_state(
        nipart.NipartQueryOption.saved()
    )
    return state.get("routes", {}).get("config", [])


def _route_state(
    destination,
    iface,
    metric=None,
    gateway=None,
    state=None,
):
    lines = [f"    - destination: {destination}"]
    if state is not None:
        lines.append(f"      state: {state}")
    lines.append(f"      next-hop-interface: {iface}")
    if gateway is not None:
        lines.append(f"      next-hop-address: {gateway}")
    lines.append(f"      table-id: {TEST_TABLE_ID}")
    if metric is not None:
        lines.append(f"      metric: {metric}")
    return "---\nroutes:\n  config:\n" + "\n".join(lines) + "\n"


def _route_absent_state(destination, iface, gateway=None):
    return load_yaml(
        _route_state(
            destination,
            iface,
            gateway=gateway,
            state="absent",
        )
    )


def _route_saved(destination, metric=None):
    for route in _saved_routes():
        if route.get("destination") != destination:
            continue
        if route.get("table-id") != TEST_TABLE_ID:
            continue
        if metric is not None and route.get("metric") != metric:
            continue
        return True
    return False


def test_apply_and_remove_ipv4_route(route_iface):
    nipart.apply(
        load_yaml(
            _route_state(
                IPV4_ROUTE_DST,
                route_iface,
                metric=100,
                gateway=IPV4_ROUTE_GW,
            )
        )
    )
    try:
        output = _kernel_routes(TEST_TABLE_ID)
        assert IPV4_ROUTE_DST in output, output
        assert "metric 100" in output, output
        assert _find_routes(
            IPV4_ROUTE_DST,
            **{
                "next-hop-interface": route_iface,
                "next-hop-address": IPV4_ROUTE_GW,
                "table-id": TEST_TABLE_ID,
                "metric": 100,
            },
        ), _running_routes()
        assert _route_saved(IPV4_ROUTE_DST, metric=100), _saved_routes()
    finally:
        nipart.apply(
            _route_absent_state(IPV4_ROUTE_DST, route_iface, IPV4_ROUTE_GW)
        )
    output = _kernel_routes(TEST_TABLE_ID)
    assert IPV4_ROUTE_DST not in output, output
    assert not _find_routes(
        IPV4_ROUTE_DST,
        **{
            "next-hop-interface": route_iface,
            "table-id": TEST_TABLE_ID,
        },
    ), _running_routes()


def test_apply_and_remove_ipv6_route(route_iface):
    nipart.apply(
        load_yaml(
            _route_state(
                IPV6_ROUTE_DST,
                route_iface,
                metric=100,
                gateway=IPV6_ROUTE_GW,
            )
        )
    )
    try:
        output = _kernel_routes(TEST_TABLE_ID, ipv6=True)
        assert IPV6_ROUTE_DST in output, output
        assert "metric 100" in output, output
        assert _find_routes(
            IPV6_ROUTE_DST,
            **{
                "next-hop-interface": route_iface,
                "next-hop-address": IPV6_ROUTE_GW,
                "table-id": TEST_TABLE_ID,
                "metric": 100,
            },
        ), _running_routes()
        assert _route_saved(IPV6_ROUTE_DST, metric=100), _saved_routes()
    finally:
        nipart.apply(
            _route_absent_state(IPV6_ROUTE_DST, route_iface, IPV6_ROUTE_GW)
        )
    output = _kernel_routes(TEST_TABLE_ID, ipv6=True)
    assert IPV6_ROUTE_DST not in output, output
    assert not _find_routes(
        IPV6_ROUTE_DST,
        **{
            "next-hop-interface": route_iface,
            "table-id": TEST_TABLE_ID,
        },
    ), _running_routes()


def test_replace_default_route(route_iface):
    nipart.apply(
        load_yaml(
            _route_state(
                "0.0.0.0/0",
                route_iface,
                metric=100,
                gateway=IPV4_ROUTE_GW,
            )
        )
    )
    try:
        assert "metric 100" in _kernel_routes(TEST_TABLE_ID)
        nipart.apply(
            load_yaml(
                "---\nroutes:\n  config:\n"
                + "    - destination: 0.0.0.0/0\n"
                + "      state: absent\n"
                + f"      next-hop-interface: {route_iface}\n"
                + f"      next-hop-address: {IPV4_ROUTE_GW}\n"
                + f"      table-id: {TEST_TABLE_ID}\n"
                + "    - destination: 0.0.0.0/0\n"
                + f"      next-hop-interface: {route_iface}\n"
                + f"      next-hop-address: {IPV4_ROUTE_GW2}\n"
                + f"      table-id: {TEST_TABLE_ID}\n"
                + "      metric: 200\n"
            )
        )
        output = _kernel_routes(TEST_TABLE_ID)
        assert "default" in output, output
        assert IPV4_ROUTE_GW2 in output, output
        assert "metric 200" in output, output
        assert IPV4_ROUTE_GW not in output, output
        matches = _find_routes(
            "0.0.0.0/0",
            **{
                "next-hop-interface": route_iface,
                "next-hop-address": IPV4_ROUTE_GW2,
                "table-id": TEST_TABLE_ID,
                "metric": 200,
            },
        )
        assert len(matches) == 1, _running_routes()
    finally:
        nipart.apply(
            _route_absent_state("0.0.0.0/0", route_iface, IPV4_ROUTE_GW2)
        )
    assert "default" not in _kernel_routes(TEST_TABLE_ID)


def test_route_restored_after_daemon_restart(route_iface):
    nipart.apply(
        load_yaml(
            _route_state(
                IPV4_ROUTE_DST,
                route_iface,
                metric=100,
                gateway=IPV4_ROUTE_GW,
            )
        )
    )
    assert IPV4_ROUTE_DST in _kernel_routes(TEST_TABLE_ID)
    stop_daemon()
    try:
        _del_route(
            [
                IPV4_ROUTE_DST,
                "dev",
                route_iface,
                "table",
                str(TEST_TABLE_ID),
            ]
        )
        assert IPV4_ROUTE_DST not in _kernel_routes(TEST_TABLE_ID)
    finally:
        start_daemon()

    def _route_restored():
        return bool(
            _find_routes(
                IPV4_ROUTE_DST,
                **{
                    "next-hop-interface": route_iface,
                    "next-hop-address": IPV4_ROUTE_GW,
                    "table-id": TEST_TABLE_ID,
                    "metric": 100,
                },
            )
        )

    try:
        assert retry_till_true_or_timeout(
            30, _route_restored
        ), "Route not restored from saved config after daemon restart"
    finally:
        nipart.apply(
            _route_absent_state(IPV4_ROUTE_DST, route_iface, IPV4_ROUTE_GW)
        )
