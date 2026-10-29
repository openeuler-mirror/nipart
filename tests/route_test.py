# SPDX-License-Identifier: Apache-2.0

import nipart
import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.statelib import load_yaml

TEST_IFACE = "route-dummy0"
TEST_TABLE_ID = 100
IPV4_LOCAL = "192.0.2.10"
IPV4_ROUTE_DST = "198.51.100.0/24"
IPV4_ROUTE_GW = "192.0.2.1"
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
