# SPDX-License-Identifier: Apache-2.0

import json

import nipart
import pytest

from .conftest import start_daemon
from .conftest import stop_daemon
from .testlib.cmdlib import exec_cmd
from .testlib.statelib import load_yaml

RULE_PRIORITY = 40000
RULE_TABLE_ID = 254
RULE_IP_FROM = "198.51.100.0/24"
RULE_IP_TO = "192.0.2.0/24"
RULE_IP_FROM_V6 = "2001:db8:f::/64"
RULE_IP_TO_V6 = "2001:db8:a::/64"
ACTION_RULE_PRIORITY = 40001
ACTION_RULE_IP_FROM = "203.0.113.0/24"
REPLACE_RULE_OLD_PRIORITY = 40100
REPLACE_RULE_NEW_PRIORITY = 40101
TEST_TABLE_ID = 500
IIF_IFACE = "rr-dummy0"


def _ip_rule_output(ipv6=False):
    cmd = (
        ["ip", "-6", "rule", "show"] if ipv6 else ["ip", "-4", "rule", "show"]
    )
    _, out, _ = exec_cmd(cmd)
    return out


def _ip_rules(ipv6=False):
    cmd = (
        ["ip", "-6", "-j", "rule", "show"]
        if ipv6
        else ["ip", "-4", "-j", "rule", "show"]
    )
    _, out, _ = exec_cmd(cmd)
    return json.loads(out)


def _normalized_ip(rule, key):
    value = rule.get(key)
    if value in (None, "all"):
        return ""
    if "/" in value:
        return value
    prefix_len = rule.get(f"{key}len")
    if prefix_len is None:
        prefix_len = 128 if ":" in value else 32
    return f"{value}/{prefix_len}"


def _canonical_ip_network(value):
    if "/" in value:
        return value
    return f"{value}/128" if ":" in value else f"{value}/32"


def _table_id(table):
    if table == "main":
        return "254"
    if table == "local":
        return "255"
    if table == "default":
        return "253"
    return str(table)


def _hex_value(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value.lower()
    return hex(value)


def _matching_rules(
    ipv6=False,
    ip_from=None,
    ip_to=None,
    priority=None,
    table_id=None,
    fwmark=None,
    fwmask=None,
    iif=None,
    action=None,
    suppress_prefix_length=None,
):
    matching = []
    for rule in _ip_rules(ipv6=ipv6):
        if ip_from is not None and (
            _normalized_ip(rule, "src") != _canonical_ip_network(ip_from)
        ):
            continue
        if ip_to is not None and (
            _normalized_ip(rule, "dst") != _canonical_ip_network(ip_to)
        ):
            continue
        if priority is not None and rule.get("priority") != priority:
            continue
        if table_id is not None and _table_id(rule.get("table")) != str(
            table_id
        ):
            continue
        if fwmark is not None and _hex_value(rule.get("fwmark")) != (
            _hex_value(fwmark)
        ):
            continue
        if fwmask is not None and _hex_value(rule.get("fwmask")) != (
            _hex_value(fwmask)
        ):
            continue
        if iif is not None and rule.get("iif") != iif:
            continue
        if action is not None and rule.get("action") != action:
            continue
        if (
            suppress_prefix_length is not None
            and rule.get("suppress_prefixlen") != suppress_prefix_length
        ):
            continue
        matching.append(rule)
    return matching


def _ip_rule_exists(ip_from, ip_to, ipv6=False, priority=RULE_PRIORITY):
    return bool(
        _matching_rules(
            ipv6=ipv6,
            ip_from=ip_from,
            ip_to=ip_to,
            priority=priority,
            table_id=RULE_TABLE_ID,
        )
    )


def _route_rule_state(ip_from, ip_to, priority=RULE_PRIORITY):
    return f"""---
route-rules:
  config:
    - ip-from: {ip_from}
      ip-to: {ip_to}
      priority: {priority}
      route-table: {RULE_TABLE_ID}
"""


def _rule_entry(
    ip_from=None,
    ip_to=None,
    priority=None,
    route_table=None,
    family=None,
    iif=None,
    action=None,
    fwmark=None,
    fwmask=None,
    suppress_prefix_length=None,
    state=None,
):
    entry = {}
    if state is not None:
        entry["state"] = state
    if family is not None:
        entry["family"] = family
    if ip_from is not None:
        entry["ip-from"] = ip_from
    if ip_to is not None:
        entry["ip-to"] = ip_to
    if priority is not None:
        entry["priority"] = priority
    if route_table is not None:
        entry["route-table"] = route_table
    if iif is not None:
        entry["iif"] = iif
    if action is not None:
        entry["action"] = action
    if fwmark is not None:
        entry["fwmark"] = fwmark
    if fwmask is not None:
        entry["fwmask"] = fwmask
    if suppress_prefix_length is not None:
        entry["suppress-prefix-length"] = suppress_prefix_length
    return entry


def _rule_state(*entries):
    return {"route-rules": {"config": list(entries)}}


def _absent_table_state(table):
    return _rule_state(_rule_entry(state="absent", route_table=table))


def _absent_route_rule_state(ip_from, ip_to):
    return f"""---
route-rules:
  config:
    - state: absent
      ip-from: {ip_from}
      ip-to: {ip_to}
      route-table: {RULE_TABLE_ID}
"""


def _replace_route_rule_state():
    return f"""---
route-rules:
  config:
    - state: absent
      ip-from: {RULE_IP_FROM}
      ip-to: {RULE_IP_TO}
      route-table: {RULE_TABLE_ID}
    - ip-from: {RULE_IP_FROM}
      ip-to: {RULE_IP_TO}
      priority: {REPLACE_RULE_NEW_PRIORITY}
      route-table: {RULE_TABLE_ID}
"""


def _blackhole_rule_state():
    return f"""---
route-rules:
  config:
    - ip-from: {ACTION_RULE_IP_FROM}
      priority: {ACTION_RULE_PRIORITY}
      action: blackhole
"""


def _absent_ip_from_route_rule_state(ip_from):
    return f"""---
route-rules:
  config:
    - state: absent
      ip-from: {ip_from}
"""


def test_add_and_remove_ipv4_route_rule():
    desired_state = load_yaml(_route_rule_state(RULE_IP_FROM, RULE_IP_TO))
    nipart.apply(desired_state)
    try:
        assert _ip_rule_exists(RULE_IP_FROM, RULE_IP_TO), _ip_rule_output()
        state = nipart.NipartClient().query_network_state(
            nipart.NipartQueryOption.running()
        )
        rules = state.get("route-rules", {}).get("config", [])
        assert any(
            rule.get("ip-from") == RULE_IP_FROM
            and rule.get("ip-to") == RULE_IP_TO
            and rule.get("priority") == RULE_PRIORITY
            for rule in rules
        ), rules
    finally:
        nipart.apply(
            load_yaml(_absent_route_rule_state(RULE_IP_FROM, RULE_IP_TO))
        )
    assert not _ip_rule_exists(RULE_IP_FROM, RULE_IP_TO), _ip_rule_output()


def test_add_and_remove_ipv6_route_rule():
    desired_state = load_yaml(
        _route_rule_state(RULE_IP_FROM_V6, RULE_IP_TO_V6)
    )
    nipart.apply(desired_state)
    try:
        assert _ip_rule_exists(
            RULE_IP_FROM_V6, RULE_IP_TO_V6, ipv6=True
        ), _ip_rule_output(ipv6=True)
    finally:
        nipart.apply(
            load_yaml(_absent_route_rule_state(RULE_IP_FROM_V6, RULE_IP_TO_V6))
        )
    assert not _ip_rule_exists(
        RULE_IP_FROM_V6, RULE_IP_TO_V6, ipv6=True
    ), _ip_rule_output(ipv6=True)


def test_add_and_remove_blackhole_route_rule():
    nipart.apply(load_yaml(_blackhole_rule_state()))
    try:
        output = _ip_rule_output()
        assert any(
            str(ACTION_RULE_PRIORITY) in line
            and ACTION_RULE_IP_FROM in line
            and "blackhole" in line
            for line in output.splitlines()
        ), output
    finally:
        nipart.apply(
            load_yaml(_absent_ip_from_route_rule_state(ACTION_RULE_IP_FROM))
        )
    output = _ip_rule_output()
    assert not any(
        str(ACTION_RULE_PRIORITY) in line and ACTION_RULE_IP_FROM in line
        for line in output.splitlines()
    ), output


def test_replace_route_rule_with_absent_and_add():
    old_state = load_yaml(
        _route_rule_state(
            RULE_IP_FROM, RULE_IP_TO, priority=REPLACE_RULE_OLD_PRIORITY
        )
    )
    nipart.apply(old_state)
    try:
        assert _ip_rule_exists(
            RULE_IP_FROM,
            RULE_IP_TO,
            priority=REPLACE_RULE_OLD_PRIORITY,
        ), _ip_rule_output()

        nipart.apply(load_yaml(_replace_route_rule_state()))

        assert not _ip_rule_exists(
            RULE_IP_FROM,
            RULE_IP_TO,
            priority=REPLACE_RULE_OLD_PRIORITY,
        ), _ip_rule_output()
        assert _ip_rule_exists(
            RULE_IP_FROM,
            RULE_IP_TO,
            priority=REPLACE_RULE_NEW_PRIORITY,
        ), _ip_rule_output()

        saved_state = nipart.NipartClient().query_network_state(
            nipart.NipartQueryOption.saved()
        )
        rules = saved_state.get("route-rules", {}).get("config", [])
        assert any(
            rule.get("ip-from") == RULE_IP_FROM
            and rule.get("ip-to") == RULE_IP_TO
            and rule.get("priority") == REPLACE_RULE_NEW_PRIORITY
            for rule in rules
        ), rules
        assert not any(
            rule.get("ip-from") == RULE_IP_FROM
            and rule.get("priority") == REPLACE_RULE_OLD_PRIORITY
            for rule in rules
        ), rules
    finally:
        nipart.apply(
            load_yaml(_absent_route_rule_state(RULE_IP_FROM, RULE_IP_TO))
        )


def test_route_rule_add_from_only_and_to_only():
    rules = [
        _rule_entry(
            ip_from=RULE_IP_FROM,
            route_table=TEST_TABLE_ID,
            priority=40200,
        ),
        _rule_entry(
            ip_to=RULE_IP_TO,
            route_table=TEST_TABLE_ID,
            priority=40201,
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        assert _matching_rules(
            ip_from=RULE_IP_FROM, table_id=TEST_TABLE_ID, priority=40200
        )
        assert _matching_rules(
            ip_to=RULE_IP_TO, table_id=TEST_TABLE_ID, priority=40201
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_route_rule_add_without_priority_apply_twice():
    rule = _rule_entry(
        ip_from=RULE_IP_FROM, ip_to=RULE_IP_TO, route_table=TEST_TABLE_ID
    )
    nipart.apply(_rule_state(rule))
    nipart.apply(_rule_state(rule))
    try:
        assert (
            len(
                _matching_rules(
                    ip_from=RULE_IP_FROM,
                    ip_to=RULE_IP_TO,
                    table_id=TEST_TABLE_ID,
                )
            )
            == 1
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_auto_choose_route_rule_priority():
    rules = [
        _rule_entry(
            ip_from=RULE_IP_FROM_V6,
            ip_to=RULE_IP_TO_V6,
            route_table=TEST_TABLE_ID,
        ),
        _rule_entry(
            ip_from=RULE_IP_FROM,
            ip_to=RULE_IP_TO,
            route_table=TEST_TABLE_ID,
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        ipv4_matches = _matching_rules(table_id=TEST_TABLE_ID)
        ipv6_matches = _matching_rules(table_id=TEST_TABLE_ID, ipv6=True)
        assert len(ipv4_matches) == 1
        assert len(ipv6_matches) == 1
        assert {
            match["priority"] for match in ipv4_matches + ipv6_matches
        } == {
            30000,
            30001,
        }
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_route_rule_add_without_route_table_uses_main():
    rule = _rule_entry(
        ip_from=RULE_IP_FROM,
        ip_to=RULE_IP_TO,
        priority=40202,
    )
    nipart.apply(_rule_state(rule))
    try:
        assert _matching_rules(
            ip_from=RULE_IP_FROM,
            ip_to=RULE_IP_TO,
            priority=40202,
            table_id=254,
        )
    finally:
        nipart.apply(
            _rule_state(
                _rule_entry(
                    state="absent",
                    ip_from=RULE_IP_FROM,
                    ip_to=RULE_IP_TO,
                )
            )
        )


def test_route_rule_add_from_to_single_host_is_sanitized():
    rule = _rule_entry(
        ip_from="203.0.113.1",
        ip_to="192.0.2.4/24",
        route_table=TEST_TABLE_ID,
        priority=40203,
    )
    nipart.apply(_rule_state(rule))
    try:
        assert _matching_rules(
            ip_from="203.0.113.1/32",
            ip_to="192.0.2.0/24",
            table_id=TEST_TABLE_ID,
            priority=40203,
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_route_rule_clear_state_with_state_absent_only():
    rules = [
        _rule_entry(
            ip_from=RULE_IP_FROM, route_table=TEST_TABLE_ID, priority=40210
        ),
        _rule_entry(
            ip_to=RULE_IP_TO, route_table=TEST_TABLE_ID, priority=40211
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        nipart.apply(_rule_state(_rule_entry(state="absent")))
        assert not _matching_rules(table_id=TEST_TABLE_ID)
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_apply_empty_state_preserve_route_rules():
    rule = _rule_entry(
        ip_from=RULE_IP_FROM, route_table=TEST_TABLE_ID, priority=40212
    )
    nipart.apply(_rule_state(rule))
    try:
        nipart.apply({"route-rules": {"config": []}})
        assert _matching_rules(
            ip_from=RULE_IP_FROM,
            table_id=TEST_TABLE_ID,
            priority=40212,
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_remove_route_rule_with_wildcard():
    rules = [
        _rule_entry(
            ip_from=RULE_IP_FROM, route_table=TEST_TABLE_ID, priority=40213
        ),
        _rule_entry(
            ip_to=RULE_IP_TO, route_table=TEST_TABLE_ID, priority=40214
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))
        assert not _matching_rules(table_id=TEST_TABLE_ID)
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_route_rule_fwmark_without_and_with_fwmask():
    rules = [
        _rule_entry(
            ip_from=RULE_IP_FROM,
            route_table=TEST_TABLE_ID,
            priority=40220,
            fwmark=0x20,
        ),
        _rule_entry(
            ip_from=RULE_IP_FROM_V6,
            route_table=TEST_TABLE_ID,
            priority=40221,
            fwmark=0x20,
            fwmask=0x10,
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        assert _matching_rules(
            ip_from=RULE_IP_FROM,
            table_id=TEST_TABLE_ID,
            priority=40220,
            fwmark=0x20,
        )
        assert _matching_rules(
            ip_from=RULE_IP_FROM_V6,
            table_id=TEST_TABLE_ID,
            priority=40221,
            fwmark=0x20,
            fwmask=0x10,
            ipv6=True,
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_route_rule_fwmask_without_fwmark_is_rejected():
    with pytest.raises(nipart.NipartValueError, match="fwmark"):
        nipart.apply(
            _rule_state(
                _rule_entry(
                    ip_from=RULE_IP_FROM,
                    route_table=TEST_TABLE_ID,
                    fwmask=0x10,
                )
            )
        )


def test_route_rule_family_only_from_all_to_all():
    rules = [
        _rule_entry(family="ipv4", route_table=TEST_TABLE_ID, priority=40230),
        _rule_entry(family="ipv6", route_table=TEST_TABLE_ID, priority=40231),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        assert _matching_rules(table_id=TEST_TABLE_ID, priority=40230)
        assert _matching_rules(
            table_id=TEST_TABLE_ID, priority=40231, ipv6=True
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_route_rule_iif():
    nipart.apply(load_yaml(f"""---
interfaces:
  - name: {IIF_IFACE}
    type: dummy
    state: up
route-rules:
  config:
    - ip-from: {RULE_IP_FROM}
      route-table: {TEST_TABLE_ID}
      priority: 40240
      iif: {IIF_IFACE}
"""))
    try:
        assert _matching_rules(
            ip_from=RULE_IP_FROM,
            table_id=TEST_TABLE_ID,
            priority=40240,
            iif=IIF_IFACE,
        )
    finally:
        nipart.apply(
            _rule_state(
                _rule_entry(
                    state="absent",
                    ip_from=RULE_IP_FROM,
                    route_table=TEST_TABLE_ID,
                    iif=IIF_IFACE,
                )
            )
        )
        nipart.apply(load_yaml(f"""---
interfaces:
  - name: {IIF_IFACE}
    type: dummy
    state: absent
"""))


def test_route_rule_unreachable_and_prohibit_actions():
    rules = [
        _rule_entry(
            ip_from="203.0.113.5/32",
            action="unreachable",
            priority=40250,
        ),
        _rule_entry(
            ip_from="203.0.113.6/32",
            action="prohibit",
            priority=40251,
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        assert _matching_rules(
            ip_from="203.0.113.5/32",
            action="unreachable",
            priority=40250,
        )
        assert _matching_rules(
            ip_from="203.0.113.6/32",
            action="prohibit",
            priority=40251,
        )
    finally:
        nipart.apply(
            _rule_state(
                _rule_entry(state="absent", ip_from="203.0.113.5/32"),
                _rule_entry(state="absent", ip_from="203.0.113.6/32"),
            )
        )


def test_route_rule_ipv6_actions():
    rules = [
        _rule_entry(
            ip_from="2001:db8:1::1/128",
            action="blackhole",
            priority=40252,
        ),
        _rule_entry(
            ip_from="2001:db8:1::2/128",
            action="unreachable",
            priority=40253,
        ),
        _rule_entry(
            ip_from="2001:db8:1::3/128",
            action="prohibit",
            priority=40254,
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        assert _matching_rules(
            ip_from="2001:db8:1::1/128",
            action="blackhole",
            priority=40252,
            ipv6=True,
        )
        assert _matching_rules(
            ip_from="2001:db8:1::2/128",
            action="unreachable",
            priority=40253,
            ipv6=True,
        )
        assert _matching_rules(
            ip_from="2001:db8:1::3/128",
            action="prohibit",
            priority=40254,
            ipv6=True,
        )
    finally:
        nipart.apply(
            _rule_state(
                _rule_entry(state="absent", ip_from="2001:db8:1::1/128"),
                _rule_entry(state="absent", ip_from="2001:db8:1::2/128"),
                _rule_entry(state="absent", ip_from="2001:db8:1::3/128"),
            )
        )


def test_delete_route_rule_and_interface():
    nipart.apply(load_yaml(f"""---
interfaces:
  - name: {IIF_IFACE}
    type: dummy
    state: up
route-rules:
  config:
    - ip-from: {RULE_IP_FROM}
      route-table: {TEST_TABLE_ID}
      priority: 40295
"""))
    try:
        assert _matching_rules(
            ip_from=RULE_IP_FROM,
            table_id=TEST_TABLE_ID,
            priority=40295,
        )
        nipart.apply(load_yaml(f"""---
interfaces:
  - name: {IIF_IFACE}
    type: dummy
    state: absent
route-rules:
  config:
    - state: absent
      ip-from: {RULE_IP_FROM}
      route-table: {TEST_TABLE_ID}
"""))
        assert not _matching_rules(
            ip_from=RULE_IP_FROM,
            table_id=TEST_TABLE_ID,
            priority=40295,
        )
        rc, _, _ = exec_cmd(["ip", "link", "show", IIF_IFACE], check=False)
        assert rc != 0
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))
        nipart.apply(load_yaml(f"""---
interfaces:
  - name: {IIF_IFACE}
    type: dummy
    state: absent
"""))


def test_route_rule_suppress_prefix_length():
    rules = [
        _rule_entry(
            ip_from=RULE_IP_FROM,
            route_table=TEST_TABLE_ID,
            priority=40260,
            suppress_prefix_length=1,
        ),
        _rule_entry(
            ip_from=RULE_IP_FROM_V6,
            route_table=TEST_TABLE_ID,
            priority=40261,
            suppress_prefix_length=0,
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        assert _matching_rules(
            ip_from=RULE_IP_FROM,
            table_id=TEST_TABLE_ID,
            priority=40260,
            suppress_prefix_length=1,
        )
        assert _matching_rules(
            ip_from=RULE_IP_FROM_V6,
            table_id=TEST_TABLE_ID,
            priority=40261,
            suppress_prefix_length=0,
            ipv6=True,
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_append_route_rule_preserves_existing():
    first_rule = _rule_entry(
        ip_from=RULE_IP_FROM, route_table=TEST_TABLE_ID, priority=40270
    )
    second_rule = _rule_entry(
        ip_to=RULE_IP_TO, route_table=TEST_TABLE_ID, priority=40271
    )
    nipart.apply(_rule_state(first_rule))
    nipart.apply(_rule_state(second_rule))
    try:
        assert _matching_rules(
            ip_from=RULE_IP_FROM,
            table_id=TEST_TABLE_ID,
            priority=40270,
        )
        assert _matching_rules(
            ip_to=RULE_IP_TO,
            table_id=TEST_TABLE_ID,
            priority=40271,
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_route_rule_same_route_table_on_both_ip_stacks():
    rules = [
        _rule_entry(
            ip_from=RULE_IP_FROM, route_table=TEST_TABLE_ID, priority=40280
        ),
        _rule_entry(
            ip_from=RULE_IP_FROM_V6,
            route_table=TEST_TABLE_ID,
            priority=40281,
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        assert _matching_rules(
            ip_from=RULE_IP_FROM,
            table_id=TEST_TABLE_ID,
            priority=40280,
        )
        assert _matching_rules(
            ip_from=RULE_IP_FROM_V6,
            table_id=TEST_TABLE_ID,
            priority=40281,
            ipv6=True,
        )
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_absent_route_rule_with_empty_ip_from_to():
    rules = [
        _rule_entry(
            ip_from=RULE_IP_FROM_V6,
            route_table=TEST_TABLE_ID,
            priority=40290,
        ),
        _rule_entry(
            ip_to=RULE_IP_TO,
            route_table=TEST_TABLE_ID,
            priority=40291,
        ),
    ]
    nipart.apply(_rule_state(*rules))
    try:
        nipart.apply(
            _rule_state(
                _rule_entry(
                    state="absent",
                    ip_from="",
                    route_table=TEST_TABLE_ID,
                ),
                _rule_entry(
                    state="absent",
                    ip_to="",
                    route_table=TEST_TABLE_ID,
                ),
            )
        )
        assert not _matching_rules(table_id=TEST_TABLE_ID)
        assert not _matching_rules(table_id=TEST_TABLE_ID, ipv6=True)
    finally:
        nipart.apply(_absent_table_state(TEST_TABLE_ID))


def test_route_rule_without_from_to_or_family_is_rejected():
    with pytest.raises(nipart.NipartValueError):
        nipart.apply(_rule_state(_rule_entry(route_table=TEST_TABLE_ID)))


def test_route_rule_persisted_in_saved_state():
    desired_state = load_yaml(_route_rule_state(RULE_IP_FROM, RULE_IP_TO))
    nipart.apply(desired_state)
    try:
        saved_state = nipart.NipartClient().query_network_state(
            nipart.NipartQueryOption.saved()
        )
        rules = saved_state.get("route-rules", {}).get("config", [])
        assert any(
            rule.get("ip-from") == RULE_IP_FROM
            and rule.get("route-table") == RULE_TABLE_ID
            for rule in rules
        ), rules
    finally:
        nipart.apply(
            load_yaml(_absent_route_rule_state(RULE_IP_FROM, RULE_IP_TO))
        )


def test_route_rule_restored_after_daemon_restart():
    desired_state = load_yaml(_route_rule_state(RULE_IP_FROM, RULE_IP_TO))
    nipart.apply(desired_state)
    try:
        stop_daemon()
        start_daemon()
        assert _ip_rule_exists(RULE_IP_FROM, RULE_IP_TO), _ip_rule_output()
    finally:
        nipart.apply(
            load_yaml(_absent_route_rule_state(RULE_IP_FROM, RULE_IP_TO))
        )
