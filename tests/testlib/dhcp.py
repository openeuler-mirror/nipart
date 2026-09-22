# SPDX-License-Identifier: Apache-2.0

import os
import signal

from .cmdlib import exec_cmd

DHCP_SRV_IP4_PREFIX = "192.0.2"
DHCP_SRV_IP4 = f"{DHCP_SRV_IP4_PREFIX}.1"

IPV4_CLASSLESS_ROUTE_DST_NET1 = "198.51.100.0/24"
IPV4_CLASSLESS_ROUTE_NEXT_HOP1 = "192.0.2.1"

DNSMASQ_CONF_PATH = "/tmp/nipart_test_dnsmasq.conf"
DNSMASQ_PID_PATH = "/tmp/nipart_test_dnsmasq.pid"

DHCP_SRV_NIC = "dhcp_srv"


def start_dhcp_server(
    net_ns, lease_time="48h", renewal_time=None, rebinding_time=None
):
    exec_cmd(
        f"ip netns exec {net_ns} "
        f"ip addr replace {DHCP_SRV_IP4}/24 dev {DHCP_SRV_NIC}".split()
    )
    extra_options = ""
    if renewal_time is not None:
        extra_options += f"dhcp-option-force=58,{renewal_time}\n"
    if rebinding_time is not None:
        extra_options += f"dhcp-option-force=59,{rebinding_time}\n"
    dnsmasq_conf = """
    leasefile-ro
    interface={iface}
    dhcp-range={ipv4_prefix}.200,{ipv4_prefix}.250,255.255.255.0,{lease_time}
    dhcp-option=option:classless-static-route,{classless_rt},{classless_rt_dst}
    dhcp-option=option:dns-server,{v4_dns_server}
    {extra_options}
    """.format(
        **{
            "iface": DHCP_SRV_NIC,
            "ipv4_prefix": DHCP_SRV_IP4_PREFIX,
            "classless_rt": IPV4_CLASSLESS_ROUTE_DST_NET1,
            "classless_rt_dst": IPV4_CLASSLESS_ROUTE_NEXT_HOP1,
            "v4_dns_server": DHCP_SRV_IP4,
            "lease_time": lease_time,
            "extra_options": extra_options,
        }
    )
    with open(DNSMASQ_CONF_PATH, "w") as fd:
        fd.write(dnsmasq_conf)

    exec_cmd(
        f"sudo ip netns exec {net_ns} dnsmasq "
        f"--interface={DHCP_SRV_NIC} --log-dhcp --pid-file={DNSMASQ_PID_PATH} "
        f"--conf-file={DNSMASQ_CONF_PATH} ".split()
    )


def stop_dhcp_server():
    if not os.path.exists(DNSMASQ_PID_PATH):
        return
    with open(DNSMASQ_PID_PATH, "r") as fd:
        try:
            os.kill(int(fd.read()), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            # The dnsmasq process already exited (or the pid file is
            # stale from an aborted run); nothing left to stop.
            pass
