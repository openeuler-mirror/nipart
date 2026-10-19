# SPDX-License-Identifier: Apache-2.0

import pytest

import nipart

from nipart import NipartValueError

from .testlib.cmdlib import exec_cmd
from .testlib.retry import retry_till_true_or_timeout
from .testlib.statelib import load_yaml
from .testlib.statelib import show_only

TEST_BASE_NIC = "npt-msd0"
TEST_MACSEC_NIC = "npt-ms0"
TEST_MACSEC_NO_MKA_NIC = "npt-ms1"
TEST_INVALID_MACSEC_NIC = "npt-ms2"
TEST_MKA_A_BASE = "npt-mka-veth0"
TEST_MKA_B_BASE = "npt-mka-veth1"
TEST_MKA_A_NIC = "npt-mka0"
TEST_MKA_B_NIC = "npt-mka1"

MKA_CAK = "50b71a8ef0bd5751ea76de6d6c98c03a"
MKA_CKN = "f2b4297d39da7330910a74abc0449feb45b5c0b9fc23df1430e1898fcf1c4550"


@pytest.fixture
def macsec_over_dummy():
    nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_BASE_NIC}
                type: dummy
                state: up
              - name: {TEST_MACSEC_NIC}
                type: macsec
                state: up
                macsec:
                  base-iface: {TEST_BASE_NIC}
                  encrypt: true
                  port: 1
                  validation: strict
                  send-sci: true
                  offload: "off"
                  mka-cak: {MKA_CAK}
                  mka-ckn: {MKA_CKN}
            """))
    yield
    nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_MACSEC_NIC}
                type: macsec
                state: absent
              - name: {TEST_BASE_NIC}
                type: dummy
                state: absent
            """))


def test_create_macsec(macsec_over_dummy):
    iface = show_only(TEST_MACSEC_NIC)
    assert iface["type"] == "macsec"
    assert iface["macsec"]["base-iface"] == TEST_BASE_NIC
    assert iface["macsec"]["encrypt"] is True
    assert iface["macsec"]["port"] == 1
    assert iface["macsec"]["validation"] == "strict"
    assert iface["macsec"]["send-sci"] is True
    assert iface["macsec"]["offload"] == "off"


def test_modify_macsec(macsec_over_dummy):
    nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_MACSEC_NIC}
                type: macsec
                state: up
                macsec:
                  base-iface: {TEST_BASE_NIC}
                  encrypt: false
                  validation: check
                  send-sci: false
            """))
    iface = show_only(TEST_MACSEC_NIC)
    assert iface["macsec"]["encrypt"] is False
    assert iface["macsec"]["validation"] == "check"
    assert iface["macsec"]["send-sci"] is False


def test_create_macsec_with_sci(macsec_over_dummy):
    try:
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_MACSEC_NO_MKA_NIC}
                    type: macsec
                    state: up
                    macsec:
                      base-iface: {TEST_BASE_NIC}
                      sci: 0x3e042ef52d910007
                """))
        iface = show_only(TEST_MACSEC_NO_MKA_NIC)
        assert iface["macsec"]["sci"] == "3e042ef52d910007"
        assert iface["macsec"]["port"] == 7
    finally:
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_MACSEC_NO_MKA_NIC}
                    type: macsec
                    state: absent
                """))


@pytest.fixture
def macsec_mka_pair():
    nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_MKA_A_BASE}
                type: veth
                state: up
                veth:
                  peer: {TEST_MKA_B_BASE}
              - name: {TEST_MKA_A_NIC}
                type: macsec
                state: up
                ipv4:
                  enabled: true
                  address:
                    - ip: 192.0.2.1
                      prefix-length: 24
                macsec:
                  base-iface: {TEST_MKA_A_BASE}
                  encrypt: true
                  port: 1
                  mka-cak: {MKA_CAK}
                  mka-ckn: {MKA_CKN}
              - name: {TEST_MKA_B_NIC}
                type: macsec
                state: up
                ipv4:
                  enabled: true
                  address:
                    - ip: 192.0.2.2
                      prefix-length: 24
                macsec:
                  base-iface: {TEST_MKA_B_BASE}
                  encrypt: true
                  port: 1
                  mka-cak: {MKA_CAK}
                  mka-ckn: {MKA_CKN}
            """))
    yield
    nipart.apply(load_yaml(f"""---
            interfaces:
              - name: {TEST_MKA_A_NIC}
                type: macsec
                state: absent
              - name: {TEST_MKA_B_NIC}
                type: macsec
                state: absent
              - name: {TEST_MKA_A_BASE}
                type: veth
                state: absent
              - name: {TEST_MKA_B_BASE}
                type: veth
                state: absent
            """))


def test_mka_secure_link(macsec_mka_pair):
    def ping_peer():
        rc, _, _ = exec_cmd(
            ["ping", "-c", "1", "-W", "1", "192.0.2.2"], check=False
        )
        return rc == 0

    assert retry_till_true_or_timeout(20, ping_peer)


def test_invalid_mka_key(macsec_over_dummy):
    with pytest.raises(NipartValueError):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_INVALID_MACSEC_NIC}
                    type: macsec
                    state: up
                    macsec:
                      base-iface: {TEST_BASE_NIC}
                      mka-cak: {MKA_CAK}
                """))


def test_invalid_mka_hex(macsec_over_dummy):
    with pytest.raises(NipartValueError):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_INVALID_MACSEC_NIC}
                    type: macsec
                    state: up
                    macsec:
                      base-iface: {TEST_BASE_NIC}
                      mka-cak: zzb71a8ef0bd5751ea76de6d6c98c03a
                      mka-ckn: {MKA_CKN}
                """))


def test_mka_requires_port_one(macsec_over_dummy):
    with pytest.raises(NipartValueError):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_INVALID_MACSEC_NIC}
                    type: macsec
                    state: up
                    macsec:
                      base-iface: {TEST_BASE_NIC}
                      port: 0
                      mka-cak: {MKA_CAK}
                      mka-ckn: {MKA_CKN}
                """))


def test_mka_rejects_explicit_sci(macsec_over_dummy):
    with pytest.raises(NipartValueError):
        nipart.apply(load_yaml(f"""---
                interfaces:
                  - name: {TEST_INVALID_MACSEC_NIC}
                    type: macsec
                    state: up
                    macsec:
                      base-iface: {TEST_BASE_NIC}
                      sci: 0x3e042ef52d910001
                      mka-cak: {MKA_CAK}
                      mka-ckn: {MKA_CKN}
                """))
