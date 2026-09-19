# SPDX-License-Identifier: Apache-2.0

import os
import shutil
import pathlib
import subprocess
import sys
import time

import pytest

from .testlib.cmdlib import exec_cmd
from .testlib.retry import retry_till_true_or_timeout

project_dir = pathlib.Path(__file__).parent.parent.resolve()
sys.path.insert(0, f"{project_dir}/src/python")

from nipart import NipartClient  # noqa: E402

DAEMON_LOG = "/tmp/nipart_test_daemon.log"
CLI_PATH = f"{project_dir}/target/debug/npt"
DAEMON_PID_FILE = "/var/run/nipart/nipart.pid"
DAEMON_BIN_PATH = f"{project_dir}/target/debug/nipart"
# The daemon answers IPC requests while `load_saved_state()` still runs in
# a background task.  That boot pass pauses the interface monitor, so a
# test starting right after `start_daemon()` could miss live link events
# and race with the boot apply.  Wait for the boot pass to finish before
# handing the daemon over to tests.
DAEMON_BOOT_DONE_MARKS = (
    "Saved state load finished",
    "Failed to load saved state:",
)
DAEMON_BOOT_TIMEOUT = 60


@pytest.fixture(scope="session", autouse=True)
def test_env_setup(backup_config, run_daemon):
    yield


@pytest.fixture(scope="session")
def backup_config():
    if os.path.isdir("/etc/nipart.before_test"):
        shutil.rmtree("/etc/nipart.before_test")
    if os.path.isdir("/etc/nipart"):
        os.rename("/etc/nipart", "/etc/nipart.before_test")
    yield
    if os.path.isdir("/etc/nipart") and os.path.isdir(
        "/etc/nipart.before_test"
    ):
        shutil.rmtree("/etc/nipart")
        os.rename("/etc/nipart.before_test", "/etc/nipart")


@pytest.fixture(scope="session")
def run_daemon():
    subprocess.Popen(
        DAEMON_BIN_PATH,
        stdout=sys.stdout,
        stderr=open(DAEMON_LOG, "w"),
        start_new_session=True,
    )
    time.sleep(1)
    retry_till_true_or_timeout(30, check_daemon_connection)
    _wait_daemon_boot_done(0)
    yield
    # Stop the actual current daemon (which `restart_daemon` may have
    # restarted), otherwise the last restarted daemon would survive the
    # session and keep its plugin children alive.
    stop_daemon()


def check_daemon_connection():
    try:
        client = NipartClient()
        return client.ping() == "pong"
    except Exception:
        return False


def daemon_ping():
    rc, out, _ = exec_cmd([CLI_PATH, "ping"], check=False)
    return rc == 0 and "pong" in out


def _wait_daemon_stopped():
    for _ in range(20):
        if not daemon_ping():
            return
        time.sleep(0.5)


def _wait_daemon_ready():
    for _ in range(40):
        if daemon_ping():
            break
        time.sleep(1)
    else:
        raise RuntimeError("Daemon did not become ready in time")


def _daemon_log_size():
    try:
        return os.path.getsize(DAEMON_LOG)
    except FileNotFoundError:
        return 0


def _boot_done_since(pos):
    try:
        with open(DAEMON_LOG) as log_f:
            log_f.seek(pos)
            log = log_f.read()
    except FileNotFoundError:
        return False
    return any(mark in log for mark in DAEMON_BOOT_DONE_MARKS)


def _wait_daemon_boot_done(log_pos):
    if not retry_till_true_or_timeout(
        DAEMON_BOOT_TIMEOUT, _boot_done_since, log_pos
    ):
        raise RuntimeError("Daemon did not finish loading saved state")


def start_daemon():
    # Detach the daemon from pytest's stdio: a restarted daemon that
    # inherits pytest's capture streams dies of SIGPIPE when pytest
    # closes them at the end of the session (the socket would then
    # disappear and later tests could no longer connect).
    log_pos = _daemon_log_size()
    subprocess.Popen(
        [DAEMON_BIN_PATH],
        stdout=open(DAEMON_LOG, "a"),
        stderr=open(DAEMON_LOG, "a"),
        start_new_session=True,
    )
    _wait_daemon_ready()
    _wait_daemon_boot_done(log_pos)


def stop_daemon():
    if os.path.exists(DAEMON_PID_FILE):
        with open(DAEMON_PID_FILE) as f:
            pid = f.read().strip()
        if pid:
            exec_cmd(["kill", "-TERM", pid], check=False)
            _wait_daemon_exited(pid)
            return
    _wait_daemon_stopped()


def _wait_daemon_exited(pid):
    for _ in range(40):
        try:
            # The daemon is our child (spawned via subprocess.Popen), so
            # waitpid reaps it once it exits; kill(pid, 0) alone would treat
            # an unreaped zombie as "still running" and stall the timeout.
            wpid, _ = os.waitpid(int(pid), os.WNOHANG)
        except ChildProcessError:
            # Not our child (e.g. leftover from an earlier run).
            try:
                os.kill(int(pid), 0)
            except ProcessLookupError:
                return
        else:
            if wpid == pid:
                return
        time.sleep(0.5)
    exec_cmd(["kill", "-KILL", pid], check=False)
    _wait_daemon_stopped()


@pytest.fixture
def restart_daemon():
    stop_daemon()
    start_daemon()
    yield
    stop_daemon()
    start_daemon()


REPORT_HEADER = """OS: {osname}
Kernel: {kernel_ver}
"""


def _get_osname():
    with open("/etc/os-release") as os_release:
        for line in os_release.readlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", maxsplit=1)[1].strip().strip('"')
    return ""


def _get_kernel_ver():
    return exec_cmd("uname -r".split())[1]


def pytest_report_header(config):
    return REPORT_HEADER.format(
        osname=_get_osname(),
        kernel_ver=_get_kernel_ver(),
    )
