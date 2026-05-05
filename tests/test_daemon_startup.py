"""Daemon-startup smoke tests.

The unit tests in `test_rules_allowlist.py` call rule functions directly and
miss main-loop behavior — config parsing, baseline loading, the call sites in
`run_poll` that wire `cfg.egress_allowlist` and `cfg.egress_ip_allowlist`
through to the rule functions, and the suppression logic during warmup.

If a future refactor introduces a TypeError (positional/keyword arg mismatch),
NameError, or similar at a `run_poll` call site, the rule-level unit tests
will still pass but the daemon will silently die or hang on the first poll.
These tests catch that class of bug by spawning the daemon as a subprocess and
asserting it survives long enough to emit the expected log markers.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

NETMON_DIR = Path(__file__).resolve().parent.parent
NETMON_PY = NETMON_DIR / "netmon.py"


def _spawn_daemon(env_overrides: dict[str, str] | None = None) -> subprocess.Popen:
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    # -u keeps stderr unbuffered so we can read log lines as they're emitted.
    return subprocess.Popen(
        [sys.executable, "-u", str(NETMON_PY)],
        cwd=str(NETMON_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1,
    )


def _read_stderr_with_timeout(proc: subprocess.Popen, deadline: float) -> str:
    """Drain whatever stderr is available before the deadline without blocking forever."""
    chunks: list[str] = []
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            # Process exited — read whatever is left.
            remaining = proc.stderr.read() if proc.stderr else ""
            if remaining:
                chunks.append(remaining)
            break
        try:
            # On Windows there is no select() for pipes; fall back to a short
            # timed readline by polling. readline is blocking but bounded by
            # how fast the daemon emits — vigil emits something within the
            # first poll cycle (~5s), so this terminates quickly in practice.
            line = proc.stderr.readline() if proc.stderr else ""
        except Exception:
            break
        if line:
            chunks.append(line)
        # If we have at least the startup banner, return early.
        if any("vigil starting" in c for c in chunks) and len(chunks) >= 2:
            break
    return "".join(chunks)


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        try:
            if sys.platform == "win32":
                proc.terminate()
            else:
                proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)
    # Drain pipes so the OS can release them.
    try:
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
    except Exception:
        pass


def test_daemon_starts_and_emits_banner() -> None:
    """Daemon must start, load config + baseline (or no-baseline), and log
    the 'vigil starting' banner without raising."""
    proc = _spawn_daemon()
    try:
        deadline = time.monotonic() + 15
        out = _read_stderr_with_timeout(proc, deadline)
        assert proc.poll() is None, (
            f"daemon exited prematurely with code {proc.returncode}; stderr:\n{out}"
        )
        assert "vigil starting" in out, (
            f"expected startup banner in stderr; got:\n{out}"
        )
    finally:
        _terminate(proc)


def test_daemon_completes_multiple_polls_without_crash() -> None:
    """Daemon must survive 3 poll cycles. Catches arg-mismatch / type errors
    at rule call sites that the unit-test layer cannot reach.

    Sets POLL_INTERVAL=1 and WARMUP_POLLS=1 so 3 polls fit in the timeout.
    """
    proc = _spawn_daemon(env_overrides={
        "POLL_INTERVAL": "1",
        "WARMUP_POLLS": "1",
        # Disable side-channel alert paths so the test is hermetic.
        "DISCORD_WEBHOOK_URL": "",
        "TOAST_ENABLED": "false",
    })
    try:
        # Wait long enough for ~5 polls at 1s each, plus startup overhead.
        time.sleep(8)
        assert proc.poll() is None, (
            f"daemon exited mid-loop with code {proc.returncode}; "
            f"stderr:\n{(proc.stderr.read() if proc.stderr else '')}"
        )
    finally:
        _terminate(proc)


def test_daemon_survives_with_empty_ip_allowlist() -> None:
    """Empty EGRESS_IP_ALLOWLIST must parse to () and not crash run_poll on
    the call site that passes it to check_baseline_ip_deviation."""
    proc = _spawn_daemon(env_overrides={
        "POLL_INTERVAL": "1",
        "WARMUP_POLLS": "1",
        "EGRESS_IP_ALLOWLIST": "",  # the empty-string edge case
        "DISCORD_WEBHOOK_URL": "",
        "TOAST_ENABLED": "false",
    })
    try:
        time.sleep(5)
        assert proc.poll() is None, (
            f"daemon crashed with empty EGRESS_IP_ALLOWLIST; code={proc.returncode}; "
            f"stderr:\n{(proc.stderr.read() if proc.stderr else '')}"
        )
    finally:
        _terminate(proc)
