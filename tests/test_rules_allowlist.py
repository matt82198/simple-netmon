"""Tests for process + IP allowlist coverage across baseline rules.

Covers the extension of `egress_allowlist` to short-circuit
`check_baseline_ip_deviation`, `check_baseline_volume_spike`, and
`check_short_lived_egress`, plus the new `EGRESS_IP_ALLOWLIST` config
key parsed as `ipaddress.ip_network` objects.
"""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from baseline import Baseline, ProcessProfile
from config import load_config
from rules import (
    ConnRecord,
    ExitRecord,
    check_baseline_ip_deviation,
    check_baseline_volume_spike,
    check_ioc_ip,
    check_short_lived_egress,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _conn(
    pid: int = 1234,
    proc_name: str = "evil.exe",
    raddr_ip: str = "8.8.8.8",
    raddr_port: int = 443,
    laddr_ip: str = "192.168.1.10",
    laddr_port: int = 50000,
    status: str = "ESTABLISHED",
) -> ConnRecord:
    return ConnRecord(
        pid=pid,
        proc_name=proc_name,
        laddr=(laddr_ip, laddr_port),
        raddr=(raddr_ip, raddr_port),
        status=status,
        first_seen=datetime.now(),
    )


def _exit(
    pid: int = 1234,
    proc_name: str = "evil.exe",
    lived_secs: float = 5.0,
) -> ExitRecord:
    first_seen = datetime.now() - timedelta(seconds=lived_secs)
    return ExitRecord(
        pid=pid,
        proc_name=proc_name,
        laddr=("192.168.1.10", 50000),
        raddr=("8.8.8.8", 443),
        first_seen=first_seen,
        exit_time=datetime.now(),
    )


def _baseline_with(name: str, ips: list[str], ports: list[int], max_concurrent: int) -> Baseline:
    return Baseline(
        trained_at="2026-04-01T00:00:00",
        training_duration_secs=3600,
        total_polls=720,
        processes={
            name: ProcessProfile(
                remote_ips=sorted(ips),
                remote_ports=sorted(ports),
                max_concurrent=max_concurrent,
                poll_appearances=720,
            ),
        },
    )


# ── process-allowlist coverage ────────────────────────────────────────────────

class TestProcessAllowlistOnIpDeviation:
    def test_allowlisted_process_does_not_fire_ip_deviation(self) -> None:
        baseline = _baseline_with("some.exe", ips=["1.2.3.4"], ports=[443], max_concurrent=4)
        # remote IP 8.8.8.8 is NOT in baseline → would normally fire
        conns = [_conn(proc_name="some.exe", raddr_ip="8.8.8.8")]
        allowlist = frozenset({"some.exe"})
        already: set[tuple[str, str]] = set()

        alerts = check_baseline_ip_deviation(
            conns, baseline, cdn_threshold=50, already_alerted=already,
            egress_allowlist=allowlist,
        )

        assert alerts == []

    def test_non_allowlisted_process_still_fires_ip_deviation(self) -> None:
        baseline = _baseline_with("evil.exe", ips=["1.2.3.4"], ports=[443], max_concurrent=4)
        conns = [_conn(proc_name="evil.exe", raddr_ip="8.8.8.8")]
        already: set[tuple[str, str]] = set()

        alerts = check_baseline_ip_deviation(
            conns, baseline, cdn_threshold=50, already_alerted=already,
            egress_allowlist=frozenset(),
        )

        assert len(alerts) == 1
        assert alerts[0].rule == "BASELINE_IP_DEVIATION"
        assert alerts[0].proc_name == "evil.exe"

    def test_allowlist_match_is_case_insensitive(self) -> None:
        baseline = _baseline_with("Some.EXE", ips=["1.2.3.4"], ports=[443], max_concurrent=4)
        conns = [_conn(proc_name="Some.EXE", raddr_ip="8.8.8.8")]
        allowlist = frozenset({"some.exe"})
        already: set[tuple[str, str]] = set()

        alerts = check_baseline_ip_deviation(
            conns, baseline, cdn_threshold=50, already_alerted=already,
            egress_allowlist=allowlist,
        )

        assert alerts == []


class TestProcessAllowlistOnVolumeSpike:
    def test_allowlisted_process_does_not_fire_volume_spike(self) -> None:
        # max_concurrent=2 → spike threshold is 2*1.5 = 3 → 5 conns would fire.
        baseline = _baseline_with("some.exe", ips=["1.2.3.4"], ports=[443], max_concurrent=2)
        conns = [
            _conn(pid=100 + i, proc_name="some.exe", laddr_port=50000 + i)
            for i in range(5)
        ]
        allowlist = frozenset({"some.exe"})

        alerts = check_baseline_volume_spike(conns, baseline, egress_allowlist=allowlist)

        assert alerts == []

    def test_non_allowlisted_process_still_fires_volume_spike(self) -> None:
        baseline = _baseline_with("evil.exe", ips=["1.2.3.4"], ports=[443], max_concurrent=2)
        conns = [
            _conn(pid=100 + i, proc_name="evil.exe", laddr_port=50000 + i)
            for i in range(5)
        ]

        alerts = check_baseline_volume_spike(conns, baseline, egress_allowlist=frozenset())

        assert len(alerts) == 1
        assert alerts[0].rule == "BASELINE_VOLUME_SPIKE"


class TestProcessAllowlistOnShortLived:
    def test_allowlisted_process_does_not_fire_short_lived(self) -> None:
        # exited at 5s, threshold 30s → would normally fire.
        exits = [_exit(proc_name="some.exe", lived_secs=5.0)]
        allowlist = frozenset({"some.exe"})
        already: set[int] = set()

        alerts = check_short_lived_egress(
            exits, threshold_secs=30, already_alerted=already,
            egress_allowlist=allowlist,
        )

        assert alerts == []

    def test_non_allowlisted_process_still_fires_short_lived(self) -> None:
        exits = [_exit(proc_name="evil.exe", lived_secs=5.0)]
        already: set[int] = set()

        alerts = check_short_lived_egress(
            exits, threshold_secs=30, already_alerted=already,
            egress_allowlist=frozenset(),
        )

        assert len(alerts) == 1
        assert alerts[0].rule == "SHORT_LIVED_EGRESS"


# ── IP allowlist (CIDR) ───────────────────────────────────────────────────────

class TestIpAllowlistConfigParsing:
    def _write_env(self, tmp_path: Path, body: str) -> Path:
        env_path = tmp_path / "config.env"
        env_path.write_text(body, encoding="utf-8")
        return env_path

    def _clear_env_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # dotenv won't override already-set env vars; clear potentially-set keys.
        for key in (
            "EGRESS_IP_ALLOWLIST",
            "EGRESS_ALLOWLIST",
            "IOC_IPS",
            "BASELINE_PATH",
            "DISCORD_WEBHOOK_URL",
        ):
            monkeypatch.delenv(key, raising=False)

    def test_parses_mixed_cidr_and_individual_ips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._clear_env_keys(monkeypatch)
        env_path = self._write_env(
            tmp_path,
            # Use RFC 5737 documentation IPs (192.0.2.x) — never real hosts.
            "EGRESS_IP_ALLOWLIST=10.0.0.0/24,2603:1063::/32,192.0.2.1\n",
        )

        cfg = load_config(env_path)

        nets = list(cfg.egress_ip_allowlist)
        assert ipaddress.ip_network("10.0.0.0/24") in nets
        assert ipaddress.ip_network("2603:1063::/32") in nets
        # Bare IP becomes /32 host network.
        assert ipaddress.ip_network("192.0.2.1/32") in nets
        assert len(nets) == 3

    def test_empty_value_parses_to_empty_collection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._clear_env_keys(monkeypatch)
        env_path = self._write_env(tmp_path, "EGRESS_IP_ALLOWLIST=\n")

        cfg = load_config(env_path)

        assert list(cfg.egress_ip_allowlist) == []

    def test_missing_key_parses_to_empty_collection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._clear_env_keys(monkeypatch)
        env_path = self._write_env(tmp_path, "# nothing here\n")

        cfg = load_config(env_path)

        assert list(cfg.egress_ip_allowlist) == []

    def test_whitespace_and_blank_entries_are_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._clear_env_keys(monkeypatch)
        env_path = self._write_env(
            tmp_path,
            "EGRESS_IP_ALLOWLIST= 10.0.0.0/24 , , 192.168.1.0/24 \n",
        )

        cfg = load_config(env_path)

        nets = list(cfg.egress_ip_allowlist)
        assert ipaddress.ip_network("10.0.0.0/24") in nets
        assert ipaddress.ip_network("192.168.1.0/24") in nets
        assert len(nets) == 2


class TestIpAllowlistOnIpDeviation:
    def test_ip_inside_allowlisted_cidr_does_not_fire_ip_deviation(self) -> None:
        baseline = _baseline_with("evil.exe", ips=["1.2.3.4"], ports=[443], max_concurrent=4)
        # 10.20.30.40 is not in baseline, but is inside the allowlisted /24.
        conns = [_conn(proc_name="evil.exe", raddr_ip="10.20.30.40")]
        allowlist_nets = (ipaddress.ip_network("10.20.30.0/24"),)
        already: set[tuple[str, str]] = set()

        alerts = check_baseline_ip_deviation(
            conns, baseline, cdn_threshold=50, already_alerted=already,
            egress_allowlist=frozenset(),
            ip_allowlist=allowlist_nets,
        )

        assert alerts == []

    def test_individual_ip_in_allowlist_does_not_fire(self) -> None:
        baseline = _baseline_with("evil.exe", ips=["1.2.3.4"], ports=[443], max_concurrent=4)
        # Use RFC 5737 documentation IP as a test example.
        conns = [_conn(proc_name="evil.exe", raddr_ip="192.0.2.1")]
        allowlist_nets = (ipaddress.ip_network("192.0.2.1/32"),)
        already: set[tuple[str, str]] = set()

        alerts = check_baseline_ip_deviation(
            conns, baseline, cdn_threshold=50, already_alerted=already,
            egress_allowlist=frozenset(),
            ip_allowlist=allowlist_nets,
        )

        assert alerts == []

    def test_ip_outside_allowlist_still_fires(self) -> None:
        baseline = _baseline_with("evil.exe", ips=["1.2.3.4"], ports=[443], max_concurrent=4)
        conns = [_conn(proc_name="evil.exe", raddr_ip="8.8.8.8")]
        allowlist_nets = (ipaddress.ip_network("10.20.30.0/24"),)
        already: set[tuple[str, str]] = set()

        alerts = check_baseline_ip_deviation(
            conns, baseline, cdn_threshold=50, already_alerted=already,
            egress_allowlist=frozenset(),
            ip_allowlist=allowlist_nets,
        )

        assert len(alerts) == 1
        assert alerts[0].rule == "BASELINE_IP_DEVIATION"


class TestIpAllowlistDoesNotMaskIocs:
    def test_ioc_match_still_fires_when_ip_is_egress_allowlisted(self) -> None:
        # Same IP appears in BOTH lists. IOC must win — these lists are independent.
        # check_ioc_ip is intentionally NOT given an ip_allowlist parameter.
        # Using RFC 5737 documentation IP as example.
        ioc_ip = "192.0.2.1"
        conns = [_conn(proc_name="curl.exe", raddr_ip=ioc_ip)]
        already_ioc: set[tuple[int, str]] = set()

        ioc_alerts = check_ioc_ip(conns, frozenset({ioc_ip}), already_ioc)

        assert len(ioc_alerts) == 1
        assert ioc_alerts[0].rule == "IOC_IP_MATCH"
        assert ioc_ip in ioc_alerts[0].dst
