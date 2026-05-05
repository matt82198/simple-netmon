"""Tests for OAuth-chaining detection rules + DomainCache.

Phase 1 of the vigil pivot from generic egress watcher to OAuth chaining
detector. Threat model: attacker compromises an OAuth-bearing client (e.g.
claude.ai), registers MCP connectors, and pivots into Google/MS/GitHub via
chained OAuth flows. These rules catch host-side indicators in flight.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest

from rules import (
    ConnRecord,
    check_mcp_connector_traffic,
    check_oauth_provider_chain,
    check_oauth_provider_contact,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _conn(
    pid: int = 1234,
    proc_name: str = "claude.exe",
    raddr_ip: str = "142.250.80.46",
    raddr_port: int = 443,
    laddr_ip: str = "192.168.1.10",
    laddr_port: int = 50000,
    status: str = "ESTABLISHED",
    domain: str | None = None,
    first_seen: datetime | None = None,
) -> ConnRecord:
    return ConnRecord(
        pid=pid,
        proc_name=proc_name,
        laddr=(laddr_ip, laddr_port),
        raddr=(raddr_ip, raddr_port),
        status=status,
        first_seen=first_seen or datetime.now(),
        domain=domain,
    )


_OAUTH_DOMAINS = frozenset({
    "accounts.google.com",
    "oauth2.googleapis.com",
    "login.microsoftonline.com",
    "login.live.com",
    "github.com",
    "slack.com",
    "api.notion.com",
    "api.atlassian.com",
})

_BROWSER_PROCS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "arc.exe", "zen.exe",
})

_MCP_PATTERNS = ("api.anthropic.com", "claude.ai")


# ── OAUTH_PROVIDER_CONTACT ────────────────────────────────────────────────────

class TestOAuthProviderContact:
    def test_non_browser_to_oauth_provider_fires(self) -> None:
        conns = [_conn(proc_name="claude.exe", domain="accounts.google.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
        )

        assert len(alerts) == 1
        assert alerts[0].rule == "OAUTH_PROVIDER_CONTACT"
        assert alerts[0].proc_name == "claude.exe"

    def test_browser_to_oauth_provider_does_not_fire(self) -> None:
        conns = [_conn(proc_name="chrome.exe", domain="accounts.google.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
        )

        assert alerts == []

    def test_browser_to_unrelated_domain_does_not_fire(self) -> None:
        conns = [_conn(proc_name="chrome.exe", domain="example.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
        )

        assert alerts == []

    def test_no_domain_does_not_fire(self) -> None:
        conns = [_conn(proc_name="claude.exe", domain=None)]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
        )

        assert alerts == []

    def test_dedupes_repeat_pid_domain(self) -> None:
        conns = [
            _conn(pid=42, proc_name="claude.exe", domain="accounts.google.com"),
            _conn(pid=42, proc_name="claude.exe", domain="accounts.google.com"),
        ]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
        )

        assert len(alerts) == 1

    def test_domain_match_is_case_insensitive(self) -> None:
        conns = [_conn(proc_name="claude.exe", domain="Accounts.Google.COM")]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
        )

        assert len(alerts) == 1

    def test_browser_match_is_case_insensitive(self) -> None:
        conns = [_conn(proc_name="Chrome.EXE", domain="accounts.google.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
        )

        assert alerts == []

    def test_empty_oauth_domains_no_fire(self) -> None:
        conns = [_conn(proc_name="claude.exe", domain="accounts.google.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, frozenset(), _BROWSER_PROCS, already,
        )

        assert alerts == []


# ── OAUTH_PROVIDER_CHAIN ──────────────────────────────────────────────────────

class TestOAuthProviderChain:
    def test_two_providers_in_window_fires_once(self) -> None:
        chain_state: dict[int, list[tuple[str, datetime]]] = {}
        already: set[int] = set()
        now = datetime.now()

        # First contact: accounts.google.com
        conns1 = [_conn(pid=99, proc_name="python.exe",
                        domain="accounts.google.com", first_seen=now)]
        alerts1 = check_oauth_provider_chain(
            conns1, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )
        assert alerts1 == []  # only 1 provider so far

        # Second contact: login.microsoftonline.com a moment later
        conns2 = [_conn(pid=99, proc_name="python.exe",
                        domain="login.microsoftonline.com",
                        first_seen=now + timedelta(seconds=2))]
        alerts2 = check_oauth_provider_chain(
            conns2, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )
        assert len(alerts2) == 1
        assert alerts2[0].rule == "OAUTH_PROVIDER_CHAIN"
        assert alerts2[0].pid == 99

    def test_same_provider_twice_does_not_fire(self) -> None:
        chain_state: dict[int, list[tuple[str, datetime]]] = {}
        already: set[int] = set()
        now = datetime.now()

        conns1 = [_conn(pid=99, proc_name="python.exe",
                        domain="accounts.google.com", first_seen=now)]
        check_oauth_provider_chain(
            conns1, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )

        conns2 = [_conn(pid=99, proc_name="python.exe",
                        domain="accounts.google.com",
                        first_seen=now + timedelta(seconds=5))]
        alerts = check_oauth_provider_chain(
            conns2, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )

        assert alerts == []

    def test_browser_chain_does_not_fire(self) -> None:
        chain_state: dict[int, list[tuple[str, datetime]]] = {}
        already: set[int] = set()
        now = datetime.now()

        conns = [
            _conn(pid=42, proc_name="chrome.exe",
                  domain="accounts.google.com", first_seen=now),
            _conn(pid=42, proc_name="chrome.exe",
                  domain="login.microsoftonline.com",
                  first_seen=now + timedelta(seconds=1)),
        ]
        alerts = check_oauth_provider_chain(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )

        assert alerts == []

    def test_outside_window_does_not_fire(self) -> None:
        chain_state: dict[int, list[tuple[str, datetime]]] = {}
        already: set[int] = set()
        now = datetime.now()

        conns1 = [_conn(pid=99, proc_name="python.exe",
                        domain="accounts.google.com", first_seen=now)]
        check_oauth_provider_chain(
            conns1, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=60, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )

        # 90 seconds later — outside the 60s window, first entry expires.
        conns2 = [_conn(pid=99, proc_name="python.exe",
                        domain="login.microsoftonline.com",
                        first_seen=now + timedelta(seconds=90))]
        alerts = check_oauth_provider_chain(
            conns2, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=60, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )

        assert alerts == []

    def test_no_refire_within_same_window(self) -> None:
        chain_state: dict[int, list[tuple[str, datetime]]] = {}
        already: set[int] = set()
        now = datetime.now()

        conns = [
            _conn(pid=99, proc_name="python.exe",
                  domain="accounts.google.com", first_seen=now),
            _conn(pid=99, proc_name="python.exe",
                  domain="login.microsoftonline.com",
                  first_seen=now + timedelta(seconds=1)),
        ]
        alerts1 = check_oauth_provider_chain(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )
        assert len(alerts1) == 1

        # Another poll: same pid, same providers still in window — must NOT re-fire.
        conns2 = [_conn(pid=99, proc_name="python.exe",
                        domain="github.com",
                        first_seen=now + timedelta(seconds=3))]
        alerts2 = check_oauth_provider_chain(
            conns2, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )
        assert alerts2 == []

    def test_below_threshold_does_not_fire(self) -> None:
        chain_state: dict[int, list[tuple[str, datetime]]] = {}
        already: set[int] = set()
        now = datetime.now()

        conns = [_conn(pid=99, proc_name="python.exe",
                       domain="accounts.google.com", first_seen=now)]
        alerts = check_oauth_provider_chain(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=3,
            chain_state=chain_state, already_alerted=already,
        )

        assert alerts == []

    def test_three_providers_with_threshold_3_fires(self) -> None:
        chain_state: dict[int, list[tuple[str, datetime]]] = {}
        already: set[int] = set()
        now = datetime.now()

        conns = [
            _conn(pid=99, proc_name="python.exe",
                  domain="accounts.google.com", first_seen=now),
            _conn(pid=99, proc_name="python.exe",
                  domain="login.microsoftonline.com",
                  first_seen=now + timedelta(seconds=1)),
            _conn(pid=99, proc_name="python.exe",
                  domain="github.com",
                  first_seen=now + timedelta(seconds=2)),
        ]
        alerts = check_oauth_provider_chain(
            conns, _OAUTH_DOMAINS, _BROWSER_PROCS,
            window_secs=30, threshold=3,
            chain_state=chain_state, already_alerted=already,
        )

        assert len(alerts) == 1

    def test_empty_oauth_domains_no_fire(self) -> None:
        chain_state: dict[int, list[tuple[str, datetime]]] = {}
        already: set[int] = set()
        now = datetime.now()

        conns = [
            _conn(pid=99, proc_name="python.exe",
                  domain="accounts.google.com", first_seen=now),
            _conn(pid=99, proc_name="python.exe",
                  domain="login.microsoftonline.com",
                  first_seen=now + timedelta(seconds=1)),
        ]
        alerts = check_oauth_provider_chain(
            conns, frozenset(), _BROWSER_PROCS,
            window_secs=30, threshold=2,
            chain_state=chain_state, already_alerted=already,
        )

        assert alerts == []


# ── MCP_CONNECTOR_TRAFFIC ─────────────────────────────────────────────────────

class TestMcpConnectorTraffic:
    def test_non_browser_to_anthropic_api_fires(self) -> None:
        conns = [_conn(proc_name="claude.exe", domain="api.anthropic.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
        )

        assert len(alerts) == 1
        assert alerts[0].rule == "MCP_CONNECTOR_TRAFFIC"

    def test_browser_to_anthropic_api_does_not_fire(self) -> None:
        conns = [_conn(proc_name="chrome.exe", domain="api.anthropic.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
        )

        assert alerts == []

    def test_python_to_claude_ai_fires(self) -> None:
        conns = [_conn(proc_name="python.exe", domain="claude.ai")]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
        )

        assert len(alerts) == 1

    def test_subdomain_suffix_match_fires(self) -> None:
        # beta.api.anthropic.com is a legit subdomain of api.anthropic.com.
        conns = [_conn(proc_name="node.exe", domain="beta.api.anthropic.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
        )

        assert len(alerts) == 1

    def test_attacker_suffix_spoof_does_not_fire(self) -> None:
        # api.anthropic.com.evil.com is NOT a subdomain of api.anthropic.com.
        conns = [_conn(proc_name="node.exe", domain="api.anthropic.com.evil.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
        )

        assert alerts == []

    def test_unrelated_domain_does_not_fire(self) -> None:
        conns = [_conn(proc_name="python.exe", domain="example.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
        )

        assert alerts == []

    def test_no_domain_does_not_fire(self) -> None:
        conns = [_conn(proc_name="claude.exe", domain=None)]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
        )

        assert alerts == []

    def test_dedupes_repeat_pid_domain(self) -> None:
        conns = [
            _conn(pid=42, proc_name="claude.exe", domain="api.anthropic.com"),
            _conn(pid=42, proc_name="claude.exe", domain="api.anthropic.com"),
        ]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
        )

        assert len(alerts) == 1

    def test_empty_patterns_no_fire(self) -> None:
        conns = [_conn(proc_name="claude.exe", domain="api.anthropic.com")]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, (), _BROWSER_PROCS, already,
        )

        assert alerts == []


# ── DomainCache integration ──────────────────────────────────────────────────

class TestDomainCache:
    def test_lookup_returns_domain_after_refresh(self) -> None:
        from dns_cache import DomainCache
        import json

        canned = json.dumps([
            {"RecordName": "accounts.google.com", "Data": "142.250.80.46", "Type": 1},
            {"RecordName": "github.com", "Data": "140.82.121.4", "Type": 1},
        ])

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": canned, "stderr": "",
            })()
            cache.refresh()

        assert cache.lookup("142.250.80.46") == "accounts.google.com"
        assert cache.lookup("140.82.121.4") == "github.com"
        assert cache.lookup("8.8.8.8") is None

    def test_lookup_is_case_insensitive_storage(self) -> None:
        from dns_cache import DomainCache
        import json

        canned = json.dumps([
            {"RecordName": "Accounts.Google.COM", "Data": "1.2.3.4", "Type": 1},
        ])

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": canned, "stderr": "",
            })()
            cache.refresh()

        # Stored lowercased.
        assert cache.lookup("1.2.3.4") == "accounts.google.com"

    def test_ttl_eviction_prunes_old_entries(self) -> None:
        from dns_cache import DomainCache
        import json

        first = json.dumps([
            {"RecordName": "old.example.com", "Data": "10.0.0.1", "Type": 1},
        ])
        empty = json.dumps([])

        cache = DomainCache(ttl_secs=10)

        # First refresh at t=0 — populate.
        with patch("dns_cache.subprocess.run") as mock_run, \
             patch("dns_cache.time.time", return_value=1000.0):
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": first, "stderr": "",
            })()
            cache.refresh()

        assert cache.lookup("10.0.0.1") == "old.example.com"

        # Second refresh past the TTL with empty result — old entry must prune.
        with patch("dns_cache.subprocess.run") as mock_run, \
             patch("dns_cache.time.time", return_value=2000.0):
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": empty, "stderr": "",
            })()
            cache.refresh()

        assert cache.lookup("10.0.0.1") is None

    def test_subprocess_failure_is_tolerated(self) -> None:
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.side_effect = OSError("powershell not found")
            # Must not raise — failure tolerant.
            cache.refresh()

        assert cache.lookup("anything") is None

    def test_subprocess_timeout_is_tolerated(self) -> None:
        import subprocess
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=2)
            cache.refresh()

        assert cache.lookup("anything") is None

    def test_invalid_json_is_tolerated(self) -> None:
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": "not json {{", "stderr": "",
            })()
            cache.refresh()

        assert cache.lookup("anything") is None

    def test_filters_non_a_aaaa_records(self) -> None:
        from dns_cache import DomainCache
        import json

        # Type 12 = PTR; Type 1 = A; Type 28 = AAAA.
        canned = json.dumps([
            {"RecordName": "1.0.0.10.in-addr.arpa.", "Data": "host.example.com", "Type": 12},
            {"RecordName": "good.example.com", "Data": "10.0.0.1", "Type": 1},
            {"RecordName": "ipv6.example.com", "Data": "2001:db8::1", "Type": 28},
        ])

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": canned, "stderr": "",
            })()
            cache.refresh()

        assert cache.lookup("10.0.0.1") == "good.example.com"
        assert cache.lookup("2001:db8::1") == "ipv6.example.com"
        # PTR record's Data was a hostname, not an IP — never indexed.
        assert cache.lookup("host.example.com") is None

    def test_single_object_response_is_handled(self) -> None:
        # Get-DnsClientCache | ConvertTo-Json (without -AsArray) emits a single
        # bare object when only one entry exists on PS 5.1.
        from dns_cache import DomainCache
        import json

        canned = json.dumps(
            {"RecordName": "solo.example.com", "Data": "5.6.7.8", "Type": 1}
        )

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": canned, "stderr": "",
            })()
            cache.refresh()

        assert cache.lookup("5.6.7.8") == "solo.example.com"

    def test_lookups_for_pid_window_returns_all_seen_domains(self) -> None:
        from dns_cache import DomainCache
        import json

        canned = json.dumps([
            {"RecordName": "a.example.com", "Data": "1.1.1.1", "Type": 1},
            {"RecordName": "b.example.com", "Data": "2.2.2.2", "Type": 1},
        ])

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": canned, "stderr": "",
            })()
            cache.refresh()

        domains = cache.lookups_for_pid_window(["1.1.1.1", "2.2.2.2", "9.9.9.9"])
        assert "a.example.com" in domains
        assert "b.example.com" in domains
        assert len(domains) == 2  # 9.9.9.9 has no entry → omitted
