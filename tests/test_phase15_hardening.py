"""Phase 1.5 hardening tests — convergent audit findings.

Six fixes from a parallel tdd-tail + network-bug-hunter review of
Phase 1's OAuth-chaining rules. Tests written tests-first (RED) before any
implementation lands; each class corresponds to one fix.

1. MCP / OAuth domain match: substring → suffix-aware (no spoof, no FP).
2. PID-reuse eviction across all already_alerted sets on process exit.
3. Browser allowlist: validate executable path, not just process name.
4. DNS reverse-lookup fallback for DoH-bypassing processes.
5. Expanded `OAUTH_PROVIDER_DOMAINS` defaults.
6. Expanded `MCP_ENDPOINT_HOST_PATTERNS` defaults.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest


# ── shared helpers ────────────────────────────────────────────────────────────

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
):
    from rules import ConnRecord
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
    "claude.ai",
})

_BROWSER_PROCS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "arc.exe", "zen.exe",
})

_MCP_PATTERNS = ("api.anthropic.com", "claude.ai")


# ─────────────────────────────────────────────────────────────────────────────
# Fix 1 — Suffix-aware domain matching
# ─────────────────────────────────────────────────────────────────────────────

class TestMcpSuffixMatch:
    """Substring matching is both an attacker bypass AND a false-positive
    surface. Replace with: domain == p OR domain.endswith("." + p).
    """

    def test_exact_pattern_match_fires(self) -> None:
        from rules import check_mcp_connector_traffic
        conns = [_conn(proc_name="claude.exe", domain="api.anthropic.com")]
        already: set[tuple[int, str]] = set()
        alerts = check_mcp_connector_traffic(conns, _MCP_PATTERNS, _BROWSER_PROCS, already)
        assert len(alerts) == 1

    def test_legitimate_subdomain_fires(self) -> None:
        from rules import check_mcp_connector_traffic
        conns = [_conn(proc_name="claude.exe", domain="beta.api.anthropic.com")]
        already: set[tuple[int, str]] = set()
        alerts = check_mcp_connector_traffic(conns, _MCP_PATTERNS, _BROWSER_PROCS, already)
        assert len(alerts) == 1

    def test_attacker_suffix_spoof_does_not_fire(self) -> None:
        """`api.anthropic.com.evil.com` is a substring of api.anthropic.com.
        Suffix-match must reject it.
        """
        from rules import check_mcp_connector_traffic
        conns = [_conn(proc_name="claude.exe", domain="api.anthropic.com.evil.com")]
        already: set[tuple[int, str]] = set()
        alerts = check_mcp_connector_traffic(conns, _MCP_PATTERNS, _BROWSER_PROCS, already)
        assert alerts == []

    def test_no_dot_boundary_substring_does_not_fire(self) -> None:
        """`notapi.anthropic.com` contains `api.anthropic.com` as a substring
        but is a different domain — must not fire.
        """
        from rules import check_mcp_connector_traffic
        conns = [_conn(proc_name="claude.exe", domain="notapi.anthropic.com")]
        already: set[tuple[int, str]] = set()
        alerts = check_mcp_connector_traffic(conns, _MCP_PATTERNS, _BROWSER_PROCS, already)
        assert alerts == []

    def test_claude_ai_exact_fires(self) -> None:
        from rules import check_mcp_connector_traffic
        conns = [_conn(proc_name="python.exe", domain="claude.ai")]
        already: set[tuple[int, str]] = set()
        alerts = check_mcp_connector_traffic(conns, _MCP_PATTERNS, _BROWSER_PROCS, already)
        assert len(alerts) == 1

    def test_claude_ai_suffix_spoof_does_not_fire(self) -> None:
        """`evilclaude.ai` ends in `claude.ai` only at character level. Must
        require dot boundary.
        """
        from rules import check_mcp_connector_traffic
        conns = [_conn(proc_name="python.exe", domain="evilclaude.ai")]
        already: set[tuple[int, str]] = set()
        alerts = check_mcp_connector_traffic(conns, _MCP_PATTERNS, _BROWSER_PROCS, already)
        assert alerts == []


# ─────────────────────────────────────────────────────────────────────────────
# Fix 2 — PID-reuse eviction across all alerted sets
# ─────────────────────────────────────────────────────────────────────────────

class TestEvictPid:
    """Windows reuses PIDs aggressively. When a PID exits its entries must be
    evicted from every already-alerted set so the next process at that PID
    can re-fire.
    """

    def test_evict_pid_removes_from_tuple_keyed_set(self) -> None:
        from netmon import evict_pid

        oauth_contact_alerted: set[tuple[int, str]] = {
            (99, "accounts.google.com"),
            (100, "github.com"),
        }
        mcp_traffic_alerted: set[tuple[int, str]] = {
            (99, "api.anthropic.com"),
            (101, "claude.ai"),
        }

        evict_pid(99, oauth_contact_alerted, mcp_traffic_alerted)

        assert (99, "accounts.google.com") not in oauth_contact_alerted
        assert (99, "api.anthropic.com") not in mcp_traffic_alerted
        # Other pids untouched.
        assert (100, "github.com") in oauth_contact_alerted
        assert (101, "claude.ai") in mcp_traffic_alerted

    def test_evict_pid_removes_from_int_keyed_set(self) -> None:
        from netmon import evict_pid

        oauth_chain_alerted: set[int] = {99, 100}
        evict_pid(99, oauth_chain_alerted)
        assert 99 not in oauth_chain_alerted
        assert 100 in oauth_chain_alerted

    def test_evict_pid_removes_from_dict(self) -> None:
        from netmon import evict_pid

        chain_state: dict[int, list[tuple[str, datetime]]] = {
            99: [("accounts.google.com", datetime.now())],
            100: [("github.com", datetime.now())],
        }
        evict_pid(99, chain_state)
        assert 99 not in chain_state
        assert 100 in chain_state

    def test_evict_pid_safe_when_pid_absent(self) -> None:
        from netmon import evict_pid

        s: set[tuple[int, str]] = {(100, "x")}
        d: dict[int, list] = {100: []}
        # Must not raise.
        evict_pid(99, s, d)
        assert s == {(100, "x")}
        assert d == {100: []}

    def test_evict_pid_handles_mixed_collection_types(self) -> None:
        from netmon import evict_pid

        tuple_set: set[tuple[int, str]] = {(99, "a"), (99, "b"), (100, "c")}
        int_set: set[int] = {99, 100}
        d: dict[int, str] = {99: "x", 100: "y"}

        evict_pid(99, tuple_set, int_set, d)

        assert (99, "a") not in tuple_set
        assert (99, "b") not in tuple_set
        assert (100, "c") in tuple_set
        assert 99 not in int_set
        assert 99 not in d

    def test_pid_reuse_after_eviction_re_fires_oauth_contact(self) -> None:
        """Integration-flavored: pre-populate alerted state for pid 99,
        evict, then verify a fresh ConnRecord at pid 99 fires.
        """
        from netmon import evict_pid
        from rules import check_oauth_provider_contact

        already: set[tuple[int, str]] = {(99, "accounts.google.com")}

        # Without eviction, this would be suppressed.
        conns = [_conn(pid=99, proc_name="evil.exe", domain="accounts.google.com")]
        suppressed = check_oauth_provider_contact(conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already)
        assert suppressed == []  # pre-eviction: still in already-alerted

        evict_pid(99, already)

        alerts = check_oauth_provider_contact(conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already)
        assert len(alerts) == 1

    def test_pid_reuse_after_eviction_re_fires_mcp(self) -> None:
        from netmon import evict_pid
        from rules import check_mcp_connector_traffic

        already: set[tuple[int, str]] = {(99, "api.anthropic.com")}
        conns = [_conn(pid=99, proc_name="evil.exe", domain="api.anthropic.com")]
        assert check_mcp_connector_traffic(conns, _MCP_PATTERNS, _BROWSER_PROCS, already) == []

        evict_pid(99, already)

        alerts = check_mcp_connector_traffic(conns, _MCP_PATTERNS, _BROWSER_PROCS, already)
        assert len(alerts) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Fix 3 — Browser path validation
# ─────────────────────────────────────────────────────────────────────────────

_BROWSER_PATHS = (
    r"C:\Program Files\Google\Chrome\Application",
    r"C:\Program Files (x86)\Google\Chrome\Application",
    r"C:\Program Files\Mozilla Firefox",
    r"C:\Program Files\Microsoft\Edge\Application",
)


class TestBrowserPathValidation:
    """Name-only allowlisting lets attackers bypass with a renamed binary or
    code-injection into a real browser. Verify the executable lives under a
    known browser install root.
    """

    def test_chrome_in_program_files_is_legitimate(self) -> None:
        from rules import _is_legitimate_browser

        with patch("rules.psutil.Process") as mock_proc:
            mock_proc.return_value.exe.return_value = (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            )
            assert _is_legitimate_browser(1234, "chrome.exe", _BROWSER_PATHS) is True

    def test_chrome_outside_install_dir_is_not_legitimate(self) -> None:
        from rules import _is_legitimate_browser

        with patch("rules.psutil.Process") as mock_proc:
            mock_proc.return_value.exe.return_value = (
                r"C:\Users\Public\malware\chrome.exe"
            )
            assert _is_legitimate_browser(1234, "chrome.exe", _BROWSER_PATHS) is False

    def test_access_denied_falls_back_to_safe_deny(self) -> None:
        from rules import _is_legitimate_browser
        import psutil

        with patch("rules.psutil.Process") as mock_proc:
            mock_proc.return_value.exe.side_effect = psutil.AccessDenied(1234)
            # Safe-deny: cannot verify path → not legitimate.
            assert _is_legitimate_browser(1234, "chrome.exe", _BROWSER_PATHS) is False

    def test_no_such_process_falls_back_to_safe_deny(self) -> None:
        from rules import _is_legitimate_browser
        import psutil

        with patch("rules.psutil.Process") as mock_proc:
            mock_proc.side_effect = psutil.NoSuchProcess(1234)
            assert _is_legitimate_browser(1234, "chrome.exe", _BROWSER_PATHS) is False

    def test_empty_browser_paths_means_no_one_is_legit(self) -> None:
        from rules import _is_legitimate_browser

        with patch("rules.psutil.Process") as mock_proc:
            mock_proc.return_value.exe.return_value = (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            )
            # Extreme strict mode: empty allowlist means no process is legit.
            assert _is_legitimate_browser(1234, "chrome.exe", ()) is False

    def test_proc_name_not_in_browser_set_skips_path_check(self) -> None:
        """Non-browser-named procs aren't even candidates — function returns
        False without invoking psutil.
        """
        from rules import _is_legitimate_browser

        with patch("rules.psutil.Process") as mock_proc:
            assert _is_legitimate_browser(1234, "evil.exe", _BROWSER_PATHS) is False

    def test_check_oauth_contact_with_browser_paths_chrome_legit(self) -> None:
        """Integration: chrome.exe at a legit path is allowlisted."""
        from rules import check_oauth_provider_contact

        conns = [_conn(pid=1234, proc_name="chrome.exe", domain="accounts.google.com")]
        already: set[tuple[int, str]] = set()

        with patch("rules.psutil.Process") as mock_proc:
            mock_proc.return_value.exe.return_value = (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            )
            alerts = check_oauth_provider_contact(
                conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
                browser_paths=_BROWSER_PATHS,
            )

        assert alerts == []

    def test_check_oauth_contact_renamed_chrome_not_allowlisted(self) -> None:
        """Integration: chrome.exe at a non-install path falls through the
        allowlist and fires OAUTH_PROVIDER_CONTACT.
        """
        from rules import check_oauth_provider_contact

        conns = [_conn(pid=1234, proc_name="chrome.exe", domain="accounts.google.com")]
        already: set[tuple[int, str]] = set()

        with patch("rules.psutil.Process") as mock_proc:
            mock_proc.return_value.exe.return_value = r"C:\Users\Public\malware\chrome.exe"
            alerts = check_oauth_provider_contact(
                conns, _OAUTH_DOMAINS, _BROWSER_PROCS, already,
                browser_paths=_BROWSER_PATHS,
            )

        assert len(alerts) == 1
        assert alerts[0].rule == "OAUTH_PROVIDER_CONTACT"

    def test_check_mcp_renamed_chrome_not_allowlisted(self) -> None:
        from rules import check_mcp_connector_traffic

        conns = [_conn(pid=1234, proc_name="chrome.exe", domain="api.anthropic.com")]
        already: set[tuple[int, str]] = set()

        with patch("rules.psutil.Process") as mock_proc:
            mock_proc.return_value.exe.return_value = r"C:\Users\Public\malware\chrome.exe"
            alerts = check_mcp_connector_traffic(
                conns, _MCP_PATTERNS, _BROWSER_PROCS, already,
                browser_paths=_BROWSER_PATHS,
            )

        assert len(alerts) == 1


class TestBrowserPathsConfig:
    """`OAUTH_BROWSER_PATHS` config key must parse as a comma-separated list
    of install dirs.
    """

    def _clear_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in (
            "OAUTH_BROWSER_PATHS",
            "OAUTH_BROWSER_PROCS",
            "OAUTH_PROVIDER_DOMAINS",
            "MCP_ENDPOINT_HOST_PATTERNS",
            "EGRESS_ALLOWLIST",
            "EGRESS_IP_ALLOWLIST",
            "IOC_IPS",
            "BASELINE_PATH",
            "DISCORD_WEBHOOK_URL",
            "DNS_REVERSE_LOOKUP_ENABLED",
        ):
            monkeypatch.delenv(key, raising=False)

    def test_default_includes_program_files_chrome(self, tmp_path, monkeypatch) -> None:
        from config import load_config
        self._clear_env(monkeypatch)
        env_path = tmp_path / "config.env"
        env_path.write_text("# default\n", encoding="utf-8")

        cfg = load_config(env_path)

        assert any(
            "Google\\Chrome\\Application" in p or "Google/Chrome/Application" in p
            for p in cfg.oauth_browser_paths
        )

    def test_custom_paths_parsed_from_env(self, tmp_path, monkeypatch) -> None:
        from config import load_config
        self._clear_env(monkeypatch)
        env_path = tmp_path / "config.env"
        env_path.write_text(
            "OAUTH_BROWSER_PATHS=C:\\opt\\chrome,C:\\opt\\firefox\n",
            encoding="utf-8",
        )

        cfg = load_config(env_path)

        assert "C:\\opt\\chrome" in cfg.oauth_browser_paths
        assert "C:\\opt\\firefox" in cfg.oauth_browser_paths


# ─────────────────────────────────────────────────────────────────────────────
# Fix 4 — DoH-fallback reverse DNS
# ─────────────────────────────────────────────────────────────────────────────

class TestDomainCacheReverseLookup:
    """`Get-DnsClientCache` misses processes that use DoH or hardcode IPs.
    `get_or_resolve(ip)` falls back to socket reverse DNS for those.
    """

    def test_returns_cached_domain_when_present(self) -> None:
        from dns_cache import DomainCache
        import json

        canned = json.dumps([
            {"RecordName": "accounts.google.com", "Data": "1.2.3.4", "Type": 1},
        ])
        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": canned, "stderr": "",
            })()
            cache.refresh()

        with patch("dns_cache.socket.getnameinfo") as mock_rdns:
            result = cache.get_or_resolve("1.2.3.4")
            assert result == "accounts.google.com"
            # When forward cache hits, reverse DNS must NOT be called.
            mock_rdns.assert_not_called()

    def test_falls_back_to_reverse_dns_on_miss(self) -> None:
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.socket.getnameinfo") as mock_rdns:
            mock_rdns.return_value = ("accounts.google.com", "0")
            result = cache.get_or_resolve("142.250.80.46")
            assert result == "accounts.google.com"
            mock_rdns.assert_called_once()

    def test_reverse_dns_failure_returns_none(self) -> None:
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.socket.getnameinfo") as mock_rdns:
            mock_rdns.side_effect = socket.gaierror("no such host")
            result = cache.get_or_resolve("8.8.8.8")
            assert result is None  # Hard-fail tolerant.

    def test_reverse_dns_timeout_returns_none(self) -> None:
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.socket.getnameinfo") as mock_rdns:
            mock_rdns.side_effect = socket.timeout("timed out")
            result = cache.get_or_resolve("8.8.8.8")
            assert result is None

    def test_reverse_dns_oserror_returns_none(self) -> None:
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.socket.getnameinfo") as mock_rdns:
            mock_rdns.side_effect = OSError("kaboom")
            result = cache.get_or_resolve("8.8.8.8")
            assert result is None

    def test_reverse_dns_caches_result(self) -> None:
        """Second call for same IP must not hit socket again — cached."""
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.socket.getnameinfo") as mock_rdns:
            mock_rdns.return_value = ("accounts.google.com", "0")
            r1 = cache.get_or_resolve("142.250.80.46")
            r2 = cache.get_or_resolve("142.250.80.46")
            assert r1 == r2 == "accounts.google.com"
            assert mock_rdns.call_count == 1

    def test_reverse_dns_ttl_eviction(self) -> None:
        """Reverse-resolved entries must age out at TTL like forward ones."""
        from dns_cache import DomainCache
        import json

        cache = DomainCache(ttl_secs=10)
        with patch("dns_cache.socket.getnameinfo") as mock_rdns, \
             patch("dns_cache.time.time", return_value=1000.0):
            mock_rdns.return_value = ("a.example.com", "0")
            cache.get_or_resolve("1.1.1.1")

        # Trigger a refresh past the TTL — should prune reverse-resolved too.
        with patch("dns_cache.subprocess.run") as mock_run, \
             patch("dns_cache.time.time", return_value=2000.0):
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": json.dumps([]), "stderr": "",
            })()
            cache.refresh()

        # After eviction the IP is gone from reverse cache; a new lookup
        # would have to hit socket again. Verify by intercepting socket.
        with patch("dns_cache.socket.getnameinfo") as mock_rdns:
            mock_rdns.return_value = ("b.example.com", "0")
            result = cache.get_or_resolve("1.1.1.1")
            assert result == "b.example.com"  # Fresh lookup, not cached value.

    def test_reverse_dns_disabled_via_flag(self) -> None:
        """If `enable_reverse=False`, never call socket — return None on miss."""
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30, enable_reverse=False)
        with patch("dns_cache.socket.getnameinfo") as mock_rdns:
            result = cache.get_or_resolve("8.8.8.8")
            assert result is None
            mock_rdns.assert_not_called()


class TestDnsReverseLookupConfig:
    def _clear_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in (
            "DNS_REVERSE_LOOKUP_ENABLED",
            "OAUTH_BROWSER_PATHS",
            "OAUTH_BROWSER_PROCS",
            "OAUTH_PROVIDER_DOMAINS",
            "MCP_ENDPOINT_HOST_PATTERNS",
            "EGRESS_ALLOWLIST",
            "EGRESS_IP_ALLOWLIST",
            "IOC_IPS",
            "BASELINE_PATH",
            "DISCORD_WEBHOOK_URL",
        ):
            monkeypatch.delenv(key, raising=False)

    def test_default_is_false(self, tmp_path, monkeypatch) -> None:
        # Default is False (secure-by-default; PTR records can be spoofed).
        from config import load_config
        self._clear_env(monkeypatch)
        env_path = tmp_path / "config.env"
        env_path.write_text("# default\n", encoding="utf-8")

        cfg = load_config(env_path)
        assert cfg.dns_reverse_lookup_enabled is False

    def test_can_be_disabled(self, tmp_path, monkeypatch) -> None:
        from config import load_config
        self._clear_env(monkeypatch)
        env_path = tmp_path / "config.env"
        env_path.write_text("DNS_REVERSE_LOOKUP_ENABLED=false\n", encoding="utf-8")

        cfg = load_config(env_path)
        assert cfg.dns_reverse_lookup_enabled is False


# ─────────────────────────────────────────────────────────────────────────────
# Fix 5 — Expanded OAUTH_PROVIDER_DOMAINS defaults
# ─────────────────────────────────────────────────────────────────────────────

class TestExpandedOauthDomainDefaults:
    """Each newly-seeded default must trigger OAUTH_PROVIDER_CONTACT for a
    non-browser process.
    """

    @pytest.mark.parametrize("domain", [
        "api.box.com",
        "www.dropbox.com",
        "login.salesforce.com",
        "test.salesforce.com",
        "linear.app",
        "zoom.us",
        "graph.microsoft.com",
    ])
    def test_default_domain_fires_for_non_browser(self, domain: str) -> None:
        from config import load_config
        from rules import check_oauth_provider_contact
        import os

        # Use defaults — clear any env override.
        old = os.environ.pop("OAUTH_PROVIDER_DOMAINS", None)
        try:
            cfg = load_config()
        finally:
            if old is not None:
                os.environ["OAUTH_PROVIDER_DOMAINS"] = old

        conns = [_conn(proc_name="python.exe", domain=domain)]
        already: set[tuple[int, str]] = set()

        alerts = check_oauth_provider_contact(
            conns, cfg.oauth_provider_domains, cfg.oauth_browser_procs, already,
        )

        assert len(alerts) == 1, f"expected fire for {domain}, got {alerts}"
        assert alerts[0].rule == "OAUTH_PROVIDER_CONTACT"


# ─────────────────────────────────────────────────────────────────────────────
# Fix 6 — Expanded MCP_ENDPOINT_HOST_PATTERNS defaults
# ─────────────────────────────────────────────────────────────────────────────

class TestExpandedMcpPatternDefaults:
    @pytest.mark.parametrize("domain", [
        "console.anthropic.com",
        "platform.claude.com",
    ])
    def test_default_pattern_fires_for_non_browser(self, domain: str) -> None:
        from config import load_config
        from rules import check_mcp_connector_traffic
        import os

        old = os.environ.pop("MCP_ENDPOINT_HOST_PATTERNS", None)
        try:
            cfg = load_config()
        finally:
            if old is not None:
                os.environ["MCP_ENDPOINT_HOST_PATTERNS"] = old

        conns = [_conn(proc_name="claude.exe", domain=domain)]
        already: set[tuple[int, str]] = set()

        alerts = check_mcp_connector_traffic(
            conns, cfg.mcp_endpoint_host_patterns, cfg.oauth_browser_procs, already,
        )

        assert len(alerts) == 1, f"expected fire for {domain}, got {alerts}"
        assert alerts[0].rule == "MCP_CONNECTOR_TRAFFIC"
