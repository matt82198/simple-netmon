"""Regression tests for the PowerShell 5.1 incompatibility in DomainCache.

Background: ``Get-DnsClientCache | ConvertTo-Json -AsArray`` was the original
implementation, but ``-AsArray`` is PowerShell 6+ only. On Windows PowerShell
5.1 (the default Windows 11 shell) the command fails with a
ParameterBindingException, ``Get-DnsClientCache`` never returns, and
``DomainCache`` stays empty — which silently disables the three new
domain-keyed OAuth rules.

These tests pin the fix:
1. The PS command sent must NOT contain ``-AsArray``.
2. The cache must handle both shapes ``ConvertTo-Json`` (without ``-AsArray``)
   emits: a bare object when one record exists, a list when many do.
3. If the OLD command somehow ran on PS 5.1, the cache must stay empty and
   the daemon must not crash.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest


# ── Fix is locked in: command must not use -AsArray ──────────────────────────

class TestPowerShellCommand:
    def test_command_does_not_use_asarray_flag(self) -> None:
        """-AsArray is PS 6+ only. PS 5.1 (Windows default) rejects it."""
        from dns_cache import _PS_COMMAND

        assert "-AsArray" not in _PS_COMMAND
        assert "Get-DnsClientCache" in _PS_COMMAND
        assert "ConvertTo-Json" in _PS_COMMAND


# ── Both PS 5.1 output shapes must populate the cache correctly ──────────────

class TestPs51OutputShapes:
    """``ConvertTo-Json`` (no ``-AsArray``) emits a bare object for one record
    and a list for many. Both must round-trip through DomainCache.lookup().
    """

    def test_single_bare_object_populates_cache(self) -> None:
        """One DNS entry → ConvertTo-Json emits a bare object on PS 5.1."""
        from dns_cache import DomainCache

        # Exact shape PS 5.1 emits when Get-DnsClientCache has one entry.
        canned = json.dumps({
            "Entry": "accounts.google.com",
            "RecordName": "accounts.google.com",
            "RecordType": "A",
            "Status": 0,
            "Section": 1,
            "TimeToLive": 60,
            "DataLength": 4,
            "Data": "142.250.80.46",
            "Type": 1,
        })

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": canned, "stderr": "",
            })()
            cache.refresh()

        assert cache.lookup("142.250.80.46") == "accounts.google.com"

    def test_array_of_objects_populates_cache(self) -> None:
        """Many DNS entries → ConvertTo-Json emits a JSON list on PS 5.1."""
        from dns_cache import DomainCache

        canned = json.dumps([
            {"RecordName": "accounts.google.com", "Data": "142.250.80.46", "Type": 1},
            {"RecordName": "github.com",          "Data": "140.82.121.4",  "Type": 1},
            {"RecordName": "ipv6.example.com",    "Data": "2001:db8::1",   "Type": 28},
        ])

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 0, "stdout": canned, "stderr": "",
            })()
            cache.refresh()

        assert cache.lookup("142.250.80.46") == "accounts.google.com"
        assert cache.lookup("140.82.121.4") == "github.com"
        assert cache.lookup("2001:db8::1") == "ipv6.example.com"


# ── Negative test: PS 5.1 ParameterBindingException must not break things ────

class TestPs51ParameterBindingFailure:
    """Pre-fix behavior: ``-AsArray`` triggers a ParameterBindingException on
    PS 5.1, the subprocess returns non-zero with empty stdout, and DomainCache
    must absorb the failure cleanly without crashing the daemon.
    """

    # Verbatim stderr that PS 5.1 emits for `-AsArray` (line breaks elided).
    _PS51_PARAMETER_BINDING_STDERR = (
        "ConvertTo-Json : A parameter cannot be found that matches parameter "
        "name 'AsArray'.\n"
        "At line:1 char:35\n"
        "+ Get-DnsClientCache | ConvertTo-Json -AsArray\n"
        "+                                     ~~~~~~~~\n"
        "    + CategoryInfo          : InvalidArgument: (:) [ConvertTo-Json], "
        "ParameterBindingException\n"
        "    + FullyQualifiedErrorId : NamedParameterNotFound,"
        "Microsoft.PowerShell.Commands.ConvertToJsonCommand\n"
    )

    def test_parameter_binding_exception_leaves_cache_empty(self) -> None:
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 1,
                "stdout": "",
                "stderr": self._PS51_PARAMETER_BINDING_STDERR,
            })()
            # Must not raise — daemon survives a failed PS subprocess.
            cache.refresh()

        assert cache.lookup("142.250.80.46") is None
        assert cache.lookup("anything") is None

    def test_parameter_binding_exception_does_not_crash_daemon(self) -> None:
        """Repeated PS failures across many polls must never raise — the
        daemon's monitor loop relies on this to keep running.
        """
        from dns_cache import DomainCache

        cache = DomainCache(ttl_secs=30)
        with patch("dns_cache.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {
                "returncode": 1,
                "stdout": "",
                "stderr": self._PS51_PARAMETER_BINDING_STDERR,
            })()
            for _ in range(5):
                cache.refresh()  # ≥1 must run; none may raise.

        assert cache.lookup("anything") is None
