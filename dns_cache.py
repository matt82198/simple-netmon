"""DNS resolution cache enriched from Windows DnsClient cache.

Polls `Get-DnsClientCache` via PowerShell on every poll cycle and maintains a
rolling-window IP→domain map keyed by remote IP. Used by the OAuth chaining
rules to enrich each `ConnRecord` with the domain name the client most recently
resolved to that destination.

Failure-tolerant: any subprocess error, JSON-parse error, or unexpected schema
is logged and ignored — the daemon keeps polling. A stale cache returns None
on lookup, which simply suppresses domain-aware rules until the next refresh.

Public API:
    DomainCache(ttl_secs=30, ps_executable="powershell", enable_reverse=True, oauth_domains=(), mcp_patterns=())
    .refresh()                          # subprocess + merge
    .lookup(ip) -> Optional[str]        # most-recent domain for IP
    .get_or_resolve(ip) -> Optional[str]  # lookup with reverse-DNS fallback (if enabled)
    .lookups_for_pid_window(ips) -> list[str]
"""
from __future__ import annotations

import json
import logging
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

# Windows: suppress the conhost flash that would otherwise pop on every poll.
# 0 on non-Windows is a no-op for `creationflags`.
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

# DnsClient record type codes:
#   1  = A
#   28 = AAAA
#   12 = PTR (skip — Data is a hostname, not an IP)
#   5  = CNAME (skip — Data is another hostname)
# Anything we don't explicitly accept gets dropped at parse time.
_ACCEPTED_RECORD_TYPES = frozenset({1, 28})

_PS_COMMAND = "Get-DnsClientCache | ConvertTo-Json"
_PS_TIMEOUT_SECS = 2

log = logging.getLogger("vigil.dns_cache")


@dataclass
class DomainRecord:
    domain: str
    first_seen: float  # monotonic-ish epoch from time.time()


class DomainCache:
    """Rolling IP→domain cache populated from Get-DnsClientCache.

    Internally keyed by IP because rules look up by IP. Older entries past
    ``ttl_secs`` are pruned on each ``refresh()``.
    """

    def __init__(
        self,
        ttl_secs: int = 30,
        ps_executable: str = "powershell",
        enable_reverse: bool = True,
        oauth_domains: tuple[str, ...] | None = None,
        mcp_patterns: tuple[str, ...] | None = None,
    ) -> None:
        self._ttl_secs = ttl_secs
        self._ps_executable = ps_executable
        self._enable_reverse = enable_reverse
        self._oauth_domains = oauth_domains or ()
        self._mcp_patterns = mcp_patterns or ()
        self._records: dict[str, DomainRecord] = {}

    def refresh(self) -> None:
        """Snapshot Get-DnsClientCache, merge into rolling window.

        Failure-tolerant: errors are logged and swallowed. The cache state
        survives across failures (last good entries remain until they age out).
        """
        now = time.time()
        # Prune stale entries first so a long subprocess outage still ages
        # everything out at the expected TTL.
        self._prune(now)

        try:
            result = subprocess.run(
                [self._ps_executable, "-NoProfile", "-Command", _PS_COMMAND],
                capture_output=True,
                text=True,
                timeout=_PS_TIMEOUT_SECS,
                check=False,
                creationflags=_NO_WINDOW,
            )
        except subprocess.TimeoutExpired:
            log.debug("dns_cache: Get-DnsClientCache timed out")
            return
        except OSError as exc:
            log.debug("dns_cache: subprocess failed: %s", exc)
            return
        except Exception as exc:  # pragma: no cover — defensive
            log.warning("dns_cache: unexpected subprocess error: %s", exc)
            return

        if result.returncode != 0:
            log.debug("dns_cache: powershell exited %d: %s",
                      result.returncode, (result.stderr or "").strip())
            return

        stdout = (result.stdout or "").strip()
        if not stdout:
            return

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            log.debug("dns_cache: invalid JSON from Get-DnsClientCache: %s", exc)
            return

        # ConvertTo-Json (without -AsArray, which is PS 6+ only) emits a bare
        # object when there's exactly one record and a list otherwise. Wrap
        # the single-object case so the iteration below handles both shapes.
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            log.debug("dns_cache: unexpected JSON shape: %s", type(parsed).__name__)
            return

        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            rtype = entry.get("Type")
            # Coerce string types if PowerShell ever serializes as enum text.
            try:
                rtype_int = int(rtype) if rtype is not None else None
            except (TypeError, ValueError):
                rtype_int = None
            if rtype_int is not None and rtype_int not in _ACCEPTED_RECORD_TYPES:
                continue
            name = entry.get("RecordName")
            data = entry.get("Data")
            if not isinstance(name, str) or not isinstance(data, str):
                continue
            domain = name.strip().rstrip(".").lower()
            ip = data.strip()
            if not domain or not ip:
                continue
            # Defensive: PTR/CNAME records that slipped past Type filtering
            # (e.g. Type field absent) would put a hostname in Data. We only
            # want IPs as keys — a quick validation is "contains a dot or
            # colon and starts with a digit/letter that's part of an IP". The
            # cheap heuristic: reject if Data contains alphabetic chars that
            # aren't hex digits in an IPv6 address. We err on the side of
            # accepting; rules degrade gracefully if a junk key never matches.
            if _looks_like_ip(ip):
                self._records[ip] = DomainRecord(domain=domain, first_seen=now)

    def lookup(self, ip: str) -> Optional[str]:
        """Most-recently-seen domain that resolved to this IP, or None.

        Eviction happens at refresh() time only — we trust the daemon to be
        polling on schedule. A lookup against a stale cache is preferable to
        silently returning None for a few extra seconds.
        """
        rec = self._records.get(ip)
        if rec is None:
            return None
        return rec.domain

    def get_or_resolve(self, ip: str) -> Optional[str]:
        """Lookup an IP in the cache, falling back to reverse-DNS if not found.

        If reverse DNS lookup is enabled and the cache miss occurs, attempts
        socket.getnameinfo() to resolve the IP to a hostname with a 2-second
        timeout. Successful resolutions are cached. Returns None if lookup fails
        or reverse-DNS is disabled.
        """
        hit = self.lookup(ip)
        if hit is not None:
            return hit
        if not self._enable_reverse:
            return None
        # Save and restore socket timeout to avoid blocking poll thread.
        # getnameinfo() doesn't support per-call timeout, so we use the
        # default timeout mechanism.
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            host, _ = socket.getnameinfo((ip, 0), 0)
        except (socket.gaierror, socket.timeout, OSError):
            return None
        finally:
            socket.setdefaulttimeout(old_timeout)
        if host and host != ip:
            domain = host.strip().rstrip(".").lower()
            # Defense against PTR spoofing: reject reverse-DNS results that
            # claim to be OAuth providers or MCP endpoints. An attacker controls
            # the PTR record for their IP and could claim to be accounts.google.com
            # to suppress OAuth_PROVIDER_CONTACT / OAUTH_PROVIDER_CHAIN alerts.
            if self._is_oauth_relevant(domain):
                log.warning(
                    "dns_cache: rejected suspicious PTR for %s claiming %s (OAuth-relevant domain)",
                    ip, domain
                )
                return None
            self._records[ip] = DomainRecord(domain=domain, first_seen=time.time())
            return domain
        return None

    def lookups_for_pid_window(self, ip_seq: list[str]) -> list[str]:
        """Helper for chain rule: domains for this batch of IPs (deduped)."""
        seen: list[str] = []
        seen_set: set[str] = set()
        for ip in ip_seq:
            d = self.lookup(ip)
            if d and d not in seen_set:
                seen_set.add(d)
                seen.append(d)
        return seen

    # ── internal ──────────────────────────────────────────────────────────

    def _is_oauth_relevant(self, domain: str) -> bool:
        """Check if domain matches a known OAuth provider or MCP endpoint.

        Returns True if the domain exactly matches or is a subdomain of any
        OAuth provider or MCP pattern. Used to reject suspicious reverse-DNS
        results that could suppress alerts (PTR spoofing defense).
        """
        if not domain:
            return False
        domain_lower = domain.lower()
        for d in self._oauth_domains:
            if domain_lower == d or domain_lower.endswith("." + d):
                return True
        for p in self._mcp_patterns:
            if domain_lower == p or domain_lower.endswith("." + p):
                return True
        return False

    def _prune(self, now: float) -> None:
        cutoff = now - self._ttl_secs
        stale = [ip for ip, rec in self._records.items() if rec.first_seen < cutoff]
        for ip in stale:
            self._records.pop(ip, None)


def _looks_like_ip(s: str) -> bool:
    """Cheap IP-shape check; we don't need full parsing here."""
    if not s:
        return False
    if ":" in s:  # IPv6
        return all(c in "0123456789abcdefABCDEF:%." for c in s)
    if s.count(".") == 3:
        parts = s.split(".")
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return False
