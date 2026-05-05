from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Sequence

import psutil

from alerter import Alert
from baseline import Baseline

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

RULE_BASELINE_UNKNOWN = "BASELINE_UNKNOWN_PROCESS"
RULE_BASELINE_IP      = "BASELINE_IP_DEVIATION"
RULE_BASELINE_PORT    = "BASELINE_PORT_DEVIATION"
RULE_BASELINE_VOLUME  = "BASELINE_VOLUME_SPIKE"


@dataclass
class ConnRecord:
    pid: int
    proc_name: str
    laddr: tuple[str, int]
    raddr: tuple[str, int]
    status: str
    first_seen: datetime
    domain: str | None = field(default=None)  # enriched hostname from dns_cache


@dataclass
class ExitRecord:
    pid: int
    proc_name: str
    laddr: tuple[str, int]
    raddr: tuple[str, int]
    first_seen: datetime
    exit_time: datetime


# ── Domain-matching helpers ───────────────────────────────────────────────────

def _domain_matches(domain: str, pattern: str) -> bool:
    """Suffix-aware domain match: exact or subdomain.

    Prevents both attacker bypass (fake-accounts.google.com.evil.io does not
    match accounts.google.com) and false positives (notgoogle.com does not
    match google.com).
    """
    d = domain.lower()
    p = pattern.lower()
    return d == p or d.endswith("." + p)


def _domain_matches_any(domain: str, patterns: Sequence[str]) -> bool:
    """Return True if domain suffix-matches any pattern in the sequence."""
    for p in patterns:
        if _domain_matches(domain, p):
            return True
    return False


def _is_legitimate_browser(
    pid: int,
    proc_name: str,
    browser_paths: Sequence[str],
) -> bool:
    """Check whether a process named like a browser actually lives under a known install dir.

    Returns False (safe-deny) if the process cannot be inspected or lives outside
    all known browser install paths.
    """
    if not browser_paths:
        return False
    try:
        exe = psutil.Process(pid).exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return False
    exe_lower = exe.replace("\\", "/").lower()
    for path in browser_paths:
        p_lower = path.replace("\\", "/").lower()
        if exe_lower.startswith(p_lower.rstrip("/") + "/") or exe_lower == p_lower.lower():
            return True
    return False


def _is_browser(
    pid: int,
    proc_name: str,
    browser_procs: frozenset[str],
    browser_paths: Sequence[str] = (),
) -> bool:
    """Return True if this process should be treated as a browser for OAuth checks.

    When browser_paths is non-empty, validates executable location as well as name.
    """
    if proc_name.lower() not in browser_procs:
        return False
    if not browser_paths:
        return True
    return _is_legitimate_browser(pid, proc_name, browser_paths)


# ── Core detection rules ──────────────────────────────────────────────────────

def check_ioc_ip(
    conns: list[ConnRecord],
    ioc_ips: frozenset[str],
    already_alerted: set[tuple[int, str]],
) -> list[Alert]:
    alerts: list[Alert] = []
    for c in conns:
        remote_ip = c.raddr[0]
        if remote_ip not in ioc_ips:
            continue
        key = (c.pid, remote_ip)
        if key in already_alerted:
            continue
        already_alerted.add(key)
        alerts.append(Alert(
            rule="IOC_IP_MATCH",
            proc_name=c.proc_name,
            pid=c.pid,
            src=f"{c.laddr[0]}:{c.laddr[1]}",
            dst=f"{remote_ip}:{c.raddr[1]}",
            detail=f"connection to known IOC {remote_ip}",
            severity="CRITICAL",
            timestamp=datetime.now(),
        ))
    return alerts


def check_parallel_exfil(
    conns: list[ConnRecord],
    threshold: int,
    already_alerted: set[int],
) -> list[Alert]:
    # count outbound established connections per pid
    pid_counts: dict[int, list[ConnRecord]] = {}
    for c in conns:
        if c.status in {"ESTABLISHED", "SYN_SENT"}:
            pid_counts.setdefault(c.pid, []).append(c)

    alerts: list[Alert] = []
    for pid, pid_conns in pid_counts.items():
        if len(pid_conns) < threshold:
            continue
        if pid in already_alerted:
            continue
        already_alerted.add(pid)
        sample = pid_conns[0]
        alerts.append(Alert(
            rule="PARALLEL_EXFIL",
            proc_name=sample.proc_name,
            pid=pid,
            src=f"{sample.laddr[0]}",
            dst="multiple",
            detail=f"{len(pid_conns)} simultaneous outbound connections (threshold={threshold})",
            severity="LOW",
            timestamp=datetime.now(),
        ))
    return alerts


def check_new_process_egress(
    conns: list[ConnRecord],
    known_egress_names: set[str],
    egress_allowlist: frozenset[str] = frozenset(),
) -> list[Alert]:
    # alert once per unique proc_name not seen in rolling history and not allowlisted
    seen_this_call: set[str] = set()
    alerts: list[Alert] = []
    for c in conns:
        name = c.proc_name
        if name.lower() in egress_allowlist:
            continue
        if name in known_egress_names or name in seen_this_call:
            continue
        seen_this_call.add(name)
        alerts.append(Alert(
            rule="NEW_PROCESS_EGRESS",
            proc_name=name,
            pid=c.pid,
            src=f"{c.laddr[0]}:{c.laddr[1]}",
            dst=f"{c.raddr[0]}:{c.raddr[1]}",
            detail=f"first-seen outbound process: {name}",
            severity="MEDIUM",
            timestamp=datetime.now(),
        ))
    return alerts


def check_short_lived_egress(
    exited_procs: list[ExitRecord],
    threshold_secs: int,
    already_alerted: set[int],
    egress_allowlist: frozenset[str] = frozenset(),
) -> list[Alert]:
    alerts: list[Alert] = []
    for rec in exited_procs:
        if rec.proc_name.lower() in egress_allowlist:
            continue
        if rec.pid in already_alerted:
            continue
        lived = (rec.exit_time - rec.first_seen).total_seconds()
        if lived >= threshold_secs:
            continue
        already_alerted.add(rec.pid)
        alerts.append(Alert(
            rule="SHORT_LIVED_EGRESS",
            proc_name=rec.proc_name,
            pid=rec.pid,
            src=f"{rec.laddr[0]}:{rec.laddr[1]}",
            dst=f"{rec.raddr[0]}:{rec.raddr[1]}",
            detail=f"process exited after {lived:.1f}s (threshold={threshold_secs}s)",
            severity="LOW",
            timestamp=datetime.now(),
        ))
    return alerts


# ── OAuth / MCP chain detection rules ─────────────────────────────────────────

def check_oauth_provider_contact(
    conns: list[ConnRecord],
    oauth_domains: frozenset[str],
    browser_procs: frozenset[str],
    already_alerted: set[tuple[int, str]],
    browser_paths: Sequence[str] = (),
) -> list[Alert]:
    """Alert when a non-browser process contacts an OAuth identity provider.

    Dedupes by (pid, domain). Browser procs are exempt. When browser_paths is
    provided, validates the executable location rather than trusting the name.
    """
    alerts: list[Alert] = []
    for c in conns:
        domain = c.domain
        if domain is None:
            continue
        domain_lower = domain.lower()
        if not _domain_matches_any(domain_lower, oauth_domains):
            continue
        if _is_browser(c.pid, c.proc_name, browser_procs, browser_paths):
            continue
        key = (c.pid, domain_lower)
        if key in already_alerted:
            continue
        already_alerted.add(key)
        alerts.append(Alert(
            rule="OAUTH_PROVIDER_CONTACT",
            proc_name=c.proc_name,
            pid=c.pid,
            src=f"{c.laddr[0]}:{c.laddr[1]}",
            dst=f"{c.raddr[0]}:{c.raddr[1]}",
            detail=f"OAuth provider contact: {domain}",
            severity="MEDIUM",
            timestamp=c.first_seen,
        ))
    return alerts


def check_oauth_provider_chain(
    conns: list[ConnRecord],
    oauth_domains: frozenset[str],
    browser_procs: frozenset[str],
    window_secs: int,
    threshold: int,
    chain_state: dict[int, list[tuple[str, datetime]]],
    already_alerted: set[int],
    browser_paths: Sequence[str] = (),
) -> list[Alert]:
    """Alert when a single process touches >= threshold distinct OAuth providers
    within window_secs. This is the core AI-pivot detection rule.

    chain_state is mutated in place: {pid: [(domain, first_seen), ...]}.
    already_alerted prevents re-firing within the same window.
    """
    alerts: list[Alert] = []
    for c in conns:
        domain = c.domain
        if domain is None:
            continue
        domain_lower = domain.lower()
        if not _domain_matches_any(domain_lower, oauth_domains):
            continue
        if _is_browser(c.pid, c.proc_name, browser_procs, browser_paths):
            continue

        pid = c.pid
        now = c.first_seen
        window_start = now.timestamp() - window_secs

        # Prune stale entries for this pid
        entries = chain_state.get(pid, [])
        entries = [(d, t) for (d, t) in entries if t.timestamp() > window_start]

        # Add this domain if not already present in window
        known_domains = {d for (d, _) in entries}
        if domain_lower not in known_domains:
            entries.append((domain_lower, now))
        chain_state[pid] = entries

        if pid in already_alerted:
            continue

        unique_domains = {d for (d, _) in entries}
        if len(unique_domains) >= threshold:
            already_alerted.add(pid)
            providers_str = ", ".join(sorted(unique_domains))
            alerts.append(Alert(
                rule="OAUTH_PROVIDER_CHAIN",
                proc_name=c.proc_name,
                pid=pid,
                src=f"{c.laddr[0]}",
                dst="multiple",
                detail=f"{len(unique_domains)} OAuth providers in window: {providers_str}",
                severity="HIGH",
                timestamp=now,
            ))
    return alerts


def check_mcp_connector_traffic(
    conns: list[ConnRecord],
    mcp_patterns: Sequence[str],
    browser_procs: frozenset[str],
    already_alerted: set[tuple[int, str]],
    browser_paths: Sequence[str] = (),
) -> list[Alert]:
    """Alert when a non-browser process contacts a known MCP/AI infrastructure endpoint.

    Uses suffix-aware matching against mcp_patterns.
    """
    alerts: list[Alert] = []
    for c in conns:
        domain = c.domain
        if domain is None:
            continue
        domain_lower = domain.lower()
        if not _domain_matches_any(domain_lower, mcp_patterns):
            continue
        if _is_browser(c.pid, c.proc_name, browser_procs, browser_paths):
            continue
        key = (c.pid, domain_lower)
        if key in already_alerted:
            continue
        already_alerted.add(key)
        alerts.append(Alert(
            rule="MCP_CONNECTOR_TRAFFIC",
            proc_name=c.proc_name,
            pid=c.pid,
            src=f"{c.laddr[0]}:{c.laddr[1]}",
            dst=f"{c.raddr[0]}:{c.raddr[1]}",
            detail=f"MCP endpoint contact: {domain}",
            severity="HIGH",
            timestamp=c.first_seen,
        ))
    return alerts


# ── Baseline deviation rules ──────────────────────────────────────────────────

def check_baseline_unknown_process(
    conns: list[ConnRecord],
    baseline: Baseline | None,
    known_egress_names: set[str],
    egress_allowlist: frozenset[str],
    already_alerted: set[str],          # keyed by proc_name; mutated in place
) -> list[Alert]:
    # When baseline is None: delegate to check_new_process_egress
    if baseline is None:
        return check_new_process_egress(conns, known_egress_names, egress_allowlist)

    alerts: list[Alert] = []
    seen_this_call: set[str] = set()
    for c in conns:
        name = c.proc_name
        if name in seen_this_call:
            continue
        if name.lower() in egress_allowlist:
            continue
        if name in baseline.processes:
            continue
        if name in already_alerted:
            continue
        seen_this_call.add(name)
        already_alerted.add(name)
        alerts.append(Alert(
            rule=RULE_BASELINE_UNKNOWN,
            proc_name=name,
            pid=c.pid,
            src=f"{c.laddr[0]}:{c.laddr[1]}",
            dst=f"{c.raddr[0]}:{c.raddr[1]}",
            detail=f"process not in baseline: {name}",
            severity="MEDIUM",
            timestamp=datetime.now(),
        ))
    return alerts


def _ip_in_any_network(remote_ip: str, networks: Sequence[IpNetwork]) -> bool:
    if not networks:
        return False
    try:
        addr = ipaddress.ip_address(remote_ip)
    except ValueError:
        return False
    for net in networks:
        # ipaddress rejects cross-version containment checks with TypeError;
        # gate by version so we don't silently swallow real bugs.
        if addr.version != net.version:
            continue
        if addr in net:
            return True
    return False


def check_baseline_ip_deviation(
    conns: list[ConnRecord],
    baseline: Baseline | None,
    cdn_threshold: int,
    already_alerted: set[tuple[str, str]],  # (proc_name, remote_ip); mutated in place
    egress_allowlist: frozenset[str] = frozenset(),
    ip_allowlist: Sequence[IpNetwork] = (),
) -> list[Alert]:
    if baseline is None:
        return []

    alerts: list[Alert] = []
    for c in conns:
        name = c.proc_name
        if name.lower() in egress_allowlist:
            continue
        profile = baseline.processes.get(name)
        if profile is None:
            continue
        if len(profile.remote_ips) > cdn_threshold:
            continue
        remote_ip = c.raddr[0]
        if remote_ip in set(profile.remote_ips):
            continue
        if _ip_in_any_network(remote_ip, ip_allowlist):
            continue
        key: tuple[str, str] = (name, remote_ip)
        if key in already_alerted:
            continue
        already_alerted.add(key)
        alerts.append(Alert(
            rule=RULE_BASELINE_IP,
            proc_name=name,
            pid=c.pid,
            src=f"{c.laddr[0]}:{c.laddr[1]}",
            dst=f"{remote_ip}:{c.raddr[1]}",
            detail=f"remote IP {remote_ip} not in baseline for {name}",
            severity="MEDIUM",
            timestamp=datetime.now(),
        ))
    return alerts


def check_baseline_port_deviation(
    conns: list[ConnRecord],
    baseline: Baseline | None,
    already_alerted: set[tuple[str, int]],  # (proc_name, port); mutated in place
) -> list[Alert]:
    if baseline is None:
        return []

    alerts: list[Alert] = []
    for c in conns:
        name = c.proc_name
        profile = baseline.processes.get(name)
        if profile is None:
            continue
        port = c.raddr[1]
        if port in set(profile.remote_ports):
            continue
        key: tuple[str, int] = (name, port)
        if key in already_alerted:
            continue
        already_alerted.add(key)
        alerts.append(Alert(
            rule=RULE_BASELINE_PORT,
            proc_name=name,
            pid=c.pid,
            src=f"{c.laddr[0]}:{c.laddr[1]}",
            dst=f"{c.raddr[0]}:{port}",
            detail=f"remote port {port} not in baseline for {name}",
            severity="MEDIUM",
            timestamp=datetime.now(),
        ))
    return alerts


def check_baseline_volume_spike(
    conns: list[ConnRecord],
    baseline: Baseline | None,
    egress_allowlist: frozenset[str] = frozenset(),
) -> list[Alert]:
    # No already_alerted — fires every poll while condition holds.
    if baseline is None:
        return []

    by_proc: dict[str, list[ConnRecord]] = {}
    for c in conns:
        by_proc.setdefault(c.proc_name, []).append(c)

    alerts: list[Alert] = []
    for name, proc_conns in by_proc.items():
        if name.lower() in egress_allowlist:
            continue
        profile = baseline.processes.get(name)
        if profile is None:
            continue
        count = len(proc_conns)
        if count <= profile.max_concurrent * 1.5:
            continue
        sample = proc_conns[0]
        alerts.append(Alert(
            rule=RULE_BASELINE_VOLUME,
            proc_name=name,
            pid=sample.pid,
            src=f"{sample.laddr[0]}",
            dst="multiple",
            detail=f"{count} connections (baseline max={profile.max_concurrent})",
            severity="MEDIUM",
            timestamp=datetime.now(),
        ))
    return alerts
