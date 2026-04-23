from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from alerter import Alert
from baseline import Baseline

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


@dataclass
class ExitRecord:
    pid: int
    proc_name: str
    laddr: tuple[str, int]
    raddr: tuple[str, int]
    first_seen: datetime
    exit_time: datetime


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
            timestamp=datetime.now(),
        ))
    return alerts


def check_short_lived_egress(
    exited_procs: list[ExitRecord],
    threshold_secs: int,
    already_alerted: set[int],
) -> list[Alert]:
    alerts: list[Alert] = []
    for rec in exited_procs:
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
            timestamp=datetime.now(),
        ))
    return alerts


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
            timestamp=datetime.now(),
        ))
    return alerts


def check_baseline_ip_deviation(
    conns: list[ConnRecord],
    baseline: Baseline | None,
    cdn_threshold: int,
    already_alerted: set[tuple[str, str]],  # (proc_name, remote_ip); mutated in place
) -> list[Alert]:
    if baseline is None:
        return []

    alerts: list[Alert] = []
    for c in conns:
        name = c.proc_name
        profile = baseline.processes.get(name)
        if profile is None:
            continue
        if len(profile.remote_ips) > cdn_threshold:
            continue
        remote_ip = c.raddr[0]
        if remote_ip in set(profile.remote_ips):
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
            timestamp=datetime.now(),
        ))
    return alerts


def check_baseline_volume_spike(
    conns: list[ConnRecord],
    baseline: Baseline | None,
) -> list[Alert]:
    # No already_alerted — fires every poll while condition holds.
    if baseline is None:
        return []

    by_proc: dict[str, list[ConnRecord]] = {}
    for c in conns:
        by_proc.setdefault(c.proc_name, []).append(c)

    alerts: list[Alert] = []
    for name, proc_conns in by_proc.items():
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
            timestamp=datetime.now(),
        ))
    return alerts
