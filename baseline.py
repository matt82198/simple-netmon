from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class ProcessProfile:
    remote_ips: list[str]      # sorted, deduplicated
    remote_ports: list[int]    # sorted, deduplicated
    max_concurrent: int
    poll_appearances: int


@dataclass
class Baseline:
    trained_at: str
    training_duration_secs: int
    total_polls: int
    processes: dict[str, ProcessProfile]  # keyed by proc_name as returned by psutil


def load_baseline(path: Path) -> Baseline | None:
    """Load a Baseline from a JSON file. Returns None on missing file or malformed JSON."""
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        processes: dict[str, ProcessProfile] = {}
        for name, prof in data.get("processes", {}).items():
            processes[name] = ProcessProfile(
                remote_ips=list(prof.get("remote_ips", [])),
                remote_ports=list(prof.get("remote_ports", [])),
                max_concurrent=int(prof.get("max_concurrent", 0)),
                poll_appearances=int(prof.get("poll_appearances", 0)),
            )
        return Baseline(
            trained_at=str(data.get("trained_at", "")),
            training_duration_secs=int(data.get("training_duration_secs", 0)),
            total_polls=int(data.get("total_polls", 0)),
            processes=processes,
        )
    except Exception as exc:
        print(f"baseline: failed to load {path}: {exc}", file=sys.stderr)
        return None


def save_baseline(baseline: Baseline, path: Path) -> None:
    """Serialize baseline to JSON and atomically write to path.

    Note: callers should invoke this on KeyboardInterrupt to preserve
    partial baselines collected during training runs.
    """
    data = asdict(baseline)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def record_poll(baseline: Baseline, conns: list) -> None:
    """Update baseline from one poll's worth of connections.

    Accepts a list of ConnRecord-like objects (duck-typed: .proc_name,
    .raddr tuple, .status). Does NOT increment total_polls — caller does that.
    """
    # group connections by proc_name for this poll
    by_proc: dict[str, list] = {}
    for c in conns:
        by_proc.setdefault(c.proc_name, []).append(c)

    for proc_name, proc_conns in by_proc.items():
        profile = baseline.processes.get(proc_name)
        if profile is None:
            profile = ProcessProfile(
                remote_ips=[],
                remote_ports=[],
                max_concurrent=0,
                poll_appearances=0,
            )
            baseline.processes[proc_name] = profile

        # union remote IPs and ports
        existing_ips = set(profile.remote_ips)
        existing_ports = set(profile.remote_ports)
        for c in proc_conns:
            if c.raddr and len(c.raddr) >= 2:
                existing_ips.add(c.raddr[0])
                existing_ports.add(c.raddr[1])

        profile.remote_ips = sorted(existing_ips)
        profile.remote_ports = sorted(existing_ports)
        profile.max_concurrent = max(profile.max_concurrent, len(proc_conns))
        profile.poll_appearances += 1
