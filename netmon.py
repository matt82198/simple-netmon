from __future__ import annotations

import argparse
import logging
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

import psutil

from alerter import dispatch
from baseline import Baseline, load_baseline, record_poll, save_baseline
from config import PRIVATE_PREFIXES, Config, load_config
from rules import (
    ConnRecord,
    ExitRecord,
    check_ioc_ip,
    check_new_process_egress,
    check_parallel_exfil,
    check_short_lived_egress,
    check_baseline_unknown_process,
    check_baseline_ip_deviation,
    check_baseline_port_deviation,
    check_baseline_volume_spike,
)

_OUTBOUND_STATUSES = {"ESTABLISHED", "SYN_SENT"}


@dataclass
class DaemonState:
    ioc_alerted: set[tuple[int, str]] = field(default_factory=set)
    exfil_alerted: set[int] = field(default_factory=set)
    short_lived_alerted: set[int] = field(default_factory=set)
    egress_name_history: deque[set[str]] = field(default_factory=deque)
    active_outbound: dict[int, ConnRecord] = field(default_factory=dict)
    exited_queue: list[ExitRecord] = field(default_factory=list)
    prev_pids: set[int] = field(default_factory=set)
    poll_count: int = 0
    baseline_proc_alerted: set = field(default_factory=set)   # set[str] proc_name
    baseline_ip_alerted: set = field(default_factory=set)     # set[tuple[str,str]]
    baseline_port_alerted: set = field(default_factory=set)   # set[tuple[str,int]]


def build_logger(cfg: Config) -> logging.Logger:
    log = logging.getLogger("netmon")
    log.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    fh = RotatingFileHandler(
        cfg.log_path,
        maxBytes=cfg.log_max_bytes,
        backupCount=cfg.log_backup_count,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    log.addHandler(fh)
    log.addHandler(sh)
    return log


def snapshot(cfg: Config) -> list[ConnRecord]:
    records: list[ConnRecord] = []
    now = datetime.now()

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except Exception:
        return records

    for conn in raw_conns:
        if not conn.raddr:
            continue
        if conn.status not in _OUTBOUND_STATUSES:
            continue

        remote_ip = conn.raddr.ip
        if cfg.filter_private and any(remote_ip.startswith(p) for p in PRIVATE_PREFIXES):
            continue

        pid = conn.pid or 0
        proc_name = "unknown"
        if pid:
            try:
                proc_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "unknown"

        records.append(ConnRecord(
            pid=pid,
            proc_name=proc_name,
            laddr=(conn.laddr.ip, conn.laddr.port),
            raddr=(conn.raddr.ip, conn.raddr.port),
            status=conn.status,
            first_seen=now,
        ))

    return records


def detect_exits(
    prev_pids: set[int],
    curr_pids: set[int],
    active_outbound: dict[int, ConnRecord],
) -> list[ExitRecord]:
    exited_pids = prev_pids - curr_pids
    now = datetime.now()
    exits: list[ExitRecord] = []

    for pid in exited_pids:
        rec = active_outbound.get(pid)
        if rec is None:
            continue
        exits.append(ExitRecord(
            pid=rec.pid,
            proc_name=rec.proc_name,
            laddr=rec.laddr,
            raddr=rec.raddr,
            first_seen=rec.first_seen,
            exit_time=now,
        ))

    return exits


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="netmon")
    parser.add_argument("--train", metavar="SECONDS", nargs="?", const=3600, type=int,
        help="Run baseline training for N seconds (default 3600), write baseline.json, exit")
    parser.add_argument("--baseline", metavar="PATH", type=Path, default=None)
    parser.add_argument("--config", metavar="PATH", type=Path, default=None)
    return parser.parse_args()


def run_training(duration_secs: int, baseline_path: Path, cfg: Config, log: logging.Logger) -> None:
    from baseline import Baseline
    started_at = datetime.now()
    bl = Baseline(trained_at=started_at.isoformat(), training_duration_secs=duration_secs, total_polls=0, processes={})
    log.info("training mode: %ds → %s", duration_secs, baseline_path)
    deadline = time.monotonic() + duration_secs
    poll_num = 0
    try:
        while time.monotonic() < deadline:
            conns = snapshot(cfg)
            record_poll(bl, conns)
            bl.total_polls += 1
            poll_num += 1
            if poll_num % 60 == 0:
                log.info("training: poll %d, %.0fs remaining", poll_num, max(0, deadline - time.monotonic()))
            time.sleep(cfg.poll_interval)
    except KeyboardInterrupt:
        log.info("training interrupted at poll %d — saving partial baseline", poll_num)
    save_baseline(bl, baseline_path)
    log.info("training complete: %d polls, %d processes → %s", bl.total_polls, len(bl.processes), baseline_path)


def run_poll(state: DaemonState, cfg: Config, log: logging.Logger, baseline: Baseline | None = None) -> None:
    # 1. snapshot
    curr_conns = snapshot(cfg)

    # 2. current pids with outbound connections
    curr_pids = {c.pid for c in curr_conns}

    # 3. detect exits
    state.exited_queue = detect_exits(state.prev_pids, curr_pids, state.active_outbound)

    # 4. update active_outbound — preserve first_seen for existing pids
    for c in curr_conns:
        if c.pid not in state.active_outbound:
            state.active_outbound[c.pid] = c
    for gone in state.exited_queue:
        state.active_outbound.pop(gone.pid, None)

    # 5. push current proc names into rolling history (maxlen enforced by deque)
    current_names = {c.proc_name for c in curr_conns}
    state.egress_name_history.append(current_names)

    # 6. known egress = union of all history windows except the current poll
    history_without_current = list(state.egress_name_history)[:-1]
    known_egress: set[str] = set().union(*history_without_current) if history_without_current else set()

    # 7. advance poll counter; alerting is suppressed during warmup
    state.poll_count += 1
    alerting_active = state.poll_count > cfg.warmup_polls

    # 8. run all checks and dispatch
    ioc_alerts = check_ioc_ip(curr_conns, cfg.ioc_ips, state.ioc_alerted)
    exfil_alerts = check_parallel_exfil(curr_conns, cfg.parallel_exfil_threshold, state.exfil_alerted)
    egress_alerts = check_new_process_egress(curr_conns, known_egress, cfg.egress_allowlist)
    short_lived_alerts = check_short_lived_egress(
        state.exited_queue, cfg.short_lived_threshold, state.short_lived_alerted
    )

    if baseline is not None:
        bl_proc_alerts   = check_baseline_unknown_process(curr_conns, baseline, known_egress, cfg.egress_allowlist, state.baseline_proc_alerted)
        bl_ip_alerts     = check_baseline_ip_deviation(curr_conns, baseline, cfg.baseline_suppress_cdn_threshold, state.baseline_ip_alerted)
        bl_port_alerts   = check_baseline_port_deviation(curr_conns, baseline, state.baseline_port_alerted)
        bl_volume_alerts = check_baseline_volume_spike(curr_conns, baseline)
        egress_alerts    = []   # suppress old rule when baseline loaded
    else:
        bl_proc_alerts = bl_ip_alerts = bl_port_alerts = bl_volume_alerts = []

    if alerting_active:
        for alert in (*ioc_alerts, *exfil_alerts, *egress_alerts, *bl_proc_alerts, *bl_ip_alerts, *bl_port_alerts, *bl_volume_alerts, *short_lived_alerts):
            dispatch(alert, cfg, log)
    else:
        total = len(ioc_alerts) + len(exfil_alerts) + len(egress_alerts) + len(short_lived_alerts) + len(bl_proc_alerts) + len(bl_ip_alerts) + len(bl_port_alerts) + len(bl_volume_alerts)
        if total:
            log.debug("warmup poll %d: suppressed %d alert(s)", state.poll_count, total)

    # 9. update prev_pids
    state.prev_pids = curr_pids


def main() -> None:
    args = parse_args()
    cfg = load_config(config_path=args.config)
    log = build_logger(cfg)

    script_dir = Path(__file__).parent
    if args.baseline:
        baseline_path = args.baseline
    elif cfg.baseline_path:
        baseline_path = cfg.baseline_path
    else:
        baseline_path = script_dir / "baseline.json"

    if args.train is not None:
        run_training(args.train, baseline_path, cfg, log)
        return

    baseline = load_baseline(baseline_path)
    if baseline is not None:
        log.info("baseline loaded: %d processes", len(baseline.processes))
    else:
        log.info("no baseline — running without baseline rules")

    # existing state init and loop — pass baseline to run_poll
    state = DaemonState()
    state.egress_name_history = deque(maxlen=cfg.new_process_lookback)
    log.info("netmon starting — poll_interval=%ds warmup_polls=%d", cfg.poll_interval, cfg.warmup_polls)
    while True:
        try:
            run_poll(state, cfg, log, baseline)
        except Exception as exc:
            log.error("poll error: %s", exc, exc_info=True)
        time.sleep(cfg.poll_interval)


if __name__ == "__main__":
    main()
