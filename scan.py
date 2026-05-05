"""Quick-scan utility — prints current outbound connections and any IOC matches.

This is a standalone diagnostic script, not part of the daemon. Run it from
the vigil directory to get a one-shot snapshot of active outbound connections.

Usage:
    python scan.py
    python scan.py --ioc 192.0.2.1,198.51.100.5
"""
import argparse
import sys

import psutil
from datetime import datetime


def _default_ioc_ips() -> set[str]:
    """Return the IOC set from config.env if loadable, otherwise empty set.

    This allows scan.py to be used standalone without a running config, while
    still surfacing configured IOCs if config.env is present.
    """
    try:
        from config import load_config
        cfg = load_config()
        return set(cfg.ioc_ips)
    except Exception:
        return set()


def main(ioc_ips: set[str] | None = None) -> None:
    if ioc_ips is None:
        ioc_ips = _default_ioc_ips()

    print(f"=== VIGIL SCAN {datetime.now().strftime('%H:%M:%S')} ===")
    if ioc_ips:
        print(f"[*] Checking {len(ioc_ips)} IOC IP(s)")
    else:
        print("[*] No IOC IPs configured (set IOC_IPS in config.env to enable IOC matching)")

    hits = []
    conns = []

    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue
        if conn.status not in ("ESTABLISHED", "SYN_SENT"):
            continue
        try:
            name = psutil.Process(conn.pid).name()
        except Exception:
            name = "unknown"
        rip = conn.raddr.ip
        if rip in ioc_ips:
            hits.append(f"  [IOC HIT] {name}({conn.pid}) -> {rip}:{conn.raddr.port} [{conn.status}]")
        conns.append((name, conn.pid, rip, conn.raddr.port))

    print(f"\nIOC hits: {len(hits)}")
    for h in hits:
        print(h)

    print(f"\n=== ALL OUTBOUND ({len(conns)}) ===")
    for name, pid, rip, port in sorted(conns):
        print(f"  {name:<35} ({pid:>6}) -> {rip:<20}:{port}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vigil one-shot connection scan")
    parser.add_argument(
        "--ioc",
        metavar="IP[,IP...]",
        default=None,
        help="Comma-separated IOC IPs to check (overrides config.env)",
    )
    args = parser.parse_args()

    ioc_ips: set[str] | None = None
    if args.ioc:
        ioc_ips = {ip.strip() for ip in args.ioc.split(",") if ip.strip()}

    main(ioc_ips)
