#!/usr/bin/env python3
"""
vigil demo — MCP Connector Traffic simulation

SAFE DEMO: This script makes HEAD/GET requests with no credentials, no OAuth flows,
and no real authentication. All requests are informational probes to public
infrastructure. No data is submitted or stored.

Purpose: demonstrate vigil's MCP_CONNECTOR_TRAFFIC detection rule.
Expected alert: MCP_CONNECTOR_TRAFFIC fired in netmon.log.

Usage:
  python demo_mcp_traffic.py           # run the demo
  python demo_mcp_traffic.py --dry-run # see what WOULD be requested
"""

import argparse
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: requests library not found. Install with: pip install -r requirements.txt")
    sys.exit(1)

# Disable SSL warnings for cleanliness (we're probing, not validating)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


MCP_TARGETS = [
    ("claude.ai", "https://claude.ai/", "HEAD"),
    ("claude.ai/api", "https://claude.ai/api/mcp/connectors", "GET"),
    ("api.anthropic.com", "https://api.anthropic.com/v1/messages", "HEAD"),
]


def probe(label: str, url: str, method: str = "HEAD", dry_run: bool = False) -> None:
    """
    Issue a single safe probe request using HEAD or GET.
    No credentials, no body, no authentication headers.
    """
    if dry_run:
        print(f"  [DRY-RUN] {method} {url}")
        return

    t0 = time.perf_counter()
    try:
        resp = requests.request(
            method,
            url,
            timeout=5,
            allow_redirects=False,
            headers={"User-Agent": "vigil-demo/1.0 (safety-probe; no-auth)"},
            verify=False,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"  [{label}] {method} {url} -> {resp.status_code} ({elapsed_ms:.0f}ms)")
    except requests.exceptions.RequestException as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"  [{label}] {method} {url} -> ERROR: {type(exc).__name__} ({elapsed_ms:.0f}ms)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="vigil demo — MCP connector traffic detection (safe probe)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what WOULD be requested without actually sending requests",
    )
    args = parser.parse_args()

    print("[DEMO] MCP Connector Traffic Simulation")
    print("[DEMO] Sending requests to Anthropic/Claude infrastructure endpoints")
    print("[DEMO] Expected alert: MCP_CONNECTOR_TRAFFIC in netmon.log\n")

    if args.dry_run:
        print("[DRY-RUN] These requests would be sent:\n")

    t0_overall = time.perf_counter()
    for label, url, method in MCP_TARGETS:
        probe(label, url, method=method, dry_run=args.dry_run)
        if not args.dry_run:
            time.sleep(0.3)
    elapsed_total = time.perf_counter() - t0_overall

    print()
    if args.dry_run:
        print("[DRY-RUN] Total time: would be <1s")
    else:
        print(f"[DEMO] Completed in {elapsed_total:.1f}s")
        print("[DEMO] Check netmon.log for MCP_CONNECTOR_TRAFFIC alert (within 5–10s)")


if __name__ == "__main__":
    main()
