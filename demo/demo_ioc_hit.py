#!/usr/bin/env python3
"""
vigil demo — IOC IP Hit simulation

SAFE DEMO: This script makes a HEAD request to an IOC IP address. By default,
it uses 127.0.0.2 (loopback variant), which will not reach any real host.
Users can override with --ip to test against actual IOC IPs from their config.

No credentials, no authentication, no sensitive data submission.

Purpose: demonstrate vigil's IOC_IP_MATCH detection rule.
Expected alert: IOC_IP_MATCH fired in netmon.log (if IOC IP is configured).

Usage:
  python demo_ioc_hit.py              # use safe loopback default (127.0.0.2)
  python demo_ioc_hit.py --ip <IP>   # test against a specific IOC IP
  python demo_ioc_hit.py --dry-run    # see what WOULD be requested
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


def probe(ip: str, port: int = 443, dry_run: bool = False) -> None:
    """
    Issue a single safe HEAD request to an IP address (HTTPS).
    No credentials, no body, no authentication headers.
    """
    url = f"https://{ip}:{port}/"

    if dry_run:
        print(f"  [DRY-RUN] HEAD {url} (with {5}s timeout, expect timeout/connection error)")
        return

    print(f"[DEMO] Connecting to {ip}:{port} (HEAD request)...")
    t0 = time.perf_counter()
    try:
        resp = requests.head(
            url,
            timeout=5,
            allow_redirects=False,
            headers={"User-Agent": "vigil-demo/1.0 (safety-probe; no-auth)"},
            verify=False,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"  [IOC_HIT] HEAD {url} -> {resp.status_code} ({elapsed_ms:.0f}ms)")
    except requests.exceptions.Timeout:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"  [IOC_HIT] HEAD {url} -> TIMEOUT ({elapsed_ms:.0f}ms)")
    except requests.exceptions.ConnectionError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        # Connection refused is expected for loopback test IPs
        if "127.0.0.2" in url:
            print(f"  [IOC_HIT] HEAD {url} -> CONNECTION REFUSED (expected for 127.0.0.2) ({elapsed_ms:.0f}ms)")
        else:
            print(f"  [IOC_HIT] HEAD {url} -> CONNECTION ERROR ({elapsed_ms:.0f}ms)")
    except requests.exceptions.RequestException as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"  [IOC_HIT] HEAD {url} -> ERROR: {type(exc).__name__} ({elapsed_ms:.0f}ms)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="vigil demo — IOC IP hit detection (safe probe)"
    )
    parser.add_argument(
        "--ip",
        type=str,
        default="127.0.0.2",
        help="IOC IP to probe (default: 127.0.0.2, a safe loopback variant). "
        "To test against real IOC IPs, add them to IOC_IPS in config.env and override here.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Port to connect to (default: 443 for HTTPS)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what WOULD be requested without actually sending requests",
    )
    args = parser.parse_args()

    print("[DEMO] IOC IP Hit Simulation")
    if args.ip == "127.0.0.2":
        print("[DEMO] Using safe loopback default (127.0.0.2)")
        print("[DEMO] Connection will fail, but vigil will NOT alert (not in IOC_IPS by default)")
        print("[DEMO] To test real IOC detection:")
        print("[DEMO]   1. Add IOC IP to IOC_IPS in config.env")
        print("[DEMO]   2. Run: python demo_ioc_hit.py --ip <your-ioc-ip>")
    else:
        print(f"[DEMO] Testing against IOC IP: {args.ip}:{args.port}")
        print("[DEMO] Expected alert: IOC_IP_MATCH in netmon.log")

    print()

    if args.dry_run:
        print("[DRY-RUN] Request that would be sent:\n")

    probe(args.ip, port=args.port, dry_run=args.dry_run)

    print()
    if args.dry_run:
        print("[DRY-RUN] Total time: would be <5s (timeout per request)")
    else:
        print("[DEMO] Completed")
        if args.ip != "127.0.0.2":
            print("[DEMO] Check netmon.log for IOC_IP_MATCH alert (within 5–10s)")
        else:
            print("[DEMO] (No alert expected — 127.0.0.2 is not configured as IOC)")


if __name__ == "__main__":
    main()
