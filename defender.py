"""Real-time defense actions for high-confidence vigil detections.

Policy: only act on CRITICAL severity. Opt-in (defender_enabled=False default)
and dry-run default (defender_dry_run=True). Action: outbound firewall block
on the detected destination IP via netsh.
"""
from __future__ import annotations

import logging
import subprocess
import sys

_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def defend(alert, cfg, log: logging.Logger) -> None:
    """Block an alert's destination IP via Windows firewall if conditions are met.

    Only acts if:
    1. cfg.defender_enabled is True
    2. alert.severity == "CRITICAL"
    3. alert has a dst field (remote IP:port or similar)

    In dry-run mode (default), logs the action without executing netsh.
    """
    if not getattr(cfg, "defender_enabled", False):
        return
    if getattr(alert, "severity", None) != "CRITICAL":
        return
    dst = getattr(alert, "dst", None) or getattr(alert, "remote_ip", None)
    if not dst:
        log.warning("defender: CRITICAL alert missing dst, skipping")
        return
    # Extract just the IP address (strip :port if present)
    remote_ip = dst.split(":")[0] if ":" in dst else dst
    rule_name = f"vigil-block-{remote_ip}"
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
           f"name={rule_name}", "dir=out", "action=block",
           f"remoteip={remote_ip}", "enable=yes"]
    if getattr(cfg, "defender_dry_run", True):
        log.info("defender DRY-RUN would run: %s", " ".join(cmd))
        return
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                                creationflags=_NO_WINDOW, check=False)
        if result.returncode == 0:
            log.warning("defender BLOCKED %s (rule=%s)", remote_ip, rule_name)
        else:
            log.error("defender netsh failed rc=%d: %s", result.returncode, (result.stderr or "").strip())
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.error("defender exception: %s", exc)
