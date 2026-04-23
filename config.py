from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_SCRIPT_DIR = Path(__file__).parent

PRIVATE_PREFIXES: tuple[str, ...] = (
    "10.",
    "127.",
    "::1",
    "fe80",
    "192.168.",
    *[f"172.{i}." for i in range(16, 32)],
)

_DEFAULT_EGRESS_ALLOWLIST: frozenset[str] = frozenset({
    # browsers
    "chrome.exe", "msedge.exe", "firefox.exe",
    # microsoft / windows
    "svchost.exe", "lsass.exe", "services.exe", "explorer.exe",
    "onedrive.exe", "onedrive.sync.service.exe",
    "runtimebroker.exe", "backgroundtaskhost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "searchapp.exe", "searchindexer.exe",
    "wuauclt.exe", "waasmedic.exe", "securityhealthservice.exe",
    "msmпeng.exe", "nissrv.exe",
    # dev tools
    "node.exe", "python.exe", "pythonw.exe", "code.exe", "git.exe",
    "windowsterminal.exe",
    # comms (user-installed)
    "teams.exe", "slack.exe", "discord.exe",
})

_DEFAULT_IOC_IPS: frozenset[str] = frozenset({
    "160.79.104.10",
    "20.190.157.1",
    "34.98.64.218",
    "20.49.91.128",
    "34.237.6.16",
})


def _parse_bool(value: str, default: bool) -> bool:
    if value.lower() in {"true", "1", "yes"}:
        return True
    if value.lower() in {"false", "0", "no"}:
        return False
    return default


@dataclass
class Config:
    poll_interval: int
    ioc_ips: frozenset[str]
    parallel_exfil_threshold: int
    short_lived_threshold: int
    new_process_lookback: int
    warmup_polls: int
    discord_webhook_url: str | None
    toast_enabled: bool
    log_path: str
    log_max_bytes: int
    log_backup_count: int
    filter_private: bool
    egress_allowlist: frozenset[str]  # lowercased; checked case-insensitively
    baseline_path: Path | None          # None = use script dir / baseline.json
    baseline_suppress_cdn_threshold: int  # default 50


def load_config(config_path: Path | None = None) -> Config:
    if config_path is not None:
        env_path = config_path
    else:
        env_path = _SCRIPT_DIR / "config.env"
    if env_path.exists():
        load_dotenv(env_path)
    else:
        load_dotenv()

    raw_ioc = os.getenv("IOC_IPS", "")
    if raw_ioc.strip():
        ioc_ips: frozenset[str] = frozenset(
            ip.strip() for ip in raw_ioc.split(",") if ip.strip()
        )
    else:
        ioc_ips = _DEFAULT_IOC_IPS

    default_log = str(_SCRIPT_DIR / "netmon.log")

    return Config(
        poll_interval=int(os.getenv("POLL_INTERVAL", "5")),
        ioc_ips=ioc_ips,
        parallel_exfil_threshold=int(os.getenv("PARALLEL_EXFIL_THRESHOLD", "10")),
        short_lived_threshold=int(os.getenv("SHORT_LIVED_THRESHOLD", "30")),
        new_process_lookback=int(os.getenv("NEW_PROCESS_LOOKBACK", "5")),
        warmup_polls=int(os.getenv("WARMUP_POLLS", "5")),
        discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL") or None,
        toast_enabled=_parse_bool(os.getenv("TOAST_ENABLED", "true"), True),
        log_path=os.getenv("LOG_PATH", default_log),
        log_max_bytes=int(os.getenv("LOG_MAX_BYTES", str(5_242_880))),
        log_backup_count=int(os.getenv("LOG_BACKUP_COUNT", "3")),
        filter_private=_parse_bool(os.getenv("FILTER_PRIVATE", "true"), True),
        egress_allowlist=frozenset(
            n.strip().lower()
            for n in os.getenv("EGRESS_ALLOWLIST", "").split(",")
            if n.strip()
        ) or _DEFAULT_EGRESS_ALLOWLIST,
        baseline_path=(
            Path(raw_bp) if (raw_bp := os.getenv("BASELINE_PATH", "").strip()) else None
        ),
        baseline_suppress_cdn_threshold=int(
            os.getenv("BASELINE_SUPPRESS_CDN_THRESHOLD", "50")
        ),
    )
