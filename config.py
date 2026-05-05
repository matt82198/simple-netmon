from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

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
    "msmpeng.exe", "nissrv.exe",
    # dev tools
    "node.exe", "python.exe", "pythonw.exe", "code.exe", "git.exe",
    "windowsterminal.exe",
    # comms (user-installed)
    "teams.exe", "slack.exe", "discord.exe",
})

_DEFAULT_IOC_IPS: frozenset[str] = frozenset({
    # Add known-bad IPs here or set IOC_IPS in config.env.
    # No defaults shipped — populate from your own threat intel.
})

_DEFAULT_OAUTH_PROVIDER_DOMAINS: frozenset[str] = frozenset({
    # Google
    "accounts.google.com",
    "oauth2.googleapis.com",
    "openidconnect.googleapis.com",
    "graph.microsoft.com",
    # Microsoft
    "login.microsoftonline.com",
    "login.live.com",
    # GitHub
    "github.com",
    "api.github.com",
    # Atlassian
    "api.atlassian.com",
    "id.atlassian.com",
    # Slack
    "slack.com",
    # Notion
    "api.notion.com",
    # Box
    "api.box.com",
    # Dropbox
    "www.dropbox.com",
    # Salesforce
    "login.salesforce.com",
    "test.salesforce.com",
    # Linear
    "linear.app",
    # Zoom
    "zoom.us",
    # Discord
    "discord.com",
})

_DEFAULT_OAUTH_BROWSER_PROCS: frozenset[str] = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "arc.exe", "zen.exe",
    # macOS / Linux equivalents
    "google chrome", "firefox", "safari", "microsoft edge",
})

_DEFAULT_MCP_ENDPOINT_PATTERNS: tuple[str, ...] = (
    "api.anthropic.com",
    "claude.ai",
    "console.anthropic.com",
    "platform.claude.com",
    "smithery.ai",
    "glama.ai",
    "modelcontextprotocol.io",
)

_DEFAULT_OAUTH_BROWSER_PATHS: tuple[str, ...] = (
    r"C:\Program Files\Google\Chrome\Application",
    r"C:\Program Files (x86)\Google\Chrome\Application",
    r"C:\Program Files\Mozilla Firefox",
    r"C:\Program Files\Microsoft\Edge\Application",
    r"C:\Program Files (x86)\Microsoft\Edge\Application",
    "/Applications/Google Chrome.app",
    "/Applications/Firefox.app",
    "/Applications/Microsoft Edge.app",
    "/usr/bin",
    "/usr/lib",
)


def _parse_bool(value: str, default: bool) -> bool:
    if value.lower() in {"true", "1", "yes"}:
        return True
    if value.lower() in {"false", "0", "no"}:
        return False
    return default


def _parse_ip_networks(raw: str) -> tuple[IpNetwork, ...]:
    """Parse a comma-separated list of IPs/CIDRs into ip_network objects.

    Bare IPv4 addresses become /32 networks; bare IPv6 become /128. Empty or
    whitespace-only entries are ignored. Malformed entries are skipped with a
    warning to stderr — we don't want one bad entry to disable the whole
    allowlist on a daemon that's already running.
    """
    if not raw or not raw.strip():
        return ()
    nets: list[IpNetwork] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            print(
                f"config: invalid EGRESS_IP_ALLOWLIST entry {entry!r}: {exc}",
                file=sys.stderr,
            )
    return tuple(nets)


def _parse_str_set(raw: str, default: frozenset[str]) -> frozenset[str]:
    """Parse a comma-separated list of strings, lowercased. Returns default if empty."""
    parsed = frozenset(s.strip().lower() for s in raw.split(",") if s.strip())
    return parsed if parsed else default


def _parse_tuple(raw: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Parse a comma-separated list of strings. Returns default if empty."""
    parsed = tuple(s.strip() for s in raw.split(",") if s.strip())
    return parsed if parsed else default


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
    egress_allowlist: frozenset[str]          # lowercased; checked case-insensitively
    egress_ip_allowlist: tuple[IpNetwork, ...]  # parsed CIDRs/IPs; bare IPs become /32 or /128
    baseline_path: Path | None                # None = use script dir / baseline.json
    baseline_suppress_cdn_threshold: int      # default 50
    # OAuth / MCP detection
    oauth_provider_domains: frozenset[str]    # domains that trigger OAUTH_PROVIDER_CONTACT
    oauth_browser_procs: frozenset[str]       # process names exempt from OAuth rules
    oauth_browser_paths: tuple[str, ...]      # install-dir paths for browser ancestry check
    mcp_endpoint_host_patterns: tuple[str, ...]  # suffix patterns for MCP traffic detection
    oauth_chain_window_secs: int              # window for OAUTH_PROVIDER_CHAIN (default 60)
    oauth_chain_threshold: int               # providers in window to fire chain (default 2)
    dns_reverse_lookup_enabled: bool         # fallback to reverse DNS on cache miss
    # Real-time defense
    defender_enabled: bool                   # opt-in; default False
    defender_dry_run: bool                   # dry-run mode; default True


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

    raw_oauth = os.getenv("OAUTH_PROVIDER_DOMAINS", "")
    oauth_provider_domains = (
        frozenset(d.strip().lower() for d in raw_oauth.split(",") if d.strip())
        if raw_oauth.strip()
        else _DEFAULT_OAUTH_PROVIDER_DOMAINS
    )

    raw_browser_procs = os.getenv("OAUTH_BROWSER_PROCS", "")
    oauth_browser_procs = (
        frozenset(p.strip().lower() for p in raw_browser_procs.split(",") if p.strip())
        if raw_browser_procs.strip()
        else _DEFAULT_OAUTH_BROWSER_PROCS
    )

    raw_browser_paths = os.getenv("OAUTH_BROWSER_PATHS", "")
    oauth_browser_paths = (
        tuple(p.strip() for p in raw_browser_paths.split(",") if p.strip())
        if raw_browser_paths.strip()
        else _DEFAULT_OAUTH_BROWSER_PATHS
    )

    raw_mcp = os.getenv("MCP_ENDPOINT_HOST_PATTERNS", "")
    mcp_endpoint_host_patterns = (
        tuple(p.strip() for p in raw_mcp.split(",") if p.strip())
        if raw_mcp.strip()
        else _DEFAULT_MCP_ENDPOINT_PATTERNS
    )

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
        egress_ip_allowlist=_parse_ip_networks(os.getenv("EGRESS_IP_ALLOWLIST", "")),
        baseline_path=(
            Path(raw_bp) if (raw_bp := os.getenv("BASELINE_PATH", "").strip()) else None
        ),
        baseline_suppress_cdn_threshold=int(
            os.getenv("BASELINE_SUPPRESS_CDN_THRESHOLD", "50")
        ),
        oauth_provider_domains=oauth_provider_domains,
        oauth_browser_procs=oauth_browser_procs,
        oauth_browser_paths=oauth_browser_paths,
        mcp_endpoint_host_patterns=mcp_endpoint_host_patterns,
        oauth_chain_window_secs=int(os.getenv("OAUTH_CHAIN_WINDOW_SECS", "60")),
        oauth_chain_threshold=int(os.getenv("OAUTH_CHAIN_THRESHOLD", "2")),
        dns_reverse_lookup_enabled=_parse_bool(
            os.getenv("DNS_REVERSE_LOOKUP_ENABLED", "false"), False
        ),
        defender_enabled=_parse_bool(os.getenv("DEFENDER_ENABLED", "false"), False),
        defender_dry_run=_parse_bool(os.getenv("DEFENDER_DRY_RUN", "true"), True),
    )
