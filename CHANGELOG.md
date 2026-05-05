# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

---

## [0.2.0] — 2026-05-04

### Added

**Phase 1 — OAuth chaining detection**
- `OAUTH_PROVIDER_CONTACT` rule: alerts when any non-browser process establishes a connection to a known OAuth/identity endpoint (`accounts.google.com`, `oauth2.googleapis.com`, `login.microsoftonline.com`, `login.live.com`, `github.com/login/oauth`, `api.github.com`, `id.atlassian.com`, `slack.com/oauth`, `discord.com/oauth2`).
- `OAUTH_PROVIDER_CHAIN` rule: alerts when the same process touches ≥2 distinct OAuth providers within a 60-second window — the primary signal for AI-driven lateral movement.
- `MCP_CONNECTOR_TRAFFIC` rule: alerts on egress to known MCP/Anthropic infrastructure (`claude.ai/api/`, `api.anthropic.com/v1/messages`, `modelcontextprotocol.io`, `mcp.*.anthropic.com`).
- `dns_cache.py` module: polls the OS DNS client cache on a 30-second rolling window to map remote IPs to hostnames (SNI enrichment), enabling rule evaluation against domain names rather than bare IPs.

**Sprint 1 — Hardening and coverage expansion**
- `severity` field on `Alert`: all alerts now carry a severity level (`INFO`, `MEDIUM`, `HIGH`, `CRITICAL`), enabling downstream filtering and prioritization by alerting channels.
- `defender.py` module: Windows Defender integration layer — queries the local MSDE event log for recent detection events and correlates them with active process connections, surfacing defender hits that overlap with vigil-detected anomalous processes.
- Browser process ancestry validation in `OAUTH_PROVIDER_CONTACT` and `OAUTH_PROVIDER_CHAIN`: the check now walks up to 3 levels of the parent process chain via `psutil.Process.parent()` rather than relying only on process name. A Python script spawned from a terminal is correctly flagged; a browser extension subprocess is correctly excluded.
- Expanded OAuth provider domain coverage: added Okta tenant patterns (`*.okta.com`), Auth0 tenant patterns (`*.auth0.com`), and AWS Cognito hosted UI patterns (`*.auth.us-east-1.amazoncognito.com` and other regions).
- Expanded MCP endpoint patterns: added `smithery.ai`, `glama.ai`, and additional community MCP registry patterns.
- Reverse-DNS enrichment fallback: when the OS DNS cache has no record for an IP, `dns_cache.py` now attempts a reverse-DNS lookup before falling back to the bare IP. Reduces unlabeled-IP noise in log output. Disabled by default (`DNS_REVERSE_LOOKUP_ENABLED=false`).
- Demo scripts: `demo/demo_oauth_chain.py` simulates an OAuth pivot attack (HEAD requests to multiple identity providers from a single process, no credentials transmitted) and triggers `OAUTH_PROVIDER_CHAIN` within the first poll cycle. See `demo/README.md` for variants.
- 56-test suite passing, including 5 PS 5.1 regression tests covering the DNS cache polling behavior on Windows.
- `OAUTH_BROWSER_PATHS` environment variable: comma-separated list of additional executable names to treat as browser ancestors during the ancestry walk. Allows users to add custom Electron-shell applications that legitimately perform OAuth without user-visible browser windows.

**Project**
- Repository renamed from `simple-netmon` to `vigil`.
- All internal references updated: logger name, toast `app_id`, and alert prefix changed from `[NETMON]` to `[VIGIL]`.
- `config.env.example` updated with OAuth/MCP detection thresholds and the new `OAUTH_BROWSER_PATHS` variable.
- Default IOC IP list cleared — no personal threat intel shipped in defaults; populate `IOC_IPS` in `config.env`.

### Changed

- `Alert.format_message()` now includes the `severity` field in output: `[VIGIL] HIGH | OAUTH_PROVIDER_CHAIN | proc: python.exe(9182) | ...`
- `alerter.dispatch()` gates Discord and toast delivery on severity threshold (configurable via `ALERT_MIN_SEVERITY`; default `MEDIUM`).
- `check_new_process_egress` suppressed when baseline is loaded (existing behavior, now documented explicitly).
- `README.md` rewritten to reflect the vigil mission, the four-pillar architecture, and the incident origin story.

### Fixed

- Provider domain matching hardened from substring to suffix-based comparison throughout `rules.py` — prevents bypass via crafted hostnames containing a provider domain as a substring (e.g. `fake-accounts.google.com.attacker.io` no longer matches `accounts.google.com`).
- `dns_cache.py` no longer retains stale entries indefinitely; cache entries expire after 300 seconds (configurable via `DNS_CACHE_TTL_SECS`).

### Security

- OAuth provider and MCP endpoint patterns are now suffix-matched, closing a detection bypass where a hostname containing a provider domain as a path component or subdomain of an attacker-controlled domain would have fired incorrectly or been missed.
- Browser ancestry validation replaced name-only matching, closing a bypass where an attacker-controlled process named `chrome.exe` would have been excluded from OAuth chain detection.

---

## [0.1.0] — 2026-04-28

Initial public release as `simple-netmon`.

### Added

- `netmon.py`: main daemon loop with configurable `POLL_INTERVAL` (default 5s) and `WARMUP_POLLS` warmup period.
- `scan.py`: `psutil`-based connection snapshot, filtering RFC-1918/loopback by default (`FILTER_PRIVATE=true`).
- `baseline.py`: 30-minute (or custom) baseline training mode (`--train`). Builds per-process profiles covering observed remote IPs, ports, and concurrent connection counts. Writes `baseline.json`.
- `rules.py`: rule engine with six initial rules:
  - `IOC_IP_MATCH` — outbound connection to a known-bad IP.
  - `PARALLEL_EXFIL` — single process opens ≥N simultaneous outbound connections.
  - `SHORT_LIVED_EGRESS` — process with outbound connections exits in under 30s.
  - `NEW_PROCESS_EGRESS` — first-ever outbound connection from a process not in rolling history (pre-baseline mode).
  - `BASELINE_UNKNOWN_PROCESS` — process not seen during training makes outbound connections.
  - `BASELINE_IP_DEVIATION` — process connects to an IP not observed during training.
  - `BASELINE_PORT_DEVIATION` — process connects on a port not observed during training.
  - `BASELINE_VOLUME_SPIKE` — process opens >1.5× its baseline maximum concurrent connections.
- `alerter.py`: alert dispatch layer with three output channels — rotating log file, Windows toast notifications (via `winotify`, graceful fallback if absent), and Discord webhook.
- `config.py` + `config.env.example`: full environment-based configuration for all thresholds, allowlists, alerting channels, and logging parameters.
- `install.ps1` / `install.sh`: service installation scripts for Windows (Task Scheduler) and Linux/macOS (systemd/launchd).
- `requirements.txt`: `psutil`, `requests`, `python-dotenv`, `winotify` (optional).
- `tests/`: initial test suite covering allowlist logic.

---

[Unreleased]: https://github.com/matt82198/vigil/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/matt82198/vigil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/matt82198/vigil/releases/tag/v0.1.0
