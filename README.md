# vigil

**The host-resident detector for AI-driven OAuth pivots — because no existing tool watches which process is touching which identity provider.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![Platform: Windows | macOS | Linux](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)]()

---

## What this is

vigil is a host-resident daemon that detects AI-agent behavior on your machine by watching process-level network telemetry in real time. It knows which processes are browsers, which domains are identity providers, and what machine-paced OAuth chaining looks like. It does not intercept traffic. It does not require a proxy. It runs on your host, polls `psutil`, and fires alerts when the pattern matches.

The rules were written from a real incident, not a threat model.

---

## The AI Behavior Score

The most novel thing vigil does is assign every active process a per-process **AI Behavior Score** (0–100) — a composite that measures how closely a process's observed network behavior matches the signature of an autonomous AI agent. Classic rules fire on individual events. The score fires on behavioral gestalt.

Six signals contribute, each weighted:

| Signal | Max pts | What it catches |
|--------|---------|-----------------|
| OAuth provider chain breadth | 25 | How many distinct identity providers touched in 60s |
| MCP traffic presence | 20 | Egress to AI infrastructure from a non-AI process |
| Request cadence CV | 20 | Machine-regular timing (CV < 0.1 = highly regular) |
| Identity hits without browser ancestry | 15 | OAuth flow with no browser anywhere in the parent chain |
| Sub-100ms inter-request gaps | 10 | Faster than any human can click |
| Parallel egress fan-out | 10 | Simultaneous outbound connections, not sequential browsing |

**Score tiers:**

| Score | Tier | Action |
|-------|------|--------|
| 0–29 | Human / normal automation | No alert |
| 30–59 | Automated tooling | Logged at INFO |
| 60–84 | AI agent | `AI_AGENT_BEHAVIOR` alert fired once per PID |
| 85–100 | AI agent + escalation | `AI_AGENT_ESCALATION` — same urgency as a known-IOC IP hit |

**Sample output — what a real OAuth pivot looks like to vigil:**

```
2026-05-04 01:14:28 WARNING [VIGIL] AI_AGENT_BEHAVIOR | proc: python.exe(9182) | score=74/100 | tier=AI_AGENT
  oauth_chain:    22  (3 providers: google, microsoft, github)
  mcp_traffic:    20  (claude.ai/api/ contacted; process not a known AI client)
  cadence_cv:     20  (CV=0.08 over 6 requests — machine-paced)
  no_browser:     12  (parent: WindowsTerminal.exe; no browser ancestry)
  sub_100ms:       0
  parallel:        0
  ─────────────────
  TOTAL:          74  → AI_AGENT tier (threshold: 60)
```

The score is additive on top of event-based rules — it does not replace them.

---

## Run the demo against your own machine in 30 seconds

```bash
# Terminal 1 — start vigil
python netmon.py

# Terminal 2 — run the OAuth pivot simulation (safe: HEAD requests only, no credentials)
python demo/demo_oauth_chain.py
```

Watch `netmon.log`. You should see `OAUTH_PROVIDER_CHAIN` fire within the first poll cycle (5–10 seconds). The demo script issues HEAD requests to Google, Microsoft, and GitHub identity endpoints from a single Python process — the same behavioral signature as an AI-driven pivot.

```bash
# MCP connector traffic simulation
python demo/demo_mcp_traffic.py

# IOC IP hit simulation (safe loopback default)
python demo/demo_ioc_hit.py
```

See `demo/README.md` for expected log output from each variant and troubleshooting if alerts don't fire.

> **Note:** If `python.exe` is in your `EGRESS_ALLOWLIST` in `config.py` (it is by default, for dev ergonomics), remove it before running the demo. OAuth chain rules bypass the generic egress allowlist in the current sprint — but confirm your config first.

---

## What's live today (Sprint 1)

### Event-based detection rules

| Rule | Fires when |
|------|------------|
| `OAUTH_PROVIDER_CONTACT` | Any non-browser process contacts an OAuth/identity endpoint |
| `OAUTH_PROVIDER_CHAIN` | Same process touches ≥2 distinct OAuth providers within 60s |
| `MCP_CONNECTOR_TRAFFIC` | Egress to `claude.ai/api/`, `api.anthropic.com/v1/messages`, or known MCP endpoints |
| `IOC_IP_MATCH` | Outbound connection to a known-bad IP |
| `PARALLEL_EXFIL` | Single process opens ≥N simultaneous outbound connections |
| `SHORT_LIVED_EGRESS` | Process connects outbound and exits in < 30s |
| `BASELINE_IP_DEVIATION` | Process connects to an IP absent from its trained baseline |
| `NEW_PROCESS_EGRESS` | First-ever outbound connection from a process not seen during training |

**Example alert:**

```
2026-05-04 01:14:22 WARNING [VIGIL] HIGH | OAUTH_PROVIDER_CHAIN | proc: python.exe(9182) | 10.0.0.5→accounts.google.com | 3 OAuth providers in 8.2s: accounts.google.com, login.microsoftonline.com, api.github.com
```

### Severity tiers

Alerts are classified `CRITICAL / HIGH / MEDIUM / LOW` based on rule type and context. `IOC_IP_MATCH` and `AI_AGENT_ESCALATION` are CRITICAL. `OAUTH_PROVIDER_CHAIN` from an unexpected process is HIGH. Generic egress deviations are MEDIUM or LOW depending on baseline confidence.

### Sprint 1 features shipping now

- **Severity tiers** — CRITICAL / HIGH / MEDIUM / LOW on all alert types
- **Opt-in firewall block** — on CRITICAL alerts, vigil can inject a Windows Defender Firewall outbound block rule for the offending remote IP (requires elevated process; opt-in via config)
- **Browser ancestry validation** — walks the parent process chain up to 3 levels via `psutil`; does not trust process name alone
- **Suffix-aware domain matching** — prevents bypass via subdomain crafting (e.g., `evil.accounts.google.com.attacker.io` does not match `accounts.google.com`)
- **Expanded provider coverage** — Okta, Auth0, AWS Cognito tenant patterns, Atlassian, Slack, Discord OAuth endpoints added to the provider set

---

## Install and run

**Requirements:** Python 3.11+, pip. Windows requires an elevated prompt for `psutil.net_connections(kind="inet")`.

### Bash / macOS / Linux

```bash
git clone https://github.com/matt82198/vigil
cd vigil
pip install -r requirements.txt
cp config.env.example config.env
# Edit config.env — set DISCORD_WEBHOOK_URL if you want push alerts

# Step 1: train a baseline (learn what normal looks like on this machine)
python netmon.py --train 1800

# Step 2: run the daemon
python netmon.py
```

### PowerShell / Windows

```powershell
git clone https://github.com/matt82198/vigil
Set-Location vigil
pip install -r requirements.txt
Copy-Item config.env.example config.env
# Edit config.env

# Train (30-minute baseline — run elevated for full connection visibility)
python netmon.py --train 1800

# Run
python netmon.py
```

### Install as a Windows background service

```powershell
# Elevated PowerShell
.\install.ps1
```

**First alert fires in under 60 seconds** if you have browser-less OAuth traffic on the machine right now. If you want to verify detection without waiting, run the demo.

---

## Why not Falco / Sysmon / Suricata / Wazuh / proxy-based MCP tools?

| Tool | What it does well | What it misses |
|------|------------------|----------------|
| **Falco** | Kernel syscall anomaly detection | Linux-only; no OAuth semantic awareness; `googleapis.com` egress is not anomalous at the syscall layer |
| **Sysmon** | Process and network event logging on Windows | Log-only, no detection logic; no concept of "same process touched N identity providers in 60s" |
| **Suricata** | High-throughput network IDS/IPS | Network-layer, not host-layer; no process-level context; HTTPS = opaque without full MITM |
| **Wazuh** | SIEM correlation across event sources | Aggregates events from other tools; not natively aware of OAuth chaining; not real-time process-level |
| **mcp-scan / agentauditkit** | Static config scanning, CI/CD | Detects at rest, not at runtime; no behavioral telemetry |
| **MCP-Defender** | Desktop GUI for MCP traffic blocking | GUI-first; no OAuth chain awareness; no behavioral scoring |
| **pipelock** | Runtime egress firewall + DLP | No process-level identity context; no OAuth chain correlation |

vigil's combination that no other tool in this table has: **host-resident + process-level context + OAuth semantic awareness + behavioral scoring**. It knows `python.exe` is not a browser. It knows which domains are identity providers. It can compute a behavioral score across multiple poll cycles and alert on the pattern, not just individual events.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        vigil daemon                          │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   scan.py    │    │  dns_cache   │    │  baseline.py │  │
│  │  psutil poll │───▶│  SNI/host    │───▶│  process     │  │
│  │  every 5s    │    │  enrichment  │    │  profiles    │  │
│  └──────┬───────┘    └──────────────┘    └──────┬───────┘  │
│         │                                        │          │
│         ▼                                        ▼          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    rules.py                          │   │
│  │  Pillar 1: C2 / beaconing detection                  │   │
│  │  Pillar 2: Baseline deviation                        │   │
│  │  Pillar 3: Identity / OAuth chain / MCP              │   │
│  │  Pillar 4: AI Behavior Score (ai_score.py)           │   │
│  └──────────────────────────┬───────────────────────────┘   │
│                             │                               │
│                             ▼                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                   alerter.py                         │   │
│  │  log file  │  Windows toast  │  Discord webhook      │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Roadmap

### Phase 1 — Implemented

- [x] Baseline training and deviation detection (IP, port, volume, new process)
- [x] IOC IP matching
- [x] OAuth provider contact and chain detection
- [x] MCP connector traffic detection
- [x] DNS enrichment via `dns_cache.py` (SNI hostname mapping)
- [x] Windows toast + Discord webhook alerting
- [x] 56-test suite with PS 5.1 regression coverage

### Sprint 1 — Shipping now

- [x] Severity tiers (CRITICAL / HIGH / MEDIUM / LOW) on all rule types
- [x] Opt-in firewall block on CRITICAL detections (Defender outbound rule injection)
- [x] Browser ancestry walk via `psutil.Process.parent()` — 3-level chain
- [x] Suffix-aware domain matching (prevents subdomain bypass)
- [x] Expanded provider coverage (Okta, Auth0, Cognito, Atlassian, Slack, Discord)
- [ ] DoH reverse-DNS fallback for host enrichment
- [ ] PID reuse eviction from connection tracking

### Sprint 2 — Next

- [ ] AI Behavior Score (`ai_score.py`) — per-process composite 0–100 with tier alerts
- [ ] `AI_AGENT_BEHAVIOR` and `AI_AGENT_ESCALATION` alert rules
- [ ] `AI_SCORE_RAPID_RISE` — alert on processes that ramp from 0 to ≥30 in a single window
- [ ] Score dashboard (TUI or HTML report)
- [ ] C2 beaconing detection (regular intervals, low-bandwidth keep-alives)
- [ ] DNS tunneling detection

### Phase 3 — Planned

- [ ] ETW/WFP hook for sub-poll-interval request timing (true sub-second CV)
- [ ] Pluggable identity provider config (add a provider in config, not code)
- [ ] Cross-machine alert correlation via shared log
- [ ] Process kill on `AI_AGENT_ESCALATION` (opt-in)

---

## Origin

In April 2026, an attacker with access to a compromised cloud account used a legitimate API session to silently register three MCP connectors — against Google Calendar, Gmail, and Google Drive — on a machine they did not control. No malware was dropped. No credentials were phished. The entire lateral move happened over legitimate HTTPS to legitimate Google APIs, at machine speed, while the machine sat idle. No IDS caught it. The only signal was in Certificate Transparency logs, found days later.

vigil was built to catch that class of attack in real time. The rules are not derived from a threat model — they are derived from the actual event sequence observed on a real host. That provenance is the reason the detection logic looks the way it does.

---

## Contributing

Issues and PRs welcome.

The most valuable contribution: if you have telemetry from an actual OAuth chaining incident (sanitized), open an issue with the event sequence. It directly informs the scoring rubric and rule thresholds.

The detection logic (`rules.py`, `ai_score.py`) and the data pipeline (`netmon.py`, `scan.py`) are intentionally separated. Adding a rule means adding a function to `rules.py` and wiring it in `run_poll()`. Adding an identity provider means extending `OAUTH_PROVIDERS` in `config.py` — no code changes.

---

## License

MIT. Use it, fork it, embed it in your own tooling.

---

## Disclaimer

Defensive use only. Do not deploy on systems you do not own or have explicit authorization to monitor.
