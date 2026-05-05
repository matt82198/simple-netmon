# Contributing to vigil

Thank you for helping vigil catch AI-driven lateral movement. Contributions are welcome — here's how to get started.

## Development Setup

**Prerequisites**: Python 3.11+, pip, Windows/macOS/Linux

```bash
git clone https://github.com/matt82198/vigil
cd vigil
python -m venv venv
# On Windows: venv\Scripts\activate
# On macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov black  # For testing and formatting
```

## Running Tests

All tests live in `tests/`. Run the suite before submitting a PR:

```bash
pytest tests/ -v
pytest tests/ --cov=vigil  # Show coverage
```

## Adding a New Detection Rule

New rules live in `rules.py` and are wired into `netmon.py:run_poll()`.

### Rule structure

A rule is a function that takes a `ConnRecord` (active network connection) and returns an `Alert` or `None`:

```python
def check_new_rule(conn: ConnRecord, baseline: BaselineProfile, config: Config) -> Optional[Alert]:
    """
    Detect [threat pattern].

    Args:
        conn: Active network connection with process, IP, port, SNI hostname.
        baseline: Historical process/IP profile from training phase.
        config: Config with IOC IPs, OAuth domains, thresholds.

    Returns:
        Alert with severity, message, and detection reasoning — or None.
    """
    # Check your condition
    if conn.raddr[0] in config.ioc_ips:
        return Alert(
            rule="MY_RULE_NAME",
            severity="CRITICAL",
            proc_name=conn.proc_name,
            pid=conn.pid,
            src=f"{conn.laddr[0]}:{conn.laddr[1]}",
            dst=f"{conn.raddr[0]}:{conn.raddr[1]}",
            detail="Known C2 beacon.",
            timestamp=datetime.now(),
        )
    return None
```

### Severity tiering

- **CRITICAL**: Known IOC IP, confirmed C2 domain, immediate threat to Managed Identity (OAuth token leak in flight).
- **HIGH**: AI agent pattern (`AI_AGENT_ESCALATION`), parallel exfil, process behavior strongly inconsistent with baseline.
- **MEDIUM**: Deviation from baseline (new IP, new port), `AI_AGENT_BEHAVIOR` tier, unexpected identity provider contact.
- **LOW**: First-time egress from a benign process, informational deviations (DEBUG tier if noise expected).

Use `MEDIUM` when in doubt. Every rule that fires should be actionable without false-positive fatigue.

### TDD requirement

Every new rule **must** ship with at least one passing test:

```python
# tests/test_rules.py
def test_my_rule_fires_on_ioc_ip():
    from rules import ConnRecord, check_ioc_ip
    from datetime import datetime

    conn = ConnRecord(
        pid=1234, proc_name="python.exe",
        laddr=("10.0.0.5", 50000), raddr=("198.51.100.1", 8883),
        status="ESTABLISHED", first_seen=datetime.now(),
    )
    already: set[tuple[int, str]] = set()
    alerts = check_ioc_ip([conn], frozenset({"198.51.100.1"}), already)
    assert alerts and alerts[0].rule == "IOC_IP_MATCH"
    assert alerts[0].severity == "CRITICAL"
```

## Adding a New Identity Provider

If you need vigil to recognize a new OAuth provider (e.g., Auth0, Okta, Cognito):

1. Add the provider domain(s) to `config.py:_DEFAULT_OAUTH_PROVIDER_DOMAINS`:
   ```python
   _DEFAULT_OAUTH_PROVIDER_DOMAINS: frozenset[str] = frozenset({
       "accounts.google.com",
       "login.microsoftonline.com",
       "api.github.com",
       "auth.example.com",  # Your new provider
   })
   ```

2. Test the chain detection by adding a test case in `tests/test_oauth_rules.py`.

3. Consider the suffix-matching strategy: if your provider has many subdomains (e.g., `tenant.okta.com`), the suffix match (`domain.endswith("." + p)`) already handles this if you add the root (`okta.com`).

## Proposing a Major Feature or Pillar Expansion

If you want to propose a new detection pillar (e.g., DNS tunneling, process-tree analysis), **open an issue first**. Do not submit a PR. This helps the project converge on design before implementation.

The four pillars are:
1. **C2 implant detection** — beaconing, DNS tunneling, domain fronting.
2. **Real-time defense** — firewall injection, process kill on high-confidence detections.
3. **Managed identity monitoring** — lateral movement via OAuth chains and cross-identity account activity.
4. **AI-behavior detection** — agent-paced request cadence, MCP traffic from non-AI processes, OAuth without browser ancestry.

New features should advance one of these pillars rather than only widening OAuth coverage. Issues help clarify which pillar and how.

## Code style

- **Python**: PEP 8. Type hints encouraged (especially for public functions).
- **Formatting**: Black is optional but recommended.
- **Comments**: Explain the "why" (threat model, false positive concern) not the "what."
- **Logging**: Use `logger.info()`, `logger.warning()`, `logger.debug()` — not print statements.

## PR review SLA

Best-effort review within **≤7 days** for security-relevant changes (new rules, identity monitoring, or detection logic). Non-critical bug fixes and docs may take longer. If your PR is time-sensitive, mention it in the description.

## Changelog

For user-facing changes (new rules, config knobs, alert format changes), update `CHANGELOG.md` in the root with a brief bullet point describing what changed and which pillar it advances.

---

**Questions?** Open an issue or reach out. vigil is built from a real incident — the more detail you can share about your threat model or detection need, the better the PR.
