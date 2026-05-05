# vigil Demo Scripts

Safe demonstration scripts for vigil detection rules. Each script simulates attacker behavior with **zero credential submission**, **HEAD/GET requests only**, and **no authentication flows**.

## Installation

```bash
pip install -r requirements.txt
```

## Scripts

### `demo_oauth_chain.py` — OAuth Provider Chain Detection

Simulates an AI agent pivoting across OAuth identity providers in rapid sequence.

**What it does:**
- Sends HEAD requests to: `accounts.google.com`, `login.microsoftonline.com`, `api.github.com`, `oauth2.googleapis.com`
- Completes in ~2 seconds
- No credentials submitted, no OAuth flow initiated

**Expected alert:**
- `OAUTH_PROVIDER_CHAIN` — 3+ distinct OAuth providers contacted in <5s
- `OAUTH_PROVIDER_CONTACT` — individual provider contact alerts

**Usage:**
```bash
python demo_oauth_chain.py              # run the demo
python demo_oauth_chain.py --dry-run    # preview requests without sending
```

**Example output:**
```
[DEMO] OAuth Provider Chain Simulation
[DEMO] Sending HEAD requests to 4 OAuth providers in rapid sequence (<2s)
[DEMO] Expected alert: OAUTH_PROVIDER_CHAIN in netmon.log

  [accounts.google.com] HEAD https://accounts.google.com/ -> 200 (120ms)
  [login.microsoftonline.com] HEAD https://login.microsoftonline.com/common -> 200 (105ms)
  [api.github.com] HEAD https://api.github.com/user/repos -> 401 (95ms)
  [oauth2.googleapis.com] HEAD https://oauth2.googleapis.com/token -> 405 (110ms)

[DEMO] Completed in 2.1s
[DEMO] Check netmon.log for OAUTH_PROVIDER_CHAIN alert (within 5–10s)
```

**Note:** Alert may be suppressed if `python.exe` is in the `EGRESS_ALLOWLIST` in config (a known limitation — the allowlist is intended to suppress generic egress noise, not semantic rules like OAuth chains).

---

### `demo_mcp_traffic.py` — MCP Connector Traffic Detection

Simulates unauthorized MCP connector registration to Anthropic infrastructure.

**What it does:**
- Sends HEAD/GET requests to: `claude.ai/`, `claude.ai/api/mcp/connectors`, `api.anthropic.com/v1/messages`
- Completes in ~1 second
- No credentials submitted, expects 401/403 responses (normal for unauthenticated API calls)

**Expected alert:**
- `MCP_CONNECTOR_TRAFFIC` — egress to Anthropic MCP endpoints from non-approved process

**Usage:**
```bash
python demo_mcp_traffic.py              # run the demo
python demo_mcp_traffic.py --dry-run    # preview requests without sending
```

**Example output:**
```
[DEMO] MCP Connector Traffic Simulation
[DEMO] Sending requests to Anthropic/Claude infrastructure endpoints
[DEMO] Expected alert: MCP_CONNECTOR_TRAFFIC in netmon.log

  [claude.ai] HEAD https://claude.ai/ -> 200 (85ms)
  [claude.ai/api] GET https://claude.ai/api/mcp/connectors -> 403 (90ms)
  [api.anthropic.com] HEAD https://api.anthropic.com/v1/messages -> 401 (80ms)

[DEMO] Completed in 0.9s
[DEMO] Check netmon.log for MCP_CONNECTOR_TRAFFIC alert (within 5–10s)
```

---

### `demo_ioc_hit.py` — IOC IP Hit Detection

Simulates connection to a known attacker IP from the IOC list.

**What it does:**
- Sends a HEAD request to a specified IP address
- **By default uses `127.0.0.2`** (a loopback variant) — safe, won't reach any real host
- Users can override with `--ip` to test against actual IOC IPs from their config
- Completes in <5 seconds (timeout per request)

**Expected alert:**
- `IOC_IP_MATCH` — connection to IP in `IOC_IPS` config (only if `--ip` points to a configured IOC)

**Usage:**
```bash
python demo_ioc_hit.py                  # use safe default (127.0.0.2, no alert expected)
python demo_ioc_hit.py --ip <your-ioc-ip>   # test against an IOC from your config
python demo_ioc_hit.py --ip <IP> --dry-run  # preview request without sending
```

**Example output (safe default):**
```
[DEMO] IOC IP Hit Simulation
[DEMO] Using safe loopback default (127.0.0.2)
[DEMO] Connection will fail, but vigil will NOT alert (not in IOC_IPS by default)
[DEMO] To test real IOC detection:
[DEMO]   1. Add IOC IP to vigil config IOC_IPS
[DEMO]   2. Run: python demo_ioc_hit.py --ip <your-ioc-ip>

[DEMO] Connecting to 127.0.0.2:443 (HEAD request)...
  [IOC_HIT] HEAD https://127.0.0.2:443/ -> CONNECTION REFUSED (expected for 127.0.0.2) (45ms)

[DEMO] Completed
[DEMO] (No alert expected — 127.0.0.2 is not configured as IOC)
```

**To test with real IOC IPs:**

1. Add an IOC IP to `IOC_IPS` in your `config.env`
2. Run: `python demo_ioc_hit.py --ip <your-ioc-ip>`
3. Within 5–10s, you should see `IOC_IP_MATCH` in `netmon.log`

---

## Running the Full Demo Sequence

To demonstrate all three rule families in one test:

```bash
# Terminal 1: Start vigil (if not already running)
python netmon.py

# Terminal 2: Run all three demos in sequence
python demo_oauth_chain.py     # ~2s
python demo_mcp_traffic.py     # ~1s
python demo_ioc_hit.py         # ~5s (timeout per request)
```

**Expected log output (in `netmon.log`):**
```
2026-05-04 14:22:10 WARNING [VIGIL] MEDIUM | OAUTH_PROVIDER_CONTACT | proc: python.exe(9182) | ...
2026-05-04 14:22:11 WARNING [VIGIL] HIGH | OAUTH_PROVIDER_CHAIN | proc: python.exe(9182) | ...
2026-05-04 14:22:13 WARNING [VIGIL] HIGH | MCP_CONNECTOR_TRAFFIC | proc: python.exe(9182) | ...
```

---

## Safety Guarantees

- No credentials submitted — HEAD/GET requests only, no Authorization headers, no form data
- No real OAuth flow — no `code`, `token`, `client_id`, `client_secret` in any request
- No auth interaction — 401/403 responses are expected and ignored
- All targets are public infrastructure — Google, Microsoft, GitHub, Anthropic
- IOC default is safe — `127.0.0.2` loopback won't reach any real host
- No persistence — scripts exit immediately, no daemons or loops
- Fail-soft — network errors are logged and ignored, no crash
- Transparent — all requests printed to stdout before sending
- Dry-run mode — `--dry-run` flag allows safe preview without network access

---

## Troubleshooting

### "OAUTH_PROVIDER_CHAIN alert did not fire"

1. Verify vigil is running: `python netmon.py`
2. Wait 30+ seconds after starting vigil (warmup period, default `WARMUP_POLLS=5` × 5s = 25s)
3. Check if `python.exe` is in `EGRESS_ALLOWLIST` — if yes, OAuth chain rules may be suppressed (known limitation)
   - **Workaround**: Run demo from a virtual environment with a different interpreter name, or temporarily remove `python.exe` from allowlist
4. Tail the vigil log: `Get-Content -Tail 50 -Wait netmon.log` (Windows) or `tail -f netmon.log`

### "MCP_CONNECTOR_TRAFFIC alert did not fire"

1. Verify vigil is running
2. Confirm `claude.ai` is in the MCP provider list in `config.py`
3. Check netmon.log for any parse or rule evaluation errors

### "IOC_IP_MATCH alert did not fire"

1. Verify you're using `--ip` to specify an IOC IP from your config
2. Confirm the IOC IP is in `IOC_IPS` in `config.env`
3. Default `127.0.0.2` won't trigger an alert (intentional safety measure)

---

## Known Limitations

- **Python process allowlisting**: By default, `python.exe` is in `EGRESS_ALLOWLIST` for dev ergonomics. This may suppress OAuth and MCP alerts for Python scripts. Workaround: run the demo from a venv with a renamed interpreter, or remove `python.exe` from the allowlist.
- **Windows vs. Linux process naming**: Process name visible to vigil depends on how Python is invoked — may appear as `python.exe`, `python`, or the virtual environment name.

---

## Contributing / Extending

Future demo variants (not in this version):

- **Variant D — Beaconing**: Regular 30s intervals to a test server (C2 detection)
- **Variant E — Baseline deviation**: Spawn process connecting to unseen IP (baseline deviation detection)
- **Variant F — AI Behavior Score**: Real-time score display demo (Sprint 2)

---

## Questions?

See the main vigil documentation or raise an issue in the repo.
