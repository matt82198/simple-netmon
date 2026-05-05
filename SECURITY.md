# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest minor | yes |
| Older releases | no |

This is a small project with rapid iteration. Only the latest minor version receives security updates.

## Reporting a Vulnerability

Please report security vulnerabilities in one of two ways:

1. **GitHub Private Vulnerability Reporting** (preferred)
   - Use the Security tab → "Report a vulnerability" on this repository

2. **Email** (if you prefer)
   - See the repository profile for a security contact email

**Do not open public issues for security vulnerabilities.**

## What to Include

When reporting, please provide:
- Clear description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact and attack scenario
- Suggested fix or mitigation (if you have one)

## Response Timeline

- **Acknowledgment**: Within 72 hours
- **Fix or mitigation plan**: Within 30 days for high-severity issues
- **Public disclosure**: Coordinated 90-day default, or sooner if exploit is actively in the wild

## Scope

**In scope:**
- vigil daemon code and logic
- defender.py action execution
- OAuth 2.0 / MCP rule evaluation and detection

**Out of scope:**
- False positives in detection rules (use the issue tracker instead)
- User's host security posture or configuration guidance (ask the community)

## Hall of Fame

With your permission, we credit security researchers in the CHANGELOG. Request anonymity if preferred.

## Important Note

**vigil is a defensive security tool.** Do not use the public issue tracker to share live attacker IOCs, active threat indicators, or zero-day exploitation details. Use private channels for sensitive threat intel.

---

For questions, open a discussion or contact via private vulnerability report.
