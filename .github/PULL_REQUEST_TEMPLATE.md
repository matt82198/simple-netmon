## Summary

<!-- What does this PR do? 1-2 sentences. -->

<!-- Example: Adds OAUTH_PROVIDER_CHAIN rule to detect rapid sequential contact to ≥2 distinct OAuth endpoints within 60s window, with severity tiering based on whether the process has browser ancestry. -->

## Pillar(s) advanced

- [ ] C2 implant detection
- [ ] Real-time defense
- [ ] Managed identity monitoring
- [ ] AI-behavior detection

## Risk notes

<!-- Any detection logic changes, new config knobs, or changes to alerting format? Mention them here. -->

<!-- Example: This rule has high FP potential on multi-tenant environments where service accounts legitimately reach 2+ identity providers. Suggest setting OAUTH_CHAIN_THRESHOLD=3 on those systems. -->

## Testing notes

<!-- How did you verify this works? Run the test suite? Add new tests? Test against a live system? -->

## Checklist

- [ ] Tests added/updated and passing locally (`pytest tests/ -v`)
- [ ] No personal IOCs (IPs, hostnames, domains) added to defaults in `config.py` or `rules.py`
- [ ] CHANGELOG.md updated for user-facing changes (new rules, config knobs, alert format)
- [ ] Security implications considered:
  - [ ] Could this rule create new false positives in prod?
  - [ ] Could any defender action (kill, firewall block) break legitimate workflows?
  - [ ] Any new external data source (IOC list, provider domain list) added? Documented source/refresh SLA?

---

**Questions?** See CONTRIBUTING.md for guidelines on rule severity, identity provider additions, and pillar alignment.
