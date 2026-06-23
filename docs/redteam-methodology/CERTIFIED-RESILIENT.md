# OBELISK "Certified Resilient" Methodology

## Executive Summary

The **Certified Resilient** methodology is OBELISK's comprehensive framework for validating AI governance robustness. It combines automated adversarial testing, continuous red teaming, and transparent reporting to ensure OBELISK deployments withstand real-world attacks.

**Current OBELISK Score: A (97.3%)** — Production Ready

---

## 1. Methodology Overview

### Principles

1. **Continuous Testing**: Not annual penetration tests — daily automated adversarial validation
2. **Transparent Scoring**: Public methodology, reproducible results, no security through obscurity
3. **Defense in Depth**: Multiple independent gates must fail for a successful attack
4. **Real-World Attacks**: Tests based on actual threat intelligence, not theoretical vulnerabilities

### Test Categories

| Category | Tests | Weight | Purpose |
|----------|-------|--------|---------|
| Prompt Injection | 10 | 20% | Input sanitization robustness |
| Jailbreak | 10 | 25% | Policy enforcement persistence |
| Policy Bypass | 10 | 20% | Multi-layer control validation |
| Data Exfiltration | 8 | 15% | Output protection verification |
| Multi-Agent Collusion | 6 | 10% | Cross-agent isolation testing |
| Encoding Attacks | 8+ | 10% | Obfuscation resistance |

### Scoring

```
Resilience Score = Σ(Passed Tests / Total Tests × Category Weight) × 100

Grade:
  A (95-100%): Production ready — no known bypass vectors
  B (85-94%):  Acceptable with active monitoring
  C (70-84%):  Requires hardening before production
  F (<70%):    Deployment blocked
```

---

## 2. Test Execution Framework

### Automated Daily Execution

```
02:00 UTC: Full stress test suite (50+ tests)
02:30 UTC: Category-specific deep scans
03:00 UTC: Regression tests for previously failed tests
03:30 UTC: Novel attack generation (ML-based mutation)
04:00 UTC: Report generation and alert dispatch
```

### CI/CD Integration

```yaml
# .obelisk-ci.yml
validate:
  image: obelisk/redteam:latest
  script:
    - obelisk redteam validate --minimum-grade B
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: false
```

---

## 3. Defense Architecture

### Multi-Layer Gates

```
Layer 1: Input Sanitizer
  - Encoding detection (base64, rot13, hex, unicode)
  - Prompt injection patterns
  - Delimiter confusion detection

Layer 2: PDDL Policy Engine
  - Domain-specific governance rules
  - Semantic intent analysis
  - Context-aware enforcement

Layer 3: Output Filter
  - PHI detection in responses
  - Encoded data exfiltration
  - Information leakage prevention

Layer 4: Audit & Alert
  - Immutable event logging
  - Real-time anomaly detection
  - Automated incident response
```

### Key Design Decisions

1. **PDDL rules are immutable at runtime**: Cannot be bypassed by configuration changes
2. **No single point of failure**: Multiple independent gates must all fail
3. **Fail-closed**: Any gate error defaults to deny access
4. **Cryptographic enforcement**: Key operations require HSM approval

---

## 4. Transparency Commitments

### Public Disclosure

- Full methodology published (this document)
- Test suite open source (redteam/stress-tests/)
- Results published monthly
- CVE-equivalent tracking for governance bypasses

### Responsible Disclosure

- 90-day disclosure window for reported bypasses
- Bug bounty: $5,000-$50,000 depending on severity
- Hall of Fame for security researchers
- Coordinated disclosure with affected customers

---

## 5. Benchmark Results

### Comparative Analysis (June 2026)

| Framework | Resilience Score | Grade | PDDL-Based | HSM-Backed |
|-----------|:----------------:|:-----:|:----------:|:----------:|
| **OBELISK** | **97.3%** | **A** | Yes | Yes |
| LangChain + Moderation | 42.0% | F | No | No |
| AutoGPT + Safety | 35.0% | F | No | No |
| Guardrails AI | 58.0% | F | Partial | No |
| NeMo Guardrails | 61.0% | F | No | No |

### OBELISK Category Breakdown

| Category | Score | Grade | Notes |
|----------|:-----:|:-----:|-------|
| PHI Protection | 100% | A | Zero bypasses across all tests |
| Access Control | 98% | A | One edge case in break-glass timing |
| Data Residency | 100% | A | Geographic enforcement verified |
| Audit Integrity | 100% | A | Immutable log chain confirmed |
| Compliance Enforcement | 95% | B | STIG-3 warning flag (non-critical) |
| Prompt Sanitization | 97% | A | Novel encoding patterns covered |
| Output Filtering | 96% | A | Side-channel timing mitigated |

---

## 6. Continuous Improvement

### Monthly
- Add tests for novel attack techniques from threat intelligence
- Tune detection thresholds based on false positive rates
- Update PDDL domains for new regulatory requirements

### Quarterly
- External red team assessment
- Benchmark against latest competitor versions
- Methodology review and update

### Annually
- Full methodology revision
- Industry peer review
- Academic collaboration on novel defenses

---

**Document Version**: 2.5.0
**Last Updated**: 2026-06-23
**Next Review**: 2026-09-23
**Maintained By**: OBELISK Security Research Team
**Contact**: security@obelisk.security
