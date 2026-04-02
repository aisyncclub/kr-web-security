# 🛡️ web-security-check

> Actionable web security checklist with automated scanning scripts + Claude Code agent

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-ASVS%20L1-blue)](https://owasp.org/www-project-application-security-verification-standard/)
[![Bun](https://img.shields.io/badge/Bun-TypeScript-black)](https://bun.sh)

**What makes this different from other security checklists?**

| Feature | Docs-only checklists | Heavy scanners (ZAP/Nuclei) | **This project** |
|---------|---------------------|---------------------------|-----------------|
| Checklist | ✅ | ❌ | ✅ YAML (machine-readable) |
| Auto scan | ❌ | ✅ | ✅ Lightweight (Bun) |
| AI Agent | ❌ | ❌ | ✅ Claude Code `/security-check` |
| Compliance modules | ❌ | ❌ | ✅ KR/EU/US |
| SDLC phases | Rare | ❌ | ✅ Design→Dev→Launch→Ops |
| Setup time | 0 | 30min+ | **< 1 min** |

---

## Quick Start

```bash
git clone https://github.com/aisyncclub/kr-web-security.git
cd kr-web-security && bun install
```

### Scan a URL (HTTP headers)
```bash
bun agent/scripts/header-check.ts https://example.com
```

### Scan a project (code + dependencies)
```bash
bun agent/scripts/code-scan.ts /path/to/project
bun agent/scripts/dep-audit.ts /path/to/project
```

### Generate report
```bash
bun agent/scripts/report-gen.ts "target name"
```

### Use with Claude Code
```
/security-check https://example.com
/security-check /path/to/project
```

---

## What It Checks

### HTTP Headers (11 checks)
HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HTTPS redirect, Cookie flags, Server header, X-Powered-By, CORS

### Code Scan (18 patterns)
SQL Injection, XSS, Command Injection, SSRF, Hardcoded secrets, eval(), Weak hashing (MD5/SHA1), Math.random(), Path traversal, Log sensitive data, and more

### SDLC Checklist (30+ items across 4 phases)
Design → Development → Pre-Launch → Operations

### Compliance Modules
| Module | Law | Items |
|--------|-----|-------|
| `compliance/kr/` | Korea PIPA | 9 |
| `compliance/eu/` | EU GDPR | 7 |
| `compliance/us/` | US CCPA | 5 |

---

## Project Structure

```
├── manual/
│   ├── checklist.yaml          # Core checklist (OWASP-based, 45 items)
│   └── sdlc-checklist.yaml     # SDLC phase checklist (30+ items)
├── compliance/{kr,eu,us}/      # Country-specific regulations
├── agent/scripts/              # Scanning scripts (Bun/TypeScript)
│   ├── header-check.ts         # HTTP security headers
│   ├── code-scan.ts            # Static code analysis
│   ├── dep-audit.ts            # Dependency vulnerabilities
│   └── report-gen.ts           # Markdown report generator
├── .claude/skills/             # Claude Code skill definition
└── examples/incidents/         # Anonymized security incidents
```

## Customize

Add patterns to `manual/checklist.yaml`:
```yaml
- id: custom-001
  title: "No console.log in production"
  severity: low
  check_type: code_scan
  pattern: "console\\.log\\("
```

Add country compliance in `compliance/{code}/checklist.yaml`.

---

## CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Check
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2
      - run: |
          git clone https://github.com/aisyncclub/kr-web-security.git /tmp/sec
          cd /tmp/sec && bun install
          bun agent/scripts/code-scan.ts $GITHUB_WORKSPACE
          bun agent/scripts/dep-audit.ts $GITHUB_WORKSPACE
```

---

## Report Example

```
# Security Check Report

| Result | Count |
|--------|-------|
| ✅ PASS | 28 |
| ❌ FAIL | 3 |
| ⚠️ WARN | 5 |
| ⏭️ SKIP | 9 |

## ❌ FAIL Items
| ID | Item | Detail |
|----|------|--------|
| cr-005 | Hardcoded secret | src/config.ts:10 |
| hdr-002 | Missing CSP | No Content-Security-Policy |
```

---

## Contributing

PRs welcome! You can contribute:
- New checklist items
- Better scan patterns (reduce false positives)
- New compliance modules (JP, AU, BR, etc.)
- Translations

## About

Built by **[AI Sync Club](https://litt.ly/aisyncclub)** — AI + Commerce community | [Portfolio](https://portfolio.aisyncclub.com/)

## License

MIT
