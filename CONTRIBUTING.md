# Contributing

Thank you for your interest in contributing!

## How to Contribute

### Add Checklist Items
Edit `manual/checklist.yaml` and add items following this format:
```yaml
- id: your-id
  title: "Short title"
  description: "What to check"
  severity: critical|high|medium|low
  check_type: code_scan|http_header|manual|dependency
  pattern: "regex pattern"  # for code_scan only
  owasp: "A01:2021"         # optional
```

### Add Compliance Modules
Create `compliance/{country_code}/checklist.yaml`:
```yaml
module: xx
name: "Country Name (Law)"
items:
  - id: xx-001
    title: "Requirement"
    law: "Law Article X"
    severity: critical
    check_type: manual
```

### Improve Scan Patterns
- Reduce false positives in `agent/scripts/code-scan.ts`
- Add new header checks in `agent/scripts/header-check.ts`

### Add Incident Examples
Create `examples/incidents/YYYY-MM-DD-description.md` (anonymized).

## Guidelines
- Keep items actionable and specific
- Include OWASP mapping where applicable
- Anonymize all incident reports
- Test scan scripts before submitting
