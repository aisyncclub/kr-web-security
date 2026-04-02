# web-security-check

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-ASVS%20L1-blue)](https://owasp.org/www-project-application-security-verification-standard/)
[![Bun](https://img.shields.io/badge/runtime-Bun-black)](https://bun.sh)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-skill-purple)](https://claude.ai/code)

[English](README.en.md) | 한국어

범용 웹 보안 점검 도구 + Claude Code 에이전트

> OWASP ASVS L1 + CWE Top 25 + SDLC 단계별 + 국가별 규정 모듈 (KR/EU/US)

---

## 빠른 시작

### 설치

```bash
git clone https://github.com/aisyncclub/kr-web-security.git
cd kr-web-security
bun install

# Claude Code 글로벌 스킬 등록
mkdir -p ~/.claude/skills/security-check
cp .claude/skills/security-check/SKILL.md ~/.claude/skills/security-check/SKILL.md
```

### Claude Code에서 사용

```
/security-check                        # 현재 프로젝트 코드 스캔
/security-check https://example.com    # HTTP 헤더 점검
/security-check /path/to/project       # 특정 프로젝트 스캔
```

### CLI 직접 사용

```bash
bun agent/scripts/header-check.ts https://example.com
bun agent/scripts/code-scan.ts /path/to/project
bun agent/scripts/dep-audit.ts /path/to/project
bun agent/scripts/report-gen.ts "대상"
```

---

## 구조

```
web-security-check/
├── manual/
│   ├── checklist.yaml          # 범용 체크리스트 (OWASP 기반, 45항목)
│   └── 01-legal.md             # 법규 매뉴얼 (KR 기준)
│
├── compliance/                 # 국가별 규정 모듈
│   ├── kr/checklist.yaml       # 한국: PIPA + 전자상거래법 (9항목)
│   ├── eu/checklist.yaml       # EU: GDPR (7항목)
│   └── us/checklist.yaml       # US: CCPA/CPRA (5항목)
│
├── agent/scripts/              # 점검 스크립트
│   ├── header-check.ts         # HTTP 보안 헤더 (11항목)
│   ├── code-scan.ts            # 코드 정적 분석 (18패턴)
│   ├── dep-audit.ts            # 의존성 취약점
│   └── report-gen.ts           # 통합 리포트
│
├── examples/incidents/         # 익명화된 보안 사고 사례
└── .claude/skills/             # Claude Code 스킬 정의
```

---

## 점검 범위

### HTTP 헤더 (11항목)

| 헤더 | 점검 내용 | OWASP |
|------|----------|-------|
| HSTS | max-age=31536000 이상 | A05 |
| CSP | default-src 정책 | A05 |
| X-Frame-Options | DENY/SAMEORIGIN | A05 |
| X-Content-Type-Options | nosniff | A05 |
| Referrer-Policy | strict-origin | A05 |
| Permissions-Policy | 기능 제한 설정 | A05 |
| HTTPS 리다이렉트 | 301 to https | A02 |
| 쿠키 보안 | Secure; HttpOnly; SameSite | A05 |
| Server 헤더 | 버전 정보 숨김 | A05 |
| X-Powered-By | 제거 | A05 |
| CORS | 와일드카드(*) 금지 | A05 |

### 코드 스캔 (18패턴)

| 카테고리 | 패턴 | OWASP |
|----------|------|-------|
| SQL Injection | 문자열 연결 쿼리 | A03 |
| XSS | innerHTML, document.write | A03 |
| Command Injection | exec/spawn + 사용자 입력 | A03 |
| SSRF | 사용자 URL fetch | A03 |
| 하드코딩 시크릿 | api_key=, password=, secret= | A02 |
| eval | eval(), new Function() | A03 |
| 취약한 해시 | MD5, SHA1 | A02 |
| 안전하지 않은 랜덤 | Math.random() | A02 |
| 경로 순회 | path.join + req.params | A01 |
| HTML Sanitizer 미적용 | innerHTML, v-html | A03 |
| 로그 민감정보 | console.log + password/token | A09 |

### 국가별 규정 (모듈식)

| 국가 | 법규 | 항목 수 |
|------|------|---------|
| 🇰🇷 한국 | PIPA + 전자상거래법 | 9 |
| 🇪🇺 EU | GDPR | 7 |
| 🇺🇸 미국 | CCPA/CPRA | 5 |

---

## 체크리스트 커스터마이즈

`manual/checklist.yaml`을 수정하면 code-scan이 자동 반영:

```yaml
- id: custom-001
  title: "console.log 제거"
  severity: low
  check_type: code_scan
  pattern: "console\\.log\\("
  owasp: null
```

국가별 규정 추가는 `compliance/{국가코드}/checklist.yaml` 생성.

---

## CI/CD 통합 (권장)

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

## 리포트 예시

```
# 보안 점검 리포트

| 결과 | 건수 |
|------|------|
| ✅ PASS | 28 |
| ❌ FAIL | 3 |
| ⚠️ WARN | 5 |
| ⏭️ SKIP | 9 |

## ❌ FAIL 항목
| ID | 항목 | 상세 |
|----|------|------|
| cr-005 | 하드코딩 시크릿 | src/config.ts:10 |
| hdr-002 | CSP 미설정 | Content-Security-Policy 없음 |
| hdr-009 | X-Powered-By 노출 | Express |
```

---

## 라이선스

MIT
