---
name: security-check
description: "웹사이트/프로젝트 보안 자동 점검. URL로 HTTP 헤더 점검, 프로젝트 경로로 코드 정적 분석 + 의존성 취약점 점검. OWASP Top 10 + 개인정보보호법 기준 PASS/FAIL 리포트 생성."
argument-hint: "<URL 또는 프로젝트 경로>"
allowed-tools:
  - Read
  - Bash
  - Glob
  - Grep
  - Write
---

# 보안 점검 에이전트

## 개요
대한민국 웹사이트 보안 체크리스트(kr-web-security) 기반으로 자동 점검을 수행합니다.

## 스크립트 위치
프로젝트: `/Users/firstandre/dev_test_file/kr-web-security`

## 실행 흐름

### 1. 인자 파싱
- URL (http/https로 시작) → HTTP 헤더 점검 모드
- 경로 (/ 로 시작) → 코드 스캔 + 의존성 점검 모드
- URL + 경로 둘 다 → 전체 점검

### 2. URL 모드 (HTTP 헤더 점검)
```bash
bun /Users/firstandre/dev_test_file/kr-web-security/agent/scripts/header-check.ts <URL>
```
점검 항목: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HTTPS 리다이렉트, 쿠키 보안 플래그

### 3. 경로 모드 (코드 정적 분석)
```bash
bun /Users/firstandre/dev_test_file/kr-web-security/agent/scripts/code-scan.ts <PATH>
bun /Users/firstandre/dev_test_file/kr-web-security/agent/scripts/dep-audit.ts <PATH>
```
점검 항목: SQL Injection 패턴, XSS, Command Injection, 하드코딩된 시크릿, eval 사용, 취약한 해시, 의존성 CVE

### 4. 리포트 생성
```bash
bun /Users/firstandre/dev_test_file/kr-web-security/agent/scripts/report-gen.ts <대상>
```
결과: 마크다운 리포트 (PASS/FAIL/WARN/SKIP 항목별 정리)

## 주의사항
- 외부 URL 점검 시 봇 탐지가 있는 사이트는 차단될 수 있음
- code_scan은 정규식 기반이므로 false positive 가능 → 사람 확인 필요
- `check_type: manual` 항목은 자동 점검 불가 → 수동 확인 안내
- 점검 결과는 /tmp/ 에 JSON으로 저장됨

## 체크리스트 기준
`/Users/firstandre/dev_test_file/kr-web-security/manual/checklist.yaml`

OWASP Top 10 (2021) + 개인정보보호법 + 전자상거래법 + KISA 가이드 기반
