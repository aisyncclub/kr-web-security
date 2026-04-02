# kr-web-security

대한민국 웹사이트 보안 매뉴얼 + 자동 점검 에이전트

커뮤니티 / 발주·주문 관리 / 고객 DB 보유 사이트 기준

## 구조

```
manual/           보안 매뉴얼 (법적의무~OWASP 매핑)
  checklist.yaml  machine-readable 체크리스트
agent/scripts/    자동 점검 스크립트 (Bun/TypeScript)
  header-check.ts HTTP 보안 헤더 점검
  code-scan.ts    코드 정적 분석 (checklist.yaml 연동)
  dep-audit.ts    의존성 취약점 점검
  report-gen.ts   통합 리포트 생성
examples/         실제 사고 사례
```

## 사용법

### HTTP 헤더 점검
```bash
bun agent/scripts/header-check.ts https://example.com
```

### 코드 스캔
```bash
bun agent/scripts/code-scan.ts /path/to/project
```

### 의존성 점검
```bash
bun agent/scripts/dep-audit.ts /path/to/project
```

### 전체 점검 (헤더 + 코드 + 의존성 → 통합 리포트)
```bash
bun agent/scripts/header-check.ts https://example.com
bun agent/scripts/code-scan.ts /path/to/project
bun agent/scripts/dep-audit.ts /path/to/project
bun agent/scripts/report-gen.ts "https://example.com + /path/to/project"
```

### Claude Code 에이전트로 사용
```
/security-check https://example.com
/security-check /path/to/project
```

## 기준
- OWASP Top 10 (2021)
- 개인정보보호법
- 전자상거래법
- KISA 가이드
