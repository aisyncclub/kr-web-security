# kr-web-security

대한민국 웹사이트 보안 매뉴얼 + Claude Code 자동 점검 에이전트

> 커뮤니티 / 쇼핑몰 / B2B 발주 / 고객 DB 보유 사이트 기준
> OWASP Top 10 + 개인정보보호법 + 전자상거래법 + KISA 가이드

---

## 빠른 시작

### 1. 설치

```bash
# 프로젝트 클론
git clone https://github.com/aisyncclub/kr-web-security.git
cd kr-web-security
bun install

# Claude Code 글로벌 스킬로 등록
mkdir -p ~/.claude/skills/security-check
cp .claude/skills/security-check/SKILL.md ~/.claude/skills/security-check/SKILL.md
```

### 2. Claude Code에서 사용

```
# 현재 프로젝트 보안 점검
/security-check

# 특정 URL 헤더 점검
/security-check https://example.com

# 특정 프로젝트 코드 스캔
/security-check /path/to/project
```

### 3. CLI로 직접 사용

```bash
# HTTP 보안 헤더 점검
bun agent/scripts/header-check.ts https://example.com

# 코드 정적 분석
bun agent/scripts/code-scan.ts /path/to/project

# 의존성 취약점 점검
bun agent/scripts/dep-audit.ts /path/to/project

# 통합 리포트 생성 (위 3개 실행 후)
bun agent/scripts/report-gen.ts "대상 이름"
```

---

## 프로젝트 구조

```
kr-web-security/
├── manual/                    # 보안 매뉴얼
│   ├── checklist.yaml         # 체크리스트 (52항목, machine-readable)
│   ├── 01-legal.md            # 법적 의무 (개인정보보호법, 전자상거래법)
│   └── research-*.md          # 리서치 원본 데이터
│
├── agent/scripts/             # 자동 점검 스크립트
│   ├── header-check.ts        # HTTP 보안 헤더 점검 (8항목)
│   ├── code-scan.ts           # 코드 정적 분석 (18패턴)
│   ├── dep-audit.ts           # 의존성 취약점 점검
│   └── report-gen.ts          # 통합 마크다운 리포트 생성
│
├── .claude/skills/            # Claude Code 스킬 정의
│   └── security-check/
│       └── SKILL.md
│
├── examples/incidents/        # 실제 보안 사고 사례
│   └── 2026-04-02-adminplus.md
│
└── package.json
```

---

## 점검 항목 상세

### HTTP 헤더 점검 (header-check.ts)

URL을 입력하면 응답 헤더를 분석하여 보안 설정을 점검합니다.

| # | 점검 항목 | 기대 값 | OWASP |
|---|----------|---------|-------|
| 1 | HSTS (Strict-Transport-Security) | max-age=31536000 이상 | A05 |
| 2 | CSP (Content-Security-Policy) | default-src 정책 설정 | A05 |
| 3 | X-Frame-Options | DENY 또는 SAMEORIGIN | A05 |
| 4 | X-Content-Type-Options | nosniff | A05 |
| 5 | Referrer-Policy | strict-origin-when-cross-origin | A05 |
| 6 | Permissions-Policy | camera=(), microphone=() 등 | A05 |
| 7 | HTTPS 리다이렉트 | HTTP→HTTPS 301 | A02 |
| 8 | 쿠키 보안 플래그 | Secure; HttpOnly; SameSite | A05 |

**출력 예시:**
```
🔍 HTTP 보안 헤더 점검: https://example.com

✅ [srv-001] HSTS
   현재: max-age=31536000; includeSubDomains
   기대: max-age=31536000 이상

❌ [srv-002] CSP
   현재: 없음
   기대: default-src 정책 설정

📊 결과: PASS 5 / FAIL 2 / WARN 1 / SKIP 0
```

---

### 코드 정적 분석 (code-scan.ts)

프로젝트 경로의 TypeScript/JavaScript 파일을 스캔하여 보안 취약점 패턴을 탐지합니다.
`checklist.yaml`의 `check_type: code_scan` 항목과 자동 연동됩니다.

| 카테고리 | 탐지 패턴 | 심각도 |
|----------|----------|--------|
| **SQL Injection** | 템플릿 리터럴 내 직접 변수 삽입 | CRITICAL |
| **XSS** | innerHTML, dangerouslySetInnerHTML, document.write | CRITICAL |
| **Command Injection** | exec/spawn에 사용자 입력 전달 | CRITICAL |
| **SSRF** | 사용자 입력 URL로 fetch 호출 | HIGH |
| **하드코딩된 시크릿** | api_key=, password=, secret= 패턴 | CRITICAL |
| **eval 사용** | eval(), new Function() | HIGH |
| **취약한 해시** | MD5, SHA1 (비밀번호용) | CRITICAL |
| **안전하지 않은 랜덤** | Math.random() | MEDIUM |
| **주민번호 수집** | 주민번호/resident_number 패턴 | CRITICAL |
| **카드번호 저장** | card_number, cvv 패턴 | CRITICAL |
| **API 키 노출** | APIKEY, SECRET_KEY 하드코딩 | HIGH |
| **파일 업로드** | multer/upload/formidable 사용 시 | CRITICAL |

**출력 예시:**
```
🔍 코드 정적 분석: /path/to/project
체크리스트 로드: 14개 패턴

🔴 CRITICAL (A02:2021) [pay-002] API 키 환경변수 관리 — 1건
   src/config.ts:10  const API_KEY = 'AIzaSy...';

🟠 HIGH (A02:2021) [dep-003] 안전한 랜덤 생성 — 3건
   src/utils.ts:45  const id = Math.random().toString(36);

--- 심각도별 합계 ---
  CRITICAL: 1
  HIGH: 3
```

> **참고:** 정규식 기반이므로 false positive가 발생할 수 있습니다. 결과는 사람이 검토하세요.

---

### 의존성 취약점 점검 (dep-audit.ts)

`package.json`을 분석하여 알려진 취약점이 있는 패키지를 찾습니다.

```
🔍 의존성 취약점 점검: /path/to/project
   총 패키지: 45개

📊 취약점 현황:
   CRITICAL: 0
   HIGH:     1
   MODERATE: 3
   LOW:      2

상세:
   HIGH: lodash — Prototype Pollution
   MODERATE: express — Open Redirect
```

---

### 통합 리포트 (report-gen.ts)

위 3개 스크립트의 결과를 합쳐서 마크다운 리포트를 생성합니다.

```
# 보안 점검 리포트

| 항목 | 내용 |
|------|------|
| 점검일 | 2026-04-03 |
| 대상 | https://example.com + /path/to/project |
| 기준 | kr-web-security checklist v1.0 |

## 요약
| 결과 | 건수 |
|------|------|
| ✅ PASS | 23 |
| ❌ FAIL | 5 |
| ⚠️ WARN | 3 |
| ⏭️ SKIP (수동) | 21 |

## ❌ FAIL 항목 (즉시 조치 필요)
| ID | 항목 | 상세 |
|----|------|------|
| pay-002 | API 키 환경변수 관리 | src/config.ts:10 하드코딩 |
| srv-002 | CSP 헤더 | 미설정 |
...
```

---

## 체크리스트 커스터마이즈

`manual/checklist.yaml`을 수정하면 code-scan이 자동으로 반영합니다.

```yaml
# 새 패턴 추가 예시
- id: custom-001
  title: "console.log 제거"
  description: "프로덕션 코드에서 console.log 사용 금지"
  severity: low
  check_type: code_scan
  pattern: "console\\.log\\("
  owasp: null
```

---

## 체크리스트 카테고리 (52항목)

| 카테고리 | 항목 수 | 자동 점검 |
|----------|---------|----------|
| 법적 의무 | 6 | 일부 (code_scan) |
| 인증/접근 제어 | 7 | HTTP 헤더 + code_scan |
| 인젝션/봇 방어 | 6 | code_scan |
| 고객 DB 보안 | 5 | code_scan |
| 서버/인프라 | 7 | HTTP 헤더 |
| 모니터링/로깅 | 4 | 수동 |
| 결제/발주 특화 | 3 | code_scan |
| AI 자동화 보안 | 3 | 수동 |
| 파일 업로드 보안 | 4 | code_scan + 수동 |
| 커뮤니티 특화 | 2 | code_scan |
| B2B 발주 특화 | 3 | code_scan + 수동 |
| 의존성 관리 | 3 | dependency + code_scan |

---

## 매뉴얼 문서

| 문서 | 내용 |
|------|------|
| `manual/01-legal.md` | 개인정보보호법 조항별 상세, 전자상거래법, 과징금 사례 6건 |
| `manual/checklist.yaml` | 전체 52항목 machine-readable 체크리스트 |
| `manual/research-*.md` | 리서치 원본 (법규, 커뮤니티/쇼핑몰/B2B 특화 보안) |
| `examples/incidents/` | 실제 보안 사고 사례 (AdminPlus 2026-04-02) |

---

## 한국 과징금 주요 사례

| 시기 | 기업 | 유출 규모 | 과징금 |
|------|------|-----------|--------|
| 2023 | 카카오 | 오픈채팅 | 151억원 |
| 2023 | LG유플러스 | 30만명 | 68억원 |
| 2024 | 골프존 | 221만명 | 75억원 |
| 2024 | 전북대학교 | 32만명 | 6.2억원 |
| 2025 | SK텔레콤 | 2,324만명 | 1,347억원 |
| 2025 | 쿠팡 | 3,370만 계정 | ~1조원 예상 |

> **소규모 사업자도 수천만원 과태료 부과 사례 존재.**

---

## 기여

체크리스트 항목 추가, 탐지 패턴 개선, 사고 사례 추가 등 PR 환영합니다.

## 라이선스

Private repository. 내부 사용 전용.
