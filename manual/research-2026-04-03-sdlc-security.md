# 웹사이트 빌딩 전 과정 보안 체크 프로세스 리서치 보고서

> 조사일: 2026-04-01 | 깊이: Deep (2-Pass, 12+ 소스 전문 분석)

---

## TL;DR (3줄 요약)

1. **보안은 런칭 전 점검이 아니라 설계 단계부터 시작**해야 하며, OWASP Secure SDLC + STRIDE 위협 모델링이 업계 표준이다.
2. **Next.js/React 생태계의 2025-2026년 치명적 취약점(CVE-2025-29927, CVE-2025-66478)**이 발견되었으므로, 미들웨어를 보안 경계로 사용하지 말고 모든 핸들러에서 독립적으로 인증을 검증해야 한다.
3. **자동화 가능한 보안 체크가 전체의 약 70%**이며, CI/CD 파이프라인에 SAST/DAST/SCA를 통합하면 대부분의 일반적 취약점을 사전에 차단할 수 있다.

---

## 목차

1. [개발 단계별 보안 체크리스트](#1-개발-단계별-보안-체크리스트)
2. [프레임워크별 보안 가이드](#2-프레임워크별-보안-가이드)
3. [개인정보 수집 시 보안 체크리스트](#3-개인정보-수집-시-보안-체크리스트)
4. [사이트 런칭 전 최종 보안 점검](#4-사이트-런칭-전-최종-보안-점검-pre-launch)
5. [OWASP Top 10 2025 변경사항](#5-owasp-top-10-2025-변경사항)
6. [보안 자동화 도구 매트릭스](#6-보안-자동화-도구-매트릭스)
7. [Sources](#sources)

---

## 1. 개발 단계별 보안 체크리스트

### 1.1 설계 단계 (Design Phase)

| # | 체크 항목 | 상세 | 자동화 |
|---|----------|------|--------|
| D-1 | **STRIDE 위협 모델링** | Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege 6개 카테고리로 시스템 위협 분석 | 반자동 (Microsoft Threat Modeling Tool, OWASP Threat Dragon) |
| D-2 | **데이터 흐름 다이어그램(DFD)** | 모든 데이터 입출력 경로, 신뢰 경계(Trust Boundary) 식별 | 수동 |
| D-3 | **인증 아키텍처 설계** | Passkey/WebAuthn 우선, MFA 필수, OAuth 2.0/OIDC 표준 준수 | 수동 (설계 리뷰) |
| D-4 | **권한 모델 정의** | RBAC/ABAC 설계, 최소 권한 원칙, 권한 상승 경로 차단 | 수동 |
| D-5 | **데이터 분류** | PII/민감정보/일반정보 분류, 암호화 요구사항 정의 | 반자동 (Sentra, BigID) |
| D-6 | **API 보안 설계** | 인증 필수 엔드포인트 정의, Rate Limiting 정책, CORS 정책 | 수동 |
| D-7 | **에러 처리 전략** | 사용자에게 노출할 에러와 내부 로깅 에러 분리 설계 | 수동 |
| D-8 | **서드파티 의존성 평가** | 사용할 라이브러리/서비스의 보안 이력 사전 조사 | 반자동 (Snyk Advisor) |

### 1.2 코딩 단계 (Implementation Phase)

| # | 체크 항목 | 상세 | 자동화 |
|---|----------|------|--------|
| C-1 | **입력 검증 (서버사이드)** | 모든 사용자 입력을 Zod/Joi 등으로 스키마 검증, 클라이언트 검증은 UX용 | **자동** (SAST + lint 규칙) |
| C-2 | **SQL Injection 방지** | Prepared Statement / 파라미터화 쿼리 필수, ORM 사용 권장 | **자동** (SAST) |
| C-3 | **XSS 방지** | `dangerouslySetInnerHTML` 금지 또는 DOMPurify 필수, CSP 헤더 설정 | **자동** (SAST + CSP) |
| C-4 | **CSRF 방지** | SameSite 쿠키, Origin 검증, CSRF 토큰 (Server Actions은 자동) | 반자동 |
| C-5 | **시크릿 하드코딩 금지** | 소스코드/git 히스토리에 API 키, 비밀번호 없음 | **자동** (git-secrets, Gitleaks) |
| C-6 | **안전한 세션 관리** | httpOnly + Secure + SameSite=Lax 쿠키, 세션 타임아웃 24h 이내 | 반자동 |
| C-7 | **비밀번호 해싱** | bcrypt / scrypt / Argon2 사용, MD5/SHA1 금지 | **자동** (SAST) |
| C-8 | **파일 업로드 보안** | 파일 타입 화이트리스트, 서버사이드 MIME 검증, 크기 제한 | 반자동 |
| C-9 | **로깅에서 민감정보 제외** | 비밀번호, 토큰, PII가 로그에 포함되지 않도록 | 반자동 |
| C-10 | **의존성 보안** | `npm audit` / `bun audit` 정기 실행, lockfile 커밋 | **자동** (Dependabot, Snyk) |

**금지 패턴 (Anti-Patterns)**:
- `eval()`, `exec()`, `system()` 사용 금지
- `localStorage`/`sessionStorage`에 인증 토큰 저장 금지
- `NEXT_PUBLIC_` 접두사로 시크릿 노출 금지
- 와일드카드 CORS (`Access-Control-Allow-Origin: *`) 금지
- `console.log`로 민감 데이터 출력 금지

### 1.3 테스트 단계 (Verification Phase)

| # | 체크 항목 | 도구 | 자동화 |
|---|----------|------|--------|
| T-1 | **SAST (정적 분석)** | Semgrep, SonarQube, Snyk Code, CodeQL | **자동** (CI/CD) |
| T-2 | **DAST (동적 분석)** | OWASP ZAP, Burp Suite, StackHawk | **자동** (CI/CD) |
| T-3 | **SCA (의존성 스캔)** | Snyk, Dependabot, Renovate | **자동** (CI/CD) |
| T-4 | **시크릿 스캔** | Gitleaks, git-secrets, TruffleHog | **자동** (pre-commit hook) |
| T-5 | **인증/인가 테스트** | 수평/수직 권한 상승 테스트, IDOR 테스트 | 반자동 |
| T-6 | **비즈니스 로직 테스트** | 가격 변조, 워크플로우 우회, Race Condition | 수동 |
| T-7 | **보안 헤더 검증** | SecurityHeaders.com, Mozilla Observatory | **자동** |
| T-8 | **SSL/TLS 검증** | SSL Labs, testssl.sh | **자동** |
| T-9 | **침투 테스트** | 전문 펜테스터 또는 Bug Bounty | 수동 |

### 1.4 배포 단계 (Deployment Phase)

| # | 체크 항목 | 상세 | 자동화 |
|---|----------|------|--------|
| P-1 | **디버그 모드 비활성화** | `NODE_ENV=production`, 소스맵 비노출 | **자동** (배포 스크립트) |
| P-2 | **환경 분리** | dev/staging/production 환경별 시크릿 분리 | **자동** (Vercel/AWS) |
| P-3 | **HTTPS 강제** | TLS 1.2+ 필수, TLS 1.0/1.1 비활성화, HSTS 설정 | **자동** |
| P-4 | **보안 헤더 설정** | CSP, X-Frame-Options, X-Content-Type-Options 등 | **자동** (next.config.ts) |
| P-5 | **서버 정보 은닉** | Server 헤더 제거, 에러 페이지에 스택 트레이스 비노출 | **자동** |
| P-6 | **기본 계정 제거** | 기본 admin/admin 등 제거, 불필요한 서비스 포트 차단 | 반자동 |
| P-7 | **컨테이너 보안** | 이미지 취약점 스캔, non-root 사용자 실행 | **자동** (Trivy, Snyk Container) |
| P-8 | **WAF 설정** | 웹 애플리케이션 방화벽 규칙 설정 | 반자동 |
| P-9 | **DDoS 방어** | CDN/엣지 레벨 Rate Limiting, 봇 차단 | **자동** (Cloudflare, Vercel) |
| P-10 | **백업 설정** | 데이터베이스 자동 백업, 복구 테스트 | **자동** |

### 1.5 운영 단계 (Operations Phase)

| # | 체크 항목 | 상세 | 자동화 |
|---|----------|------|--------|
| O-1 | **보안 모니터링** | 인증 실패, 비정상 접근 패턴, API 남용 탐지 | **자동** (SIEM) |
| O-2 | **로그 관리** | 인증/인가 이벤트, 관리자 행동, 에러 로그 중앙 수집 | **자동** |
| O-3 | **인시던트 대응 계획** | 침해 감지 -> 격리 -> 분석 -> 복구 -> 사후 분석 프로세스 | 수동 (문서화) |
| O-4 | **의존성 업데이트** | 주간 자동 PR, 크리티컬 CVE는 24시간 내 패치 | **자동** (Dependabot) |
| O-5 | **정기 펜테스트** | 분기/반기별 침투 테스트 | 수동 |
| O-6 | **보안 감사** | 연간 보안 감사, 컴플라이언스 검증 | 수동 |
| O-7 | **데이터 보존/삭제** | 보존 기간 만료 데이터 자동 삭제, 삭제 증적 | 반자동 |

---

## 2. 프레임워크별 보안 가이드

### 2.1 Next.js / React 보안

#### 치명적 취약점 (2025-2026)

| CVE | CVSS | 영향 | 조치 |
|-----|------|------|------|
| **CVE-2025-29927** | 9.1 | 미들웨어 인증 우회 (`x-middleware-subrequest` 헤더) | Next.js 12.3.5, 13.5.9, 14.2.25, 15.2.3+ 업데이트 |
| **CVE-2025-66478** | 10.0 | React Server Components Flight 프로토콜 RCE | 즉시 패치 적용 |
| **CVE-2025-55182** | 10.0 | React 원격 코드 실행 | 즉시 패치 적용 |

#### Next.js 보안 체크리스트

```
인증
 [ ] Passkey/WebAuthn을 기본 인증으로 설정 (2026 표준)
 [ ] 세션 토큰을 httpOnly + Secure + SameSite=Lax 쿠키에 저장
 [ ] localStorage/sessionStorage에 토큰 저장 금지
 [ ] MFA 활성화 (고위험 작업: 이메일 변경, 데이터 내보내기, 관리자 접근)
 [ ] 세션 만료 설정 (일반: 24h, 관리자: 15분)
 [ ] 권한 상승 시 세션 ID 교체

API/Server Actions
 [ ] 모든 API Route와 Server Action에서 독립적 인증 검증
 [ ] 미들웨어를 보안 경계로 사용하지 않음 (라우팅/UX용으로만)
 [ ] Zod로 모든 입력 스키마 검증
 [ ] Rate Limiting 적용 (로그인/OTP/비밀번호 재설정)
 [ ] 401(미인증) vs 403(미인가) 정확한 응답 코드 사용

데이터 보호
 [ ] Server Component -> Client Component 데이터 전달 시 민감정보 필터링
 [ ] DTO 패턴으로 데이터 노출 제어
 [ ] NEXT_PUBLIC_ 변수에 시크릿 포함 금지
 [ ] .env 파일 .gitignore에 추가

XSS 방지
 [ ] dangerouslySetInnerHTML 사용 시 DOMPurify로 살균
 [ ] 오픈 리다이렉트 방지 (returnTo는 상대 경로만 허용)

보안 헤더 (next.config.ts)
 [ ] Content-Security-Policy (frame-ancestors 'none' 포함)
 [ ] X-Frame-Options: DENY
 [ ] X-Content-Type-Options: nosniff
 [ ] Strict-Transport-Security (max-age=63072000; includeSubDomains; preload)
 [ ] Referrer-Policy: strict-origin-when-cross-origin
 [ ] Permissions-Policy: camera=(), microphone=(), geolocation=()
```

**next.config.ts 보안 헤더 설정 예시**:

```typescript
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
];
```

### 2.2 Bun 서버 보안

```
 [ ] Bun.serve()에 HTTPS 활성화
 [ ] WebSocket 연결 시 인증 토큰 검증
 [ ] 환경변수는 .env 파일로 관리 (Bun 자동 로드, dotenv 불필요)
 [ ] 라우트 핸들러에서 입력 검증
 [ ] Rate Limiting 미들웨어 적용
 [ ] CORS 정책을 명시적으로 설정 (와일드카드 금지)
```

### 2.3 Supabase 인증 보안

```
 [ ] Row Level Security (RLS) 모든 테이블에 활성화
 [ ] service_role 키 절대 프론트엔드에 노출 금지 (RLS 우회)
 [ ] anon 키는 RLS 활성화 상태에서만 안전
 [ ] RLS 정책에서 user_metadata 사용 금지 (사용자가 수정 가능)
 [ ] 이메일 인증 활성화 (가짜 계정 방지)
 [ ] 최소 비밀번호 길이 강제
 [ ] MFA 활성화
 [ ] PII 필드에 추가 암호화 (Postgres 내장 암호화 함수)
 [ ] 인증/DB 접근 로그 모니터링
 [ ] API 키 유출 시 즉시 재생성
 [ ] 커스텀 역할로 세분화된 접근 제어
```

### 2.4 Vercel 배포 보안

```
 [ ] 환경변수를 Vercel 대시보드/CLI로만 관리 (레포지토리에 커밋 금지)
 [ ] 클라이언트 노출 환경변수 명시적 지정 (기본은 서버 전용)
 [ ] Deployment Protection 활성화 (프리뷰 환경 보호)
 [ ] Git Fork Protection 설정
 [ ] 로그/소스 보호 활성화
 [ ] 고급: HashiCorp Vault 또는 AWS Secrets Manager 연동
 [ ] OIDC Federation으로 백엔드 보안 접근
```

### 2.5 AWS 배포 보안

```
 [ ] IAM 역할 최소 권한 원칙 (와일드카드 권한 금지)
 [ ] S3 버킷 퍼블릭 접근 차단
 [ ] VPC 레이어별 세분화
 [ ] 데이터베이스 인터넷 직접 접근 차단
 [ ] Security Group/방화벽 규칙 리뷰
 [ ] CloudTrail 로그 활성화
 [ ] AWS Secrets Manager로 시크릿 관리
 [ ] 스토리지 접근 로그 활성화
```

---

## 3. 개인정보 수집 시 보안 체크리스트

### 3.1 회원가입 폼 보안

| # | 체크 항목 | 자동화 |
|---|----------|--------|
| F-1 | HTTPS/TLS 암호화 전송 필수 | **자동** |
| F-2 | 서버사이드 + 클라이언트사이드 입력 검증 | 반자동 |
| F-3 | SQL Injection / XSS 방지 (입력 살균) | **자동** (SAST) |
| F-4 | CAPTCHA로 봇 자동 가입 방지 | 반자동 |
| F-5 | Rate Limiting으로 무차별 대입 방지 | **자동** |
| F-6 | 비밀번호 강도 요구사항 (12자+, 복잡성) | **자동** |
| F-7 | 비밀번호 bcrypt/Argon2로 해싱 저장 | **자동** |
| F-8 | 이메일 인증으로 가짜 계정 방지 | 반자동 |
| F-9 | 에러 메시지에서 계정 존재 여부 노출 금지 | 수동 |

### 3.2 결제 정보 처리

| # | 체크 항목 | 자동화 |
|---|----------|--------|
| P-1 | PCI DSS 준수 (카드 정보 직접 처리 시) | 수동 (인증) |
| P-2 | 결제는 Stripe/Toss 등 PCI 인증 서비스 위임 권장 | - |
| P-3 | 카드 번호 서버에 저장 금지 (토큰화) | **자동** (결제 서비스) |
| P-4 | 결제 페이지 TLS 1.2+ 필수 | **자동** |
| P-5 | 가격/수량 변조 서버사이드 검증 | 수동 |

### 3.3 이메일/전화번호 수집

| # | 체크 항목 | 자동화 |
|---|----------|--------|
| E-1 | 수집 목적 명시 및 동의 획득 | 수동 |
| E-2 | 수집 최소화 원칙 (필요한 정보만) | 수동 |
| E-3 | 암호화 저장 (AES-256 at rest) | **자동** |
| E-4 | 접근 권한 최소화 (RBAC) | 반자동 |
| E-5 | 마케팅 수신 동의 별도 획득 | 수동 |

### 3.4 쿠키/트래킹 동의

| # | 체크 항목 | 규정 | 자동화 |
|---|----------|------|--------|
| K-1 | 쿠키 동의 배너 표시 | GDPR/ePrivacy | 반자동 (CMP 도구) |
| K-2 | 필수/분석/마케팅 쿠키 분류 | GDPR | 수동 |
| K-3 | Opt-in 방식 (사전 체크 금지) | GDPR | 반자동 |
| K-4 | 동의 철회 기능 제공 | GDPR/CCPA | 반자동 |
| K-5 | 쿠키 정책 문서화 | 전체 | 수동 |

### 3.5 데이터 보존/삭제 정책

| # | 체크 항목 | 자동화 |
|---|----------|--------|
| R-1 | 데이터 보존 기간 정의 및 문서화 | 수동 |
| R-2 | 보존 기간 만료 시 자동 삭제 | **자동** |
| R-3 | 삭제 요청 처리 프로세스 (GDPR 잊힐 권리) | 반자동 |
| R-4 | 삭제 증적 로그 보관 | **자동** |
| R-5 | 백업에서도 삭제 반영 | 반자동 |

### 3.6 한국 개인정보보호법 / ISMS-P 요구사항

```
수집 단계
 [ ] 개인정보 수집 시 목적, 항목, 보유기간 고지 및 동의
 [ ] 필수/선택 동의 항목 분리
 [ ] 만 14세 미만 법정대리인 동의
 [ ] 고유식별정보(주민번호 등) 수집 제한

보유/이용 단계
 [ ] 목적 외 이용 금지
 [ ] 접근 권한 관리 (최소 권한)
 [ ] 개인정보 암호화 (전송: TLS, 저장: AES-256)
 [ ] 접근 로그 기록 및 보관 (최소 6개월)

제공/위탁 단계
 [ ] 제3자 제공 시 별도 동의
 [ ] 위탁 시 수탁자 관리감독
 [ ] 국외 이전 시 별도 고지/동의

파기 단계
 [ ] 보유기간 경과 시 지체 없이 파기
 [ ] 복구 불가능한 방법으로 파기
 [ ] 파기 기록 관리

정보주체 권리
 [ ] 열람/정정/삭제/처리정지 요청 처리
 [ ] 개인정보 처리방침 공개 (2025.4 작성지침 반영)
```

---

## 4. 사이트 런칭 전 최종 보안 점검 (Pre-Launch)

> 런칭 2-3주 전에 시작하여 수정/재검증 시간 확보 권장

### 4.1 인프라 & 암호화

| # | 점검 항목 | 확인 방법 | 자동화 |
|---|----------|----------|--------|
| L-1 | SSL/TLS 인증서 유효성 | SSL Labs (ssllabs.com/ssltest) | **자동** |
| L-2 | TLS 1.2+ 강제, 1.0/1.1 비활성화 | testssl.sh | **자동** |
| L-3 | HSTS 헤더 설정 | curl -I 또는 SecurityHeaders.com | **자동** |
| L-4 | HTTP -> HTTPS 리다이렉트 | curl -I http://domain.com | **자동** |
| L-5 | DNS 설정 정확성 (A/CNAME/MX) | dig, nslookup | **자동** |
| L-6 | DNSSEC 활성화 (권장) | dnsviz.net | 반자동 |

### 4.2 정보 노출 차단

| # | 점검 항목 | 확인 방법 | 자동화 |
|---|----------|----------|--------|
| L-7 | 에러 페이지에 스택 트레이스/내부 경로 비노출 | 수동 테스트 + DAST | 반자동 |
| L-8 | Server 헤더에 버전 정보 비노출 | curl -I | **자동** |
| L-9 | 디렉토리 리스팅 비활성화 | 브라우저 직접 확인 | **자동** |
| L-10 | 소스맵 프로덕션 비노출 | 브라우저 DevTools | 반자동 |
| L-11 | robots.txt에 민감 경로 노출 금지 | 직접 확인 | 수동 |
| L-12 | .env, .git 등 설정 파일 접근 차단 | curl 테스트 | **자동** |

### 4.3 인증 & 접근 제어

| # | 점검 항목 | 확인 방법 | 자동화 |
|---|----------|----------|--------|
| L-13 | 기본 계정/비밀번호 제거 | 수동 확인 | 수동 |
| L-14 | 관리자 패널 공개 접근 차단 | URL 접근 테스트 | 반자동 |
| L-15 | 불필요한 서비스/포트 차단 | nmap 스캔 | **자동** |
| L-16 | 세션 쿠키 Secure/HttpOnly 플래그 | 브라우저 DevTools | **자동** |

### 4.4 애플리케이션 보안

| # | 점검 항목 | 확인 방법 | 자동화 |
|---|----------|----------|--------|
| L-17 | 디버그 모드 비활성화 | 환경변수 확인 | **자동** |
| L-18 | 콘솔 로그에 민감 정보 없음 | 브라우저 DevTools | 수동 |
| L-19 | 보안 헤더 전체 설정 확인 | SecurityHeaders.com | **자동** |
| L-20 | 의존성 취약점 0 Critical/High | npm audit / Snyk | **자동** |
| L-21 | OWASP ZAP 스캔 통과 | ZAP 자동 스캔 | **자동** |

### 4.5 데이터 & 백업

| # | 점검 항목 | 확인 방법 | 자동화 |
|---|----------|----------|--------|
| L-22 | 데이터베이스 백업 설정 및 테스트 | 복구 테스트 | 반자동 |
| L-23 | 로그 수집/보관 정책 설정 | 로그 시스템 확인 | **자동** |
| L-24 | 인시던트 대응 계획 문서화 | 문서 확인 | 수동 |
| L-25 | 개인정보 처리방침 게시 | 페이지 확인 | 수동 |

### 4.6 서드파티 & 공급망

| # | 점검 항목 | 확인 방법 | 자동화 |
|---|----------|----------|--------|
| L-26 | 서드파티 스크립트 SRI 해시 적용 | HTML 확인 | 반자동 |
| L-27 | CDN 제공자 보안 상태 확인 | 벤더 문서 확인 | 수동 |
| L-28 | 빌드 파이프라인 의존성 버전 고정 | lockfile 확인 | **자동** |
| L-29 | CI/CD 환경 프로덕션 격리 | 인프라 확인 | 반자동 |

---

## 5. OWASP Top 10 2025 변경사항

| 순위 | 2025 | 변경 | 핵심 |
|------|------|------|------|
| A01 | **Broken Access Control** | SSRF 통합 | 접근 제어 실패 + SSRF |
| A02 | **Security Misconfiguration** | 5위->2위 상승 | 설정 오류 급증 |
| A03 | **Software Supply Chain Failures** | **신규** | 공급망 공격 (의존성, 빌드 시스템) |
| A04 | Injection | 유지 | SQL/XSS/Command Injection |
| A05 | Cryptographic Failures | 유지 | 암호화 실패 |
| A06 | Insecure Design | 유지 | 안전하지 않은 설계 |
| A07 | Identification and Authentication Failures | 유지 | 인증 실패 |
| A08 | Security Logging and Monitoring Failures | 유지 | 로깅/모니터링 부족 |
| A09 | Vulnerable and Outdated Components | 유지 | 취약한 컴포넌트 |
| A10 | **Mishandling of Exceptional Conditions** | **신규** | 에러 처리 실패, 논리 오류 |

**핵심 변화**: 증상이 아닌 근본 원인에 집중하는 방향으로 전환. 공급망 보안과 에러 처리가 새로운 카테고리로 등장.

---

## 6. 보안 자동화 도구 매트릭스

### CI/CD 파이프라인 통합 도구

| 카테고리 | 도구 | 용도 | 무료/유료 | CI/CD 통합 |
|----------|------|------|----------|-----------|
| **SAST** | Semgrep | 정적 코드 분석 | 무료(OSS) | GitHub Actions, GitLab CI |
| **SAST** | SonarQube | 코드 품질 + 보안 | 무료(CE) | 전체 |
| **SAST** | CodeQL | GitHub 네이티브 분석 | 무료(공개 레포) | GitHub Actions |
| **SAST** | Snyk Code | 개발자 친화적 분석 | 프리미엄 | GitHub/GitLab PR 피드백 |
| **DAST** | OWASP ZAP | 동적 웹앱 스캔 | 무료(OSS) | Docker, GitHub Actions |
| **DAST** | StackHawk | 개발자 친화적 DAST | 프리미엄 | CI/CD 네이티브 |
| **DAST** | Burp Suite | 전문 펜테스트 | 프리미엄 | CI 확장 |
| **SCA** | Dependabot | 의존성 자동 업데이트 | 무료 | GitHub 네이티브 |
| **SCA** | Snyk | 의존성 취약점 스캔 | 프리미엄 | 전체 |
| **SCA** | Renovate | 의존성 자동 PR | 무료(OSS) | 전체 |
| **시크릿** | Gitleaks | git 히스토리 시크릿 스캔 | 무료(OSS) | pre-commit hook |
| **시크릿** | TruffleHog | 시크릿 탐지 | 무료(OSS) | CI/CD |
| **헤더** | SecurityHeaders.com | 보안 헤더 등급 | 무료 | API |
| **SSL** | SSL Labs | TLS 설정 검증 | 무료 | API |
| **통합** | Aikido | SAST+SCA+IaC+시크릿 올인원 | 프리미엄 | 전체 |
| **통합** | Jit | AppSec 통합 플랫폼 | 프리미엄 | 전체 |

### 권장 최소 자동화 구성 (소규모 프로젝트)

```yaml
# .github/workflows/security.yml 예시 구조
name: Security Checks
on: [push, pull_request]

jobs:
  sast:
    # Semgrep 정적 분석

  dependency-scan:
    # npm audit 또는 Snyk

  secret-scan:
    # Gitleaks

  security-headers:
    # SecurityHeaders.com API 체크
```

### 자동화 비율 요약

| 단계 | 전체 항목 | 자동화 가능 | 비율 |
|------|----------|-----------|------|
| 설계 | 8 | 2 | 25% |
| 코딩 | 10 | 7 | 70% |
| 테스트 | 9 | 6 | 67% |
| 배포 | 10 | 7 | 70% |
| 운영 | 7 | 4 | 57% |
| Pre-Launch | 29 | 18 | 62% |
| **전체** | **73** | **44** | **~60%** |

---

## Key Insights

### So What? (의미)

1. **2025년 상반기에만 23,667개 CVE 공개** (전년 대비 16% 증가), 그중 161개가 실제 악용됨. 보안은 선택이 아닌 필수.
2. **Next.js 미들웨어는 보안 경계가 아니다** -- CVE-2025-29927 이후 모든 핸들러에서 독립적 인증이 업계 상식이 됨.
3. **공급망 공격이 OWASP Top 10에 신규 진입** (A03) -- 의존성 관리가 코드 품질만큼 중요해짐.
4. **한국 ISMS-P는 101개 인증 기준** (관리체계 16 + 보호대책 64 + 개인정보 21)으로, 일정 규모 이상 서비스는 의무 인증.

### Now What? (행동)

1. **즉시**: Next.js를 최신 패치 버전으로 업데이트하고, 의존성 취약점 스캔을 CI/CD에 추가한다.
2. **1주 내**: 위 체크리스트 중 자동화 가능 항목(44개)을 CI/CD 파이프라인에 통합한다.
3. **런칭 전**: Pre-Launch 체크리스트 29개 항목을 순차적으로 검증한다.
4. **지속적**: Dependabot/Renovate로 의존성 자동 업데이트, 분기별 수동 보안 리뷰를 운영한다.

---

## Sources

### OWASP & Secure SDLC
- [OWASP in SDLC](https://owasp.org/www-project-integration-standards/writeups/owasp_in_sdlc/)
- [OWASP Secure Development Guide](https://devguide.owasp.org/en/02-foundations/02-secure-development/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)
- [OWASP Secure by Design Framework](https://owasp.org/www-project-secure-by-design-framework/)
- [OWASP Top 10:2025 Introduction](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [OWASP Top 10 2025: Key Changes (Aikido)](https://www.aikido.dev/blog/owasp-top-10-2025-changes-for-developers)
- [OWASP Top 10 2025: Key Changes (Fastly)](https://www.fastly.com/blog/new-2025-owasp-top-10-list-what-changed-what-you-need-to-know)
- [OWASP Cheat Sheet for SDLC](https://dev.to/yayabobi/owasp-cheat-sheet-for-sdlc-with-downloadable-xls-4pjm)
- [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)

### Next.js / React Security
- [Next.js Security Best Practices 2026 (Authgear)](https://www.authgear.com/post/nextjs-security-best-practices)
- [Next.js Data Security Guide (Official)](https://nextjs.org/docs/app/guides/data-security)
- [Complete Next.js Security Guide 2025 (TurboStarter)](https://www.turbostarter.dev/blog/complete-nextjs-security-guide-2025-authentication-api-protection-and-best-practices)
- [Next.js Security Hardening 2026 (Medium)](https://medium.com/@widyanandaadi22/next-js-security-hardening-five-steps-to-bulletproof-your-app-in-2026-61e00d4c006e)
- [Security Checklist for React and Next.js (The New Stack)](https://thenewstack.io/a-security-checklist-for-your-react-and-next-js-apps/)
- [Next.js Authentication Guide 2026 (WorkOS)](https://workos.com/blog/nextjs-app-router-authentication-guide-2026)

### Supabase / Firebase Security
- [Supabase Row Level Security Docs](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase Securing Your Data](https://supabase.com/docs/guides/database/secure-data)
- [Supabase Security Best Practices (Supadex)](https://www.supadex.app/blog/best-security-practices-in-supabase-a-comprehensive-guide)
- [API Security Best Practices Supabase & Firebase 2026](https://www.audityour.app/blog/api-security-best-practices)

### Vercel / AWS Deployment Security
- [Vercel Security Settings](https://vercel.com/docs/project-configuration/security-settings)
- [Vercel Sensitive Environment Variables](https://vercel.com/docs/environment-variables/sensitive-environment-variables)
- [Vercel Deployment Protection](https://vercel.com/docs/deployment-protection)
- [AWS Secrets Manager + Vercel (Terraform)](https://vercel.com/kb/guide/integrating_aws_secrets_manager_with_vercel_using_terraform)

### PII & Privacy
- [PII Compliance Checklist 2025 (Sentra)](https://www.sentra.io/learn/pii-compliance-checklist)
- [Protect PII in Web Forms (Kiteworks)](https://www.kiteworks.com/secure-web-forms/protect-pii-checklist/)
- [Privacy by Design GDPR Guide (SecurePrivacy)](https://secureprivacy.ai/blog/privacy-by-design-gdpr-2025)
- [PII Compliance Checklist (GDPR Local)](https://gdprlocal.com/pii-compliance-checklist/)
- [PII & PCI Data Security Checklist (PKWARE)](https://www.pkware.com/blog/pii-pci-data-security-checklist-a-guide-to-protecting-sensitive-data)

### Pre-Launch & Security Audit
- [Application Security Audit Checklist 2026 (Offensive360)](https://offensive360.com/blog/application-security-audit-checklist/)
- [Security Testing Checklist Before Go-Live (TestRiQ)](https://www.testriq.com/blog/post/security-testing-checklist-before-go-live-2)
- [Web Application Security Testing Checklist (Apiiro)](https://apiiro.com/blog/web-application-security-testing-checklist/)
- [SDLC Security (OX Security)](https://www.ox.security/blog/sdlc-security-everything-you-need-to-know/)

### Security Automation Tools
- [Top 10 SAST Tools 2025 (OX Security)](https://www.ox.security/blog/static-application-security-sast-tools/)
- [Top 10 DAST Tools 2026 (Escape)](https://escape.tech/blog/top-dast-tools/)
- [DAST Tools 2026 (Checkmarx)](https://checkmarx.com/learn/dast/dast-tools-key-features-and-12-solutions-to-know-in-2026/)
- [Integrating Security Tools into CI/CD (Jit)](https://www.jit.io/resources/appsec-tools/integrating-application-security-tools-into-ci-cd-pipelines)

### 한국 규정
- [ISMS-P 인증기준 (KISA)](https://isms.kisa.or.kr/main/)
- [개인정보보호 포털](https://www.privacy.go.kr/)
- [개인정보 처리방침 작성지침 2025.4](https://www.privacy.go.kr/front/bbs/bbsView.do?bbsNo=BBSMSTR_000000000049&bbscttNo=20806)
