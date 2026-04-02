# 범용 웹 보안 점검 도구/에이전트 구축 리서치

**작성일**: 2026-04-01
**목적**: 범용 웹 보안 점검 에이전트를 설계하기 위한 기술 리서치

---

## 1. 기존 오픈소스 보안 스캐너 비교

### 도구별 상세 비교표

| 도구 | 유형 | 점검 범위 | 탐지 방식 | 규칙 수 | CLI 명령 예시 | 라이선스 |
|------|------|----------|----------|---------|-------------|---------|
| **OWASP ZAP** | DAST (동적) | XSS, SQLi, CSRF, 인젝션, 퍼징 | 프록시 기반 크롤링 + 능동 스캔 | 수천개 (플러그인) | `zap-cli quick-scan https://target.com` | Apache 2.0 |
| **Nuclei** | DAST/Config | CVE, 미스설정, 노출된 서비스 | YAML 템플릿 기반 HTTP 요청 매칭 | 9,000+ 커뮤니티 템플릿 | `nuclei -target https://example.com` | MIT |
| **Semgrep** | SAST (정적) | SQLi, XSS, SSRF, Path Traversal, 코드 품질 | AST 기반 패턴 매칭 + 테인트 분석 | 3,000+ (레지스트리) | `semgrep scan --config auto` | LGPL 2.1 |
| **ESLint Security** | SAST (정적) | JS/Node 보안 패턴 14개 | AST 기반 규칙 | 14개 | `eslint --plugin security .` | Apache 2.0 |
| **Snyk** | SCA + SAST | 의존성 취약점, 라이선스, 코드 | CVE DB 매칭 + 코드 분석 | 취약점 DB 수만개 | `snyk test` / `snyk monitor` | 프리미엄(무료 플랜 있음) |
| **Trivy** | SCA + Config | 컨테이너, IaC, 의존성, 시크릿 | CVE DB + 정책 기반 | OS/앱 패키지 DB | `trivy fs .` / `trivy image <img>` | Apache 2.0 |

### 도구별 장단점 분석

#### OWASP ZAP
- **장점**: 무료 오픈소스 DAST 중 최고 평가, API/Docker 지원, CI/CD 통합 용이, 커뮤니티 활발
- **단점**: 인증된 페이지/비즈니스 로직 테스트 한계, 스캔 시간 길 수 있음
- **적합**: 외부에서 접근 가능한 웹앱의 동적 취약점 탐지

#### Nuclei
- **장점**: 극도로 빠름, 새 CVE 발견 수시간 내 템플릿 업데이트, YAML 규칙 작성 쉬움
- **단점**: 알려진 패턴만 탐지 (제로데이 불가), 코드 레벨 분석 없음
- **적합**: 대규모 인프라 스캔, 알려진 취약점 빠른 확인

#### Semgrep
- **장점**: AST 기반이라 정규식보다 정확, 30+ 언어 지원, 테인트 분석으로 데이터 흐름 추적
- **단점**: Pro 기능(cross-file 분석) 유료, 런타임 취약점은 미탐지
- **적합**: 코드 리뷰 자동화, 개발 단계 보안 검증

#### Snyk
- **장점**: 가장 큰 취약점 DB, 자동 수정 PR 생성, IDE 통합
- **단점**: 무료 플랜 제한 (200 테스트/월), SCA 중심이라 커스텀 코드 분석 약함
- **적합**: 오픈소스 의존성 취약점 관리

#### Trivy
- **장점**: 올인원 (컨테이너+IaC+SCA+시크릿), 설치 간단, DB 자동 업데이트
- **단점**: 웹앱 동적 테스트 불가, 코드 정적 분석 없음
- **적합**: DevOps/컨테이너 환경 보안

#### ESLint Security Plugin
- **장점**: 개발자 익숙한 도구 확장, zero config 가능
- **단점**: 규칙 14개로 제한적, JS/Node만 지원, 유지보수 활발하지 않음
- **적합**: 기존 ESLint 워크플로우에 기본 보안 추가

### 탐지 방식 비교: 정규식 vs AST

| 방식 | 도구 | 정확도 | 오탐율 | 속도 |
|------|------|--------|--------|------|
| **정규식** | grep, eslint-plugin-no-secrets | 낮음 | 높음 | 매우 빠름 |
| **AST 패턴 매칭** | Semgrep, ESLint | 높음 | 중간 | 빠름 |
| **AST + 테인트 분석** | Semgrep Pro | 매우 높음 | 낮음 | 보통 |
| **YAML 템플릿 (HTTP)** | Nuclei | 높음 (알려진 패턴) | 낮음 | 매우 빠름 |
| **크롤링 + 능동 스캔** | ZAP | 높음 | 중간 | 느림 |

---

## 2. 범용 보안 체크리스트 표준

### 2-1. OWASP ASVS (Application Security Verification Standard)

**최신 버전**: v5.0.0 (2025년 5월 출시)
**이전 안정 버전**: v4.0.3 (2021년)

#### 3단계 검증 레벨
| 레벨 | 대상 | 설명 | 항목 수 (v4.0) |
|------|------|------|---------------|
| **L1** | 모든 앱 | OWASP Top 10 대응, 기본 보안 | ~130개 |
| **L2** | 민감 데이터 앱 | 대부분의 보안 위험 대응 | ~230개 |
| **L3** | 금융/의료/군사 | 최고 수준 보안 | 286개 전체 |

#### 14개 챕터 구조
1. Architecture, Design and Threat Modeling
2. Authentication
3. Session Management
4. Access Control
5. Validation, Sanitization and Encoding
6. Stored Cryptography
7. Error Handling and Logging
8. Data Protection
9. Communication
10. Malicious Code
11. Business Logic
12. Files and Resources
13. API and Web Service
14. Configuration

#### 도구 설계 시 활용법
- L1 항목을 자동화 점검의 기본 기준으로 설정
- 각 항목에 자동/수동 점검 가능 여부 태깅
- 요구사항 ID 형식: `v<version>-<chapter>.<section>.<requirement>`

### 2-2. CWE/SANS Top 25 (2025년판)

| 순위 | CWE ID | 이름 | 점수 | 자동 탐지 가능 |
|------|--------|------|------|--------------|
| 1 | CWE-79 | Cross-site Scripting (XSS) | 60.38 | SAST + DAST |
| 2 | CWE-89 | SQL Injection | 28.72 | SAST + DAST |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) | 13.64 | SAST + DAST |
| 4 | CWE-862 | Missing Authorization | 13.28 | SAST (부분) |
| 5 | CWE-787 | Out-of-bounds Write | 12.68 | SAST |
| 6 | CWE-22 | Path Traversal | 8.99 | SAST + DAST |
| 7 | CWE-416 | Use After Free | 8.47 | SAST |
| 8 | CWE-125 | Out-of-bounds Read | 7.88 | SAST |
| 9 | CWE-78 | OS Command Injection | 7.85 | SAST + DAST |
| 10 | CWE-94 | Code Injection | 7.57 | SAST + DAST |
| 11 | CWE-120 | Classic Buffer Overflow | 6.96 | SAST |
| 12 | CWE-434 | Unrestricted File Upload | 6.87 | SAST + DAST |
| 13 | CWE-476 | NULL Pointer Dereference | 6.41 | SAST |
| 14 | CWE-121 | Stack-based Buffer Overflow | 5.75 | SAST |
| 15 | CWE-502 | Deserialization of Untrusted Data | 5.23 | SAST |
| 16 | CWE-122 | Heap-based Buffer Overflow | 5.21 | SAST |
| 17 | CWE-863 | Incorrect Authorization | 4.14 | SAST (부분) |
| 18 | CWE-20 | Improper Input Validation | 4.09 | SAST |
| 19 | CWE-284 | Improper Access Control | 4.07 | 수동 |
| 20 | CWE-200 | Sensitive Info Exposure | 4.01 | SAST + DAST |
| 21 | CWE-306 | Missing Authentication | 3.47 | SAST (부분) |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) | 3.36 | SAST + DAST |
| 23 | CWE-77 | Command Injection | 3.15 | SAST + DAST |
| 24 | CWE-639 | Auth Bypass via User-Controlled Key | 2.62 | SAST |
| 25 | CWE-770 | Resource Allocation Without Limits | 2.54 | SAST (부분) |

**웹 애플리케이션 관련 핵심 항목** (1~6, 9~10, 12, 15, 18, 20~24번) = 총 15개가 웹앱에 직접 관련

### 2-3. Mozilla Observatory 점검 항목

**채점 방식**: 100점 기준 시작, 감점/보너스 적용, 최대 135점
**총 테스트 수**: 67개 (10개 카테고리)

| 카테고리 | 테스트 수 | 최대 보너스 | 최대 감점 |
|---------|---------|-----------|---------|
| Cookies | 9 | +5 | -40 |
| CORS | 5 | 0 | -50 |
| Content Security Policy | 9 | +10 | -25 |
| HSTS | 7 | +5 | -20 |
| Redirections | 8 | 0 | -20 |
| Referrer Policy | 5 | +5 | -5 |
| Subresource Integrity | 10 | +5 | -50 |
| X-Content-Type-Options | 3 | 0 | -5 |
| X-Frame-Options | 5 | +5 | -20 |
| X-XSS-Protection | 5 | 0 | -5 |

**등급표**:
| 점수 | 등급 |
|------|------|
| 100+ | A+ |
| 90-99 | A |
| 85-89 | A- |
| 80-84 | B+ |
| 70-79 | B |
| 65-69 | B- |
| 60-64 | C+ |
| 50-59 | C |
| 45-49 | C- |
| 40-44 | D+ |
| 30-39 | D |
| 25-29 | D- |
| 0-24 | F |

---

## 3. 다국어/다법률 지원 구조

### 주요 개인정보보호법 비교

| 항목 | GDPR (EU) | CCPA (미국 캘리포니아) | PIPA (한국) |
|------|----------|---------------------|-----------|
| **시행** | 2018 | 2020 | 2011 (2023 대폭 개정) |
| **적용 범위** | EU 거주자 데이터 처리 전체 | 연매출 $25M+ 또는 5만명+ 데이터 | 한국 내 개인정보 처리 전체 |
| **동의 요건** | 명시적 사전 동의 (옵트인) | 옵트아웃 방식 | 명시적 사전 동의 (옵트인) |
| **DPO 요건** | 외부/공동 DPO 가능 | 없음 | 내부 CPO 필수 |
| **과징금** | 최대 매출 4% 또는 2천만 유로 | 건당 $2,500~$7,500 | 최대 매출 3% 또는 30억원 |
| **영향평가** | DPIA 필수 (고위험) | 없음 | 공공기관만 DPIA 필수 |
| **국외 이전** | 적정성 결정 또는 SCC | 별도 규정 없음 | 정보주체 동의 필수 |
| **삭제권** | 있음 (잊힐 권리) | 있음 | 있음 |
| **이동권** | 있음 | 제한적 | 있음 (2023 개정) |

### 모듈화 설계 구조

```
src/
  compliance/
    base.ts              # 공통 인터페이스 (ComplianceCheck, ComplianceResult)
    gdpr/
      index.ts           # GDPR 전체 체크 목록
      consent.ts         # 동의 관련 점검
      data-transfer.ts   # 국외 이전 점검
      privacy-policy.ts  # 처리방침 점검
    ccpa/
      index.ts
      opt-out.ts         # 옵트아웃 메커니즘
      do-not-sell.ts     # DNT 링크 확인
    pipa/
      index.ts
      consent.ts         # 한국식 동의 절차
      cpo.ts             # CPO 지정 확인
      retention.ts       # 보유기간 명시 확인
    registry.ts          # 법규 모듈 등록/로딩
    types.ts             # 공통 타입 정의
```

#### 핵심 인터페이스

```typescript
interface ComplianceModule {
  id: string;           // 'gdpr' | 'ccpa' | 'pipa'
  name: string;         // 표시 이름
  country: string;      // ISO 3166-1 alpha-2
  checks: ComplianceCheck[];
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface ComplianceCheck {
  id: string;           // 'pipa-001'
  title: string;        // 한국어/영어 제목
  description: string;
  lawReference: string; // '개인정보보호법 제30조'
  checkType: 'auto' | 'manual' | 'semi-auto';
  automationFn?: (ctx: ScanContext) => Promise<CheckResult>;
}
```

---

## 4. 코드 정적 분석 Best Practices

### 4-1. Semgrep 규칙 작성법

#### YAML 규칙 기본 구조
```yaml
rules:
  - id: sql-injection-express
    message: |
      Possible SQL injection via string concatenation.
      Use parameterized queries instead.
    severity: ERROR
    languages: [typescript, javascript]
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021"]
      confidence: HIGH
    patterns:
      - pattern: |
          $DB.query($QUERY + $INPUT, ...)
      - pattern-not: |
          $DB.query($QUERY + $CONST, ...)
      - metavariable-regex:
          metavariable: $CONST
          regex: "^[\"'].*[\"']$"
```

#### 패턴 연산자 정리

| 연산자 | 의미 | 용도 |
|--------|------|------|
| `pattern` | 코드 패턴 매칭 | 기본 탐지 |
| `patterns` | AND 조건 결합 | 여러 조건 모두 충족 |
| `pattern-either` | OR 조건 | 여러 패턴 중 하나 |
| `pattern-not` | 제외 조건 | false positive 감소 |
| `pattern-inside` | 스코프 한정 | 특정 함수/클래스 내부만 |
| `pattern-not-inside` | 스코프 제외 | 안전한 컨텍스트 제외 |
| `pattern-regex` | 정규식 매칭 | AST 불가능한 패턴 |
| `metavariable-regex` | 메타변수 정규식 | 변수명/값 필터링 |
| `metavariable-comparison` | 메타변수 비교 | 수치 조건 |
| `focus-metavariable` | 특정 메타변수 포커스 | 정확한 위치 보고 |

#### 테인트 분석 규칙 예시
```yaml
rules:
  - id: xss-express-response
    message: Unsanitized user input in HTTP response
    severity: ERROR
    languages: [typescript, javascript]
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: $REQ.query.$PARAM
          - pattern: $REQ.body.$PARAM
          - pattern: $REQ.params.$PARAM
    pattern-sinks:
      - pattern: $RES.send($SINK)
      - pattern: $RES.write($SINK)
    pattern-sanitizers:
      - pattern: DOMPurify.sanitize(...)
      - pattern: escapeHtml(...)
```

### 4-2. 언어별 보안 패턴

#### TypeScript/JavaScript 특화 패턴
```yaml
# 1. eval() 사용
- pattern: eval($X)

# 2. innerHTML 직접 할당
- pattern: $EL.innerHTML = $X

# 3. 안전하지 않은 정규식 (ReDoS)
- pattern: new RegExp($X)

# 4. prototype pollution
- pattern: $OBJ[$KEY] = $VAL

# 5. 하드코딩된 시크릿
- pattern: |
    const $SECRET = "..."
  metavariable-regex:
    metavariable: $SECRET
    regex: "(password|secret|api_key|token)"

# 6. SSRF
- pattern: fetch($URL)
  where $URL comes from user input (taint mode)

# 7. Path Traversal
- pattern: fs.readFile($PATH, ...)
  where $PATH comes from req.params (taint mode)
```

#### Python 특화 패턴
- `subprocess.call(shell=True)` - OS 명령 인젝션
- `pickle.loads($X)` - 역직렬화 취약점
- `yaml.load($X)` (without Loader) - YAML 인젝션
- `render_template_string($X)` - SSTI

#### Go 특화 패턴
- `fmt.Sprintf` in SQL queries - SQL 인젝션
- `http.ListenAndServe` without TLS - 평문 통신
- `template.HTML($X)` - XSS

#### Java 특화 패턴
- `Runtime.getRuntime().exec($CMD)` - OS 명령 인젝션
- `ObjectInputStream.readObject()` - 역직렬화
- `new File($USERPATH)` - Path Traversal

### 4-3. False Positive 줄이는 방법

| 기법 | 설명 | 적용 도구 |
|------|------|----------|
| **테인트 분석** | 소스→싱크 데이터 흐름 추적 | Semgrep Pro |
| **pattern-not 활용** | 안전한 패턴 명시적 제외 | Semgrep |
| **safe_functions 설정** | 불투명 함수 호출을 안전으로 간주 | Semgrep (`taint_assume_safe_functions: true`) |
| **safe_booleans/numbers** | Boolean/Number 표현식 자동 새니타이즈 | Semgrep |
| **cross-file 분석** | 파일 간 데이터 흐름 추적 | Semgrep Pro (`interfile: true`) |
| **sanitizer 등록** | 커스텀 새니타이저 함수 등록 | Semgrep (pattern-sanitizers) |
| **by-side-effect 새니타이징** | 변수가 새니타이저를 통과하면 이후 안전 처리 | Semgrep |
| **allowlist** | 특정 파일/디렉토리 제외 | 모든 도구 |
| **confidence 레벨** | HIGH만 보고하여 노이즈 감소 | Semgrep, Snyk |

**핵심 수치**: Semgrep Pro의 cross-file + cross-function 분석은 false positive를 **25% 감소**, true positive를 **250% 증가**시킴

---

## 5. HTTP 보안 점검 확장

### 5-1. SecurityHeaders.com / OWASP 점검 전체 항목

#### 구현해야 할 헤더 (14개)

| 헤더 | 권장값 | 보호 대상 |
|------|--------|----------|
| **Strict-Transport-Security** | `max-age=63072000; includeSubDomains; preload` | HTTPS 강제 |
| **Content-Security-Policy** | 앱별 맞춤 | XSS, 데이터 인젝션 |
| **X-Frame-Options** | `DENY` | 클릭재킹 |
| **X-Content-Type-Options** | `nosniff` | MIME 스니핑 |
| **Referrer-Policy** | `strict-origin-when-cross-origin` | 정보 유출 |
| **Permissions-Policy** | `geolocation=(), camera=(), microphone=()` | 브라우저 기능 제한 |
| **Cross-Origin-Opener-Policy** | `same-origin` | Spectre 공격 |
| **Cross-Origin-Embedder-Policy** | `require-corp` | 크로스오리진 리소스 |
| **Cross-Origin-Resource-Policy** | `same-site` | Spectre/리소스 탈취 |
| **Access-Control-Allow-Origin** | 특정 도메인만 | CORS 제어 |
| **Content-Type** | `text/html; charset=UTF-8` | XSS (인코딩) |
| **Set-Cookie** | `Secure; HttpOnly; SameSite=Strict` | 세션 탈취 |
| **Cache-Control** | `no-store` (민감 페이지) | 정보 캐시 |
| **X-Permitted-Cross-Domain-Policies** | `none` | Flash/PDF CORS |

#### 제거/최소화해야 할 헤더 (5개)

| 헤더 | 조치 | 이유 |
|------|------|------|
| **Server** | 제거 또는 일반화 | 서버 소프트웨어 노출 |
| **X-Powered-By** | 제거 | 기술 스택 노출 |
| **X-AspNet-Version** | 비활성화 | .NET 버전 노출 |
| **X-AspNetMvc-Version** | 비활성화 | MVC 버전 노출 |
| **X-DNS-Prefetch-Control** | `off` | 도메인 정보 유출 |

### 5-2. SSL Labs 점검 항목

| 카테고리 | 점검 항목 | A+ 기준 |
|---------|----------|---------|
| **프로토콜** | TLS 버전 지원 | TLS 1.2 + TLS 1.3 필수, TLS 1.0/1.1 미지원 |
| **암호 스위트** | AEAD 지원 | AEAD 필수, 128비트 미만 금지 |
| **인증서** | 체인 유효성 | SHA-256+, 유효한 체인, CT 로그 |
| **포워드 시크리시** | ECDHE/DHE | 모든 스위트에 FS 적용 |
| **HSTS** | 헤더 존재 | max-age 6개월 이상, preload 포함 |
| **OCSP** | 스테이플링 | OCSP 스테이플링 활성화 |
| **취약점** | 알려진 공격 | POODLE, ROBOT, Heartbleed 등 미취약 |
| **리네고시에이션** | 보안 재협상 | Secure Renegotiation 지원 |

**즉시 F 등급**: POODLE, GOLDENDOODLE, Zombie POODLE, Sleeping POODLE 취약

### 5-3. 쿠키 보안 점검

| 속성 | 확인 항목 | 심각도 |
|------|----------|--------|
| `Secure` | HTTPS에서만 전송 | Critical |
| `HttpOnly` | JavaScript 접근 차단 | Critical |
| `SameSite` | CSRF 방지 (Strict/Lax) | High |
| `Path` | 적절한 경로 제한 | Medium |
| `Domain` | 과도한 도메인 범위 확인 | Medium |
| `Max-Age/Expires` | 세션 쿠키 수명 적절성 | Medium |
| `__Secure-` prefix | Secure 속성 강제 | Low (보너스) |
| `__Host-` prefix | Secure + Path=/ + no Domain | Low (보너스) |

### 5-4. CORS 점검

| 점검 항목 | 위험 | 심각도 |
|----------|------|--------|
| `Access-Control-Allow-Origin: *` | 모든 도메인 허용 | Critical |
| Origin 반사 (reflecting) | 요청 Origin을 그대로 반환 | Critical |
| `null` Origin 허용 | sandboxed iframe 공격 | High |
| Credentials + 와일드카드 | 인증 정보 유출 | Critical |
| 과도한 메서드/헤더 허용 | 불필요한 공격 표면 | Medium |

### 5-5. 서브리소스 무결성 (SRI)

| 점검 항목 | 설명 |
|----------|------|
| CDN 스크립트 integrity 속성 | 외부 JS에 해시값 포함 여부 |
| crossorigin 속성 | `crossorigin="anonymous"` 설정 |
| CSS integrity | 외부 CSS에도 SRI 적용 |
| 해시 알고리즘 | SHA-384 이상 사용 |

---

## 6. CI/CD 통합

### 6-1. GitHub Actions 보안 스캐닝 워크플로우

```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  # 1. 코드 정적 분석 (SAST)
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Semgrep Scan
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/typescript
            p/javascript
            p/owasp-top-ten
          generateSarif: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: semgrep.sarif

  # 2. 의존성 취약점 스캔 (SCA)
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trivy Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: trivy-results.sarif

  # 3. 시크릿 탐지
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # 4. HTTP 헤더 점검 (배포 후)
  headers:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Check Security Headers
        run: |
          npx security-headers-check https://your-site.com
```

### 6-2. Pre-commit Hook 설정

#### `.pre-commit-config.yaml`
```yaml
repos:
  # 시크릿 탐지
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.2
    hooks:
      - id: gitleaks

  # Semgrep 정적 분석
  - repo: https://github.com/semgrep/semgrep
    rev: v1.96.0
    hooks:
      - id: semgrep
        args: ['--config', 'auto', '--error']

  # ESLint 보안 규칙 (JS/TS 프로젝트)
  - repo: local
    hooks:
      - id: eslint-security
        name: ESLint Security
        entry: npx eslint --plugin security --rule 'security/detect-eval-with-expression: error'
        language: system
        files: \.(js|ts|jsx|tsx)$
```

#### Gitleaks 설정 (`.gitleaks.toml`)
```toml
[extend]
useDefault = true

[allowlist]
paths = [
  "node_modules/",
  "dist/",
  ".git/",
  "*.test.ts",
  "*.spec.ts"
]
```

### 6-3. PR 자동 코멘트

```yaml
# .github/workflows/pr-security-comment.yml
name: PR Security Review
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: Run Security Scan
        id: scan
        run: |
          semgrep scan --config auto --json > results.json
          echo "count=$(jq '.results | length' results.json)" >> $GITHUB_OUTPUT
      - name: Comment on PR
        if: steps.scan.outputs.count > 0
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('results.json'));
            const findings = results.results.map(r =>
              `- **${r.check_id}** (${r.extra.severity}): ${r.extra.message.split('\n')[0]} at \`${r.path}:${r.start.line}\``
            ).join('\n');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Security Scan Results\n\nFound ${results.results.length} issue(s):\n\n${findings}`
            });
```

---

## 7. 종합 설계 권장사항

### 7-1. 추천 도구 조합 (레이어별)

| 레이어 | 도구 | 역할 |
|--------|------|------|
| **코드 정적 분석** | Semgrep (커스텀 규칙) | XSS, SQLi, SSRF 등 코드 레벨 탐지 |
| **의존성 취약점** | Trivy | npm/pip/go 패키지 CVE 점검 |
| **시크릿 탐지** | Gitleaks | API 키, 비밀번호, 토큰 유출 탐지 |
| **HTTP 헤더** | 커스텀 스캐너 | 14개 보안 헤더 + 5개 제거 헤더 점검 |
| **SSL/TLS** | testssl.sh 또는 커스텀 | 프로토콜, 암호 스위트, 인증서 점검 |
| **동적 스캔** | Nuclei (선택) | 알려진 CVE, 미스설정 탐지 |
| **법규 준수** | 커스텀 체커 | PIPA/GDPR/CCPA 필수 항목 점검 |

### 7-2. 자동화 가능 vs 수동 점검 분류

| 카테고리 | 자동화 가능 | 수동/반자동 |
|---------|------------|-----------|
| HTTP 헤더 | 14개 헤더 존재/값 확인 | CSP 정책 적절성 판단 |
| SSL/TLS | 프로토콜, 암호, 인증서 | 비즈니스 요구사항 맞춤 |
| 코드 보안 | 패턴 기반 탐지 (Semgrep) | 비즈니스 로직 취약점 |
| 의존성 | CVE DB 매칭 | 취약점 영향도 판단 |
| 시크릿 | 엔트로피/패턴 탐지 | 테스트용 값 구분 |
| 법규 준수 | 처리방침 존재, 동의 폼 존재 | 동의 문구 적절성, 법률 해석 |
| 인증/세션 | 세션 쿠키 속성 확인 | 인증 우회 시도 |

### 7-3. 출력 포맷 권장

```typescript
interface SecurityReport {
  target: string;          // URL 또는 프로젝트 경로
  scanDate: string;        // ISO 8601
  grade: string;           // A+ ~ F
  score: number;           // 0 ~ 100
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    pass: number;
  };
  categories: {
    httpHeaders: CategoryResult;
    ssl: CategoryResult;
    codeAnalysis: CategoryResult;
    dependencies: CategoryResult;
    secrets: CategoryResult;
    compliance: CategoryResult;
  };
  findings: Finding[];
}

interface Finding {
  id: string;              // 'header-hsts-missing'
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  remediation: string;     // 수정 방법
  references: string[];    // CWE, OWASP 링크
  evidence?: string;       // 실제 발견된 값
  location?: string;       // 파일:라인 또는 URL
}
```

---

## Sources

### 보안 스캐너 비교
- [The 6 best OWASP security testing tools in 2026](https://beaglesecurity.com/blog/article/best-owasp-security-testing-tools.html)
- [The Top 28 Open-Source Security Tools: A 2026 Guide | Wiz](https://www.wiz.io/academy/application-security/open-source-code-security-tools)
- [5 Best Open Source Application Security Tools in 2026 | Jit](https://www.jit.io/resources/appsec-tools/5-open-source-product-security-tools-for-developers-you-should-know-of)

### OWASP ASVS
- [OWASP ASVS GitHub](https://github.com/OWASP/ASVS)
- [OWASP ASVS 공식 페이지](https://owasp.org/www-project-application-security-verification-standard/)
- [ASVS Levels 설명](https://www.pivotpointsecurity.com/what-the-new-owasp-asvs-4-0-levels-really-mean/)

### CWE/SANS Top 25
- [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [SANS Top 25](https://www.sans.org/top25-software-errors)

### HTTP 보안 헤더
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [SecurityHeaders.com](https://securityheaders.com/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [The Complete Guide to HTTP Security Headers 2026](https://gf.dev/learn/web-security-headers)

### Semgrep
- [Semgrep Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
- [Semgrep JavaScript Deep Dive](https://semgrep.dev/blog/2025/a-technical-deep-dive-into-semgreps-javascript-vulnerability-detection/)
- [Semgrep TypeScript Ruleset](https://semgrep.dev/p/typescript)
- [Semgrep False Positive Reduction](https://semgrep.dev/docs/kb/semgrep-code/reduce-false-positives)
- [Semgrep vs ESLint 2026](https://dev.to/rahulxsingh/semgrep-vs-eslint-security-focused-sast-vs-javascript-linter-2026-hef)

### Mozilla Observatory
- [Tests & Scoring](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring)
- [HTTP Observatory GitHub](https://github.com/mozilla/http-observatory)

### SSL Labs
- [SSL Server Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)

### Nuclei
- [Nuclei GitHub](https://github.com/projectdiscovery/nuclei)
- [Nuclei Template Guide](https://www.intigriti.com/researchers/blog/hacking-tools/hacker-tools-nuclei)

### Trivy
- [Trivy GitHub](https://github.com/aquasecurity/trivy)
- [Trivy 공식 사이트](https://trivy.dev/)

### Snyk
- [Snyk CLI GitHub](https://github.com/snyk/cli)
- [Snyk Open Source Docs](https://docs.snyk.io/scan-with-snyk/snyk-open-source)

### ESLint Security
- [eslint-plugin-security GitHub](https://github.com/eslint-community/eslint-plugin-security)
- [eslint-plugin-no-secrets GitHub](https://github.com/nickdeis/eslint-plugin-no-secrets)

### 시크릿 탐지 / CI/CD
- [Gitleaks GitHub](https://github.com/gitleaks/gitleaks)
- [Gitleaks Pre-Commit Guide](https://dev.to/sirlawdin/secret-scanning-in-ci-pipelines-using-gitleaks-and-pre-commit-hook-1e3f)
- [GitHub SARIF Upload Docs](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)

### 개인정보보호법
- [한국 PIPA 개요](https://pandectes.io/blog/an-overview-of-south-koreas-personal-information-protection-act-pipa/)
- [GDPR vs PIPA 비교](https://www.dataguidance.com/sites/default/files/gdpr_v_pipa_may_2023_update.pdf)
- [한국 데이터 보호법](https://www.dlapiperdataprotection.com/index.html?t=law&c=KR)
