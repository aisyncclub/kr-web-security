# 사이트 유형별 특화 보안 조치 리서치 보고서

> 조사일: 2026-04-01
> 범위: 커뮤니티, 쇼핑몰, B2B 발주 사이트 보안 + 소규모 사업자 필수 조치 + 2025-2026 트렌드

---

## TL;DR (3줄 요약)

1. **커뮤니티/쇼핑몰/B2B 각 유형별 공격 벡터가 다르다** -- 커뮤니티는 XSS/업로드, 쇼핑몰은 결제사기/PCI-DSS, B2B는 API키/전자문서 유출이 핵심 위협
2. **소규모 사업자도 무료 도구로 80% 방어 가능** -- KISA 무료 점검, Cloudflare 무료 WAF/Turnstile, Let's Encrypt, OWASP ZAP 조합
3. **2026년 핵심 트렌드는 AI 공격 고도화 + 제로트러스트 확산** -- 딥페이크 BEC, 섀도우 AI, 공급망 공격이 급증하며 경계 기반 보안은 붕괴

---

## 1. 커뮤니티 사이트 보안

### 1.1 게시판 XSS/CSRF 방어 실무

#### XSS 방어 (OWASP A03:2021)

| 방어 계층 | 구현 방법 | 도구/라이브러리 |
|-----------|----------|----------------|
| **입력 검증** | 서버 측 허용 태그 화이트리스트 | DOMPurify (프론트), sanitize-html (백엔드) |
| **출력 이스케이프** | HTML 엔티티 변환 (`<` -> `&lt;`) | React 자동 이스케이프, markupsafe (Python) |
| **CSP 헤더** | `script-src 'self'` 설정으로 인라인 스크립트 차단 | Helmet.js (Node.js) |
| **쿠키 보호** | `HttpOnly; Secure; SameSite=Strict` | 프레임워크 내장 설정 |

**CSP 헤더 설정 예시:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'
```

**주의**: 게시판에서 사용자 HTML 허용 시 반드시 서버 측 HTML sanitizer 적용. `innerHTML` 직접 할당은 금지.

#### CSRF 방어 (OWASP A01:2021)

| 방어 방법 | 설명 | 적용 범위 |
|-----------|------|----------|
| **CSRF 토큰** | 폼마다 고유 토큰 생성/검증 | 모든 POST/PUT/DELETE 요청 |
| **SameSite 쿠키** | `SameSite=Lax` 이상 설정 | 세션 쿠키 |
| **Referer 검증** | Origin/Referer 헤더 확인 | API 엔드포인트 |
| **Double Submit Cookie** | 쿠키 + 폼 값 이중 검증 | SPA 환경 |

**출처**: [개발자를 위한 보안 완전 가이드](https://www.youngju.dev/blog/architecture/2026-03-03-security-fundamentals-for-developers)

### 1.2 사용자 업로드 파일 보안

| 위협 | 대응 | 구현 |
|------|------|------|
| **웹셸 업로드** | 실행 권한 제거 + 확장자 화이트리스트 | `.jpg`, `.png`, `.gif`, `.pdf`만 허용 |
| **MIME 타입 위조** | 서버 측 매직바이트 검증 | file-type 라이브러리로 실제 타입 확인 |
| **경로 조작** | 원본 파일명 사용 금지 | `crypto.randomUUID()` + 확장자로 저장 |
| **악성 이미지** | 이미지 리프로세싱 | sharp (Node.js)로 재인코딩 |
| **대용량 업로드** | 파일 크기 제한 | 10MB 이하 제한 + multer limits 설정 |

**필수 원칙:**
- 업로드 디렉토리에서 스크립트 실행 차단 (Nginx: `location ~* ^/uploads/ { deny all; }`)
- 업로드 파일은 별도 도메인/CDN에서 서빙 (동일 도메인 쿠키 접근 차단)
- 서버 측 검증이 핵심 -- 클라이언트 측 검증만으로는 불충분

**출처**: [파일 업로드 취약점 방어](https://owin2828.github.io/devlog/2020/01/09/etc-2.html), [안전한 파일 업로드](https://support.dextsolution.com/TechDoc/view.aspx?kb_id=E_000019)

### 1.3 스팸/봇 방어 (reCAPTCHA 대안 포함)

| 서비스 | 가격 | 특징 | 추천 대상 |
|--------|------|------|----------|
| **Cloudflare Turnstile** | 무료 (20위젯, 무제한) | 제로 마찰, 백그라운드 검증, 광고 데이터 미수집 | 소규모~중규모 |
| **hCaptcha** | 무료 (기본) / 유료 | 프라이버시 중심, 점유율 1위 | GDPR 중시 |
| **ALTCHA** | 오픈소스 | 쿠키/추적 없음, 접근성 우수 | 개인정보 중시 |
| **Google reCAPTCHA v3** | 무료 (월 100만건) | 스코어 기반 (0.0~1.0), 가장 보편적 | 대규모 |
| **AWS WAF CAPTCHA** | 종량제 | AWS 생태계 통합, WAF 규칙 연동 | AWS 사용자 |

**추가 봇 방어 기법:**
- Rate Limiting: IP당 분당 요청 수 제한 (express-rate-limit, Bun 자체 구현)
- Honeypot 필드: 숨겨진 폼 필드 (봇만 채움)
- User-Agent/행동 분석: 비정상 패턴 탐지

**출처**: [2026 reCAPTCHA 대안 비교](https://capmonster.cloud/en/blog/5-best-recaptcha-alternatives-in-2026-incl-cloudflare-turnstile), [Cloudflare Turnstile](https://www.cloudflare.com/application-services/products/turnstile/)

### 1.4 한국 커뮤니티 해킹 사례

| 연도 | 대상 | 유출 규모 | 공격 방법 | 핵심 원인 |
|------|------|----------|----------|----------|
| **2008** | 옥션 | 1,863만명 | 해킹 | 보안 체계 미흡 |
| **2011** | SK컴즈(네이트) | 3,500만명 | 악성코드 | 중국발 APT 공격 |
| **2015** | 뽐뿌 | 196만명 | **SQL Injection** | 제로보드4 사용, MD5 해시 |
| **2016** | 인터파크 | 1,030만건 | 스피어피싱 | 내부 직원 PC 감염 |
| **2017** | 하나투어 | 100만건 | 해킹 | 고객정보 DB 직접 접근 |
| **2023** | 골프존 | 221만건 | 랜섬웨어 | 보안 관리 소홀 |
| **2025** | 대형 통신사 | 대규모 | 서버 침해 | 계정 관리 부실, 암호화 미흡 |

**뽐뿌 사건 교훈** (가장 대표적인 커뮤니티 해킹):
- 개발 중단된 CMS(제로보드4) 사용 -> **최신 패치된 프레임워크 사용 필수**
- MD5 해시 사용 -> **bcrypt/argon2 사용 필수**
- SQL Injection 방어 없음 -> **Prepared Statement 필수**
- 과징금 1,040만원 부과 (현행법 기준 훨씬 높아질 수 있음)

**출처**: [뽐뿌 해킹 사건](https://namu.wiki/w/%EB%BD%90%EB%BF%8C%20%EA%B0%9C%EC%9D%B8%EC%A0%95%EB%B3%B4%20%ED%95%B4%ED%82%B9%20%EC%82%AC%EA%B1%B4), [대한민국 정보 보안 사고 목록](https://ko.wikipedia.org/wiki/%EB%8C%80%ED%95%9C%EB%AF%BC%EA%B5%AD%EC%9D%98_%EC%A0%95%EB%B3%B4_%EB%B3%B4%EC%95%88_%EC%82%AC%EA%B3%A0_%EB%AA%A9%EB%A1%9D)

---

## 2. 쇼핑몰/전자상거래 보안

### 2.1 PG사 연동 보안

#### 주요 PG사 및 보안 요구사항

| PG사 | 특징 | 보안 요구사항 |
|------|------|-------------|
| **토스페이먼츠** | 개발자 친화적 API, 최신 위젯 | TLS 1.2+, 시크릿키 서버만 사용, 10분 결제 만료 |
| **NHN KCP** | 대형 쇼핑몰 점유율 높음 | PCI-DSS 인증, AES 암호화 |
| **KG이니시스** | 시장 점유율 1위 | PCI-DSS 준수, 3D Secure |
| **나이스페이먼츠** | 안정적 운영 | PCI-DSS, 본인인증 연동 |
| **포트원(아임포트)** | 멀티 PG 통합 | 각 PG 보안 규격 자동 적용 |

#### 토스페이먼츠 보안 핵심 규칙

1. **클라이언트 키 vs 시크릿 키 분리**: 클라이언트 키는 SDK 초기화용, 시크릿 키는 서버 API 호출용
2. **시크릿 키 노출 금지**: GitHub, 클라이언트 코드, 로그에 절대 포함 불가
3. **Server-to-Server 호출**: 결제 승인은 반드시 서버에서 수행
4. **TLS 1.2 이상 필수**: SSL 하위 버전 차단
5. **결제 승인 10분 제한**: 리다이렉트 후 10분 내 승인 API 호출

**출처**: [토스페이먼츠 개발자센터](https://docs.tosspayments.com/reference/using-api/api-keys), [토스페이먼츠 결제 연동](https://docs.tosspayments.com/guides/payment/integration)

### 2.2 PCI-DSS 한국 적용

#### PCI-DSS v4.0 (2025년 3월 31일 전면 시행)

| 요구사항 | 설명 | 소규모 사업자 적용 |
|----------|------|------------------|
| **네트워크 보안** | 방화벽, 네트워크 세분화 | 클라우드 보안 그룹 설정 |
| **카드 데이터 암호화** | 저장/전송 시 암호화 | PG사 토큰화 사용 (직접 저장 금지) |
| **취약점 관리** | 정기 보안 검사 | 분기별 취약점 스캔 |
| **접근 제어** | 최소 권한 원칙 | DB 계정 권한 분리 |
| **모니터링** | 네트워크 모니터링, 로그 분석 | 접속 기록 1년 보관 |
| **보안 정책** | 정보 보안 정책 수립 | 개인정보 처리방침 공개 |

**한국 특수 사항:**
- 한국은 PG사가 카드 데이터를 처리하므로, 일반 가맹점은 **카드번호를 직접 저장하지 않는 것이 원칙**
- PG사 토큰(빌링키)만 저장 -> PCI-DSS 범위 대폭 축소
- Visa Korea 준수 프로그램: 연간 거래 600만건 이상 가맹점은 Level 1 (QSA 평가 필수)

**출처**: [Visa Korea PCI-DSS](https://www.visakorea.com/partner-with-us/pci-dss-compliance-information.html), [PCI DSS 표준](https://www.pcisecuritystandards.org/pdfs/pci_dss_korean.pdf)

### 2.3 결제 사기 방지

| 방어 기법 | 설명 | 도구/서비스 |
|-----------|------|------------|
| **3D Secure 2.3.1** | 카드사 추가 인증 (2025.1 EMVCo 최신) | PG사 제공 |
| **AI 이상 거래 탐지** | 평소와 다른 결제 패턴 자동 감지 | 토스페이먼츠 FDS, KG이니시스 FDS |
| **속도 제한** | 동일 카드/IP 반복 결제 차단 | 자체 구현 + PG사 제공 |
| **AVS (주소 확인)** | 입력 주소와 카드 등록 주소 대조 | PG사 연동 |
| **Device Fingerprinting** | 디바이스 고유 특성 분석 | 토스페이먼츠, Sift Science |
| **지리적 필터링** | 해외 IP 결제 제한/추가 인증 | 자체 구현 |
| **최소 금액 시험 결제 탐지** | 소액 반복 결제 패턴 차단 | PG사 FDS |

### 2.4 주문/배송 데이터 보호

| 데이터 | 보호 방법 | 법적 근거 |
|--------|----------|----------|
| **이름/전화번호** | AES-256 암호화 저장, 마스킹 표시 | 개인정보보호법 |
| **주소** | 암호화 저장, 배송 완료 후 접근 제한 | 개인정보보호법 |
| **결제 정보** | PG사 토큰만 저장, 카드번호 미저장 | PCI-DSS, 전자금융거래법 |
| **주문 이력** | 접속기록 1~2년 보관 | 전자상거래법 제6조 |
| **배송 추적** | HTTPS API, API 키 인증 | - |

**2025년 개정 사항** (개인정보 안전성 확보조치 기준):
- 접속기록 보관: 일반 1년, 5만명 이상 처리 시 2년
- 비밀번호: 일방향 암호화 (bcrypt/argon2)
- 접근권한: 업무 변경 시 즉시 변경/말소
- 데이터 중요도 기반 보호체계로 전환 (네트워크 차단 중심 -> 데이터 분류 중심)

**출처**: [개인정보 안전성 확보조치 기준](https://www.law.go.kr/admRulLsInfoP.do?chrClsCd=010202&admRulSeq=2100000229672), [2025 안전성 확보조치 안내서 (PDF)](https://business.cch.com/CybersecurityPrivacy/KoreanGuidetotheStandardsforEnsuringtheSafetyofPersonalInformationOctober2024.pdf)

---

## 3. B2B 발주/도매 사이트 보안

### 3.1 거래처 정보 보호

| 보호 대상 | 위험 | 대응 |
|-----------|------|------|
| **거래처 연락처** | 경쟁사 유출 | 암호화 저장 + 접근 권한 분리 |
| **거래 단가/계약조건** | 가격 정보 유출 | 역할 기반 접근 제어 (RBAC) |
| **거래 이력** | 거래 패턴 노출 | 접근 로그 기록 + 대량 조회 알림 |
| **재고/발주 수량** | 사업 정보 노출 | API 응답에 필요 최소 데이터만 포함 |

**B2B 특화 원칙:**
- 거래처별 전용 계정 발급 (공유 계정 금지)
- 거래처가 볼 수 있는 데이터 범위 엄격 제한
- 계약 종료 시 계정 즉시 비활성화

### 3.2 발주서/견적서 전자문서 보안

| 보안 조치 | 구현 방법 |
|-----------|----------|
| **전송 암호화** | HTTPS/TLS 1.2+ 필수, 이메일 발송 시 파일 암호화 |
| **문서 비밀번호** | 엑셀/PDF 비밀번호 설정 (수신자만 알 수 있는 별도 채널로 전달) |
| **전자서명** | 공동인증서 또는 민간인증서 기반 전자서명 |
| **접근 이력** | 누가 언제 다운로드했는지 기록 |
| **보존 기간** | 전자상거래법: 계약/청약 5년, 대금결제 5년, 소비자 불만 3년 |
| **개인정보 마스킹** | 발주서 내 전화번호/주소 부분 마스킹 옵션 제공 |

**전자문서 서비스:**
- DocuSign API: 전자서명 + 문서 관리 통합
- 카카오페이 전자서명: 한국 시장 특화
- NHN 다이퀘스트: 전자문서 관리 솔루션

### 3.3 API 키 관리

| 원칙 | 구현 | 도구 |
|------|------|------|
| **환경변수 저장** | `.env` 파일에만 저장, Git 커밋 금지 | dotenv (Node), Bun 자동 로드 |
| **키 회전** | 정기적 키 갱신 (최소 분기 1회) | AWS Secrets Manager, Vault |
| **최소 권한** | API 키별 접근 범위 제한 | 키별 IP/엔드포인트 제한 |
| **Git 유출 방지** | `.gitignore` + pre-commit 훅 | gitleaks, git-secrets |
| **키 노출 탐지** | 실시간 유출 모니터링 | GitHub Secret Scanning (무료), GitGuardian |

**API 키 관리 도구 (2026 기준):**
- **AWS Secrets Manager**: AWS 환경, 자동 회전 지원
- **HashiCorp Vault**: 멀티 클라우드, 동적 시크릿
- **Doppler**: SaaS형, 팀 협업 지원
- **Infisical**: 오픈소스, 자체 호스팅 가능

**출처**: [API Key Management Tools 2026](https://www.digitalapi.ai/blogs/top-api-key-management-tools), [B2B API Integration Practices](https://www.planeks.net/b2b-api-integration/)

### 3.4 IP 기반 접근 제어

| 적용 대상 | 방법 | 구현 |
|-----------|------|------|
| **관리자 페이지** | IP 화이트리스트 | Nginx `allow/deny`, 클라우드 보안 그룹 |
| **API 엔드포인트** | 거래처별 IP 제한 | WAF 규칙, 미들웨어 |
| **SSH 접근** | 오피스 IP만 허용 | 방화벽 규칙 (포트 22 IP 제한) |
| **DB 접근** | 애플리케이션 서버 IP만 허용 | DB 방화벽, VPC 보안 그룹 |

**WAF 솔루션:**

| 서비스 | 가격 | 특징 |
|--------|------|------|
| **Cloudflare WAF** | 무료(기본)/Pro $20/월 | CDN+WAF 통합, DDoS 방어 포함 |
| **AWS WAF** | 종량제 (규칙당 $5/월 + 요청당) | AWS 네이티브, Shield 연동 |
| **펜타시큐리티 WAPPLES** | 국산, 온프레미스/클라우드 | 한국 보안인증 |
| **Cloudbric WAF+** | SaaS형, 국내 최초 | 한국어 지원, KISA 인증 |

**출처**: [웹방화벽(WAF)](https://www.pentasecurity.co.kr/web-application-firewall/), [Cloudflare WAF](https://www.cloudflare.com/application-services/products/waf/), [Cloudbric WAF+](https://www.cloudbric.co.kr/cloudbric-waf/)

---

## 4. 소규모 사업자 필수 보안 조치

### 4.1 비용 대비 효과 순위 (무료~저비용)

| 순위 | 조치 | 비용 | 방어 효과 | 난이도 |
|------|------|------|----------|--------|
| 1 | **HTTPS (Let's Encrypt)** | 무료 | 전송 데이터 암호화 | 낮음 |
| 2 | **Cloudflare 무료 플랜** | 무료 | DDoS + 기본 WAF + CDN | 낮음 |
| 3 | **비밀번호 bcrypt 해시** | 무료 | 유출 시 복호화 방지 | 중간 |
| 4 | **CSP/보안 헤더 설정** | 무료 | XSS/클릭재킹 방어 | 중간 |
| 5 | **Cloudflare Turnstile** | 무료 | 봇/스팸 방어 | 낮음 |
| 6 | **OWASP ZAP 자가 점검** | 무료 | 웹 취약점 사전 발견 | 중간 |
| 7 | **KISA 무료 보안 점검** | 무료 | 전문가 점검 | 낮음 (신청만) |
| 8 | **gitleaks (pre-commit)** | 무료 | API 키 유출 방지 | 낮음 |
| 9 | **npm/bun audit** | 무료 | 의존성 취약점 발견 | 낮음 |
| 10 | **관리자 2FA** | 무료 | 계정 탈취 방지 | 낮음 |

### 4.2 무료/저비용 보안 도구 상세

#### SSL 인증서 - Let's Encrypt

- **URL**: https://letsencrypt.org/ko/
- **인증서 타입**: DV (Domain Validated)
- **유효기간**: 90일 (자동 갱신 가능)
- **설정 도구**: Certbot (`sudo certbot --nginx`)
- **자동 갱신**: `certbot renew` cron 등록
- **제한**: 와일드카드 인증서는 DNS 인증 필요

#### 웹 취약점 스캐너 - OWASP ZAP

- **URL**: https://www.zaproxy.org/
- **기능**: SQL Injection, XSS, IDOR 등 자동 탐지
- **사용법**: GUI 또는 CLI, CI/CD 연동 가능
- **장점**: 무료이면서 상용 솔루션 수준의 기능
- **대안**: Nikto (웹서버 스캐너), Nuclei (템플릿 기반 스캐너)

#### CDN/WAF/DDoS - Cloudflare 무료 플랜

- **URL**: https://www.cloudflare.com/
- **무료 포함**: DNS, CDN, 기본 DDoS 방어, SSL, 페이지 규칙
- **Pro 플랜 ($20/월)**: WAF 규칙셋, 이미지 최적화, 모바일 최적화
- **Turnstile (봇 방어)**: 무료 (20 위젯, 무제한 챌린지)

#### 코드 보안 스캐너

| 도구 | 용도 | 가격 |
|------|------|------|
| **gitleaks** | Git에 커밋된 시크릿 탐지 | 무료 (오픈소스) |
| **GitHub Secret Scanning** | 푸시된 시크릿 자동 탐지 | 무료 (공개 저장소) |
| **Snyk** | 의존성 취약점 + 코드 분석 | 무료 (오픈소스 프로젝트) |
| **npm audit / bun audit** | 패키지 취약점 확인 | 무료 |
| **ESLint security plugin** | 코드 패턴 보안 검사 | 무료 |

**출처**: [OWASP ZAP 소개](https://www.openmaru.io/owasp-zap-devops%EB%A5%BC-%EC%9C%84%ED%95%9C-self-%EC%9B%B9-%EC%B7%A8%EC%95%BD%EC%A0%90-%EC%A0%90%EA%B2%80-%EB%8F%84%EA%B5%AC-%EC%86%8C%EA%B0%9C/), [Let's Encrypt](https://letsencrypt.org/ko/)

### 4.3 KISA 무료 보안 점검 서비스

| 서비스 | 대상 | 점검 내용 | 신청 |
|--------|------|----------|------|
| **중소기업 보안 취약점 점검** | 중소기업 (연 250개사) | 웹, 모바일앱, 개발/운영 환경 | https://www.kisa.or.kr/1020303 |
| **보호나라 보안 취약점 점검** | 기업 | 시스템/네트워크/무선 네트워크 | https://www.boho.or.kr/ |
| **털린 내 정보 찾기** | 개인/기업 | 다크웹 유출 계정 확인 | https://kidc.eprivacy.go.kr/ |
| **지역정보보호지원센터** | 지역 중소기업 | 보안 컨설팅, 교육 | 전국 10개소 |
| **정보보호 공시 사전점검** | 공시 대상 기업 | 무상 컨설팅 | https://isds.kisa.or.kr/ |

**문의**: Tel 1644-7630, Mail helpdesk@finss.co.kr

**출처**: [KISA 보호나라](https://www.boho.or.kr/kr/subPage.do?menuNo=205009), [KISA 중소기업 보안](https://www.kisa.or.kr/1020303)

---

## 5. 2025-2026 보안 트렌드

### 5.1 AI 기반 보안 위협/방어

#### 공격 측 (위협)

| 위협 | 설명 | 대응 |
|------|------|------|
| **AI 설계 공격 시나리오** | 단순 피싱 생성을 넘어 AI가 공격 시나리오 자체를 설계/실행 | AI 기반 방어 시스템 도입 |
| **딥페이크 BEC** | 음성/영상 딥페이크로 CEO/거래처 사칭 결제 유도 | 결제 승인 다단계 인증, 콜백 확인 |
| **섀도우 AI** | 승인 안 된 AI 도구로 기밀 정보 입력/유출 | AI 사용 정책 수립, DLP 도구 |
| **자동화된 크리덴셜 스터핑** | 다크웹 유출 계정으로 AI 기반 대규모 로그인 시도 | MFA 필수, 이상 로그인 탐지 |
| **AI 피싱 이메일** | 자연스러운 한국어 피싱 메일 대량 생성 | 이메일 보안 게이트웨이, 직원 교육 |

#### 방어 측 (활용)

| 활용 | 도구/서비스 |
|------|------------|
| **이상 행동 탐지** | AWS GuardDuty, CrowdStrike Falcon |
| **자동 위협 대응** | Wiz Workflows, SOAR 플랫폼 |
| **로그 분석 자동화** | Elastic SIEM, Splunk AI |
| **취약점 자동 발견** | Snyk Code, GitHub Copilot Security |

**출처**: [2025 보안 이슈 2026 전망](https://exosp.com/blog/2025-security-issues-2026-outlook), [2025 사이버 침해 경고](https://www.dginclusion.com/news/articleView.html?idxno=1403)

### 5.2 제로 트러스트 아키텍처

**핵심 원칙**: "절대 신뢰하지 말고, 항상 검증하라 (Never Trust, Always Verify)"

#### 한국 도입 현황

| 시점 | 사항 |
|------|------|
| 2022.10 | 제로트러스트/공급망 보안 포럼 발족 |
| 2023.07 | 제로트러스트 가이드라인 1.0 발간 |
| 2024.12 | 제로트러스트 가이드라인 2.0 발간 |
| 2025.09 | N2SF(국가망 보안체계) 가이드라인 1.0 공개 |

#### 6가지 기본 원리

1. 모든 접근에 대한 명시적 신뢰 확인 후 리소스 접근 허용
2. 중앙집중적 정책 관리 및 접근제어 결정
3. 사용자/기기 관리 및 강력한 인증
4. 세밀한 접근제어 (최소 권한 부여)
5. 논리 경계 생성 및 세션 단위 접근 허용
6. 지속적 모니터링/로깅 및 신뢰성 검증

#### 소규모 사업자 적용 방법

| 원리 | 소규모 구현 |
|------|-----------|
| 명시적 검증 | 모든 API에 인증 토큰 필수 |
| 최소 권한 | DB 계정 권한 분리, 관리자 별도 계정 |
| 세션 관리 | JWT 만료 시간 설정, 리프레시 토큰 |
| 모니터링 | 접속 로그 기록, 이상 행동 알림 |
| 네트워크 분리 | VPC 서브넷 분리, 보안 그룹 |

**출처**: [2026 제로트러스트](https://m.boannews.com/html/detail.html?tab_type=1&idx=141478)

### 5.3 클라우드 보안 (AWS/GCP 한국 리전)

#### AWS 한국 리전 (ap-northeast-2, 서울)

| 서비스 | 용도 | 가격대 |
|--------|------|--------|
| **AWS Shield Standard** | DDoS 기본 방어 | 무료 |
| **AWS WAF** | 웹 방화벽 | 규칙당 $5/월 + 요청당 |
| **AWS GuardDuty** | 위협 탐지 | 종량제 |
| **AWS Secrets Manager** | 시크릿 관리 | $0.40/시크릿/월 |
| **AWS Certificate Manager** | SSL 인증서 | 무료 (AWS 서비스용) |
| **AWS CloudTrail** | 감사 로그 | 무료 (기본) |

#### GCP 한국 리전 (asia-northeast3, 서울)

| 서비스 | 용도 |
|--------|------|
| **Cloud Armor** | WAF + DDoS |
| **Secret Manager** | 시크릿 관리 |
| **Cloud IAM** | 접근 제어 |
| **Security Command Center** | 보안 대시보드 |

#### Cloudflare (글로벌, 한국 PoP 포함)

| 플랜 | 가격 | 포함 기능 |
|------|------|----------|
| **Free** | $0 | DNS, CDN, 기본 DDoS, SSL |
| **Pro** | $20/월 | WAF 규칙셋, 이미지 최적화 |
| **Business** | $200/월 | 고급 WAF, 100% SLA |

**소규모 사업자 추천 조합**: Cloudflare 무료 (CDN+DDoS) + AWS Lightsail/EC2 (서버) + Let's Encrypt (SSL) + OWASP ZAP (자가 점검)

**출처**: [AWS WAF](https://aws.amazon.com/waf/), [AWS 한국 블로그 DDoS](https://aws.amazon.com/ko/blogs/korea/anti-ddos-for-game/)

---

## 2025년 주요 보안 사고 요약

| 사고 | 피해 | 핵심 원인 | 교훈 |
|------|------|----------|------|
| **대형 통신사 정보 유출** | 역대 최대 규모 | 서버 계정 관리 부실, 암호화 미흡, 거버넌스 부재 | 기본기(계정/암호화)가 가장 중요 |
| **온라인 서점 랜섬웨어** | 5일 서비스 중단, 약 100억원 손실 | 오프사이트 백업 미구축 | 백업은 별도 위치에 반드시 |
| **가상자산 거래소 탈취** | 수조원 규모 | 연계 서비스 취약점 | 공급망 전체 보안 필요 |
| **공급망 공격** | 고객사 접속 계정 탈취 | 외부 협력사 PC 감염 | 서드파티 보안 관리 필수 |
| **크리덴셜 스터핑** | 대규모 개인정보 유출 | 다크웹 유출 계정 재사용 | MFA 도입 + 비밀번호 재사용 금지 |

---

## 체크리스트 연동 (checklist.yaml 기존 항목 매핑)

이 리서치 결과와 기존 `checklist.yaml`의 매핑:

| 리서치 항목 | 체크리스트 ID | 상태 |
|------------|-------------|------|
| XSS 방어 | inj-002 | 이미 존재 |
| CSRF 방어 | auth-006 | 이미 존재 |
| SQL Injection 방어 | inj-001 | 이미 존재 |
| 파일 업로드 보안 | - | **추가 필요** |
| 봇/스팸 방어 | inj-005 | 이미 존재 (reCAPTCHA) |
| PG사 연동 보안 | pay-002 | 부분 존재 |
| PCI-DSS 준수 | db-002 | 부분 존재 |
| 결제 사기 방지 | - | **추가 필요** |
| B2B 거래처 정보 보호 | - | **추가 필요** |
| API 키 관리 | pay-002 | 이미 존재 |
| IP 접근 제어 | auth-005 | 이미 존재 |
| 제로트러스트 원칙 | - | **추가 고려** |

### 추가 권장 체크리스트 항목

```yaml
# 파일 업로드 보안
- id: upload-001
  title: "업로드 파일 확장자 화이트리스트"
  description: "허용 확장자만 업로드 가능, 서버측 매직바이트 검증"
  severity: critical
  owasp: "A04:2021"

- id: upload-002
  title: "업로드 디렉토리 실행 권한 제거"
  description: "업로드 디렉토리에서 스크립트 실행 차단"
  severity: critical
  owasp: "A05:2021"

# 결제 사기 방지
- id: pay-004
  title: "FDS 연동"
  description: "PG사 FDS(이상거래탐지) 활성화 확인"
  severity: high
  owasp: null

# B2B 거래처 보안
- id: b2b-001
  title: "거래처별 전용 계정"
  description: "공유 계정 금지, 거래처별 독립 계정 및 접근 범위 제한"
  severity: high
  owasp: "A01:2021"

- id: b2b-002
  title: "발주서 개인정보 마스킹"
  description: "발주서 다운로드 시 전화번호/주소 부분 마스킹 옵션"
  severity: medium
  owasp: null
```

---

## Sources

- [개발자를 위한 보안 완전 가이드 (2026)](https://www.youngju.dev/blog/architecture/2026-03-03-security-fundamentals-for-developers)
- [React SPA 인증 실전 가이드 - XSS/CSRF 방어](https://www.youngju.dev/blog/architecture/2026-03-08-sso-cookie-jwt-auth-react)
- [뽐뿌 개인정보 해킹 사건](https://namu.wiki/w/%EB%BD%90%EB%BF%8C%20%EA%B0%9C%EC%9D%B8%EC%A0%95%EB%B3%B4%20%ED%95%B4%ED%82%B9%20%EC%82%AC%EA%B1%B4)
- [대한민국 정보 보안 사고 목록 (위키백과)](https://ko.wikipedia.org/wiki/%EB%8C%80%ED%95%9C%EB%AF%BC%EA%B5%AD%EC%9D%98_%EC%A0%95%EB%B3%B4_%EB%B3%B4%EC%95%88_%EC%82%AC%EA%B3%A0_%EB%AA%A9%EB%A1%9D)
- [쇼핑몰 결제 시스템 PG사 연동 보안 강화 전략](https://www.jaenung.net/tree/52)
- [토스페이먼츠 개발자센터 - API 키](https://docs.tosspayments.com/reference/using-api/api-keys)
- [토스페이먼츠 결제 연동 가이드](https://docs.tosspayments.com/guides/payment/integration)
- [Visa Korea PCI-DSS 규제 준수](https://www.visakorea.com/partner-with-us/pci-dss-compliance-information.html)
- [PCI DSS 표준 (한국어 PDF)](https://www.pcisecuritystandards.org/pdfs/pci_dss_korean.pdf)
- [2025 보안 이슈 2026 전망 - 엑소스피어](https://exosp.com/blog/2025-security-issues-2026-outlook)
- [2026 제로트러스트 보안 키워드 - 보안뉴스](https://m.boannews.com/html/detail.html?tab_type=1&idx=141478)
- [KISA 보호나라 보안취약점 점검](https://www.boho.or.kr/kr/subPage.do?menuNo=205009)
- [KISA 중소기업 보안 취약점 점검](https://www.kisa.or.kr/1020303)
- [털린 내 정보 찾기](https://kidc.eprivacy.go.kr/)
- [개인정보 안전성 확보조치 기준](https://www.law.go.kr/admRulLsInfoP.do?chrClsCd=010202&admRulSeq=2100000229672)
- [2026 reCAPTCHA 대안 비교](https://capmonster.cloud/en/blog/5-best-recaptcha-alternatives-in-2026-incl-cloudflare-turnstile)
- [Cloudflare Turnstile](https://www.cloudflare.com/application-services/products/turnstile/)
- [Cloudflare WAF](https://www.cloudflare.com/application-services/products/waf/)
- [AWS WAF](https://aws.amazon.com/waf/)
- [Cloudbric WAF+](https://www.cloudbric.co.kr/cloudbric-waf/)
- [펜타시큐리티 웹방화벽](https://www.pentasecurity.co.kr/web-application-firewall/)
- [Let's Encrypt](https://letsencrypt.org/ko/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [API Key Management Tools 2026](https://www.digitalapi.ai/blogs/top-api-key-management-tools)
- [B2B API Integration Practices](https://www.planeks.net/b2b-api-integration/)
- [파일 업로드 취약점 방어](https://owin2828.github.io/devlog/2020/01/09/etc-2.html)
- [Helmet.js 보안 헤더](https://github.com/helmetjs/helmet)
- [한국 전자상거래법 개정 2025](https://aixpost.com/growth-insight/korea-ecommerce-law-2025/)
- [2026 공격 표면 관리 키워드 - CIO](https://www.cio.com/article/4106715/%EC%82%AC%EC%A0%84-%EB%8C%80%EC%9D%91%EC%9D%B4-%ED%95%B5%EC%8B%AC%C2%B7%C2%B7%C2%B72026%EB%85%84-%EA%B3%B5%EA%B2%A9-%ED%91%9C%EB%A9%B4-%EA%B4%80%EB%A6%AC%EC%9D%98-%ED%95%B5%EC%8B%AC-%ED%82%A4%EC%9B%8C.html)
