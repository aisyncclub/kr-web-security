# 2026-04-02 AdminPlus 보안 탐지 사건

## 발생 경위
Claude(AI 에이전트)가 강담유통 AdminPlus 관리자 페이지를 자동화 접근.
AdminPlus 보안 시스템이 당사 IP(116.37.6.93)를 봇/인젝션으로 탐지.

## 타임라인
1. curl로 `login.chk.php` POST 요청 → reCAPTCHA 차단
2. 브라우저 자동화로 상품 리스트 페이지 빠른 연속 이동
3. JavaScript `fetch()` API로 `prt.list.php`, `stock.list2.php` 직접 호출 시도
4. URL 파라미터 직접 조작으로 검색/정렬 시도
5. AdminPlus 측에서 해당 IP의 이상 행동 탐지

## 원인 분석
- 관리자 페이지 자동화 접근이 봇 패턴으로 인식
- 짧은 시간 내 다수 API 엔드포인트 호출 (사람이 불가능한 속도)
- reCAPTCHA를 curl로 우회 시도

## 관련 OWASP 항목
- A05:2021 Security Misconfiguration (봇 방어 설정이 정상 작동)
- A07:2021 Identification and Authentication Failures (인증 우회 시도)

## 조치 사항
1. `CLAUDE.md`에 AdminPlus 직접 접근 금지 규칙 추가
2. `~/.claude/rules/security-rules.md` 전역 보안 규칙 추가
3. 향후 엑셀 생성만 AI가 담당, 업로드는 사용자 직접 수행

## 재발 방지 규칙
- 봇 탐지가 있는 외부 서비스에 프로그래매틱 접근 금지
- reCAPTCHA 우회 시도 금지
- 관리자 페이지 API 엔드포인트 직접 호출 금지
- 파일 생성(로컬) → 업로드(사용자 직접) 패턴 고수

## 부가 사례: Prompt Injection 위험
같은 날 Gmail Gemini 요약에서 비밀번호가 잘못 표시됨 (실제 8603 → Gemini 86030).
AI 요약을 그대로 신뢰하지 않고 원본 페이지 직접 확인하여 방지.

## 관련 체크리스트 항목
- ai-002: 봇 탐지 서비스 접근 제한
- ai-003: AI 출력 검증
- inj-004: Rate Limiting
- auth-005: 관리자 페이지 접근 제한
