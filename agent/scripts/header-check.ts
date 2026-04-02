/**
 * HTTP 보안 헤더 점검 스크립트
 * Usage: bun agent/scripts/header-check.ts <URL>
 */

interface HeaderCheckResult {
  id: string;
  title: string;
  status: 'PASS' | 'FAIL' | 'WARN' | 'SKIP';
  current: string | null;
  expected: string;
  owasp: string | null;
}

const CHECKS: Array<{
  id: string;
  title: string;
  header: string | null;
  expected: string;
  owasp: string;
  check: (headers: Headers, url: string) => Promise<HeaderCheckResult>;
}> = [
  {
    id: 'srv-001',
    title: 'HSTS (Strict-Transport-Security)',
    header: 'Strict-Transport-Security',
    expected: 'max-age=31536000',
    owasp: 'A05:2021',
    check: async (headers) => {
      const val = headers.get('Strict-Transport-Security');
      const pass = val !== null && /max-age=\d{7,}/.test(val);
      return {
        id: 'srv-001', title: 'HSTS', owasp: 'A05:2021',
        status: val ? (pass ? 'PASS' : 'WARN') : 'FAIL',
        current: val, expected: 'max-age=31536000 이상',
      };
    },
  },
  {
    id: 'srv-002',
    title: 'Content-Security-Policy',
    header: 'Content-Security-Policy',
    expected: 'default-src 포함',
    owasp: 'A05:2021',
    check: async (headers) => {
      const val = headers.get('Content-Security-Policy');
      return {
        id: 'srv-002', title: 'CSP', owasp: 'A05:2021',
        status: val ? 'PASS' : 'FAIL',
        current: val ? val.substring(0, 80) + '...' : null,
        expected: 'default-src 정책 설정',
      };
    },
  },
  {
    id: 'srv-003',
    title: 'X-Frame-Options',
    header: 'X-Frame-Options',
    expected: 'DENY 또는 SAMEORIGIN',
    owasp: 'A05:2021',
    check: async (headers) => {
      const val = headers.get('X-Frame-Options');
      const pass = val !== null && /DENY|SAMEORIGIN/i.test(val);
      return {
        id: 'srv-003', title: 'X-Frame-Options', owasp: 'A05:2021',
        status: pass ? 'PASS' : 'FAIL',
        current: val, expected: 'DENY 또는 SAMEORIGIN',
      };
    },
  },
  {
    id: 'srv-004',
    title: 'X-Content-Type-Options',
    header: 'X-Content-Type-Options',
    expected: 'nosniff',
    owasp: 'A05:2021',
    check: async (headers) => {
      const val = headers.get('X-Content-Type-Options');
      return {
        id: 'srv-004', title: 'X-Content-Type-Options', owasp: 'A05:2021',
        status: val === 'nosniff' ? 'PASS' : 'FAIL',
        current: val, expected: 'nosniff',
      };
    },
  },
  {
    id: 'srv-referrer',
    title: 'Referrer-Policy',
    header: 'Referrer-Policy',
    expected: 'strict-origin-when-cross-origin',
    owasp: 'A05:2021',
    check: async (headers) => {
      const val = headers.get('Referrer-Policy');
      return {
        id: 'srv-referrer', title: 'Referrer-Policy', owasp: 'A05:2021',
        status: val ? 'PASS' : 'WARN',
        current: val, expected: 'strict-origin-when-cross-origin 권장',
      };
    },
  },
  {
    id: 'srv-permissions',
    title: 'Permissions-Policy',
    header: 'Permissions-Policy',
    expected: '설정됨',
    owasp: 'A05:2021',
    check: async (headers) => {
      const val = headers.get('Permissions-Policy');
      return {
        id: 'srv-permissions', title: 'Permissions-Policy', owasp: 'A05:2021',
        status: val ? 'PASS' : 'WARN',
        current: val ? val.substring(0, 60) : null,
        expected: 'camera=(), microphone=() 등',
      };
    },
  },
  {
    id: 'auth-002',
    title: 'HTTPS 리다이렉트',
    header: null,
    expected: 'HTTP → HTTPS 301 리다이렉트',
    owasp: 'A02:2021',
    check: async (_headers, url) => {
      try {
        const httpUrl = url.replace('https://', 'http://');
        const resp = await fetch(httpUrl, { redirect: 'manual' });
        const location = resp.headers.get('Location') ?? '';
        const pass = resp.status === 301 && location.startsWith('https');
        return {
          id: 'auth-002', title: 'HTTPS 리다이렉트', owasp: 'A02:2021',
          status: pass ? 'PASS' : 'FAIL',
          current: `${resp.status} → ${location.substring(0, 50)}`,
          expected: '301 → https://...',
        };
      } catch {
        return {
          id: 'auth-002', title: 'HTTPS 리다이렉트', owasp: 'A02:2021',
          status: 'SKIP', current: 'HTTP 연결 불가', expected: '301 리다이렉트',
        };
      }
    },
  },
  {
    id: 'auth-007',
    title: '쿠키 보안 플래그',
    header: 'Set-Cookie',
    expected: 'Secure; HttpOnly; SameSite',
    owasp: 'A05:2021',
    check: async (headers) => {
      const val = headers.get('Set-Cookie');
      if (!val) return {
        id: 'auth-007', title: '쿠키 보안 플래그', owasp: 'A05:2021',
        status: 'SKIP', current: 'Set-Cookie 헤더 없음', expected: 'Secure; HttpOnly',
      };
      const hasSecure = /Secure/i.test(val);
      const hasHttpOnly = /HttpOnly/i.test(val);
      const pass = hasSecure && hasHttpOnly;
      return {
        id: 'auth-007', title: '쿠키 보안 플래그', owasp: 'A05:2021',
        status: pass ? 'PASS' : 'FAIL',
        current: `Secure=${hasSecure}, HttpOnly=${hasHttpOnly}`,
        expected: 'Secure; HttpOnly; SameSite',
      };
    },
  },
];

async function checkHeaders(url: string): Promise<HeaderCheckResult[]> {
  if (!url.startsWith('http')) url = `https://${url}`;

  console.log(`\n🔍 HTTP 보안 헤더 점검: ${url}\n`);

  let headers: Headers;
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'KR-Web-Security-Check/1.0' },
    });
    headers = resp.headers;
  } catch (e: any) {
    console.error(`❌ 연결 실패: ${e.message}`);
    return [];
  }

  const results: HeaderCheckResult[] = [];
  for (const check of CHECKS) {
    const result = await check.check(headers, url);
    results.push(result);

    const icon = result.status === 'PASS' ? '✅' : result.status === 'FAIL' ? '❌' : result.status === 'WARN' ? '⚠️' : '⏭️';
    console.log(`${icon} [${result.id}] ${result.title}`);
    console.log(`   현재: ${result.current ?? '없음'}`);
    console.log(`   기대: ${result.expected}`);
    console.log();
  }

  const pass = results.filter(r => r.status === 'PASS').length;
  const fail = results.filter(r => r.status === 'FAIL').length;
  const warn = results.filter(r => r.status === 'WARN').length;
  console.log(`\n📊 결과: PASS ${pass} / FAIL ${fail} / WARN ${warn} / SKIP ${results.length - pass - fail - warn}`);

  return results;
}

// CLI
const url = Bun.argv[2];
if (!url) {
  console.error('Usage: bun agent/scripts/header-check.ts <URL>');
  process.exit(1);
}

const results = await checkHeaders(url);
const output = JSON.stringify(results, null, 2);
await Bun.write('/tmp/header-check-result.json', output);
console.log('\n결과 저장: /tmp/header-check-result.json');
