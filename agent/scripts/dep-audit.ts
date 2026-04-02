/**
 * 의존성 취약점 점검 스크립트
 * Usage: bun agent/scripts/dep-audit.ts <프로젝트 경로>
 */

import { join } from 'path';

interface AuditResult {
  id: string;
  status: 'PASS' | 'FAIL' | 'WARN' | 'SKIP';
  totalDeps: number;
  vulnerabilities: {
    critical: number;
    high: number;
    moderate: number;
    low: number;
  };
  details: string[];
}

async function auditDeps(projectPath: string): Promise<AuditResult> {
  const pkgPath = join(projectPath, 'package.json');
  const pkgFile = Bun.file(pkgPath);

  if (!await pkgFile.exists()) {
    console.log('⏭️  package.json 없음 — 스킵');
    return {
      id: 'dep-001', status: 'SKIP', totalDeps: 0,
      vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0 },
      details: ['package.json 없음'],
    };
  }

  const pkg = await pkgFile.json() as any;
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const totalDeps = Object.keys(deps).length;

  console.log(`\n🔍 의존성 취약점 점검: ${projectPath}`);
  console.log(`   총 패키지: ${totalDeps}개\n`);

  // npm audit API 호출
  try {
    const proc = Bun.spawn(['npm', 'audit', '--json', '--omit=dev'], {
      cwd: projectPath,
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    await proc.exited;

    try {
      const audit = JSON.parse(output);
      const vuln = audit.metadata?.vulnerabilities ?? { critical: 0, high: 0, moderate: 0, low: 0 };
      const details: string[] = [];

      if (audit.advisories) {
        for (const [, advisory] of Object.entries(audit.advisories) as any[]) {
          details.push(`${advisory.severity.toUpperCase()}: ${advisory.module_name} — ${advisory.title}`);
        }
      } else if (audit.vulnerabilities) {
        for (const [name, info] of Object.entries(audit.vulnerabilities) as any[]) {
          details.push(`${info.severity.toUpperCase()}: ${name} — ${info.via?.[0]?.title ?? 'N/A'}`);
        }
      }

      const hasCritical = vuln.critical > 0 || vuln.high > 0;

      console.log('📊 취약점 현황:');
      console.log(`   CRITICAL: ${vuln.critical}`);
      console.log(`   HIGH:     ${vuln.high}`);
      console.log(`   MODERATE: ${vuln.moderate}`);
      console.log(`   LOW:      ${vuln.low}`);

      if (details.length > 0) {
        console.log('\n상세:');
        details.slice(0, 10).forEach(d => console.log(`   ${d}`));
        if (details.length > 10) console.log(`   ... 외 ${details.length - 10}건`);
      }

      return {
        id: 'dep-001',
        status: hasCritical ? 'FAIL' : vuln.moderate > 0 ? 'WARN' : 'PASS',
        totalDeps, vulnerabilities: vuln, details,
      };
    } catch {
      console.log('⚠️  npm audit JSON 파싱 실패, 텍스트 출력:');
      console.log(output.substring(0, 500));
      return {
        id: 'dep-001', status: 'WARN', totalDeps,
        vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0 },
        details: ['npm audit 파싱 실패'],
      };
    }
  } catch {
    console.log('⚠️  npm audit 실행 불가, bun 환경에서는 수동 확인 필요');
    return {
      id: 'dep-001', status: 'WARN', totalDeps,
      vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0 },
      details: ['npm audit 실행 불가'],
    };
  }
}

// CLI
const projectPath = Bun.argv[2];
if (!projectPath) {
  console.error('Usage: bun agent/scripts/dep-audit.ts <프로젝트 경로>');
  process.exit(1);
}

const result = await auditDeps(projectPath);
await Bun.write('/tmp/dep-audit-result.json', JSON.stringify(result, null, 2));
console.log('\n결과 저장: /tmp/dep-audit-result.json');
