/**
 * 통합 보안 점검 리포트 생성
 * Usage: bun agent/scripts/report-gen.ts <URL 또는 프로젝트 경로> [--url URL] [--path PATH]
 */

import { parse } from 'yaml';
import { join } from 'path';

interface ReportSection {
  category: string;
  items: Array<{
    id: string;
    title: string;
    status: 'PASS' | 'FAIL' | 'WARN' | 'SKIP';
    detail?: string;
  }>;
}

async function loadResults(): Promise<{
  headers: any[];
  codeScan: any[];
  depAudit: any;
}> {
  const readJson = async (path: string) => {
    const file = Bun.file(path);
    if (await file.exists()) return await file.json();
    return null;
  };

  return {
    headers: (await readJson('/tmp/header-check-result.json')) ?? [],
    codeScan: (await readJson('/tmp/code-scan-result.json')) ?? [],
    depAudit: (await readJson('/tmp/dep-audit-result.json')) ?? null,
  };
}

async function loadChecklist() {
  const path = join(import.meta.dir, '..', '..', 'manual', 'checklist.yaml');
  const data = parse(await Bun.file(path).text()) as any;
  return data;
}

function generateReport(
  target: string,
  checklist: any,
  results: Awaited<ReturnType<typeof loadResults>>
): string {
  const now = new Date().toISOString().split('T')[0];
  const lines: string[] = [];

  lines.push(`# 보안 점검 리포트`);
  lines.push('');
  lines.push(`| 항목 | 내용 |`);
  lines.push(`|------|------|`);
  lines.push(`| 점검일 | ${now} |`);
  lines.push(`| 대상 | ${target} |`);
  lines.push(`| 기준 | kr-web-security checklist v${checklist.version} |`);
  lines.push('');

  // 전체 집계
  let totalPass = 0, totalFail = 0, totalWarn = 0, totalSkip = 0;
  const sections: ReportSection[] = [];

  for (const category of checklist.categories) {
    const section: ReportSection = { category: category.name, items: [] };

    for (const item of category.items) {
      let status: 'PASS' | 'FAIL' | 'WARN' | 'SKIP' = 'SKIP';
      let detail = '';

      if (item.check_type === 'http_header') {
        const match = results.headers.find((h: any) => h.id === item.id);
        if (match) {
          status = match.status;
          detail = match.current ?? '';
        }
      } else if (item.check_type === 'code_scan') {
        const findings = results.codeScan.filter((f: any) => f.id === item.id);
        if (findings.length > 0) {
          status = 'FAIL';
          detail = `${findings.length}건 발견 — ${findings[0].file}:${findings[0].line}`;
        } else {
          status = 'PASS';
          detail = '문제 없음';
        }
      } else if (item.check_type === 'dependency') {
        if (results.depAudit) {
          status = results.depAudit.status;
          const v = results.depAudit.vulnerabilities;
          detail = `C:${v.critical} H:${v.high} M:${v.moderate} L:${v.low}`;
        }
      } else {
        status = 'SKIP';
        detail = '수동 점검 필요';
      }

      section.items.push({ id: item.id, title: item.title, status, detail });

      if (status === 'PASS') totalPass++;
      else if (status === 'FAIL') totalFail++;
      else if (status === 'WARN') totalWarn++;
      else totalSkip++;
    }

    sections.push(section);
  }

  const total = totalPass + totalFail + totalWarn + totalSkip;
  const autoChecked = totalPass + totalFail + totalWarn;

  lines.push(`## 요약`);
  lines.push('');
  lines.push(`| 결과 | 건수 |`);
  lines.push(`|------|------|`);
  lines.push(`| ✅ PASS | ${totalPass} |`);
  lines.push(`| ❌ FAIL | ${totalFail} |`);
  lines.push(`| ⚠️ WARN | ${totalWarn} |`);
  lines.push(`| ⏭️ SKIP (수동) | ${totalSkip} |`);
  lines.push(`| **합계** | **${total}** (자동 점검 ${autoChecked}건) |`);
  lines.push('');

  // FAIL 항목 우선 표시
  const failItems = sections.flatMap(s => s.items.filter(i => i.status === 'FAIL'));
  if (failItems.length > 0) {
    lines.push(`## ❌ FAIL 항목 (즉시 조치 필요)`);
    lines.push('');
    lines.push(`| ID | 항목 | 상세 |`);
    lines.push(`|----|------|------|`);
    for (const item of failItems) {
      lines.push(`| ${item.id} | ${item.title} | ${item.detail} |`);
    }
    lines.push('');
  }

  // WARN 항목
  const warnItems = sections.flatMap(s => s.items.filter(i => i.status === 'WARN'));
  if (warnItems.length > 0) {
    lines.push(`## ⚠️ WARN 항목 (권장 조치)`);
    lines.push('');
    lines.push(`| ID | 항목 | 상세 |`);
    lines.push(`|----|------|------|`);
    for (const item of warnItems) {
      lines.push(`| ${item.id} | ${item.title} | ${item.detail} |`);
    }
    lines.push('');
  }

  // 카테고리별 상세
  lines.push(`## 카테고리별 상세`);
  lines.push('');
  for (const section of sections) {
    const pass = section.items.filter(i => i.status === 'PASS').length;
    const fail = section.items.filter(i => i.status === 'FAIL').length;
    lines.push(`### ${section.category} (${pass}/${section.items.length} PASS)`);
    lines.push('');
    lines.push(`| 상태 | ID | 항목 | 상세 |`);
    lines.push(`|------|----|------|------|`);
    for (const item of section.items) {
      const icon = item.status === 'PASS' ? '✅' : item.status === 'FAIL' ? '❌' : item.status === 'WARN' ? '⚠️' : '⏭️';
      lines.push(`| ${icon} | ${item.id} | ${item.title} | ${item.detail ?? ''} |`);
    }
    lines.push('');
  }

  // SKIP 항목 안내
  if (totalSkip > 0) {
    lines.push(`## 수동 점검 필요 항목 (${totalSkip}건)`);
    lines.push('');
    lines.push('자동 점검이 불가능한 항목입니다. 매뉴얼을 참고하여 직접 확인하세요.');
    lines.push('');
    const skipItems = sections.flatMap(s => s.items.filter(i => i.status === 'SKIP'));
    for (const item of skipItems) {
      lines.push(`- [${item.id}] ${item.title}`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push(`*Generated by kr-web-security v${checklist.version}*`);

  return lines.join('\n');
}

// CLI
const target = Bun.argv[2];
if (!target) {
  console.error('Usage: bun agent/scripts/report-gen.ts <URL 또는 프로젝트 경로>');
  process.exit(1);
}

console.log('\n📋 보안 점검 리포트 생성 중...\n');

const [checklist, results] = await Promise.all([
  loadChecklist(),
  loadResults(),
]);

const report = generateReport(target, checklist, results);
const reportPath = `/tmp/security-report-${new Date().toISOString().split('T')[0]}.md`;
await Bun.write(reportPath, report);
console.log(report);
console.log(`\n\n📄 리포트 저장: ${reportPath}`);
