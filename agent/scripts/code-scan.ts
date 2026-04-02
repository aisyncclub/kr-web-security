/**
 * 코드 정적 분석 스크립트
 * Usage: bun agent/scripts/code-scan.ts <프로젝트 경로>
 *
 * checklist.yaml의 check_type: code_scan 항목을 읽어서 패턴 매칭
 */

import { parse } from 'yaml';
import { join, relative } from 'path';
import { Glob } from 'bun';

interface ScanItem {
  id: string;
  title: string;
  pattern: string;
  severity: string;
  owasp: string | null;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  owasp: string | null;
  file: string;
  line: number;
  content: string;
}

async function loadChecklist(): Promise<ScanItem[]> {
  const checklistPath = join(import.meta.dir, '..', '..', 'manual', 'checklist.yaml');
  const file = Bun.file(checklistPath);
  if (!await file.exists()) {
    console.error('❌ checklist.yaml을 찾을 수 없습니다:', checklistPath);
    process.exit(1);
  }

  const data = parse(await file.text()) as any;
  const items: ScanItem[] = [];

  for (const category of data.categories) {
    for (const item of category.items) {
      if (item.check_type === 'code_scan' && item.pattern) {
        items.push({
          id: item.id,
          title: item.title,
          pattern: item.pattern,
          severity: item.severity,
          owasp: item.owasp ?? null,
        });
      }
    }
  }

  return items;
}

async function scanProject(projectPath: string, items: ScanItem[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const extensions = ['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs'];
  const ignorePatterns = ['node_modules', '.git', 'dist', '.next', 'build'];

  for (const ext of extensions) {
    const glob = new Glob(`**/*.${ext}`);
    for await (const filePath of glob.scan({ cwd: projectPath })) {
      if (ignorePatterns.some(p => filePath.includes(p))) continue;

      const fullPath = join(projectPath, filePath);
      const content = await Bun.file(fullPath).text();
      const lines = content.split('\n');

      for (const item of items) {
        try {
          const regex = new RegExp(item.pattern, 'gi');
          for (let i = 0; i < lines.length; i++) {
            if (regex.test(lines[i])) {
              findings.push({
                id: item.id,
                title: item.title,
                severity: item.severity,
                owasp: item.owasp,
                file: filePath,
                line: i + 1,
                content: lines[i].trim().substring(0, 120),
              });
            }
            regex.lastIndex = 0;
          }
        } catch {
          // invalid regex, skip
        }
      }
    }
  }

  return findings;
}

function printFindings(findings: Finding[], projectPath: string): void {
  if (findings.length === 0) {
    console.log('\n✅ 코드 스캔 완료: 발견된 문제 없음');
    return;
  }

  console.log(`\n🔍 코드 스캔 완료: ${findings.length}건 발견\n`);

  // severity 순 정렬
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

  const grouped = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = `[${f.id}] ${f.title}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(f);
  }

  for (const [key, items] of grouped) {
    const sev = items[0].severity.toUpperCase();
    const owasp = items[0].owasp ? ` (${items[0].owasp})` : '';
    const icon = sev === 'CRITICAL' ? '🔴' : sev === 'HIGH' ? '🟠' : '🟡';

    console.log(`${icon} ${sev}${owasp} ${key} — ${items.length}건`);
    for (const f of items.slice(0, 5)) {
      console.log(`   ${f.file}:${f.line}  ${f.content}`);
    }
    if (items.length > 5) console.log(`   ... 외 ${items.length - 5}건`);
    console.log();
  }

  console.log('--- 심각도별 합계 ---');
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const count = findings.filter(f => f.severity === sev).length;
    if (count > 0) console.log(`  ${sev.toUpperCase()}: ${count}`);
  }
}

// CLI
const projectPath = Bun.argv[2];
if (!projectPath) {
  console.error('Usage: bun agent/scripts/code-scan.ts <프로젝트 경로>');
  process.exit(1);
}

console.log(`\n🔍 코드 정적 분석: ${projectPath}\n`);
const items = await loadChecklist();
console.log(`체크리스트 로드: ${items.length}개 패턴\n`);

const findings = await scanProject(projectPath, items);
printFindings(findings, projectPath);

const output = JSON.stringify(findings, null, 2);
await Bun.write('/tmp/code-scan-result.json', output);
console.log('\n결과 저장: /tmp/code-scan-result.json');
