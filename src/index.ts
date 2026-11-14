#!/usr/bin/env node
/**
 * pkgsentry CLI
 *
 *   pkgsentry scan <tarball|dir> [--json|--sarif] [--min-severity high] [--fail-on high]
 *   pkgsentry diff <old.tgz> <new.tgz> [--json]
 *   pkgsentry rules
 *
 * 退出码: 0 正常 / 1 达到 --fail-on 阈值 / 2 用法或输入错误
 */

import { existsSync, statSync } from 'node:fs';
import { RULES } from './rules';
import { diffReports } from './diff';
import { renderDiff, renderDiffJson, renderJson, renderReport, renderSarif } from './report';
import { DEFAULT_OPTIONS, scanPath } from './scanner';
import { scoreFindings } from './score';
import type { Severity } from './types';

const HELP = `pkgsentry — npm 包静态行为分析器

用法:
  pkgsentry scan <tarball|目录> [选项]
  pkgsentry diff <旧版本 tarball|目录> <新版本 tarball|目录> [选项]
  pkgsentry rules

scan 选项:
  --json               输出完整 JSON
  --sarif              输出 SARIF 2.1.0
  --min-severity <级别> 只显示 >= 级别的发现 (info|low|medium|high|critical)
  --fail-on <级别>      发现达到该级别时以退出码 1 结束
  --limit <n>          最多显示的发现数 (默认 200)
  --max-file-bytes <n> 单文件分析上限
  --quiet              只输出结论行

diff 选项:
  --json               输出完整 JSON
  --limit <n>          最多显示的新增行为数 (默认 100)

示例:
  pkgsentry scan ./evil-package-1.2.3.tgz
  pkgsentry diff ./pkg-1.0.0.tgz ./pkg-1.1.0.tgz --fail-on high
  pkgsentry scan ./pkg-dir --json > baseline.json
`;

function fail(message: string): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(2);
}

interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Map<string, string | true>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string | true>();
  const positional: string[] = [];
  const takesValue = new Set(['--min-severity', '--fail-on', '--limit', '--max-file-bytes']);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--help' || arg === '-h') {
      flags.set('--help', true);
      continue;
    }
    if (arg.startsWith('--')) {
      if (takesValue.has(arg)) {
        const value = argv[i + 1];
        if (value === undefined) fail(`${arg} 缺少参数`);
        flags.set(arg, value);
        i++;
      } else {
        flags.set(arg, true);
      }
      continue;
    }
    positional.push(arg);
  }
  return { command: positional.shift() ?? '', positional, flags };
}

function parseSeverity(value: string | true | undefined): Severity | undefined {
  if (value === undefined || value === true) return undefined;
  const normalized = value.toLowerCase();
  if (!['info', 'low', 'medium', 'high', 'critical'].includes(normalized)) {
    fail(`无效的严重度: ${value}`);
  }
  return normalized as Severity;
}

function requireInput(path: string): string {
  if (!existsSync(path)) fail(`路径不存在: ${path}`);
  return path;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  if (args.flags.has('--help') || args.command === '' || args.command === 'help') {
    process.stdout.write(HELP);
    process.exit(args.command === '' ? 2 : 0);
  }

  const options = { ...DEFAULT_OPTIONS };
  const maxFileBytes = args.flags.get('--max-file-bytes');
  if (typeof maxFileBytes === 'string') {
    const n = Number.parseInt(maxFileBytes, 10);
    if (!Number.isFinite(n) || n <= 0) fail('--max-file-bytes 必须是正整数');
    options.maxFileBytes = n;
  }
  const quiet = args.flags.has('--quiet');
  options.quiet = quiet;

  if (args.command === 'rules') {
    for (const rule of RULES) {
      process.stdout.write(`${rule.id.padEnd(30)} ${rule.severity.padEnd(8)} w=${String(rule.weight).padStart(3)}  ${rule.title}\n`);
    }
    return;
  }

  if (args.command === 'scan') {
    const target = args.positional[0];
    if (!target) fail('scan 需要一个 tarball 或目录路径');
    const report = scanPath(requireInput(target), options);

    if (args.flags.has('--json')) {
      process.stdout.write(`${renderJson(report)}\n`);
    } else if (args.flags.has('--sarif')) {
      process.stdout.write(`${renderSarif(report)}\n`);
    } else if (quiet) {
      const all = [...report.archiveFindings, ...report.files.flatMap((f) => f.findings)];
      const verdict = scoreFindings(all).verdict;
      process.stdout.write(`${report.package.name}@${report.package.version}\t${verdict.level}\t${verdict.score}\t${all.length} findings\n`);
    } else {
      const minSeverity = parseSeverity(args.flags.get('--min-severity'));
      const limitValue = args.flags.get('--limit');
      const limit = typeof limitValue === 'string' ? Number.parseInt(limitValue, 10) : undefined;
      process.stdout.write(
        renderReport(report, { ...(minSeverity ? { minSeverity } : {}), ...(limit ? { limit } : {}) }),
      );
    }

    const failOn = parseSeverity(args.flags.get('--fail-on'));
    if (failOn) {
      const all = [...report.archiveFindings, ...report.files.flatMap((f) => f.findings)];
      const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
      if (all.some((f) => rank[f.severity] >= rank[failOn])) process.exit(1);
    }
    return;
  }

  if (args.command === 'diff') {
    const [oldPath, newPath] = args.positional;
    if (!oldPath || !newPath) fail('diff 需要两个路径: <old> <new>');
    const oldReport = scanPath(requireInput(oldPath), options);
    const newReport = scanPath(requireInput(newPath), options);
    const diff = diffReports(oldReport, newReport);

    if (args.flags.has('--json')) {
      process.stdout.write(`${renderDiffJson(diff)}\n`);
    } else {
      const limitValue = args.flags.get('--limit');
      const limit = typeof limitValue === 'string' ? Number.parseInt(limitValue, 10) : undefined;
      process.stdout.write(renderDiff(diff, limit ? { limit } : {}));
    }

    const failOn = parseSeverity(args.flags.get('--fail-on'));
    if (failOn) {
      const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
      if (diff.newFindings.some((f) => rank[f.severity] >= rank[failOn])) process.exit(1);
    }
    return;
  }

  fail(`未知命令: ${args.command}\n\n${HELP}`);
}

main();
