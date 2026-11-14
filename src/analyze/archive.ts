/**
 * 归档层面的检查:条目类型、路径安全、可执行文件、隐藏文件、元数据。
 */

import { makeFinding } from '../findings';
import type { Finding, PackageMeta, TarEntry } from '../types';

const EXEC_MAGIC: Array<{ name: string; test: (b: Buffer) => boolean }> = [
  { name: 'ELF', test: (b) => b.length > 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46 },
  { name: 'Mach-O', test: (b) => b.length > 4 && ((b[0] === 0xcf && b[1] === 0xfa) || (b[0] === 0xfe && b[1] === 0xed) || (b[0] === 0xce && b[1] === 0xfa) || (b[0] === 0xbe && b[1] === 0xba)) },
  { name: 'PE', test: (b) => b.length > 2 && b[0] === 0x4d && b[1] === 0x5a },
  { name: 'wasm', test: (b) => b.length > 4 && b[0] === 0x00 && b[1] === 0x61 && b[2] === 0x73 && b[3] === 0x6d },
];

const ARCHIVE_BANNED_NAMES = new Set(['.npmrc', '.git-credentials', '.netrc', '.pypirc', '.htpasswd']);

const SCRIPT_EXTENSION_RE = /\.(?:sh|bash|zsh|fish|ps1|bat|cmd|js|mjs|cjs)$/i;

export interface ArchiveFindingsResult {
  findings: Finding[];
  hiddenExecutables: string[];
}

export function analyzeArchiveEntries(
  entries: TarEntry[],
  unsafePaths: string[],
  symlinks: Array<{ path: string; target: string }>,
  hardLinks: Array<{ path: string; target: string }>,
  maxFileBytes: number,
): ArchiveFindingsResult {
  const findings: Finding[] = [];
  const hiddenExecutables: string[] = [];
  const seenPaths = new Map<string, number>();

  for (const raw of unsafePaths) {
    findings.push(
      makeFinding({
        ruleId: 'artifact.path-traversal',
        file: raw,
        line: 1,
        evidence: raw.slice(0, 160),
        message: `归档条目路径逃逸包根:${raw}`,
      }),
    );
  }

  for (const link of symlinks) {
    // 目标为绝对路径或含 .. 逃逸 → 高危
    const target = link.target.replace(/\\/g, '/');
    const escapes = target.startsWith('/') || target.split('/').includes('..');
    if (escapes) {
      findings.push(
        makeFinding({
          ruleId: 'artifact.symlink-escape',
          file: link.path,
          line: 1,
          evidence: `${link.path} → ${link.target}`,
        }),
      );
    }
  }
  for (const link of hardLinks) {
    if (link.target.split('/').includes('..') || link.target.startsWith('/')) {
      findings.push(
        makeFinding({
          ruleId: 'artifact.symlink-escape',
          file: link.path,
          line: 1,
          evidence: `hardlink ${link.path} → ${link.target}`,
        }),
      );
    }
  }

  for (const entry of entries) {
    if (entry.type === 'dir') continue;
    const count = (seenPaths.get(entry.path) ?? 0) + 1;
    seenPaths.set(entry.path, count);

    const base = entry.path.split('/').pop() ?? entry.path;
    if (entry.path.startsWith('.') || entry.path.includes('/.')) {
      if (ARCHIVE_BANNED_NAMES.has(base)) {
        findings.push(
          makeFinding({
            ruleId: 'artifact.dotfile',
            file: entry.path,
            line: 1,
            evidence: entry.path,
            message: `包内包含 ${base},可能被 npm/yarn 或后续工具当成真实配置读取。`,
          }),
        );
      }
    }

    if (entry.type !== 'file') continue;
    if (entry.bytes.length > maxFileBytes * 0.8) {
      findings.push(
        makeFinding({
          ruleId: 'artifact.oversized-file',
          file: entry.path,
          line: 1,
          evidence: `${entry.bytes.length} 字节`,
        }),
      );
    }

    const magic = EXEC_MAGIC.find((m) => m.test(entry.bytes));
    const executableBit = (entry.mode & 0o111) !== 0;
    if (magic) {
      hiddenExecutables.push(entry.path);
      findings.push(
        makeFinding({
          ruleId: 'artifact.hidden-executable',
          file: entry.path,
          line: 1,
          evidence: `${magic.name} 二进制,${entry.bytes.length} 字节`,
          tags: [`magic=${magic.name}`],
        }),
      );
    } else if (executableBit && !SCRIPT_EXTENSION_RE.test(entry.path) && !entry.path.includes('/bin/') && !/^bin\//.test(entry.path)) {
      // 浏览器可执行位很常见;`bin/` 下的 CLI 入口本来就该可执行。
      // 只在"既不是脚本、也不在 bin 目录"时提示,避免把 semver/uuid 这类正常包里
      // 的 dist-node/bin 入口当成投放的二进制。
      findings.push(
        makeFinding({
          ruleId: 'artifact.hidden-executable',
          file: entry.path,
          line: 1,
          evidence: `mode=${entry.mode.toString(8)} 非脚本文件带可执行位`,
          severityOverride: 'medium',
        }),
      );
    }
  }

  for (const [path, count] of seenPaths) {
    if (count > 1) {
      findings.push(makeFinding({ ruleId: 'artifact.hash-mismatch', file: path, line: 1, evidence: `${count} 个同名条目` }));
    }
  }

  return { findings, hiddenExecutables };
}

export interface MetadataContext {
  /** 已知热门包名,用于拼写仿冒判断 */
  popularNames?: string[];
}

const DEFAULT_POPULAR = [
  'lodash',
  'react',
  'express',
  'axios',
  'chalk',
  'debug',
  'typescript',
  'webpack',
  'eslint',
  'prettier',
  'request',
  'moment',
  'underscore',
  'commander',
  'dotenv',
  'cross-env',
  'node-fetch',
  'colors',
  'event-stream',
  'babel-core',
];

/** Damerau-Levenshtein 距离,阈值 2 内视为可疑 */
function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 2) return 99;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i]![0] = i;
  for (let j = 0; j <= n; j++) dp[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i]![j] = Math.min(dp[i - 1]![j]! + 1, dp[i]![j - 1]! + 1, dp[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i]![j] = Math.min(dp[i]![j]!, dp[i - 2]![j - 2]! + 1);
      }
    }
  }
  return dp[m]![n]!;
}

export function normalizePackageName(name: string): string {
  return name.replace(/^@[^/]+\//, '').replace(/[-_.]/g, '').toLowerCase();
}

export function analyzeMetadata(pkg: PackageMeta, ctx: MetadataContext = {}): Finding[] {
  const findings: Finding[] = [];
  const popular = ctx.popularNames ?? DEFAULT_POPULAR;
  const base = normalizePackageName(pkg.name);
  if (base.length >= 4) {
    for (const candidate of popular) {
      const target = normalizePackageName(candidate);
      if (base === target) continue;
      const dist = editDistance(base, target);
      if (dist > 0 && dist <= (target.length > 8 ? 2 : 1)) {
        findings.push(
          makeFinding({
            ruleId: 'supply.typosquat-suspect',
            file: 'package.json',
            line: 1,
            evidence: `${pkg.name} vs ${candidate} (距离 ${dist})`,
            message: `包名 ${pkg.name} 与常见包 ${candidate} 极为相似,存在仿冒可能。`,
          }),
        );
        break;
      }
    }
  }

  // 依赖自带生命周期脚本的提示(仅当依赖列表里有可疑名字)
  const scripts = pkg.lifecycleScripts;
  if (Object.keys(scripts).length === 0) {
    // 正常的库
  }

  if (!pkg.name || !pkg.version) {
    findings.push(
      makeFinding({
        ruleId: 'supply.install-script-present',
        file: 'package.json',
        line: 1,
        evidence: '缺少 name/version',
        message: 'package.json 缺少必要的 name/version 字段,归档可能被重新打包。',
      }),
    );
  }

  return findings;
}
