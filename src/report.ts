/**
 * 输出层:人类可读、JSON(供 CI 缓存基线)、SARIF(GitHub code scanning)。
 */

import type { ArchiveReport, DiffResult, Finding, Severity } from './types';
import { scoreFindings } from './score';

const COLORS = {
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  green: '\u001b[32m',
  cyan: '\u001b[36m',
  magenta: '\u001b[35m',
  gray: '\u001b[90m',
};

const useColor = process.env.NO_COLOR === undefined && process.stdout.isTTY !== false;

function paint(text: string, color: keyof typeof COLORS): string {
  return useColor ? `${COLORS[color]}${text}${COLORS.reset}` : text;
}

function severityColor(severity: Severity): keyof typeof COLORS {
  switch (severity) {
    case 'critical':
      return 'red';
    case 'high':
      return 'magenta';
    case 'medium':
      return 'yellow';
    case 'low':
      return 'cyan';
    default:
      return 'gray';
  }
}

export interface RenderOptions {
  verbose?: boolean;
  /** 只显示达到该等级的发现 */
  minSeverity?: Severity;
  /** 最大展示条数 */
  limit?: number;
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function renderReport(report: ArchiveReport, options: RenderOptions = {}): string {
  const all = [...report.archiveFindings, ...report.files.flatMap((f) => f.findings)];
  const score = scoreFindings(all);
  const lines: string[] = [];

  const pkg = report.package;
  lines.push('');
  lines.push(paint(`pkg://${pkg.name || '(unnamed)'}@${pkg.version || '(no version)'}`, 'bold'));
  lines.push(paint(`  source: ${report.source}`, 'dim'));
  lines.push(paint(`  files: ${report.stats.fileCount}  (JS: ${report.stats.jsFileCount})   decoded-layers: ${report.stats.layersDecoded}   ${report.stats.durationMs}ms`, 'dim'));
  if (pkg.description) lines.push(paint(`  ${pkg.description.slice(0, 100)}`, 'dim'));

  const verdictColor: keyof typeof COLORS =
    score.verdict.level === 'critical' ? 'red' : score.verdict.level === 'high' ? 'magenta' : score.verdict.level === 'suspicious' ? 'yellow' : score.verdict.level === 'low' ? 'cyan' : 'green';
  lines.push('');
  lines.push(`${paint('verdict:', 'bold')} ${paint(score.verdict.level.toUpperCase(), verdictColor)}  ${paint(`score ${score.total}/100`, 'bold')}  ${paint(score.verdict.label, 'dim')}`);

  const cats = Object.entries(score.byCategory).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  if (cats.length) {
    lines.push(paint(`  category: ${cats.map(([k, v]) => `${k}=${v}`).join('  ')}`, 'dim'));
  }
  if (score.chains.length) {
    lines.push(`  ${paint('chains:', 'magenta')} ${score.chains.map((c) => `${c.label} (+${c.bonus})`).join(' | ')}`);
  }

  if (pkg.lifecycleScripts && Object.keys(pkg.lifecycleScripts).length) {
    lines.push('');
    lines.push(paint('lifecycle scripts:', 'bold'));
    for (const [name, cmd] of Object.entries(pkg.lifecycleScripts)) {
      lines.push(`  ${paint(name, 'yellow')}: ${cmd.length > 160 ? `${cmd.slice(0, 160)}…` : cmd}`);
    }
  }

  const minRank = options.minSeverity ? SEVERITY_RANK[options.minSeverity] : 0;
  const visible = all.filter((f) => SEVERITY_RANK[f.severity] >= minRank).sort(bySeverityRank);
  const limit = options.limit ?? 200;

  lines.push('');
  lines.push(paint(`findings (${visible.length}/${all.length}):`, 'bold'));
  if (visible.length === 0) {
    lines.push(paint('  none', 'green'));
  }
  for (const f of visible.slice(0, limit)) {
    const color = severityColor(f.severity);
    const loc = `${f.file}:${f.line}:${f.column}`;
    lines.push(`  ${paint(`[${f.severity.toUpperCase().padEnd(8)}]`, color)} ${paint(f.ruleId, 'bold')} ${paint(loc, 'dim')}`);
    lines.push(`      ${f.message}`);
    if (f.evidence) lines.push(`      ${paint('›', 'gray')} ${paint(truncate(f.evidence, 150), 'dim')}`);
    if (f.decodedFrom) lines.push(`      ${paint(`↳ decoded from ${f.decodedFrom}`, 'cyan')}`);
    if (f.tags.length) lines.push(`      ${paint(f.tags.join(' '), 'gray')}`);
  }
  if (visible.length > limit) lines.push(paint(`  … ${visible.length - limit} more (use --json for full list)`, 'dim'));

  if (report.stats.skipped.length) {
    lines.push('');
    for (const s of report.stats.skipped) lines.push(paint(`  ! ${s}`, 'yellow'));
  }
  lines.push('');
  return lines.join('\n');
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function bySeverityRank(a: Finding, b: Finding): number {
  const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (rank !== 0) return rank;
  return b.effectiveWeight - a.effectiveWeight;
}

export function renderJson(report: ArchiveReport, extra: Record<string, unknown> = {}): string {
  const all = [...report.archiveFindings, ...report.files.flatMap((f) => f.findings)];
  const score = scoreFindings(all);
  return JSON.stringify(
    {
      tool: 'pkgsentry',
      version: '0.1.0',
      ...extra,
      source: report.source,
      package: report.package,
      verdict: score.verdict,
      score: { total: score.total, raw: score.raw, byCategory: score.byCategory, chains: score.chains },
      stats: report.stats,
      findings: all,
      files: report.files,
      archiveFindings: report.archiveFindings,
    },
    null,
    2,
  );
}

export function renderDiff(diff: DiffResult, options: RenderOptions = {}): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(paint(`diff: ${diff.oldVersion} → ${diff.newVersion}`, 'bold'));
  lines.push(`  score: ${diff.oldScore} → ${paint(String(diff.newScore), diff.scoreDelta > 0 ? 'red' : diff.scoreDelta < 0 ? 'green' : 'dim')} (${diff.scoreDelta >= 0 ? '+' : ''}${diff.scoreDelta})`);
  lines.push(`  verdict: ${diff.oldVerdict.level} → ${diff.newVerdict.level}`);

  if (diff.scriptChanges.length) {
    lines.push('');
    lines.push(paint('script changes:', 'bold'));
    for (const change of diff.scriptChanges) {
      lines.push(`  ${paint(change.name, 'yellow')}`);
      if (change.before !== undefined) lines.push(`    - ${change.before}`);
      if (change.after !== undefined) lines.push(`    + ${paint(change.after, 'red')}`);
    }
  }

  if (diff.addedFiles.length) {
    lines.push('');
    lines.push(paint('new files with findings:', 'bold'));
    for (const f of diff.addedFiles.slice(0, 40)) lines.push(`  + ${f}`);
  }

  lines.push('');
  const newCount = diff.newFindings.length;
  lines.push(paint(`NEW behaviours (${newCount}):`, newCount ? 'red' : 'green'));
  if (newCount === 0) lines.push(paint('  none — 没有新增行为', 'green'));
  const limit = options.limit ?? 100;
  for (const f of diff.newFindings.slice(0, limit)) {
    lines.push(`  ${paint('+', 'red')} ${paint(`[${f.severity.toUpperCase()}]`, severityColor(f.severity))} ${paint(f.ruleId, 'bold')} ${paint(`${f.file}:${f.line}`, 'dim')} ${paint(`weight ${f.weight}→${f.effectiveWeight}`, 'gray')}`);
    lines.push(`      ${f.message}`);
    if (f.evidence) lines.push(`      ${paint(`› ${truncate(f.evidence, 150)}`, 'dim')}`);
  }

  if (diff.removedRuleIds.length) {
    lines.push('');
    lines.push(paint(`REMOVED behaviours: ${diff.removedRuleIds.join(', ')}`, 'dim'));
  }
  if (diff.changedFindings.length) {
    lines.push('');
    lines.push(paint(`changed findings: ${diff.changedFindings.length}`, 'dim'));
  }
  lines.push('');
  return lines.join('\n');
}

export function renderDiffJson(diff: DiffResult): string {
  return JSON.stringify({ tool: 'pkgsentry', version: '0.1.0', diff }, null, 2);
}

/** SARIF 2.1.0 — 可直接上传 GitHub code scanning */
export function renderSarif(report: ArchiveReport): string {
  const all = [...report.archiveFindings, ...report.files.flatMap((f) => f.findings)];
  const ruleIds = [...new Set(all.map((f) => f.ruleId))];
  const results = all.map((f) => ({
    ruleId: f.ruleId,
    level: sarifLevel(f.severity),
    message: { text: `${f.message}${f.evidence ? ` (evidence: ${f.evidence})` : ''}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: `package/${f.file}` },
          region: { startLine: Math.max(1, f.line), startColumn: Math.max(1, f.column) },
        },
      },
    ],
    properties: { weight: f.effectiveWeight, category: f.category, tags: f.tags, decodedFrom: f.decodedFrom },
  }));

  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'pkgsentry',
              informationUri: 'https://example.invalid/pkgsentry',
              version: '0.1.0',
              rules: ruleIds.map((id) => ({ id, name: id })),
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  );
}

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' | 'none' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default:
      return 'none';
  }
}
