/**
 * 版本差分。
 *
 * 目标场景:同一个包从 v1 → v2,新版本"多出来"的行为最值得看(投毒往往就是在补丁版本里
 * 塞进恶意代码)。因此:
 *  - 指纹 = (ruleId, file, 归一化证据),不含行号 —— 代码挪行不算新行为;
 *  - 新行为按规则本身的严重度给"新增加成",高危规则新出现时加成更高;
 *  - 消失的行为单独列出(可能是攻击者做的清理,也可能是正常重构)。
 */

import type { ArchiveReport, DiffResult, Finding } from './types';
import { scoreFindings, verdictFor } from './score';

/** 新行为的加权:严重度越高,对总分影响越大 */
export function applyNewnessBoost(finding: Finding): number {
  const base = finding.effectiveWeight;
  switch (finding.severity) {
    case 'critical':
      return Math.min(100, base + 20);
    case 'high':
      return Math.min(100, base + 14);
    case 'medium':
      return Math.min(100, base + 8);
    case 'low':
      return Math.min(100, base + 3);
    default:
      return base;
  }
}

function allFindings(report: ArchiveReport): Finding[] {
  return [...report.archiveFindings, ...report.files.flatMap((f) => f.findings)];
}

/** 用于差分的键:规则 + 文件 + 证据指纹(去掉行号) */
function diffKey(f: Finding): string {
  return f.fingerprint;
}

export function diffReports(oldReport: ArchiveReport, newReport: ArchiveReport): DiffResult {
  const oldFindings = allFindings(oldReport);
  const newFindings = allFindings(newReport);

  const oldByKey = new Map<string, Finding>();
  for (const f of oldFindings) oldByKey.set(diffKey(f), f);

  const fresh: Finding[] = [];
  const changed: Finding[] = [];
  const newKeys = new Set<string>();
  /** 新版本用于评分的视图:新行为替换成加成后的权重 */
  const scoredNew: Finding[] = [];

  for (const f of newFindings) {
    const key = diffKey(f);
    newKeys.add(key);
    const before = oldByKey.get(key);
    if (!before) {
      const isNew: Finding = { ...f, isNew: true, effectiveWeight: applyNewnessBoost(f) };
      fresh.push(isNew);
      scoredNew.push(isNew);
    } else {
      scoredNew.push(f);
      if (before.weight !== f.weight) changed.push(f);
    }
  }

  // 消失的行为
  const removed: Finding[] = [];
  for (const [key, f] of oldByKey) {
    if (!newKeys.has(key)) removed.push(f);
  }

  const newScoreBreakdown = scoreFindings(scoredNew);
  const oldScoreBreakdown = scoreFindings(oldFindings);
  const oldScore = oldScoreBreakdown.total;
  const scoreDelta = Math.round((newScoreBreakdown.total - oldScore) * 10) / 10;

  // package.json 脚本差异
  const scriptChanges: DiffResult['scriptChanges'] = [];
  const oldScripts = oldReport.package.lifecycleScripts;
  const newScripts = newReport.package.lifecycleScripts;
  for (const name of new Set([...Object.keys(oldScripts), ...Object.keys(newScripts)]) as Set<string>) {
    const before = oldScripts[name];
    const after = newScripts[name];
    if (before !== after) {
      scriptChanges.push({ name, ...(before !== undefined ? { before } : {}), ...(after !== undefined ? { after } : {}) });
    }
  }

  // 文件差异
  const oldFiles = new Set(oldReport.files.map((f) => f.path));
  const newFiles = new Set(newReport.files.map((f) => f.path));
  const addedFiles = [...newFiles].filter((p) => !oldFiles.has(p)).sort();
  const removedFiles = [...oldFiles].filter((p) => !newFiles.has(p)).sort();

  return {
    oldSource: oldReport.source,
    newSource: newReport.source,
    oldVersion: oldReport.package.version || '(unknown)',
    newVersion: newReport.package.version || '(unknown)',
    newFindings: fresh.sort(bySeverity),
    changedFindings: changed,
    removedRuleIds: [...new Set(removed.map((f) => f.ruleId))].sort(),
    scoreDelta,
    oldScore,
    newScore: newScoreBreakdown.total,
    oldVerdict: verdictFor(oldScore, oldFindings),
    newVerdict: verdictFor(newScoreBreakdown.total, newFindings),
    scriptChanges,
    addedFiles,
    removedFiles,
  };
}

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function bySeverity(a: Finding, b: Finding): number {
  const rank = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
  if (rank !== 0) return rank;
  return b.effectiveWeight - a.effectiveWeight;
}
