/**
 * Finding 构造、指纹与去重。
 *
 * 指纹刻意不含行号:同一段恶意代码在补丁版本里往上挪几行不该算"新行为"。
 * 差分逻辑基于 (ruleId, file, 归一化后的 evidence) 三元组。
 */

import { createHash } from 'node:crypto';
import { rule } from './rules';
import type { Category, Finding, Severity } from './types';

export interface FindingInput {
  ruleId: string;
  /** 覆盖规则默认严重度(用于同规则不同置信度的场景) */
  severityOverride?: Severity;
  file: string;
  line?: number;
  column?: number;
  evidence?: string;
  /** 覆盖规则的默认描述,用于补充上下文 */
  message?: string;
  tags?: string[];
  decodedFrom?: string;
  /** 提高权重:同一作用域内出现组合行为 */
  weightBoost?: number;
}

/** 调用方通常把文件名绑定在分析上下文里,这里允许省略 */
export type FindingDraft = Omit<FindingInput, 'file'> & { file?: string };

/** 每个严重度对应的权重上限 */
const SEVERITY_CAP: Record<Severity, number> = {
  info: 10,
  low: 30,
  medium: 55,
  high: 78,
  critical: 100,
};

/** 把草稿补全成完整输入 */
export function completeDraft(draft: FindingDraft, defaultFile: string): FindingInput {
  return { ...draft, file: draft.file || defaultFile };
}

/** 把 evidence 归一化:压掉数字、长串和空白,让同一行为的指纹稳定 */
function normalizeEvidence(raw: string): string {
  return raw
    .replace(/\s+/g, ' ')
    .replace(/[0-9a-f]{16,}/gi, '<hex>')
    .replace(/[A-Za-z0-9+/]{24,}={0,2}/g, '<b64>')
    .replace(/\d+/g, '<n>')
    .replace(/['"`]/g, '')
    .trim()
    .slice(0, 200);
}

export function fingerprintOf(ruleId: string, file: string, evidence: string): string {
  return createHash('sha256').update(`${ruleId}\u0000${file}\u0000${normalizeEvidence(evidence)}`).digest('hex').slice(0, 16);
}

export function makeFinding(input: FindingInput): Finding {
  const def = rule(input.ruleId);
  const evidence = (input.evidence ?? '').slice(0, 200);
  const severity = input.severityOverride ?? (def.severity as Severity);
  // 覆盖严重度时,权重也跟着严重度走:否则"降级为 medium 的发现"仍带着 high 的 60 分,
  // 评分与展示会互相矛盾。差值不超过 25,避免覆盖后权重跳变过大。
  const severityCap = SEVERITY_CAP[severity];
  const baseWeight = Math.min(def.weight, severityCap);
  const weight = Math.max(0, Math.min(100, baseWeight + (input.weightBoost ?? 0)));
  const finding: Finding = {
    ruleId: def.id,
    category: def.category as Category,
    severity,
    weight,
    title: def.title,
    message: input.message ?? def.description,
    file: input.file,
    line: input.line ?? 1,
    column: input.column ?? 1,
    evidence,
    tags: input.tags ?? [],
    effectiveWeight: weight,
    fingerprint: fingerprintOf(def.id, input.file, evidence),
  };
  if (input.decodedFrom) finding.decodedFrom = input.decodedFrom;
  return finding;
}

/**
 * 同一文件内完全相同的发现(同规则 + 同归一化证据)只保留权重最高的一条,
 * 并合并行号到 tags,避免一个正则命中几十次把报告刷爆。
 */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const f of findings) {
    // 同规则 + 同证据(即使来源链不同)合并为一条,来源记进 tags
    const key = f.fingerprint;
    const prev = best.get(key);
    if (!prev) {
      best.set(key, { ...f, tags: [...f.tags] });
      continue;
    }
    // 合并来源链,保留每一条被合并发现的出处
    if (f.decodedFrom && f.decodedFrom !== prev.decodedFrom) {
      const tag = `also-from=${f.decodedFrom}`;
      if (!prev.tags.includes(tag)) prev.tags.push(tag);
    }
    if (f.weight > prev.weight) {
      const occurrences = prev.tags.filter((t) => t.startsWith('occurrences=')).map((t) => Number(t.slice(12)))[0] ?? 1;
      prev.weight = f.weight;
      prev.effectiveWeight = f.weight;
      prev.line = f.line;
      prev.column = f.column;
      prev.evidence = f.evidence;
      prev.tags.push(`occurrences=${occurrences + 1}`);
    } else {
      const countTag = prev.tags.find((t) => t.startsWith('occurrences='));
      const count = countTag ? Number(countTag.slice(12)) : 1;
      prev.tags = prev.tags.filter((t) => !t.startsWith('occurrences='));
      prev.tags.push(`occurrences=${count + 1}`);
    }
  }
  return [...best.values()];
}
