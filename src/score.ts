/**
 * 评分与结论。
 *
 * 评分不是简单加总:高危链(读凭据+外发、解码+动态执行)有乘数,
 * 同一类别大量低分命中会饱和(递减),避免"规则数量多"的包被误判。
 * 最终给出 0-100 分与 clean/low/suspicious/high/critical 五档。
 */

import type { Category, Finding, Severity, Verdict } from './types';

/** 按严重度给每条命中一个代表分(取规则权重与严重度下限的较大者) */
const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const SEVERITY_FLOOR: Record<Severity, number> = {
  info: 5,
  low: 15,
  medium: 30,
  high: 55,
  critical: 80,
};

/** 类别上限:防止某类规则刷分淹没其它信号 */
const CATEGORY_CAP: Record<Category, number> = {
  install: 100,
  artifact: 70,
  credentials: 80,
  network: 70,
  execution: 75,
  obfuscation: 60,
  filesystem: 65,
  'supply-chain': 45,
  evasion: 60,
};

/**
 * 高危组合:命中左侧全部规则时,总分额外加成。
 * 这些组合是真实投毒样本里反复出现的链条,单独出现其中一环并不致命。
 */
const CHAINS: Array<{ id: string; requires: string[]; bonus: number; label: string }> = [
  { id: 'exfil-chain', requires: ['cred.sensitive-env|cred.env-dump|cred.ssh-directory|cred.npmrc|cred.browser-data', 'net.http-request|net.raw-socket|net.dns-exfil'], bonus: 22, label: '读凭据 + 出站网络' },
  { id: 'decode-exec-chain', requires: ['obf.base64-blob|obf.hex-blob|obf.charcode-blob|obf.payload-decoded', 'exec.encoded-payload|exec.eval|exec.new-function|exec.vm-module'], bonus: 18, label: '编码载荷 + 动态执行' },
  { id: 'remote-code-chain', requires: ['net.http-request|net.raw-socket', 'exec.eval|exec.new-function|exec.vm-module|exec.child-process'], bonus: 20, label: '网络 + 执行' },
  { id: 'install-exfil-chain', requires: ['supply.install-script-present|install.network-command|install.shell-pipe', 'cred.sensitive-env|cred.env-dump|cred.ssh-directory|cred.npmrc'], bonus: 25, label: '安装期执行 + 凭据访问' },
  { id: 'persistence-chain', requires: ['fs.autostart|fs.write-outside-package', 'exec.child-process|exec.eval|net.http-request'], bonus: 15, label: '持久化 + 执行/外发' },
];

function matches(ruleIds: Set<string>, spec: string): boolean {
  for (const alt of spec.split('|')) if (ruleIds.has(alt)) return true;
  return false;
}

export function severityScore(finding: Finding): number {
  const floor = SEVERITY_FLOOR[finding.severity] ?? 0;
  return Math.max(finding.effectiveWeight, floor);
}

export interface ScoreBreakdown {
  raw: number;
  byCategory: Record<string, number>;
  chains: Array<{ id: string; label: string; bonus: number }>;
  total: number;
  verdict: Verdict;
}

/**
 * 计算总分。
 * @param findings 全部发现
 * @param options.onlyNewForBonus 差分模式下只把新行为计入加分
 */
export function scoreFindings(findings: Finding[]): ScoreBreakdown {
  const ruleIds = new Set(findings.map((f) => f.ruleId));

  // 已经计过分的规则不再重复计分(同规则不同行号),避免刷分
  const categories = new Map<Category, number>();
  const seenRules = new Set<string>();
  // 同一类别内的去重:同一条证据(指纹相同)即使来自不同文件也视为一个信号
  const seenEvidence = new Set<string>();

  for (const f of findings) {
    if (f.severity === 'info') continue;
    const evidenceKey = `${f.category}\u0000${f.fingerprint}`;
    if (seenRules.has(f.ruleId) && seenEvidence.has(evidenceKey)) continue;
    if (seenRules.has(f.ruleId)) {
      // 同规则但证据/位置不同(例如多个安装脚本各自命中),按一个规则的满额计一次即可
      continue;
    }
    seenRules.add(f.ruleId);
    seenEvidence.add(evidenceKey);
    const score = severityScore(f);
    // 同类后续规则的边际贡献递减:1, 0.55, 0.4, 0.31…(按该类已累积分数归一)
    const prev = categories.get(f.category) ?? 0;
    const decay = prev === 0 ? 1 : Math.max(0.25, 1 / (1 + Math.sqrt(prev / 25)));
    categories.set(f.category, prev + score * decay);
  }

  const byCategory: Record<string, number> = {};
  let raw = 0;
  for (const [category, value] of categories) {
    const capped = Math.min(value, CATEGORY_CAP[category] ?? 70);
    byCategory[category] = Math.round(capped * 10) / 10;
    raw += capped;
  }

  const chains: Array<{ id: string; label: string; bonus: number }> = [];
  let chainBonus = 0;
  for (const chain of CHAINS) {
    if (!chain.requires.every((spec) => matches(ruleIds, spec))) continue;
    chains.push({ id: chain.id, label: chain.label, bonus: chain.bonus });
    chainBonus += chain.bonus;
  }

  // 饱和:把加和信号压到 0-100,同时保留 tail 区分度。
  // 分母 70 经过样本回归:单条 eval(45)≈47 分(suspicious),
  // 单条 critical 安装脚本(95)≈75 分,典型的"读凭据+外发"链 ≈85+ 分。
  const saturated = 100 * (1 - Math.exp(-(raw + chainBonus) / 70));
  const total = Math.round(Math.min(100, saturated) * 10) / 10;
  return { raw: Math.round(raw * 10) / 10, byCategory, chains, total, verdict: verdictFor(total, findings) };
}

export function verdictFor(total: number, findings: Finding[]): Verdict {
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  // 只有低危/提示信号时不给高风险结论:例如"有 postinstall + 写本地文件"分数可能不低,
  // 但没有任何明确危险行为,结论应该封顶在 suspicious。
  const maxSeverityRank = findings.reduce((max, f) => Math.max(max, SEVERITY_RANK[f.severity]), 0);
  const effectiveTotal = maxSeverityRank <= SEVERITY_RANK.medium ? Math.min(total, 45) : total;
  total = effectiveTotal;
  let level: Verdict['level'];
  let label: string;
  if (total >= 85 || criticalCount >= 2) {
    level = 'critical';
    label = 'critical — 极可能为恶意包或已遭投毒';
  } else if (total >= 65 || criticalCount >= 1) {
    level = 'high';
    label = 'high — 存在明确的高危行为,需人工复核';
  } else if (total >= 40 || highCount >= 2) {
    level = 'suspicious';
    label = 'suspicious — 有可疑行为模式,建议审计';
  } else if (total >= 15) {
    level = 'low';
    label = 'low — 有低风险信号,通常可放行';
  } else {
    level = 'clean';
    label = 'clean — 未发现显著风险';
  }
  return { level, label, score: total };
}
