/**
 * package.json 生命周期脚本 + 安装脚本行为的分析。
 *
 * npm 会在 `npm install` 时按 preinstall → install → postinstall → prepare 顺序执行这些命令。
 * 这是投毒包最常用的触发器,所以单独建模,并对脚本内容做 shell 层面的特征分析。
 */

import { makeFinding } from '../findings';
import { decodeBase64, decodeEscapes, extractTextPayloads, looksLikeBase64 } from '../deobfuscate';
import type { DecodedPayload } from '../deobfuscate';
import type { Finding } from '../types';

const LIFECYCLE_KEYS = ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare', 'prepublish', 'preuninstall', 'uninstall'];

export interface InstallScript {
  name: string;
  command: string;
}

export function collectLifecycleScripts(pkg: Record<string, unknown>): InstallScript[] {
  const scripts = pkg.scripts;
  if (!scripts || typeof scripts !== 'object') return [];
  const out: InstallScript[] = [];
  for (const key of LIFECYCLE_KEYS) {
    const value = (scripts as Record<string, unknown>)[key];
    if (typeof value === 'string' && value.trim() !== '') out.push({ name: key, command: value });
  }
  return out;
}

export interface InstallAnalysis {
  findings: Finding[];
  payloads: DecodedPayload[];
  /** 提取到的安装阶段命令序列,用于差分展示 */
  commands: string[];
}

interface ShellPattern {
  re: RegExp;
  ruleId: string;
  message?: string;
}

const REMOTE_FETCH = /(?:curl|wget|fetch)\s+(?:[^\n|;]*?)\s*(?:\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b|\|\s*node\b|\|\s*python[0-9.]*\b)/i;

const PATTERNS: ShellPattern[] = [
  {
    re: REMOTE_FETCH,
    ruleId: 'install.shell-pipe',
    message: '安装脚本把远端内容直接管道给 shell/node 执行',
  },
  {
    re: /\b(?:curl|wget)\b[^\n;]*\b(?:https?|ftp):\/\/|(?:https?|ftp):\/\/[^\s'"]+\s*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/i,
    ruleId: 'install.network-command',
  },
  {
    re: /\bnode\s+(?:-[a-z]*\s+)*-e\b|\bnode\s+(?:-[a-z]*\s+)*-p\b|\bnode\s*<<<|\bnode\s*<\(/i,
    ruleId: 'install.node-eval',
  },
  {
    re: /\bpowershell(?:\.exe)?\b|\bpwsh\b|\bInvoke-Expression\b|\bIEX\s*\(/i,
    ruleId: 'install.powershell',
  },
  {
    re: /\bbase64\s+(?:-d|--decode)\b|(?:ba|z)?sh\s+-c\s+["']?\$\(/i,
    ruleId: 'install.encoded-command',
  },
  {
    re: /\bchmod\s+(?:\+x|[0-7]*7[0-7]*)\b|\brm\s+-rf\s+(?:\/|~|\$HOME)|\bcrontab\s+(?:-e|-l|file|-)|\b\/etc\/cron\b|>>?\s*~?\/?\.(?:bashrc|zshrc|profile|bash_profile)\b|\b~\/\.ssh\b|\bLaunchAgents\b|\breg\s+add\b.*\\Run\b/i,
    ruleId: 'install.suspicious-shell',
  },
];

/** 判断脚本里是否有长编码串 */
function findEncodedBlob(command: string): string | null {
  const b64 = /[A-Za-z0-9+/]{60,}={0,2}/g;
  let m: RegExpExecArray | null;
  while ((m = b64.exec(command)) !== null) {
    if (looksLikeBase64(m[0])) return m[0];
  }
  const escaped = command.match(/(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}){24,}/);
  if (escaped) return escaped[0];
  return null;
}

export function analyzeInstallScripts(scripts: InstallScript[], file = 'package.json'): InstallAnalysis {
  const findings: Finding[] = [];
  const payloads: DecodedPayload[] = [];
  const commands: string[] = [];

  for (const script of scripts) {
    const command = script.command;
    commands.push(`${script.name}: ${command}`);
    const evidence = command.length > 180 ? `${command.slice(0, 180)}…` : command;
    const loc = 1;

    findings.push(
      makeFinding({
        ruleId: 'supply.install-script-present',
        file,
        line: loc,
        evidence: `${script.name}: ${evidence}`,
        message: `声明了生命周期脚本 ${script.name},npm install 时自动执行。`,
        tags: [`script=${script.name}`],
      }),
    );

    let matchedAny = false;
    for (const pattern of PATTERNS) {
      if (!pattern.re.test(command)) continue;
      matchedAny = true;
      findings.push(
        makeFinding({
          ruleId: pattern.ruleId,
          file,
          line: loc,
          evidence: `${script.name}: ${evidence}`,
          ...(pattern.message ? { message: pattern.message } : {}),
          tags: [`script=${script.name}`],
        }),
      );
    }

    const blob = findEncodedBlob(command);
    if (blob) {
      findings.push(
        makeFinding({
          ruleId: 'install.obfuscated-payload',
          file,
          line: loc,
          evidence: blob.slice(0, 120),
          tags: [`script=${script.name}`, `length=${blob.length}`],
        }),
      );

      // 纯静态解码:base64 / 八进制转义,不执行
      const decoded = looksLikeBase64(blob) ? decodeBase64(blob) : decodeEscapes(blob);
      if (decoded !== null) {
        payloads.push({
          text: decoded,
          method: looksLikeBase64(blob) ? 'base64' : 'hex',
          origin: `${file}:${script.name} 内嵌载荷`,
          sourcePreview: blob.slice(0, 80),
          depth: 1,
          looksExecutable: true,
          textKind: 'code',
        });
      }
    }

    const readsEnv = /(?:\$\{?[A-Z_]*(?:TOKEN|SECRET|KEY|PASSWORD|NPM_|AWS_|GITHUB_)[A-Z_]*\}?|\bprintenv\b|\benv\b\s*(?:\||>))/i.test(command);
    const doesNetwork = /\b(?:curl|wget|nc|ncat|http|https|fetch|Invoke-WebRequest)\b/i.test(command);
    if (readsEnv && doesNetwork) {
      findings.push(
        makeFinding({
          ruleId: 'install.env-and-network',
          file,
          line: loc,
          evidence: `${script.name}: ${evidence}`,
          tags: [`script=${script.name}`],
        }),
      );
    }

    // 文本层面的编码块解码(例如 node -e 里的 base64)
    for (const payload of extractTextPayloads(command, file, 1)) {
      payloads.push(payload);
    }

    void matchedAny;
  }

  // 汇总:多个脚本中任意一个命中高危 → 追加"安装期存在危险行为"的能力标签,权重由 scorer 处理
  return { findings, payloads, commands };
}
