/**
 * 扫描编排:输入(tarball / 已解压目录)→ 归档检查 → package.json → 各文件规则 → 解码二次扫描 → 评分。
 *
 * 关键约束:任何被分析的内容都不会被执行。tarball 只在内存中解包,
 * 目录输入只读取字节(不跟随符号链接到包外)。
 */

import { readFileSync, readdirSync, lstatSync, realpathSync } from 'node:fs';
import { basename, extname, join, resolve, sep } from 'node:path';
import { buildStaticEnv, parseProgram } from './ast';
import { analyzeJsSource } from './analyze/js';
import { analyzeInstallScripts, collectLifecycleScripts } from './analyze/install';
import { analyzeArchiveEntries, analyzeMetadata } from './analyze/archive';
import { dedupeFindings, makeFinding } from './findings';
import { extractPayloads, extractTextPayloads } from './deobfuscate';
import type { DecodedPayload } from './deobfuscate';
import { scoreFindings } from './score';
import { decompressTarball, readTar, TarLimitError } from './tar';
import type { FileReport, PackageMeta, ScanOptions, TarEntry } from './types';

export const DEFAULT_OPTIONS: ScanOptions = {
  maxFileBytes: 8 * 1024 * 1024,
  maxTotalBytes: 128 * 1024 * 1024,
  maxEntries: 20_000,
  maxDecodeDepth: 3,
  quiet: false,
};

const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx']);
// 文档类文件不参与规则匹配:README 里出现 `curl` 或 `require('x')` 只是示例,
// 把它当行为会淹没真实信号。
const DOC_EXTENSIONS = new Set(['.md', '.markdown', '.rst', '.txt', '.adoc', '.html', '.htm', '.json', '.yml', '.yaml', '.toml', '.lock']);
const TEXT_EXTENSIONS = new Set(['.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd', '.py', '.rb', '.pl']);

/** .d.ts 只是类型声明,不含运行时代码 */
function isDeclarationFile(path: string): boolean {
  return /\.d\.(?:ts|mts|cts)$/i.test(path);
}
const SKIP_DIRS = new Set(['node_modules', '.git', 'test', 'tests', '__tests__', 'docs', 'examples', 'coverage']);
const MAX_TEXT_FILE = 512 * 1024;

export interface LoadedPackage {
  source: string;
  entries: TarEntry[];
  unsafePaths: string[];
  symlinks: Array<{ path: string; target: string }>;
  hardLinks: Array<{ path: string; target: string }>;
  truncated: boolean;
}

/** 从 tarball 文件加载 */
export function loadFromTarball(filePath: string, options: ScanOptions): LoadedPackage {
  const raw = readFileSync(filePath);
  const tarBytes = decompressTarball(raw, options.maxTotalBytes * 2);
  const result = readTar(tarBytes, options);
  return {
    source: filePath,
    entries: result.entries,
    unsafePaths: result.unsafePaths,
    symlinks: result.symlinks,
    hardLinks: result.hardLinks,
    truncated: result.truncated,
  };
}

/**
 * 从已解压目录加载。
 * 使用 lstat 并跳过符号链接,且以 realpath 校验任何路径仍位于根目录内。
 */
export function loadFromDirectory(dir: string, options: ScanOptions): LoadedPackage {
  const root = realpathSync(resolve(dir));
  const entries: TarEntry[] = [];
  const unsafePaths: string[] = [];
  const symlinks: Array<{ path: string; target: string }> = [];
  const hardLinks: Array<{ path: string; target: string }> = [];
  let totalBytes = 0;
  let truncated = false;

  const walk = (current: string) => {
    if (entries.length >= options.maxEntries) {
      truncated = true;
      return;
    }
    let names: string[];
    try {
      names = readdirSync(current);
    } catch {
      return;
    }
    for (const name of names) {
      const abs = join(current, name);
      const rel = abs.slice(root.length + 1).split(sep).join('/');
      let stat;
      try {
        stat = lstatSync(abs);
      } catch {
        continue;
      }
      if (stat.isSymbolicLink()) {
        let target = '';
        try {
          target = require('node:fs').readlinkSync(abs);
        } catch {
          /* ignore */
        }
        symlinks.push({ path: rel, target });
        entries.push({ path: rel, bytes: Buffer.alloc(0), mode: stat.mode, type: 'symlink', linkTarget: target });
        // 不跟随符号链接
        continue;
      }
      if (stat.isDirectory()) {
        entries.push({ path: rel, bytes: Buffer.alloc(0), mode: stat.mode, type: 'dir' });
        if (!SKIP_DIRS.has(name)) walk(abs);
        continue;
      }
      if (!stat.isFile()) continue;
      const limit = Math.min(stat.size, options.maxFileBytes);
      if (stat.size > options.maxFileBytes) truncated = true;
      totalBytes += limit;
      if (totalBytes > options.maxTotalBytes) {
        truncated = true;
        return;
      }
      let bytes: Buffer;
      try {
        const fd = require('node:fs').openSync(abs, 'r');
        try {
          bytes = Buffer.alloc(limit);
          const read = require('node:fs').readSync(fd, bytes, 0, limit, 0);
          bytes = bytes.subarray(0, read);
        } finally {
          require('node:fs').closeSync(fd);
        }
      } catch {
        continue;
      }
      entries.push({ path: rel, bytes, mode: stat.mode, type: 'file' });
    }
  };

  walk(root);
  return { source: dir, entries, unsafePaths, symlinks, hardLinks, truncated };
}

/** 读取 package.json(容错:注释、BOM) */
export function parsePackageJson(bytes: Buffer): Record<string, any> | null {
  let text = bytes.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  try {
    return JSON.parse(text) as Record<string, any>;
  } catch {
    try {
      // 某些包的 json 带注释
      const cleaned = text
        .replace(/^\s*\/\/.*$/gm, '')
        .replace(/\/\*[\s\S]*?\*\//g, '');
      return JSON.parse(cleaned) as Record<string, any>;
    } catch {
      return null;
    }
  }
}

export function packageMetaFrom(pkg: Record<string, any>, entries: TarEntry[]): PackageMeta {
  const lifecycleScripts: Record<string, string> = {};
  for (const script of collectLifecycleScripts(pkg)) lifecycleScripts[script.name] = script.command;

  const dependencies: Record<string, string> = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
    ...(pkg.peerDependencies ?? {}),
  };

  const entryPoints: string[] = [];
  for (const key of ['main', 'module', 'browser', 'types', 'typings']) {
    const value = pkg[key];
    if (typeof value === 'string') entryPoints.push(value);
  }
  if (typeof pkg.bin === 'string') entryPoints.push(pkg.bin);
  else if (pkg.bin && typeof pkg.bin === 'object') {
    for (const value of Object.values(pkg.bin)) if (typeof value === 'string') entryPoints.push(value);
  }

  const authors: string[] = [];
  if (typeof pkg.author === 'string') authors.push(pkg.author);
  else if (pkg.author && typeof pkg.author.name === 'string') authors.push(pkg.author.name);
  if (Array.isArray(pkg.contributors)) {
    for (const c of pkg.contributors) {
      if (typeof c === 'string') authors.push(c);
      else if (c && typeof c.name === 'string') authors.push(c.name);
    }
  }
  if (Array.isArray(pkg.maintainers)) {
    for (const m of pkg.maintainers) {
      if (typeof m === 'string') authors.push(m);
      else if (m && typeof m.name === 'string') authors.push(m.name);
    }
  }

  const meta: PackageMeta = {
    name: typeof pkg.name === 'string' ? pkg.name : '',
    version: typeof pkg.version === 'string' ? pkg.version : '',
    lifecycleScripts,
    dependencies,
    entryPoints: [...new Set(entryPoints)],
    authors: [...new Set(authors)],
  };
  if (typeof pkg.description === 'string') meta.description = pkg.description;
  if (typeof pkg.license === 'string') meta.license = pkg.license;
  const repo = pkg.repository;
  if (typeof repo === 'string') meta.repository = repo;
  else if (repo && typeof repo.url === 'string') meta.repository = repo.url;
  void entries;
  return meta;
}

export interface ScanResultUnscored {
  loaded: LoadedPackage;
  pkg: Record<string, any> | null;
  meta: PackageMeta;
  fileReports: FileReport[];
  archiveFindings: import('./types').Finding[];
  payloadCount: number;
  skipped: string[];
}

/** 对单个文件的内容做分析(含第二层解码递归) */
function analyzeFile(entry: TarEntry, options: ScanOptions): { report: FileReport; payloadCount: number } {
  const path = entry.path;
  const ext = extname(path).toLowerCase();
  const base = basename(path);
  const findings: import('./types').Finding[] = [];
  const capabilities = new Set<string>();
  let payloadCount = 0;

  const isDeclaration = isDeclarationFile(path);
  const isJs = JS_EXTENSIONS.has(ext) && !isDeclaration;
  const isDoc = DOC_EXTENSIONS.has(ext);
  const isText = TEXT_EXTENSIONS.has(ext) || base === 'Dockerfile' || base === 'Makefile';

  if (!isJs && !isText) {
    if (isDeclaration || isDoc) {
      return {
        report: { path, bytes: entry.bytes.length, parseMode: 'other', findings, capabilities: [] },
        payloadCount,
      };
    }
    return {
      report: { path, bytes: entry.bytes.length, parseMode: 'other', findings, capabilities: [] },
      payloadCount,
    };
  }

  const text = entry.bytes.toString('utf8');

  if (isJs) {
    const direct = analyzeJsSource(text, path, { depth: 0 });
    findings.push(...direct.findings);
    for (const cap of direct.capabilities) capabilities.add(cap);

    // 解码 → 二次扫描
    const parsed = parseProgram(text, { allowLoose: true });
    if (parsed) {
      const payloads = extractPayloads(parsed.ast, text, path, options.maxDecodeDepth);
      payloadCount += payloads.length;
      for (const payload of payloads) {
        analyzePayload(payload, findings, capabilities, options);
      }
    } else {
      // 解析失败(可能是被压缩/混淆到无法解析),退到文本解码
      for (const payload of extractTextPayloads(text, path, options.maxDecodeDepth)) {
        payloadCount++;
        analyzePayload(payload, findings, capabilities, options);
      }
    }
  } else if (isText) {
    if (entry.bytes.length > MAX_TEXT_FILE) {
      // 大文本仅扫描前 512KB
    }
    const clipped = text.slice(0, MAX_TEXT_FILE);
    const textFindings = analyzeJsSource(clipped, path, { mode: 'text' });
    findings.push(...textFindings.findings);
    for (const cap of textFindings.capabilities) capabilities.add(cap);

    for (const payload of extractTextPayloads(clipped, path, options.maxDecodeDepth)) {
      payloadCount++;
      analyzePayload(payload, findings, capabilities, options);
    }
  }

  return {
    report: {
      path,
      bytes: entry.bytes.length,
      parseMode: isJs ? 'ast' : 'text',
      findings: dedupeFindings(findings),
      capabilities: [...capabilities],
    },
    payloadCount,
  };
}

/**
 * 对一层解码产物做分析。若解码结果是 JS,走完整 AST 规则;
 * 若是 shell/命令文本,走安装脚本规则(但只作为"文本"处理)。
 */
function analyzePayload(
  payload: DecodedPayload,
  sink: import('./types').Finding[],
  capabilities: Set<string>,
  options: ScanOptions,
  depth = 1,
): void {
  const from = payload.origin;

  // 只有解出"像代码/命令/URL"的内容才值得记一条高危发现。
  // 解出普通文本(正则片段、空白表、资源字符串)在 lodash 这类库里随处可见,
  // 记成 payload-decoded 会直接淹没真实信号。
  if (payload.textKind === 'text') return;
  if (!payload.looksExecutable && payload.textKind !== 'url') return;

  sink.push(
    makeFinding({
      ruleId: 'obf.payload-decoded',
      file: from.split(':')[0] ?? from,
      line: Number(from.split(':')[1]) || 1,
      evidence: payload.text.slice(0, 160),
      message: `以 ${payload.method} 还原出${payload.textKind === 'code' ? '可执行代码' : 'URL'}`,
      tags: [`method=${payload.method}`, `depth=${payload.depth}`],
      decodedFrom: from,
    }),
  );
  capabilities.add('obfuscation');

  if (payload.depth > options.maxDecodeDepth) return;

  if (payload.textKind === 'code') {
    const res = analyzeJsSource(payload.text, from.split(':')[0] ?? from, {
      decodedFrom: from,
      depth: payload.depth,
    });
    for (const f of res.findings) {
      // 解码后的执行/网络/凭据命中,视为比表层更强的信号
      f.decodedFrom = from;
      f.tags = [...f.tags, 'from-decoded-payload'];
      if (f.ruleId === 'exec.eval' || f.ruleId === 'exec.new-function' || f.ruleId === 'exec.child-process' || f.ruleId === 'exec.vm-module') {
        const escalated = makeFinding({
          ruleId: 'exec.encoded-payload',
          file: f.file,
          line: f.line,
          evidence: f.evidence,
          message: `解码后的载荷中出现 ${f.ruleId}`,
          decodedFrom: from,
        });
        sink.push(escalated);
        capabilities.add('execution');
      }
      sink.push(f);
      capabilities.add(capabilityOfRule(f.ruleId));
    }

    // 进一步:解码代码里再套编码,继续下钻
    const nested = parseProgram(payload.text, { allowLoose: true });
    if (nested && payload.depth < options.maxDecodeDepth) {
      for (const inner of extractPayloads(nested.ast, payload.text, from, options.maxDecodeDepth - payload.depth)) {
        analyzePayload(inner, sink, capabilities, options, payload.depth + 1);
      }
    }
    return;
  }

  // shell / 命令文本:用安装脚本规则做只读匹配
  if (/(?:curl|wget|sh\s+-c|powershell|chmod|process\.env|crontab)/i.test(payload.text)) {
    const shellish = analyzeInstallScripts([{ name: 'decoded-payload', command: payload.text }], from.split(':')[0] ?? 'decoded');
    for (const f of shellish.findings) {
      if (f.ruleId === 'supply.install-script-present') continue;
      f.decodedFrom = from;
      f.tags = [...f.tags, 'from-decoded-payload'];
      sink.push(f);
      capabilities.add(capabilityOfRule(f.ruleId));
    }
  }
}

function capabilityOfRule(ruleId: string): string {
  if (ruleId.startsWith('net.')) return 'network';
  if (ruleId.startsWith('cred.')) return 'credentials';
  if (ruleId.startsWith('exec.')) return 'execution';
  if (ruleId.startsWith('fs.')) return 'filesystem';
  if (ruleId.startsWith('evasion.')) return 'evasion';
  if (ruleId.startsWith('obf.')) return 'obfuscation';
  return 'other';
}

/** 主扫描函数 */
export function scanLoaded(loaded: LoadedPackage, options: ScanOptions): ScanResultUnscored {
  const fileReports: FileReport[] = [];
  const archiveFindings: import('./types').Finding[] = [];
  const skipped: string[] = [];
  let payloadCount = 0;

  const pkgEntry = loaded.entries.find((e) => e.path === 'package.json' && e.type === 'file');
  let pkg: Record<string, any> | null = null;
  if (pkgEntry) pkg = parsePackageJson(pkgEntry.bytes);
  const meta = pkg ? packageMetaFrom(pkg, loaded.entries) : {
    name: '', version: '', lifecycleScripts: {}, dependencies: {}, entryPoints: [], authors: [],
  };

  // 归档检查
  const archiveResult = analyzeArchiveEntries(
    loaded.entries,
    loaded.unsafePaths,
    loaded.symlinks,
    loaded.hardLinks,
    options.maxFileBytes,
  );
  archiveFindings.push(...archiveResult.findings);
  archiveFindings.push(...analyzeMetadata(meta));

  if (loaded.truncated) {
    skipped.push('归档超过大小/条目上限,部分内容未分析');
  }

  // 安装脚本
  if (pkg) {
    const scripts = collectLifecycleScripts(pkg);
    const install = analyzeInstallScripts(scripts);
    const installFindings = install.findings;
    for (const payload of install.payloads) {
      payloadCount++;
      const sink: import('./types').Finding[] = [];
      const caps = new Set<string>();
      analyzePayload(payload, sink, caps, options);
      installFindings.push(...sink);
    }
    if (installFindings.length) {
      fileReports.push({
        path: 'package.json',
        bytes: pkgEntry?.bytes.length ?? 0,
        parseMode: 'json',
        findings: dedupeFindings(installFindings),
        capabilities: ['install'],
      });
    }

    // 依赖里带安装脚本的风险(只对直接依赖,且依赖未随包提供时无法判断内容,仅提示)
    const suspiciousDeps = Object.keys(meta.dependencies).filter((d) => /^(?:event-stream|flatmap-stream)$/.test(d));
    if (suspiciousDeps.length) {
      archiveFindings.push(
        makeFinding({
          ruleId: 'supply.lifecycle-in-dependency',
          file: 'package.json',
          line: 1,
          evidence: `依赖: ${suspiciousDeps.join(', ')}`,
          message: '依赖列表包含历史上发生投毒事件的包,应锁定并审计其版本。',
        }),
      );
    }
  }

  // 逐文件
  for (const entry of loaded.entries) {
    if (entry.type !== 'file') continue;
    if (entry.path === 'package.json') continue;
    const ext = extname(entry.path).toLowerCase();
    const isAnalyzable = JS_EXTENSIONS.has(ext) || TEXT_EXTENSIONS.has(ext);
    if (!isAnalyzable) {
      // 非代码文件只做文本层面的编码串探测,且限于小文件
      if (entry.bytes.length > 0 && entry.bytes.length <= MAX_TEXT_FILE && isProbablyText(entry.bytes)) {
        const text = entry.bytes.toString('utf8');
        const payloads = extractTextPayloads(text, entry.path, 1);
        if (payloads.length) {
          const findings: import('./types').Finding[] = [];
          const caps = new Set<string>();
          for (const payload of payloads) {
            payloadCount++;
            analyzePayload(payload, findings, caps, options);
          }
          fileReports.push({
            path: entry.path,
            bytes: entry.bytes.length,
            parseMode: 'text',
            findings: dedupeFindings(findings),
            capabilities: [...caps],
          });
        }
      }
      continue;
    }
    const { report, payloadCount: pc } = analyzeFile(entry, options);
    payloadCount += pc;
    if (report.findings.length || report.capabilities.length) fileReports.push(report);
  }

  return { loaded, pkg, meta, fileReports, archiveFindings: dedupeFindings(archiveFindings), payloadCount, skipped };
}

function isProbablyText(buf: Buffer): boolean {
  const sample = buf.subarray(0, 1024);
  let printable = 0;
  for (const b of sample) {
    if (b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b < 0x7f)) printable++;
    else if (b >= 0x80) printable += 0.5;
  }
  return printable / Math.max(1, sample.length) > 0.85;
}

/** 完整扫描入口:自动判别 tarball / 目录 */
export function scanPath(inputPath: string, options: ScanOptions = DEFAULT_OPTIONS): import('./types').ArchiveReport {
  const started = Date.now();
  const stat = lstatSync(inputPath);
  let loaded: LoadedPackage;
  if (stat.isDirectory()) {
    loaded = loadFromDirectory(inputPath, options);
  } else {
    loaded = loadFromTarball(inputPath, options);
  }
  const result = scanLoaded(loaded, options);

  const allFindings = [...result.archiveFindings, ...result.fileReports.flatMap((f) => f.findings)];
  const scored = scoreFindings(allFindings);
  for (const f of allFindings) {
    f.effectiveWeight = scored.total >= 0 ? f.effectiveWeight : f.effectiveWeight;
  }

  const report: import('./types').ArchiveReport = {
    source: result.loaded.source,
    package: result.meta,
    files: result.fileReports,
    archiveFindings: result.archiveFindings,
    stats: {
      entryCount: result.loaded.entries.length,
      fileCount: result.loaded.entries.filter((e) => e.type === 'file').length,
      totalBytes: result.loaded.entries.reduce((sum, e) => sum + e.bytes.length, 0),
      jsFileCount: result.loaded.entries.filter((e) => e.type === 'file' && JS_EXTENSIONS.has(extname(e.path).toLowerCase())).length,
      skipped: result.skipped,
      layersDecoded: result.payloadCount,
      durationMs: Date.now() - started,
    },
  };
  return report;
}

export function scanSummary(report: import('./types').ArchiveReport): ReturnType<typeof scoreFindings> {
  const all = [...report.archiveFindings, ...report.files.flatMap((f) => f.findings)];
  return scoreFindings(all);
}

export { TarLimitError };
