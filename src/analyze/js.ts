/**
 * JS 源码规则引擎。
 *
 * 输入一段源码 → 输出 Findings + 该文件"能力"集合。
 * 全过程只解析与求值常量,不执行任何代码。
 */

import type { Node, StaticEnv } from '../ast';
import {
  buildStaticEnv,
  evalStaticArray,
  evalStaticString,
  memberPath,
  parseProgram,
  positionOf,
  sliceSource,
  staticMemberName,
  walkAst,
} from '../ast';
import { completeDraft, makeFinding } from '../findings';
import type { FindingDraft } from '../findings';
import { looksExecutable, classifyText } from '../deobfuscate';
import type { Category, Finding, Severity } from '../types';
import { isFunctionNode } from '../ast';

export interface JsAnalysis {
  findings: Finding[];
  capabilities: string[];
}

export interface JsAnalysisOptions {
  /** 这条 finding 来自哪一层解码 */
  decodedFrom?: string;
  /** 递归深度,防止解码套娃失控 */
  depth?: number;
  /** 文件是文本(非 AST)时,仅做字符串规则 */
  mode?: 'ast' | 'text';
}

// ── 模块 / 导入解析 ─────────────────────────────────────────────

const MODULE_ALIASES: Record<string, string> = {
  'node:http': 'http',
  'node:https': 'https',
  'node:net': 'net',
  'node:tls': 'tls',
  'node:dns': 'dns',
  'node:child_process': 'child_process',
  'node:fs': 'fs',
  'node:fs/promises': 'fs',
  'node:os': 'os',
  'node:path': 'path',
  'node:vm': 'vm',
  'node:zlib': 'zlib',
  'node:crypto': 'crypto',
  'node:module': 'module',
  'fs/promises': 'fs',
  'node:https/promises': 'https',
};

const NETWORK_MODULES = new Set([
  'http',
  'https',
  'net',
  'tls',
  'dns',
  'dgram',
  'axios',
  'got',
  'node-fetch',
  'undici',
  'request',
  'superagent',
  'needle',
  'phin',
  'cross-fetch',
  'isomorphic-fetch',
  'ws',
]);

const CP_FUNCS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork', 'execFileSync']);
const VM_FUNCS = new Set(['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction', 'Script', 'createContext']);
const FS_WRITE_FUNCS = new Set([
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'createWriteStream',
  'copyFile',
  'copyFileSync',
  'rename',
  'renameSync',
  'write',
  'writeSync',
]);
const FS_READ_FUNCS = new Set([
  'readFile',
  'readFileSync',
  'readdir',
  'readdirSync',
  'createReadStream',
  'open',
  'openSync',
  'read',
  'readSync',
]);
const FS_DELETE_FUNCS = new Set(['rm', 'rmSync', 'unlink', 'unlinkSync', 'rmdir', 'rmdirSync', 'rimraf']);

const NETWORK_METHODS = new Set([
  'request',
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'head',
  'connect',
  'fetch',
  'send',
  'sendBeacon',
  'query',
  'resolve',
  'lookup',
  'resolve4',
  'resolve6',
  'resolveTxt',
]);

interface ImportMap {
  /** 本地名 → 规范模块名,例如 cp → child_process */
  modules: Map<string, string>;
  /** 解构导入的本地名 → `模块.导出` */
  members: Map<string, string>;
}

function canonicalizeModule(spec: string): string {
  return MODULE_ALIASES[spec] ?? spec.replace(/^node:/, '');
}

/** 解析 callee 的点路径,并把导入别名替换成模块名 */
function resolvePath(node: Node, imports: ImportMap, depth = 0): string | null {
  if (!node || depth > 8) return null;
  if (node.type === 'Identifier') {
    const name = node.name;
    if (imports.members.has(name)) return imports.members.get(name)!;
    if (imports.modules.has(name)) return imports.modules.get(name)!;
    // 未绑定的标识符只是一个普通变量名,不能当成模块路径 —— 否则压缩代码里
    // 叫 `ws`/`got` 的局部变量会被误判成网络库。
    return '~' + name;
  }
  if (node.type === 'MemberExpression') {
    const base = resolvePath(node.object, imports, depth + 1);
    const prop = staticMemberName(node);
    if (base === null || prop === null) return null;
    return `${base}.${prop}`;
  }
  if (node.type === 'CallExpression') {
    // require('x') 直接内联写法
    if (node.callee?.type === 'Identifier' && node.callee.name === 'require' && node.arguments.length >= 1) {
      const spec = evalStaticString(node.arguments[0], null);
      if (spec !== null) return canonicalizeModule(spec);
    }
    return null;
  }
  if (node.type === 'ImportExpression') {
    const spec = evalStaticString(node.source, null);
    return spec === null ? null : canonicalizeModule(spec);
  }
  if (node.type === 'ThisExpression') return 'this';
  return null;
}

function buildImportMap(ast: Node): ImportMap {
  const modules = new Map<string, string>();
  const members = new Map<string, string>();

  walkAst(ast, {
    VariableDeclarator(node: Node) {
      const init = node.init;
      if (!init || init.type !== 'CallExpression') return;
      if (init.callee?.type !== 'Identifier' || init.callee.name !== 'require') return;
      if (init.arguments.length < 1) return;
      const spec = evalStaticString(init.arguments[0], null);
      if (spec === null) return;
      const mod = canonicalizeModule(spec);
      const id = node.id;
      if (!id) return;
      if (id.type === 'Identifier') {
        modules.set(id.name, mod);
      } else if (id.type === 'ObjectPattern') {
        for (const prop of id.properties) {
          if (!prop || prop.type !== 'Property') continue;
          const key = prop.key;
          let importedName: string | null = null;
          if (key?.type === 'Identifier') importedName = key.name;
          else if (key?.type === 'Literal' && typeof key.value === 'string') importedName = key.value;
          if (importedName === null) continue;
          const local = prop.value?.type === 'Identifier' ? prop.value.name : null;
          if (local === null) continue;
          members.set(local, `${mod}.${importedName}`);
        }
      }
    },
    ImportDeclaration(node: Node) {
      const spec = typeof node.source?.value === 'string' ? node.source.value : null;
      if (spec === null) return;
      const mod = canonicalizeModule(spec);
      for (const specifier of node.specifiers) {
        if (!specifier?.local?.name) continue;
        if (specifier.type === 'ImportDefaultSpecifier' || specifier.type === 'ImportNamespaceSpecifier') {
          modules.set(specifier.local.name, mod);
        } else if (specifier.type === 'ImportSpecifier') {
          const imported = specifier.imported?.name ?? specifier.imported?.value;
          if (typeof imported === 'string') members.set(specifier.local.name, `${mod}.${imported}`);
        }
      }
    },
  });

  return { modules, members };
}

// ── 常量 / 参数工具 ─────────────────────────────────────────────

function argString(node: Node, env: StaticEnv | null): string | null {
  return evalStaticString(node, env);
}

/** 把子树里所有能静态求值的字符串都收集出来(用于路径/域名检测) */
function collectStaticStrings(node: Node, env: StaticEnv | null, out: string[], depth = 0): void {
  if (!node || depth > 12) return;
  const direct = evalStaticString(node, env);
  if (direct !== null) out.push(direct);
  switch (node.type) {
    case 'TemplateLiteral':
      for (const expr of node.expressions) collectStaticStrings(expr, env, out, depth + 1);
      break;
    case 'BinaryExpression':
      collectStaticStrings(node.left, env, out, depth + 1);
      collectStaticStrings(node.right, env, out, depth + 1);
      break;
    case 'CallExpression':
    case 'NewExpression':
      for (const a of node.arguments ?? []) collectStaticStrings(a, env, out, depth + 1);
      if (node.callee) collectStaticStrings(node.callee, env, out, depth + 1);
      break;
    case 'MemberExpression':
      collectStaticStrings(node.object, env, out, depth + 1);
      if (node.computed) collectStaticStrings(node.property, env, out, depth + 1);
      break;
    case 'ConditionalExpression':
      collectStaticStrings(node.consequent, env, out, depth + 1);
      collectStaticStrings(node.alternate, env, out, depth + 1);
      break;
    case 'AssignmentExpression':
      collectStaticStrings(node.right, env, out, depth + 1);
      break;
    case 'SequenceExpression':
      for (const e of node.expressions) collectStaticStrings(e, env, out, depth + 1);
      break;
    case 'ArrayExpression':
      for (const e of node.elements ?? []) collectStaticStrings(e, env, out, depth + 1);
      break;
    default:
      break;
  }
}

// ── 特征表 ──────────────────────────────────────────────────────

const SENSITIVE_ENV_RE =
  /^(?:NPM_TOKEN|NODE_AUTH_TOKEN|NPM_CONFIG_.*|AWS_[A-Z_]+|GITHUB_TOKEN|GH_TOKEN|CI_JOB_TOKEN|GITLAB_[A-Z_]+|DOCKER_[A-Z_]+|AZURE_[A-Z_]+|GOOGLE_[A-Z_]+|OPENAI_[A-Z_]+|ANTHROPIC_[A-Z_]+|SLACK_[A-Z_]+|DISCORD_[A-Z_]+|STRIPE_[A-Z_]+|DATABASE_URL|SSH_[A-Z_]+|GPG_[A-Z_]+|.*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY|ACCESS_KEY).*)$/i;

const BROWSER_PATHS_RE =
  /(?:Google[\/\\ ]Chrome|Chromium|Mozilla[\/\\ ]Firefox|BraveSoftware|Microsoft[\/\\ ]Edge|Safari)[\s\S]{0,80}(?:Cookies|Login\s+Data|Local\s+State|Web\s+Data|key4\.db|logins\.json)/i;

const CRED_PATH_RES: Array<{ re: RegExp; ruleId: string }> = [
  { re: /(?:^|[\/\\])(?:\.ssh)(?:[\/\\]|$)|id_(?:rsa|dsa|ecdsa|ed25519)|known_hosts|authorized_keys|\.ssh[\/\\]config/i, ruleId: 'cred.ssh-directory' },
  { re: /\.npmrc\b|\/npmrc$/i, ruleId: 'cred.npmrc' },
  { re: /\.pypirc|\.git-credentials|\.netrc|\.docker[\/\\]config\.json|\.aws[\/\\]credentials|\.config[\/\\]gcloud/i, ruleId: 'cred.npmrc' },
  { re: BROWSER_PATHS_RE, ruleId: 'cred.browser-data' },
  { re: /\.bash_history|\.zsh_history|\.history\b|\.bash_profile|\.profile\b/i, ruleId: 'cred.shell-history' },
  { re: /(?:Electrum|Exodus|MetaMask|wallet\.dat|\.ethereum[\/\\]keystore|\.bitcoin|atomic[\/\\]Local\s+Storage|ledger|trezor)/i, ruleId: 'cred.crypto-wallet' },
];

const CLOUD_METADATA_RE = /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.100|metadata\.azure\.com/i;

const SUSPICIOUS_HOST_RE =
  /(?:\bwebhook\.site|pastebin\.com|paste\.ee|transfer\.sh|requestbin|pipedream\.net|ngrok\.io|ngrok\.app|anonfiles|0x0\.st|file\.io|termbin\.com|beeceptor\.com|mockbin\.org|interactsh|burpcollaborator|canarytokens)/i;

const IP_URL_RE = /(?:https?|wss?|ftp):\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/i;

const AUTOSTART_RE =
  /(?:crontab|@reboot|\/etc\/cron|LaunchAgents|LaunchDaemons|systemd[\/\\](?:user|system)|Microsoft[\/\\]Windows[\/\\]CurrentVersion[\/\\]Run|autostart|\.config\/autostart|rc\.local)/i;

const SHELL_PERSIST_WRITE_RE =
  /(?:^|[\/\\])(?:\.bashrc|\.bash_profile|\.zshrc|\.zprofile|\.profile|\.config[\/\\].*)(?:$|[\/\\])/i;

// ── 主入口 ──────────────────────────────────────────────────────

export function analyzeJsSource(source: string, file: string, options: JsAnalysisOptions = {}): JsAnalysis {
  const findings: Finding[] = [];
  const capabilities = new Set<string>();
  const decodedFrom = options.decodedFrom;
  const depth = options.depth ?? 0;
  const emit = (input: FindingDraft) => {
    const f = makeFinding({ ...completeDraft(input, file), decodedFrom });
    findings.push(f);
    capabilities.add(capabilityOf(f.ruleId));
  };

  const parsed = options.mode === 'text' ? null : parseProgram(source, { allowLoose: true });
  const env: StaticEnv = parsed ? buildStaticEnv(parsed.ast) : { strings: new Map(), arrays: new Map(), reassigned: new Set() };
  const rawText = source;

  // 文本模式:只做正则层面的混淆/凭据检测
  if (!parsed) {
    scanRawText(source, file, emit);
    return { findings, capabilities: [...capabilities] };
  }

  const ast = parsed.ast;
  const imports = buildImportMap(ast);
  const decodeCtx: DecodeContext = { env, imports, decodedVars: buildDecodedVars(ast, env, imports) };

  // ── 逐文件能力记录,用于同作用域组合 ──
  interface Cap {
    kind: 'credential' | 'network' | 'exec' | 'fs-write' | 'decode';
    node: Node;
    line: number;
    detail: string;
    funcId: number;
  }
  const capRecords: Cap[] = [];

  // 函数作用域 id:最近的外层函数
  const funcIdOf = new Map<Node, number>();
  let nextFuncId = 0;
  const assignFuncIds = (node: Node, current: number) => {
    if (isFunctionNode(node)) {
      current = nextFuncId++;
      funcIdOf.set(node, current);
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range') continue;
      const value = (node as any)[key];
      if (Array.isArray(value)) {
        for (const item of value) if (item && typeof item.type === 'string') assignFuncIds(item, current);
      } else if (value && typeof value.type === 'string') {
        assignFuncIds(value, current);
      }
    }
  };
  assignFuncIds(ast, -1);

  const funcIdFor = (ancestors: Node[]): number => {
    for (let i = ancestors.length - 1; i >= 0; i--) {
      const anc = ancestors[i]!;
      if (isFunctionNode(anc)) return funcIdOf.get(anc) ?? -1;
    }
    return -1;
  };

  // 简易污点:保存"来自网络调用"的变量名(按函数作用域)
  const taintedByFunc = new Map<number, Set<string>>();
  const taint = (funcId: number, name: string) => {
    let set = taintedByFunc.get(funcId);
    if (!set) {
      set = new Set();
      taintedByFunc.set(funcId, set);
    }
    set.add(name);
  };

  const isNetworkCallPath = (path: string | null): boolean => {
    if (path === null) return false;
    // `~name` 表示未绑定的普通标识符,只在它是众所周知的全局时才算网络
    if (path.startsWith('~')) {
      const bare = path.slice(1);
      return /^(?:fetch|XMLHttpRequest|WebSocket|EventSource)$/.test(bare) || bare === 'navigator';
    }
    const [mod, method] = splitPath(path);
    if (mod === 'fetch' || path === 'fetch') return true;
    if (mod === 'XMLHttpRequest' || path === 'XMLHttpRequest') return true;
    if (path.startsWith('navigator.') && method === 'sendBeacon') return true;
    if (!NETWORK_MODULES.has(mod)) return false;
    if (method === null) return true;
    return NETWORK_METHODS.has(method);
  };

  // ── 污点传播:网络响应的数据流 ──
  // 真实样本的写法通常是多层回调:
  //   https.get(url, res => { let body=''; res.on('data', c => body += c);
  //                           res.on('end', () => eval(body)); })
  // 只靠"网络调用回调的形参"不够,需要沿 (1) 嵌套函数 (2) .on/事件订阅 (3) 赋值 传播。
  const networkParamsByFunc = new Map<number, Set<string>>();
  /** 处于"网络数据流上下文"的函数(网络回调本身,以及其内部嵌套的回调) */
  const taintedContextFuncs = new Set<number>();

  // 第一遍:标记网络调用回调,并递归标记其内部所有嵌套函数
  const markTaintedContext = (fn: Node, ownerId: number) => {
    const id = funcIdOf.get(fn) ?? ownerId;
    if (taintedContextFuncs.has(id)) return;
    taintedContextFuncs.add(id);
    for (const param of fn.params ?? []) {
      if (param?.type === 'Identifier') {
        const set = networkParamsByFunc.get(id) ?? new Set<string>();
        set.add(param.name);
        networkParamsByFunc.set(id, set);
      }
    }
    const visitChildren = (n: Node, d: number) => {
      if (!n || d > 30) return;
      if (isFunctionNode(n)) {
        markTaintedContext(n, id);
        return;
      }
      for (const key of Object.keys(n)) {
        if (key === 'loc' || key === 'range') continue;
        const value: unknown = (n as Record<string, unknown>)[key];
        if (Array.isArray(value)) for (const item of value) if (item && typeof (item as Node).type === 'string') visitChildren(item as Node, d + 1);
        else if (value && typeof (value as Node).type === 'string') visitChildren(value as Node, d + 1);
      }
    };
    visitChildren(fn.body ?? fn, 0);
  };

  walkAst(ast, {
    CallExpression(node: Node, _s: unknown, ancestors: Node[]) {
      if (!isNetworkCallPath(resolvePath(node.callee, imports))) return;
      const owner = funcIdFor(ancestors);
      for (const arg of node.arguments ?? []) {
        if (!isFunctionNode(arg)) continue;
        markTaintedContext(arg, owner);
      }
    },
  });

  const referencesTaintedName = (node: Node, depth = 0): boolean => {
    if (!node || depth > 12) return false;
    if (node.type === 'Identifier' && taintedNameAnywhere(node.name)) return true;
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range') continue;
      const value: unknown = (node as Record<string, unknown>)[key];
      if (Array.isArray(value)) {
        for (const item of value) if (item && typeof (item as Node).type === 'string' && referencesTaintedName(item as Node, depth + 1)) return true;
      } else if (value && typeof (value as Node).type === 'string' && referencesTaintedName(value as Node, depth + 1)) return true;
    }
    return false;
  };

  const taintedNameAnywhere = (name: string): boolean => {
    for (const [, set] of taintedByFunc) if (set.has(name)) return true;
    for (const [, set] of networkParamsByFunc) if (set.has(name)) return true;
    return false;
  };

  // 第二遍:在污点上下文的函数里,把赋值目标也标污;`.on(evt, cb)` 的接收者被污染时,
  // 其回调里的形参同样视为污点源。迭代到不动点,覆盖多级嵌套。
  for (let round = 0; round < 6; round++) {
    let changed = false;
    const taintName = (id: number, name: string) => {
      const set = taintedByFunc.get(id) ?? new Set<string>();
      if (!set.has(name)) {
        set.add(name);
        taintedByFunc.set(id, set);
        changed = true;
      }
    };
    const taintInContext = (owner: number) => {
      if (!taintedContextFuncs.has(owner)) return;
      walkAst(ast, {
        VariableDeclarator(node: Node, _s: unknown, ancestors: Node[]) {
          if (!node.id || node.id.type !== 'Identifier' || !node.init) return;
          if (referencesTaintedName(node.init)) taintName(owner, node.id.name);
        },
        AssignmentExpression(node: Node, _s: unknown, ancestors: Node[]) {
          if (!node.left || node.left.type !== 'Identifier') return;
          if (referencesTaintedName(node.right)) taintName(owner, node.left.name);
        },
        CallExpression(node: Node, _s: unknown, ancestors: Node[]) {
          // res.on('data', cb) —— 接收者(res)已污染,事件回调的形参也是网络数据
          const method = staticMemberName(node.callee);
          if (!method || !/^(?:on|once|addListener|pipe|forEach|map)$/.test(method)) return;
          const receiver = node.callee?.object;
          const receiverTainted =
            (receiver?.type === 'Identifier' && taintedNameAnywhere(receiver.name)) ||
            (receiver?.type === 'MemberExpression' && staticMemberName(receiver) !== null && taintedNameAnywhere(staticMemberName(receiver)!));
          if (!receiverTainted) return;
          for (const arg of node.arguments ?? []) {
            if (!isFunctionNode(arg)) continue;
            markTaintedContext(arg, owner);
            for (const param of arg.params ?? []) {
              if (param?.type === 'Identifier') {
                const set = networkParamsByFunc.get(funcIdOf.get(arg) ?? owner) ?? new Set<string>();
                set.add(param.name);
                networkParamsByFunc.set(funcIdOf.get(arg) ?? owner, set);
                changed = true;
              }
            }
          }
        },
      });
    };
    for (const id of taintedContextFuncs) taintInContext(id);
    if (!changed) break;
  }


  /** 名字是否可能承载网络返回的数据(同函数内或任意网络回调形参) */
  const isTaintedName = (name: string, funcId: number): boolean => {
    if (taintedByFunc.get(funcId)?.has(name)) return true;
    return taintedNameAnywhere(name);
  };

  // ── 遍历 ──
  const seen = new Set<string>();
  const pushFinding = (input: FindingDraft) => {
    const key = `${input.ruleId}\u0000${input.line ?? 1}\u0000${(input.evidence ?? '').slice(0, 120)}`;
    if (seen.has(key)) return;
    seen.add(key);
    emit(input);
  };

  walkAst(ast, {
    VariableDeclarator(node: Node, _s: unknown, ancestors: Node[]) {
      // 污点:变量赋值来自网络调用或网络响应(如 res.on('data', c => body += c))
      const init = node.init;
      if (!node.id || node.id.type !== 'Identifier') return;
      if (init && containsNetworkCall(init, imports)) {
        taint(funcIdFor(ancestors), node.id.name);
      }
    },
    AssignmentExpression(node: Node, _s: unknown, ancestors: Node[]) {
      if (!node.left || node.left.type !== 'Identifier') return;
      if (!containsNetworkCall(node.right, imports)) return;
      taint(funcIdFor(ancestors), node.left.name);
    },

    CallExpression(node: Node, _s: unknown, ancestors: Node[]) {
      handleCall(node, false, ancestors);
    },
    NewExpression(node: Node, _s: unknown, ancestors: Node[]) {
      handleCall(node, true, ancestors);
    },
    ImportExpression(node: Node, _s: unknown, ancestors: Node[]) {
      const spec = evalStaticString(node.source, env);
      pushFinding({
        ruleId: 'exec.dynamic-require',
        line: positionOf(node, { line: 1, column: 1 }).line,
        column: positionOf(node, { line: 1, column: 1 }).column,
        evidence: sliceSource(source, node),
        message: `动态 import(${spec === null ? '变量' : spec})`,
      });
    },
    DebuggerStatement(node: Node) {
      pushFinding({
        ruleId: 'evasion.debugger-detect',
        line: positionOf(node, { line: 1, column: 1 }).line,
        column: positionOf(node, { line: 1, column: 1 }).column,
        evidence: 'debugger',
      });
    },
    ForInStatement(node: Node, _s: unknown, ancestors: Node[]) {
      if (memberPath(node.right)?.startsWith('process.env')) {
        const loc = positionOf(node, { line: 1, column: 1 });
        pushFinding({ ruleId: 'cred.env-dump', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      }
    },
  });

  function handleCall(node: Node, isNew: boolean, ancestors: Node[]): void {
    const callee = node.callee;
    const loc = positionOf(node, { line: 1, column: 1 });
    const path = resolvePath(callee, imports);
    const funcId = funcIdFor(ancestors);
    const args: string[] = [];
    for (const a of node.arguments ?? []) collectStaticStrings(a, env, args);

    // ── eval / Function ──
    // 间接调用写法 `(0, eval)(x)` / `(eval)(x)` / `window.eval(x)` / `globalThis.Function(...)`
    const isEvalCall = isNew ? false : isEvalCallee(callee, env);
    if (isEvalCall) {
      pushFinding({ ruleId: 'exec.eval', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      capRecords.push({ kind: 'exec', node, line: loc.line, detail: 'eval', funcId });
      noteDecodedExecArg(node, 'eval', loc.line, funcId);
      if (argReferencesTaint(node, funcId, isTaintedName) || containsNetworkCall(node, imports)) {
        pushFinding({
          ruleId: 'net.remote-fetch-eval',
          line: loc.line,
          column: loc.column,
          evidence: sliceSource(source, node),
          message: 'eval 的参数来自网络调用(或同函数内存在网络请求)',
        });
      }
    }
    if (isFunctionCallee(callee, env)) {
      // 所有参数都能静态求值 → 是写死的代码体(可疑);
      // 只要有一个参数是运行期拼接的 → 模板引擎/编译器的标准写法(lodash template),
      // 不单独报;恶意载荷若是字面量或静态可解码串,下面仍会捕获。
      const argValues: Array<string | null> = (node.arguments ?? []).map((a: Node) => evalStaticString(a, env));
      const allStatic = argValues.length > 0 && argValues.every((v) => v !== null);
      const firstStatic = argValues[0] ?? null;
      const isGlobalShim = firstStatic !== null && argValues.length === 1 && /^\s*(?:return\s+this|return\s+globalThis)\s*;?\s*$/.test(firstStatic);
      const isDynamicSource = !allStatic && !findStaticDecodedArgument(node, decodeCtx);
      if (!isGlobalShim && !isDynamicSource) {
        pushFinding({ ruleId: 'exec.new-function', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
        capRecords.push({ kind: 'exec', node, line: loc.line, detail: 'Function', funcId });
        noteDecodedExecArg(node, 'Function', loc.line, funcId);
      }
      if (argReferencesTaint(node, funcId, isTaintedName) || containsNetworkCall(node, imports)) {
        pushFinding({ ruleId: 'net.remote-fetch-eval', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      }
    }

    // ── process.env 读取 ──
    if (callee?.type === 'MemberExpression') {
      const envPath = memberPath(callee.object);
      const prop = staticMemberName(callee);
      if (envPath === 'process.env' && prop !== null) {
        if (SENSITIVE_ENV_RE.test(prop)) {
          pushFinding({
            ruleId: 'cred.sensitive-env',
            line: loc.line,
            column: loc.column,
            evidence: sliceSource(source, node),
            tags: [`env=${prop}`],
          });
        } else {
          pushFinding({ ruleId: 'cred.process-env', line: loc.line, column: loc.column, evidence: sliceSource(source, node), tags: [`env=${prop}`] });
        }
        capRecords.push({ kind: 'credential', node, line: loc.line, detail: `env:${prop}`, funcId });
      }
      // 整体转储:必须是 JSON.stringify(process.env) / Object.entries(process.env) 这种直接形态
      if (isEnvDumpCall(callee, node.arguments ?? [])) {
        pushFinding({
          ruleId: 'cred.env-dump',
          line: loc.line,
          column: loc.column,
          evidence: sliceSource(source, node),
          severityOverride: 'high',
        });
        capRecords.push({ kind: 'credential', node, line: loc.line, detail: 'env-dump', funcId });
      }
      if (envPath === 'process.env' && prop === null) {
        // process.env[动态键]
        pushFinding({ ruleId: 'cred.process-env', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      }
    }

    // ── os.homedir / path 拼接出凭据位置 ──
    if (path === 'os.homedir' || path === 'homedir') {
      // 仅记录枚举行为;不当作"已读到凭据",避免和任意网络调用凑成组合误报
      pushFinding({ ruleId: 'cred.homedir-enumeration', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
    }

    // ── 网络 ──
    if (isNetworkCallPath(path)) {
      pushFinding({ ruleId: 'net.http-request', line: loc.line, column: loc.column, evidence: sliceSource(source, node), tags: path ? [path] : [] });
      capRecords.push({ kind: 'network', node, line: loc.line, detail: path ?? 'network', funcId });
    }
    if (path && /^(?:net\.|tls\.|dgram\.)/.test(path)) {
      pushFinding({ ruleId: 'net.raw-socket', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
    }
    if (path && /^(?:dns\.)/.test(path)) {
      pushFinding({ ruleId: 'net.dns-exfil', line: loc.line, column: loc.column, evidence: sliceSource(source, node), message: '使用 DNS 解析 API,若参数由数据拼接则为外带信道' });
    }

    // 目标域名检查
    for (const text of args) {
      const hostMatch = text.match(IP_URL_RE);
      if (hostMatch) {
        pushFinding({ ruleId: 'net.ip-literal', line: loc.line, column: loc.column, evidence: text.slice(0, 120), tags: [`ip=${hostMatch[1]}`] });
      }
      if (CLOUD_METADATA_RE.test(text)) {
        pushFinding({ ruleId: 'cred.cloud-metadata', line: loc.line, column: loc.column, evidence: text.slice(0, 120) });
        capRecords.push({ kind: 'credential', node, line: loc.line, detail: 'cloud-metadata', funcId });
      }
      if (SUSPICIOUS_HOST_RE.test(text)) {
        pushFinding({ ruleId: 'net.pastebin-like', line: loc.line, column: loc.column, evidence: text.slice(0, 120) });
      }
      for (const { re, ruleId } of CRED_PATH_RES) {
        if (re.test(text)) {
          pushFinding({ ruleId, line: loc.line, column: loc.column, evidence: text.slice(0, 120) });
          capRecords.push({ kind: 'credential', node, line: loc.line, detail: text.slice(0, 60), funcId });
        }
      }
    }

    // ── fs 写入 / 删除 / chmod ──
    const [mod, fn] = splitPath(path);
    if (mod === 'fs' && fn !== null) {
      if (FS_WRITE_FUNCS.has(fn)) {
        capRecords.push({ kind: 'fs-write', node, line: loc.line, detail: `fs.${fn}`, funcId });
        // 目标路径:第一个参数若落在包外(home / etc / 绝对路径 / 启动位置)才算持久化
        const targetPath = node.arguments?.[0] ?? null;
        const outside = targetPath ? isOutsidePackagePath(targetPath, env, imports) : false;
        pushFinding({
          ruleId: outside ? 'fs.write-outside-package' : 'fs.write-file',
          line: loc.line,
          column: loc.column,
          evidence: sliceSource(source, node),
          tags: ['write'],
        });
        for (const text of args) {
          if (AUTOSTART_RE.test(text)) {
            pushFinding({ ruleId: 'fs.autostart', line: loc.line, column: loc.column, evidence: text.slice(0, 120) });
          }
          if (SHELL_PERSIST_WRITE_RE.test(text)) {
            pushFinding({ ruleId: 'fs.autostart', line: loc.line, column: loc.column, evidence: text.slice(0, 120), message: '写入 shell 启动脚本' });
          }
        }
        // 释放二进制
        const binary =
          node.arguments.find((a: Node) => a?.type === 'CallExpression' && decodeBinaryMagic(a, env, imports)) ?? null;
        if (binary) {
          pushFinding({ ruleId: 'fs.binary-drop', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
        }
      }
      if (FS_DELETE_FUNCS.has(fn)) {
        pushFinding({ ruleId: 'fs.delete-recursive', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      }
    }
    if ((path === 'fs.chmod' || path === 'fs.chmodSync') && args.some((a) => /0o?7|0o?755|0o?777|\+x/.test(a))) {
      pushFinding({ ruleId: 'fs.chmod-exec', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
    }

    // ── 子进程 ──
    if ((mod === 'child_process' && fn !== null && CP_FUNCS.has(fn)) || path === 'child_process') {
      pushFinding({ ruleId: 'exec.child-process', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      capRecords.push({ kind: 'exec', node, line: loc.line, detail: `cp.${fn ?? 'module'}`, funcId });
      for (const text of args) {
        if (AUTOSTART_RE.test(text)) pushFinding({ ruleId: 'fs.autostart', line: loc.line, column: loc.column, evidence: text.slice(0, 120) });
        if (SHELL_PERSIST_WRITE_RE.test(text)) pushFinding({ ruleId: 'fs.autostart', line: loc.line, column: loc.column, evidence: text.slice(0, 120) });
        // exec('curl ... | sh'):命令本身就把远端内容交给 shell
        if (/(?:curl|wget)[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/i.test(text) || /(?:powershell|Invoke-Expression)\b.*(?:DownloadString|IEX)/i.test(text)) {
          pushFinding({
            ruleId: 'net.remote-fetch-eval',
            line: loc.line,
            column: 1,
            evidence: text.slice(0, 140),
            message: '子进程命令从远端拉取内容并管道给 shell 执行,等同远程代码执行。',
          });
        }
      }
    }

    // ── vm ──
    if (mod === 'vm' && fn !== null && VM_FUNCS.has(fn)) {
      pushFinding({ ruleId: 'exec.vm-module', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      capRecords.push({ kind: 'exec', node, line: loc.line, detail: `vm.${fn}`, funcId });
      noteDecodedExecArg(node, `vm.${fn}`, loc.line, funcId);
      if (containsNetworkCall(node, imports) || argReferencesTaint(node, funcId, isTaintedName)) {
        pushFinding({ ruleId: 'net.remote-fetch-eval', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      }
    }

    // ── 动态 require ──
    if (!isNew && callee?.type === 'Identifier' && callee.name === 'require' && node.arguments.length >= 1) {
      const spec = argString(node.arguments[0], env);
      if (spec === null) {
        pushFinding({ ruleId: 'exec.dynamic-require', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      }
    }

    // ── require.cache / Module._load 篡改 ──
    if (path && (/require\.cache|Module\._load|require\.extensions/.test(path) || /process\.binding/.test(path))) {
      pushFinding({ ruleId: 'supply.deprecated-api-abuse', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      if (/require\.cache|Module\._load/.test(path)) {
        pushFinding({ ruleId: 'evasion.require-cache-poison', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      }
    }

    // ── 环境变量写入 .npmrc / 改 scripts ──
    if ((path === 'fs.writeFileSync' || path === 'fs.writeFile') && args.some((a) => /ignore-scripts|registry=|_authToken/i.test(a))) {
      pushFinding({ ruleId: 'evasion.npm-config-tamper', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
    }
    if (path && /child_process\.(?:exec|execSync)$/.test(path) && args.some((a) => /npm\s+config|npm\s+set|\.npmrc/i.test(a))) {
      pushFinding({ ruleId: 'evasion.npm-config-tamper', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
    }

    // ── 网络 + 凭据组合:请求参数里含 process.env / 凭据路径 ──
    if (isNetworkCallPath(path)) {
      const sendsSecrets = node.arguments.some((a: Node) => argContainsSecret(a));
      if (sendsSecrets) {
        pushFinding({ ruleId: 'net.upload-credentials', line: loc.line, column: loc.column, evidence: sliceSource(source, node) });
      }
    }
  }

  /** 找到"编码串 → 解码 → 执行"的形态:把已解码行为登记进能力集,并额外记一条 critical */
  function noteDecodedExecArg(call: Node, sinkName: string, line: number, funcId: number): void {
    const decoded = findStaticDecodedArgument(call, decodeCtx);
    if (decoded === null) return;
    capabilities.add('decode');
    capabilities.add('execution');
    pushFinding({
      ruleId: 'exec.encoded-payload',
      line,
      column: 1,
      evidence: `${sinkName}(…) 的参数来自静态可解码的编码串:${decoded.slice(0, 120)}`,
      message: `编码串在传入 ${sinkName} 之前被解码,属于典型的混淆载荷执行。`,
      tags: ['inline-decoded'],
    });
    // 解码出的内容再走一遍规则(按纯文本,避免递归 AST 爆炸)
    if (looksExecutable(decoded) && depth < 2) {
      const nested = analyzeJsSource(decoded, file, { depth: depth + 1, decodedFrom: `${file}:${line}` });
      for (const f of nested.findings) {
        if (f.ruleId === 'exec.eval') continue;
        findings.push(f);
        capabilities.add(capabilityOf(f.ruleId));
      }
    }
    void funcId;
  }

  function argContainsSecret(node: Node): boolean {
    if (!node) return false;
    let found = false;
    const visit = (n: Node, d: number) => {
      if (!n || found || d > 10) return;
      if (n.type === 'MemberExpression') {
        const mp = memberPath(n);
        if (mp && mp.startsWith('process.env')) {
          const prop = mp.slice('process.env.'.length);
          if (SENSITIVE_ENV_RE.test(prop) || prop === 'env' || mp === 'process.env') found = true;
        }
      }
      if (n.type === 'Literal' && typeof n.value === 'string') {
        if (CRED_PATH_RES.some(({ re }) => re.test(n.value!))) found = true;
      }
      for (const key of Object.keys(n)) {
        if (key === 'loc' || key === 'range') continue;
        const value: unknown = (n as Record<string, unknown>)[key];
        if (Array.isArray(value)) {
          for (const item of value) {
            if (item && typeof (item as Node).type === 'string') visit(item as Node, d + 1);
          }
        } else if (value && typeof (value as Node).type === 'string') {
          visit(value as Node, d + 1);
        }
      }
    };
    visit(node, 0);
    return found;
  }

  // ── 函数作用域内的组合行为 ──
  const byFunc = new Map<number, Cap[]>();
  for (const cap of capRecords) {
    const arr = byFunc.get(cap.funcId) ?? [];
    arr.push(cap);
    byFunc.set(cap.funcId, arr);
  }

  for (const [funcId, caps] of byFunc) {
    const kinds = new Set(caps.map((c) => c.kind));
    const line = Math.min(...caps.map((c) => c.line));
    const cred = caps.find((c) => c.kind === 'credential');
    const net = caps.find((c) => c.kind === 'network');
    const ex = caps.find((c) => c.kind === 'exec');
    const write = caps.find((c) => c.kind === 'fs-write');
    if (kinds.has('credential') && kinds.has('network')) {
      pushFinding({
        ruleId: 'net.upload-credentials',
        line,
        column: 1,
        evidence: `凭据读取(${cred?.detail} @${cred?.line}) + 网络请求(${net?.detail} @${net?.line}) 位于同一函数`,
        message: '同一函数内读取敏感材料并发出网络请求,高度疑似数据外泄。',
      });
    }
    if (kinds.has('exec') && kinds.has('network')) {
      pushFinding({
        ruleId: 'net.remote-fetch-eval',
        line,
        column: 1,
        evidence: `动态执行(${ex?.detail} @${ex?.line}) + 网络请求(${net?.detail} @${net?.line}) 位于同一函数`,
      });
    }
    if (kinds.has('credential') && kinds.has('fs-write') && write) {
      // 读凭据又写包外/启动位置 — 由各自规则已覆盖,这里只做能力标记
      capabilities.add('cred+write');
    }
    void funcId;
  }

  // ── 文件级外泄关联 ──
  // 凭据可能由辅助函数读取、在主流程里发送(跨函数)。这里只在"高价值凭据"上做文件级关联:
  // 读 ~/.ssh、.npmrc、浏览器数据、云元数据或整体转储 env 的文件,通常没有理由同时向外发请求。
  // 刻意不把"读取单个 API_KEY 环境变量 + 调用 API"这种合法 SDK 模式算进来。
  const strongCred = capRecords.filter((c) => c.kind === 'credential' && isStrongCredential(c.detail));
  const netCaps = capRecords.filter((c) => c.kind === 'network');
  if (strongCred.length > 0 && netCaps.length > 0) {
    const strongFuncs = new Set(strongCred.map((c) => c.funcId));
    const netFuncs = new Set(netCaps.map((c) => c.funcId));
    const sameFunc = [...strongFuncs].some((id) => netFuncs.has(id));
    if (!sameFunc) {
      const cred = strongCred[0]!;
      const net = netCaps[0]!;
      pushFinding({
        ruleId: 'net.upload-credentials',
        line: Math.min(cred.line, net.line),
        column: 1,
        evidence: `同一文件内读取高价值凭据(${cred.detail} @${cred.line})并向 ${net.detail} 发出请求(@${net.line})`,
        message: '同一文件里既读取高价值凭据又发起出站请求(可能经由辅助函数),疑似外泄。',
        severityOverride: 'high',
        weightBoost: -12,
        tags: ['file-level-correlation'],
      });
    }
  }

  // ── 混淆特征 ──
  scanObfuscation(ast, source, file, pushFinding, env);

  // ── 对解码载荷递归分析 ──
  // 由上层(archive 分析)负责解码并回调,避免在这里耦合 tar/文件逻辑。

  // ── 反分析特征 ──
  // 沙箱/CI 检测:supports-color 这类库读 CI 变量是完全正常的。
  // 只有出现"容器/虚拟机/调试器"的实证信号(/.dockerenv、/proc 里的 cgroup、vmware 等)才报。
  const containerArtifact = /\/\.dockerenv|\/proc\/(?:1\/)?cgroup|\/proc\/self\/status|container\.conf|KUBERNETES_SERVICE_HOST|\/proc\/version/i;
  if (containerArtifact.test(rawText) && /(?:readFileSync|existsSync|readFile|statSync|cat\s)/.test(rawText)) {
    pushFinding({ ruleId: 'evasion.sandbox-detect', line: 1, column: 1, evidence: '源码读取容器特征文件用于环境判断' });
  }
  scanExitGuard(ast, source, pushFinding);
  scanDelay(ast, source, pushFinding);

  return { findings, capabilities: [...capabilities] };
}

// ── 辅助 ────────────────────────────────────────────────────────

function splitPath(path: string | null): [string, string | null] {
  if (path === null) return ['', null];
  const idx = path.indexOf('.');
  if (idx === -1) return [path, null];
  return [path.slice(0, idx), path.slice(idx + 1)];
}

/** 高价值凭据:合法库几乎不会在读它们的同时联网 */
function isStrongCredential(detail: string): boolean {
  return /(?:^|\/)\.ssh|id_rsa|id_ed25519|\.npmrc|env-dump|cloud-metadata|Cookies|Login Data|wallet|git-credentials|\.aws/i.test(detail);
}

function capabilityOf(ruleId: string): string {
  if (ruleId.startsWith('net.')) return 'network';
  if (ruleId.startsWith('cred.')) return 'credentials';
  if (ruleId.startsWith('exec.')) return 'execution';
  if (ruleId.startsWith('fs.')) return 'filesystem';
  if (ruleId.startsWith('evasion.')) return 'evasion';
  if (ruleId.startsWith('obf.')) return 'obfuscation';
  return 'other';
}

const NETWORK_SUBTREE_HINT = /^(?:http|https|net|tls|dns|fetch|axios|got|undici|node-fetch)$/;

/** 判断子树里是否包含网络调用(用于数据流近似) */
function containsNetworkCall(node: Node, imports: ImportMap, depth = 0): boolean {
  if (!node || depth > 12) return false;
  if ((node.type === 'CallExpression' || node.type === 'NewExpression') && node.callee) {
    const path = resolvePath(node.callee, imports);
    if (path !== null) {
      const [mod, method] = splitPath(path);
      if (path === 'fetch' || mod === 'XMLHttpRequest') return true;
      if (NETWORK_SUBTREE_HINT.test(mod) && (method === null || NETWORK_METHODS.has(method))) return true;
      if (mod === 'navigator' && method === 'sendBeacon') return true;
      if ((mod === 'undici' || mod === 'axios' || mod === 'got') && method !== null) return true;
    }
  }
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'range') continue;
    const v = (node as any)[key];
    if (Array.isArray(v)) {
      for (const item of v) if (item && typeof item.type === 'string' && containsNetworkCall(item, imports, depth + 1)) return true;
    } else if (v && typeof v.type === 'string' && containsNetworkCall(v, imports, depth + 1)) return true;
  }
  return false;
}

/** eval/Function 的参数是否引用了"由网络响应赋值"的变量 */
function argReferencesTaint(node: Node, funcId: number, isTainted: (name: string, funcId: number) => boolean): boolean {
  let found = false;
  const visit = (n: Node, d: number) => {
    if (!n || found || d > 10) return;
    if (n.type === 'Identifier' && isTainted(n.name, funcId)) found = true;
    for (const key of Object.keys(n)) {
      if (key === 'loc' || key === 'range') continue;
      const value: unknown = (n as Record<string, unknown>)[key];
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item && typeof (item as Node).type === 'string') visit(item as Node, d + 1);
        }
      } else if (value && typeof (value as Node).type === 'string') {
        visit(value as Node, d + 1);
      }
    }
  };
  for (const arg of node.arguments ?? []) visit(arg, 0);
  return found;
}

/** 间接 eval:`eval`、`(0, eval)`、`(eval)`、`window.eval`、`globalThis.eval` */
function isEvalCallee(callee: Node, env: StaticEnv | null, depth = 0): boolean {
  if (!callee || depth > 6) return false;
  if (callee.type === 'Identifier') return callee.name === 'eval';
  if (callee.type === 'SequenceExpression') {
    const last = callee.expressions[callee.expressions.length - 1];
    return isEvalCallee(last, env, depth + 1);
  }
  if (callee.type === 'MemberExpression') {
    const name = staticMemberName(callee);
    if (name !== 'eval') return false;
    const base = memberPath(callee.object);
    return base === 'window' || base === 'globalThis' || base === 'global' || base === 'self';
  }
  return false;
}

/** Function 构造器:`Function(x)`、`new Function(x)`、`window.Function(x)` */
function isFunctionCallee(callee: Node, env: StaticEnv | null, depth = 0): boolean {
  if (!callee || depth > 6) return false;
  if (callee.type === 'Identifier') return callee.name === 'Function';
  if (callee.type === 'SequenceExpression') {
    const last = callee.expressions[callee.expressions.length - 1];
    return isFunctionCallee(last, env, depth + 1);
  }
  if (callee.type === 'MemberExpression') {
    if (staticMemberName(callee) !== 'Function') return false;
    const base = memberPath(callee.object);
    return base === 'window' || base === 'globalThis' || base === 'global';
  }
  return false;
}

function isEnvDumpCall(callee: Node, args: Node[]): boolean {
  const path = memberPath(callee);
  if (!path) return false;
  // Object.keys 只拿到变量名列表(debug 库用它读 DEBUG 前缀),不算转储值
  const isSerializer = path === 'JSON.stringify' || path === 'Object.entries' || path === 'Object.values' || path === 'Object.assign';
  if (!isSerializer) return false;
  // 只有直接转储 process.env(或它的整体引用)才算;JSON.stringify({built:true}) 不算
  return args.some((arg) => isProcessEnvReference(arg));
}

/**
 * 判断表达式是否把 process.env 整体交出去:
 * `JSON.stringify(process.env)`、`{ env: process.env }`、`[process.env]` 都算。
 * 只统计"作为值"出现的位置,不会把 `{ 'process.env': 1 }` 这种键名算进去。
 */
function isProcessEnvReference(node: Node | null | undefined, depth = 0): boolean {
  if (!node || depth > 8) return false;
  if (memberPath(node) === 'process.env') return true;
  switch (node.type) {
    case 'LogicalExpression':
      return isProcessEnvReference(node.left, depth + 1) || isProcessEnvReference(node.right, depth + 1);
    case 'ConditionalExpression':
      return isProcessEnvReference(node.consequent, depth + 1) || isProcessEnvReference(node.alternate, depth + 1);
    case 'ObjectExpression':
      return (node.properties ?? []).some((p: Node) => p?.type === 'Property' && isProcessEnvReference(p.value, depth + 1));
    case 'ArrayExpression':
      return (node.elements ?? []).some((e: Node) => e && isProcessEnvReference(e, depth + 1));
    case 'CallExpression':
      // Object.assign({}, process.env) 之类
      return (node.arguments ?? []).some((a: Node) => isProcessEnvReference(a, depth + 1));
    default:
      return false;
  }
}

/**
 * 判断写入目标是否位于包目录之外。
 *
 * 只看能把路径折叠成字符串的情形(os.homedir()/HOMEDRIVE/绝对路径/上级目录/点文件);
 * 求值不出来的动态路径不直接判定为外部,交给通配规则(避免把 `path.join(__dirname,'dist')` 误报)。
 */
function isOutsidePackagePath(node: Node, env: StaticEnv | null, imports: ImportMap): boolean {
  const fragments: string[] = [];
  collectStaticStrings(node, env, fragments);

  let sawHomedir = false;
  let sawAbsolute = false;
  let sawParentEscape = false;
  let sawPackageRelative = false;

  const visit = (n: Node, d: number) => {
    if (!n || d > 10) return;
    if ((n.type === 'CallExpression' || n.type === 'MemberExpression') && n.type) {
      const path = n.type === 'CallExpression' ? resolvePath(n.callee, imports) : resolvePath(n, imports);
      if (path === 'os.homedir' || path === 'os.tmpdir' || path === 'process.cwd' || path === 'os.tmpDir') {
        if (path === 'os.homedir') sawHomedir = true;
      }
    }
    if (n.type === 'Identifier') {
      if (/^(?:HOMEDRIVE|HOME|USERPROFILE|APPDATA|LOCALAPPDATA)$/.test(n.name)) sawHomedir = true;
      if (n.name === '__dirname' || n.name === 'require' ) sawPackageRelative = true;
    }
    if (n.type === 'Literal' && typeof n.value === 'string') {
      const v = n.value;
      if (v.startsWith('/') || /^[A-Za-z]:\\/.test(v)) sawAbsolute = true;
      if (v.split(/[\\/]/).includes('..')) sawParentEscape = true;
      if (/(?:^\.|\.)(?:bashrc|zshrc|profile|npmrc|ssh\b|bash_profile|config\b|aws\b|git-credentials)/i.test(v)) sawHomedir = true;
    }
    for (const key of Object.keys(n)) {
      if (key === 'loc' || key === 'range') continue;
      const value: unknown = (n as Record<string, unknown>)[key];
      if (Array.isArray(value)) {
        for (const item of value) if (item && typeof (item as Node).type === 'string') visit(item as Node, d + 1);
      } else if (value && typeof (value as Node).type === 'string') {
        visit(value as Node, d + 1);
      }
    }
  };
  visit(node, 0);

  for (const fragment of fragments) {
    if (/(?:^|\/)\.?(?:ssh|bashrc|zshrc|profile|npmrc|bash_profile|aws|config|git-credentials)(?:\/|$)/i.test(fragment)) sawHomedir = true;
    if (fragment.startsWith('/') || /^[A-Za-z]:\\/.test(fragment)) sawAbsolute = true;
  }

  if (sawHomedir) return true;
  // 绝对路径只有在没有 __dirname 锚定时才视为包外
  if (sawAbsolute && !sawPackageRelative) return true;
  if (sawParentEscape && !sawPackageRelative) return true;
  return false;
}

/**
 * 判断调用参数是否"静态可解码":base64 / hex 转义 / String.fromCharCode /
 * 字符数组 join / reverse,或对上述结果再调用 Buffer.from(...,'base64').toString()。
 * 返回解码后的文本;解不出返回 null。全程不执行代码。
 */
function findStaticDecodedArgument(call: Node, ctx: DecodeContext, depth = 0): string | null {
  if (!call || depth > 6) return null;
  const args = call.arguments ?? [];
  for (const arg of args) {
    const decoded = decodeExpression(arg, ctx, depth + 1);
    if (decoded !== null && decoded.length > 0) return decoded;
  }
  return null;
}

/**
 * 预计算:哪些变量被赋值成"解码后的文本"。
 * 只处理单一赋值且未被重新赋值的名字,避免引入错误的数据流。
 */
function buildDecodedVars(ast: Node, env: StaticEnv, imports: ImportMap): Map<string, string> {
  const out = new Map<string, string>();
  const ctx: DecodeContext = { env, imports, decodedVars: out };
  // 迭代到不动点,支持 a→b→c 的链式传播(最多 4 轮)
  for (let round = 0; round < 4; round++) {
    let changed = false;
    walkAst(ast, {
      VariableDeclarator(node: Node) {
        if (!node.id || node.id.type !== 'Identifier' || !node.init) return;
        const name = node.id.name;
        if (env.reassigned.has(name) || out.has(name)) return;
        const decoded = decodeExpression(node.init, ctx);
        if (decoded !== null && decoded.length >= 8) {
          out.set(name, decoded);
          changed = true;
        }
      },
    });
    if (!changed) break;
  }
  return out;
}

/**
 * 静态解码上下文:除 AST 常量表外,还包含"变量 → 已解码文本"的映射。
 * decodedVars 由 buildDecodedVars() 预计算,用来穿透
 *   const p = String.fromCharCode(…); eval(p)
 * 这类一层间接。
 */
export interface DecodeContext {
  env: StaticEnv | null;
  imports: ImportMap;
  decodedVars: Map<string, string>;
}

function decodeExpression(node: Node, ctx: DecodeContext, depth = 0): string | null {
  const { env, imports } = ctx;
  if (!node || depth > 8) return null;

  if (node.type === 'Identifier') {
    const cached = ctx.decodedVars.get(node.name);
    if (cached !== undefined) return cached;
    // 普通字符串常量(如 var s = "\x6c...")由解析器已还原,直接给出
    const literal = env?.strings.get(node.name);
    if (literal !== undefined) return literal;
    return null;
  }

  if (node.type === 'CallExpression') {
    const calleePath = resolvePath(node.callee, imports);
    const callee = node.callee;

    // Buffer.from(<str>, 'base64'|'hex').toString(...)
    if (calleePath === 'Buffer.from' || (callee?.type === 'MemberExpression' && staticMemberName(callee) === 'from' && memberPath(callee.object) === 'Buffer')) {
      if (node.arguments.length >= 2) {
        const enc = evalStaticString(node.arguments[1], env);
        const data = evalStaticString(node.arguments[0], env);
        if (enc && data && /^(base64|base64url|hex)$/i.test(enc)) {
          const normalized = enc.toLowerCase().startsWith('base64') ? data : data;
          try {
            const buf = enc.toLowerCase() === 'hex' ? Buffer.from(normalized, 'hex') : Buffer.from(normalized.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
            const text = buf.toString('utf8');
            return text.includes('\u0000') ? null : text;
          } catch {
            return null;
          }
        }
      }
    }

    // String.fromCharCode(...) / fromCodePoint(...)
    if (callee?.type === 'MemberExpression' && (staticMemberName(callee) === 'fromCharCode' || staticMemberName(callee) === 'fromCodePoint')) {
      const value = evalStaticString(node, env);
      if (value !== null) return value;
      // 参数可能是数组展开
      if (node.arguments.length === 1 && node.arguments[0].type === 'ArrayExpression') {
        const arr = evalStaticArray(node.arguments[0]);
        if (arr) return String.fromCharCode(...(arr as number[]));
      }
    }

    // atob(<str>) / decodeURIComponent(<str>)
    if (callee?.type === 'Identifier' && (callee.name === 'atob' || callee.name === 'unescape')) {
      const value = evalStaticString(node.arguments[0], env);
      if (value !== null) {
        if (callee.name === 'atob') {
          try {
            return Buffer.from(value, 'base64').toString('utf8');
          } catch {
            return null;
          }
        }
        return (globalThis as any).unescape(value) as string;
      }
    }

    // .join('') —— 取参数的静态数组
    if (callee?.type === 'MemberExpression' && staticMemberName(callee) === 'join') {
      const arr = evalStaticArray(callee.object);
      if (arr) {
        const sep = node.arguments.length ? evalStaticString(node.arguments[0], env) : '';
        const allNumeric = arr.every((x) => typeof x === 'number');
        if (allNumeric) return String.fromCharCode(...(arr as number[]));
        return arr.map(String).join(sep ?? '');
      }
      // arr.split('').reverse().join('')
      if (callee.object?.type === 'CallExpression') {
        const reverseCall = callee.object;
        const reverseName = reverseCall.callee?.type === 'MemberExpression' ? staticMemberName(reverseCall.callee) : null;
        if (reverseName === 'reverse') {
          const inner = decodeExpression(reverseCall.callee.object, ctx, depth + 1);
          if (inner !== null) return [...inner].reverse().join('');
          const innerStatic = evalStaticString(reverseCall.callee.object, env);
          if (innerStatic !== null) return [...innerStatic].reverse().join('');
        }
      }
    }

    // .toString() 外层:Buffer.from(...).toString('utf8')
    if (callee?.type === 'MemberExpression' && staticMemberName(callee) === 'toString') {
      return decodeExpression(callee.object, ctx, depth + 1);
    }

    // 嵌套调用:把内层结果继续解
    const asStatic = evalStaticString(node, env);
    if (asStatic !== null && (asStatic.length > 24 || /[^\x20-\x7e]/.test(asStatic))) return null;
    return null;
  }

  // 模板 / 拼接出来的编码串
  const staticValue = evalStaticString(node, env);
  if (staticValue !== null) {
    // 由调用方进一步判断是否是 base64/hex 形态;这里只做 charCode 类还原
    if (/^[0-9a-fA-F]{24,}$/.test(staticValue) && staticValue.length % 2 === 0) {
      const out = Buffer.from(staticValue, 'hex').toString('utf8');
      if (!out.includes('\u0000')) return out;
    }
    if (/^(?:\\x[0-9a-fA-F]{2}){8,}$/.test(staticValue)) {
      const out = staticValue.replace(/\\x([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(Number.parseInt(h, 16)));
      return out;
    }
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = decodeExpression(node.left, ctx, depth + 1);
    const right = decodeExpression(node.right, ctx, depth + 1);
    if (left !== null && right !== null) return left + right;
    return null;
  }

  return null;
}

/** 判断某个表达式是否会解码出可执行二进制魔数 */
function decodeBinaryMagic(node: Node, env: StaticEnv | null, imports: ImportMap, depth = 0): boolean {
  if (!node || depth > 8) return false;
  if (node.type === 'CallExpression') {
    const path = resolvePath(node.callee, imports);
    if (path === 'Buffer.from' || path === 'Buffer.from') {
      if (node.arguments.length >= 2) {
        const enc = evalStaticString(node.arguments[1], env);
        if (enc && /^(base64|hex)$/i.test(enc)) {
          const data = evalStaticString(node.arguments[0], env);
          if (data) {
            const buf = Buffer.from(data, enc as BufferEncoding);
            return hasBinaryMagic(buf);
          }
        }
      }
    }
  }
  return false;
}

function hasBinaryMagic(buf: Buffer): boolean {
  if (buf.length < 4) return false;
  // ELF
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return true;
  // Mach-O (32/64, 大小端)
  if ((buf[0] === 0xcf && buf[1] === 0xfa) || (buf[0] === 0xfe && buf[1] === 0xed) || (buf[0] === 0xca && buf[1] === 0xfe)) return true;
  // PE / MZ
  if (buf[0] === 0x4d && buf[1] === 0x5a) return true;
  // universal binary fat header
  if (buf[0] === 0xbe && buf[1] === 0xba && buf[2] === 0xfe && buf[3] === 0xca) return true;
  return false;
}

// ── 混淆扫描 ───────────────────────────────────────────────────

function scanObfuscation(
  ast: Node,
  source: string,
  file: string,
  push: (input: FindingDraft) => void,
  env: StaticEnv,
): void {
  const base64Candidates: Array<{ value: string; line: number }> = [];
  const hexCandidates: Array<{ value: string; line: number }> = [];
  const charCodeCalls: Array<{ line: number; length: number }> = [];
  const singleCharArrays: Array<{ line: number; length: number }> = [];
  let shortIdentifiers = 0;
  let totalIdentifiers = 0;

  walkAst(ast, {
    Identifier(node: Node, _s: unknown, ancestors: Node[]) {
      const parent = ancestors[ancestors.length - 2];
      const isProp = parent?.type === 'MemberExpression' && parent.property === node && !parent.computed;
      const isKey = parent?.type === 'Property' && parent.key === node && !parent.computed;
      if (isProp || isKey) return;
      totalIdentifiers++;
      if (node.name.length <= 2) shortIdentifiers++;
    },
    Literal(node: Node) {
      if (typeof node.value !== 'string') return;
      const loc = node.loc?.start;
      const line = loc?.line ?? 1;
      const value = node.value;
      if (looksLikeBase64Str(value)) base64Candidates.push({ value, line });
      if (/^(?:\.[\s\S]{0})?[0-9a-fA-F]{32,}$/.test(value) || (value.match(/\\x[0-9a-fA-F]{2}/g) ?? []).length >= 12) {
        hexCandidates.push({ value, line });
      }
    },
    CallExpression(node: Node) {
      const callee = node.callee;
      if (!callee || callee.type !== 'MemberExpression') return;
      const name = staticMemberName(callee);
      const line = node.loc?.start.line ?? 1;
      if (name === 'fromCharCode' || name === 'fromCodePoint') {
        if ((node.arguments?.length ?? 0) >= 16) charCodeCalls.push({ line, length: node.arguments.length });
      }
      if (name === 'join') {
        const obj = callee.object;
        if (obj?.type === 'ArrayExpression' && obj.elements.length >= 20) {
          const allShort = obj.elements.every((e: Node) => e?.type === 'Literal' && typeof e.value === 'string' && e.value.length <= 2);
          if (allShort) {
            const joined = obj.elements.map((e: Node) => e.value as string).join('');
            const printableRatio = [...joined].filter((c) => c >= ' ' && c <= '~').length / Math.max(1, [...joined].length);
            if (printableRatio >= 0.85 && /[A-Za-z_$()[\]{};=]/.test(joined)) {
              singleCharArrays.push({ line, length: obj.elements.length });
            }
          }
        }
      }
    },
    ArrayExpression(node: Node) {
      if (node.elements.length < 20) return;
      const allShort = node.elements.every((e: Node) => e?.type === 'Literal' && typeof e.value === 'string' && e.value.length <= 2);
      if (!allShort) return;
      // semver 的 WHITESPACE_CHARACTERS 这类空白/控制字符表也是"字符数组",但完全没有混淆意义。
      // 只有拼起来是可见字符、且像标识符/调用时才算可疑。
      const joined = node.elements.map((e: Node) => e.value as string).join('');
      const printableRatio = [...joined].filter((c) => c >= ' ' && c <= '~').length / Math.max(1, [...joined].length);
      if (printableRatio < 0.85) return;
      if (!/[A-Za-z_$()[\]{};=]/.test(joined)) return;
      singleCharArrays.push({ line: node.loc?.start.line ?? 1, length: node.elements.length });
    },
  });

  if (base64Candidates.length) {
    const longest = base64Candidates.reduce((a, b) => (b.value.length > a.value.length ? b : a));
    push({ ruleId: 'obf.base64-blob', line: longest.line, column: 1, evidence: `${longest.value.slice(0, 100)}… (${longest.value.length} chars)`, tags: [`count=${base64Candidates.length}`] });
  }
  if (hexCandidates.length) {
    const longest = hexCandidates.reduce((a, b) => (b.value.length > a.value.length ? b : a));
    push({ ruleId: 'obf.hex-blob', line: longest.line, column: 1, evidence: `${longest.value.slice(0, 100)}… (${longest.value.length} chars)`, tags: [`count=${hexCandidates.length}`] });
    if ((longest.value.match(/\\x[0-9a-fA-F]{2}/g) ?? []).length >= 40) {
      push({ ruleId: 'obf.hex-escape-code', line: longest.line, column: 1, evidence: longest.value.slice(0, 100) });
    }
  }
  for (const call of charCodeCalls) {
    push({ ruleId: 'obf.charcode-blob', line: call.line, column: 1, evidence: `String.fromCharCode 参数 ${call.length} 个` });
  }
  for (const arr of singleCharArrays) {
    push({ ruleId: 'obf.char-array', line: arr.line, column: 1, evidence: `字符数组 ${arr.length} 项 + join` });
  }

  // 压缩产物(min.js)天然全是短标识符,单独看没有信号价值。
  // 只有在"短标识符密集 + 同时存在编码块"时才提示,否则跳过。
  const hasEncodedBlob = base64Candidates.length > 0 || hexCandidates.length > 0 || charCodeCalls.length > 0;
  if (hasEncodedBlob && totalIdentifiers >= 60 && shortIdentifiers / totalIdentifiers > 0.75) {
    push({
      ruleId: 'obf.identifier-mangling',
      line: 1,
      column: 1,
      evidence: `${shortIdentifiers}/${totalIdentifiers} 个标识符长度为 1-2`,
    });
  }

  // 双重转义:`\\\\x` 等
  const doubledEscapes = (source.match(/\\\\\\\\x[0-9a-fA-F]{2}/g) ?? []).length;
  if (doubledEscapes >= 10) {
    push({ ruleId: 'obf.excessive-escapes', line: 1, column: 1, evidence: `双重转义 ${doubledEscapes} 处` });
  }

  // Unicode 转义:lodash 的 unicode 正则表完全是这个形状,所以必须再加一层条件 ——
  // 只有当转义块解出来像代码时才报。我们的正则能识别正则/字符类片段,会返回 text。
  // 真正需要警惕的是"可执行代码被整段转义":源码里出现转义形式的 eval/require/exec 等关键字。
  // lodash 那种 `'\u00c0': 'A'` 的字母映射表、unicode 正则表都不符合。
  const escapedKeywords = (source.match(/\\u00(?:65|76|61|6c)|\\x(?:65|76|61|6c)/gi) ?? []).length;
  const unicodeEscapeMatches = source.match(/\\u[0-9a-fA-F]{4}/g) ?? [];
  if (unicodeEscapeMatches.length >= 60 && escapedKeywords >= 12) {
    push({ ruleId: 'obf.unicode-escape-code', line: 1, column: 1, evidence: `Unicode 转义 ${unicodeEscapeMatches.length} 处,含转义关键字` });
  }
  void env;
  void file;
}

function looksLikeBase64Str(value: string): boolean {
  if (value.length < 60) return false;
  const compact = value.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return false;
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[+/=]/].filter((re) => re.test(compact)).length;
  return classes >= 3 && compact.length % 4 === 0;
}

function scanExitGuard(ast: Node, source: string, push: (input: FindingDraft) => void): void {
  // process.exit 在 if 分支里本身很正常(CLI 的 --help/--version 处理)。
  // 只有条件本身在探测运行环境(env / 容器 / 主机名 / 调试器)时才提示。
  walkAst(ast, {
    IfStatement(node: Node) {
      const condition = node.test ? sliceSource(source, node.test, 300) : '';
      const consequent = node.consequent ? sliceSource(source, node.consequent, 500) : '';
      if (!/process\.exit/.test(consequent)) return;
      if (!/(?:process\.env|NODE_ENV|CI\b|dockerenv|proc\/|hostname|USER|USERNAME|debugger|argv)/i.test(condition)) return;
      push({ ruleId: 'evasion.exit-guard', line: node.loc?.start.line ?? 1, column: 1, evidence: `if (${condition.slice(0, 120)}) { … process.exit … }` });
    },
  });
}

function scanDelay(ast: Node, source: string, push: (input: FindingDraft) => void): void {
  walkAst(ast, {
    CallExpression(node: Node) {
      const callee = node.callee;
      if (!callee || callee.type !== 'Identifier') return;
      if (callee.name !== 'setTimeout' && callee.name !== 'setInterval') return;
      const delay = node.arguments?.[1];
      if (!delay || delay.type !== 'Literal' || typeof delay.value !== 'number') return;
      if (delay.value < 30_000) return;
      const body = node.arguments[0];
      const bodyText = body ? sliceSource(source, body, 600) : '';
      if (/exec|eval|Function|http|fetch|require|writeFile/.test(bodyText) || body?.type === 'Identifier') {
        push({ ruleId: 'evasion.delay-execution', line: node.loc?.start.line ?? 1, column: 1, evidence: `延时 ${delay.value}ms 后执行敏感动作` });
      }
    },
  });
}

function scanRawText(source: string, file: string, emit: (input: FindingDraft) => void): void {
  // 文本模式(解析失败或 shell 脚本):保守的正则匹配,宁缺毋滥
  const lines = source.split('\n');
  lines.forEach((line, idx) => {
    const trimmed = line.trim().slice(0, 140);
    if (/process\.env|printenv|env\s*\|/.test(line)) {
      // 定向读取敏感变量名
      const sensitive = line.match(/process\.env\.([A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)[A-Z0-9_]*)/i);
      emit({
        ruleId: sensitive ? 'cred.sensitive-env' : 'cred.process-env',
        line: idx + 1,
        column: 1,
        evidence: trimmed,
        ...(sensitive ? { tags: [`env=${sensitive[1]}`] } : {}),
      });
    }
    if (/(?:^|[\/\\])\.ssh|id_rsa|id_ed25519|\.npmrc|\.aws[\/]credentials|\.git-credentials/i.test(line)) {
      const isSsh = /\.ssh|id_rsa|id_ed25519/i.test(line);
      emit({ ruleId: isSsh ? 'cred.ssh-directory' : 'cred.npmrc', line: idx + 1, column: 1, evidence: trimmed });
    }
    if (/Cookies|Login Data|Local State|\.ethereum|wallet\.dat/i.test(line)) {
      emit({ ruleId: 'cred.browser-data', line: idx + 1, column: 1, evidence: trimmed });
    }
    if (/https?:\/\/169\.254\.169\.254|metadata\.google\.internal/i.test(line)) {
      emit({ ruleId: 'cred.cloud-metadata', line: idx + 1, column: 1, evidence: trimmed });
    }
    // 任意出站网络调用(含库调用写法)
    if (/(?:https?\.(?:get|request|post)\s*\(|\bfetch\s*\(|axios\.|\bgot\s*\(|XMLHttpRequest|navigator\.sendBeacon)/.test(line) || /(?:curl|wget|nc\s)/.test(line)) {
      emit({ ruleId: 'net.http-request', line: idx + 1, column: 1, evidence: trimmed });
    }
    if (/(?:curl|wget)[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/i.test(line)) {
      emit({ ruleId: 'install.shell-pipe', line: idx + 1, column: 1, evidence: trimmed });
    }
    if (/\b(?:eval|new Function)\s*\(/.test(line)) {
      emit({ ruleId: 'exec.eval', line: idx + 1, column: 1, evidence: trimmed });
    }
    if (/child_process|\.exec(?:Sync)?\s*\(|spawn(?:Sync)?\s*\(/.test(line)) {
      emit({ ruleId: 'exec.child-process', line: idx + 1, column: 1, evidence: trimmed });
    }
  });
  void file;
}
