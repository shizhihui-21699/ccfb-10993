/**
 * 简单混淆还原。
 *
 * 仅做**字符串变换**,不 eval、不 new Function、不 import。每一种解码都产出
 * `DecodedPayload`,带上来源(文件/行/手法),供规则引擎二次扫描。
 *
 * 支持的形态:
 *  - base64 / base64url 长串(含 Buffer.from(x,'base64'))
 *  - `\xNN` 十六进制转义序列
 *  - `\uNNNN` Unicode 转义序列
 *  - String.fromCharCode(...) / fromCodePoint(...)
 *  - 字符数组 + join('')(含 `[...].reverse().join('')`)
 *  - 字符串反转字面量
 *  - 上述手法的嵌套(最多 maxDepth 层)
 *  - 常见的数组轮转(registry[rot] 形式)不做通用还原,只提示
 */

import type { Node } from './ast';
import { collectStringLiterals, evalStaticArray, evalStaticString, parseProgram, positionOf, staticMemberName, walkAst } from './ast';

export interface DecodedPayload {
  text: string;
  /** 编码手法 */
  method: 'base64' | 'hex' | 'unicode-escape' | 'charcode' | 'char-array' | 'reverse' | 'concat';
  /** 来源描述,写进 Finding.decodedFrom */
  origin: string;
  /** 原文的简短预览 */
  sourcePreview: string;
  depth: number;
  /** 解码产生的文本是否像 JS / shell / URL */
  looksExecutable: boolean;
  /** 若解码文本又是一段代码,附上解析结果(可能为 null) */
  textKind: 'code' | 'text' | 'url';
}

const MIN_BASE64_LEN = 40;
const MIN_HEX_LEN = 24;
const MIN_CHARCODE_LEN = 16;
const MAX_DECODED_BYTES = 2 * 1024 * 1024;

/** 严格的 base64 判定,避免把普通英文单词误判 */
export function looksLikeBase64(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < MIN_BASE64_LEN) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) && !/^[A-Za-z0-9_-]+={0,2}$/.test(trimmed)) return false;
  // 必须有足够的熵:至少包含大小写与数字中的两类
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[+/_-]/].filter((re) => re.test(trimmed)).length;
  if (classes < 2) return false;
  // 长度不应明显偏离 4 的倍数(允许 url-safe 无填充)
  if (trimmed.length % 4 === 1) return false;
  return true;
}

export function looksLikeHexString(value: string): boolean {
  const compact = value.replace(/\\x([0-9a-fA-F]{2})/g, '').length > 0;
  if (compact) {
    // 形态一:连续 \xNN
    if ((value.match(/\\x[0-9a-fA-F]{2}/g) ?? []).length >= MIN_HEX_LEN / 2) return true;
  }
  const bare = value.trim();
  if (bare.length >= MIN_HEX_LEN && /^[0-9a-fA-F]+$/.test(bare) && bare.length % 2 === 0) return true;
  return false;
}

/** 解码 `\xNN` / `\uNNNN` 转义;若不是转义串返回 null */
export function decodeEscapes(value: string): string | null {
  if (!/\\x[0-9a-fA-F]{2}/.test(value) && !/\\u[0-9a-fA-F]{4}/.test(value)) return null;
  const out = value.replace(/\\x([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(Number.parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_m, h: string) => String.fromCharCode(Number.parseInt(h, 16)));
  return out;
}

/** base64 解码,兼容 url-safe;失败返回 null */
export function decodeBase64(value: string): string | null {
  let normalized = value.trim().replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4;
  if (pad === 1) return null;
  if (pad !== 0) normalized += '='.repeat(4 - pad);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) return null;
  try {
    const buf = Buffer.from(normalized, 'base64');
    if (buf.length > MAX_DECODED_BYTES) return null;
    // 追加的 = 可能吞掉真实字符;反向校验
    const text = buf.toString('utf8');
    if (text.includes('\u0000')) {
      // 含 NUL 的多半是二进制,不做文本还原
      return null;
    }
    return text;
  } catch {
    return null;
  }
}

const CODE_HINTS = [
  /require\s*\(/,
  /\bmodule\.exports\b/,
  /\bexport\s+(default|const|function)\b/,
  /\bfunction\s+\w+?\s*\(/,
  /\bimport\s+.*from\s+['"]/,
  /new\s+Function\s*\(/,
  /\beval\s*\(/,
  /\bprocess\.(env|exit|argv)\b/,
  /\bchild_process\b/,
  /\bhttps?\.[a-zA-Z]+/,
  /\bcurl\b|\bwget\b|\/bin\/sh\b|\bpowershell\b/,
  /\bexec(?:Sync)?\s*\(/,
  /\bBuffer\.from\b/,
];

/**
 * 判断解码后的文本是否"像可执行内容",而不仅仅是"能解出可读文本"。
 *
 * 关键教训:lodash 里的 `/\u0041-\u005A/` 这类正则和空白字符表也能被 \uNNNN 解码,
 * 但它们解出来的是正则片段/空白,不是代码。因此要求:
 *  - 命中至少两个代码特征,或
 *  - 命中一个强特征(require / eval / child_process / exec / 远端 shell 管道)。
 */
const STRONG_CODE_HINTS = [
  /require\s*\(/,
  /\beval\s*\(/,
  /new\s+Function\s*\(/,
  /\bchild_process\b/,
  /\bexec(?:Sync)?\s*\(/,
  /\bspawn(?:Sync)?\s*\(/,
  /\bprocess\.env\b/,
  /(?:curl|wget)[^|;]*\|\s*(?:ba|z|k)?sh\b/,
  /\bmodule\.exports\b\s*=/,
  /\bhttps?\.(?:get|request|post)\s*\(/,
];

export function looksExecutable(text: string): boolean {
  if (text.length < 8) return false;
  if (/^\s*(https?|ftp|wss?):\/\//.test(text)) return true;
  // 纯正则/字符类/空白表:即使含代码词汇也不当代码
  if (/^\(\?:|^\[|^\\[dswDSW]/.test(text.trim()) && !/require|eval|exec/.test(text)) return false;
  if (STRONG_CODE_HINTS.some((re) => re.test(text))) return true;
  let hits = 0;
  for (const re of CODE_HINTS) if (re.test(text)) hits++;
  return hits >= 2;
}

export function classifyText(text: string): 'code' | 'url' | 'text' {
  if (/^\s*(https?|wss?|ftp):\/\/\S+\s*$/.test(text)) return 'url';
  return looksExecutable(text) ? 'code' : 'text';
}

/**
 * 从 AST 收集所有可静态还原的载荷。
 * `maxDepth` 控制递归(解码结果再解码),避免恶意包用嵌套编码撑爆分析器。
 */
export function extractPayloads(ast: Node, source: string, file: string, maxDepth = 3): DecodedPayload[] {
  const payloads: DecodedPayload[] = [];
  const seen = new Set<string>();
  let layers = 0;

  const record = (payload: Omit<DecodedPayload, 'textKind' | 'looksExecutable'>) => {
    const key = `${payload.method}\u0000${payload.text}`;
    if (seen.has(key)) return;
    if (payload.text.length < 8 || payload.text.length > MAX_DECODED_BYTES) return;
    seen.add(key);
    layers++;
    const looks = looksExecutable(payload.text);
    payloads.push({ ...payload, looksExecutable: looks, textKind: classifyText(payload.text) });
  };

  const decodeRecursive = (text: string, method: DecodedPayload['method'], origin: string, depth: number, preview: string) => {
    if (depth > maxDepth) return;
    record({ text, method, origin, sourcePreview: preview, depth });

    // 对明显是代码的文本,尝试继续解出其中的编码串
    if (depth === maxDepth) return;
    if (!looksExecutable(text)) {
      // 即便不像代码,也试一次 base64 套娃
      if (text.length > MIN_BASE64_LEN && looksLikeBase64(text)) {
        const inner = decodeBase64(text);
        if (inner && inner !== text) decodeRecursive(inner, 'base64', `${origin} → base64#${depth + 1}`, depth + 1, previewOf(inner));
      }
      return;
    }
    try {
      const innerAst = parseProgram(text, { allowLoose: true });
      if (innerAst) {
        for (const nested of extractPayloads(innerAst.ast, text, file, 0)) {
          if (nested.text === text) continue;
          decodeRecursive(nested.text, nested.method, `${origin} → ${nested.method}#${depth + 1}`, depth + 1, previewOf(nested.text));
        }
      }
    } catch {
      /* 解析失败就算了 */
    }
  };

  walkAst(ast, {
    Literal(node: Node) {
      if (typeof node.value !== 'string') return;
      const loc = positionOf(node, { line: 1, column: 1 });
      const origin = `${file}:${loc.line}`;
      const preview = previewOf(node.value);
      const base64Hit = looksLikeBase64(node.value);
      if (base64Hit) {
        const decoded = decodeBase64(node.value);
        if (decoded !== null) decodeRecursive(decoded, 'base64', `${origin} base64`, 1, preview);
      }
      if (looksLikeHexString(node.value)) {
        const escapeDecoded = decodeEscapes(node.value);
        if (escapeDecoded !== null) {
          decodeRecursive(escapeDecoded, 'hex', `${origin} \\xNN`, 1, preview);
        } else if (/^[0-9a-fA-F]+$/.test(node.value.trim())) {
          const raw = node.value.trim();
          let text = '';
          for (let i = 0; i < raw.length; i += 2) text += String.fromCharCode(Number.parseInt(raw.slice(i, i + 2), 16));
          decodeRecursive(text, 'hex', `${origin} hex-bytes`, 1, preview);
        }
      }
      if (/\\u[0-9a-fA-F]{4}/.test(node.value)) {
        const unicode = decodeEscapes(node.value);
        if (unicode !== null) decodeRecursive(unicode, 'unicode-escape', `${origin} \\uNNNN`, 1, preview);
      }
      if (node.value.length > 20 && reversedLooksLikeCode(node.value)) {
        const reversed = [...node.value].reverse().join('');
        decodeRecursive(reversed, 'reverse', `${origin} reverse`, 1, preview);
      }
    },
    TemplateLiteral(node: Node) {
      const value = evalStaticString(node, null);
      if (value === null || value.length < MIN_BASE64_LEN) return;
      const loc = positionOf(node, { line: 1, column: 1 });
      const origin = `${file}:${loc.line}`;
      if (looksLikeBase64(value)) {
        const decoded = decodeBase64(value);
        if (decoded !== null) decodeRecursive(decoded, 'base64', `${origin} base64(template)`, 1, previewOf(value));
      }
    },
    CallExpression(node: Node) {
      const callee = node.callee;
      if (!callee || callee.type !== 'MemberExpression') return;
      const name = staticMemberName(callee);
      const loc = positionOf(node, { line: 1, column: 1 });
      const origin = `${file}:${loc.line}`;

      // String.fromCharCode(...) / String.fromCodePoint(...)
      if (name === 'fromCharCode' || name === 'fromCodePoint') {
        const value = evalStaticString(node, null);
        if (value !== null && value.length >= MIN_CHARCODE_LEN) {
          decodeRecursive(value, 'charcode', `${origin} String.${name}`, 1, previewOf(value));
        }
      }

      // array.join('')
      if (name === 'join') {
        const arr = evalStaticArray(callee.object);
        if (arr && arr.length >= MIN_CHARCODE_LEN) {
          const sep = node.arguments.length ? evalStaticString(node.arguments[0], null) : '';
          const value = arr.map(String).join(sep ?? '');
          if (value.length >= MIN_CHARCODE_LEN) {
            // 区分纯数字数组(charcode) 与 字符数组
            const allNumeric = arr.every((x) => typeof x === 'number');
            decodeRecursive(
              allNumeric ? String.fromCharCode(...(arr as number[])) : value,
              allNumeric ? 'charcode' : 'char-array',
              `${origin} array.join`,
              1,
              previewOf(value),
            );
          }
        }
      }

      // Buffer.from('...', 'base64').toString()
      if (callee.object && callee.object.type === 'CallExpression') {
        // 由内层 CallExpression 处理
      }
    },

    MemberExpression(node: Node) {
      // Buffer.from(x, 'base64') 的第二种捕获点
      const target = node;
      if (target.object?.type === 'CallExpression' && staticMemberName(target.object.callee) === 'from') {
        /* placeholder — 在 CallExpression 分支处理 */
      }
    },
  });

  // Buffer.from('...', 'base64').toString('utf8') 专门处理
  walkAst(ast, {
    CallExpression(node: Node) {
      const callee = node.callee;
      if (!callee || callee.type !== 'MemberExpression') return;
      if (staticMemberName(callee) !== 'toString') return;
      const obj = callee.object;
      if (!obj || obj.type !== 'CallExpression') return;
      const inner = obj.callee;
      if (!inner || inner.type !== 'MemberExpression' || staticMemberName(inner) !== 'from') return;
      if (obj.arguments.length < 2) return;
      const data = evalStaticString(obj.arguments[0], null);
      const enc = evalStaticString(obj.arguments[1], null);
      if (data === null || enc === null || !/^base64(url)?$/i.test(enc)) return;
      const decoded = decodeBase64(data);
      if (decoded === null) return;
      const loc = positionOf(node, { line: 1, column: 1 });
      decodeRecursive(decoded, 'base64', `${file}:${loc.line} Buffer.from(...,'base64')`, 1, previewOf(data));
    },
  });

  // 拼接式混淆 `'a'+'b'+'c'`:把整体静态求值结果纳入(若够长且含可疑 token)
  walkAst(ast, {
    BinaryExpression(node: Node) {
      if (node.operator !== '+') return;
      if (node.left?.type === 'BinaryExpression') return; // 只在最外层处理
      const value = evalStaticString(node, null);
      if (value === null || value.length < 200) return;
      if (!looksExecutable(value)) return;
      const loc = positionOf(node, { line: 1, column: 1 });
      record({
        text: value,
        method: 'concat',
        origin: `${file}:${loc.line} 纯拼接`,
        sourcePreview: previewOf(value),
        depth: 1,
      });
    },
  });

  return payloads;
}

function reversedLooksLikeCode(value: string): boolean {
  const reversed = [...value].reverse().join('');
  return looksExecutable(reversed);
}

function previewOf(value: string): string {
  const compact = value.replace(/\s+/g, ' ');
  return compact.length > 80 ? `${compact.slice(0, 80)}…` : compact;
}

/**
 * 从纯文本(非 JS 文件)中提取 base64 块,例如 postinstall 的 shell 脚本。
 */
export function extractTextPayloads(text: string, file: string, maxDepth = 2): DecodedPayload[] {
  const out: DecodedPayload[] = [];
  const seen = new Set<string>();
  const b64Re = /(?:^|[^\w+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])/g;
  let match: RegExpExecArray | null;
  let guard = 0;
  while ((match = b64Re.exec(text)) !== null && guard++ < 50) {
    const candidate = match[1]!;
    if (!looksLikeBase64(candidate)) continue;
    const decoded = decodeBase64(candidate);
    if (decoded === null || seen.has(decoded)) continue;
    seen.add(decoded);
    const line = text.slice(0, match.index).split('\n').length;
    out.push({
      text: decoded,
      method: 'base64',
      origin: `${file}:${line} text-base64`,
      sourcePreview: previewOf(candidate),
      depth: 1,
      looksExecutable: looksExecutable(decoded),
      textKind: classifyText(decoded),
    });
    if (maxDepth > 1) {
      for (const nested of extractTextPayloads(decoded, file, maxDepth - 1)) {
        if (seen.has(nested.text)) continue;
        seen.add(nested.text);
        out.push({ ...nested, origin: `${file}:${line} text-base64 → ${nested.method}`, depth: nested.depth + 1 });
      }
    }
  }

  // hex 转义块
  const hexRe = /((?:\\x[0-9a-fA-F]{2}){12,})/g;
  guard = 0;
  while ((match = hexRe.exec(text)) !== null && guard++ < 50) {
    const decoded = decodeEscapes(match[1]!);
    if (decoded === null || seen.has(decoded)) continue;
    seen.add(decoded);
    const line = text.slice(0, match.index).split('\n').length;
    out.push({
      text: decoded,
      method: 'hex',
      origin: `${file}:${line} text-hex`,
      sourcePreview: previewOf(match[1]!),
      depth: 1,
      looksExecutable: looksExecutable(decoded),
      textKind: classifyText(decoded),
    });
  }

  return out;
}
