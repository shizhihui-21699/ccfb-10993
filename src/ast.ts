/**
 * AST 工具层。
 *
 * 只做解析、遍历和 **纯静态常量折叠**(字符串拼接、String.fromCharCode、数组取字面量等)。
 * 绝不调用 eval / new Function,也不导入任何被分析的模块。
 */

import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

export type Node = any; // acorn ESTree 节点;结构随语法而变,这里用宽类型换可读性

export interface ParseOptions {
  /** 解析失败后是否改用宽松的 script 模式重试 */
  allowLoose?: boolean;
}

export interface ParseResult {
  ast: Node;
  /** 解析过程中跳过的注释等信息不需要 */
  sourceType: 'script' | 'module';
}

const BASE_ACORN_OPTIONS: acorn.Options = {
  ecmaVersion: 'latest',
  allowHashBang: true,
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  allowImportExportEverywhere: true,
  locations: true,
  ranges: true,
  preserveParens: false,
};

export function parseProgram(code: string, opts: ParseOptions = {}): ParseResult | null {
  const attempts: Array<'module' | 'script'> = ['module', 'script'];
  for (const sourceType of attempts) {
    try {
      const ast = acorn.parse(code, { ...BASE_ACORN_OPTIONS, sourceType, allowReserved: true });
      return { ast, sourceType };
    } catch {
      /* 尝试下一种 */
    }
  }
  if (opts.allowLoose) {
    // 最后尝试:去掉 shebang 后当表达式片段解析
    try {
      const stripped = code.replace(/^#!.*/, '');
      const ast = acorn.parse(stripped, { ...BASE_ACORN_OPTIONS, sourceType: 'script' });
      return { ast, sourceType: 'script' };
    } catch {
      return null;
    }
  }
  return null;
}

export function walkAst(ast: Node, visitors: Record<string, (node: Node, state: any, ancestors: Node[]) => void>): void {
  walk.fullAncestor(ast, (node: Node, _state: any, ancestors: Node[]) => {
    const visitor = visitors[node.type];
    if (visitor) visitor(node, null, ancestors);
  });
}

export function isFunctionNode(node: Node): boolean {
  return (
    !!node &&
    (node.type === 'FunctionDeclaration' ||
      node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression')
  );
}

/** 展开表达式节点:括号在解析时已折叠,直接返回 */
export function unwrap(node: Node): Node {
  return node;
}

/** 取得属性访问的静态名:`a.b` → `b`,`a['b']` → `b` */
export function staticMemberName(node: Node): string | null {
  if (!node) return null;
  if (node.type === 'MemberExpression') {
    if (!node.computed && node.property && node.property.type === 'Identifier') return node.property.name;
    if (node.computed) {
      const value = evalStaticString(node.property, null);
      if (value !== null) return value;
    }
  }
  return null;
}

/** 把链式成员访问折叠成点路径:`process.env.NPM_TOKEN` → `process.env.NPM_TOKEN` */
export function memberPath(node: Node): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const base = memberPath(node.object);
    const name = staticMemberName(node);
    if (base === null || name === null) return null;
    return `${base}.${name}`;
  }
  if (node.type === 'ThisExpression') return 'this';
  return null;
}

export interface StaticEnv {
  /** 单次赋值的 const/let 字面量绑定 */
  strings: Map<string, string>;
  /** 已知数组字面量(元素为数字或可求值字符串) */
  arrays: Map<string, Array<string | number>>;
  /** 被重新赋值的名字,不能当作常量 */
  reassigned: Set<string>;
}

/**
 * 扫描顶层(含嵌套)的变量声明,收集能被静态求值的绑定。
 * 只接受"整个文件里该名字仅出现在这一处声明"的简单情形。
 */
export function buildStaticEnv(ast: Node): StaticEnv {
  const strings = new Map<string, string>();
  const arrays = new Map<string, Array<string | number>>();
  const reassigned = new Set<string>();
  const declarations = new Map<string, number>();
  const writes = new Map<string, number>();

  walkAst(ast, {
    VariableDeclarator(node: Node) {
      if (node.id && node.id.type === 'Identifier' && node.init) {
        declarations.set(node.id.name, (declarations.get(node.id.name) ?? 0) + 1);
      }
    },
    AssignmentExpression(node: Node) {
      const target = node.left;
      if (target && target.type === 'Identifier') {
        reassigned.add(target.name);
        writes.set(target.name, (writes.get(target.name) ?? 0) + 1);
      }
    },
    UpdateExpression(node: Node) {
      if (node.argument && node.argument.type === 'Identifier') reassigned.add(node.argument.name);
    },
  });

  // 第二遍:真正求值那些唯一且未被写入的声明
  walkAst(ast, {
    VariableDeclarator(node: Node) {
      if (!node.id || node.id.type !== 'Identifier' || !node.init) return;
      const name = node.id.name;
      if (declarations.get(name) !== 1 || reassigned.has(name)) return;
      const str = evalStaticString(node.init, null);
      if (str !== null) {
        strings.set(name, str);
        return;
      }
      const arr = evalStaticArray(node.init);
      if (arr) arrays.set(name, arr);
    },
  });

  return { strings, arrays, reassigned };
}

/** 判断节点是否为数字字面量 */
function numericLiteral(node: Node): number | null {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'number') return node.value;
  if (node.type === 'UnaryExpression' && node.operator === '-' && node.argument?.type === 'Literal' && typeof node.argument.value === 'number') {
    return -node.argument.value;
  }
  return null;
}

const MAX_STATIC_STRING = 1 << 20;

/**
 * 纯静态求值字符串表达式,求不出就返回 null。
 * 支持:字面量、模板串(无插值或插值可求值)、`+` 拼接、String.fromCharCode(...)、
 * Buffer/atob 以外的基本转换、知名变量绑定、数组 join、三元表达式中的常量分支。
 */
export function evalStaticString(node: Node, env: StaticEnv | null, depth = 0): string | null {
  if (!node || depth > 12) return null;
  switch (node.type) {
    case 'Literal':
      if (typeof node.value === 'string') return node.value;
      return null;
    case 'TemplateLiteral': {
      if (node.expressions.length === 0) return node.quasis[0]?.value?.cooked ?? '';
      let out = '';
      for (let i = 0; i < node.quasis.length; i++) {
        out += node.quasis[i]?.value?.cooked ?? '';
        if (i < node.expressions.length) {
          const part = evalStaticString(node.expressions[i], env, depth + 1);
          if (part === null) return null;
          out += part;
          if (out.length > MAX_STATIC_STRING) return null;
        }
      }
      return out;
    }
    case 'BinaryExpression': {
      if (node.operator !== '+') return null;
      const left = evalStaticString(node.left, env, depth + 1);
      if (left === null) return null;
      const right = evalStaticString(node.right, env, depth + 1);
      if (right === null) return null;
      if (left.length + right.length > MAX_STATIC_STRING) return null;
      return left + right;
    }
    case 'Identifier': {
      if (env && env.strings.has(node.name)) return env.strings.get(node.name)!;
      return null;
    }
    case 'ConditionalExpression': {
      const test = evalStaticBoolean(node.test, env, depth + 1);
      if (test === null) return null;
      return evalStaticString(test ? node.consequent : node.alternate, env, depth + 1);
    }
    case 'CallExpression': {
      const callee = node.callee;
      if (!callee) return null;
      // String.fromCharCode(...数字)
      if (callee.type === 'MemberExpression' && staticMemberName(callee) === 'fromCharCode') {
        const codes = node.arguments.map((a: Node) => numericLiteral(a));
        if (codes.some((c: number | null) => c === null)) return null;
        return String.fromCharCode(...codes);
      }
      // String.fromCodePoint(...)
      if (callee.type === 'MemberExpression' && staticMemberName(callee) === 'fromCodePoint') {
        const codes = node.arguments.map((a: Node) => numericLiteral(a));
        if (codes.some((c: number | null) => c === null)) return null;
        return String.fromCodePoint(...codes);
      }
      // 数组.join('')
      if (callee.type === 'MemberExpression' && staticMemberName(callee) === 'join') {
        const arr = evalStaticArray(callee.object);
        if (arr) {
          const sep = node.arguments.length ? evalStaticString(node.arguments[0], env, depth + 1) : '';
          if (sep === null) return null;
          return arr.map(String).join(sep);
        }
      }
      // decodeURIComponent(常量)
      if (callee.type === 'Identifier' && callee.name === 'decodeURIComponent' && node.arguments.length === 1) {
        const inner = evalStaticString(node.arguments[0], env, depth + 1);
        if (inner === null || inner.length > MAX_STATIC_STRING) return null;
        try {
          return decodeURIComponent(inner);
        } catch {
          return null;
        }
      }
      // String(x) / Number 无关紧要
      return null;
    }
    case 'MemberExpression': {
      // 数组字面量 index
      if (node.computed) {
        const idx = numericLiteral(node.property);
        const arr = evalStaticArray(node.object);
        if (idx !== null && arr && idx >= 0 && idx < arr.length) {
          const item = arr[idx];
          return typeof item === 'string' ? item : null;
        }
      }
      return null;
    }
    default:
      return null;
  }
}

export function evalStaticBoolean(node: Node, env: StaticEnv | null, depth = 0): boolean | null {
  if (!node || depth > 8) return null;
  if (node.type === 'Literal') return Boolean(node.value);
  if (node.type === 'Identifier') {
    if (node.name === 'undefined') return false;
    return null;
  }
  if (node.type === 'UnaryExpression' && node.operator === '!') {
    const inner = evalStaticBoolean(node.argument, env, depth + 1);
    return inner === null ? null : !inner;
  }
  if (node.type === 'BinaryExpression') {
    const left = evalStaticString(node.left, env, depth + 1) ?? (numericLiteral(node.left) !== null ? String(numericLiteral(node.left)) : null);
    const right = evalStaticString(node.right, env, depth + 1) ?? (numericLiteral(node.right) !== null ? String(numericLiteral(node.right)) : null);
    if (left === null || right === null) {
      if (node.operator === '===' || node.operator === '==') {
        // 常量与非常量不可能相等时才返回
        return null;
      }
      return null;
    }
    switch (node.operator) {
      case '===':
      case '==':
        return left === right;
      case '!==':
      case '!=':
        return left !== right;
      default:
        return null;
    }
  }
  return null;
}

export function evalStaticArray(node: Node): Array<string | number> | null {
  if (!node) return null;
  if (node.type === 'ArrayExpression') {
    const out: Array<string | number> = [];
    for (const element of node.elements) {
      if (!element) return null; // 稀疏数组
      const num = numericLiteral(element);
      if (num !== null) {
        out.push(num);
        continue;
      }
      if (element.type === 'Literal' && typeof element.value === 'string') {
        out.push(element.value);
        continue;
      }
      return null;
    }
    return out;
  }
  return null;
}

/** 节点在源码中的位置 → 1 基行列 */
export function positionOf(node: Node, fallback: { line: number; column: number }): { line: number; column: number } {
  const loc = node?.loc?.start;
  if (!loc) return fallback;
  return { line: loc.line, column: loc.column + 1 };
}

/** 安全提取源码片段用于证据展示 */
export function sliceSource(source: string, node: Node, maxLen = 160): string {
  if (!node || typeof node.start !== 'number' || typeof node.end !== 'number') {
    return '';
  }
  const raw = source.slice(node.start, node.end).replace(/\s+/g, ' ');
  return raw.length > maxLen ? `${raw.slice(0, maxLen)}…` : raw;
}

/** 遍历所有字符串字面量(含模板串的 cooked 值),给解码器用 */
export function collectStringLiterals(ast: Node): Array<{ value: string; node: Node }> {
  const out: Array<{ value: string; node: Node }> = [];
  walkAst(ast, {
    Literal(node: Node) {
      if (typeof node.value === 'string') out.push({ value: node.value, node });
    },
    TemplateLiteral(node: Node) {
      for (const quasi of node.quasis) {
        const cooked = quasi?.value?.cooked;
        if (typeof cooked === 'string' && cooked.length > 0) out.push({ value: cooked, node });
      }
    },
  });
  return out;
}

/** 把函数体内的语句拼成一个简化阴影,便于识别"先查环境再外发"的模式 */
export function isAsyncOrReturnsPromise(node: Node): boolean {
  return node?.async === true || (node?.body && node.body.type !== 'BlockStatement') || false;
}

export const KNOWN_GLOBAL_OBJECTS = new Set([
  'process',
  'globalThis',
  'global',
  'window',
  'require',
  'module',
  'exports',
  'Buffer',
  'console',
]);

export { walk };
