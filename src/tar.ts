/**
 * 最小化 tar 读取器 + gzip 解压。
 *
 * 有意不落盘、不调用系统 `tar`:整个归档在内存里解析,便于施加上限
 * (条目数、单文件大小、总量),也避免解压路径穿越到工作目录。
 * 支持 ustar、pax 扩展头、GNU 长文件名。
 */

import { gunzipSync } from 'node:zlib';
import type { TarEntry } from './types';

const BLOCK = 512;

export class TarLimitError extends Error {}

export interface TarReadLimits {
  maxEntries: number;
  maxFileBytes: number;
  maxTotalBytes: number;
}

function readString(buf: Buffer, start: number, len: number): string {
  const slice = buf.subarray(start, start + len);
  const nul = slice.indexOf(0);
  return (nul === -1 ? slice : slice.subarray(0, nul)).toString('utf8');
}

function readOctal(buf: Buffer, start: number, len: number): number {
  // GNU base-256 扩展:最高位为 1
  if (buf[start]! & 0x80) {
    let value = 0;
    for (let i = start + 1; i < start + len; i++) value = value * 256 + buf[i]!;
    return value;
  }
  const text = readString(buf, start, len).trim();
  if (text === '') return 0;
  const parsed = Number.parseInt(text, 8);
  return Number.isFinite(parsed) ? parsed : 0;
}

function verifyChecksum(header: Buffer): boolean {
  const stored = readOctal(header, 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) {
    // 校验和计算时,checksum 字段本身按空格计入
    sum += i >= 148 && i < 156 ? 0x20 : header[i]!;
  }
  return stored === sum || stored === sum + 256; // 某些实现用有符号字节
}

/** 解析 pax 记录的 `LEN key=value\n` 序列 */
function parsePax(data: Buffer): Map<string, string> {
  const out = new Map<string, string>();
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) break;
    const length = Number.parseInt(data.subarray(offset, space).toString('utf8'), 10);
    if (!Number.isFinite(length) || length <= 0 || offset + length > data.length) break;
    const record = data.subarray(space + 1, offset + length - 1).toString('utf8');
    const eq = record.indexOf('=');
    if (eq > 0) out.set(record.slice(0, eq), record.slice(eq + 1));
    offset += length;
  }
  return out;
}

/** 规范化包内路径;拒绝绝对路径与 `..` 穿越(只记录,不落盘) */
export function normalizeEntryPath(raw: string): { path: string; unsafe: boolean } {
  let p = raw.replace(/\\/g, '/');
  let unsafe = false;
  if (p.startsWith('/')) {
    unsafe = true;
    p = p.replace(/^\/+/, '');
  }
  if (/^[A-Za-z]:/.test(p)) unsafe = true;
  const parts: string[] = [];
  for (const segment of p.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      unsafe = true;
      if (parts.length) parts.pop();
      continue;
    }
    parts.push(segment);
  }
  return { path: parts.join('/'), unsafe };
}

/** 去掉 npm tarball 常见的顶层 `package/` 前缀 */
export function stripPackagePrefix(path: string): string {
  if (path === 'package') return '';
  if (path.startsWith('package/')) return path.slice('package/'.length);
  return path;
}

export interface TarReadResult {
  entries: TarEntry[];
  unsafePaths: string[];
  hardLinks: Array<{ path: string; target: string }>;
  symlinks: Array<{ path: string; target: string }>;
  /** 归档里出现了非普通文件/目录的类型 */
  otherTypes: Array<{ path: string; type: string }>;
  truncated: boolean;
}

export function readTar(
  raw: Buffer,
  limits: TarReadLimits,
  opts: { stripPackagePrefix?: boolean } = {},
): TarReadResult {
  const result: TarReadResult = {
    entries: [],
    unsafePaths: [],
    hardLinks: [],
    symlinks: [],
    otherTypes: [],
    truncated: false,
  };

  let offset = 0;
  let totalBytes = 0;
  // pax / GNU 长名状态,作用于下一条常规条目
  let pendingPath: string | undefined;
  let pendingLink: string | undefined;
  let pendingSize: number | undefined;
  let globalPax = new Map<string, string>();

  while (offset + BLOCK <= raw.length) {
    const header = raw.subarray(offset, offset + BLOCK);
    // 两个连续全零块表示归档结束
    if (header.every((b) => b === 0)) break;

    if (!verifyChecksum(header)) {
      throw new TarLimitError(`tar 头校验和无效,偏移 ${offset}`);
    }

    const typeflag = String.fromCharCode(header[156] || 0x30);
    const rawName = readString(header, 0, 100);
    const prefix = readString(header, 345, 155);
    const headerName = prefix ? `${prefix}/${rawName}` : rawName;
    let size = readOctal(header, 124, 12);
    if (pendingSize !== undefined) size = pendingSize;

    const dataStart = offset + BLOCK;
    if (dataStart + size > raw.length) {
      result.truncated = true;
      break;
    }
    const data = raw.subarray(dataStart, dataStart + size);
    const padded = Math.ceil(size / BLOCK) * BLOCK;
    offset = dataStart + padded;

    // 元数据条目
    if (typeflag === 'x') {
      const pax = parsePax(data);
      if (pax.has('path')) pendingPath = pax.get('path');
      if (pax.has('linkpath')) pendingLink = pax.get('linkpath');
      if (pax.has('size')) {
        const n = Number.parseInt(pax.get('size')!, 10);
        if (Number.isFinite(n)) pendingSize = n;
      }
      continue;
    }
    if (typeflag === 'g') {
      globalPax = parsePax(data);
      continue;
    }
    if (typeflag === 'L') {
      pendingPath = readString(data, 0, data.length);
      continue;
    }
    if (typeflag === 'K') {
      pendingLink = readString(data, 0, data.length);
      continue;
    }
    if (typeflag === 'V' || typeflag === 'D' || typeflag === 'M' || typeflag === 'S') {
      // volume label / dumpdir / multivolume / sparse — 不处理
      continue;
    }

    const effectiveName = pendingPath ?? globalPax.get('path') ?? headerName;
    const effectiveLink = pendingLink ?? globalPax.get('linkpath') ?? readString(header, 157, 100);
    pendingPath = undefined;
    pendingLink = undefined;
    pendingSize = undefined;

    if (result.entries.length >= limits.maxEntries) {
      result.truncated = true;
      break;
    }

    // 先对原始条目名判安全,再剥掉 package/ 前缀 —— 顺序反了会把 `../` 洗掉
    const normalized = normalizeEntryPath(effectiveName);
    const unsafe = normalized.unsafe;
    const path = opts.stripPackagePrefix === false ? normalized.path : stripPackagePrefix(normalized.path);
    if (unsafe) result.unsafePaths.push(effectiveName);
    if (path === '') continue; // 顶层 package/ 自身

    totalBytes += size;
    if (totalBytes > limits.maxTotalBytes) {
      throw new TarLimitError(`解压总量超过上限 ${limits.maxTotalBytes} 字节`);
    }

    const mode = readOctal(header, 100, 8);

    if (typeflag === '1') {
      result.hardLinks.push({ path, target: effectiveLink });
      result.entries.push({ path, bytes: Buffer.alloc(0), mode, type: 'hardlink', linkTarget: effectiveLink });
      continue;
    }
    if (typeflag === '2') {
      result.symlinks.push({ path, target: effectiveLink });
      result.entries.push({ path, bytes: Buffer.alloc(0), mode, type: 'symlink', linkTarget: effectiveLink });
      continue;
    }
    if (typeflag === '5') {
      result.entries.push({ path, bytes: Buffer.alloc(0), mode, type: 'dir' });
      continue;
    }
    if (typeflag !== '0' && typeflag !== '\0' && typeflag !== '7') {
      result.otherTypes.push({ path, type: typeflag });
      result.entries.push({ path, bytes: Buffer.alloc(0), mode, type: 'other' });
      continue;
    }

    if (size > limits.maxFileBytes) {
      // 超限文件只保留前 N 字节供表层扫描,并标记
      result.entries.push({ path, bytes: data.subarray(0, limits.maxFileBytes), mode, type: 'file' });
      result.truncated = true;
      continue;
    }

    // 复制一份,避免整个原始 buffer 被孤立引用
    result.entries.push({ path, bytes: Buffer.from(data), mode, type: 'file' });
  }

  return result;
}

/** 判断 buffer 是否 gzip(npm 的 .tgz) */
export function isGzip(buf: Buffer): boolean {
  return buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
}

export function decompressTarball(buf: Buffer, maxUncompressedBytes: number): Buffer {
  if (!isGzip(buf)) return buf;
  try {
    return gunzipSync(buf, { maxOutputLength: maxUncompressedBytes });
  } catch (err) {
    throw new TarLimitError(`gzip 解压失败或超出上限:${(err as Error).message}`);
  }
}
