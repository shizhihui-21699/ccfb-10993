/**
 * 共享类型定义。
 *
 * 设计原则:分析器只读取字节、解析 AST、做常量求值,绝不执行被分析的代码。
 * 所有"行为"最终收敛成 Finding;扫码结果可序列化,便于基线/差分和 SARIF 输出。
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export type Category =
  | 'install'
  | 'network'
  | 'credentials'
  | 'execution'
  | 'obfuscation'
  | 'filesystem'
  | 'supply-chain'
  | 'evasion'
  | 'artifact';

export interface Finding {
  /** 稳定规则 id,如 `exec.eval`;差分时用来判断"新行为类别" */
  ruleId: string;
  category: Category;
  severity: Severity;
  /** 规则基础权重(0-100),见 rules.ts */
  weight: number;
  title: string;
  /** 人话解释:这条命中意味着什么 */
  message: string;
  /** 相对包根的路径 */
  file: string;
  line: number;
  column: number;
  /** 触发命中的代码/字符串片段(截断) */
  evidence: string;
  tags: string[];
  /** 若该发现来自解码后的第二层载荷,记录来源链 */
  decodedFrom?: string;
  /** 差分阶段标记:该行为在旧版本中不存在 */
  isNew?: boolean;
  /** 差分后的实际权重(含新增加成) */
  effectiveWeight: number;
  /** 用于去重与差分的指纹 */
  fingerprint: string;
}

export interface FileReport {
  path: string;
  bytes: number;
  /** 解析失败时降级为文本扫描 */
  parseMode: 'ast' | 'text' | 'json' | 'other';
  findings: Finding[];
  /** 该文件内观测到的能力集合,用于跨规则组合(如 读凭据 + 外发) */
  capabilities: string[];
}

export interface PackageMeta {
  name: string;
  version: string;
  description?: string;
  license?: string;
  repository?: string;
  lifecycleScripts: Record<string, string>;
  dependencies: Record<string, string>;
  /** 例如 `bin`、`main`、`files` */
  entryPoints: string[];
  authors: string[];
}

export interface TarEntry {
  /** 规范化后的包内路径,已去掉 npm 的 `package/` 前缀 */
  path: string;
  bytes: Buffer;
  mode: number;
  /** 解析出的原始 typeflag */
  type: 'file' | 'dir' | 'symlink' | 'hardlink' | 'other';
  linkTarget?: string;
}

export interface ArchiveReport {
  /** 输入文件或目录的展示名 */
  source: string;
  package: PackageMeta;
  files: FileReport[];
  /** 归档层面的问题:路径穿越、异常条目、超大文件等 */
  archiveFindings: Finding[];
  stats: {
    entryCount: number;
    fileCount: number;
    totalBytes: number;
    jsFileCount: number;
    skipped: string[];
    layersDecoded: number;
    durationMs: number;
  };
}

export interface DiffResult {
  oldSource: string;
  newSource: string;
  oldVersion: string;
  newVersion: string;
  /** 仅在新版本中出现的行为 */
  newFindings: Finding[];
  /** 两版都有、但目标/证据发生变化的 */
  changedFindings: Finding[];
  removedRuleIds: string[];
  scoreDelta: number;
  oldScore: number;
  newScore: number;
  oldVerdict: Verdict;
  newVerdict: Verdict;
  /** package.json 生命周期脚本差异 */
  scriptChanges: Array<{ name: string; before?: string; after?: string }>;
  /** 新出现的文件 */
  addedFiles: string[];
  removedFiles: string[];
}

export interface Verdict {
  level: 'clean' | 'low' | 'suspicious' | 'high' | 'critical';
  label: string;
  score: number;
}

export interface RuleDefinition {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  weight: number;
  description: string;
}

export interface ScanOptions {
  /** 单文件(解压后)最大字节数 */
  maxFileBytes: number;
  /** 整包解压总量上限,防 zip bomb */
  maxTotalBytes: number;
  /** 最大条目数 */
  maxEntries: number;
  /** 载荷递归解码层数 */
  maxDecodeDepth: number;
  quiet: boolean;
}
