# pkgsentry

npm 依赖进仓前的**静态行为分析器**。解开 tarball,在**不执行任何代码**的前提下,检查安装脚本、
网络请求、凭据访问、动态执行和混淆载荷,并支持同一包前后两个版本的差分——新冒出来的危险行为会被单独标出并加权。

```
pkgsentry scan  ./evil-pkg-1.2.3.tgz
pkgsentry diff  ./pkg-1.0.0.tgz ./pkg-1.1.0.tgz --fail-on high
pkgsentry rules
```

---

## 快速开始

```bash
npm install
npm run samples     # 生成样本包到 samples/packages/
npm test            # 构建并运行 38 个端到端测试
npm run build

# 扫描一个 tarball 或已解压目录
node dist/src/index.js scan samples/packages/evil-env-exfil-3.2.1.tgz
node dist/src/index.js scan samples/packages/evil-env-exfil-3.2.1.tgz --json
node dist/src/index.js scan samples/packages/evil-env-exfil-3.2.1.tgz --sarif > results.sarif

# 版本差分
node dist/src/index.js diff samples/packages/diffpkg-1.0.0.tgz samples/packages/diffpkg-1.0.1.tgz
```

退出码:`0` 正常,`1` 达到 `--fail-on` 阈值,`2` 用法或输入错误——可直接挂到 CI 的 pre-install 检查。

---

## 安全模型:只读、不执行

这是整个工具的硬约束,实现上体现在每一层:

| 风险 | 处理方式 |
|---|---|
| 执行被分析代码 | 只用 acorn **解析** AST;从不 `eval` / `new Function` / `require` 被分析的模块。测试用一个会到处写文件、`exec` 的样本验证"一个副作用都没发生"。 |
| 解压覆盖系统文件 | 不调用系统 `tar`,**在内存中**解析归档;不落盘,路径穿越只记录不展开。 |
| 符号链接逃逸 | 目录输入用 `lstat` 并跳过符号链接;归档里的链接目标只做检查,从不跟随。 |
| 压缩炸弹 / 超大文件 | 单文件、解压总量、条目数三重上限;超限截断并记录。 |
| 被分析内容当作指令 | 所有字符串仅作为数据处理,解码结果只用于匹配规则,不会回灌到分析流程之外。 |

---

## 分析能力

### 1. 安装期脚本(`package.json`)

生命周期键 `preinstall / install / postinstall / prepare …` 单独建模,因为 `npm install` 会无条件执行它们。识别的形态:

- `curl … | sh`、`wget … | node` —— 远端内容直接执行
- `node -e "eval(Buffer.from('…','base64')…)"` —— 内联 + 编码
- `powershell -enc …`、`base64 -d | sh`
- 安装期"读环境变量 + 联网"组合
- 脚本里内嵌的 base64/十六进制载荷会被**静态解码**后二次扫描

### 2. 网络行为

`http/https/net/tls/dns/dgram`、`fetch`、`axios/got/undici/ws` 等。重点不是"有没有网络",而是:

- 目标是否为裸 IP、webhook.site / pastebin / transfer.sh / ngrok 之类投放常用地址
- 是否指向云元数据端点(`169.254.169.254` 等)
- 请求里是否夹带凭据或环境变量
- **响应是否流入** `eval` / `Function` / `vm`(污点传播,见下)

### 3. 凭据访问

`process.env`(区分普通变量与 `NPM_TOKEN`/`AWS_*`/`GITHUB_TOKEN` 这类敏感项)、
`JSON.stringify(process.env)` 整体转储、`~/.ssh`、`.npmrc`、`.git-credentials`、
浏览器 Cookies/Login Data、加密钱包目录、云元数据。

### 4. 动态执行

`eval`(含 `(0, eval)` 间接写法)、`new Function`、`vm.*`、`child_process.*`、动态 `require`。
**单看这些不判死**——模板引擎也用 `Function`。只有当参数可静态解码、或与网络/凭据组合时才升级。

### 5. 混淆还原(纯字符串变换)

| 形态 | 处理 |
|---|---|
| base64 | 长度 + 熵判定,避免误判普通英文;支持 `Buffer.from(…,'base64')`、url-safe |
| `\xNN` / `\uNNNN` | 转义还原;区分"整段代码被转义"与"字母映射表" |
| `String.fromCharCode(...)` | 数字数组还原 |
| 字符数组 + `join` / `reverse` | 还原并判断可打印性 |
| 纯拼接字面量 | 静态折叠后整体检查 |
| 嵌套编码 | 递归下钻(默认最多 3 层),解出的代码重新走完整规则 |

还原结果只标记为"可执行代码 / URL / 普通文本"中的前两类才计入高危——否则 lodash 的 unicode 正则表会淹没信号。

### 6. 版本差分

指纹 = `(ruleId, file, 归一化证据)`,**不含行号**。所以:

- 代码整体下移/重构不算新行为
- 新版本里第一次出现的规则命中标为 `isNew`,并按严重度加权(critical +20 / high +14 / medium +8)
- 同时列出 `package.json` 脚本变化、新增文件、消失的行为

```
diff: 1.0.0 → 1.0.1
  score: 0 → 93.9 (+93.9)
  verdict: clean → critical

script changes:
  postinstall
    + node setup.js

NEW behaviours (7):
  + [CRITICAL] net.upload-credentials setup.js:8 weight 90→100
  + [HIGH]     cred.ssh-directory      setup.js:8 weight 72→86
  …
```

### 7. 归档结构

路径穿越条目、逃逸符号链接、包内 ELF/Mach-O/PE、可疑可执行位、点文件、超大文件。

---

## 规则权重怎么定的

完整规则表见 `src/rules.ts`(`pkgsentry rules` 可打印)。权重不是拍脑袋,而是按"这条行为单独出现时有多可疑"分层:

| 档位 | 权重 | 典型规则 | 理由 |
|---|---|---|---|
| 安装期 RCE | 85–95 | `install.shell-pipe`、`install.node-eval` | 100% 在 `npm install` 执行,没有运行时条件 |
| 窃密链组合 | 85–92 | `net.upload-credentials`、`net.remote-fetch-eval` | 是"行为组合"而非单点,基本无正当用途 |
| 明确高危单点 | 60–80 | `cred.ssh-directory`、`fs.autostart`、`evasion.sandbox-detect` | 无正常用途或极罕见 |
| 需要上下文 | 35–55 | `exec.eval`、`exec.child-process`、`net.http-request` | 模板引擎、HTTP 客户端都在用 |
| 弱信号 | 12–30 | `cred.process-env`、`obf.base64-blob` | 单独看几乎无意义 |

**评分不是加总**:

1. 每条规则只计一次分(同规则多行不刷分)
2. 同类别后续规则**边际递减**(`1/(1+√(已累积/25))`),避免某类规则数量多就爆表
3. 类别有上限(如 `supply-chain` 封顶 45)
4. 跨类别的**高危链**额外加成:读凭据 + 外发、编码载荷 + 动态执行、网络 + 执行……
5. 最后做饱和压缩到 0–100
6. **严重度封顶**:如果没有任何 high 及以上命中,结论最高只到 suspicious——"有 postinstall + 写本地缓存"不该被判 critical

这些参数用样本回归过,结果见下节。

---

## 样本与标定结果

`samples/packages/` 由 `scripts/build-samples.ts` 生成(自己写 ustar 打包,以便构造路径穿越等恶意归档结构)。共 21 个包:

| 类型 | 样本 | 期望 |
|---|---|---|
| 正常 | `clean-string-utils`、`clean-with-build`、`clean-tricky-patterns`、`clean-minified`、`clean-http-client`、`benign-evolve` ×2 | clean / low / 最多 suspicious |
| 安装脚本 | `evil-postinstall-curl`、`evil-postinstall-b64` | critical |
| 窃密 | `evil-env-exfil`、`evil-typosquat-metadata` | high–critical |
| 混淆 | `evil-obfuscated-b64`、`evil-hex-escape`、`evil-charcode`、`evil-array-reverse` | critical |
| 远程执行 | `evil-remote-eval` | critical |
| 反分析/持久化 | `evil-sandbox-detect`、`evil-persistence` | high–critical |
| 归档结构 | `evil-archive-structure` | critical |
| 差分对 | `diffpkg-1.0.0` → `1.0.1` | clean → critical |

当前实测:

```
clean-string-utils   clean      0
clean-with-build     suspicious 43.5   (有 postinstall,但只写包内文件)
clean-tricky-patterns low       19.3
clean-minified       clean      0
clean-http-client    low        27.0
evil-postinstall-curl critical  76.0   (2×critical 规则)
evil-charcode        critical   87.4
evil-obfuscated-b64  critical   99.1
evil-remote-eval     critical   85.5
evil-sandbox-detect  critical   91.4
```

### 误报标定:真实流行包

用 `npm pack` 下载真实包验证(未入库,仅本地校验):

| 包 | 结果 |
|---|---|
| lodash 4.18.1 | clean |
| chalk 6.0.1 | clean |
| debug 4.4.3 | clean |
| semver 7.8.6 | clean |
| uuid 14.0.3 | clean |
| ms 2.1.3 | clean |

为此修掉的一类典型误报(每个都留了回归用例):

- 压缩代码里的局部变量 `ws(x,y)` 被当成 `ws` 网络库 → 未绑定的标识符不再当模块路径
- `Function('return this')` 全局 shim → 识别并放行
- `Object.keys(process.env)`(debug 读 `DEBUG` 前缀)→ 只拿到键名,不算转储
- lodash 的 `'À': 'A'` 字母表 / unicode 正则表 → 解码后不是代码就不算载荷
- semver 的空白字符数组 → 不可打印占比高,不算混淆
- README 里的 `curl ... | sh` 示例 → 文档类文件不参与规则
- CLI 的 `--help` 里 `process.exit` → 只有条件在探测环境时才算规避
- 模板引擎式 `Function('obj', 'return obj.' + src)` → 参数含运行期拼接时不单独报

---

## 输出格式

- **人类可读**(默认):结论、分类得分、命中的高危链、逐条 finding(规则、位置、证据、解码来源)
- **`--json`**:完整结构化结果,便于做基线与后续比对
- **`--sarif`**:SARIF 2.1.0,GitHub code scanning 可直接消费

---

## 代码结构

```
src/
  index.ts          CLI
  scanner.ts        编排:加载 → 归档检查 → 逐文件规则 → 解码二次扫描 → 评分
  tar.ts            内存 tar 解析(gzip / ustar / pax / GNU 长名)
  ast.ts            acorn 解析 + 纯静态常量折叠(不执行)
  analyze/js.ts     JS 规则引擎(含污点传播、作用域内组合关联)
  analyze/install.ts 生命周期脚本
  analyze/archive.ts 归档结构与元数据
  deobfuscate.ts    base64/hex/unicode/charCode/数组/反转 还原
  rules.ts          规则目录与权重
  findings.ts       finding 构造、指纹、去重
  score.ts          评分与结论
  diff.ts           版本差分
  report.ts         人类可读 / JSON / SARIF
scripts/build-samples.ts  样本包生成器
test/analyzer.test.ts     38 个端到端测试
```

---

## 已知局限

- **只做单文件/单包内分析**。跨包的数据流(依赖 A 读凭据、依赖 B 外发)需要把所有依赖一起喂进来,目前按文件关联,不做跨包图分析。
- **不做完整的数据流/别名分析**。污点传播覆盖"网络回调 → 赋值 → eval"这类常见链,但遇到字符串加工、对象字段传递仍可能漏。
- **混淆还原限于简单手法**。数组轮转表、控制流平坦化、自定义编码器(`rot13` 变体、异或表)只提示不还原。
- **不联网校验**。没有 registry 元数据、发布时间、维护者变更等信号——这些是判断投毒的重要补充,适合作为下一层(见下)。
- **权重是启发式**。样本回归能挡住明显的误报,但真实环境的阈值仍应按团队容忍度调整(`--fail-on`)。

## 可以接的下一步

1. registry 元数据:维护者变更、新发布的补丁版本、下载量骤降、与 tarball 哈希不符
2. 基线缓存:CI 里对每个已审计过的版本存 `--json` 结果,下次只跑差分
3. 跨包分析:把 lockfile 展开成完整依赖树一起扫,做跨包污点
4. 规则可配置:允许项目覆盖权重与开关,支持本地白名单
