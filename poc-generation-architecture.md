# GaussDB 安全测试 POC 生成架构设计

> **状态**：架构设计（不含实现细节）
> **目标读者**：Coding Agent / 工程实现者
> **版本**：1.0

---

## 一、问题背景

### 1.1 系统描述

GaussDB 自动化安全测试工具，通过 LLM 从安全攻击面分析结果生成 SQL POC（Proof of Concept），在靶场环境执行 POC 验证安全漏洞。

现有工作流：
1. 上游工具产出安全攻击面分析结果
2. Python 工作流通过非交互方式（`claude -p`）注入 prompt 和攻击面分析结果
3. LLM 一次性输出整个 POC（多步 SQL 测试序列）
4. Python 工作流提取 SQL 序列
5. GaussDB 执行器执行 SQL 序列
6. 验证是否构成安全漏洞

### 1.2 当前设计的核心缺陷

**缺陷一：跨 Session 变量绑定不可靠**

POC 跨多个 DB Session（S1=initial_user, S2=sysadmin, S3=normal_user），需要变量传递（如 S1 查询临时表 schema 名，S2 在 DROP 语句中使用该 schema 名）。当前设计要求 LLM 在输出中用 `{{var_name}}` 声明占位符，并在注释中声明 `register: var1, var2`。

问题在于：一个 Step 可能包含多条 SELECT，而 `register:` 只列变量名，不声明从哪个 SELECT 的哪行哪列提取。Runtime 无法可靠地将 SELECT 结果映射到变量，导致变量绑定经常出错。

**缺陷二：一次性生成无法适配运行时数据**

LLM 在生成整个 POC 时，尚未执行任何 SQL，不知道实际的 schema 名、表名、执行结果。占位符 `{{xxx}}` 的值是 LLM 猜测的结构，而非真实运行时数据。重试也无法解决——LLM 重试时仍然没有运行时信息。

### 1.3 业界对比

- **Airflow XCom** 使用的 `xcom_pull(task_ids='foo')['key'][0]` 模式与本设计的变量提取路径类似，但现代编排系统（Dagster、Temporal、LangGraph）已转向语言原生绑定（函数参数、future、共享 state），不再使用显式提取路径。
- **DBT** 的 `ref()` 返回 Relation 对象而非提取值——从设计上绕开了提取路径问题。
- **2026 ACL 论文**（SQL-TRAIL、MTSQL-R1、ReEx-SQL）一致表明：多轮生成在 Text-to-SQL 任务上显著优于单次生成（+5% 准确率，51.9% 延迟降低）。
- **生产系统**（Vanna 2.0、FuzzySQL、OpenChatBI、SQL Query Engine）全部使用生成-执行-反馈循环，无一使用一次性生成。

---

## 二、目标架构

### 2.1 架构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                    Python 工作流编排器                           │
│                                                                 │
│  ┌──────────┐     ┌───────────────┐     ┌────────────────┐      │
│  │ 上游攻击 │────▶│ Plan 生成     │────▶│ 逐步执行循环   │      │
│  │ 面分析   │     │ (1次LLM调用)  │     │ (N次LLM调用)   │      │
│  └──────────┘     └───────────────┘     └───────┬────────┘      │
│                                                  │               │
│                          ┌───────────────────────┘               │
│                          ▼                                       │
│  ┌──────────┐  ┌──────────────┐  ┌─────────────┐  ┌────────┐  │
│  │ Prompt   │─▶│ LLM 调用     │─▶│ SQL 提取    │─▶│ 语法   │  │
│  │ Builder  │  │ (claude -p)  │  │ & 解析      │  │ 校验   │  │
│  └──────────┘  └──────────────┘  └─────────────┘  └───┬────┘  │
│                                                           │       │
│                      ┌────────────────────────────────────┘       │
│                      ▼                                           │
│  ┌──────────┐  ┌──────────────┐  ┌─────────────┐  ┌────────┐    │
│  │ 错误     │◀─│ GaussDB      │◀─│ Allowlist  │◀─│ Session│    │
│  │ 分类器   │  │ 执行器       │  │ & Timeout  │  │ Manager│    │
│  └────┬─────┘  └──────────────┘  └─────────────┘  └────────┘    │
│       │                                                          │
│       ▼                                                          │
│  ┌──────────┐     ┌──────────────┐     ┌──────────────────┐      │
│  │ 重试     │────▶│ 审计日志     │────▶│ Append-only     │      │
│  │ 控制器   │     │              │     │ JSONL File       │      │
│  └──────────┘     └──────────────┘     └──────────────────┘      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 核心原则

| 原则 | 说明 | 设计理由 |
|---|---|---|
| **LLM 零执行面** | LLM 只输出 SQL 文本，Python 执行所有 SQL | 安全边界在架构层，不在 prompt 层。LLM 生成的是攻击 SQL，不能有直接执行权限 |
| **逐步生成，非一次性** | 每步一次 `claude -p` 调用，看到上一步真实结果后再生成下一步 | LLM 无法在执行前可靠声明提取路径。逐步生成让 LLM 基于真实数据而非猜测 |
| **全新 prompt，不用 `--resume`** | 每次 `claude -p` 调用是独立 session，Python 在 prompt 中注入前置结果 | `--resume` 会累积上下文漂移（失败重试的噪音渗入后续步骤）。全新 prompt 让 LLM 输入完全可检视、可重现 |
| **Python 是唯一记忆载体** | 变量值由 Python 从执行结果中提取，以文本形式注入下一步 prompt | LLM 不需要 session 记忆——prompt 文本就是它的全部输入 |
| **Plan 是可审计产物** | LLM 先生成计划（不含 SQL），再逐步生成 SQL | Plan 可在执行前人工审查；给 LLM 全局视野，避免后续步骤忘记整体目标 |
| **审计日志独立于 LLM** | 日志由 Python 写入 append-only 文件，LLM 碰不到 | 安全工具的审计轨迹是核心交付物。同进程的 hook 日志可被篡改 |

---

## 三、两阶段流程

### 3.1 阶段一：Plan 生成

**输入**：上游攻击面分析结果

**处理**：一次 `claude -p` 调用，LLM 根据攻击面分析生成分步 POC 计划。Plan 包含每步的描述、Session 角色、期望发现什么值、允许的语句类型、依赖关系。**不包含 SQL。**

**输出**：结构化 POC Plan

**设计理由**：
- Plan 是可审计产物——安全团队可在执行前审查
- Plan 给 LLM 全局视野——避免 step 5 忘记 step 1 的目标
- Plan 可缓存——同一 Plan 可在不同环境重复执行
- Plan 声明的 `expected_output` 让 Python 知道从执行结果中提取什么值

### 3.2 阶段二：逐步执行

**输入**：POC Plan + GaussDB 环境

**处理**：对 Plan 中每个 Step：
1. Python 构造 prompt（Plan + 前置步骤真实结果摘要）
2. `claude -p` 调用（全新 session，无 `--resume`）→ LLM 输出该步 SQL
3. Python 提取 SQL
4. sqlglot 语法预校验
5. Python 执行 SQL（allowlist + timeout + row limit）
6. Python 分类错误（RETRY / ABORT / SURFACE）
7. 成功则 early-accept（冻结，不再让 LLM "改进"）
8. 失败则重试（最多 3 次，把错误喂回 LLM）
9. 记录审计日志

**输出**：每步执行结果 + 安全发现 + 审计日志

### 3.3 变量传递机制

**核心机制**：Python 从 Step N 的执行结果中提取值，以文本形式注入 Step N+1 的 prompt。LLM 不需要 session 记忆——prompt 文本就是它的全部输入。

```
Step 1 执行结果
    │
    ▼
Python 按 Plan 的 expected_output 提取值
    │
    ▼
results[s1].extracted_values = {temp_schema_name: "pg_temp_3"}
    │
    ▼
格式化为文本："前置步骤发现: temp_schema_name = pg_temp_3"
    │
    ▼
拼入 Step 2 的 prompt
    │
    ▼
claude -p（全新调用）→ LLM 从 prompt 文本读到值
    │
    ▼
LLM 输出: SELECT * FROM pg_temp_3.secret_temp_data;
```

### 3.4 Prompt 膨胀控制

**问题**：随着步数增加，前置结果注入会让 prompt 膨胀吗？

**回答**：不会显著膨胀。三层控制：

1. **只注入直接依赖**：prompt 只包含 `depends_on` 声明的步骤结果，不是所有历史
2. **只注入提取值**：注入标量变量值（schema 名、表名——几十字符），不注入完整结果集
3. **滚动摘要**：维护累积摘要，每步追加固定一行（~50-100字符），线性增长

| 步数 | 摘要大小 | prompt 总大小 |
|---|---|---|
| Step 2 | ~100字符 | ~700 tokens |
| Step 5 | ~400字符 | ~1000 tokens |
| Step 11 | ~1000字符 | ~1600 tokens |

即使 50 步也只有 ~6000 tokens，远低于 Claude 的 200K context。

**对比 `--resume`**：`--resume` 累积完整对话历史（prompt + SQL + 结果 + 推理 + 重试噪音），Step 11 可能达 50000+ tokens 且不可控。

---

## 四、组件职责定义

### 4.1 POC Plan Loader

**职责**：解析上游攻击面分析结果，驱动 LLM 生成 POC Plan，解析 Plan 为结构化数据。

**输入**：上游攻击面分析文本

**输出**：POC Plan（步骤列表，每步含 id、session、description、intent、expected_output、allowed_statements、depends_on）

**关键约束**：
- Plan 不含 SQL——只有步骤描述和意图
- 每步声明 `expected_output`：该步需要发现什么值、从哪个位置提取（`last_select.rows[0].column_name` 形式）
- 每步声明 `allowed_statements`：允许的 SQL 语句类型
- 每步声明 `depends_on`：依赖哪些前置步骤

### 4.2 Prompt Builder

**职责**：为每步 LLM 调用构造完整 prompt。

**输入**：POC Plan、当前步骤、前置步骤结果摘要

**输出**：完整 prompt 字符串

**关键约束**：
- 系统 prompt 静态可缓存（角色、约束、输出格式要求）
- 前置结果摘要只包含直接依赖步骤的提取值（滚动摘要）
- 重试 prompt 包含失败 SQL + 错误信息 + 错误类型
- LLM 输出格式要求：纯 SQL，不包裹 JSON/markdown

### 4.3 LLM Caller

**职责**：调用 `claude -p` 执行 LLM 推理。

**输入**：prompt 字符串

**输出**：LLM 输出文本 + 元数据（token 用量、成本、session_id）

**关键约束**：
- 每次调用是全新 session，不用 `--resume`
- 使用 `--output-format json` 获取结构化输出
- 设置 timeout（180s）
- 记录每次调用的 token 用量和成本

### 4.4 SQL Extractor & Validator

**职责**：从 LLM 输出中提取 SQL，并进行语法预校验。

**输入**：LLM 输出文本

**输出**：提取的 SQL 字符串 / 语法错误描述

**关键约束**：
- 去除 markdown 代码围栏（如果 LLM 不听话加了）
- 用 sqlglot 以 PostgreSQL 方言解析每条语句
- 语法错误返回错误描述，不放行到执行器

### 4.5 GaussDB Executor

**职责**：在指定 Session 上执行 SQL，返回结构化执行结果。

**输入**：SQL 字符串、Session 角色、允许的语句类型

**输出**：执行结果（成功/失败、列名、行数据、行数、首行、错误码、错误消息、耗时）

**关键约束**：
- **Allowlist 检查**：每条 SQL 的语句类型必须在 Plan 声明的 `allowed_statements` 内
- **Statement Timeout**：30s 超时，防止 DoS
- **Row Limit**：最多 1000 行，防止大结果集
- **Session 管理**：每个 Session 角色（initial_user/sysadmin/normal_user）独立连接
- **执行失败时 Rollback**：保持 session 干净

### 4.6 Error Classifier

**职责**：将 GaussDB 错误码分类为恢复策略。

**输入**：GaussDB 错误码（SQLSTATE）、错误消息

**输出**：错误分类（RETRY / ABORT / SURFACE）+ 描述

**分类定义**：

| 分类 | 含义 | 示例错误码 | 处理 |
|---|---|---|---|
| **RETRY** | 可重试：语法错误、对象不存在、序列化冲突 | 42601, 42704, 40001, 40P01 | 喂回 LLM 重新生成 |
| **ABORT** | 不可恢复：连接断开、内部错误 | 08001, 57P03, XX000 | 停止重试，跳过依赖此步的后续 |
| **SURFACE** | 安全发现：权限拒绝——这正是漏洞证据 | 42501 | 记录为发现，不算失败，继续下一步 |

**关键约束**：
- `42501`（insufficient privilege）是 SURFACE 而非 RETRY——权限拒绝是安全测试的核心发现
- 未知错误码默认 RETRY 但标记待人工分类
- GaussDB 特有错误码需单独映射

### 4.7 Retry Controller

**职责**：控制每步的重试行为。

**关键约束**：
- **Max Retries**：每步最多 3 次重试（EFRA 论文：1 轮通常足够，90.7% 准确率）
- **Early-Accept**：第一个成功的 SQL 冻结，不让 LLM 再"改进"（防止 DIN-SQL/MAC-SQL 回归——LLM 把对的 SQL 改错）
- **Best-Result Tracking**：如果重试都失败，保留最佳部分结果
- **ABORT 不重试**：不可恢复错误立即停止
- **SURFACE 不重试**：安全发现不重试，记录后继续

### 4.8 Audit Logger

**职责**：记录完整审计轨迹。

**输出格式**：JSONL（每行一条 JSON），append-only

**事件类型**：

| 事件 | 记录内容 |
|---|---|
| `plan` | POC 名称、漏洞描述、步骤数 |
| `attempt` | step_id、attempt 序号、完整 prompt、SQL、执行结果、错误信息、token 用量、成本、耗时 |
| `finding` | step_id、SQL、错误码、发现描述（SURFACE 类错误的详细记录） |
| `poc_complete` | POC 名称、总步数、成功步数、发现数、总成本、总耗时 |

**关键约束**：
- Append-only，不可修改历史记录
- 每次 attempt 都记录（含失败重试），不是只记最终结果
- 完整 prompt 记录——可重现
- 日志由 Python 写入，LLM 碰不到

### 4.9 Variable Extractor

**职责**：从执行结果中按 Plan 声明的提取路径提取变量值。

**输入**：执行结果（ExecResult）、Plan 声明的 expected_output

**输出**：提取的变量值字典

**提取路径格式**：`last_select.rows[0].column_name`
- `last_select`：该步最后一条 SELECT 的结果集
- `rows[0]`：第一行
- `column_name`：按列名查找值

**关键约束**：
- 提取由 Python 做，不是 LLM 做——LLM 只在 Plan 中声明提取路径
- `last_select` 不需要数 SELECT 数——大部分步骤只有一条返回数据的 SELECT
- 0 行结果时返回 None，下一步 prompt 会说"未找到值"

---

## 五、数据流示例

以 `pg_temp schema 跨会话访问` 漏洞为例：

```
上游攻击面分析:
  "pg_temp schema 可能在跨会话场景下被其他用户访问"

阶段1 - Plan 生成 (1次 claude -p):
  LLM 输出 Plan:
    steps:
      - id: s1, session: initial_user
        description: 创建临时表，发现 pg_temp schema 名
        expected_output: [{name: temp_schema_name, extract: last_select.rows[0].nspname}]
        allowed_statements: [CREATE, INSERT, SELECT, DROP]
      - id: s2, session: sysadmin
        description: 跨会话 SELECT S1 临时表
        depends_on: [s1]
        allowed_statements: [SELECT]
      - id: s3, session: normal_user
        description: normal_user 跨会话 SELECT S1 临时表
        depends_on: [s1]
        allowed_statements: [SELECT]

阶段2 - 逐步执行:

  Step s1 (claude -p 调用1):
    prompt: "执行第 s1 步...前置结果: 无..."
    LLM 输出: CREATE LOCAL TEMP TABLE ...; SELECT nspname FROM pg_namespace WHERE ...;
    Python 执行 → 成功
    Python 提取: temp_schema_name = "pg_temp_3"
  
  Step s2 (claude -p 调用2, 全新session):
    prompt: "执行第 s2 步...前置发现: temp_schema_name = pg_temp_3..."
    LLM 看到 pg_temp_3 → 输出: SELECT * FROM pg_temp_3.secret_temp_data;
    Python 执行 → 成功 (1行)
    → 漏洞确认: sysadmin 可跨会话访问 S1 临时表
  
  Step s3 (claude -p 调用3, 全新session):
    prompt: "执行第 s3 步...前置发现: temp_schema_name = pg_temp_3..."
    LLM 输出: SELECT * FROM pg_temp_3.secret_temp_data;
    Python 执行 → 错误 42501 (permission denied)
    错误分类: SURFACE (安全发现)
    → 记录发现: normal_user 权限隔离正常
```

---

## 六、安全护栏

| 护栏 | 位置 | 作用 |
|---|---|---|
| **LLM 零执行面** | 架构级 | LLM 只输出文本，Python 执行所有 SQL。推理系统和执行系统不共享进程空间 |
| **语句类型 Allowlist** | GaussDB Executor | 每步只允许 Plan 声明的语句类型，超出范围拒绝执行 |
| **Statement Timeout** | GaussDB Session | 30s 超时，防止 DoS 和死循环查询 |
| **Row Count Limit** | GaussDB Executor | 最多 1000 行，防止大结果集炸 context |
| **sqlglot 语法校验** | 执行前 | 拦截 LLM 语法错误，不浪费 DB 执行 |
| **每步重试上限** | Retry Controller | 最多 3 次，防止 LLM 死循环 |
| **Early-Accept** | Retry Controller | 成功 SQL 冻结，防止 LLM 把对的改错 |
| **Best-Result Tracking** | Retry Controller | 保留最佳部分结果，防止重试劣化 |
| **SURFACE 分类** | Error Classifier | 权限错误记为发现而非失败，不无脑重试 |
| **审计日志独立** | Audit Logger | Append-only JSONL，LLM 碰不到的进程 |
| **全新 Prompt** | LLM Caller | 不用 `--resume`，避免 context drift 和不可检视的隐藏状态 |

---

## 七、与旧设计对比

| 维度 | 旧设计（一次性 + `{{}}`） | 新设计（Plan-then-Execute） |
|---|---|---|
| LLM 调用 | 1 次 | 1 次 Plan + N 次 SQL = N+1 次 |
| 变量绑定 | LLM 写 `{{xxx}}`，runtime 猜来源 | Python 从结果提取值，文本注入下一步 prompt |
| 跨 session 传递 | `{{}}` 文本替换，LLM 猜值 | Python 提取真实值，注入 prompt |
| 失败模式 | runtime 猜错变量来源 | 不会——Python 知道提取什么 |
| 审计 | 整个 POC 文本 | 每步 (prompt, SQL, result) 结构化 |
| 可重现 | 同 prompt 同输出（可能） | 完全可重现（每步 prompt 可重放） |
| 安全边界 | LLM 输出所有 SQL，runtime 执行 | Python 逐步 allowlist + timeout |
| 成本 | 1 次调用 | N+1 次调用（~$0.08-0.15/POC） |
| 延迟 | ~30s | 2-6 分钟（批量安全测试可接受） |
| Context 管理 | 一次性全部输出 | Python 控制，滚动摘要线性增长 |
| 业界对标 | 无（已过时模式） | OpenChatBI、SQL Query Engine、Vanna 2.0、FuzzySQL |

---

## 八、设计决策记录

### 8.1 为什么不用 `--resume`

| `--resume` | 全新 prompt |
|---|---|
| 持久化上下文漂移（step 3 烧了 3 次重试的混乱渗入 step 4） | 每步干净——只有 Python 精选的前置结果 |
| LLM 输入不可检视（session 是隐藏变量） | LLM 输入 = prompt 文本，完全可检视 |
| 无法重现（session 状态不透明） | 可重现（prompt 序列可重放） |
| `--resume` 缓存有已知 bug（20x 成本膨胀，v2.1.69-v2.1.116 未修） | 不受 `--resume` bug 影响 |
| 累积所有历史（含噪音） | Python 控制——可截断、压缩、省略 |

### 8.2 为什么不用单次 `claude -p` + skill/MCP 工具（Option C）

调研结论：技术上可行，但对安全测试工具是错误选择。

- **安全 Blast Radius**：LLM 生成攻击 SQL + 有直接 DB 执行权限 = 不可控。三篇 2026 安全论文（Data Agents Under Attack、Parallax、Synapsor Runner）一致要求 Cognitive-Executive Separation（推理系统和执行系统不共享进程空间）。
- **审计性**：单次 `claude -p` 的 trajectory 是混合事件流，不是结构化审计记录。Replit 2025 年 7 月事故：agent 有写权限删了 1200 个高管的线上记录。
- **`--max-turns` 不可靠**：已知 bug（subagent 不强制执行，设 10 实际跑 72）。无法实施每步重试上限。
- **Context 不可恢复**：非交互模式下单个工具输出超 context limit 会话直接不可恢复。

### 8.3 为什么 Plan-then-Execute 而非直接逐步生成

- **Plan 是可审计产物**：安全团队可在执行前审查步骤意图
- **Plan 给 LLM 全局视野**：避免 step 5 忘记 step 1 的目标
- **Plan 可缓存**：同一 Plan 可在不同环境重复执行
- **Plan 声明数据契约**：`expected_output` 让 Python 知道提取什么值

### 8.4 为什么 `last_select` 而非 `select[N]`

| `select[N]` | `last_select` |
|---|---|
| LLM 要数 SELECT 数——CTE、子查询、UNION 都会让计数歧义 | 不用数——大部分步骤只有一条返回数据的 SELECT |
| LLM 数错则变量绑错 | 不可能数错 |
| 语句重排则索引偏移 | 不受重排影响 |

### 8.5 为什么 SURFACE 不算失败

安全测试的目的是发现漏洞。`42501`（permission denied）不是"执行失败"——它是**安全发现**：证明权限隔离生效或揭示权限边界。SURFACE 类错误记录为发现，继续下一步，不重试。

---

## 九、实现约束

### 9.1 LLM 调用约束

- 工具：`claude -p`（Claude Code print mode）
- 输出格式：`--output-format json`（获取 `{result, session_id, total_cost_usd, usage}`）
- 模型：按项目配置（Sonnet/Opus）
- Timeout：180s per call
- 不使用 `--resume` / `--continue`
- 不使用 `--allowedTools`（LLM 无工具权限）

### 9.2 GaussDB 执行约束

- 方言：PostgreSQL 兼容（GaussDB 兼容 PostgreSQL）
- 连接：每个 Session 角色独立连接，长连接复用
- 驱动：psycopg2 或等价物
- 语法校验：sqlglot，`dialect='postgres'`，`error_level=IMMEDIATE`

### 9.3 输出格式约束

- LLM 输出纯 SQL 文本，不包裹 JSON（存储过程/匿名块有转义问题）
- Python 做兜底清洗（去除 markdown 围栏、截取 SQL 起始词后的内容）
- 审计日志 JSONL 格式，UTF-8 编码

### 9.4 成本约束

- 单个 POC（11 步 + teardown）：预计 ~$0.08-0.15
- 批量执行时可并行（不同 POC 之间无依赖）

---

## 十、验收标准

| 验收项 | 标准 |
|---|---|
| 变量绑定可靠性 | 跨 session 变量 100% 由 Python 提取注入，不依赖 LLM 声明 |
| 审计完整性 | 每步每次 attempt 的 (prompt, SQL, result, error) 都在 JSONL 日志中 |
| 可重现性 | 给定相同 Plan + 相同 DB 状态，可重放每步 prompt 并得到相同 SQL |
| 安全边界 | LLM 无直接 DB 执行权限；每步 SQL 受 allowlist 约束 |
| 错误处理 | RETRY 最多 3 次；ABORT 跳过依赖链；SURFACE 记录为发现 |
| 成本 | 单 POC 成本 < $0.20 |
| 延迟 | 11 步 POC 总延迟 < 10 分钟 |

---

## 附录 A：术语表

| 术语 | 定义 |
|---|---|
| POC | Proof of Concept，安全漏洞验证用例 |
| Plan | LLM 生成的分步 POC 计划，不含 SQL |
| Step | Plan 中的一个步骤，含描述、Session 角色、期望输出、允许语句 |
| Session | 数据库连接会话，按角色区分（initial_user/sysadmin/normal_user） |
| Expected Output | Plan 中声明的每步期望发现值及提取路径 |
| Allowlist | 每步允许的 SQL 语句类型列表 |
| Early-Accept | 第一个成功的 SQL 冻结，不再让 LLM 改进 |
| Best-Result Tracking | 重试都失败时保留最佳部分结果 |
| SURFACE | 错误分类之一——安全发现（如权限拒绝），不算失败 |
| Rolling Summary | 累积的前置步骤发现摘要，每步追加一行 |
