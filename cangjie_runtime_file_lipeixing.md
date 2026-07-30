# Cangjie Runtime 文件系统漏洞确认报告

## 1. 报告范围

本报告对 `cangjie_runtime` 中 `CJ_FS_OpenFile` 符号链接跟随漏洞进行验证与双评级。

## 2. 基线与验证方式

| 项目 | 值 |
| --- | --- |
| 目标仓库 | `cangjie_runtime` |
| 目标版本 tag | `v1.2.0-beta.03` |
| 目标版本 commit | `7bd93c5f90552bc95b1cd9d13d34971d211c00c3` |
| 已验证 SDK 范围 | `Cangjie Compiler 1.0.5 cjnative` |
| 平台 | Linux x86_64 (WSL) |
| 报告日期 | 2026-07-30 |

## 3. 漏洞概述

### 3.1 基本信息

| 字段 | 内容 |
| --- | --- |
| 编号 | CJ-002 |
| CWE | CWE-367 (TOCTOU) / CWE-59 (Link Following) |
| 文件 | `stdlib/libs/std/fs/native/file_system_unix.c` |
| 漏洞行 | 710-750 |
| 类型 | 普通安全漏洞 |
| 细类 | 符号链接跟随 + TOCTOU 竞争 |

### 3.2 漏洞代码（目标 commit `7bd93c5f`，逐行验证）

路径：`stdlib/libs/std/fs/native/file_system_unix.c`

```c
// line 700-757
extern FsInfo* CJ_FS_OpenFile(const char* path, int32_t openMode)
{
    FsInfo* result = GetDefaultFsResult();
    char realPath[PATH_MAX + 1] = {0x00};
    const char* filePath = realPath;

    // line 710: realpath 解析路径
    if (realpath(path, realPath) == NULL) {
        if (errno != ENOENT) {           // line 719: 非 ENOENT 错误，返回
            result->fd = -1;
            result->msg = CJ_FS_ErrmesGet(errno);
            return result;
        }
        filePath = path;                 // line 725: ★ ENOENT 回退到原始 path（可能含符号链接）
    }

    // line 728-743: 构造 open 标志
    switch (openMode) {
        case CJ_WRONLY:
            access = O_WRONLY | O_CREAT | O_TRUNC;   // line 734: 无 O_NOFOLLOW
            break;
        // ...
    }

    // line 750: open 调用——无 O_NOFOLLOW，跟随符号链接
    int32_t fd = open(filePath, (int)(access), DEFFILEMODE);

    result->fd = (intptr_t)fd;
    return result;
}
```

### 3.3 漏洞点

1. **`realpath()` ENOENT 回退（line 725）**：当 `realpath()` 返回 NULL 且 `errno == ENOENT`（目标文件不存在）时，`filePath` 回退为原始 `path`。如果 `path` 是符号链接，此回退保留了符号链接路径。

2. **`open()` 无 `O_NOFOLLOW`（line 734, 750）**：所有写入模式（`CJ_WRONLY`、`CJ_APPEND`、`CJ_RDWT`）的 `open()` 调用均未设置 `O_NOFOLLOW` 标志，因此会跟随符号链接操作目标文件。

### 3.4 两条利用路径

**路径 A（预置符号链接，无需竞态）：**

攻击者预先在目标路径放置符号链接，指向不存在的文件。应用打开该路径时，`realpath()` 解析符号链接后返回 ENOENT（目标不存在），代码回退到原始 `path`（符号链接），`open()` 跟随符号链接在目标位置创建/截断文件。

```
攻击者创建 symlink: /tmp/uploads/log.txt → /etc/cron.d/payload（目标不存在）
→ 应用调用 File("/tmp/uploads/log.txt", Write) → CJ_FS_OpenFile
→ realpath() 解析 symlink → /etc/cron.d/payload 不存在 → NULL (ENOENT)
→ filePath = "/tmp/uploads/log.txt"（原始 symlink 路径）
→ open(filePath, O_CREAT|O_TRUNC) → 跟随 symlink → 创建 /etc/cron.d/payload
→ 应用写入数据 → 数据进入 /etc/cron.d/payload
```

**关键：此路径不需要竞态。** 攻击者只需预先放置符号链接，然后等待应用打开它。攻击复杂度为低（AC=L）。

**路径 B（TOCTOU 竞态，如 CJ-002 原始描述）：**

```
realpath(path) → NULL (ENOENT，文件不存在且无符号链接)
→ 攻击者在窗口内创建 symlink: path → victim file
→ open(path, O_CREAT|O_TRUNC) → 跟随 symlink → 截断 victim file
```

此路径需要精确计时，竞态窗口极短（`realpath()` 返回到 `open()` 调用之间），攻击复杂度为高（AC=H）。

### 3.5 PoC 评估

原始 PoC 为 Python 模拟，存在以下问题：

1. **非 Cangjie 程序**：Python 模拟，未调用实际的 `CJ_FS_OpenFile` 函数
2. **测试的是不同的 TOCTOU**：PoC 模拟的是 `exists() → open()` 竞态（SEC-001），而非 `realpath() → open()` 竞态（CJ-002）
3. **人工扩大窗口**：PoC 中 `time.sleep(0.01)` 人为扩大竞态窗口，不代表真实代码中的窗口大小
4. **未覆盖路径 A**：PoC 只测试竞态路径（路径 B），未测试更简单的预置符号链接路径（路径 A）

**结论：原始 PoC 不构成对 CJ-002 的有效验证。** 漏洞代码本身在源码中已确认存在，但 PoC 未准确测试目标函数的特定漏洞路径。

## 4. 确认意见分析

### 4.1 确认意见 1："要构造特定服务可以传入 path"

**合理，接受。**

`std.fs` 是基础库，漏洞需要应用满足以下条件才能触发：
- 应用接受用户可控的文件路径
- 应用使用 `File(path, OpenMode.Write)` 创建文件
- 攻击者对文件所在目录有写权限（可创建符号链接）

库提供的是有缺陷的底层实现（`realpath()` 回退 + 无 `O_NOFOLLOW`），实际安全影响需要应用代码桥接。

### 4.2 确认意见 2："竞态窗口需要特定时机触发，难以利用"

**部分合理，部分反驳。**

**合理部分**：确认意见正确指出了 TOCTOU 竞态（路径 B）的困难性。`realpath()` 返回到 `open()` 调用之间的窗口极短（纳秒级），攻击者需要精确计时，且文件必须在 `realpath()` 调用时不存在。这些条件确实难以满足。

**反驳部分**：确认意见只考虑了竞态路径（路径 B），忽略了更简单的非竞态路径（路径 A）。路径 A 不需要竞态——攻击者只需预先放置符号链接指向不存在的目标，`realpath()` 会返回 ENOENT，代码回退到原始路径（符号链接），`open()` 跟随符号链接在目标位置创建文件。

路径 A 的条件：
- 攻击者有目标目录的写权限（可创建符号链接）→ 本地访问
- 进程有目标位置的写权限（可创建/截断文件）→ 取决于进程权限
- 应用使用攻击者可控的路径 → 特定部署条件

这些是部署条件（AT=P），但不需要竞态计时。攻击复杂度为低（AC=L）。

**结论**：确认意见 2 对竞态路径成立，但对漏洞整体不成立——漏洞有更简单的非竞态利用路径。

## 5. CVSS 双评级

### 5.1 评分依据

基于路径 A（更简单的利用路径）和基础库条件综合评定：

| 指标 | 值 | 依据 |
| --- | --- | --- |
| AV | L | 需要本地文件系统访问以创建符号链接 |
| AC | L | 路径 A 无需竞态——预置符号链接即可；条件（本地访问 + 进程权限 + 应用使用可控路径）在多用户/共享目录场景下常见 |
| AT (4.0) | P | 基础库——需特定部署条件：应用接受可控路径 + 攻击者有目录写权限 + 进程有目标写权限 |
| PR | L | 需要目标目录的写权限 |
| UI | N | 无用户交互 |
| S | U | 库的漏洞影响使用它的应用；文件系统权限是 OS 的责任 |
| C | L | 读模式下可通过符号链接读取目标文件，但取决于进程权限和目标文件可读性 |
| I | L | 写模式下可通过符号链接创建/截断目标文件，但取决于进程权限和目标目录可写性 |
| A | N | 无直接可用性影响 |

> AC=L 的理由：漏洞有两条利用路径，路径 A（预置符号链接）不需要竞态，攻击复杂度为低。路径 B（TOCTOU 竞态）复杂度为高，但攻击者会优先选择更简单的路径 A。AC 取较易路径。
>
> C=L/I=L 的理由：`std.fs` 是基础库，库的固有贡献是提供了 `realpath()` ENOENT 回退 + 无 `O_NOFOLLOW` 的缺陷实现。实际的信息泄露/完整性影响取决于进程权限和目标文件——如果进程非特权，目标只能是进程可写的目录内的文件；如果进程特权运行，影响可升级为高。库的固有贡献按低评估。

### 5.2 CVSS 3.1 评分

```
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N
分数：4.4
等级：Medium
```

计算过程：
- Exploitability = 8.22 x 0.55 x 0.77 x 0.62 x 0.85 = 1.835
- ISCBase = 1 - (1-0.22)(1-0.22)(1-0) = 0.3916
- Impact(S:U) = 6.42 x 0.3916 = 2.514
- BaseScore = Roundup(2.514 + 1.835) = Roundup(4.349) = **4.4**

### 5.3 CVSS 4.0 评分

```
CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N
分数：~4.0
等级：Medium
```

### 5.4 评分汇总

| 体系 | 向量 | 分数 | 等级 |
|---|---|---:|---|
| CVSS 3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` | **4.4** | **Medium** |
| CVSS 4.0 | `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` | **~4.0** | **Medium** |

### 5.5 与原始评分对比

| | 原始评估 | 本报告评估 | 差异原因 |
|---|---:|---:|---|
| CVSS 3.1 | 7.7 High | **4.4 Medium** | AV:N→L（需本地访问创建 symlink）；确认意见 1（基础库）→S:U+C:L+I:L；确认意见 2 部分反驳（AC=L 而非 H，因路径 A 无需竞态） |

## 6. 最终判定

| 项目 | 结论 |
|---|---|
| 漏洞是否成立 | **成立** — `realpath()` ENOENT 回退 + 无 `O_NOFOLLOW` 的代码在源码中已确认 |
| 最终定级 | **Medium** |
| CVSS 3.1 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` = **4.4 Medium** |
| CVSS 4.0 | `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` = **~4.0 Medium** |
| 确认意见 1（基础库） | **接受** — `std.fs` 是基础库，需特定应用代码桥接 |
| 确认意见 2（竞态困难） | **部分接受** — TOCTOU 竞态（路径 B）确实困难；但漏洞有更简单的非竞态利用路径（路径 A），AC 取较易路径为 L |
| PoC 有效性 | **无效** — Python 模拟，非 Cangjie 程序；测试的是 SEC-001 的 TOCTOU 而非 CJ-002；人工扩大窗口 |
| 修复建议 | `open()` 添加 `O_NOFOLLOW`；对创建操作使用 `O_CREAT | O_EXCL | O_NOFOLLOW` 原子创建；`realpath()` ENOENT 回退时使用 `O_NOFOLLOW` 打开原始路径 |
