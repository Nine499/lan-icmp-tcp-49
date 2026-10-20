# lit4 技术文档

面向后来接手的 Agent：读完本文即可理解项目全貌、改动点与约束，无需通读源码猜意图。

---

## 1. 项目定位

`lit4` 是一个**零依赖**的局域网主机探测 CLI：

- **ICMP 子命令**：对整个网段做存活探测（ping 扫描），输出每台存活主机的往返耗时。
- **TCP 子命令**：对指定主机集合 × 端口集合做 connect 扫描，输出每个开放端口的连接耗时。
- **无需 root**：ICMP 走 Linux `SOCK_DGRAM + IPPROTO_ICMP`（ping socket），不碰 raw socket。
- 单一入口命令 `lit4`，由 `pyproject.toml` 的 `[project.scripts]` 注册。

设计目标：局域网（/24 量级）秒级出结果，输出可直接被管道/脚本消费（一行一条，无表头、无颜色）。

---

## 2. 仓库结构

```
lan-icmp-tcp-49/
├── pyproject.toml          # 项目元数据、入口点、构建后端（uv_build）
├── uv.lock                 # 锁定的空依赖集（项目本身无第三方依赖）
├── .python-version         # 3.14
├── README.md               # 面向用户的安装与用法
├── docs/TECHNICAL.md       # 本文档
└── src/lit4/
    ├── __init__.py         # __version__（时间版本号）
    ├── cli.py              # argparse 入口，仅做参数解析与调度
    └── scan.py             # 全部扫描逻辑（ICMP + TCP + 解析/打印）
```

**分层约定**：`cli.py` 只负责「解析参数 → 调 `scan.py`」，不含任何网络逻辑；所有算法、报文构造、并发控制都在 `scan.py`。改动扫描行为时只动 `scan.py`。

---

## 3. 运行环境与工具链硬约束

| 项 | 值 | 说明 |
|---|---|---|
| Python | `>=3.14`（开发机为 3.14.4） | `except (OSError, TimeoutError)` 中 `TimeoutError` 与 builtin `TimeoutError` 同义（3.11+ 起 `asyncio.TimeoutError` 已并入 builtin） |
| 包管理 | **只用 uv** | 禁止 pip/poetry/npm 等；未装直接报错不代装 |
| 构建后端 | `uv_build>=0.13.1,<0.14.0` | `src` 布局自动识别，无需额外配置 |
| 第三方依赖 | **无** | `dependencies = []`，改功能不要引库 |
| 平台 | WSL Ubuntu / Linux | ICMP ping socket 与 `net.ipv4.ping_group_range` 是 Linux 特性 |

### 安装与运行

```bash
# 开发态直接跑
uv run lit4 icmp 192.168.1.0/24
uv run lit4 tcp 192.168.1.0/24 80,443

# 全局安装（uv tool）
uv tool install /home/forty-wsl/github/lan-icmp-tcp-49
```

### 版本号

`__version__` 与 `pyproject.toml` 的 `version` 必须**保持一致**，格式为 `YYYYMMDD.HHMM.SSMS`（时间递增版本号，用 time-version-49 skill 生成）。发布新版本时两处同步改。

---

## 4. CLI 接口（cli.py）

```
lit4 --version
lit4 icmp <CIDR>...
lit4 tcp  <CIDR>... <PORTS> [--timeout 秒]
```

- `icmp`：`targets` 为 `nargs="+"`，可传多个 CIDR/IP。
- `tcp`：`items` 为 `nargs="+"`，**除最后一个参数外全部按 CIDR 解析，最后一个参数一定是端口表**。这是位置参数约定，不是 bug——`--timeout` 是唯一的 flag。
- `tcp --timeout` 默认 `0.5` 秒，是**单次** TCP connect 的超时，不是整个扫描的总超时。
- `cmd` 为 `required=True` 的 subparser，裸跑 `lit4` 会报错退出。

---

## 5. 核心算法（scan.py）

### 5.1 目标展开 `expand_targets(items) -> list[str]`

- 每个 item 交给 `ipaddress.ip_network(item, strict=False)`：`strict=False` 意味着 `192.168.1.5/24` 这种「主机位非零」写法会被规范化为整个 /24，不会报错。
- 只允许 IPv4；IPv6 直接 `SystemExit`，错误信息含原始输入。
- 用 `net.hosts()` 展开：**自动排除网络地址和广播地址**（`192.168.1.0` 与 `192.168.1.255` 不会被探测）。/24 → 254 个 IP。
- 多个 item 的结果直接 extend 拼接，**不去重**——重复传 CIDR 会重复探测（TCP 端结果按 dict 键去重，不影响输出正确性，只浪费流量）。

### 5.2 端口表解析 `parse_ports(spec) -> list[int]`

支持语法（逗号分隔，可混合）：

| 写法 | 含义 |
|---|---|
| `80` | 单端口 |
| `80,443` | 多端口 |
| `80-90` | 闭区间（含两端） |
| `20-25,80,443` | 混合 |

细节：
- `start > end` 时自动交换（`80-20` 等价于 `20-80`）。
- 结果过滤到 `1..65535`，用 `set` 去重后**升序排序**返回。
- 空段（如 `80,,443`）静默跳过；整个解析结果为空则 `SystemExit`。
- 不校验端口语义（如 0 端口被过滤掉，但 `int()` 解析非数字会抛未捕获 `ValueError`——已知可接受的粗糙点，输入来自用户自己）。

### 5.3 ICMP 存活扫描 `icmp_scan(targets, timeout=1.5, idle=0.15) -> int`

**为什么无需 root**：Linux 内核的 `IPPROTO_ICMP` DGRAM socket（ping socket）允许非特权用户发 ICMP echo。前提：

```
net.ipv4.ping_group_range  # 需包含当前 uid/gid，Ubuntu 默认包含
```

创建失败（`PermissionError`）→ stderr 打印提示并 `SystemExit(1)`，不静默降级。

**报文构造**（RFC 792）：

```
echo request: type=8 code=0 checksum id seq payload
echo reply:   type=0 code=0 ...
payload = b"lit4" * 8  # 32 字节，对齐经典 ping
ident   = os.getpid() & 0xFFFF
```

- `_icmp_checksum`：标准 16 位反码和（奇数长度补 `\x00`，两次折叠进 16 位，取反）。
- **注意**：Linux ping socket 会**改写内层 ICMP id**，所以接收端**不校验 id/seq**，只认 `data[0] == 0`（echo reply）且 `addr[0]` 在已发送集合中。这意味着同机其他进程的 ping 回包理论上可能被误收——局域网扫描场景可接受。

**发送策略**：
1. 先同步 `sock.sendto` 连发全部目标（socket 已设 non-blocking）。
2. 遇 `BlockingIOError`（发送缓冲满）的 IP 进 `pending` 列表。
3. `pending` 里的用 `loop.sock_sendto` 并发补发，整体 `wait_for(..., 0.2s)` 兜底，超时丢弃不拖慢扫描。`sent_at` 时间戳统一记为入队时刻（补发耗时不计入 RTT，误差 <200ms，局域网可忽略）。
4. `OSError`（如 ENETUNREACH）静默忽略——探测型工具，不可达即视为不存活。

**接收与结束条件**（关键：这是「快」的来源）：
- 单独 `asyncio.Task` 跑 `receiver()`，`loop.sock_recvfrom` 挂起等待。
- 收到新 host 的 reply 时记录 `found[ip] = RTT毫秒`，刷新 `last_recv`。
- 主循环每 20ms 检查：
  - 已等满 `timeout`（默认 1.5s）→ 结束；
  - **已有结果 且 距最后一次收包超过 `idle`（默认 0.15s）→ 提前结束**。
- 所以在正常局域网里，254 个 IP 的扫描往往 0.5s 内就退出，不会傻等满 1.5s。

**输出**：`_print_results` 按 IP **数值**升序（`ipaddress.ip_address` 转 int 排序，不是字符串排序），每行 `192.168.1.1 56ms`，毫秒取整（`:.0f`）。返回存活数。

### 5.4 TCP connect 扫描 `tcp_scan(targets, ports, timeout=0.5, concurrency=2048) -> int`

**模型**：对 `targets × ports` 的笛卡尔积，每个 `(host, port)` 做一次 `asyncio.open_connection`（完整三次握手），成功即端口开放。

```python
sem = asyncio.Semaphore(concurrency)   # 限制在途连接数，防 fd 耗尽
lock = asyncio.Lock()
up: dict[tuple[str, int], float] = {}  # (ip, port) -> 毫秒
```

- `probe(host, port)`：
  1. `async with sem` 拿信号量；
  2. `time.perf_counter()` 计时起点；
  3. `asyncio.wait_for(open_connection, timeout)` —— 超时/拒绝/网络错误（`OSError, TimeoutError`）直接 return，视为关闭；
  4. 成功则 `(perf_counter - t0) * 1000` 得毫秒，`writer.close()` + `wait_closed()`（`wait_closed` 的 `OSError` 忽略，避免对端已断开导致异常冒泡）；
  5. 拿 `lock` 写入 `up[(host, port)] = ms`。
- 主流程 `gather` 全部 probe（信号量在内部控并发），最后统一排序打印。

**输出格式**（与用户约定一致，重要）：

```
<ip>:<port> <ms>ms
```

例：

```
192.168.1.1:80 56ms
192.168.1.1:443 61ms
192.168.1.124:443 107ms
```

- 同一 IP 多个端口开放 → **多行**，每端口独立 RTT。
- 排序键：`(IP 数值, 端口号)` —— 先 IP 升序，同 IP 内端口升序。
- 返回值是**开放 (ip, port) 条数**，不是主机数。
- 历史行为（曾改为「一 IP 一行、记最快端口」）已废弃，勿回退。

---

## 6. 输出契约（给下游脚本/Agent）

- **stdout 只有结果行**，无表头、无进度条、无颜色；诊断信息（如 ICMP 权限错误）走 stderr。
- 每行字段以单空格分隔，`flush=True` 实时吐出，可安全管道给 `awk`/`head`。
- ICMP：`{ip} {ms}ms`（2 字段+单位后缀）。
- TCP：`{ip}:{port} {ms}ms`（2 字段+单位后缀，ip:port 合并为一列）。
- 解析示例：`awk '{print $1, $2}'` 在两种模式下都成立——第一列是目标（ICMP 为 ip，TCP 为 ip:port），第二列是延迟。

---

## 7. 已知限制与设计取舍

1. **仅 IPv4**：IPv6 直接退出。刻意不做双栈（ping socket 语义不同）。
2. **无端口服务识别**：只报开放与耗时，不读 banner、不识别协议。
3. **TCP 是 connect 扫描**：会走完整握手，目标侧有日志痕迹；被防火墙 DROP 的端口表现为等满 timeout。未实现 SYN 半开（需 raw socket / root，与「无需 root」目标冲突）。
4. **ICMP id 不校验**：见 5.3，Linux ping socket 改写 id 所致，换 raw socket 可解但破坏免 root。
5. **重复 CIDR 不去重**：`expand_targets` 行为，见 5.1。
6. **`parse_ports` 不捕获 `ValueError`**：传 `abc` 会 traceback 而非友好报错——用户自用工具，未过度防御。
7. **concurrency=2048**：/24 × 200 端口量级足够；若扫更大网段 + 高并发，注意 `ulimit -n`（`asyncio.open_connection` 每连接占一个 fd）。
8. **无测试套件**：项目无 `tests/`，改动后以真实网段手测为主（见下节）。

---

## 8. 验证方式（改完代码怎么测）

```bash
# 1. 语法/导入
uv run python -c "from lit4 import scan"

# 2. ICMP 对真实网段（需 ping_group_range 允许）
uv run lit4 icmp 192.168.1.0/24

# 3. TCP：验证「一 IP 多端口多行、ip:port 带延迟」
uv run lit4 tcp 192.168.1.1/24 80,443,53
# 期望输出形如：
# 192.168.1.1:80 56ms
# 192.168.1.1:443 58ms
# 192.168.1.124:443 107ms

# 4. 端口解析边界
uv run python -c "from lit4.scan import parse_ports; print(parse_ports('20-25,80,443'))"
# 期望 [20, 21, 22, 23, 24, 25, 80, 443]
```

---

## 9. 修改守则（给下一个 Agent）

1. 改动前读本文第 5、6 节——输出格式是与用户的显式契约，破坏它需要用户明示。
2. 保持零依赖；需要新能力先想标准库能否做到。
3. `cli.py` 保持薄；算法进 `scan.py`。
4. 遵守项目全局约束：Python 只用 uv；简体中文注释/文档；不写假设性需求与向后兼容代码；默认 85 分交付不过度打磨。
5. 版本号两处同步（`__init__.py` 与 `pyproject.toml`），格式 `YYYYMMDD.HHMM.SSMS`。
6. 提交用 git-commit-49 skill（只本地 commit，不 push）。

---

## 10. Git 历史锚点

```
9381372 feat: lit4 局域网 ICMP/TCP 快速扫描工具初始版本
5eea8ca feat: 扫描结果按 IP 升序并显示毫秒往返耗时
12474bb chore: 同步 uv.lock 中的包版本号
```

初始版本即确定「免 root ICMP + TCP connect」双模式；随后补了 IP 排序与毫秒耗时；再随后是锁文件同步。当前工作树在此基础上完成了「TCP 输出带端口号、每端口独立延迟」的契约变更（本文档同时落地）。
