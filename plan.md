# wireproxy-rs（从 0 重构）+ gotatun 替换 boringtun：重构计划

> 目标：将当前 `@wireproxy-rs/` 的 Rust 用户态 WireGuard 实现整体重构为 **gotatun 驱动的 userspace WireGuard + smoltcp 虚拟协议栈**，并学习/吸收 `@onetun/` 的实现思想（任务拆分、事件流、虚拟接口/端口管理、零配置用户态转发），解决现有性能瓶颈。
>
> 本文是“从零重构”的可执行工程计划：不依赖现有 `wireproxy-rs/src` 代码结构与实现，可完全推倒重来。

---

## 1. 背景与问题陈述

### 1.1 现状

- `wireproxy`（Go 版）功能：通过 WireGuard peer 连接远端网络，但**不创建系统 TUN**，对外暴露：
  - SOCKS5（TCP CONNECT）
  - HTTP proxy（CONNECT + 少量 GET 支持）
  - TCP Client/Server Tunnel（端口转发）
  - STDIO Tunnel
  - /metrics + /readyz（带 CheckAlive ping）
- 现有 Rust 版（`wireproxy-rs/`）采用 `boringtun + smoltcp` 的 in-process netstack 方案，但出现明显性能问题。

### 1.2 目标问题（Why gotatun）

- `gotatun` 是用户态 WireGuard 实现（boringtun 的 fork），在工程化上提供：
  - 完整 device 层：UDP 收发、握手/定时器、peer 管理、AllowedIPs 路由
  - 高性能 packet/缓冲池（`PacketBufPool`）、批处理与异步任务模型
  - trait 抽象：`IpSend/IpRecv` 可替代真实 TUN，适配“完全用户态”的虚拟链路
- 目标：用 gotatun 替换 boringtun，使 WG 侧吞吐/CPU/延迟更稳定，并降低我们自己维护 WG protocol 细节的成本。

---

## 2. 总体设计（吸收 onetun 思路）

### 2.1 核心理念（从 onetun 学到的）

- **任务拆分清晰**：WG 的 routine/consume/produce 与虚拟网络栈 poll loop 解耦；各模块以通道/事件通信。
- **虚拟接口（smoltcp）**：把 TCP/UDP/ICMP 的状态机放在进程内，避免系统网络配置、root、TUN。
- **面向流的应用层**：SOCKS/HTTP/Tunnel 依旧是 tokio TCP listener + per-conn task。
- **虚拟端口/连接映射**：对 UDP/多连接场景，用端口池/映射降低资源泄漏与冲突风险（onetun 的 UDP port pool 设计值得借鉴）。

### 2.2 推荐架构（gotatun::device + smoltcp + “内核任务”）

建议采用“单核 netstack + gotatun device 任务”的组合：

```
┌──────────────────────────┐
│  SOCKS5/HTTP/Tunnels      │  (tokio tasks, per-conn)
└─────────────┬────────────┘
              │  connect()/listen()/read()/write()
              ▼
┌──────────────────────────┐
│   Netstack Core Task      │  (single-threaded smoltcp poll)
│  - socket set             │
│  - port allocator         │
│  - DNS/ICMP helper         │
└───────┬───────────┬──────┘
        │outbound IP│inbound IP
        ▼           ▲
  mpsc::Sender      │  mpsc::Receiver
        │           │
┌───────▼───────────┴──────┐
│   IpLink (virtual TUN)     │
│  - implements IpRecv/IpSend│
│  - carries Packet<Ip>      │
└───────────┬───────────────┘
            │
            ▼
┌──────────────────────────┐
│ gotatun::device::Device   │
│ - handle_outgoing         │
│ - handle_incoming(v4/v6)  │
│ - handle_timers           │
│ - AllowedIPs routing      │
└─────────────┬────────────┘
              │ UDP
              ▼
        Internet/WG endpoint
```

关键点：

- WG 协议实现完全交由 gotatun device 层处理。
- 我们只负责“IP 包的生产/消费”：
  - smoltcp 产生 IP 包 -> 送进 gotatun -> 加密后 UDP 发出
  - UDP 收到加密包 -> gotatun 解密 -> 产生 IP 包 -> 喂给 smoltcp

### 2.3 替代方案对比（建议写进设计评审）

- **方案 A（推荐）**：`gotatun::device::Device` + 自定义 `IpSend/IpRecv`
  - 优点：WG 协议与 UDP IO 都交给 gotatun；我们只做 netstack 与业务；性能与可维护性最好。
  - 缺点：需要理解 gotatun device 的配置约束（例如必须先 set_private_key）。

- **方案 B（不推荐但可选）**：直接用 `gotatun::noise::Tunn` 自己写 UDP + timers
  - 优点：更像 onetun；能完全掌控任务模型。
  - 缺点：需要自己处理更多 WG packet parsing/rate limiter/cookie/handshake flush 等细节，容易回到“维护 WG 协议实现”的坑。

结论：wireproxy 的目标不是造 WG，而是提供 proxy/tunnel，因此优先方案 A。

---

## 3. gotatun 作为 wireproxy 的“用户态 WireGuard 引擎”集成方案

### 3.1 依赖方式

- 本地开发：
  - `gotatun = { path = "../gotatun/gotatun", default-features = false, features = ["device"] }`
- 生产/发布：
  - 推荐固定 git revision（或 fork 后发布到 crates.io），保证可复现。

### 3.2 gotatun 配置关键点

- gotatun device 的 `PeerState` 创建依赖 device private key。
  - 因此：**不要在 DeviceBuilder 阶段提前 `.with_peer(...)`**（否则可能触发 `expect("Private key must be set first")`）。
  - 正确流程：
    1) `DeviceBuilder::new().with_default_udp().with_ip_pair(ip_tx, ip_rx).with_listen_port(...) .build().await`
    2) `device.write(async |d| { d.set_private_key(...).await; d.clear_peers(); d.add_peers(peers); }).await?`

### 3.3 IpLink：用通道模拟 TUN（核心适配层）

实现一个 `IpLink`：

- `IpSend`：gotatun 解密后的 `Packet<Ip>` -> `mpsc::Sender<Packet<Ip>>` 发给 Netstack Core。
- `IpRecv`：Netstack Core 生成的 `Packet<Ip>` -> `mpsc::Receiver<Packet<Ip>>` 供 gotatun 读取。
- MTU：
  - 初期用常量 `MtuWatcher::new(mtu)`；后续可按配置/PMTU 做动态。

注意：

- `Packet<Ip>` 可以先用 `gotatun::packet::Packet::from_bytes(BytesMut)` 创建；
- 性能优化阶段再引入可复用 pool（见第 8 节）。

---

## 4. Netstack（smoltcp）从 0 设计

### 4.1 核心组件：Netstack Core 单任务

- 单线程/单任务拥有：
  - `smoltcp::iface::Interface`
  - `smoltcp::iface::SocketSet`
  - 一个实现 `smoltcp::phy::Device` 的虚拟网卡（队列 + MTU）
  - 连接/端口分配器
  - 对外 API（command channel）：connect/listen/udp_exchange/ping/read/write/close

为何单任务：

- smoltcp 本身适合单线程 poll。
- “一个 owner”避免大量锁与跨任务可变借用难题。

### 4.2 虚拟网卡（smoltcp::phy::Device）实现策略

- Rx：来自 gotatun 的 inbound IP 包队列（`VecDeque<Packet<Ip>>` 或 `VecDeque<Vec<u8>>`）
- Tx：smoltcp 生成的 outbound IP 包写入后，推到 gotatun outbound 队列（最终由 `IpRecv` 读走）

关键要求：

- TxToken.consume 必须能拿到一段 `&mut [u8]` 写入：
  - MVP：用 `Vec<u8>`/`BytesMut` 分配
  - 优化：使用 `PacketBufPool` 或自建 slab/pool

### 4.3 Netstack 对外抽象（给 Proxy/Tunnel 使用）

从 0 设计新的 API（建议）：

- `WgRuntime`（应用运行时）
  - `connect(SocketAddr) -> WgTcpStream`
  - `listen(port) -> WgTcpListener`
  - `udp_exchange(target, payload, timeout) -> Vec<u8>`（DNS 需要）
  - `ping(IpAddr, timeout)`（/readyz 需要）
  - `stats()`（/metrics 需要）

内部实现：

- `WgTcpStream` 不是直接 tokio socket，而是对 Netstack Core 的 command/notify 封装。
- 读写采用 backpressure：
  - read：若 `can_recv()` false -> 等待通知
  - write：若 `can_send()` false -> 等待通知

这部分可以借鉴 onetun 的“事件驱动 + poll loop”，但推荐使用**明确的 command channel**而不是全量广播事件（避免热路径广播开销）。

---

## 5. 业务功能重建（Proxy / Tunnels / Health）

### 5.1 SOCKS5

- 仅实现 TCP CONNECT（与 Go 版对齐）。
- 认证：支持 username/password（可选）。
- 数据转发：
  - `tokio::net::TcpStream <-> WgTcpStream` 双向 copy。

### 5.2 HTTP Proxy

- 支持 CONNECT（必须）
- 可选支持 GET（参考 wireproxy-rs 现有行为，或对齐 Go 版“目前只支持 CONNECT”）
- Basic auth（可选）

### 5.3 TCP Client Tunnel

- 本地 listen -> 目标 `Target` 通过 WG 连接 -> 转发。

### 5.4 TCP Server Tunnel

- 在 WG 网内 listen 一个端口（smoltcp listener）
- 收到连接后连接本地 `Target`（tokio TCP），进行双向转发。

### 5.5 STDIO Tunnel

- stdin/stdout <-> `WgTcpStream`

### 5.6 DNS

- 若 `[Interface].DNS` 为空：走系统 DNS（`tokio::net::lookup_host`）。
- 若配置了 DNS server：通过 `udp_exchange` 走 WG 内 DNS。
- 实现策略：并发 A/AAAA（与现有 wireproxy-rs 的 parallel query 思路一致）。

### 5.7 Health endpoints

- `/metrics`
  - 数据来源：gotatun device 的 `device.read(|d| d.peers().await)`
  - 输出格式：尽量保持 Go wireproxy / wg show 风格
- `/readyz`
  - 定时对 `CheckAlive` 的 IP 执行 ICMP ping（smoltcp icmp socket）
  - 超时/最近一次响应时间窗口与 Go 版对齐（interval + 2s）

---

## 6. 工程结构（建议的 crate/module layout）

从 0 重构时，建议把“协议/核心”与“CLI/二进制”分离：

- `crates/wireproxy-core/`
  - `wg/`：gotatun device wrapper + peer config
  - `netstack/`：smoltcp core + socket api
  - `proxy/`：socks5/http
  - `tunnel/`：tcp client/server/stdio
  - `dns/`：resolver
  - `health/`：readyz/metrics
  - `config/`：兼容 wireproxy.ini

- `crates/wireproxy-cli/`
  - clap 参数
  - 读取 config
  - 启动 runtime + routines

若暂时不想 workspace：也可以保持单 crate，但至少按模块目录拆分，避免 `src/*.rs` 平铺。

---

## 7. 分阶段实施计划（Milestones）

> 这是“可落地”的执行顺序；每个里程碑都应当能单独编译、运行并具备可观测性。

### M0：定义验收标准 & 性能基线

- 明确最小功能集合：SOCKS5 CONNECT、HTTP CONNECT、TCP Client/Server、STDIO、/metrics、/readyz、WGConfig 导入。
- 确定目标平台：Linux + macOS 优先（Windows 可后置）。
- 建立基线：
  - 用现有 wireproxy-rs/Go wireproxy 跑同一组场景（吞吐、CPU、延迟、内存）。
  - 输出 KPI：
    - 单连接吞吐（MB/s）
    - 100/1000 并发连接下 CPU 占用
    - 延迟 P50/P99

### M1：新工程骨架（Hello WG）

- 新建 `wireproxy-core`（或在现有 crate 下新建 `src/new/`），保证 main 可跑。
- 引入 gotatun 依赖（feature `device`）。
- 实现最小 `IpLink`（仅通道回显，不接 smoltcp），验证：
  - 能启动 gotatun device
  - 能 set_private_key
  - 能 add_peer（AllowedIPs + endpoint）
  - 能在 log 中看到握手/keepalive 行为

### M2：Netstack Core MVP（smoltcp 能跑起来）

- 实现虚拟 `smoltcp::phy::Device`（队列 Rx/Tx）。
- 建立 `NetstackCore` poll loop：
  - 接收 gotatun inbound IP -> push_rx
  - poll -> drain_tx -> 送到 gotatun outbound
- 实现最小 `connect()`：建立 smoltcp TCP socket 并完成握手。

### M3：WgTcpStream API（可读写）

- 实现 `WgTcpStream`：
  - `read()` / `write()` / `close()`
  - `tokio::select!` 与 netstack notify 协作
- 增加端口分配器（ephemeral port allocator），避免冲突。

### M4：SOCKS5 + TCP Client Tunnel

- SOCKS5 CONNECT：
  - 完成认证（可选）
  - `runtime.connect(target)`
  - 双向转发
- TCP Client Tunnel：listen -> connect -> proxy
- 加入基础 e2e 测试：本地起一个 echo server，通过 WG 通路访问。

### M5：HTTP CONNECT/GET + STDIO

- HTTP CONNECT：
  - parse request + auth + 建立 remote
- GET（可选）：如果需要对齐 wireproxy-rs 当前行为，则实现；否则明确不支持。
- STDIO tunnel：stdin/stdout 与 remote stream。

### M6：TCP Server Tunnel（WG 侧 listen）

- smoltcp listener + accept
- accept 后连接本地 target，proxy
- 增加 server-mode peer（Peer 无 endpoint）用例（如果要对齐 Go wireproxy）。

### M7：DNS + Health

- DNS：system / in-tunnel
- /readyz：ICMP ping（smoltcp icmp）
- /metrics：gotatun peer stats

### M8：性能优化迭代

重点优化路径：

- **减少内存分配**：
  - outbound IP 包：改用 `BytesMut` 预分配 + reuse
  - 尝试把 netstack 的 TxToken 直接写入可复用 buffer
- **批处理**：
  - gotatun `IpRecv::recv` 支持 batch iterator：
    - netstack 每次 poll 后可一次性吐出多个 packet
  - inbound 处理同理（一次 drain 多个）
- **背压与队列大小**：
  - `mpsc` capacity 调参，避免过大导致内存激增，也避免过小导致抖动
- **日志与 tracing**：
  - 热路径避免 trace/debug 造成性能下降（运行时可动态调级）

### M9：对齐行为与文档/发布

- 配置兼容性：WGConfig 导入、inline comment、key: value 等语法差异（按需）
- 兼容 Go wireproxy 行为差异清单（明确列出）
- CI：e2e + bench（可参考现有 `wireproxy-rs/.github/workflows`）

---

## 8. 性能验证与基准测试方案

### 8.1 Bench 场景建议

- 场景 A：单连接大流量（例如 1GiB）
  - 目标：吞吐接近 Go wireproxy 或优于旧 Rust
- 场景 B：多连接（100/1000）中小流量
  - 目标：CPU/延迟稳定，无明显锁竞争尖峰
- 场景 C：DNS 压测
  - 目标：并发解析无超时/无内存膨胀

### 8.2 工具

- macOS/Linux：
  - `cargo flamegraph`（或 `pprof`）
  - `tokio-console`（可选）
  - `hyperfine` 做命令级基准
- WireGuard 侧：
  - 对比 `wg show` 的 handshake/tx/rx 指标

---

## 9. 风险与应对

- gotatun device 配置时序（private key / peers）
  - 应对：封装 `WgEngine::from_config`，内部一次性 write 完成配置。
- smoltcp 与真实网络差异（例如 TCP 行为/窗口/重传）
  - 应对：明确这是 userspace netstack；必要时调优 socket buffer/timeout。
- UDP 支持（SOCKS5 UDP/UDP tunnel）复杂
  - 应对：先交付 TCP 与 DNS；UDP forwarding 作为后续 milestone（参考 onetun UDP port pool）。
- 高并发下的 channel/backpressure
  - 应对：在 M8 调整队列与批处理策略；必要时引入 lock-free ring buffer。

---

## 10. 最终验收清单（Definition of Done）

- 功能：SOCKS5 CONNECT、HTTP CONNECT、TCP Client/Server、STDIO、DNS、/metrics、/readyz
- 配置：兼容 Go wireproxy 主配置格式（含 WGConfig 导入）
- 性能：至少达到旧 Rust 实现的吞吐与 CPU（目标：明显优于旧 Rust）
- 稳定性：长时间运行无内存泄漏/队列爆炸
- 可观测：日志可定位握手、peer stats、readyz 失败原因

---

## 11. 需要你确认的少量问题（不阻塞执行，但会影响细节）

1) 目标平台优先级：Linux / macOS / Windows？
2) HTTP proxy 是否必须支持 GET，还是只要 CONNECT（对齐 Go）？
3) 是否要支持 Go wireproxy 的 server-mode（Peer 无 Endpoint）？
4) 是否计划支持 UDP forwarding（Socks5 UDP / UDP tunnel），还是暂时只做 DNS 这类点状 UDP？
