# Segment — 基于 HTTP/2 伪装层的代理协议设计文档

> 版本: v1 (draft)
> 技术栈: Go (≥1.24)
> 状态: 设计中，随实现迭代

Segment 是一个以 **TLS 1.3 + HTTP/2 为伪装层（fronting layer）**、内部运行自有多路复用帧协议的代理协议。伪装层刻意模拟 **HLS/DASH 视频流媒体站** 的真实流量形态；服务端采用 **caddy-like 模式**——它首先是一个能正常工作的"视频站"，只有通过应用层鉴权的客户端才能获得隧道能力。协议的目标是在网络审查严格的地区，为信息自由提供一条**高伪装性、性能良好**的通路。

**定位声明**: 我们不做"完美伪装"的承诺。伪装是分层对抗（对抗流量分析、指纹识别、主动探测），我们追求在每一层做到极致，并如实记录已知权衡（见 §11 安全分析）。

---

## 1. 设计目标与取舍

| 目标 | 手段 | 优先级 |
|---|---|---|
| 高伪装性 | 视频流媒体流量形态模拟、h2 指纹模拟、caddy-like 真实服务、帧填充、流量整形 | P0 |
| 性能 | 零拷贝路径、缓冲池、h2 大窗口、帧级流水线 | P0 |
| 票据快速恢复 | 单次票据 + HMAC 通过普通鉴权 POST 恢复；媒体流只在确认后开放 | P0 |
| TLS-in-TLS 缓解 | 内层全量加密+填充、握手阶段流量整形、尺寸归一化 | P0 |
| 密钥安全 | 应用层 PSK 鉴权；泄露即失效（可轮换）；服务端密钥不出内存 | P0 |
| UDP over TCP | UDP 数据报在隧道流内的定长帧封装 | P0 |
| 客户端形态 | SOCKS5（TCP+UDP ASSOCIATE）起步，TUN 预留 | P1 |

### 1.1 关键取舍说明

- **为什么用 HTTP/2 而非 QUIC/HTTP3**: 需求明确指定 HTTP/2。h2 基于 TCP，不提供 TLS early data；它的流复用、流控、填充位、扩展 CONNECT 等特性足以支撑隧道与伪装。QUIC 可作未来变体。
- **为什么内层自己做会话加密而不是直接依赖 TLS**: 内层加密使我们能在 TLS 之内再叠一层"内容不可见"，配合填充与整形把内层 TLS 流量（代理 https 站点时）彻底打成媒体数据形态，这是对抗 TLS-in-TLS 检测的关键。
- **票据恢复的落地**: 首次完整握手换取 session ticket 后，后续连接先通过普通的 `POST /api/v1/telemetry` 提交票据与 HMAC 证明；收到成功确认后才打开媒体标记的控制流和数据流。这牺牲了旧版所谓的“应用层 0-RTT”，换来清晰的认证边界：任何媒体形态的流在连接进入 Ready 之前都只能得到伪站响应。真 TLS 0-RTT（early data）仍记为未来工作（§11.4）。

---

## 2. 总体架构

```
 ┌────────────────────────── 客户端 ──────────────────────────┐   ┌────────────────────────── 服务端 ──────────────────────────┐
 │ 入站: SOCKS5 (TCP+UDP) / TUN(预留)                        │   │ caddy-like HTTP/2 服务器                                  │
 │        │                                                  │   │   • 未鉴权请求 → 真实伪视频站响应(manifest/segment/资源)   │
 │        ▼                                                  │   │   • 鉴权请求   → 隧道流升级                                │
 │ 连接管理器 (dial per 目标 4 元组)                          │   │        │                                                  │
 │        │                                                  │   │        ▼                                                  │
 │ 内层 Segment 协议: 帧编解码 + AES-256-GCM + 填充 + 票据恢复│   │ 内层 Segment 协议: 帧编解码 + AES-256-GCM + 填充 + 票据恢复│
 │        │                                                  │   │        │                                                  │
 │ 伪装层: uTLS(Chrome 指纹) + h2 客户端行为模拟              │◄─TLS1.3/h2─►│ 伪装层: TLS1.3 服务端 + h2 服务器行为模拟              │
 │        │  (媒体请求形态 / SETTINGS / WINDOW_UPDATE 节奏)   │   │        │  (视频站路由 / 媒体节奏)                               │
 └───────────────────────────────────────────────────────────┘   └───────────────────────────────────────────────────────────────┘
```

### 2.1 分层职责

| 层 | 模块 | 职责 |
|---|---|---|
| L1 传输 | `crypto/tls` + TCP | 真实 TLS 1.3，ALPN=h2，证书来自真实 CA |
| L2 伪装 | `internal/h2x` | 自研最小 h2 封装（基于 `x/net/http2.Framer`）：连接前导、SETTINGS、流状态机、填充、流控、帧级控制 |
| L3 隧道语义 | `internal/segment` | 内层帧协议：`OPEN / DATA / CLOSE / KEEPALIVE`，流=通道（TCP 连接 / UDP 流） |
| L4 安全 | `internal/segment`(crypto) + `internal/auth` | HKDF 派生密钥、AES-256-GCM 会话加密、PSK 鉴权、session ticket、防重放 |
| L5 反检测 | `internal/pacing` + `internal/auth` | 媒体节奏整形、帧尺寸归一化、h2 指纹随机化 |
| L6 入站 | `internal/socks5` / `internal/tun` | 本地 SOCKS5 / TUN 网卡接入 |

### 2.2 代码目录

```
D:\SEGMENT\
├─ docs/design.md            # 本文档
├─ cmd/
│  ├─ segment-server/        # 服务端 CLI
│  └─ segment-client/        # 客户端 CLI
├─ internal/
│  ├─ auth/                  # PSK 鉴权、session ticket、快速恢复、防重放
│  ├─ h2x/                   # x/net/http2.Framer 封装（双向）
│  ├─ pacing/                # 媒体节奏流量整形
│  ├─ segment/               # 内层帧协议、会话加密、填充
│  ├─ socks5/                # SOCKS5 入站
│  ├─ tun/                   # TUN 入站（预留）
│  └─ config/                # 配置加载
├─ go.mod / go.sum
└─ Makefile
```

---

## 3. 伪装层：TLS 与 HTTP/2

### 3.1 TLS 1.3

- **ALPN**: 仅 `["h2"]`。请求方模拟现代浏览器，不会回退到 h1.1。
- **证书**: 服务端使用真实 CA 签发的证书（SAN 匹配域名）。v1 不做 ECH/域名前置（CDN fronting 生态已基本关闭），自持域名 + 自持证书是主要部署形态。
- **密码套件**: 客户端按 Chrome 的 TLS 1.3 套件序（`TLS_AES_128_GCM_SHA256` 优先等）；服务端以 Go 默认 TLS 1.3 套件即可（TLS 1.3 下套件选择对指纹影响小）。
- **扩展**: 客户端携带 Chrome 常见扩展序（通过 uTLS 模板获得，见 §3.3）；开启 `record_size_limit` 支持（若 Go 版本允许），否则依赖内层填充。
- **会话恢复**: 客户端开启 TLS 1.3 PSK 恢复（`ClientSessionCache`），减少外层握手开销；内层票据仍经普通鉴权 POST 验证，不在 TLS early data 中发送。

### 3.2 HTTP/2 行为模拟（客户端）

客户端 h2 行为按 Chrome 的视频播放器特征建模：

- **SETTINGS 参数**（仿 Chrome 1xx）:
  - `HEADER_TABLE_SIZE = 65536`
  - `ENABLE_PUSH = 0`
  - `MAX_CONCURRENT_STREAMS = 1000`
  - `INITIAL_WINDOW_SIZE = 6291456` (6 MiB)
  - `MAX_HEADER_LIST_SIZE = 262144`
- **连接建立**: 连接前导 `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + SETTINGS 一并发；鉴权 POST 可以立即开流，但媒体标记的控制/数据流必须等待鉴权确认。
- **流形态**: 隧道流表现为"媒体分段下载"：`GET /videos/{v}/seg-{n}.m4s` 类请求，带 `Range`、`Accept`、`Referer` 等真实播放器头；请求头顺序与 Chrome 一致。
- **流控节奏**: 收到媒体数据后按"播放器缓冲"节奏回 WINDOW_UPDATE（分批、带抖动），而非一次放满窗口。
- **填充**: 开启 h2 DATA 帧填充位，填充长度随机，使帧尺寸分布逼近真实媒体分段。

### 3.3 客户端指纹（uTLS）

- 客户端 TLS ClientHello 通过 **uTLS** 以 Chrome 模板生成（`utls.HelloChrome_Auto` =
  Chrome 133），确保 JA3/JA4 指纹落在 Chrome 分布内。**已实现并在客户端默认启用**
  （`segment-client -tls-fingerprint=go` 可退回标准库 ClientHello）。
- 服务端 hello 目前为标准 Go 服务端 hello；更强的服务端指纹模拟（uTLS server
  hello）列入未来工作（见 §11.4）。

### 3.4 caddy-like 伪视频站（服务端）

服务端首先是一个**真实可访问的视频站**（静态资源 + 伪媒体生成），未鉴权的任何请求都得到正常响应，杜绝"端口只回特征数据"的主动探测暴露：

| 路由 | 行为 |
|---|---|
| `GET /` 、`/index.html` | 视频站首页（真实 HTML） |
| `GET /api/v1/config` | 站点配置 JSON（播放器参数等） |
| `GET /videos/{id}/index.m3u8` | HLS manifest：真实分片列表（伪分片时长 6s 等） |
| `GET /videos/{id}/manifest.mpd` | DASH manifest |
| `GET /videos/{id}/seg-{n}.ts` / `seg-{n}.m4s` | 伪媒体分段：确定性伪随机字节（种子=id+seq），大小模拟真实分片（256KB~1MB），带 `ETag`/`Cache-Control`/`Accept-Ranges` |
| `GET /videos/{id}/thumb-{n}.jpg` | 缩略图（伪随机 JPEG 噪声，可缓存） |
| `GET /favicon.ico` 等杂项 | 静态资源 |
| 任意未匹配 | 404 页面（标准） |

- 伪媒体分段是**确定性**的（同一 URL 永远同一内容），可被缓存/CDN 化，主动探测者抓到的是一致内容——进一步坐实"这是一个内容站"。
- 服务端对每个连接限制伪媒体带宽（可选），避免被用来做免费存储/带宽滥用。
- **隧道端点也伪装成媒体路由**（§3.6），从 URL 层面无法区分哪条流是隧道。

### 3.5 鉴权（TLS 之内、应用层）

鉴权发生在 TLS 建立之后、HTTP/2 之内，全部密文传输，PSK 不落网络：

1. 客户端对**每个新会话**（无有效 ticket 时）发送 `POST /api/v1/telemetry`（外观是埋点上报）：
   - 请求体 = `nonce(12) || AES-GCM(keyAuth, nonce, ts || clientNonce(16) || connNonce(16))`，其中 `keyAuth = HKDF(PSK, "segment-auth")`，`connNonce` 为本连接新选的 16B 随机数（用于派生连接级数据密钥，保证跨连接前向隔离）。
   - 头携带 `X-Sg-C: <ts>.<hex(hmac)>`，`hmac = HMAC-SHA256(keyAuth, ts||clientNonce||connNonce)`，用于服务端在解密前快速过滤（时间戳新鲜窗口 ±30s）。
2. 服务端校验：时间戳新鲜、HMAC 正确、解密成功 → 生成会话：
   - `sessionKey`（32B 随机）作为本会话内层加密主密钥；
   - `ticket = nonce(12) || AES-GCM(keySrv, nonce, sessionId(16) || exp(8))`（服务端密钥加密、内容对客户端不透明；**ticket 内不含 sessionKey**）；
   - 响应 `200` + `Set-Cookie: x-sg-ticket=<ticket>`（外观是会话 cookie），响应体 = `ticket || sessionKey`（已处 TLS 之内，明文传递安全）。
3. 客户端持久化缓存 `{ticket, sessionKey}`；服务端在内存维护 `sessionId → {sessionKey, exp}` 表（TTL + LRU 上限，重启即失效，客户端自动回退完整握手）。
4. 每个新连接：客户端新选 `connNonce`，双方派生 `keyData = HKDF(sessionKey, connNonce, "segment-data")` —— 即使某连接被记录，密钥也无法跨连接复用（前向隔离）。

**密钥轮换**: PSK 可热更新（服务端 SIGHUP 重载），旧 PSK 保留一个宽限期；`keySrv` 轮换使存量 ticket 自然失效（客户端静默重走完整握手）。

### 3.6 隧道建立（流劫持模型）

- 鉴权通过后，客户端在**同一 h2 连接**上打开隧道流，请求形态与 Chrome 120 的真实媒体分片 fetch 无法区分：
  - TCP: `GET /videos/{v}/seg-{n}.m4s` + 三头标记组合 `sec-fetch-dest: empty` + `sec-fetch-mode: cors` + `priority: u=1, i`（这正是 Chromium MSE/HLS 分片请求的真实形态；不再使用自定义头，wire 上零自定义字段）。
  - UDP: 同样三头组合（客户端将其作为 `sec-fetch-dest: empty` 的普通 fetch 发送）。
  - 控制流：stream ID 1 + 同一三头组合（外观是"manifest 刷新"轮询）。
  - 完整客户端头集与真实 Chrome 120 一致：`:accept: */*`、`accept-encoding: identity`、`accept-language`、`range: bytes=0-`、`sec-ch-ua`/`sec-ch-ua-mobile`/`sec-ch-ua-platform`、`sec-fetch-site: same-origin`、标准 `user-agent`。
- 服务端以 `hasTunnelMarkers`（三头组合同时命中）判定隧道流并升级为**双向隧道流**：服务端先发一组"响应头"（`200` + `Content-Type: video/mp4` + `Content-Length: <大值>`，与实际流量无关，仅用于让流看起来像媒体下载），随后直接在该流上收发内层 Segment 帧（§4）。
- 流 ID 即通道 ID：`TCP 流` = 一条 TCP 连接；`UDP 流` = 一个 UDP 4 元组会话。
- 每连接一条 `control 流`（第 1 条流）承担保活与会话控制（外观是"manifest 刷新"轮询）。

> 撞车语义：任何恰好携带这三头的真实浏览器请求（伪站对 `/videos/*/seg-*.m4s` 返回媒体）也会进入隧道判定——无鉴权能力时服务端返回媒体响应，绝不回 HTTP 错误；有能力时（该请求恰含有效会话）走加密帧解析，非法帧按流级 RST 处理（等 ready 上限 8s，防止挂起）。
>
> 不使用 RFC 8441 扩展 CONNECT（`CONNECT ... :protocol=...`）：扩展 CONNECT 流量形态特征明显（WebTransport），不如"媒体 GET 流劫持"自然。`:protocol` 机制可作隐藏变体（配置开关）。

---

## 4. 内层 Segment 协议

### 4.1 流（Stream）与通道（Channel）

- 一个 h2 连接内：`流 1` = control（保活/控制帧）；其余流 = 数据通道。
- 每条隧道流的 h2 DATA 帧负载 = 恰好一个 **Segment 帧**（加密后）。h2 帧填充 + 内层填充叠加实现尺寸归一化（§4.4）。
- 帧在流内严格有序；帧头不携带流 ID（h2 层已确定），降低开销。

### 4.2 帧格式

内层帧 = 明文头(8B) + 密文负载（AES-256-GCM，nonce = 会话级计数器，见 §4.3）：

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type | Flags |  PadLen  |             Length                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload (encrypted)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 字段 | 大小 | 说明 |
|---|---|---|
| Type | 3 bit | 帧类型 |
| Flags | 5 bit | 每类型定义 |
| PadLen | 1 B | 填充长度（明文，属于负载统计的一部分，用于还原真实长度） |
| Length | 2 B | 密文负载长度（含 GCM tag 16B），≤ 65535 |
| Payload | 变长 | AES-256-GCM 密文 |

> 当前传输路径只在鉴权完成后发送 Segment 帧，活动帧负载均为密文。编解码器仍保留旧版明文 `FRAME_AUTH_RESUME` 类型用于线格式兼容与测试，但客户端不再发送、服务端也不再把它作为连接准入信号。帧类型只有 6 种，长度经填充归一化（§4.4）。

**帧类型**:

| Type | 名称 | 方向 | Flags | 负载（解密后） |
|---|---|---|---|---|
| 0 | `FRAME_OPEN` | C→S | `UDP=0x1` | `addrLen(1B) || addr || port(2B BE) || padding` |
| 1 | `FRAME_DATA` | 双向 | `FIN=0x1` | `dataLen(2B) || data || padding` |
| 2 | `FRAME_CLOSE` | 双向 | `RST=0x1` | `reason(1B) || padding` |
| 3 | `FRAME_KEEPALIVE` | 双向 | — | `ts(8B) || padding` |
| 4 | `FRAME_ACK` | 双向 | — | `echo(8B) || padding`（确认控制帧/探测） |
| 5 | `FRAME_AUTH_RESUME` | C→S | — | 旧版兼容类型，明文定长 256B；当前传输不使用，恢复证明改走普通鉴权 POST |

- `FRAME_OPEN`：隧道流上的第一个帧。TCP 通道负载目标地址；UDP 通道负载目标地址+端口，随后该流上的 `FRAME_DATA` 每帧负载 = `dgramLen(2B) || datagram`（一个 UDP 数据报，长度 ≤ MTU 配置，默认 1200）。
- `FRAME_DATA`：`FIN` 置位表示该方向数据结束（TCP 半关闭）。
- `FRAME_CLOSE`：通道关闭（TCP RST 或 UDP 会话结束）。
- 同一通道帧数上限/时间上限可配置（防滥用）。

### 4.3 会话加密

- 会话主密钥 `sessionKey`（32B，服务端在鉴权时生成，随 ticket 下发）。
- 数据密钥派生: `keyData = HKDF-SHA256(sessionKey, salt=连接随机 nonce, info="segment-data")`；`keyAuth` 仅用于鉴权 blob（§3.5）。
- **AES-256-GCM**，nonce = 12B：`[8B 会话计数器 BE || 4B 随机前缀]`，计数器每条流独立起点（流 ID 派生），防跨流重放；帧级重放由 GCM 认证失败自然拒绝。
- 票据恢复（§5）时，恢复会话沿用原 `sessionKey`，但**每个新连接重新派生** `keyData`（salt=新连接 nonce），保证连接间密钥隔离（ticket 泄露不泄露历史流量）。

### 4.4 填充策略（尺寸归一化）

观测者只能看到 h2 层帧尺寸分布。真实 HLS/DASH 分段流量特征：**分段大小聚集在若干档位**（如 16KB、64KB、256KB、512KB、1MB 分片 + 小控制包）。填充策略：

1. 内层 `FRAME_DATA` 负载按目标档位补齐（`padTo(chunkSize)`），档位从会话内伪随机选择，分布对齐媒体分段分布。
2. h2 层 `PAD_LENGTH` 再叠加 0~255B 抖动（h2 填充位），抹掉 GCM tag/头对齐残差。
3. `FRAME_OPEN/CLOSE/KEEPALIVE` 等控制帧统一填充到固定小尺寸（如 256B），控制流与数据流尺寸分布分开建模（真实播放器控制请求也是小包）。
4. 填充字节为 CSPRNG 随机（`crypto/rand`），避免压缩/可预测性。
5. h2 层 `PAD_LENGTH` 只做**长度**抖动（0~255B 随机），填充字节为全零——与真实浏览器实现一致（Chrome 等使用零填充）；`x/net/http2` 的 Framer 亦强制零填充字节。

### 4.5 UDP over TCP

- 每个 UDP 4 元组（目标 IP:端口 × 客户端源端口）独占一条隧道流；TCP 的可靠有序性保证数据报**有序到达**（与真实 UDP 的无序语义不同，但对 QUIC/DNS 等主流应用无影响，文档明示该取舍）。
- 数据报长度前缀 2B（≤ MTU 配置，默认 1200B，覆盖主流 QUIC/DNS 包）。
- 空闲超时（默认 30s）后服务端/客户端任一侧发 `FRAME_CLOSE` 回收流。
- 可选 `UDP+ECN` 标志位传递 ECN（v1 不做，记录）。

### 4.6 保活

- control 流每 `keepalive_interval`（默认 20s，可抖动）发 `FRAME_KEEPALIVE`，服务端回 `FRAME_ACK`；外观是播放器 manifest 轮询。
- 空闲数据流不发保活（真实播放器空闲流会被关闭），由 control 流统一保活连接。
- 心跳超时（默认 3×间隔）判定连接死亡。

---

## 5. 单次票据快速恢复

### 5.1 流程

1. **首次连接**: 完整鉴权（§3.5）→ 客户端持有 `ticket + sessionKey`。
2. **恢复请求**: 新 TLS/h2 连接先打开普通 `POST /api/v1/telemetry`，请求体为 `connNonce(16) || ticket(52) || freshNonce(16) || hmac(32)`，其中 `hmac = HMAC-SHA256(sessionKey, connNonce||freshNonce||ticket)`。该请求不携带媒体隧道标记。
3. **服务端准入**:
   - 先校验 ticket、有效期、单次使用状态与 HMAC，再建立当前连接的会话并返回短 JSON 确认；
   - 缺失、伪造、过期或重放的证明交给同一个已配置伪站处理，不返回专用的 403、RST 或鉴权帧；
   - 在连接状态变为 Ready 之前，任何带媒体标记的流（包括首个 stream 1）都交给伪站处理。
4. **隧道开放**: 客户端只有在收到精确的恢复确认后才派生本连接的 `keyData`，随后打开控制流和数据流。有效隧道流先收到看似媒体响应的 `:status 200`、`content-type: video/mp4`，再开始传输 DATA。
5. **自动回退**: 恢复失败时客户端在新连接上执行完整鉴权；服务端重启导致旧票据失效时无需用户干预。
6. **连接间隔离**: 每个新连接重新派生 `keyData`（§4.3），密钥不能跨连接直接复用。

### 5.2 防重放细节

- ticket 单次有效 + seen-set；freshNonce 与当前 connNonce 绑定 HMAC，同一票据再次使用会被拒绝。
- 无效载荷在写入 used 表之前被拒绝；只有已通过密码学校验的有效票据才占用防重放状态，且表有容量上限。
- 这是 TLS 握手后的“一次请求恢复”，不是 TLS 或应用层 0-RTT；客户端在确认前不会发送隧道数据，因此不存在旧版“未认证媒体流先行”的准入歧义。

---

## 6. TLS-in-TLS 缓解

代理 https 站点时会产生双层 TLS。检测手段与对策：

| 检测手段 | 对策 |
|---|---|
| 内层 TLS 记录尺寸分布（ClientHello 小包簇 → ServerHello+Cert 大包簇的"握手签名"） | 内层流量被 AES-GCM 整体加密并切成均匀帧，任何内层 TLS 记录边界在帧内消失（§4.2/§4.4） |
| 握手阶段的突发节奏（握手期间无数据→突然大流量） | `internal/pacing` 在**内层握手期间**给帧插入媒体式节奏：短突发+抖动间隔，模拟播放器缓冲起播 |
| 首包时间/包长统计（h2 流建立后的首帧大小） | 首帧强制补到媒体分段档位；`FRAME_OPEN` 与首批 `FRAME_DATA` 合并为一次"分段下载" |
| 双向速率不对称 | 媒体下载天然不对称，隧道做方向性整形：下行按分段节奏、上行按播放器遥测节奏 |
| h2 帧大小恒定（隧道特征） | 档位伪随机 + h2 填充抖动 + 长流中途换档（模拟分段切换） |

**实现要点**: 服务端对每条隧道流做"起播阶段"（前 1~2s 低速率、抖动）与"稳定阶段"（目标速率+噪声）的两段式整形；整形参数随 manifest 中的"码率档"（配置）变化。

---

## 7. 流量整形（internal/pacing）

- **令牌桶 + 抖动**: 以配置的目标码率（如 4 Mbps）为均值，突发 256KB~1MB、间隔按媒体分段调度（伪随机泊松过程），模拟播放器下载-缓冲-下载的节奏。
- **方向独立**: 下行（媒体下载）高码率 + 分段节奏；上行（遥测/信令）低码率 + 小包节奏。
- **起播阶段**: 连接前 0.5~2s 随机初始缓冲（模拟播放器起播），期间带宽从 0 爬升到目标。
- 客户端与服务端同时启用（两端整形叠加不会累积失真，各自独立建模）。

---

## 8. 客户端入站

### 8.1 SOCKS5（RFC 1928）

- 支持 `CONNECT`（TCP）与 `UDP ASSOCIATE`；`NO AUTH`（本地回环默认）+ 可选 `USERNAME/PASSWORD`。
- UDP ASSOCIATE：本地 UDP 套接字接收数据报，按目标地址映射到对应 UDP 隧道流（§4.5），响应数据报回写客户端。
- 并发连接上限、空闲超时、错误映射（SOCKS 响应码 ↔ `FRAME_CLOSE` reason）。

### 8.2 TUN（预留）

- 平台抽象接口 `internal/tun.Device`（Open/Read/Write/Close），Windows 走 wintun、Linux 走 `/dev/net/tun`。
- 路由接管：默认路由 + 分流规则（绕过内网/保留地址），IP 包封装为 `FRAME_DATA`（类型扩展 `TUN=0x2`，负载=IP 包）。
- v1 提供接口与空实现 + 文档；SOCKS5 稳定后实现。

---

## 9. 性能设计

- **零拷贝**: 入站 socket → 帧负载缓冲 → h2 写缓冲，全程 `sync.Pool` 复用；`io.CopyBuffer` 批量搬运。
- **缓冲池**: 帧负载（16KB/64KB 档）、h2 写缓冲池化；GC 压力最小化（`SetGCPercent` 可选）。
- **流控**: 连接窗口初始 6 MiB，服务端主动批量回 WINDOW_UPDATE（合并、按节奏）；避免逐帧 ACK 往返。
- **加密**: AES-GCM 硬件加速（AES-NI）；避免每帧分配 nonce/头部。
- **并发**: 每条流一个 goroutine + 每连接一个写协程（写锁串行化）；控制流与数据流分离。
- **UDP**: 数据报合并写（同流小包批量 flush）；MTU 1200 减少分片。
- 基准: `go test -bench` 提供加密吞吐、帧编解码、端到端带宽基准（见 §12）。

---

## 10. 配置示例

```yaml
# server.yaml
listen: ":443"
tls:
  cert: /etc/segment/server.crt
  key:  /etc/segment/server.key
  alpn: ["h2"]
psk: "change-me-32-bytes-minimum"
fake-site:
  title: "示例视频站"
  bitrate_kbps: 4000        # 目标码率
  segment_seconds: 6
  chunk_scale: [16, 64, 256, 512, 1024]  # KB 档位分布
pacing:
  startup_seconds: [0.5, 2.0]
  burst_max_kb: 1024
auth:
  ticket_ttl: 24h
  replay_window: 30s
udp:
  mtu: 1200
  idle_timeout: 30s
```

```yaml
# client.yaml
server: "video.example.com:443"
sni: "video.example.com"
psk: "change-me-32-bytes-minimum"      # 与服务端一致
tls_fingerprint: "chrome_120"          # uTLS 模板
socks5:
  listen: "127.0.0.1:1080"
  udp: true
keepalive_interval: 20s
```

---

## 11. 安全分析

### 11.1 威胁模型

对抗方 = 国家级 DPI/主动探测者，能力：完整被动流量记录、TLS 指纹库、主动连接/内容探测、部分中间盒干扰。假设：PSK 与证书私钥不泄露（泄露即失效，可轮换）。

### 11.2 提供的防护

- 被动流量分析: 流量形态与真实视频站分布不可区分（§3/§4.4/§7），内层内容不可读（AES-GCM）。
- 主动探测: caddy-like 服务对一切请求给出真实内容（§3.4）；无鉴权则无隧道，探测者拿不到任何协议特征数据。
- 指纹识别: 客户端 JA3/JA4 落 Chrome 分布（uTLS）；h2 SETTINGS/帧节奏落浏览器分布。
- TLS-in-TLS: §6 对策；内层握手不可见。

### 11.3 已知权衡（如实记录）

| 项 | 说明 |
|---|---|
| 非"完美伪装" | 持续对抗下行为特征可能被统计区分；我们优化的是**可证伪成本**——让区分需要足够多数据与足够强的模型 |
| UDP 有序性 | UDP over TCP 牺牲无序语义；对 QUIC/DNS/多数游戏可接受，对实时性要求苛刻的场景有影响 |
| 恢复会话密钥可被服务端用于解密 | 会话密钥服务端可见（本设计如此）；对抗的是网络观测者，不是服务端 |
| 密钥单点 | PSK 泄露 → 全部鉴权失效；依赖轮换与运维纪律 |
| 单连接带宽受限于 TCP | h2 单连接 BDP 上限；v1 单连接设计，多连接聚合为未来工作 |
| Go 服务端 hello 指纹 | 服务端 TLS hello 仍为 Go 特征（TLS1.3 下较中性）；uTLS 服务端 hello 为可选增强 |
| 无 ECH/域名前置 | 自持域名模式；SNI 明文可见（但域名本身是正常视频站） |

### 11.4 未来工作

- TLS 1.3 early data（真 0-RTT）: 需 fork/patch `crypto/tls` 或换 QUIC 变体；与 h2 早数据兼容性需验证。
- ECH (Encrypted Client Hello) 支持。
- uTLS 服务端 hello 模拟。
- 多连接聚合、BDP 感知窗口调优。
- TUN 完整实现、分流规则。
- 伪装站点内容真实化（真实片源/缩略图生成）、CDN 化。

---

## 12. 测试与基准

### 12.1 已交付测试

- 单元: `internal/segment` 帧编解码（含填充、最大载荷边界、篡改/乱序拒绝、跨流隔离）、
  `internal/auth` 完整握手、票据校验、重放拒绝、过期/驱逐、`internal/h2x` 握手/流控/
  填充剥离/重置传播/伪请求服务/坏前导拒绝。
- 集成（`internal/integration`，真实回环 TCP+TLS，自签证书）:
  - 伪站点：首页 / HLS m3u8 / 确定性媒体分片（相同请求两次字节一致）/ 404；
  - SOCKS5 TCP CONNECT 隧道 echo；
  - SOCKS5 UDP ASSOCIATE 隧道数据报 echo（命中并修复了 Windows 双栈 IPv6
    UDP socket 的兼容性问题，服务端显式 udp4 + 以客户端 TCP 本地地址回包）；
  - 票据快速恢复：恢复证明先经普通鉴权 POST，通过后隧道流量直达；
  - 未认证媒体标记流（包括首个 stream 1）得到伪站响应，不暴露隧道状态；
  - 票据单次使用：同一票据第二次恢复被拒（GOAWAY/RST）；
  - 错误密钥恢复被拒。
- 竞态: `go test -race ./...` 全绿。

### 12.2 已交付基准（`go test ... -bench .`，i5-9500T 2.2GHz）

| 基准 | 数值 |
|---|---|
| Segment 帧编解码 EncodeDecode | ≈600 MB/s, 4 allocs/op（EncodeAt 池化后隧道热路径 0 分配/帧） |
| VerifyAuth（会话表满时，堆驱逐） | ≈8.6 µs/op |
| Resume（含实时完整握手） | ≈17 µs/op |
| 隧道 1MB bulk（无节奏整形，loopback） | ≈60–115 MB/s |
| 隧道 1MB bulk（生产节奏整形 256KB/2-8ms） | ≈36 MB/s |
| 16KB 写+回声 往返 | ≈0.5 ms（时延敏感路径） |
| 旧版 0-RTT 重连历史基准 | ≈0.5 ms（当前鉴权 POST 流程需重新测量） |

> 注意：会话表驱逐最初为「满表时全量排序」实现，基准暴露其饱和态 ~245µs/op；
> 已改为按过期时间的 min-heap 摊销 O(log n) 驱逐，饱和态降至 8.6µs/op（28×）。

### 12.2.1 稳定性硬化（审查驱动的修复）

以伪装度、翻墙稳定性、性能三维度审查为驱动，本轮修复（均有回归测试 / race 全绿）：

- **伪装度**：隧道标记从自定义 `x-sg-t` 头改为 Chrome 120 媒体 fetch 三头组合
  （`sec-fetch-dest: empty` + `sec-fetch-mode: cors` + `priority: u=1, i`），
  wire 上零自定义字段；客户端请求头集与真实 Chrome 120 一致（§3.6）。
- **翻墙稳定性**：
  - 重连退避指数化 + ±30% 抖动（1s/2s/4s→30s 上限），打破固定重连节奏的统计特征；
  - `Close()` 可中断进行中的重连（所有网络步骤观察 `closed`，装隧道前二次校验），
    不再产生无人监督的幽灵隧道；TLS 握手/整体握手加 deadline；
  - relay 双泵对端 idle 时自动收尾（`CloseRead` 唤醒阻塞泵 + END_STREAM 释放流槽、
    回传 EOF），消除了 relay 永久挂死与流表泄漏（~1000 流打满连接的问题）；
  - h2 writerLoop 零泄漏（`closeNotify` 驱动退出；发送方双 select 兜底，无
    send-on-closed / 竞态 / 挂死）；`remoteInitWin` 数据竞争修复；
  - SOCKS5 UDP 即时回写替代抽样式泵 —— 高流量应答不再背压击穿 h2 流控杀死
    整条隧道；ASSOCIATE 会话感知控制连接关闭 + datagram idle 超时（5min）+
    每会话 128 流上限 + 全量清理；CONNECT relay 一腿结束即关另一腿；
  - 流级故障（目标拒绝等）不再被误判为隧道死亡而清空隧道；`establish` 失败
    路径清理已建隧道；重复 Connect 只启动一个监督 goroutine。
- **性能**：
  - Segment 发送路径零分配化：`EncodeAt`/`encodeClearAt` 就地加密（调用方
    sync.Pool 20KB 缓冲，GCM 支持 plain/dst 重叠），隧道 relay 数据块按帧上限
    读取；UDP 报文明确拒绝超帧上限（16KB）的报文而非撞池报错。
- **服务端 DoS 硬化**：鉴权 POST body 上限 64KB（未认证者不能拖垮内存）；
  票据 `Resume` 先校验后记账（无效票据洪泛不增长 `used` 表）+ `used` 容量上限；
  伪站点行 8KB / 头 100 条限额与 h2 preface 识别；TLS 握手与 h2 preface 超时
  （10s）；Accept 瞬时错误退避续跑；`pickSize` 对空/负/超大配置防御；
  时钟回拨不再停摆清理（单调时钟语义）。

### 12.3 实现状态对照

| 设计项 | 状态 | 说明 |
|---|---|---|
| L1 TLS 1.3 + ALPN h2 | ✅ | `crypto/tls`；服务端同时接受 TLS 1.2（真实 CDN 行为，TLS 1.3 优先） |
| ALPN 分流 / HTTP/1.1 伪站 | ✅ | 非 h2 连接由 `fakesite.ServeHTTP11` 提供 h1.1 站点（老客户端/降级代理不被"空回复"） |
| L2 定制 h2 引擎 | ✅ | `internal/h2x`（Chrome 1xx SETTINGS、replenish-on-consume 流控、零 padding） |
| L3 Segment 帧 | ✅ | 4B 头，1 h2 DATA = 1 帧（DataChunk=16000 保证单帧不超对端 max frame size） |
| L4 会话加密/鉴权 | ✅ | AES-256-GCM；每连接 keyData=HKDF(sessionKey, connNonce)；每流每方向子密钥+计数器 nonce |
| 完整握手 POST /api/v1/telemetry | ✅ | 响应体 = ticket‖sessionKey；服务端同时用握手中的 connNonce 建立该连接 keyData |
| 票据快速恢复 | ✅ | 恢复证明通过普通 `POST /api/v1/telemetry`；票据单次使用；成功确认后才开放媒体标记流 |
| 流劫持伪装 | ✅ | 隧道流 = Chrome 120 媒体 fetch 三头标记（sec-fetch-dest: empty + sec-fetch-mode: cors + priority: u=1,i），无自定义请求头；Ready 前所有媒体标记流（含 stream 1）统一回落伪站 |
| UDP over TCP | ✅ | FRAME_OPEN+FlagUDP；1 DATA=1 数据报（单帧上限 DataChunk=16000B）；30s 空闲回收 |
| 保活 | ✅ | FRAME_KEEPALIVE/FRAME_ACK，客户端 25s 周期 |
| h2 随机 pad 长度 | ✅ | 0-255 随机，pad 字节全零（与浏览器一致） |
| 媒体节奏整形 | ✅ | `internal/tunnel.Pacing`：突发(默认 256KB)+2-8ms 抖动停顿，服务端 CLI 默认开启 |
| SOCKS5 入口 | ✅ | TCP CONNECT + UDP ASSOCIATE |
| TUN 入口 | 🔲 预留 | `internal/tun` 接口已定，`Open` 返回 ErrNotImplemented（见 §8.2） |
| 客户端正向代理/CDN 化 | 🔲 | 未来工作 |
| uTLS 客户端指纹 | ✅ | `-tls-fingerprint=chrome`（默认，uTLS HelloChrome_Auto=Chrome 133 规范）\| `go`（stdlib） |
| 服务端密钥轮换 + 客户端回退 | ✅ | keySrv 每次启动随机（重启作废旧票据）；客户端恢复失败自动回退完整握手并重发新票据 |
| 配置 | ✅ | `internal/config` YAML（flag 覆盖）；§10 骨架即交付格式 |
| 会话凭据持久化 | ✅ | `-cred` 文件（0600，base64 ticket+key+expiry）；恢复成功后删除（票据单次使用）；重启客户端可快速恢复 |
| 断线自愈 | ✅ | 客户端监督 goroutine：连接丢失 → 有界指数退避（1s/2s/4s→30s 上限，±30% 抖动，打破固定重连节奏）重连（票据快速恢复，失败回退完整握手）；SOCKS 入口在重连期间等待并重试；Close 可中断进行中的重连（不产生幽灵隧道） |
