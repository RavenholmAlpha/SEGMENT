# Segment

一个**完全伪装**的代理协议（Go 实现）。网络层看起来是一个普通视频流媒体站
（HLS/DASH 行为），内层是一条端到端加密、多路复用的隧道。面向信息自由受限
地区：普通人看到的是一套真实的流媒体网站，只有持有 PSK 的客户端能获得隧道。

> 安全立场（诚实版）：PSK 泄露是该设计的**唯一**真实风险点。伪装不是"完美"的：
> 一个能实时中间人 TLS（即能伪造证书且客户端信任其 CA）的对手，可以看到请求路径
> 与帧到达模式。协议对抗的是**被动观察/统计检测/大规模主动探测**，而不是"天然
> 不可检测"（见 `docs/design.md` 第 11 章）。

## 架构分层

```
L1  TLS 1.3 (ALPN h2)              —— 与真实浏览器完全一致的前置层
L2  定制 h2 引擎 (internal/h2x)    —— 原生 http2.Framer，Chrome 系 SETTINGS
L3  Segment 帧协议 (internal/segment) —— 1 个 h2 DATA 帧 = 1 个 Segment 帧
L4  AES-256-GCM 会话加密 + PSK 鉴权 (internal/auth)
L5  反检测 (internal/tunnel)       —— 随机 h2 pad 长度、媒体节奏整形
L6  入口 (internal/socks5 + 预留 internal/tun)
```

## 特性

- **伪装层是真实功能站点**：`segment-server` 是一个 caddy 风格的流媒体站 ——
  首页、HLS m3u8、DASH MPD、确定性生成的媒体分片、缩略图、JSON 配置接口。
  没有凭据的访客只能看到站点本体；隧道流是"带 Chrome 120 媒体 fetch 形态标记
  （sec-fetch-dest: empty + sec-fetch-mode: cors + priority: u=1,i）的媒体请求"，
  wire 上零自定义头字段。
  站点同时支持 HTTP/2 与 HTTP/1.1（ALPN 分流）—— 老客户端/企业代理把连接
  降级到 h1.1 时站点依然正常（曾因仅支持 h2 导致这部分客户端"空回复"，
  已修复）；TLS 亦兼容 1.2（真实 CDN 必须，且 1.3 优先）。
- **应用层 0-RTT**：会话票据（单次使用、服务端加密、内部不含密钥）+ HMAC
  证明 → 新连接首飞即可带加密数据（Go 标准库 `crypto/tls` 不支持真正的
  TLS early data，故 0-RTT 做在应用层）。
- **流式 TCP + UDP over TCP**：UDP 一个 FRAME_DATA = 一个数据报，30s 空闲回收。
- **电信级防检测细节**：Chrome 133 uTLS ClientHello 指纹（`-tls-fingerprint=go` 可退回
  stdlib）、Chrome 1xx 系 SETTINGS、随机 pad 长度(0-255) 但内容全零（与真实浏览器
  一致）、媒体节奏整形（突发 + 抖动停顿）、每流每方向独立子密钥 + 计数器 nonce。
- **生产级韧性**：客户端凭据持久化（`-cred`，0600，原子写）→ 重启进程即 0-RTT 恢复；
  断线自动重连（指数退避 1s→30s 上限 + ±30% 抖动；服务端重启导致票据过期时自动
  回退完整握手；Close 可中断进行中的重连）；YAML 配置（`-config`，flag 覆盖）。
- **稳定性硬化**：未认证请求体的 DoS 防护（鉴权前 body 上限；无效 0-RTT 载荷
  不占存储）；伪站点行/头长度限额与 h2 preface 识别；TLS/preface 握手超时与
  Accept 瞬时错误退避；SOCKS5 UDP 即时回写（高流量应答不再击穿隧道流控）、
  会话/流 idle 回收与数量上限；relay 任一侧结束即关另一侧、relay 对端 idle 时
  自动收尾（CloseRead + END_STREAM）、h2 writer goroutine 零泄漏。`go test -race ./...`
  全套通过。
- **SOCKS5 入口**：TCP CONNECT + UDP ASSOCIATE。TUN 入口接口已预留（见下）。

## 快速开始

```powershell
# 服务端（自签证书 + 默认媒体节奏整形）
go run ./cmd/segment-server -listen 127.0.0.1:8443 -psk "0123456789abcdef0123456789abcdef" -insecure

# 客户端（本地 SOCKS5；首次连接完成完整握手并缓存会话凭据）
go run ./cmd/segment-client -server 127.0.0.1:8443 -psk "0123456789abcdef0123456789abcdef" -socks 127.0.0.1:1080 -insecure

# 使用
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

生产部署请使用 `-cert/-key`（正式证书）；客户端用 `-cacert` 校验。

## 测试与基准

```powershell
$env:GOCACHE="D:\SEGMENT\.gocache"; $env:GOTMPDIR="D:\SEGMENT\.gotmp"; $env:GOTELEMETRY="off"
go test ./...            # 单元 + 端到端集成
go test -race ./...      # 竞态检测
go test ./internal/integration/ -bench . -benchtime 3x -run '^$'
```

| 基准 | 结果 (i5-9500T) |
|---|---|
| Segment 帧 编解码 | ≈780 MB/s, 2 allocs/op |
| 完整握手鉴权（会话表满时） | ≈8.6 µs（min-heap 驱逐） |
| 票据恢复验证（含握手） | ≈17 µs |
| 隧道 bulk 1MB（绿色模式） | ≈60–115 MB/s |
| 隧道 bulk 1MB（生产节奏整形） | ≈36 MB/s |
| 16KB 往返（时延敏感） | ≈0.5 ms |
| 0-RTT 重连（TCP+TLS+h2+恢复） | ≈0.5 ms |

集成测试覆盖：伪站点行为、完整握手、SOCKS5 TCP/UDP、0-RTT 恢复、票据单次
使用（重放拒绝）、错误密钥拒绝。

## 目录

```
cmd/segment-server    服务端 CLI（伪站点 + 隧道；-config YAML）
cmd/segment-client    客户端 CLI（SOCKS5 入口；-config/-cred/-tls-fingerprint）
internal/auth         PSK 握手、票据、0-RTT 恢复（min-heap 会话驱逐）
internal/client       客户端连接管理（uTLS 指纹、凭据持久化、断线自愈）
internal/config       YAML 配置加载
internal/fakesite     伪视频站点内容生成（h2 + h1.1）
internal/h2x          定制 h2 引擎（流控、填充、服务器端）
internal/segment      Segment 帧协议 + AES-256-GCM 会话加密
internal/socks5       SOCKS5 TCP + UDP ASSOCIATE
internal/tunnel       隧道引擎（帧编解码、中继、节奏整形）
internal/tun          TUN 入口预留（未实现，见 docs/design.md §8.2）
docs/design.md        完整协议设计文档（加密、伪装、威胁模型）
```

## 已知边界（诚实清单）

- PSK 是单点信任根；泄露即全盘失守。
- 服务端密钥（票据加密 keySrv）每次启动随机轮换 → 重启后旧票据失效；客户端会自动
  回退完整握手并重发新票据（已实测：服务端宕机→重启→客户端自愈恢复，首个请求即通）。
- 客户端凭据文件 `-cred` 内含可用的会话密钥（0600 权限）；其风险范围等同本机被攻陷
  时的一次性会话泄露（不含 PSK 本身）。
- TUN 入口未实现（接口已预留）；Windows 上 SOCKS5 UDP 使用 IPv4 socket。
- 真正的 TLS early data / ECH / 服务端指纹(uTLS server) 属于后续计划（见设计文档）。