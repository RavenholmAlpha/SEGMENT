<div align="center">

# 🎬 SEGMENT

**伪装为功能型 HTTP/2 视频流媒体站点的加密多路复用代理**

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/RavenholmAlpha/SEGMENT?style=flat-square&color=brightgreen)](https://github.com/RavenholmAlpha/SEGMENT/releases)
[![HTTP/2](https://img.shields.io/badge/Fronting-HTTP%2F2-1f6feb?style=flat-square)](https://www.rfc-editor.org/rfc/rfc9113)

*普通访客看到真实 HLS/DASH 内容；认证客户端获得加密 TCP 与 UDP 隧道。*

---

[English](README.md) | **中文**

[特性](#特性) · [快速开始](#快速开始) · [配置](#配置) · [架构](#架构) · [部署](#部署) · [测试](#测试)

</div>

## 为什么选择 SEGMENT？

| 可观测特征 | SEGMENT 的处理方式 |
|:--|:--|
| 未知端点返回协议错误或立即关闭 | **功能型媒体站点** — 普通请求和被拒请求都获得正常 HLS/DASH 内容 |
| 隧道准入通过特殊响应、重置或流顺序泄露 | **伪站优先准入** — 鉴权完成前，所有媒体标记流始终停留在伪站路径 |
| 自定义 HTTP 头暴露隧道开关 | **浏览器媒体请求形态** — 认证流使用普通 Chrome 风格请求字段 |
| HTTP/2 DATA 出现在合法响应之前 | **媒体响应语义** — 隧道流先发送 `200` 和 `video/mp4` 响应头，再发送 DATA |
| 重连反复执行完整 PSK 交换 | **单次票据恢复** — 普通鉴权 POST 先证明缓存票据，再开放媒体流 |

## 特性

<table>
<tr>
<td width="50%">

🎞️ **功能型流媒体伪站**<br>
服务端渲染视频门户，包含 HLS 播放列表、DASH manifest、确定性媒体分片、缩略图和 JSON 配置。

🛡️ **伪站优先探测处理**<br>
缺失、错误、过期或重放的凭据统一通过配置的站点渲染，不返回隧道专用状态。

🌐 **浏览器式 TLS 与 HTTP/2**<br>
客户端默认使用 Chrome uTLS ClientHello；HTTP/2 引擎发送 Chrome 系 SETTINGS 与媒体请求头。

🔐 **内层会话加密**<br>
Segment 帧使用 AES-256-GCM，并进行逐连接、逐流、逐方向的密钥分离。

</td>
<td width="50%">

🎟️ **单次票据恢复**<br>
凭据持久化支持短鉴权恢复 POST、自动回退完整握手以及票据重放拒绝。

🪢 **TCP 与 UDP 中继**<br>
SOCKS5 TCP CONNECT 和 UDP ASSOCIATE 共享加密 HTTP/2 隧道；每个 UDP DATA 帧保持一个数据报。

📐 **媒体流量节奏整形**<br>
可配置突发大小与随机停顿，把隧道出口塑造成缓冲式媒体传输。

🔄 **自动恢复**<br>
客户端通过有界指数退避和抖动重连，刷新会话凭据并恢复本地 SOCKS 服务。

</td>
</tr>
</table>

## 快速开始

### 从源码构建

```bash
git clone https://github.com/RavenholmAlpha/SEGMENT.git
cd SEGMENT

go build -trimpath -ldflags="-s -w" -o segment-server ./cmd/segment-server
go build -trimpath -ldflags="-s -w" -o segment-client ./cmd/segment-client
```

也可以使用 Makefile：

```bash
make build
```

### 本地测试

生成共享密钥，保存打印出的值，并使用临时开发证书运行两端：

```bash
PSK="$(openssl rand -hex 32)"
printf 'PSK=%s\n' "$PSK"

# 终端 1 — 服务端
./segment-server \
  -listen 127.0.0.1:8443 \
  -psk "$PSK" \
  -insecure \
  -pacing=true

# 终端 2 — 填入刚才打印的同一个 PSK，再启动客户端
PSK="在此粘贴同一个值"
./segment-client \
  -server 127.0.0.1:8443 \
  -psk "$PSK" \
  -socks 127.0.0.1:1080 \
  -insecure
```

验证本地 SOCKS5 隧道：

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com/
```

### 公网部署

使用真实域名证书，保持客户端证书校验开启，并把会话凭据缓存放在私有本地路径：

```bash
# 服务端
./segment-server \
  -listen :443 \
  -cert /etc/segment/fullchain.pem \
  -key /etc/segment/privkey.pem \
  -psk "$PSK" \
  -pacing=true

# 客户端
./segment-client \
  -server video.example.com:443 \
  -sni video.example.com \
  -psk "$PSK" \
  -socks 127.0.0.1:1080 \
  -cred /var/lib/segment/client-cred.json \
  -tls-fingerprint chrome
```

普通浏览器访问 `https://video.example.com/` 时会显示流媒体伪装站点。

## 配置

命令行参数会覆盖 YAML 中加载的值。

### 服务端 YAML

```yaml
listen: 0.0.0.0:443
cert: /etc/segment/fullchain.pem
key: /etc/segment/privkey.pem
psk: "替换为至少32字节的随机密钥"

pacing:
  enabled: true
  burst_kb: 256
  min_pause_ms: 2
  max_pause_ms: 8
```

启动命令：

```bash
segment-server -config /etc/segment/server.yaml
```

| 参数 | 默认值 | 说明 |
|:--|:--|:--|
| `-config` | — | YAML 配置文件 |
| `-listen` | `:443` | 公网监听地址 |
| `-cert` | — | PEM 格式 TLS 证书 |
| `-key` | — | PEM 格式 TLS 私钥 |
| `-psk` | 必填 | 至少 32 字节的预共享密钥 |
| `-insecure` | `false` | 生成临时自签名开发证书 |
| `-pacing` | `true` | 把隧道出口塑造成媒体突发 |
| `-pacing-burst` | `256` | 每个突发的 KiB 数 |
| `-pacing-min-ms` | `2` | 随机停顿最小值 |
| `-pacing-max-ms` | `8` | 随机停顿最大值 |

### 客户端 YAML

```yaml
server: video.example.com:443
sni: video.example.com
psk: "替换为与服务端相同的共享密钥"
socks: 127.0.0.1:1080
cred_file: /var/lib/segment/client-cred.json
tls_fingerprint: chrome
```

启动命令：

```bash
segment-client -config /etc/segment/client.yaml
```

| 参数 | 默认值 | 说明 |
|:--|:--|:--|
| `-config` | — | YAML 配置文件 |
| `-server` | 必填 | `host:port` 格式服务端地址 |
| `-sni` | 服务端主机名 | TLS SNI 与 HTTP/2 authority |
| `-psk` | 必填 | 与服务端一致的共享密钥 |
| `-socks` | `127.0.0.1:1080` | 本地 SOCKS5 监听地址 |
| `-cred` | — | 持久化单次票据凭据文件 |
| `-tls-fingerprint` | `chrome` | `chrome` 或 `go` ClientHello |
| `-cacert` | 系统根证书 | 额外私有 CA 证书包 |
| `-insecure` | `false` | 在本地测试中跳过服务端证书验证 |

## 架构

### 协议栈

| 层 | 职责 |
|:--|:--|
| **TLS 前置层** | TLS 1.3 优先、HTTP/2 ALPN、真实证书和 Chrome 风格客户端指纹 |
| **媒体伪站** | 功能型 HTTP/2 与 HTTP/1.1 HLS/DASH 站点 |
| **准入** | 通过普通 POST 完成 PSK 鉴权或单次票据证明 |
| **HTTP/2 引擎** | 浏览器系 SETTINGS、流控、流生命周期与 DATA padding |
| **Segment 加密** | AES-256-GCM 帧与逐连接、逐流密钥派生 |
| **隧道** | 加密控制、TCP 中继、UDP 中继、节奏整形与空闲清理 |
| **本地入口** | SOCKS5 TCP CONNECT 与 UDP ASSOCIATE |

### 连接生命周期

1. 客户端以浏览器式 ClientHello 建立 TLS 并协商 HTTP/2。
2. 普通 `POST /api/v1/telemetry` 完成 PSK 鉴权或证明缓存票据。
3. 只有证明验证成功后，服务端才把 HTTP/2 连接标记为 Ready。
4. 客户端随后打开媒体形态控制流和加密中继流。
5. 每个获准隧道流在首个 DATA 帧前收到视频式 HTTP 响应头。
6. 连接断开触发带抖动重连；失效票据自动回退完整交换。

### 反检测设计

| 观测向量 | SEGMENT 行为 |
|:--|:--|
| **普通浏览** | 通过 HTTP/2 或 HTTP/1.1 提供完整、确定性的流媒体站点 |
| **未认证媒体流** | 使用同一个配置伪站响应器，包括首个 HTTP/2 流 |
| **错误完整鉴权** | 返回伪站内容，不返回专用认证状态 |
| **票据重放** | 对外返回伪站内容，内部保持票据单次使用 |
| **TLS 指纹识别** | 客户端默认使用 Chrome uTLS ClientHello |
| **HTTP/2 指纹识别** | 浏览器系设置、请求头、流控与全零随机长度 padding |
| **响应顺序** | `:status` 与 `content-type` 在隧道 DATA 之前发送 |
| **流量分析** | 突发整形、随机停顿、载荷填充与逐流密码计数器 |

### 票据恢复

服务端签发的票据对客户端不透明，票据内部不包含会话密钥。客户端在本地保存票据和密钥，通过绑定新连接 nonce 的 HMAC 证明持有密钥。证明经普通鉴权 POST 发送，不带媒体标记。只有收到精确成功响应后，客户端才建立新的内层会话并打开媒体形态流。

票据在验证成功后被原子消费。服务端密钥轮换后，客户端会自然执行新的完整鉴权交换并缓存新凭据。

## 项目结构

```text
SEGMENT/
├── cmd/
│   ├── segment-server/       媒体前置服务端二进制
│   └── segment-client/       SOCKS5 客户端二进制
├── deploy/                   YAML 与 systemd 部署资产
├── internal/
│   ├── auth/                 PSK 交换、票据、恢复与重放控制
│   ├── client/               TLS 指纹、凭据持久化与重连
│   ├── config/               YAML 配置与校验
│   ├── fakesite/             HLS/DASH 伪装内容
│   ├── h2x/                  HTTP/2 帧、流控与流
│   ├── segment/              内层帧与 AES-256-GCM 会话加密
│   ├── server/               TLS/ALPN 监听与伪站路由
│   ├── socks5/               TCP CONNECT 与 UDP ASSOCIATE 入口
│   └── tunnel/               准入、编解码器、中继与节奏整形
└── docs/design.md            协议设计与威胁模型
```

## 部署

| 资源 | 说明 |
|:--|:--|
| [部署指南](deploy/README.md) | 域名证书、systemd 服务、本地客户端与运维 |
| [服务端 YAML](deploy/server.yaml.example) | 面向生产的服务端配置示例 |
| [客户端 YAML](deploy/client.yaml.example) | 面向生产的客户端配置示例 |
| [服务端 unit](deploy/segment-server.service) | systemd 服务定义 |
| [客户端 unit](deploy/segment-client.service) | systemd 服务定义 |
| [协议设计](docs/design.md) | 鉴权、加密、HTTP/2 行为、节奏整形与测试覆盖 |

## 测试

```bash
# 完整单元与端到端集成测试
go test ./...

# 静态分析
go vet ./...

# 竞态检测
go test -race ./...

# 基准测试
go test -bench=Benchmark -benchmem ./internal/...
```
