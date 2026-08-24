<div align="center">

# 🎬 SEGMENT

**An encrypted multiplexed proxy presented as a functional HTTP/2 video streaming site**

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/RavenholmAlpha/SEGMENT?style=flat-square&color=brightgreen)](https://github.com/RavenholmAlpha/SEGMENT/releases)
[![HTTP/2](https://img.shields.io/badge/Fronting-HTTP%2F2-1f6feb?style=flat-square)](https://www.rfc-editor.org/rfc/rfc9113)

*Real HLS/DASH cover content for ordinary visitors; authenticated clients receive an encrypted TCP and UDP tunnel.*

---

**English** | [中文](README.zh.md)

[Features](#features) · [Quick Start](#quick-start) · [Configuration](#configuration) · [Architecture](#architecture) · [Deployment](#deployment) · [Testing](#testing)

</div>

## Why SEGMENT?

| Observable pattern | SEGMENT's approach |
|:--|:--|
| An unknown endpoint returns a protocol error or closes immediately | **Functional media site** — ordinary and rejected requests receive normal HLS/DASH content |
| Tunnel admission leaks through a special response, reset, or stream order | **Decoy-first admission** — every media-marked stream stays on the cover path until authentication is complete |
| Custom HTTP headers expose a tunnel switch | **Browser-shaped media fetches** — authenticated streams use ordinary Chrome-style request fields |
| HTTP/2 DATA appears before a valid response | **Media response semantics** — tunnel streams send `200` and `video/mp4` headers before DATA |
| Reconnect behavior repeats a full PSK exchange | **Single-use ticket resume** — a normal authentication POST proves the cached ticket before media streams open |

## Features

<table>
<tr>
<td width="50%">

🎞️ **Functional Streaming Cover**<br>
The server renders a video portal with HLS playlists, DASH manifests, deterministic media segments, thumbnails, and JSON configuration.

🛡️ **Decoy-First Probe Handling**<br>
Missing, invalid, expired, or replayed credentials are rendered through the configured site rather than a tunnel-specific status.

🌐 **Browser-Like TLS and HTTP/2**<br>
The client uses a Chrome uTLS ClientHello by default; the HTTP/2 engine emits Chrome-family settings and media fetch headers.

🔐 **Inner Session Encryption**<br>
Segment frames are protected with AES-256-GCM using per-connection, per-stream, and per-direction key separation.

</td>
<td width="50%">

🎟️ **Single-Use Ticket Resume**<br>
Credential persistence enables a short authenticated resume POST, automatic full-handshake fallback, and ticket replay rejection.

🪢 **TCP and UDP Relay**<br>
SOCKS5 TCP CONNECT and UDP ASSOCIATE share the encrypted HTTP/2 tunnel; each UDP DATA frame preserves one datagram.

📐 **Media Traffic Pacing**<br>
Configurable burst sizes and randomized pauses shape tunnel egress like buffered media delivery.

🔄 **Automatic Recovery**<br>
The client reconnects with bounded exponential backoff and jitter, refreshes credentials, and resumes local SOCKS service.

</td>
</tr>
</table>

## Quick Start

### Build from Source

```bash
git clone https://github.com/RavenholmAlpha/SEGMENT.git
cd SEGMENT

go build -trimpath -ldflags="-s -w" -o segment-server ./cmd/segment-server
go build -trimpath -ldflags="-s -w" -o segment-client ./cmd/segment-client
```

Or use the Makefile:

```bash
make build
```

### Local Test

Generate a shared key, keep the printed value, and run both sides with an ephemeral development certificate:

```bash
PSK="$(openssl rand -hex 32)"
printf 'PSK=%s\n' "$PSK"

# Terminal 1 — server
./segment-server \
  -listen 127.0.0.1:8443 \
  -psk "$PSK" \
  -insecure \
  -pacing=true

# Terminal 2 — export the same printed PSK, then start the client
PSK="paste-the-same-value-here"
./segment-client \
  -server 127.0.0.1:8443 \
  -psk "$PSK" \
  -socks 127.0.0.1:1080 \
  -insecure
```

Verify the local SOCKS5 tunnel:

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com/
```

### Public Deployment

Use a real domain certificate, keep client certificate validation enabled, and store the session credential cache in a private local path:

```bash
# Server
./segment-server \
  -listen :443 \
  -cert /etc/segment/fullchain.pem \
  -key /etc/segment/privkey.pem \
  -psk "$PSK" \
  -pacing=true

# Client
./segment-client \
  -server video.example.com:443 \
  -sni video.example.com \
  -psk "$PSK" \
  -socks 127.0.0.1:1080 \
  -cred /var/lib/segment/client-cred.json \
  -tls-fingerprint chrome
```

Opening `https://video.example.com/` in an ordinary browser displays the cover streaming site.

## Configuration

Command-line flags override values loaded from YAML.

### Server YAML

```yaml
listen: 0.0.0.0:443
cert: /etc/segment/fullchain.pem
key: /etc/segment/privkey.pem
psk: "replace-with-at-least-32-random-bytes"

pacing:
  enabled: true
  burst_kb: 256
  min_pause_ms: 2
  max_pause_ms: 8
```

Start with:

```bash
segment-server -config /etc/segment/server.yaml
```

| Flag | Default | Description |
|:--|:--|:--|
| `-config` | — | YAML configuration file |
| `-listen` | `:443` | Public listen address |
| `-cert` | — | TLS certificate in PEM format |
| `-key` | — | TLS private key in PEM format |
| `-psk` | required | Pre-shared key of at least 32 bytes |
| `-insecure` | `false` | Generate an ephemeral self-signed development certificate |
| `-pacing` | `true` | Shape tunnel egress as media bursts |
| `-pacing-burst` | `256` | Bytes per burst in KiB |
| `-pacing-min-ms` | `2` | Minimum randomized pause |
| `-pacing-max-ms` | `8` | Maximum randomized pause |

### Client YAML

```yaml
server: video.example.com:443
sni: video.example.com
psk: "replace-with-the-same-shared-key"
socks: 127.0.0.1:1080
cred_file: /var/lib/segment/client-cred.json
tls_fingerprint: chrome
```

Start with:

```bash
segment-client -config /etc/segment/client.yaml
```

| Flag | Default | Description |
|:--|:--|:--|
| `-config` | — | YAML configuration file |
| `-server` | required | Server address in `host:port` form |
| `-sni` | server host | TLS SNI and HTTP/2 authority |
| `-psk` | required | Shared key matching the server |
| `-socks` | `127.0.0.1:1080` | Local SOCKS5 listen address |
| `-cred` | — | Persistent single-use ticket credential file |
| `-tls-fingerprint` | `chrome` | `chrome` or `go` ClientHello |
| `-cacert` | system roots | Additional private CA bundle |
| `-insecure` | `false` | Skip server certificate verification in local tests |

## Architecture

### Protocol Stack

| Layer | Responsibility |
|:--|:--|
| **TLS Front** | TLS 1.3 preferred, HTTP/2 ALPN, real certificate, Chrome-like client fingerprint |
| **Media Cover** | Functional HTTP/2 and HTTP/1.1 HLS/DASH site |
| **Admission** | Full PSK authentication or single-use ticket proof through an ordinary POST |
| **HTTP/2 Engine** | Browser-family SETTINGS, flow control, stream lifecycle, and DATA padding |
| **Segment Crypto** | AES-256-GCM frames and per-connection/per-stream key derivation |
| **Tunnel** | Encrypted control, TCP relay, UDP relay, pacing, and idle cleanup |
| **Ingress** | Local SOCKS5 TCP CONNECT and UDP ASSOCIATE |

### Connection Lifecycle

1. The client opens TLS with a browser-style ClientHello and negotiates HTTP/2.
2. A normal `POST /api/v1/telemetry` completes full PSK authentication or proves a cached ticket.
3. The server marks the HTTP/2 connection ready only after the proof is validated.
4. The client then opens a media-shaped control stream and encrypted relay streams.
5. Each accepted tunnel stream receives video-like HTTP response headers before its first DATA frame.
6. Disconnects trigger jittered reconnect; invalidated tickets automatically fall back to the full exchange.

### Anti-Detection Design

| Observation vector | SEGMENT behavior |
|:--|:--|
| **Ordinary browsing** | Serves a complete deterministic streaming site over HTTP/2 or HTTP/1.1 |
| **Unauthenticated media stream** | Uses the same configured cover-site responder, including on the first HTTP/2 stream |
| **Invalid full authentication** | Returns cover content instead of a dedicated authentication status |
| **Ticket replay** | Returns cover content while the ticket remains single-use internally |
| **TLS fingerprinting** | Chrome uTLS ClientHello is the client default |
| **HTTP/2 fingerprinting** | Browser-family settings, headers, flow control, and zero-filled randomized padding |
| **Response ordering** | `:status` and `content-type` are emitted before tunnel DATA |
| **Traffic analysis** | Burst pacing, randomized pauses, payload padding, and per-stream crypto counters |

### Ticket Resume

The server-issued ticket is opaque to the client and does not contain the session key. The client stores the ticket and key locally, then proves possession with an HMAC bound to the new connection nonce. The proof travels through the ordinary authentication POST without media markers. Only an exact success response permits the client to establish the new inner session and open media-shaped streams.

Tickets are consumed atomically after successful validation. A server key rotation naturally causes the client to run a fresh full authentication exchange and cache a new credential.

## Project Structure

```text
SEGMENT/
├── cmd/
│   ├── segment-server/       Media-fronted server binary
│   └── segment-client/       SOCKS5 client binary
├── deploy/                   YAML and systemd deployment assets
├── internal/
│   ├── auth/                 PSK exchange, tickets, resume, and replay control
│   ├── client/               TLS fingerprinting, persistence, and reconnect
│   ├── config/               YAML configuration and validation
│   ├── fakesite/             HLS/DASH cover content
│   ├── h2x/                  HTTP/2 framing, flow control, and streams
│   ├── segment/              Inner frames and AES-256-GCM session crypto
│   ├── server/               TLS/ALPN listener and cover routing
│   ├── socks5/               TCP CONNECT and UDP ASSOCIATE ingress
│   └── tunnel/               Admission, codecs, relays, and pacing
└── docs/design.md            Protocol design and threat model
```

## Deployment

| Resource | Description |
|:--|:--|
| [Deployment guide](deploy/README.md) | Domain certificate, systemd services, local client, and operations |
| [Server YAML](deploy/server.yaml.example) | Production-oriented server example |
| [Client YAML](deploy/client.yaml.example) | Production-oriented client example |
| [Server unit](deploy/segment-server.service) | systemd service definition |
| [Client unit](deploy/segment-client.service) | systemd service definition |
| [Protocol design](docs/design.md) | Authentication, encryption, HTTP/2 behavior, pacing, and test coverage |

## Testing

```bash
# Full unit and end-to-end integration suite
go test ./...

# Static analysis
go vet ./...

# Race detector
go test -race ./...

# Benchmarks
go test -bench=Benchmark -benchmem ./internal/...
```
