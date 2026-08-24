# Segment 一键部署参考

拓扑：`浏览器/App → SOCKS5 127.0.0.1:1080 → segment-client ——(TLS 1.3, h2)——→ segment-server(:443, VPS) → 目标`

```
VPS（segment-server）                 本机 / 网关（segment-client）
/opt/segment/bin/segment-server       /opt/segment/bin/segment-client
/etc/segment/server.yaml              /etc/segment/client.yaml
/etc/segment/{fullchain,privkey}.pem  /var/lib/segment/client-cred.json
```

## 1. VPS（服务器）

```bash
# 用户与目录
useradd -r -s /usr/sbin/nologin segment
mkdir -p /opt/segment/bin /etc/segment
# 拷贝二进制 + 样例并填写:
#   deploy/server.yaml.example -> /etc/segment/server.yaml
#   （填真实 PSK；cert/key 指向下面签发的证书）
cp deploy/segment-server.service /etc/systemd/system/

# 证书（Let's Encrypt，域名须解析到本机）
apt install certbot
certbot certonly --standalone -d vps.example.com
# 或: certbot certonly --webroot ... 

systemctl daemon-reload && systemctl enable --now segment-server
systemctl status segment-server
journalctl -u segment-server -f

# 防火墙：仅 443/tcp
```

验证伪装站（任何人可见）：`curl https://vps.example.com/` 应返回一个正常流媒体站页面。

## 2. 本地（客户端）

```bash
mkdir -p /opt/segment/bin /etc/segment /var/lib/segment
# 拷贝二进制 + 样例并填写:
#   deploy/client.yaml.example -> /etc/segment/client.yaml
#   （server/sni 指向 vps.example.com:443，psk 与服务端一致）
cp deploy/segment-client.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now segment-client

# 验证隧道
curl -x socks5h://127.0.0.1:1080 https://example.com/   # 应 200
```

## 3. PSK 与证书续期

- PSK：`openssl rand -hex 32` 生成（64 hex 字符），两端一致。换 PSK 时客户端自动重握，无需逐个重启。
- 证书续期：certbot renew 后重启服务端加载新证书：
  ```bash
  # /etc/letsencrypt/renewal-hooks/deploy/segment-reload.sh
  #!/bin/sh
  systemctl reload segment-server
  ```

## 4. 运维注意

- 服务端重启会使存量会话票据作废（密钥在内存），客户端 30 秒内自动回退完整握手，业务无感知。
- 客户端 `cred_file` 权限 0600，只装本用户可读。
- SOCKS 只绑 127.0.0.1；如需局域网共享，自行权衡暴露面后再改 `socks` 字段。
- 隧道内 UDP 数据报上限 16KB；标准 DNS/QUIC 无影响。
- 全球上网延迟 = VPS 往返；跨洋场景选临近区域 VPS。