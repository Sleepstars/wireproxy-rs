# wireproxy-rs

Userspace WireGuard client in Rust that exposes SOCKS5/HTTP proxies and TCP tunnels
without creating a TUN device. Built on `gotatun` + `tokio` with a pure userspace netstack.

## Features

- SOCKS5 proxy (TCP CONNECT, optional username/password auth)
- HTTP proxy (CONNECT + GET, optional Basic auth)
- TCP client/server tunnels and STDIO tunnel
- Health endpoints (`/metrics`, `/readyz`)
- Go wireproxy config format compatibility (WGConfig import supported)

## Build

Requirements: Rust stable toolchain.

```bash
cd wireproxy-rs
cargo build --release
```

Using `just` (optional):

```bash
just build
just build-release
```

Cross-compile helpers are included in `justfile`:

```bash
just setup-zigbuild
just build-linux
```

## Usage

```bash
wireproxy-rs -c /path/to/wireproxy.conf
wireproxy-rs -n -c /path/to/wireproxy.conf   # configtest
wireproxy-rs -i 127.0.0.1:9080 -c /path/to/wireproxy.conf
```

## Example config

```ini
[Interface]
Address = 10.200.200.2/32
PrivateKey = BASE64_PRIVATE_KEY
 DNS = 10.200.200.1
 # MTU = 1420
 # ListenPort = 51820
 # CheckAlive = 1.1.1.1,8.8.8.8
 # CheckAliveInterval = 5

[Peer]
PublicKey = BASE64_PUBLIC_KEY
Endpoint = my.ddns.example.com:51820
# PresharedKey = BASE64_PRESHARED_KEY
# PersistentKeepalive = 25
# AllowedIPs = 0.0.0.0/0,::/0

[Socks5]
BindAddress = 127.0.0.1:25344
# Username = user
# Password = pass

[http]
BindAddress = 127.0.0.1:25345
# Username = user
# Password = pass

[TCPClientTunnel]
BindAddress = 127.0.0.1:25565
Target = play.cubecraft.net:25565

[TCPServerTunnel]
ListenPort = 3422
Target = localhost:25545

[STDIOTunnel]
Target = ssh.myserver.net:22
```

You can also import a WireGuard config:

```ini
WGConfig = /path/to/wg.conf

[Socks5]
BindAddress = 127.0.0.1:25344
```

## Health endpoints

Start with `-i host:port` to enable:

- `/metrics` returns WireGuard-style stats (like `wg show`, with secrets redacted)
- `/readyz` returns last ping timestamps for `CheckAlive`

## Notes / current gaps vs Go wireproxy

- `[Peer]` without `Endpoint` (server mode) is not supported yet.
- `AllowedIPs` defaults to `0.0.0.0/0, ::/0` when omitted (Go leaves it empty).
- `[TCPClientTunnel].BindAddress` currently expects IP:port (hostnames not yet accepted).
- INI parsing does not accept `key: value` or inline comments on the same line.
