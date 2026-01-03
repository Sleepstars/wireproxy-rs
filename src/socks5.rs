use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Socks5Config;
use crate::dns;
use crate::proxy;
use crate::wg::WireguardRuntime;

pub async fn spawn(config: Socks5Config, runtime: WireguardRuntime) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.bind_address)
        .await
        .with_context(|| format!("socks5 bind {}", config.bind_address))?;

    log::info!("socks5 proxy listening on {}", config.bind_address);

    tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(result) => result,
                Err(err) => {
                    log::error!("socks5 accept error: {err}");
                    continue;
                }
            };

            let runtime = runtime.clone();
            let config = config.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_client(socket, config, runtime).await {
                    log::error!("socks5 client error: {err:#}");
                }
            });
        }
    });

    Ok(())
}

async fn handle_client(
    mut socket: TcpStream,
    config: Socks5Config,
    runtime: WireguardRuntime,
) -> anyhow::Result<()> {
    if !negotiate_auth(&mut socket, &config).await? {
        return Ok(());
    }

    let request = read_request(&mut socket).await?;
    if request.cmd != CMD_CONNECT {
        reply(&mut socket, REP_COMMAND_NOT_SUPPORTED).await?;
        return Ok(());
    }

    let target_addr = resolve_target(&runtime, request).await?;
    let remote = match runtime.connect(target_addr).await {
        Ok(remote) => remote,
        Err(err) => {
            log::error!("socks5 connect error: {err:#}");
            reply(&mut socket, REP_GENERAL_FAILURE).await?;
            return Ok(());
        }
    };

    reply(&mut socket, REP_SUCCESS).await?;
    proxy::proxy_tcp(socket, remote).await?;
    Ok(())
}

async fn resolve_target(runtime: &WireguardRuntime, request: SocksRequest) -> anyhow::Result<SocketAddr> {
    match request.addr {
        SocksAddr::Ip(ip) => Ok(SocketAddr::new(ip, request.port)),
        SocksAddr::Domain(domain) => {
            let ip = dns::resolve(runtime, &domain).await?;
            Ok(SocketAddr::new(ip, request.port))
        }
    }
}

async fn negotiate_auth(socket: &mut TcpStream, config: &Socks5Config) -> anyhow::Result<bool> {
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        anyhow::bail!("unsupported socks version {}", header[0]);
    }

    let methods_len = header[1] as usize;
    let mut methods = vec![0u8; methods_len];
    socket.read_exact(&mut methods).await?;

    let needs_auth = !config.username.is_empty();
    let selected = if needs_auth {
        if methods.contains(&METHOD_USER_PASS) {
            METHOD_USER_PASS
        } else {
            METHOD_NO_ACCEPT
        }
    } else if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NO_ACCEPT
    };

    socket.write_all(&[SOCKS_VERSION, selected]).await?;
    if selected == METHOD_NO_ACCEPT {
        return Ok(false);
    }

    if selected == METHOD_USER_PASS {
        return Ok(verify_user_pass(socket, config).await?);
    }

    Ok(true)
}

async fn verify_user_pass(socket: &mut TcpStream, config: &Socks5Config) -> anyhow::Result<bool> {
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;
    if header[0] != USERPASS_VERSION {
        socket.write_all(&[USERPASS_VERSION, USERPASS_STATUS_FAIL]).await?;
        return Ok(false);
    }

    let user_len = header[1] as usize;
    let mut user = vec![0u8; user_len];
    socket.read_exact(&mut user).await?;

    let mut pass_len = [0u8; 1];
    socket.read_exact(&mut pass_len).await?;
    let pass_len = pass_len[0] as usize;
    let mut pass = vec![0u8; pass_len];
    socket.read_exact(&mut pass).await?;

    let ok = user == config.username.as_bytes() && pass == config.password.as_bytes();
    let status = if ok { USERPASS_STATUS_OK } else { USERPASS_STATUS_FAIL };
    socket.write_all(&[USERPASS_VERSION, status]).await?;
    Ok(ok)
}

async fn read_request(socket: &mut TcpStream) -> anyhow::Result<SocksRequest> {
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        anyhow::bail!("unsupported socks version {}", header[0]);
    }

    let cmd = header[1];
    let atyp = header[3];

    let addr = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            socket.read_exact(&mut ip).await?;
            SocksAddr::Ip(IpAddr::V4(Ipv4Addr::from(ip)))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            socket.read_exact(&mut ip).await?;
            SocksAddr::Ip(IpAddr::V6(Ipv6Addr::from(ip)))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let len = len[0] as usize;
            let mut domain = vec![0u8; len];
            socket.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain)?;
            SocksAddr::Domain(domain)
        }
        _ => {
            reply(socket, REP_ADDR_TYPE_NOT_SUPPORTED).await?;
            anyhow::bail!("unsupported address type {}", atyp);
        }
    };

    let mut port_buf = [0u8; 2];
    socket.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(SocksRequest { cmd, addr, port })
}

async fn reply(socket: &mut TcpStream, reply: u8) -> anyhow::Result<()> {
    let response = [
        SOCKS_VERSION,
        reply,
        0x00,
        ATYP_IPV4,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    socket.write_all(&response).await?;
    Ok(())
}

enum SocksAddr {
    Ip(IpAddr),
    Domain(String),
}

struct SocksRequest {
    cmd: u8,
    addr: SocksAddr,
    port: u16,
}

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPT: u8 = 0xFF;
const USERPASS_VERSION: u8 = 0x01;
const USERPASS_STATUS_OK: u8 = 0x00;
const USERPASS_STATUS_FAIL: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;
