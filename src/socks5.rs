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

async fn resolve_target(
    runtime: &WireguardRuntime,
    request: SocksRequest,
) -> anyhow::Result<SocketAddr> {
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
    socket.flush().await?;
    if selected == METHOD_NO_ACCEPT {
        return Ok(false);
    }

    if selected == METHOD_USER_PASS {
        return verify_user_pass(socket, config).await;
    }

    Ok(true)
}

async fn verify_user_pass(socket: &mut TcpStream, config: &Socks5Config) -> anyhow::Result<bool> {
    let mut header = [0u8; 2];
    socket.read_exact(&mut header).await?;
    if header[0] != USERPASS_VERSION {
        socket
            .write_all(&[USERPASS_VERSION, USERPASS_STATUS_FAIL])
            .await?;
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
    let status = if ok {
        USERPASS_STATUS_OK
    } else {
        USERPASS_STATUS_FAIL
    };
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

// SOCKS5 protocol constants
pub(crate) const SOCKS_VERSION: u8 = 0x05;
pub(crate) const METHOD_NO_AUTH: u8 = 0x00;
pub(crate) const METHOD_USER_PASS: u8 = 0x02;
pub(crate) const METHOD_NO_ACCEPT: u8 = 0xFF;
pub(crate) const USERPASS_VERSION: u8 = 0x01;
pub(crate) const USERPASS_STATUS_OK: u8 = 0x00;
pub(crate) const USERPASS_STATUS_FAIL: u8 = 0x01;
pub(crate) const CMD_CONNECT: u8 = 0x01;
pub(crate) const ATYP_IPV4: u8 = 0x01;
pub(crate) const ATYP_DOMAIN: u8 = 0x03;
pub(crate) const ATYP_IPV6: u8 = 0x04;
pub(crate) const REP_SUCCESS: u8 = 0x00;
pub(crate) const REP_GENERAL_FAILURE: u8 = 0x01;
pub(crate) const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub(crate) const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_version_is_correct() {
        assert_eq!(SOCKS_VERSION, 0x05);
    }

    #[test]
    fn auth_methods_are_correct() {
        assert_eq!(METHOD_NO_AUTH, 0x00);
        assert_eq!(METHOD_USER_PASS, 0x02);
        assert_eq!(METHOD_NO_ACCEPT, 0xFF);
    }

    #[test]
    fn address_types_are_correct() {
        assert_eq!(ATYP_IPV4, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x03);
        assert_eq!(ATYP_IPV6, 0x04);
    }

    #[test]
    fn reply_codes_are_correct() {
        assert_eq!(REP_SUCCESS, 0x00);
        assert_eq!(REP_GENERAL_FAILURE, 0x01);
        assert_eq!(REP_COMMAND_NOT_SUPPORTED, 0x07);
        assert_eq!(REP_ADDR_TYPE_NOT_SUPPORTED, 0x08);
    }

    #[test]
    fn build_greeting_no_auth() {
        // Client greeting: version + nmethods + methods
        let greeting = [SOCKS_VERSION, 0x01, METHOD_NO_AUTH];
        assert_eq!(greeting[0], 0x05);
        assert_eq!(greeting[1], 0x01); // 1 method
        assert_eq!(greeting[2], 0x00); // NO AUTH
    }

    #[test]
    fn build_greeting_with_auth() {
        let greeting = [SOCKS_VERSION, 0x02, METHOD_NO_AUTH, METHOD_USER_PASS];
        assert_eq!(greeting.len(), 4);
        assert_eq!(greeting[1], 0x02); // 2 methods
    }

    #[test]
    fn build_connect_request_ipv4() {
        // CONNECT to 192.168.1.1:80
        let mut request = vec![
            SOCKS_VERSION,
            CMD_CONNECT,
            0x00, // reserved
            ATYP_IPV4,
            192,
            168,
            1,
            1, // IP
        ];
        request.extend_from_slice(&80u16.to_be_bytes()); // port

        assert_eq!(request.len(), 10);
        assert_eq!(request[3], ATYP_IPV4);
    }

    #[test]
    fn build_connect_request_domain() {
        // CONNECT to example.com:443
        let domain = b"example.com";
        let mut request = vec![
            SOCKS_VERSION,
            CMD_CONNECT,
            0x00,
            ATYP_DOMAIN,
            domain.len() as u8,
        ];
        request.extend_from_slice(domain);
        request.extend_from_slice(&443u16.to_be_bytes());

        assert_eq!(request[3], ATYP_DOMAIN);
        assert_eq!(request[4], 11); // domain length
    }

    #[test]
    fn build_connect_request_ipv6() {
        // CONNECT to ::1:8080
        let ipv6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV6];
        request.extend_from_slice(&ipv6);
        request.extend_from_slice(&8080u16.to_be_bytes());

        assert_eq!(request.len(), 22); // 4 + 16 + 2
        assert_eq!(request[3], ATYP_IPV6);
    }

    #[test]
    fn parse_server_choice_no_auth() {
        let response = [SOCKS_VERSION, METHOD_NO_AUTH];
        assert_eq!(response[0], SOCKS_VERSION);
        assert_eq!(response[1], METHOD_NO_AUTH);
    }

    #[test]
    fn parse_server_choice_user_pass() {
        let response = [SOCKS_VERSION, METHOD_USER_PASS];
        assert_eq!(response[1], METHOD_USER_PASS);
    }

    #[test]
    fn parse_server_choice_no_accept() {
        let response = [SOCKS_VERSION, METHOD_NO_ACCEPT];
        assert_eq!(response[1], METHOD_NO_ACCEPT);
    }

    #[test]
    fn parse_connect_reply_success() {
        let reply = [
            SOCKS_VERSION,
            REP_SUCCESS,
            0x00,
            ATYP_IPV4,
            0,
            0,
            0,
            0, // bound addr
            0,
            0, // bound port
        ];
        assert_eq!(reply[1], REP_SUCCESS);
    }

    #[test]
    fn parse_connect_reply_failure() {
        let reply = [
            SOCKS_VERSION,
            REP_GENERAL_FAILURE,
            0x00,
            ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(reply[1], REP_GENERAL_FAILURE);
    }

    #[test]
    fn build_userpass_request() {
        let user = b"testuser";
        let pass = b"testpass";

        let mut request = vec![USERPASS_VERSION, user.len() as u8];
        request.extend_from_slice(user);
        request.push(pass.len() as u8);
        request.extend_from_slice(pass);

        assert_eq!(request[0], USERPASS_VERSION);
        assert_eq!(request[1], 8); // username length
    }

    #[test]
    fn parse_userpass_response_ok() {
        let response = [USERPASS_VERSION, USERPASS_STATUS_OK];
        assert_eq!(response[1], USERPASS_STATUS_OK);
    }

    #[test]
    fn parse_userpass_response_fail() {
        let response = [USERPASS_VERSION, USERPASS_STATUS_FAIL];
        assert_eq!(response[1], USERPASS_STATUS_FAIL);
    }
}
