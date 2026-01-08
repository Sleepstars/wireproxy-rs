use std::net::{IpAddr, SocketAddr};

use anyhow::Context;

use crate::dns;
use crate::wg::WireguardRuntime;

pub async fn resolve_target(
    runtime: &WireguardRuntime,
    target: &str,
    default_port: u16,
) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let (host, port) = split_host_port(target, default_port)?;
    if port == 0 {
        anyhow::bail!("target port is required");
    }
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => dns::resolve(runtime, &host).await?,
    };
    Ok(SocketAddr::new(ip, port))
}

pub fn split_host_port(input: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    if let Some(stripped) = input.strip_prefix('[') {
        let end = stripped.find(']').context("invalid IPv6 host")?;
        let host = &stripped[..end];
        let rest = stripped[end + 1..].trim_start_matches(':');
        let port = if rest.is_empty() {
            default_port
        } else {
            rest.parse::<u16>().context("invalid port")?
        };
        return Ok((host.to_string(), port));
    }

    let mut iter = input.rsplitn(2, ':');
    let port_str = iter.next().unwrap_or("");
    let host = iter.next().unwrap_or("");
    if host.is_empty() {
        return Err(anyhow::anyhow!("invalid host:port"));
    }
    let port = if port_str.is_empty() {
        default_port
    } else {
        port_str.parse::<u16>().context("invalid port")?
    };
    Ok((host.to_string(), port))
}
