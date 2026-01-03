use anyhow::Context;

use crate::config::{Config, RoutineConfig};
use crate::wg::WireguardRuntime;

pub async fn run(config: Config, info: Option<String>) -> anyhow::Result<()> {
    log::info!("initializing wireguard runtime...");
    let runtime = WireguardRuntime::new(&config.device)
        .await
        .context("initialize wireguard runtime")?;
    runtime.start().await;
    log::info!("wireguard runtime started");

    crate::health::spawn(
        runtime.clone(),
        config.device.check_alive.clone(),
        config.device.check_alive_interval,
        info,
    )
    .await?;

    for routine in config.routines {
        match routine {
            RoutineConfig::Socks5(cfg) => {
                crate::socks5::spawn(cfg, runtime.clone()).await?;
            }
            RoutineConfig::Http(cfg) => {
                crate::http_proxy::spawn(cfg, runtime.clone()).await?;
            }
            RoutineConfig::TcpClientTunnel(cfg) => {
                crate::tunnel::spawn_tcp_client_tunnel(cfg, runtime.clone()).await?;
            }
            RoutineConfig::TcpServerTunnel(cfg) => {
                crate::tunnel::spawn_tcp_server_tunnel(cfg, runtime.clone()).await?;
            }
            RoutineConfig::StdioTunnel(cfg) => {
                crate::tunnel::spawn_stdio_tunnel(cfg, runtime.clone()).await?;
            }
        }
    }

    runtime.run().await?;
    Ok(())
}
