use anyhow::Context;
use tokio::net::TcpListener;

use crate::config::{StdioTunnelConfig, TcpClientTunnelConfig, TcpServerTunnelConfig};
use crate::proxy;
use crate::target;
use crate::wg::WireguardRuntime;

pub async fn spawn_tcp_client_tunnel(
    config: TcpClientTunnelConfig,
    runtime: WireguardRuntime,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.bind_address)
        .await
        .with_context(|| format!("tcp client tunnel bind {}", config.bind_address))?;

    tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(result) => result,
                Err(err) => {
                    log::error!("tcp client accept error: {err}");
                    continue;
                }
            };

            let runtime = runtime.clone();
            let target = config.target.clone();
            tokio::spawn(async move {
                match target::resolve_target(&runtime, &target, 0).await {
                    Ok(addr) => match runtime.connect(addr).await {
                        Ok(remote) => {
                            if let Err(err) = proxy::proxy_tcp(socket, remote).await {
                                log::error!("tcp client proxy error: {err:#}");
                            }
                        }
                        Err(err) => log::error!("tcp client connect error: {err:#}"),
                    },
                    Err(err) => log::error!("tcp client resolve error: {err:#}"),
                }
            });
        }
    });

    Ok(())
}

pub async fn spawn_tcp_server_tunnel(
    config: TcpServerTunnelConfig,
    runtime: WireguardRuntime,
) -> anyhow::Result<()> {
    tokio::spawn(async move {
        let listener = match runtime.listen(config.listen_port).await {
            Ok(listener) => listener,
            Err(err) => {
                log::error!("tcp server listen error: {err:#}");
                return;
            }
        };
        loop {
            let remote = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    log::error!("tcp server accept error: {err:#}");
                    continue;
                }
            };

            let runtime = runtime.clone();
            let target = config.target.clone();
            tokio::spawn(async move {
                match target::resolve_target(&runtime, &target, 0).await {
                    Ok(addr) => match tokio::net::TcpStream::connect(addr).await {
                        Ok(local) => {
                            if let Err(err) = proxy::proxy_tcp(local, remote).await {
                                log::error!("tcp server proxy error: {err:#}");
                            }
                        }
                        Err(err) => log::error!("tcp server local connect error: {err:#}"),
                    },
                    Err(err) => log::error!("tcp server resolve error: {err:#}"),
                }
            });
        }
    });

    Ok(())
}

pub async fn spawn_stdio_tunnel(
    config: StdioTunnelConfig,
    runtime: WireguardRuntime,
) -> anyhow::Result<()> {
    tokio::spawn(async move {
        match target::resolve_target(&runtime, &config.target, 0).await {
            Ok(addr) => match runtime.connect(addr).await {
                Ok(remote) => {
                    if let Err(err) = proxy::proxy_stdio(remote).await {
                        log::error!("stdio tunnel error: {err:#}");
                    }
                }
                Err(err) => log::error!("stdio connect error: {err:#}"),
            },
            Err(err) => log::error!("stdio resolve error: {err:#}"),
        }
    });

    Ok(())
}
