use std::io::{self, ErrorKind};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wg::WgTcpConnection;

/// Check if an error is a "normal" connection close that should be ignored
fn is_connection_closed_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
    )
}

pub async fn proxy_tcp<C>(mut client: C, mut remote: WgTcpConnection) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_buf = vec![0u8; 32 * 1024];
    let mut remote_buf = vec![0u8; 32 * 1024];

    loop {
        tokio::select! {
            result = client.read(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        // Client closed, close remote and exit
                        remote.close().await;
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = remote.write(&client_buf[..n]).await {
                            if !e.to_string().contains("closed") {
                                log::debug!("write to remote error: {e}");
                            }
                            break;
                        }
                    }
                    Err(e) if is_connection_closed_error(&e) => {
                        remote.close().await;
                        break;
                    }
                    Err(e) => {
                        log::debug!("read from client error: {e}");
                        remote.close().await;
                        break;
                    }
                }
            }
            result = remote.read(&mut remote_buf) => {
                match result {
                    Ok(0) => {
                        // Remote closed
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = client.write_all(&remote_buf[..n]).await {
                            if !is_connection_closed_error(&e) {
                                log::debug!("write to client error: {e}");
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        if !e.to_string().contains("closed") {
                            log::debug!("read from remote error: {e}");
                        }
                        break;
                    }
                }
            }
        }
    }

    remote.close().await;
    let _ = client.shutdown().await;
    Ok(())
}

pub async fn proxy_stdio(mut remote: WgTcpConnection) -> anyhow::Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stdin_buf = vec![0u8; 16 * 1024];
    let mut remote_buf = vec![0u8; 16 * 1024];

    loop {
        tokio::select! {
            result = stdin.read(&mut stdin_buf) => {
                let n = result?;
                if n == 0 {
                    remote.close().await;
                    break;
                }
                remote.write(&stdin_buf[..n]).await?;
            }
            result = remote.read(&mut remote_buf) => {
                let n = result?;
                if n == 0 {
                    break;
                }
                stdout.write_all(&remote_buf[..n]).await?;
                stdout.flush().await?;
            }
        }
    }

    remote.close().await;
    Ok(())
}
