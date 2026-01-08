use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::wg::WireguardRuntime;

const MAX_REQUEST_SIZE: usize = 8192;

pub async fn spawn(
    runtime: WireguardRuntime,
    check_alive: Vec<IpAddr>,
    check_alive_interval: u64,
    info_addr: Option<String>,
) -> anyhow::Result<()> {
    let ping_record = Arc::new(RwLock::new(HashMap::new()));

    if !check_alive.is_empty() {
        {
            let mut record = ping_record.write().await;
            for addr in &check_alive {
                record.insert(addr.to_string(), 0);
            }
        }

        let runtime = runtime.clone();
        let ping_record = ping_record.clone();
        tokio::spawn(async move {
            ping_loop(runtime, ping_record, check_alive, check_alive_interval).await;
        });
    }

    if let Some(addr) = info_addr {
        let runtime = runtime.clone();
        let ping_record = ping_record.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_info(addr, runtime, ping_record, check_alive_interval).await {
                log::error!("info server error: {err:#}");
            }
        });
    }

    Ok(())
}

async fn ping_loop(
    runtime: WireguardRuntime,
    ping_record: Arc<RwLock<HashMap<String, u64>>>,
    targets: Vec<IpAddr>,
    interval: u64,
) {
    let timeout = Duration::from_secs(interval);
    loop {
        for target in &targets {
            if let Err(err) = runtime.ping(*target, timeout).await {
                log::warn!("ping {target} failed: {err:#}");
                continue;
            }
            let now = unix_timestamp();
            let mut record = ping_record.write().await;
            record.insert(target.to_string(), now);
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

async fn serve_info(
    addr: String,
    runtime: WireguardRuntime,
    ping_record: Arc<RwLock<HashMap<String, u64>>>,
    interval: u64,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("info bind {addr}"))?;

    loop {
        let (socket, _) = listener.accept().await?;
        let runtime = runtime.clone();
        let ping_record = ping_record.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(socket, runtime, ping_record, interval).await {
                log::error!("info connection error: {err:#}");
            }
        });
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    runtime: WireguardRuntime,
    ping_record: Arc<RwLock<HashMap<String, u64>>>,
    interval: u64,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_SIZE];
    let mut read = 0usize;
    loop {
        if read == MAX_REQUEST_SIZE {
            break;
        }
        let n = socket.read(&mut buf[read..]).await?;
        if n == 0 {
            break;
        }
        read += n;
        if buf[..read].windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    if read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..read]);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    if method != "GET" {
        return write_response(&mut socket, 405, "Method Not Allowed", "").await;
    }

    let path = clean_path(path);
    match path.as_str() {
        "/readyz" => {
            let (status, body) = readyz_payload(&ping_record, interval).await;
            write_response(&mut socket, status, status_reason(status), &body).await
        }
        "/metrics" => {
            let metrics = runtime.metrics().await;
            let body = redact_metrics(&metrics);
            write_response(&mut socket, 200, "OK", &body).await
        }
        _ => write_response(&mut socket, 404, "Not Found", "").await,
    }
}

async fn readyz_payload(
    ping_record: &Arc<RwLock<HashMap<String, u64>>>,
    interval: u64,
) -> (u16, String) {
    let record = ping_record.read().await;
    let mut status = 200u16;
    let now = SystemTime::now();
    let max_age = Duration::from_secs(interval.saturating_add(2));
    for last_pong in record.values() {
        let when = UNIX_EPOCH + Duration::from_secs(*last_pong);
        if now
            .duration_since(when)
            .unwrap_or(Duration::from_secs(u64::MAX))
            > max_age
        {
            status = 503;
            break;
        }
    }

    let mut body = render_json(&record);
    body.push('\n');
    (status, body)
}

fn render_json(record: &HashMap<String, u64>) -> String {
    let mut out = String::from("{");
    let mut first = true;
    for (key, value) in record {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(key);
        out.push_str("\":");
        out.push_str(&value.to_string());
    }
    out.push('}');
    out
}

fn redact_metrics(metrics: &str) -> String {
    let mut out = String::new();
    for line in metrics.lines() {
        if let Some((key, value)) = line.split_once('=') {
            let value = if key == "private_key" || key == "preshared_key" {
                "REDACTED"
            } else {
                value
            };
            out.push_str(key);
            out.push('=');
            out.push_str(value);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn clean_path(path: &str) -> String {
    let trimmed = path.split('?').next().unwrap_or("");
    let mut segments = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            segments.pop();
            continue;
        }
        segments.push(part);
    }
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

async fn write_response(
    socket: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> anyhow::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}",
        body.len(),
    );
    socket.write_all(response.as_bytes()).await?;
    Ok(())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
