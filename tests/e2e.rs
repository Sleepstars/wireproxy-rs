//! End-to-end tests for wireproxy-rs
//!
//! Run with: WIREPROXY_TEST_CONFIG=/path/to/test.conf cargo test --test e2e -- --ignored

use std::env;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

// E2E tests bind fixed local ports from the config; run them serially to avoid
// port conflicts and one test killing the other's process.
static E2E_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
struct RoutineAddrs {
    socks5_bind: String,
    http_bind: String,
    socks5_username: String,
    socks5_password: String,
}

fn parse_routine_addrs(config: &PathBuf) -> RoutineAddrs {
    let content = std::fs::read_to_string(config)
        .unwrap_or_else(|e| panic!("failed to read config {}: {e}", config.display()));

    let mut section = String::new();

    let mut socks5_bind: Option<String> = None;
    let mut socks5_username: Option<String> = None;
    let mut socks5_password: Option<String> = None;

    let mut http_bind: Option<String> = None;

    for raw_line in content.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Strip simple inline comments.
        if let Some(idx) = line.find('#') {
            line = &line[..idx];
        }
        if let Some(idx) = line.find(';') {
            line = &line[..idx];
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if section.eq_ignore_ascii_case("Socks5") {
            if key.eq_ignore_ascii_case("BindAddress") {
                socks5_bind = Some(value.to_string());
            } else if key.eq_ignore_ascii_case("Username") {
                socks5_username = Some(value.to_string());
            } else if key.eq_ignore_ascii_case("Password") {
                socks5_password = Some(value.to_string());
            }
        } else if section.eq_ignore_ascii_case("http") && key.eq_ignore_ascii_case("BindAddress") {
            http_bind = Some(value.to_string());
        }
    }

    RoutineAddrs {
        socks5_bind: socks5_bind.unwrap_or_else(|| "127.0.0.1:1080".to_string()),
        http_bind: http_bind.unwrap_or_else(|| "127.0.0.1:8080".to_string()),
        socks5_username: socks5_username.unwrap_or_default(),
        socks5_password: socks5_password.unwrap_or_default(),
    }
}

fn get_test_config() -> Option<PathBuf> {
    env::var("WIREPROXY_TEST_CONFIG")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

fn require_test_config() -> PathBuf {
    match get_test_config() {
        Some(p) => p,
        None => {
            eprintln!("Skipping E2E test: set WIREPROXY_TEST_CONFIG to an existing config file");
            std::process::exit(0);
        }
    }
}

struct WireproxyProcess(Child);

impl Drop for WireproxyProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn start_wireproxy(config: &PathBuf) -> WireproxyProcess {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wireproxy-rs"))
        .arg("-c")
        .arg(config)
        // Keep stderr so failing tests show why the process exited.
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start wireproxy");

    std::thread::sleep(Duration::from_secs(2));

    // If the process died during startup (e.g. bind error), fail fast.
    if let Ok(Some(status)) = child.try_wait() {
        panic!("wireproxy-rs exited during startup: {status}");
    }

    WireproxyProcess(child)
}

#[tokio::test]
#[ignore = "requires WIREPROXY_TEST_CONFIG"]
async fn test_config_loads_successfully() {
    let _guard = E2E_LOCK.lock().await;
    let config = require_test_config();
    assert!(config.exists());
}

#[tokio::test]
#[ignore = "requires WIREPROXY_TEST_CONFIG"]
async fn test_socks5_proxy_connects() {
    let _guard = E2E_LOCK.lock().await;
    let config = require_test_config();
    let addrs = parse_routine_addrs(&config);
    let _proc = start_wireproxy(&config);

    let result = timeout(
        Duration::from_secs(5),
        TcpStream::connect(&addrs.socks5_bind),
    )
    .await;

    assert!(result.is_ok(), "Should connect to SOCKS5 proxy");
}

#[tokio::test]
#[ignore = "requires WIREPROXY_TEST_CONFIG"]
async fn test_http_proxy_connects() {
    let _guard = E2E_LOCK.lock().await;
    let config = require_test_config();
    let addrs = parse_routine_addrs(&config);
    let _proc = start_wireproxy(&config);

    let result = timeout(Duration::from_secs(5), TcpStream::connect(&addrs.http_bind)).await;

    assert!(result.is_ok(), "Should connect to HTTP proxy");
}

#[tokio::test]
#[ignore = "requires WIREPROXY_TEST_CONFIG"]
async fn test_socks5_handshake() {
    let _guard = E2E_LOCK.lock().await;
    let config = require_test_config();
    let addrs = parse_routine_addrs(&config);
    let _proc = start_wireproxy(&config);

    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(&addrs.socks5_bind),
    )
    .await
    .expect("Connection timeout")
    .expect("Failed to connect");

    let wants_auth = !addrs.socks5_username.is_empty();

    // SOCKS5 greeting: version 5, methods
    // If the server requires user/pass, advertise both methods so negotiation succeeds.
    let greeting: Vec<u8> = if wants_auth {
        vec![0x05, 0x02, 0x00, 0x02] // no-auth + user/pass
    } else {
        vec![0x05, 0x01, 0x00] // no-auth only
    };

    stream.write_all(&greeting).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response[0], 0x05, "Should be SOCKS5");

    if wants_auth {
        assert_eq!(response[1], 0x02, "Should require user/pass");

        // RFC1929 username/password sub-negotiation.
        // VER=1, ULEN, UNAME, PLEN, PASSWD
        let mut auth = Vec::new();
        auth.push(0x01);
        auth.push(addrs.socks5_username.len() as u8);
        auth.extend_from_slice(addrs.socks5_username.as_bytes());
        auth.push(addrs.socks5_password.len() as u8);
        auth.extend_from_slice(addrs.socks5_password.as_bytes());

        stream.write_all(&auth).await.unwrap();
        stream.flush().await.unwrap();

        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(auth_resp[0], 0x01, "Should be user/pass subnegotiation");
        assert_eq!(auth_resp[1], 0x00, "Auth should succeed");
    } else {
        assert_eq!(response[1], 0x00, "Should accept no auth");
    }
}
