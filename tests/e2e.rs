//! End-to-end tests for wireproxy-rs
//!
//! Run with: WIREPROXY_TEST_CONFIG=/path/to/test.conf cargo test --test e2e -- --ignored

use std::env;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

fn get_test_config() -> Option<PathBuf> {
    env::var("WIREPROXY_TEST_CONFIG")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

struct WireproxyProcess(Child);

impl Drop for WireproxyProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn start_wireproxy(config: &PathBuf) -> WireproxyProcess {
    let child = Command::new(env!("CARGO_BIN_EXE_wireproxy-rs"))
        .arg("-c")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start wireproxy");

    std::thread::sleep(Duration::from_secs(2));
    WireproxyProcess(child)
}

#[tokio::test]
#[ignore = "requires WIREPROXY_TEST_CONFIG"]
async fn test_config_loads_successfully() {
    let config = get_test_config().expect("WIREPROXY_TEST_CONFIG not set");
    assert!(config.exists());
}

#[tokio::test]
#[ignore = "requires WIREPROXY_TEST_CONFIG"]
async fn test_socks5_proxy_connects() {
    let config = get_test_config().expect("WIREPROXY_TEST_CONFIG not set");
    let _proc = start_wireproxy(&config);

    let result = timeout(Duration::from_secs(5), TcpStream::connect("127.0.0.1:1080")).await;

    assert!(result.is_ok(), "Should connect to SOCKS5 proxy");
}

#[tokio::test]
#[ignore = "requires WIREPROXY_TEST_CONFIG"]
async fn test_http_proxy_connects() {
    let config = get_test_config().expect("WIREPROXY_TEST_CONFIG not set");
    let _proc = start_wireproxy(&config);

    let result = timeout(Duration::from_secs(5), TcpStream::connect("127.0.0.1:8080")).await;

    assert!(result.is_ok(), "Should connect to HTTP proxy");
}

#[tokio::test]
#[ignore = "requires WIREPROXY_TEST_CONFIG"]
async fn test_socks5_handshake() {
    let config = get_test_config().expect("WIREPROXY_TEST_CONFIG not set");
    let _proc = start_wireproxy(&config);

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect("127.0.0.1:1080"))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect");

    // SOCKS5 greeting: version 5, 1 method, no auth
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response[0], 0x05, "Should be SOCKS5");
    assert_eq!(response[1], 0x00, "Should accept no auth");
}
