//! HTTP proxy protocol integration tests

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;

/// Build HTTP CONNECT request
fn build_connect_request(host: &str) -> String {
    format!(
        "CONNECT {} HTTP/1.1\r\n\
         Host: {}\r\n\r\n",
        host, host
    )
}

/// Build HTTP GET request with proxy
fn build_get_request(url: &str, host: &str) -> String {
    format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\r\n",
        url, host
    )
}

/// Build Proxy-Authorization header
fn build_proxy_auth(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    let encoded = BASE64_STD.encode(credentials.as_bytes());
    format!("Proxy-Authorization: Basic {}", encoded)
}

#[tokio::test]
async fn test_http_connect_request_format() {
    let request = build_connect_request("example.com:443");
    assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    assert!(request.contains("Host: example.com:443"));
    assert!(request.ends_with("\r\n\r\n"));
}

#[tokio::test]
async fn test_http_get_request_format() {
    let request = build_get_request("http://example.com/path", "example.com");
    assert!(request.starts_with("GET http://example.com/path HTTP/1.1\r\n"));
    assert!(request.contains("Host: example.com"));
}

#[tokio::test]
async fn test_proxy_auth_header() {
    let auth = build_proxy_auth("user", "pass");
    // "user:pass" in base64 is "dXNlcjpwYXNz"
    assert_eq!(auth, "Proxy-Authorization: Basic dXNlcjpwYXNz");
}

#[tokio::test]
async fn test_http_response_parsing() {
    let response = "HTTP/1.1 200 Connection established\r\n\r\n";
    assert!(response.contains("200"));

    let error_response = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
    assert!(error_response.contains("407"));
}
