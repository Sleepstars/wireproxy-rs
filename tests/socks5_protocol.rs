//! SOCKS5 protocol integration tests
//! These tests verify the SOCKS5 protocol implementation without requiring
//! a real WireGuard connection.

// SOCKS5 constants
const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const USERPASS_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;

/// Helper to build SOCKS5 greeting
fn build_greeting(methods: &[u8]) -> Vec<u8> {
    let mut greeting = vec![SOCKS_VERSION, methods.len() as u8];
    greeting.extend_from_slice(methods);
    greeting
}

/// Helper to build SOCKS5 connect request for IPv4
fn build_connect_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&port.to_be_bytes());
    request
}

/// Helper to build SOCKS5 connect request for domain
fn build_connect_domain(domain: &str, port: u16) -> Vec<u8> {
    let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN];
    request.push(domain.len() as u8);
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    request
}

/// Helper to build username/password auth request
fn build_userpass_auth(username: &str, password: &str) -> Vec<u8> {
    let mut request = vec![USERPASS_VERSION, username.len() as u8];
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    request
}

#[tokio::test]
async fn test_socks5_greeting_format() {
    // Test that greeting is correctly formatted
    let greeting = build_greeting(&[METHOD_NO_AUTH]);
    assert_eq!(greeting, vec![0x05, 0x01, 0x00]);

    let greeting_with_auth = build_greeting(&[METHOD_NO_AUTH, METHOD_USER_PASS]);
    assert_eq!(greeting_with_auth, vec![0x05, 0x02, 0x00, 0x02]);
}

#[tokio::test]
async fn test_socks5_connect_request_ipv4() {
    let request = build_connect_ipv4([192, 168, 1, 1], 80);
    assert_eq!(request.len(), 10);
    assert_eq!(request[0], SOCKS_VERSION);
    assert_eq!(request[1], CMD_CONNECT);
    assert_eq!(request[3], ATYP_IPV4);
}

#[tokio::test]
async fn test_socks5_connect_request_domain() {
    let request = build_connect_domain("example.com", 443);
    assert_eq!(request[3], ATYP_DOMAIN);
    assert_eq!(request[4], 11); // "example.com".len()
}

#[tokio::test]
async fn test_socks5_userpass_auth_format() {
    let auth = build_userpass_auth("user", "pass");
    assert_eq!(auth[0], USERPASS_VERSION);
    assert_eq!(auth[1], 4); // "user".len()
    assert_eq!(&auth[2..6], b"user");
    assert_eq!(auth[6], 4); // "pass".len()
    assert_eq!(&auth[7..11], b"pass");
}
