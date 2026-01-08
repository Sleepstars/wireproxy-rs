use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::HttpConfig;
use crate::proxy;
use crate::wg::WireguardRuntime;

const DEFAULT_USER_AGENT: &str = "Go-http-client/1.1";

pub async fn spawn(config: HttpConfig, runtime: WireguardRuntime) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.bind_address)
        .await
        .with_context(|| format!("http bind {}", config.bind_address))?;

    log::info!("http proxy listening on {}", config.bind_address);

    tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(result) => result,
                Err(err) => {
                    log::error!("http accept error: {err}");
                    continue;
                }
            };

            let runtime = runtime.clone();
            let config = config.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_client(socket, config, runtime).await {
                    log::error!("http client error: {err:#}");
                }
            });
        }
    });

    Ok(())
}

async fn handle_client(
    mut client: TcpStream,
    config: HttpConfig,
    runtime: WireguardRuntime,
) -> anyhow::Result<()> {
    let (req, extra) = match read_request(&mut client).await {
        Ok(req) => req,
        Err(err) => {
            log::error!("read request failed: {err}");
            return Ok(());
        }
    };

    if let Err(auth) = authenticate(&config, &req) {
        write_response_with(&mut client, &req, auth.code(), auth.needs_proxy_auth()).await?;
        log::error!("{auth}");
        return Ok(());
    }

    match req.method.as_str() {
        "CONNECT" => {
            if let Err(err) = handle_connect(&mut client, &runtime, &req, &extra).await {
                log::error!("dial proxy failed: {err:#}");
            }
        }
        "GET" => {
            if let Err(err) = handle_get(&mut client, &runtime, &req, &extra).await {
                log::error!("dial proxy failed: {err:#}");
            }
        }
        _ => {
            write_response_with(&mut client, &req, 405, false).await?;
            log::error!("unsupported protocol: {}", req.method);
        }
    }

    Ok(())
}

async fn handle_connect(
    client: &mut TcpStream,
    runtime: &WireguardRuntime,
    req: &ParsedRequest,
    extra: &[u8],
) -> anyhow::Result<()> {
    let addr = default_port_addr(&req.host, 443);
    let target_addr = resolve_target_strict(runtime, &addr).await?;
    let mut remote = runtime.connect(target_addr).await?;
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    if !extra.is_empty() {
        remote.write(extra).await?;
    }
    proxy::proxy_tcp(client, remote).await?;
    Ok(())
}

async fn handle_get(
    client: &mut TcpStream,
    runtime: &WireguardRuntime,
    req: &ParsedRequest,
    extra: &[u8],
) -> anyhow::Result<()> {
    let addr = default_port_addr(&req.host, 80);
    let target_addr = resolve_target_strict(runtime, &addr).await?;
    let mut remote = runtime.connect(target_addr).await?;

    let request_bytes = build_request_bytes(req)?;
    remote.write(&request_bytes).await?;
    if !extra.is_empty() {
        remote.write(extra).await?;
    }
    proxy::proxy_tcp(client, remote).await?;
    Ok(())
}

async fn read_request(client: &mut TcpStream) -> anyhow::Result<(ParsedRequest, Vec<u8>)> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("connection closed");
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_header_end(&buf).is_some() {
            break;
        }
    }

    let mut headers_storage = vec![httparse::EMPTY_HEADER; 64];
    let header_len;
    let req = loop {
        let mut req = httparse::Request::new(&mut headers_storage);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => {
                header_len = len;
                break req;
            }
            Ok(httparse::Status::Partial) => {
                anyhow::bail!("incomplete request");
            }
            Err(httparse::Error::TooManyHeaders) => {
                headers_storage = vec![httparse::EMPTY_HEADER; headers_storage.len() * 2];
                continue;
            }
            Err(err) => {
                anyhow::bail!("http parse error: {err:?}");
            }
        }
    };

    let method = req
        .method
        .ok_or_else(|| anyhow::anyhow!("missing method"))?;
    let raw_uri = req
        .path
        .ok_or_else(|| anyhow::anyhow!("missing request uri"))?;
    let version = req
        .version
        .ok_or_else(|| anyhow::anyhow!("missing http version"))?;
    let (proto, proto_major, proto_minor) = parse_proto(version)?;

    let mut host_header = None;
    let mut host_count = 0usize;
    let mut parsed_headers = Vec::new();
    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("Host") {
            host_count += 1;
            if host_header.is_none() {
                host_header = header_value_bytes(header)
                    .map(|value| String::from_utf8_lossy(value).to_string());
            }
        } else {
            parsed_headers.push(OwnedHeader::from(header));
        }
    }
    if host_count > 1 {
        anyhow::bail!("too many Host headers");
    }

    let parsed_uri = parse_request_uri(method, raw_uri);
    let host = match parsed_uri.host {
        Some(host) => host,
        None => host_header.unwrap_or_default(),
    };

    fix_pragma_cache_control(&mut parsed_headers);

    let request = ParsedRequest {
        method: method.to_string(),
        proto,
        proto_major,
        proto_minor,
        headers: parsed_headers,
        host,
        path: parsed_uri.path,
    };
    let extra = buf[header_len..].to_vec();
    Ok((request, extra))
}

fn parse_proto(version: u8) -> anyhow::Result<(String, u8, u8)> {
    let proto = format!("HTTP/1.{}", version);
    Ok((proto, 1, version))
}

fn parse_request_uri(method: &str, raw_uri: &str) -> ParsedUri {
    if method == "CONNECT" && !raw_uri.starts_with('/') {
        return ParsedUri {
            host: Some(raw_uri.to_string()),
            path: String::new(),
        };
    }

    if let Some(parsed) = parse_absolute_uri(raw_uri) {
        return parsed;
    }

    let mut path = raw_uri.to_string();
    if let Some(fragment) = path.find('#') {
        path.truncate(fragment);
    }
    if path.is_empty() {
        path = "/".to_string();
    }
    ParsedUri { host: None, path }
}

fn parse_absolute_uri(raw_uri: &str) -> Option<ParsedUri> {
    let scheme_end = raw_uri.find("://")?;
    let rest = &raw_uri[scheme_end + 3..];
    let mut host_end = rest.len();
    for (idx, ch) in rest.char_indices() {
        if ch == '/' || ch == '?' || ch == '#' {
            host_end = idx;
            break;
        }
    }
    let host = rest[..host_end].to_string();
    let mut path = &rest[host_end..];
    if let Some(fragment) = path.find('#') {
        path = &path[..fragment];
    }
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{}", path)
    } else {
        path.to_string()
    };
    Some(ParsedUri {
        host: Some(host),
        path,
    })
}

fn fix_pragma_cache_control(headers: &mut Vec<OwnedHeader>) {
    let mut pragma_no_cache = false;
    let mut has_cache_control = false;
    for header in headers.iter() {
        if header.name.eq_ignore_ascii_case("Pragma") && header.value == b"no-cache" {
            pragma_no_cache = true;
        }
        if header.name.eq_ignore_ascii_case("Cache-Control") {
            has_cache_control = true;
        }
    }
    if pragma_no_cache && !has_cache_control {
        headers.push(OwnedHeader {
            name: "Cache-Control".to_string(),
            value: b"no-cache".to_vec(),
        });
    }
}

fn authenticate(config: &HttpConfig, req: &ParsedRequest) -> Result<(), AuthError> {
    if config.username.is_empty() && config.password.is_empty() {
        return Ok(());
    }

    let Some(value) = header_value(&req.headers, "Proxy-Authorization") else {
        return Err(AuthError::ProxyAuthRequired);
    };

    let value = value.trim();
    let encoded = value.strip_prefix("Basic ").unwrap_or(value);
    let decoded = BASE64_STD
        .decode(encoded.as_bytes())
        .map_err(|_| AuthError::NotAcceptable)?;
    let mut parts = decoded.splitn(2, |b| *b == b':');
    let user = parts.next().unwrap_or(&[]);
    let Some(pass) = parts.next() else {
        return Err(AuthError::LengthRequired);
    };

    let user_ok = constant_time_eq(config.username.as_bytes(), user) as u8;
    let pass_ok = constant_time_eq(config.password.as_bytes(), pass) as u8;
    if user_ok & pass_ok == 1 {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn build_request_bytes(req: &ParsedRequest) -> anyhow::Result<Vec<u8>> {
    if req.host.is_empty() {
        anyhow::bail!("missing host");
    }

    let mut ruri = req.path.as_str();
    if ruri.is_empty() {
        ruri = "/";
    }
    let mut out = String::new();
    out.push_str(&format!("{} {} HTTP/1.1\r\n", req.method, ruri));
    out.push_str(&format!("Host: {}\r\n", req.host));

    if let Some(user_agent) = header_value(&req.headers, "User-Agent") {
        let value = sanitize_header_value(user_agent);
        if !value.is_empty() {
            out.push_str("User-Agent: ");
            out.push_str(&value);
            out.push_str("\r\n");
        }
    } else {
        out.push_str("User-Agent: ");
        out.push_str(DEFAULT_USER_AGENT);
        out.push_str("\r\n");
    }

    let transfer_encoding_values = header_values(&req.headers, "Transfer-Encoding");
    let content_length = content_length(&req.headers)?;

    let has_chunked = transfer_encoding_values
        .iter()
        .any(|value| has_chunked_encoding(value));

    let should_send_content_length = matches!(content_length, Some(len) if len > 0);

    let should_send_transfer_encoding = !should_send_content_length && has_chunked;

    let close = should_close(req.proto_major, req.proto_minor, &req.headers);
    if close && !connection_has_close(&req.headers) {
        out.push_str("Connection: close\r\n");
    }

    for header in &req.headers {
        if should_skip_header(&header.name) {
            continue;
        }
        out.push_str(&header.name);
        out.push_str(": ");
        out.push_str(&String::from_utf8_lossy(&header.value));
        out.push_str("\r\n");
    }

    if should_send_content_length {
        out.push_str("Content-Length: ");
        out.push_str(&content_length.unwrap_or(0).to_string());
        out.push_str("\r\n");
    } else if should_send_transfer_encoding {
        out.push_str("Transfer-Encoding: chunked\r\n");
    }

    out.push_str("\r\n");
    Ok(out.into_bytes())
}

fn should_skip_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "user-agent" | "content-length" | "transfer-encoding" | "trailer"
    )
}

fn content_length(headers: &[OwnedHeader]) -> anyhow::Result<Option<u64>> {
    let values = header_values(headers, "Content-Length");
    if values.is_empty() {
        return Ok(None);
    }

    let mut parsed = None;
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(anyhow::anyhow!("invalid Content-Length"));
        }
        let len = trimmed
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid Content-Length"))?;
        if let Some(existing) = parsed {
            if existing != len {
                return Err(anyhow::anyhow!("multiple Content-Length values"));
            }
        } else {
            parsed = Some(len);
        }
    }
    Ok(parsed)
}

fn header_values(headers: &[OwnedHeader], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .filter_map(|header| std::str::from_utf8(&header.value).ok())
        .map(|value| value.to_string())
        .collect()
}

fn has_chunked_encoding(value: &str) -> bool {
    value
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
}

fn should_close(major: u8, minor: u8, headers: &[OwnedHeader]) -> bool {
    if major < 1 {
        return true;
    }
    let has_close = connection_has_close(headers);
    if major == 1 && minor == 0 {
        return has_close || !connection_has_token(headers, "keep-alive");
    }
    has_close
}

fn connection_has_close(headers: &[OwnedHeader]) -> bool {
    connection_has_token(headers, "close")
}

fn connection_has_token(headers: &[OwnedHeader], token: &str) -> bool {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("Connection"))
        .filter_map(|h| std::str::from_utf8(&h.value).ok())
        .flat_map(|value| value.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

fn sanitize_header_value(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '\r' || ch == '\n' {
            output.push(' ');
        } else {
            output.push(ch);
        }
    }
    output.trim().to_string()
}

async fn write_response_with(
    client: &mut TcpStream,
    req: &ParsedRequest,
    status: u16,
    proxy_authenticate: bool,
) -> anyhow::Result<()> {
    let status_text = status_text(status);
    let body = format!("wireproxy: {} {} {}\r\n", req.proto, status, status_text);
    let mut response = format!(
        "HTTP/{}.{} {:03} {}\r\n",
        req.proto_major, req.proto_minor, status, status_text
    );
    if proxy_authenticate {
        response.push_str("Proxy-Authenticate: Basic realm=\"Proxy\"\r\n");
    }
    response.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    response.push_str(&body);
    client.write_all(response.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

fn status_text(status: u16) -> &'static str {
    match status {
        401 => "Unauthorized",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        411 => "Length Required",
        _ => "",
    }
}

fn default_port_addr(host: &str, default_port: u16) -> String {
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:{default_port}")
    }
}

async fn resolve_target_strict(
    runtime: &WireguardRuntime,
    target: &str,
) -> anyhow::Result<std::net::SocketAddr> {
    if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }

    let (host, port) = split_host_port_required(target)?;
    let ip = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => crate::dns::resolve(runtime, &host).await?,
    };
    Ok(std::net::SocketAddr::new(ip, port))
}

fn split_host_port_required(input: &str) -> anyhow::Result<(String, u16)> {
    if let Some(stripped) = input.strip_prefix('[') {
        let end = stripped.find(']').context("invalid IPv6 host")?;
        let host = &stripped[..end];
        let rest = stripped[end + 1..].trim_start_matches(':');
        if rest.is_empty() {
            anyhow::bail!("target port is required");
        }
        let port = rest.parse::<u16>().context("invalid port")?;
        return Ok((host.to_string(), port));
    }

    let mut iter = input.rsplitn(2, ':');
    let port_str = iter.next().unwrap_or("");
    let host = iter.next().unwrap_or("");
    if host.is_empty() || port_str.is_empty() {
        anyhow::bail!("target port is required");
    }
    let port = port_str.parse::<u16>().context("invalid port")?;
    Ok((host.to_string(), port))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn header_value<'a>(headers: &'a [OwnedHeader], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .and_then(|header| std::str::from_utf8(&header.value).ok())
}

fn header_value_bytes<'a>(header: &'a httparse::Header<'a>) -> Option<&'a [u8]> {
    if header.value.is_empty() {
        None
    } else {
        Some(header.value)
    }
}

#[derive(Clone)]
struct OwnedHeader {
    name: String,
    value: Vec<u8>,
}

impl<'a> From<httparse::Header<'a>> for OwnedHeader {
    fn from(header: httparse::Header<'a>) -> Self {
        OwnedHeader {
            name: canonical_header_name(header.name),
            value: header.value.to_vec(),
        }
    }
}

impl<'a> From<&httparse::Header<'a>> for OwnedHeader {
    fn from(header: &httparse::Header<'a>) -> Self {
        OwnedHeader {
            name: canonical_header_name(header.name),
            value: header.value.to_vec(),
        }
    }
}

fn canonical_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for ch in name.chars() {
        if ch == '-' {
            out.push(ch);
            upper = true;
            continue;
        }
        if upper {
            out.push(ch.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

struct ParsedUri {
    host: Option<String>,
    path: String,
}

struct ParsedRequest {
    method: String,
    proto: String,
    proto_major: u8,
    proto_minor: u8,
    headers: Vec<OwnedHeader>,
    host: String,
    path: String,
}

#[derive(Debug)]
enum AuthError {
    ProxyAuthRequired,
    NotAcceptable,
    LengthRequired,
    Unauthorized,
}

impl AuthError {
    fn code(&self) -> u16 {
        match self {
            AuthError::ProxyAuthRequired => 407,
            AuthError::NotAcceptable => 406,
            AuthError::LengthRequired => 411,
            AuthError::Unauthorized => 401,
        }
    }

    fn needs_proxy_auth(&self) -> bool {
        matches!(self, AuthError::ProxyAuthRequired)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::ProxyAuthRequired => write!(f, "Proxy Authentication Required"),
            AuthError::NotAcceptable => write!(f, "decode username and password failed"),
            AuthError::LengthRequired => write!(f, "username and password format invalid"),
            AuthError::Unauthorized => write!(f, "username and password not matching"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_uri_connect() {
        let result = parse_request_uri("CONNECT", "example.com:443");
        assert_eq!(result.host, Some("example.com:443".to_string()));
        assert_eq!(result.path, "");
    }

    #[test]
    fn parse_request_uri_absolute() {
        let result = parse_request_uri("GET", "http://example.com/path");
        assert_eq!(result.host, Some("example.com".to_string()));
        assert_eq!(result.path, "/path");
    }

    #[test]
    fn parse_request_uri_absolute_with_port() {
        let result = parse_request_uri("GET", "http://example.com:8080/path");
        assert_eq!(result.host, Some("example.com:8080".to_string()));
        assert_eq!(result.path, "/path");
    }

    #[test]
    fn parse_request_uri_relative() {
        let result = parse_request_uri("GET", "/path/to/resource");
        assert_eq!(result.host, None);
        assert_eq!(result.path, "/path/to/resource");
    }

    #[test]
    fn parse_request_uri_empty_becomes_slash() {
        let result = parse_request_uri("GET", "");
        assert_eq!(result.path, "/");
    }

    #[test]
    fn parse_absolute_uri_with_query() {
        let result = parse_absolute_uri("http://example.com?query=1");
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert_eq!(parsed.host, Some("example.com".to_string()));
        assert_eq!(parsed.path, "/?query=1");
    }

    #[test]
    fn parse_absolute_uri_strips_fragment() {
        let result = parse_absolute_uri("http://example.com/path#fragment");
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert_eq!(parsed.path, "/path");
    }

    #[test]
    fn default_port_addr_with_port() {
        let result = default_port_addr("example.com:8080", 443);
        assert_eq!(result, "example.com:8080");
    }

    #[test]
    fn default_port_addr_without_port() {
        let result = default_port_addr("example.com", 443);
        assert_eq!(result, "example.com:443");
    }

    #[test]
    fn split_host_port_ipv4() {
        let result = split_host_port_required("192.168.1.1:8080");
        assert!(result.is_ok());
        let (host, port) = result.unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn split_host_port_ipv6() {
        let result = split_host_port_required("[::1]:8080");
        assert!(result.is_ok());
        let (host, port) = result.unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn split_host_port_domain() {
        let result = split_host_port_required("example.com:443");
        assert!(result.is_ok());
        let (host, port) = result.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn split_host_port_missing_port() {
        let result = split_host_port_required("example.com");
        assert!(result.is_err());
    }

    #[test]
    fn find_header_end_found() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        let result = find_header_end(buf);
        assert!(result.is_some());
    }

    #[test]
    fn find_header_end_not_found() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        let result = find_header_end(buf);
        assert!(result.is_none());
    }

    #[test]
    fn canonical_header_name_simple() {
        assert_eq!(canonical_header_name("content-type"), "Content-Type");
        assert_eq!(canonical_header_name("CONTENT-TYPE"), "Content-Type");
        assert_eq!(canonical_header_name("Content-Type"), "Content-Type");
    }

    #[test]
    fn canonical_header_name_multi_dash() {
        assert_eq!(canonical_header_name("x-custom-header"), "X-Custom-Header");
    }

    fn make_header(name: &str, value: &[u8]) -> OwnedHeader {
        OwnedHeader {
            name: name.to_string(),
            value: value.to_vec(),
        }
    }

    #[test]
    fn header_value_found() {
        let headers = vec![make_header("Content-Type", b"text/html")];
        let result = header_value(&headers, "Content-Type");
        assert_eq!(result, Some("text/html"));
    }

    #[test]
    fn header_value_case_insensitive() {
        let headers = vec![make_header("Content-Type", b"text/html")];
        let result = header_value(&headers, "content-type");
        assert_eq!(result, Some("text/html"));
    }

    #[test]
    fn header_value_not_found() {
        let headers = vec![make_header("Content-Type", b"text/html")];
        let result = header_value(&headers, "Accept");
        assert!(result.is_none());
    }

    #[test]
    fn header_values_multiple() {
        let headers = vec![
            make_header("Accept", b"text/html"),
            make_header("Accept", b"application/json"),
        ];
        let result = header_values(&headers, "Accept");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn connection_has_close_true() {
        let headers = vec![make_header("Connection", b"close")];
        assert!(connection_has_close(&headers));
    }

    #[test]
    fn connection_has_close_false() {
        let headers = vec![make_header("Connection", b"keep-alive")];
        assert!(!connection_has_close(&headers));
    }

    #[test]
    fn connection_has_token_in_list() {
        let headers = vec![make_header("Connection", b"keep-alive, close")];
        assert!(connection_has_token(&headers, "close"));
        assert!(connection_has_token(&headers, "keep-alive"));
    }

    #[test]
    fn should_close_http10_no_keepalive() {
        let headers: Vec<OwnedHeader> = vec![];
        assert!(should_close(1, 0, &headers));
    }

    #[test]
    fn should_close_http11_default() {
        let headers: Vec<OwnedHeader> = vec![];
        assert!(!should_close(1, 1, &headers));
    }

    #[test]
    fn should_close_http11_with_close() {
        let headers = vec![make_header("Connection", b"close")];
        assert!(should_close(1, 1, &headers));
    }

    #[test]
    fn content_length_present() {
        let headers = vec![make_header("Content-Length", b"100")];
        let result = content_length(&headers).unwrap();
        assert_eq!(result, Some(100));
    }

    #[test]
    fn content_length_absent() {
        let headers: Vec<OwnedHeader> = vec![];
        let result = content_length(&headers).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn content_length_invalid() {
        let headers = vec![make_header("Content-Length", b"not-a-number")];
        let result = content_length(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn content_length_conflicting() {
        let headers = vec![
            make_header("Content-Length", b"100"),
            make_header("Content-Length", b"200"),
        ];
        let result = content_length(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn has_chunked_encoding_true() {
        assert!(has_chunked_encoding("chunked"));
        assert!(has_chunked_encoding("gzip, chunked"));
        assert!(has_chunked_encoding("chunked, gzip"));
    }

    #[test]
    fn has_chunked_encoding_false() {
        assert!(!has_chunked_encoding("gzip"));
        assert!(!has_chunked_encoding(""));
    }

    #[test]
    fn sanitize_header_value_normal() {
        let result = sanitize_header_value("Mozilla/5.0");
        assert_eq!(result, "Mozilla/5.0");
    }

    #[test]
    fn sanitize_header_value_with_newlines() {
        let result = sanitize_header_value("value\r\ninjected");
        assert_eq!(result, "value  injected");
    }

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"password", b"password"));
    }

    #[test]
    fn constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"password", b"passwor"));
        assert!(!constant_time_eq(b"password", b"PASSWORD"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn auth_error_codes() {
        assert_eq!(AuthError::ProxyAuthRequired.code(), 407);
        assert_eq!(AuthError::NotAcceptable.code(), 406);
        assert_eq!(AuthError::LengthRequired.code(), 411);
        assert_eq!(AuthError::Unauthorized.code(), 401);
    }

    #[test]
    fn auth_error_needs_proxy_auth() {
        assert!(AuthError::ProxyAuthRequired.needs_proxy_auth());
        assert!(!AuthError::Unauthorized.needs_proxy_auth());
    }

    #[test]
    fn status_text_known() {
        assert_eq!(status_text(401), "Unauthorized");
        assert_eq!(status_text(407), "Proxy Authentication Required");
    }

    #[test]
    fn status_text_unknown() {
        assert_eq!(status_text(999), "");
    }

    #[test]
    fn parse_proto_http10() {
        let (proto, major, minor) = parse_proto(0).unwrap();
        assert_eq!(proto, "HTTP/1.0");
        assert_eq!(major, 1);
        assert_eq!(minor, 0);
    }

    #[test]
    fn parse_proto_http11() {
        let (proto, major, minor) = parse_proto(1).unwrap();
        assert_eq!(proto, "HTTP/1.1");
        assert_eq!(major, 1);
        assert_eq!(minor, 1);
    }
}
