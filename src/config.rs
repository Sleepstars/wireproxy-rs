use std::env;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use ipnet::IpNet;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub device: DeviceConfig,
    pub routines: Vec<RoutineConfig>,
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub private_key: [u8; 32],
    pub addresses: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    pub mtu: usize,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerConfig>,
    pub check_alive: Vec<IpAddr>,
    pub check_alive_interval: u64,
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
    pub allowed_ips: Vec<IpNet>,
}

#[derive(Debug, Clone)]
pub enum RoutineConfig {
    Socks5(Socks5Config),
    Http(HttpConfig),
    TcpClientTunnel(TcpClientTunnelConfig),
    TcpServerTunnel(TcpServerTunnelConfig),
    StdioTunnel(StdioTunnelConfig),
}

#[derive(Debug, Clone)]
pub struct Socks5Config {
    pub bind_address: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub bind_address: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct TcpClientTunnelConfig {
    pub bind_address: SocketAddr,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct TcpServerTunnelConfig {
    pub listen_port: u16,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct StdioTunnelConfig {
    pub target: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required key: {0}")]
    MissingKey(String),
    #[error("invalid value for {key}: {reason}")]
    InvalidValue { key: String, reason: String },
    #[error("invalid base64 key for {0}")]
    InvalidKey(String),
    #[error("invalid file path: {0}")]
    InvalidPath(String),
    #[error("config error: {0}")]
    Other(String),
}

#[derive(Debug, Clone)]
struct IniSection {
    name: String,
    entries: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
struct IniFile {
    sections: Vec<IniSection>,
}

impl IniFile {
    fn sections_named(&self, name: &str) -> Vec<&IniSection> {
        let name = name.to_ascii_lowercase();
        self.sections
            .iter()
            .filter(|section| section.name == name)
            .collect()
    }

    fn root_section(&self) -> &IniSection {
        self.sections
            .iter()
            .find(|section| section.name.is_empty())
            .expect("root section always exists")
    }
}

impl IniSection {
    fn get(&self, key: &str) -> Result<Option<String>, ConfigError> {
        let key = key.to_ascii_lowercase();
        let value = self
            .entries
            .iter()
            .rev()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.clone());

        match value {
            Some(value) => Ok(Some(expand_env(value)?)),
            None => Ok(None),
        }
    }

    fn get_required(&self, key: &str) -> Result<String, ConfigError> {
        self.get(key)?
            .ok_or_else(|| ConfigError::MissingKey(key.to_string()))
    }
}

fn expand_env(value: String) -> Result<String, ConfigError> {
    if let Some(stripped) = value.strip_prefix("$$") {
        return Ok(format!("${}", stripped));
    }
    if let Some(var) = value.strip_prefix('$') {
        let env_value = env::var(var)
            .map_err(|_| ConfigError::Other(format!("{} references unset environment variable", var)))?;
        return Ok(env_value);
    }
    Ok(value)
}

pub fn parse_config(path: &Path) -> Result<Config, ConfigError> {
    let main = parse_ini(path)?;
    let root = main.root_section();
    let mut wg_ini = main.clone();

    if let Some(wg_path) = root.get("WGConfig")? {
        let wg_path = PathBuf::from(wg_path);
        wg_ini = parse_ini(&wg_path)?;
    }

    let device = parse_interface(&wg_ini)?;
    let peers = parse_peers(&wg_ini)?;

    let device = DeviceConfig { peers, ..device };

    let routines = parse_routines(&main)?;

    Ok(Config { device, routines })
}

fn parse_ini(path: &Path) -> Result<IniFile, ConfigError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::InvalidPath(format!("{}: {e}", path.display())))?;
    parse_ini_str(&content)
}

fn parse_ini_str(content: &str) -> Result<IniFile, ConfigError> {
    let mut sections = Vec::new();
    let mut current = IniSection {
        name: String::new(),
        entries: Vec::new(),
    };

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            sections.push(current);
            let name = line.trim_start_matches('[').trim_end_matches(']');
            current = IniSection {
                name: name.trim().to_ascii_lowercase(),
                entries: Vec::new(),
            };
            continue;
        }

        let mut parts = line.splitn(2, '=');
        let key = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let value = parts.next().map(str::trim);
        if let (Some(key), Some(value)) = (key, value) {
            current
                .entries
                .push((key.to_ascii_lowercase(), value.to_string()));
        }
    }

    sections.push(current);

    Ok(IniFile { sections })
}

fn parse_interface(ini: &IniFile) -> Result<DeviceConfig, ConfigError> {
    let sections = ini.sections_named("Interface");
    if sections.len() != 1 {
        return Err(ConfigError::Other(
            "one and only one [Interface] is expected".to_string(),
        ));
    }
    let section = sections[0];

    let addresses = parse_addr_list(section, "Address")?;
    let private_key = parse_base64_key(section, "PrivateKey")?;
    let dns = parse_ip_list(section, "DNS")?;

    let mtu = match section.get("MTU")? {
        Some(value) => value
            .parse::<usize>()
            .map_err(|e| ConfigError::InvalidValue {
                key: "MTU".to_string(),
                reason: e.to_string(),
            })?,
        None => 1420,
    };

    let listen_port = match section.get("ListenPort")? {
        Some(value) => {
            let port = value
                .parse::<u16>()
                .map_err(|e| ConfigError::InvalidValue {
                    key: "ListenPort".to_string(),
                    reason: e.to_string(),
                })?;
            Some(port)
        }
        None => None,
    };

    let check_alive = parse_ip_list(section, "CheckAlive")?;
    let check_alive_interval = match section.get("CheckAliveInterval")? {
        Some(value) => {
            if check_alive.is_empty() {
                return Err(ConfigError::Other(
                    "CheckAliveInterval is only valid when CheckAlive is set".to_string(),
                ));
            }
            value.parse::<u64>().map_err(|e| ConfigError::InvalidValue {
                key: "CheckAliveInterval".to_string(),
                reason: e.to_string(),
            })?
        }
        None => 5,
    };

    Ok(DeviceConfig {
        private_key,
        addresses,
        dns,
        mtu,
        listen_port,
        peers: Vec::new(),
        check_alive,
        check_alive_interval,
    })
}

fn parse_peers(ini: &IniFile) -> Result<Vec<PeerConfig>, ConfigError> {
    let sections = ini.sections_named("Peer");
    if sections.is_empty() {
        return Err(ConfigError::Other(
            "at least one [Peer] is expected".to_string(),
        ));
    }

    let mut peers = Vec::new();
    for section in sections {
        let public_key = parse_base64_key(section, "PublicKey")?;
        let preshared_key = match section.get("PreSharedKey")? {
            Some(value) => decode_base64_key(&value, "PreSharedKey")?,
            None => [0u8; 32],
        };

        let endpoint = match section.get("Endpoint")? {
            Some(value) => Some(resolve_socket_addr(&value)?),
            None => None,
        };

        let keepalive = match section.get("PersistentKeepalive")? {
            Some(value) => value
                .parse::<u16>()
                .map_err(|e| ConfigError::InvalidValue {
                    key: "PersistentKeepalive".to_string(),
                    reason: e.to_string(),
                })?,
            None => 0,
        };

        let mut allowed_ips = parse_allowed_ips(section)?;
        if allowed_ips.is_empty() {
            allowed_ips.push(IpNet::from_str("0.0.0.0/0").unwrap());
            allowed_ips.push(IpNet::from_str("::/0").unwrap());
        }

        peers.push(PeerConfig {
            public_key,
            preshared_key,
            endpoint,
            keepalive,
            allowed_ips,
        });
    }

    Ok(peers)
}

fn parse_routines(ini: &IniFile) -> Result<Vec<RoutineConfig>, ConfigError> {
    let mut routines = Vec::new();

    for section in ini.sections_named("Socks5") {
        let bind_address = section.get_required("BindAddress")?;
        let username = section.get("Username")?.unwrap_or_default();
        let password = section.get("Password")?.unwrap_or_default();
        routines.push(RoutineConfig::Socks5(Socks5Config {
            bind_address,
            username,
            password,
        }));
    }

    for section in ini.sections_named("http") {
        let bind_address = section.get_required("BindAddress")?;
        let username = section.get("Username")?.unwrap_or_default();
        let password = section.get("Password")?.unwrap_or_default();
        routines.push(RoutineConfig::Http(HttpConfig {
            bind_address,
            username,
            password,
        }));
    }

    for section in ini.sections_named("TCPClientTunnel") {
        let bind_address = section.get_required("BindAddress")?;
        let target = section.get_required("Target")?;
        let bind_address = bind_address.parse::<SocketAddr>().map_err(|e| {
            ConfigError::InvalidValue {
                key: "BindAddress".to_string(),
                reason: e.to_string(),
            }
        })?;
        routines.push(RoutineConfig::TcpClientTunnel(TcpClientTunnelConfig {
            bind_address,
            target,
        }));
    }

    for section in ini.sections_named("TCPServerTunnel") {
        let listen_port = section.get_required("ListenPort")?;
        let listen_port = listen_port.parse::<u16>().map_err(|e| ConfigError::InvalidValue {
            key: "ListenPort".to_string(),
            reason: e.to_string(),
        })?;
        let target = section.get_required("Target")?;
        routines.push(RoutineConfig::TcpServerTunnel(TcpServerTunnelConfig {
            listen_port,
            target,
        }));
    }

    for section in ini.sections_named("STDIOTunnel") {
        let target = section.get_required("Target")?;
        routines.push(RoutineConfig::StdioTunnel(StdioTunnelConfig { target }));
    }

    Ok(routines)
}

fn parse_addr_list(section: &IniSection, key: &str) -> Result<Vec<IpAddr>, ConfigError> {
    let value = section.get_required(key)?;
    parse_addr_list_value(&value, key)
}

fn parse_addr_list_value(value: &str, key: &str) -> Result<Vec<IpAddr>, ConfigError> {
    let mut addrs = Vec::new();
    for item in value.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
    let ip = parse_ip_or_prefix(trimmed).map_err(|e| ConfigError::InvalidValue {
        key: key.to_string(),
        reason: e,
    })?;
        addrs.push(ip);
    }
    Ok(addrs)
}

fn parse_ip_list(section: &IniSection, key: &str) -> Result<Vec<IpAddr>, ConfigError> {
    match section.get(key)? {
        Some(value) => parse_addr_list_value(&value, key),
        None => Ok(Vec::new()),
    }
}

fn parse_allowed_ips(section: &IniSection) -> Result<Vec<IpNet>, ConfigError> {
    let value = match section.get("AllowedIPs")? {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };

    let mut nets = Vec::new();
    for item in value.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let net = IpNet::from_str(trimmed).map_err(|e| ConfigError::InvalidValue {
            key: "AllowedIPs".to_string(),
            reason: e.to_string(),
        })?;
        nets.push(net);
    }
    Ok(nets)
}

fn parse_ip_or_prefix(input: &str) -> Result<IpAddr, String> {
    if let Ok(addr) = IpAddr::from_str(input) {
        return Ok(addr);
    }

    let mut parts = input.split('/');
    let ip_part = parts.next().unwrap_or("");
    if ip_part.is_empty() {
        return Err("invalid IP".to_string());
    }
    IpAddr::from_str(ip_part).map_err(|e| e.to_string())
}

fn parse_base64_key(section: &IniSection, key: &str) -> Result<[u8; 32], ConfigError> {
    let value = section.get_required(key)?;
    decode_base64_key(&value, key)
}

fn decode_base64_key(value: &str, key: &str) -> Result<[u8; 32], ConfigError> {
    let decoded = BASE64_STD
        .decode(value.as_bytes())
        .map_err(|_| ConfigError::InvalidKey(key.to_string()))?;
    if decoded.len() != 32 {
        return Err(ConfigError::InvalidKey(key.to_string()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn resolve_socket_addr(value: &str) -> Result<SocketAddr, ConfigError> {
    let mut addrs = value
        .to_socket_addrs()
        .map_err(|e| ConfigError::InvalidValue {
            key: "Endpoint".to_string(),
            reason: e.to_string(),
        })?;
    addrs.next().ok_or_else(|| ConfigError::Other("no endpoint found".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_interface_accepts_addr_without_prefix() {
        let ini = parse_ini_str(
            "[Interface]\nPrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=\nAddress = 10.5.0.2\n\n[Peer]\nPublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=\n",
        )
        .unwrap();

        let device = parse_interface(&ini).unwrap();
        assert_eq!(device.addresses.len(), 1);
    }
}
