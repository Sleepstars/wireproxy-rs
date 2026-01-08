mod app;
mod buffer;
mod config;
mod dns;
mod health;
mod http_proxy;
mod netstack;
mod proxy;
mod socks5;
mod target;
mod tunnel;
mod wg;

use std::path::PathBuf;

use clap::Parser;
use config::Config;

#[derive(Parser, Debug)]
#[command(
    name = "wireproxy-rs",
    about = "Userspace wireguard client for proxying"
)]
struct Args {
    /// Path of configuration file
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Configtest mode. Only check the configuration file for validity.
    #[arg(short = 'n', long = "configtest")]
    configtest: bool,

    /// Specify the address and port for exposing health status
    #[arg(short = 'i', long = "info")]
    info: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let config_path = match args.config {
        Some(path) => path,
        None => default_config_path()
            .ok_or_else(|| anyhow::anyhow!("configuration path is required"))?,
    };

    let config = config::parse_config(&config_path)?;

    if args.configtest {
        println!("Config OK");
        return Ok(());
    }

    app::run(config, args.info).await
}

fn default_config_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    candidates.push(PathBuf::from("/etc/wireproxy/wireproxy.conf"));
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join(".config/wireproxy.conf"));
    }

    candidates.into_iter().find(|path| path.exists())
}

// Keep the config in scope for modules that need type visibility.
#[allow(dead_code)]
fn _use_config(_config: &Config) {}
