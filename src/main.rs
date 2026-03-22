use anyhow::{Context, Result};
use airport::server::{run_tcp_server, ServerConfig};
use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "airport")]
// cli arguments which are gotten with clap
struct Cli {
    #[arg(long, default_value = "server.toml")]
    config: PathBuf,

    #[arg(long)]
    bind: Option<String>,

    #[arg(long)]
    db: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = load_server_config(&cli.config)?;

    if let Some(bind_addr) = cli.bind {
        config.bind_addr = bind_addr;
    }
    if let Some(db_path) = cli.db {
        config.db_path = db_path;
    }

    run_tcp_server(config)
}

fn load_server_config(path: &Path) -> Result<ServerConfig> {
    if !path.is_file() {
        return Ok(ServerConfig::default());
    }

    let config = load_server_config_file(path)?;
    println!("loaded server config from {}", path.display());
    Ok(config)
}

fn load_server_config_file(path: &Path) -> Result<ServerConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {} failed", path.display()))?;
    toml::from_str(&contents)
        .with_context(|| format!("parsing TOML config {} failed", path.display()))
}
