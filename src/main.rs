use anyhow::Result;
use runway_server::server::{run_tcp_server, ServerConfig};

fn main() -> Result<()> {
    let mut config = ServerConfig::default();

    let mut args = std::env::args().skip(1);
    if let Some(bind_addr) = args.next() {
        config.bind_addr = bind_addr;
    }
    if let Some(db_path) = args.next() {
        config.db_path = db_path;
    }

    run_tcp_server(config)
}
