# Airport
Airport is a relay server for the Runway protocol.

## Configuration
Server config is loaded in this order:

1. Built-in defaults (`ServerConfig::default()`).
2. TOML file from `server.toml` in the working directory (or a path passed via `--config`).
3. Explicit CLI flag overrides for `--bind` and `--db`.

Example config is provided in `server.toml`.

Run with defaults/config file if present:
```bash
cargo run --bin airport
```

Use overrides while still using TOML defaults:
```bash
cargo run --bin airport -- --bind 0.0.0.0:32767 --db relay.db
```

Use a different config file:
```bash
cargo run --bin airport -- --config ./my-server.toml
```
