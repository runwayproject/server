use librunway::transport::{
    auth_signing_payload, credential_fingerprint, decode_packet, encode_packet, read_framed,
    write_framed, ClientPacket, EncryptedBlob, RequestAuth, ServerPacket,
};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngExt;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub max_frame_bytes: usize,
    pub max_blob_bytes: usize,
    pub max_queue_per_rid: usize,
    pub db_path: String,
    pub rid_ttl_ms: u64,
    pub max_auth_skew_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:32767".to_string(),
            max_frame_bytes: 2 * 1024 * 1024,
            max_blob_bytes: 1024 * 1024,
            max_queue_per_rid: 512,
            db_path: "relay.db".to_string(),
            rid_ttl_ms: 24 * 60 * 60 * 1000, // 86 400 000 ms (24h)
            max_auth_skew_ms: 5 * 60 * 1000,
        }
    }
}

pub struct RelayState {
    db: Mutex<Connection>,
}

pub fn run_tcp_server(config: ServerConfig) -> Result<()> {
    let conn = open_database(&config.db_path)?;
    let state = Arc::new(RelayState {
        db: Mutex::new(conn),
    });

    let listener = TcpListener::bind(&config.bind_addr)
        .with_context(|| format!("binding TCP listener on {} failed", config.bind_addr))?;
    println!(
        "relay server listening on {} with db {}",
        config.bind_addr, config.db_path
    );

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("accept failed: {err}");
                continue;
            }
        };

        let state = Arc::clone(&state);
        let config = config.clone();

        thread::spawn(move || {
            if let Err(err) = handle_connection(stream, state, &config) {
                eprintln!("connection error: {err:#}");
            }
        });
    }

    Ok(())
}

fn open_database(path: &str) -> Result<Connection> {
    let conn = Connection::open(Path::new(path))
        .with_context(|| format!("opening SQLite database at {} failed", path))?;

    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS rid_owners (
            rid TEXT PRIMARY KEY,
            owner_fingerprint BLOB NOT NULL,
            expires_at_unix_ms INTEGER NOT NULL,
            created_at_unix_ms INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rid TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            created_at_unix_ms INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_blobs_rid ON blobs(rid);
        ",
    )
    .context("initializing database schema failed")?;

    Ok(conn)
}

fn handle_connection(
    mut stream: TcpStream,
    state: Arc<RelayState>,
    config: &ServerConfig,
) -> Result<()> {
    loop {
        let frame = match read_framed(&mut stream, config.max_frame_bytes) {
            Ok(bytes) => bytes,
            Err(err) => {
                if let Some(ioe) = err.downcast_ref::<std::io::Error>() {
                    if ioe.kind() == std::io::ErrorKind::UnexpectedEof {
                        return Ok(());
                    }
                }
                return Err(err).context("reading framed client packet failed");
            }
        };

        let packet: ClientPacket = decode_packet(&frame).context("invalid client packet")?;
        let response = process_packet(packet, &state, config);

        let response = match response {
            Ok(packet) => packet,
            Err(err) => ServerPacket::Error {
                message: err.to_string(),
            },
        };

        let bytes = encode_packet(&response).context("encoding server response failed")?;
        write_framed(&mut stream, &bytes).context("writing server response failed")?;
    }
}

fn process_packet(
    packet: ClientPacket,
    state: &Arc<RelayState>,
    config: &ServerConfig,
) -> Result<ServerPacket> {
    match packet {
        ClientPacket::IssueRid { auth } => {
            let owner_fp = verify_request_auth(&auth, "issue_rid", b"", config)?;

            let mut db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            purge_expired_rids(&mut db)?;

            let rid = generate_rid();
            let expires = unix_ms_now().saturating_add(config.rid_ttl_ms);
            db.execute(
                "INSERT INTO rid_owners (rid, owner_fingerprint, expires_at_unix_ms, created_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                params![rid, owner_fp, expires as i64, unix_ms_now() as i64],
            )
            .context("issuing rid failed")?;

            Ok(ServerPacket::RidIssued {
                rid,
                expires_at_unix_ms: expires,
            })
        }
        ClientPacket::RotateRid { rid, auth } => {
            validate_rid(&rid)?;
            let owner_fp = verify_request_auth(&auth, "rotate_rid", rid.as_bytes(), config)?;

            let mut db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            purge_expired_rids(&mut db)?;
            ensure_owner(&db, &rid, &owner_fp)?;

            let new_rid = generate_rid();
            let expires = unix_ms_now().saturating_add(config.rid_ttl_ms);

            let tx = db
                .transaction()
                .context("starting rotate transaction failed")?;
            tx.execute("DELETE FROM rid_owners WHERE rid = ?1", params![rid])
                .context("deleting old rid failed")?;

            tx.execute(
                "INSERT INTO rid_owners (rid, owner_fingerprint, expires_at_unix_ms, created_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                params![new_rid, owner_fp, expires as i64, unix_ms_now() as i64],
            )
            .context("inserting new rid failed")?;

            tx.execute(
                "UPDATE blobs SET rid = ?1 WHERE rid = ?2",
                params![new_rid, rid],
            )
            .context("moving queued blobs to new rid failed")?;
            tx.commit().context("rotate transaction commit failed")?;

            Ok(ServerPacket::RidRotated {
                old_rid: rid,
                new_rid,
                expires_at_unix_ms: expires,
            })
        }
        ClientPacket::PutBlob { blob } => {
            validate_blob(&blob, config)?;

            let rid = blob.recipient_rid.clone();
            let mut db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            purge_expired_rids(&mut db)?;
            ensure_rid_exists(&db, &rid)?;

            let tx = db
                .transaction()
                .context("starting blob transaction failed")?;
            let count: i64 = tx
                .query_row(
                    "SELECT COUNT(1) FROM blobs WHERE rid = ?1",
                    params![rid],
                    |row| row.get(0),
                )
                .context("counting queued blobs failed")?;

            let overflow = (count as usize)
                .saturating_add(1)
                .saturating_sub(config.max_queue_per_rid);
            if overflow > 0 {
                tx.execute(
                    "DELETE FROM blobs WHERE id IN (SELECT id FROM blobs WHERE rid = ?1 ORDER BY id ASC LIMIT ?2)",
                    params![rid, overflow as i64],
                )
                .context("evicting old queued blobs failed")?;
            }

            tx.execute(
                "INSERT INTO blobs (rid, ciphertext, created_at_unix_ms) VALUES (?1, ?2, ?3)",
                params![rid, blob.ciphertext, blob.created_at_unix_ms as i64],
            )
            .context("inserting blob failed")?;

            let queued: i64 = tx
                .query_row(
                    "SELECT COUNT(1) FROM blobs WHERE rid = ?1",
                    params![rid],
                    |row| row.get(0),
                )
                .context("counting queued blobs after insert failed")?;
            tx.commit().context("blob transaction commit failed")?;

            Ok(ServerPacket::Accepted {
                rid,
                queued: queued as usize,
            })
        }
        ClientPacket::FetchQueued { rid, auth } => {
            validate_rid(&rid)?;
            let owner_fp = verify_request_auth(&auth, "fetch_queued", rid.as_bytes(), config)?;

            let mut db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
            purge_expired_rids(&mut db)?;
            ensure_owner(&db, &rid, &owner_fp)?;

            let tx = db
                .transaction()
                .context("starting fetch transaction failed")?;
            let mut stmt = tx
                .prepare("SELECT ciphertext, created_at_unix_ms FROM blobs WHERE rid = ?1 ORDER BY id ASC")
                .context("preparing blob fetch query failed")?;

            let rows = stmt
                .query_map(params![rid], |row| {
                    Ok(EncryptedBlob {
                        recipient_rid: rid.clone(),
                        ciphertext: row.get(0)?,
                        created_at_unix_ms: row.get::<_, i64>(1)? as u64,
                    })
                })
                .context("querying queued blobs failed")?;

            let mut blobs = Vec::new();
            for row in rows {
                blobs.push(row.context("reading queued blob row failed")?);
            }
            drop(stmt);

            tx.execute("DELETE FROM blobs WHERE rid = ?1", params![rid])
                .context("deleting delivered blobs failed")?;
            tx.commit().context("fetch transaction commit failed")?;

            Ok(ServerPacket::QueuedBlobs { rid, blobs })
        }
    }
}

fn purge_expired_rids(db: &mut Connection) -> Result<()> {
    db.execute(
        "DELETE FROM rid_owners WHERE expires_at_unix_ms <= ?1",
        params![unix_ms_now() as i64],
    )
    .context("purging expired rids failed")?;
    Ok(())
}

fn ensure_rid_exists(db: &Connection, rid: &str) -> Result<()> {
    let found: i64 = db
        .query_row(
            "SELECT COUNT(1) FROM rid_owners WHERE rid = ?1",
            params![rid],
            |row| row.get(0),
        )
        .context("checking rid existence failed")?;

    if found == 0 {
        bail!("unknown or expired rid");
    }
    Ok(())
}

fn ensure_owner(db: &Connection, rid: &str, owner_fp: &[u8]) -> Result<()> {
    let db_owner: Vec<u8> = db
        .query_row(
            "SELECT owner_fingerprint FROM rid_owners WHERE rid = ?1",
            params![rid],
            |row| row.get(0),
        )
        .context("loading rid owner failed")?;

    if db_owner != owner_fp {
        bail!("rid is not owned by the authenticated credential");
    }
    Ok(())
}

fn verify_request_auth(
    auth: &RequestAuth,
    action: &str,
    body: &[u8],
    config: &ServerConfig,
) -> Result<Vec<u8>> {
    validate_request_auth_shape(auth)?;

    let now = unix_ms_now();
    let min_acceptable = now.saturating_sub(config.max_auth_skew_ms);
    let max_acceptable = now.saturating_add(config.max_auth_skew_ms);
    if auth.signed_at_unix_ms < min_acceptable || auth.signed_at_unix_ms > max_acceptable {
        bail!("request timestamp outside accepted skew window");
    }

    let vk = VerifyingKey::from_bytes(
        auth.credential_public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("credential_public_key must be 32 bytes"))?,
    )
    .context("invalid ed25519 public key")?;

    let signature =
        Signature::from_slice(&auth.signature).context("invalid ed25519 signature encoding")?;
    let payload = auth_signing_payload(action, body, auth);
    vk.verify(&payload, &signature)
        .context("request signature verification failed")?;

    Ok(credential_fingerprint(&auth.credential_public_key))
}

fn validate_blob(blob: &EncryptedBlob, config: &ServerConfig) -> Result<()> {
    validate_rid(&blob.recipient_rid)?;
    if blob.ciphertext.is_empty() {
        bail!("ciphertext must not be empty");
    }
    if blob.ciphertext.len() > config.max_blob_bytes {
        bail!(
            "ciphertext {} exceeds max blob size {}",
            blob.ciphertext.len(),
            config.max_blob_bytes
        );
    }
    Ok(())
}

fn validate_rid(rid: &str) -> Result<()> {
    let trimmed = rid.trim();
    if trimmed.is_empty() {
        bail!("rid must not be empty");
    }
    if trimmed.len() > 255 {
        bail!("rid too long");
    }
    Ok(())
}

fn validate_request_auth_shape(auth: &RequestAuth) -> Result<()> {
    if auth.credential_public_key.len() != 32 {
        bail!("credential_public_key must be exactly 32 bytes");
    }
    if auth.nonce.len() < 12 {
        bail!("nonce must be at least 12 bytes");
    }
    if auth.signature.len() != 64 {
        bail!("signature must be exactly 64 bytes for ed25519");
    }
    Ok(())
}

fn generate_rid() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);

    let mut out = String::with_capacity(32);
    for b in bytes {
        out.push(nibble_to_hex((b >> 4) & 0x0f));
        out.push(nibble_to_hex(b & 0x0f));
    }
    out
}

fn nibble_to_hex(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        _ => (b'a' + (v - 10)) as char,
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
