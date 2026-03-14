use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAuth {
    pub credential_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signed_at_unix_ms: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub recipient_rid: String,
    pub ciphertext: Vec<u8>,
    pub created_at_unix_ms: u64,
}

impl EncryptedBlob {
    pub fn new(recipient_rid: impl Into<String>, ciphertext: Vec<u8>) -> Self {
        Self {
            recipient_rid: recipient_rid.into(),
            ciphertext,
            created_at_unix_ms: unix_ms_now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientPacket {
    IssueRid { auth: RequestAuth },
    RotateRid { rid: String, auth: RequestAuth },
    PutBlob { blob: EncryptedBlob },
    FetchQueued { rid: String, auth: RequestAuth },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerPacket {
    RidIssued {
        rid: String,
        expires_at_unix_ms: u64,
    },
    RidRotated {
        old_rid: String,
        new_rid: String,
        expires_at_unix_ms: u64,
    },
    Accepted {
        rid: String,
        queued: usize,
    },
    QueuedBlobs {
        rid: String,
        blobs: Vec<EncryptedBlob>,
    },
    Error {
        message: String,
    },
}

pub fn credential_fingerprint(public_key: &[u8]) -> Vec<u8> {
    Sha256::digest(public_key).to_vec()
}

pub fn auth_signing_payload(action: &str, body: &[u8], auth: &RequestAuth) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut payload = Vec::with_capacity(96 + auth.nonce.len());
    payload.extend_from_slice(b"runway-auth-v1");

    let action_bytes = action.as_bytes();
    payload.extend_from_slice(&(action_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(action_bytes);

    payload.extend_from_slice(&(body_hash.len() as u32).to_be_bytes());
    payload.extend_from_slice(&body_hash);

    payload.extend_from_slice(&auth.signed_at_unix_ms.to_be_bytes());
    payload.extend_from_slice(&(auth.nonce.len() as u32).to_be_bytes());
    payload.extend_from_slice(&auth.nonce);
    payload
}

pub fn encode_packet<T: Serialize>(packet: &T) -> Result<Vec<u8>> {
    let bytes = serde_cbor::to_vec(packet).context("encoding packet as CBOR failed")?;
    Ok(bytes)
}

pub fn decode_packet<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T> {
    let packet = serde_cbor::from_slice(bytes).context("decoding CBOR packet failed")?;
    Ok(packet)
}

pub fn write_framed<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let len: u32 = payload
        .len()
        .try_into()
        .context("payload too large to frame")?;

    writer
        .write_all(&len.to_be_bytes())
        .context("writing frame length failed")?;
    writer
        .write_all(payload)
        .context("writing frame payload failed")?;
    writer.flush().context("flushing framed payload failed")?;
    Ok(())
}

pub fn read_framed<R: Read>(reader: &mut R, max_payload_bytes: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0_u8; 4];
    reader
        .read_exact(&mut len_buf)
        .context("reading frame length failed")?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_payload_bytes {
        bail!(
            "frame length {} exceeds configured maximum {}",
            len,
            max_payload_bytes
        );
    }

    let mut payload = vec![0_u8; len];
    reader
        .read_exact(&mut payload)
        .context("reading frame payload failed")?;
    Ok(payload)
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
