//! Opaque store-and-forward protocol for untrusted assist relays.
//!
//! Relays route ciphertext envelopes by recipient device id only.
//! They must never parse event plaintext or crypto payloads.

use serde::{Deserialize, Serialize};
use td_event::{DeviceId, RoomId};
use thiserror::Error;

/// Opaque ciphertext envelope. Relay treats `ciphertext` as an uninterpreted blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayEnvelope {
    /// Content id = blake3(ciphertext || recipient || sender || ts)
    pub envelope_id: [u8; 32],
    pub recipient_device: DeviceId,
    pub sender_device: DeviceId,
    /// Optional routing hint only — not opened by relay.
    pub room_id: Option<RoomId>,
    pub ciphertext: Vec<u8>,
    pub ts_ms: u64,
}

impl RelayEnvelope {
    pub fn new(
        recipient_device: DeviceId,
        sender_device: DeviceId,
        room_id: Option<RoomId>,
        ciphertext: Vec<u8>,
        ts_ms: u64,
    ) -> Self {
        let mut material = Vec::with_capacity(ciphertext.len() + 32 + 32 + 8);
        material.extend_from_slice(&ciphertext);
        material.extend_from_slice(&recipient_device.0);
        material.extend_from_slice(&sender_device.0);
        material.extend_from_slice(&ts_ms.to_le_bytes());
        let envelope_id = *blake3::hash(&material).as_bytes();
        Self {
            envelope_id,
            recipient_device,
            sender_device,
            room_id,
            ciphertext,
            ts_ms,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RelayRequest {
    /// Deposit an opaque envelope for later fetch by recipient.
    Put { envelope: RelayEnvelope },
    /// Fetch envelopes for a recipient with ts >= since_ts (exclusive of acked).
    Fetch {
        recipient: DeviceId,
        since_ts: u64,
        limit: u32,
    },
    /// Drop envelopes after successful local ingest (best-effort on relay).
    Ack {
        recipient: DeviceId,
        envelope_ids: Vec<[u8; 32]>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RelayResponse {
    Ok,
    Envelopes { items: Vec<RelayEnvelope> },
    Err { message: String },
}

#[derive(Debug, Error)]
pub enum RelayProtoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("frame too large: {0}")]
    TooLarge(u32),
    #[error("connection closed")]
    Closed,
}

const MAX_FRAME: u32 = 16 * 1024 * 1024;

pub async fn write_json<W: tokio::io::AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    value: &T,
) -> Result<(), RelayProtoError> {
    use tokio::io::AsyncWriteExt;
    let body = serde_json::to_vec(value)?;
    let len = body.len() as u32;
    if len > MAX_FRAME {
        return Err(RelayProtoError::TooLarge(len));
    }
    w.write_u32(len).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_json<R: tokio::io::AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> Result<T, RelayProtoError> {
    use tokio::io::AsyncReadExt;
    let len = match r.read_u32().await {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(RelayProtoError::Closed)
        }
        Err(e) => return Err(e.into()),
    };
    if len > MAX_FRAME {
        return Err(RelayProtoError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}
