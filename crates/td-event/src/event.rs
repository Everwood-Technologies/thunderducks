use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 32-byte content-addressed event id (blake3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub [u8; 32]);

impl std::fmt::Debug for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EventId({})", hex::encode(self.0))
    }
}

impl EventId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoomId(pub [u8; 32]);

impl RoomId {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl std::fmt::Debug for RoomId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoomId({})", hex::encode(self.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 32]);

impl DeviceId {
    /// Device id = blake3(verifying_key_bytes) for stable addressing.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        let hash = blake3::hash(vk.as_bytes());
        Self(*hash.as_bytes())
    }
}

impl std::fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceId({})", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    CreateRoom,
    Membership,
    Message,
    DeviceLink,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedEvent {
    pub room_id: RoomId,
    pub parents: Vec<EventId>,
    pub kind: EventKind,
    pub payload: Vec<u8>,
    pub author_device: DeviceId,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEvent {
    pub id: EventId,
    pub room_id: RoomId,
    pub parents: Vec<EventId>,
    pub kind: EventKind,
    pub payload: Vec<u8>,
    pub author_device: DeviceId,
    pub ts_ms: u64,
    /// ed25519 verifying key bytes (32)
    pub author_vk: [u8; 32],
    /// ed25519 signature bytes as vec for serde compatibility (len 64)
    pub signature: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum EventError {
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid verifying key")]
    InvalidVerifyingKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("event id mismatch")]
    IdMismatch,
    #[error("author device does not match verifying key")]
    AuthorMismatch,
}

/// Canonical bytes used for both signing and content-addressing.
/// Signature and id fields are excluded from the signed body.
pub fn body_bytes(ev: &UnsignedEvent, author_vk: &[u8; 32]) -> Result<Vec<u8>, EventError> {
    #[derive(Serialize)]
    struct Body<'a> {
        room_id: &'a RoomId,
        parents: &'a [EventId],
        kind: EventKind,
        payload: &'a [u8],
        author_device: &'a DeviceId,
        ts_ms: u64,
        author_vk: &'a [u8; 32],
    }
    Ok(serde_json::to_vec(&Body {
        room_id: &ev.room_id,
        parents: &ev.parents,
        kind: ev.kind,
        payload: &ev.payload,
        author_device: &ev.author_device,
        ts_ms: ev.ts_ms,
        author_vk,
    })?)
}

pub fn sign_event(sk: &SigningKey, unsigned: UnsignedEvent) -> Result<SignedEvent, EventError> {
    let vk = sk.verifying_key();
    let author_vk = *vk.as_bytes();
    let expected_device = DeviceId::from_verifying_key(&vk);
    if unsigned.author_device != expected_device {
        return Err(EventError::AuthorMismatch);
    }
    let body = body_bytes(&unsigned, &author_vk)?;
    let sig = sk.sign(&body);
    let mut signed = SignedEvent {
        id: EventId([0u8; 32]),
        room_id: unsigned.room_id,
        parents: unsigned.parents,
        kind: unsigned.kind,
        payload: unsigned.payload,
        author_device: unsigned.author_device,
        ts_ms: unsigned.ts_ms,
        author_vk,
        signature: sig.to_bytes().to_vec(),
    };
    let canon = canonical_bytes(&signed);
    signed.id = event_id_from_bytes(&canon);
    Ok(signed)
}

pub fn verify_event(ev: &SignedEvent) -> Result<(), EventError> {
    let vk =
        VerifyingKey::from_bytes(&ev.author_vk).map_err(|_| EventError::InvalidVerifyingKey)?;
    let device = DeviceId::from_verifying_key(&vk);
    if device != ev.author_device {
        return Err(EventError::AuthorMismatch);
    }
    let unsigned = UnsignedEvent {
        room_id: ev.room_id,
        parents: ev.parents.clone(),
        kind: ev.kind,
        payload: ev.payload.clone(),
        author_device: ev.author_device,
        ts_ms: ev.ts_ms,
    };
    let body = body_bytes(&unsigned, &ev.author_vk)?;
    let sig_arr: [u8; 64] = ev
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| EventError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(&body, &sig)
        .map_err(|_| EventError::InvalidSignature)?;
    let id = event_id_from_bytes(&canonical_bytes(ev));
    if id != ev.id {
        return Err(EventError::IdMismatch);
    }
    Ok(())
}

/// Full canonical encoding including signature (for content id).
pub fn canonical_bytes(ev: &SignedEvent) -> Vec<u8> {
    #[derive(Serialize)]
    struct Canon<'a> {
        room_id: &'a RoomId,
        parents: &'a [EventId],
        kind: EventKind,
        payload: &'a [u8],
        author_device: &'a DeviceId,
        ts_ms: u64,
        author_vk: &'a [u8; 32],
        signature: &'a [u8],
    }
    serde_json::to_vec(&Canon {
        room_id: &ev.room_id,
        parents: &ev.parents,
        kind: ev.kind,
        payload: &ev.payload,
        author_device: &ev.author_device,
        ts_ms: ev.ts_ms,
        author_vk: &ev.author_vk,
        signature: &ev.signature,
    })
    .expect("canonical serialize")
}

pub fn event_id_from_bytes(bytes: &[u8]) -> EventId {
    EventId(*blake3::hash(bytes).as_bytes())
}
