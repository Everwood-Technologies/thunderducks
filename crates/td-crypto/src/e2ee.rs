//! Vodozemac Olm (1:1) and Megolm (group) wrappers for Thunderducks.
//!
//! Session keys never leave this module except as encrypted payloads or
//! exported Megolm session keys intended to be wrapped by Olm for fanout.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use vodozemac::megolm::InboundGroupSessionPickle;
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, MegolmMessage,
    SessionConfig as MegolmConfig, SessionKey,
};
use vodozemac::olm::{
    Account, AccountPickle, InboundCreationResult, OlmMessage, Session as OlmSession,
    SessionConfig as OlmConfig, SessionPickle,
};
use vodozemac::Curve25519PublicKey;

use crate::device::DeviceId;

#[derive(Debug, Error)]
pub enum E2eeError {
    #[error("session creation: {0}")]
    SessionCreation(String),
    #[error("encryption: {0}")]
    Encrypt(String),
    #[error("decryption: {0}")]
    Decrypt(String),
    #[error("missing olm session with {0:?}")]
    MissingOlm(DeviceId),
    #[error("missing megolm inbound session {0}")]
    MissingMegolm(String),
    #[error("invalid curve25519 key")]
    InvalidKey,
    #[error("codec: {0}")]
    Codec(String),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("pickle: {0}")]
    Pickle(String),
}

/// Portable outbound Megolm state for a room (B2 shared room session).
/// Contains ratchet + signing keypair — treat like a private key; only share Olm-wrapped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomOutboundPackage {
    pub v: u8,
    pub room_id: String,
    pub session_id: String,
    pub message_index: u32,
    /// vodozemac GroupSessionPickle encrypted with [`ROOM_PICKLE_KEY`] (transport still Olm).
    pub pickle_b64: String,
    /// Inbound session key at the same ratchet index (decrypt from here forward).
    pub session_key_b64: String,
    pub owner_device: DeviceId,
}

/// Local pickle wrap key — confidentiality relies on Olm wrap in fanout, not this key alone.
pub const ROOM_PICKLE_KEY: [u8; 32] = *b"td-room-outbound-pickle-v1!!!!!!";

/// Public Olm identity material for a device (Curve25519 sender key + one OTK).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OlmDeviceKeys {
    pub device_id: DeviceId,
    /// Unpadded base64 Curve25519 identity key
    pub curve25519_b64: String,
    /// Unpadded base64 one-time key
    pub one_time_key_b64: String,
}

/// Wire envelope for an Olm ciphertext (1:1 or key fanout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OlmCiphertext {
    pub sender_device: DeviceId,
    pub recipient_device: DeviceId,
    /// JSON-serialized vodozemac OlmMessage
    pub message_json: String,
}

/// Wire envelope for a Megolm room message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MegolmCiphertext {
    pub sender_device: DeviceId,
    pub session_id: String,
    /// base64 MegolmMessage
    pub ciphertext_b64: String,
}

/// A device's E2EE state: Olm account + sessions + outbound/inbound Megolm.
pub struct E2eeDevice {
    pub device_id: DeviceId,
    account: Account,
    /// peer device -> olm session
    olm_sessions: HashMap<DeviceId, OlmSession>,
    /// room_id hex -> outbound megolm
    outbound_megolm: HashMap<String, GroupSession>,
    /// session_id -> inbound megolm
    inbound_megolm: HashMap<String, InboundGroupSession>,
}

impl E2eeDevice {
    pub fn new(device_id: DeviceId) -> Self {
        let mut account = Account::new();
        account.generate_one_time_keys(10);
        Self {
            device_id,
            account,
            olm_sessions: HashMap::new(),
            outbound_megolm: HashMap::new(),
            inbound_megolm: HashMap::new(),
        }
    }

    pub fn publish_keys(&mut self) -> Result<OlmDeviceKeys, E2eeError> {
        // one_time_keys() only returns *unpublished* OTKs. After mark_keys_as_published()
        // that map is empty even if stored_one_time_key_count() > 0 — always generate
        // when there is nothing left to hand out.
        if self.account.one_time_keys().is_empty() {
            self.account.generate_one_time_keys(10);
        }
        let otk = *self
            .account
            .one_time_keys()
            .values()
            .next()
            .ok_or_else(|| E2eeError::SessionCreation("no one-time keys".into()))?;
        // mark published so keys are considered shared
        self.account.mark_keys_as_published();
        Ok(OlmDeviceKeys {
            device_id: self.device_id,
            curve25519_b64: self.account.curve25519_key().to_base64(),
            one_time_key_b64: otk.to_base64(),
        })
    }

    fn parse_curve(b64: &str) -> Result<Curve25519PublicKey, E2eeError> {
        Curve25519PublicKey::from_base64(b64).map_err(|_| E2eeError::InvalidKey)
    }

    pub fn has_olm_session(&self, peer: DeviceId) -> bool {
        self.olm_sessions.contains_key(&peer)
    }

    /// Alice establishes outbound Olm to Bob using Bob's published keys.
    /// No-op if a session with this peer already exists.
    pub fn establish_olm_outbound(&mut self, their: &OlmDeviceKeys) -> Result<(), E2eeError> {
        if self.olm_sessions.contains_key(&their.device_id) {
            return Ok(());
        }
        let id_key = Self::parse_curve(&their.curve25519_b64)?;
        let otk = Self::parse_curve(&their.one_time_key_b64)?;
        let session = self
            .account
            .create_outbound_session(OlmConfig::version_1(), id_key, otk)
            .map_err(|e| E2eeError::SessionCreation(e.to_string()))?;
        self.olm_sessions.insert(their.device_id, session);
        Ok(())
    }

    /// Encrypt bytes to a peer via Olm (creates pre-key message on first use).
    pub fn olm_encrypt(
        &mut self,
        to: DeviceId,
        plaintext: &[u8],
    ) -> Result<OlmCiphertext, E2eeError> {
        let session = self
            .olm_sessions
            .get_mut(&to)
            .ok_or(E2eeError::MissingOlm(to))?;
        let msg = session
            .encrypt(plaintext)
            .map_err(|e| E2eeError::Encrypt(e.to_string()))?;
        let message_json =
            serde_json::to_string(&msg).map_err(|e| E2eeError::Codec(e.to_string()))?;
        Ok(OlmCiphertext {
            sender_device: self.device_id,
            recipient_device: to,
            message_json,
        })
    }

    /// Decrypt an Olm ciphertext. Establishes inbound session on first pre-key message.
    pub fn olm_decrypt(
        &mut self,
        their_identity_b64: &str,
        ct: &OlmCiphertext,
    ) -> Result<Vec<u8>, E2eeError> {
        if ct.recipient_device != self.device_id {
            return Err(E2eeError::Decrypt("not addressed to this device".into()));
        }
        let msg: OlmMessage =
            serde_json::from_str(&ct.message_json).map_err(|e| E2eeError::Codec(e.to_string()))?;

        // Prefer existing session
        if let Some(session) = self.olm_sessions.get_mut(&ct.sender_device) {
            return session
                .decrypt(&msg)
                .map_err(|e| E2eeError::Decrypt(e.to_string()));
        }

        // Establish inbound from pre-key
        match msg {
            OlmMessage::PreKey(ref prekey) => {
                let their_id = Self::parse_curve(their_identity_b64)?;
                let InboundCreationResult { session, plaintext } = self
                    .account
                    .create_inbound_session(OlmConfig::version_1(), their_id, prekey)
                    .map_err(|e| E2eeError::SessionCreation(e.to_string()))?;
                self.olm_sessions.insert(ct.sender_device, session);
                Ok(plaintext)
            }
            OlmMessage::Normal(_) => Err(E2eeError::MissingOlm(ct.sender_device)),
        }
    }

    /// Create outbound Megolm for a room (room_id as hex/string key).
    /// No-op if this device already has an outbound session for the room (B2).
    pub fn create_group_session(&mut self, room_key: &str) -> String {
        if let Some(sid) = self.group_session_id(room_key) {
            return sid;
        }
        let session = GroupSession::new(MegolmConfig::version_1());
        let sid = session.session_id();
        self.outbound_megolm.insert(room_key.to_string(), session);
        // also keep inbound for self-read
        if let Some(out) = self.outbound_megolm.get(room_key) {
            let key = out.session_key();
            let inbound = InboundGroupSession::new(&key, MegolmConfig::version_1());
            self.inbound_megolm.insert(sid.clone(), inbound);
        }
        sid
    }

    pub fn has_outbound(&self, room_key: &str) -> bool {
        self.outbound_megolm.contains_key(room_key)
    }

    pub fn group_session_id(&self, room_key: &str) -> Option<String> {
        self.outbound_megolm.get(room_key).map(|s| s.session_id())
    }

    pub fn group_message_index(&self, room_key: &str) -> Option<u32> {
        self.outbound_megolm
            .get(room_key)
            .map(|s| s.message_index())
    }

    /// Export Megolm session key (inbound material; to be Olm-wrapped).
    pub fn export_group_session_key(&self, room_key: &str) -> Result<String, E2eeError> {
        let out = self
            .outbound_megolm
            .get(room_key)
            .ok_or_else(|| E2eeError::MissingMegolm(room_key.into()))?;
        Ok(out.session_key().to_base64())
    }

    /// Export full outbound room session (pickle) for shared-room ownership (B2).
    pub fn export_room_outbound(&self, room_key: &str) -> Result<RoomOutboundPackage, E2eeError> {
        let out = self
            .outbound_megolm
            .get(room_key)
            .ok_or_else(|| E2eeError::MissingMegolm(room_key.into()))?;
        let pickle = out.pickle();
        let pickle_b64 = pickle.encrypt(&ROOM_PICKLE_KEY);
        Ok(RoomOutboundPackage {
            v: 1,
            room_id: room_key.to_string(),
            session_id: out.session_id(),
            message_index: out.message_index(),
            pickle_b64,
            session_key_b64: out.session_key().to_base64(),
            owner_device: self.device_id,
        })
    }

    /// Import shared room outbound (B2). Accepts same session_id only when advancing.
    /// Also installs inbound session_key (or_insert — never regress inbound).
    pub fn import_room_outbound(&mut self, pkg: &RoomOutboundPackage) -> Result<String, E2eeError> {
        if pkg.v != 1 {
            return Err(E2eeError::Codec(format!(
                "unsupported room outbound v={}",
                pkg.v
            )));
        }
        // Inbound first so we can decrypt history from this index forward.
        let _ = self.import_group_session_key(&pkg.session_key_b64)?;

        let pickle = GroupSessionPickle::from_encrypted(&pkg.pickle_b64, &ROOM_PICKLE_KEY)
            .map_err(|e| E2eeError::Pickle(e.to_string()))?;
        let session = GroupSession::from_pickle(pickle);
        if session.session_id() != pkg.session_id {
            return Err(E2eeError::Codec("pickle session_id mismatch".into()));
        }

        match self.outbound_megolm.get(&pkg.room_id) {
            Some(local) if local.session_id() != pkg.session_id => {
                // Different room session already owned locally — keep local (first-writer wins).
                return Ok(local.session_id());
            }
            Some(local) if local.message_index() > pkg.message_index => {
                // Local ratchet is ahead; keep local.
                return Ok(local.session_id());
            }
            _ => {
                self.outbound_megolm.insert(pkg.room_id.clone(), session);
            }
        }
        Ok(pkg.session_id.clone())
    }

    pub fn import_group_session_key(&mut self, session_key_b64: &str) -> Result<String, E2eeError> {
        let key = SessionKey::from_base64(session_key_b64)
            .map_err(|e| E2eeError::Codec(e.to_string()))?;
        let inbound = InboundGroupSession::new(&key, MegolmConfig::version_1());
        let sid = inbound.session_id();
        // Never overwrite an existing inbound: a later export is advanced past
        // already-sent indices and would break decrypt of prior ciphertext.
        self.inbound_megolm.entry(sid.clone()).or_insert(inbound);
        Ok(sid)
    }

    /// Encrypt room plaintext with Megolm (shared room outbound when present).
    pub fn megolm_encrypt(
        &mut self,
        room_key: &str,
        plaintext: &[u8],
    ) -> Result<MegolmCiphertext, E2eeError> {
        let out = self
            .outbound_megolm
            .get_mut(room_key)
            .ok_or_else(|| E2eeError::MissingMegolm(room_key.into()))?;
        let msg = out.encrypt(plaintext);
        Ok(MegolmCiphertext {
            sender_device: self.device_id,
            session_id: out.session_id(),
            ciphertext_b64: msg.to_base64(),
        })
    }

    pub fn megolm_decrypt(&mut self, ct: &MegolmCiphertext) -> Result<Vec<u8>, E2eeError> {
        let inbound = self
            .inbound_megolm
            .get_mut(&ct.session_id)
            .ok_or_else(|| E2eeError::MissingMegolm(ct.session_id.clone()))?;
        let msg = MegolmMessage::from_base64(&ct.ciphertext_b64)
            .map_err(|e| E2eeError::Codec(e.to_string()))?;
        let decrypted = inbound
            .decrypt(&msg)
            .map_err(|e| E2eeError::Decrypt(e.to_string()))?;
        Ok(decrypted.plaintext)
    }

    pub fn curve25519_b64(&self) -> String {
        self.account.curve25519_key().to_base64()
    }

    /// Export full E2EE state for durable disk (encrypted pickles).
    pub fn export_durable(&self) -> Result<E2eeDurablePackage, E2eeError> {
        let key = &ROOM_PICKLE_KEY;
        let account_b64 = self.account.pickle().encrypt(key);
        let mut olm = Vec::new();
        for (peer, sess) in &self.olm_sessions {
            olm.push(OlmSessionDurable {
                peer_device: hex::encode(peer.0),
                pickle_b64: sess.pickle().encrypt(key),
            });
        }
        let mut outbound = Vec::new();
        for (room, sess) in &self.outbound_megolm {
            outbound.push(MegolmOutboundDurable {
                room_id: room.clone(),
                session_id: sess.session_id(),
                pickle_b64: sess.pickle().encrypt(key),
            });
        }
        let mut inbound = Vec::new();
        for (sid, sess) in &self.inbound_megolm {
            inbound.push(MegolmInboundDurable {
                session_id: sid.clone(),
                pickle_b64: sess.pickle().encrypt(key),
            });
        }
        Ok(E2eeDurablePackage {
            v: 1,
            device_id: hex::encode(self.device_id.0),
            account_b64,
            olm,
            outbound,
            inbound,
        })
    }

    /// Restore E2EE state from durable package (device_id must match).
    pub fn import_durable(
        device_id: DeviceId,
        pkg: &E2eeDurablePackage,
    ) -> Result<Self, E2eeError> {
        if pkg.v != 1 {
            return Err(E2eeError::Codec(format!(
                "unsupported e2ee durable v={}",
                pkg.v
            )));
        }
        let want = hex::encode(device_id.0);
        if pkg.device_id != want {
            return Err(E2eeError::Codec("e2ee durable device_id mismatch".into()));
        }
        let key = &ROOM_PICKLE_KEY;
        let account = Account::from_pickle(
            AccountPickle::from_encrypted(&pkg.account_b64, key)
                .map_err(|e| E2eeError::Pickle(e.to_string()))?,
        );
        let mut olm_sessions = HashMap::new();
        for o in &pkg.olm {
            let peer = parse_device_hex(&o.peer_device)?;
            let sess = OlmSession::from_pickle(
                SessionPickle::from_encrypted(&o.pickle_b64, key)
                    .map_err(|e| E2eeError::Pickle(e.to_string()))?,
            );
            olm_sessions.insert(peer, sess);
        }
        let mut outbound_megolm = HashMap::new();
        for o in &pkg.outbound {
            let sess = GroupSession::from_pickle(
                GroupSessionPickle::from_encrypted(&o.pickle_b64, key)
                    .map_err(|e| E2eeError::Pickle(e.to_string()))?,
            );
            outbound_megolm.insert(o.room_id.clone(), sess);
        }
        let mut inbound_megolm = HashMap::new();
        for i in &pkg.inbound {
            let sess = InboundGroupSession::from_pickle(
                InboundGroupSessionPickle::from_encrypted(&i.pickle_b64, key)
                    .map_err(|e| E2eeError::Pickle(e.to_string()))?,
            );
            inbound_megolm.insert(i.session_id.clone(), sess);
        }
        Ok(Self {
            device_id,
            account,
            olm_sessions,
            outbound_megolm,
            inbound_megolm,
        })
    }
}

/// On-disk E2EE package (vodozemac pickles encrypted with [`ROOM_PICKLE_KEY`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eeDurablePackage {
    pub v: u32,
    pub device_id: String,
    pub account_b64: String,
    #[serde(default)]
    pub olm: Vec<OlmSessionDurable>,
    #[serde(default)]
    pub outbound: Vec<MegolmOutboundDurable>,
    #[serde(default)]
    pub inbound: Vec<MegolmInboundDurable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OlmSessionDurable {
    pub peer_device: String,
    pub pickle_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MegolmOutboundDurable {
    pub room_id: String,
    pub session_id: String,
    pub pickle_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MegolmInboundDurable {
    pub session_id: String,
    pub pickle_b64: String,
}

fn parse_device_hex(s: &str) -> Result<DeviceId, E2eeError> {
    let bytes = hex::decode(s).map_err(|e| E2eeError::Codec(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(E2eeError::Codec(format!(
            "device id want 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    Ok(DeviceId(a))
}

/// Fan out a Megolm session key to many devices over established Olm sessions.
pub fn fanout_megolm_key(
    sender: &mut E2eeDevice,
    room_key: &str,
    recipients: &[DeviceId],
) -> Result<Vec<OlmCiphertext>, E2eeError> {
    let session_key = sender.export_group_session_key(room_key)?;
    let mut out = Vec::new();
    for rid in recipients {
        if *rid == sender.device_id {
            continue;
        }
        out.push(sender.olm_encrypt(*rid, session_key.as_bytes())?);
    }
    Ok(out)
}
