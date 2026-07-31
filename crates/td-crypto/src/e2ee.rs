//! Vodozemac Olm (1:1) and Megolm (group) wrappers for Thunderducks.
//!
//! Session keys never leave this module except as encrypted payloads or
//! exported Megolm session keys intended to be wrapped by Olm for fanout.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use vodozemac::megolm::{
    GroupSession, InboundGroupSession, MegolmMessage, SessionConfig as MegolmConfig, SessionKey,
};
use vodozemac::olm::{
    Account, InboundCreationResult, OlmMessage, Session as OlmSession, SessionConfig as OlmConfig,
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
}

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
        if self.account.stored_one_time_key_count() == 0 {
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

    /// Alice establishes outbound Olm to Bob using Bob's published keys.
    pub fn establish_olm_outbound(&mut self, their: &OlmDeviceKeys) -> Result<(), E2eeError> {
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
    pub fn create_group_session(&mut self, room_key: &str) -> String {
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

    pub fn group_session_id(&self, room_key: &str) -> Option<String> {
        self.outbound_megolm.get(room_key).map(|s| s.session_id())
    }

    /// Export Megolm session key (to be Olm-wrapped to each device).
    pub fn export_group_session_key(&self, room_key: &str) -> Result<String, E2eeError> {
        let out = self
            .outbound_megolm
            .get(room_key)
            .ok_or_else(|| E2eeError::MissingMegolm(room_key.into()))?;
        Ok(out.session_key().to_base64())
    }

    pub fn import_group_session_key(&mut self, session_key_b64: &str) -> Result<String, E2eeError> {
        let key = SessionKey::from_base64(session_key_b64)
            .map_err(|e| E2eeError::Codec(e.to_string()))?;
        let inbound = InboundGroupSession::new(&key, MegolmConfig::version_1());
        let sid = inbound.session_id();
        self.inbound_megolm.insert(sid.clone(), inbound);
        Ok(sid)
    }

    /// Encrypt room plaintext with Megolm.
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
