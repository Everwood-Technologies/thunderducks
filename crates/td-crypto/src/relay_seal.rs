//! Production relay envelope seal (device-side).
//!
//! Prefer **v2 Olm per-recipient** wrap so a shared `TD_RELAY_KEY` is not required
//! for confidentiality among linked devices. v1 shared-key AEAD remains as a
//! migration / no-Olm fallback.
//!
//! Wire formats:
//! ```text
//! v1 AEAD:  [0x01][12-byte nonce][ciphertext || 16-byte tag]
//! v2 Olm:   [0x02][utf-8 JSON RelayOlmWire]
//! ```
//!
//! `RelayOlmWire.olm` encrypts canonical signed-event JSON to one recipient.
//! The relay stores opaque bytes only.
//!
//! Key derivation (v1 only): `blake3("td-relay-seal-v1" || key_material)`.

use aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::e2ee::{E2eeDevice, E2eeError, OlmCiphertext};
use crate::device::DeviceId;

/// Domain-separated label for relay seal key derivation.
pub const RELAY_SEAL_KDF_LABEL: &[u8] = b"td-relay-seal-v1";
/// Shared-key AEAD wire version.
pub const RELAY_SEAL_V1: u8 = 0x01;
/// Per-recipient Olm wire version.
pub const RELAY_SEAL_V2_OLM: u8 = 0x02;
/// Default demo key material when none configured (dev only — set TD_RELAY_KEY in prod).
pub const DEFAULT_RELAY_KEY_MATERIAL: &[u8] = b"td-relay-dev-key-change-me!!!!!!";

/// v2 outer JSON (after version byte).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayOlmWire {
    pub v: u8,
    pub sender_curve25519_b64: String,
    pub olm: OlmCiphertext,
}

#[derive(Debug, Error)]
pub enum RelaySealError {
    #[error("aead encrypt failed")]
    Encrypt,
    #[error("aead decrypt failed (wrong key or tampered ciphertext)")]
    Decrypt,
    #[error("ciphertext too short")]
    TooShort,
    #[error("unsupported seal version {0}")]
    BadVersion(u8),
    #[error("olm: {0}")]
    Olm(String),
    #[error("codec: {0}")]
    Codec(String),
}

impl From<E2eeError> for RelaySealError {
    fn from(e: E2eeError) -> Self {
        Self::Olm(e.to_string())
    }
}

/// Derive a 32-byte ChaCha20-Poly1305 key from arbitrary key material.
pub fn derive_relay_key(material: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(RELAY_SEAL_KDF_LABEL);
    h.update(material);
    *h.finalize().as_bytes()
}

/// Parse env-style key material: hex (64 chars) or raw UTF-8 secret.
pub fn parse_relay_key_material(s: &str) -> Vec<u8> {
    let t = s.trim();
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = vec![0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        out
    } else {
        t.as_bytes().to_vec()
    }
}

/// Seal plaintext bytes for relay storage (v1 shared-key AEAD).
pub fn seal_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, RelaySealError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| RelaySealError::Encrypt)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| RelaySealError::Encrypt)?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(RELAY_SEAL_V1);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open v1 AEAD sealed bytes from relay storage.
pub fn open_bytes(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, RelaySealError> {
    if sealed.is_empty() {
        return Err(RelaySealError::TooShort);
    }
    let ver = sealed[0];
    if ver != RELAY_SEAL_V1 {
        return Err(RelaySealError::BadVersion(ver));
    }
    if sealed.len() < 1 + 12 + 16 {
        return Err(RelaySealError::TooShort);
    }
    let nonce_bytes = &sealed[1..13];
    let ct = &sealed[13..];
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| RelaySealError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| RelaySealError::Decrypt)
}

/// Seal plaintext to one recipient via an established Olm session (v2).
///
/// Caller must have already established outbound Olm to `to`.
pub fn seal_bytes_olm(
    e2ee: &mut E2eeDevice,
    to: DeviceId,
    plaintext: &[u8],
) -> Result<Vec<u8>, RelaySealError> {
    let olm = e2ee.olm_encrypt(to, plaintext)?;
    let wire = RelayOlmWire {
        v: 1,
        sender_curve25519_b64: e2ee.curve25519_b64(),
        olm,
    };
    let json = serde_json::to_vec(&wire).map_err(|e| RelaySealError::Codec(e.to_string()))?;
    let mut out = Vec::with_capacity(1 + json.len());
    out.push(RELAY_SEAL_V2_OLM);
    out.extend_from_slice(&json);
    Ok(out)
}

/// Open v2 Olm-sealed bytes addressed to this device.
pub fn open_bytes_olm(
    e2ee: &mut E2eeDevice,
    sealed: &[u8],
) -> Result<Vec<u8>, RelaySealError> {
    if sealed.is_empty() {
        return Err(RelaySealError::TooShort);
    }
    if sealed[0] != RELAY_SEAL_V2_OLM {
        return Err(RelaySealError::BadVersion(sealed[0]));
    }
    let wire: RelayOlmWire = serde_json::from_slice(&sealed[1..])
        .map_err(|e| RelaySealError::Codec(e.to_string()))?;
    if wire.v != 1 {
        return Err(RelaySealError::Codec(format!(
            "unsupported RelayOlmWire.v={}",
            wire.v
        )));
    }
    e2ee
        .olm_decrypt(&wire.sender_curve25519_b64, &wire.olm)
        .map_err(Into::into)
}

/// Open either v1 (shared AEAD) or v2 (Olm) ciphertext.
///
/// Prefer Olm when version is v2; v1 requires `aead_key`.
pub fn open_bytes_auto(
    e2ee: &mut E2eeDevice,
    aead_key: Option<&[u8; 32]>,
    sealed: &[u8],
) -> Result<Vec<u8>, RelaySealError> {
    if sealed.is_empty() {
        return Err(RelaySealError::TooShort);
    }
    match sealed[0] {
        RELAY_SEAL_V2_OLM => open_bytes_olm(e2ee, sealed),
        RELAY_SEAL_V1 => {
            let key = aead_key.ok_or_else(|| {
                RelaySealError::Codec("v1 AEAD envelope but no relay key configured".into())
            })?;
            open_bytes(key, sealed)
        }
        v => Err(RelaySealError::BadVersion(v)),
    }
}

/// Peak wire version byte without opening.
pub fn seal_version(sealed: &[u8]) -> Option<u8> {
    sealed.first().copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceKeypair;
    use crate::e2ee::E2eeDevice;

    #[test]
    fn seal_roundtrip_hides_plaintext() {
        let key = derive_relay_key(b"unit-test-secret");
        let plain = br#"{"text":"super-secret-honk"}"#;
        let sealed = seal_bytes(&key, plain).unwrap();
        assert_eq!(sealed[0], RELAY_SEAL_V1);
        assert!(!sealed.windows(plain.len()).any(|w| w == plain));
        let opened = open_bytes(&key, &sealed).unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = derive_relay_key(b"a");
        let k2 = derive_relay_key(b"b");
        let sealed = seal_bytes(&k1, b"hi").unwrap();
        assert!(open_bytes(&k2, &sealed).is_err());
    }

    #[test]
    fn parse_hex_and_utf8() {
        let hex = "aa".repeat(32);
        assert_eq!(parse_relay_key_material(&hex).len(), 32);
        assert_eq!(parse_relay_key_material("hello"), b"hello");
    }

    #[test]
    fn olm_v2_roundtrip_hides_plaintext() {
        let a = DeviceKeypair::generate();
        let b = DeviceKeypair::generate();
        let mut alice = E2eeDevice::new(a.device_id());
        let mut bob = E2eeDevice::new(b.device_id());
        let bob_keys = bob.publish_keys().unwrap();
        alice.establish_olm_outbound(&bob_keys).unwrap();

        let plain = br#"{"text":"per-recipient-honk"}"#;
        let sealed = seal_bytes_olm(&mut alice, bob.device_id, plain).unwrap();
        assert_eq!(sealed[0], RELAY_SEAL_V2_OLM);
        assert!(!sealed.windows(plain.len()).any(|w| w == plain));

        // Shared AEAD key cannot open v2.
        let aead = derive_relay_key(b"irrelevant");
        assert!(open_bytes(&aead, &sealed).is_err());

        let opened = open_bytes_olm(&mut bob, &sealed).unwrap();
        assert_eq!(opened, plain);

        // Auto path
        let sealed2 = seal_bytes_olm(&mut alice, bob.device_id, b"again").unwrap();
        let got = open_bytes_auto(&mut bob, Some(&aead), &sealed2).unwrap();
        assert_eq!(got, b"again");
    }

    #[test]
    fn wrong_recipient_cannot_open_v2() {
        let a = DeviceKeypair::generate();
        let b = DeviceKeypair::generate();
        let c = DeviceKeypair::generate();
        let mut alice = E2eeDevice::new(a.device_id());
        let mut bob = E2eeDevice::new(b.device_id());
        let mut carol = E2eeDevice::new(c.device_id());
        let bob_keys = bob.publish_keys().unwrap();
        alice.establish_olm_outbound(&bob_keys).unwrap();

        let sealed = seal_bytes_olm(&mut alice, bob.device_id, b"only-bob").unwrap();
        assert!(open_bytes_olm(&mut carol, &sealed).is_err());
        assert_eq!(open_bytes_olm(&mut bob, &sealed).unwrap(), b"only-bob");
    }
}
