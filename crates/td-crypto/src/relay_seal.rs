//! Production relay envelope seal (device-side).
//!
//! Ciphertext is **ChaCha20-Poly1305** AEAD over canonical signed-event JSON.
//! The relay stores opaque bytes only — a curious operator cannot read event
//! payloads without the 32-byte relay key shared among linked devices.
//!
//! Wire format (v1):
//! ```text
//! [0x01 version][12-byte nonce][ciphertext || 16-byte tag]
//! ```
//!
//! Key derivation: `blake3("td-relay-seal-v1" || key_material)` so operators can
//! pass any secret string or raw 32 bytes via `TD_RELAY_KEY`.

use aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

/// Domain-separated label for relay seal key derivation.
pub const RELAY_SEAL_KDF_LABEL: &[u8] = b"td-relay-seal-v1";
/// Wire version byte.
pub const RELAY_SEAL_V1: u8 = 0x01;
/// Default demo key material when none configured (dev only — set TD_RELAY_KEY in prod).
pub const DEFAULT_RELAY_KEY_MATERIAL: &[u8] = b"td-relay-dev-key-change-me!!!!!!";

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

/// Seal plaintext bytes for relay storage.
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

/// Open sealed bytes from relay storage.
pub fn open_bytes(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, RelaySealError> {
    if sealed.len() < 1 + 12 + 16 {
        return Err(RelaySealError::TooShort);
    }
    let ver = sealed[0];
    if ver != RELAY_SEAL_V1 {
        return Err(RelaySealError::BadVersion(ver));
    }
    let nonce_bytes = &sealed[1..13];
    let ct = &sealed[13..];
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| RelaySealError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| RelaySealError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
