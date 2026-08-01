//! WebAuthn / passkey enrollment helpers (P1.1).
//!
//! Focused verifier for localhost MVP:
//! - mint/bind challenges
//! - parse clientDataJSON + authenticatorData
//! - register credential id + COSE ES256 public key
//! - verify assertion signatures (ES256 / P-256)
//!
//! Not a full FIDO certification stack; good enough to replace the pure
//! "device-link stub is the only identity UX" gap for web enroll.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PasskeyError {
    #[error("unknown challenge")]
    UnknownChallenge,
    #[error("challenge mismatch")]
    ChallengeMismatch,
    #[error("invalid client data: {0}")]
    ClientData(String),
    #[error("invalid authenticator data: {0}")]
    AuthData(String),
    #[error("unknown credential")]
    UnknownCredential,
    #[error("bad signature: {0}")]
    Signature(String),
    #[error("codec: {0}")]
    Codec(String),
    #[error("unsupported cose key")]
    UnsupportedKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialCreationOptions {
    pub challenge: String,
    pub rp: RelyingParty,
    pub user: UserEntity,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout_ms: u32,
    pub attestation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String,
    pub rp_id: String,
    pub timeout_ms: u32,
    pub allow_credentials: Vec<AllowCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key_spki: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub sign_count: u32,
    pub label: String,
}

#[derive(Debug, Default)]
pub struct PasskeyRegistry {
    /// challenge_b64url -> purpose
    challenges: HashMap<String, ChallengeRecord>,
    /// credential_id -> stored
    creds: HashMap<Vec<u8>, StoredCredential>,
    rp_id: String,
    rp_name: String,
    origin: String,
}

#[derive(Debug, Clone)]
struct ChallengeRecord {
    purpose: ChallengePurpose,
    user_handle: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChallengePurpose {
    Register,
    Authenticate,
}

impl PasskeyRegistry {
    pub fn new(
        rp_id: impl Into<String>,
        rp_name: impl Into<String>,
        origin: impl Into<String>,
    ) -> Self {
        Self {
            challenges: HashMap::new(),
            creds: HashMap::new(),
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            origin: origin.into(),
        }
    }

    pub fn localhost_default() -> Self {
        // WebAuthn requires secure context; localhost is allowed.
        Self::new("localhost", "Thunderducks", "http://localhost:8788")
    }

    pub fn credential_count(&self) -> usize {
        self.creds.len()
    }

    pub fn list_credentials(&self) -> Vec<&StoredCredential> {
        self.creds.values().collect()
    }

    fn mint_challenge(&mut self, purpose: ChallengePurpose, user_handle: Vec<u8>) -> String {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let ch = b64url(&raw);
        self.challenges.insert(
            ch.clone(),
            ChallengeRecord {
                purpose,
                user_handle,
            },
        );
        ch
    }

    pub fn begin_registration(
        &mut self,
        user_name: &str,
        display_name: &str,
    ) -> PublicKeyCredentialCreationOptions {
        let mut handle = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut handle);
        let challenge = self.mint_challenge(ChallengePurpose::Register, handle.to_vec());
        PublicKeyCredentialCreationOptions {
            challenge,
            rp: RelyingParty {
                id: self.rp_id.clone(),
                name: self.rp_name.clone(),
            },
            user: UserEntity {
                id: b64url(&handle),
                name: user_name.to_string(),
                display_name: display_name.to_string(),
            },
            pub_key_cred_params: vec![PubKeyCredParam {
                type_: "public-key".into(),
                alg: -7, // ES256
            }],
            timeout_ms: 60_000,
            attestation: "none".into(),
        }
    }

    pub fn finish_registration(
        &mut self,
        challenge: &str,
        credential_id_b64: &str,
        client_data_json_b64: &str,
        authenticator_data_b64: &str,
        public_key_spki_b64: &str,
        label: &str,
    ) -> Result<StoredCredential, PasskeyError> {
        let rec = self
            .challenges
            .remove(challenge)
            .ok_or(PasskeyError::UnknownChallenge)?;
        if rec.purpose != ChallengePurpose::Register {
            return Err(PasskeyError::ChallengeMismatch);
        }
        let client_raw = b64url_decode(client_data_json_b64)?;
        let client = parse_client_data(&client_raw)?;
        if client.challenge != challenge {
            return Err(PasskeyError::ChallengeMismatch);
        }
        if client.type_ != "webauthn.create" {
            return Err(PasskeyError::ClientData(format!(
                "expected webauthn.create, got {}",
                client.type_
            )));
        }
        // origin check relaxed for 127.0.0.1 vs localhost in MVP tests
        if !origin_ok(&client.origin, &self.origin) {
            return Err(PasskeyError::ClientData(format!(
                "origin {} not allowed for {}",
                client.origin, self.origin
            )));
        }

        let auth_data = b64url_decode(authenticator_data_b64)?;
        if auth_data.len() < 37 {
            return Err(PasskeyError::AuthData("too short".into()));
        }
        let rp_hash = &auth_data[0..32];
        let expected = Sha256::digest(self.rp_id.as_bytes());
        if rp_hash != expected.as_slice() {
            // allow 127.0.0.1 rpId hash if rp configured as localhost (browser variance)
            let alt = Sha256::digest(b"127.0.0.1");
            if rp_hash != alt.as_slice() {
                return Err(PasskeyError::AuthData("rpIdHash mismatch".into()));
            }
        }
        let flags = auth_data[32];
        if flags & 0x01 == 0 {
            return Err(PasskeyError::AuthData("UP flag not set".into()));
        }

        let cred_id = b64url_decode(credential_id_b64)?;
        let spki = b64url_decode(public_key_spki_b64)?;
        // validate parseable ES256 key
        P256VerifyingKey::from_public_key_der(&spki)
            .map_err(|e| PasskeyError::Codec(e.to_string()))?;

        let stored = StoredCredential {
            credential_id: cred_id.clone(),
            public_key_spki: spki,
            user_handle: rec.user_handle,
            sign_count: 0,
            label: label.to_string(),
        };
        self.creds.insert(cred_id, stored.clone());
        Ok(stored)
    }

    pub fn begin_authentication(&mut self) -> PublicKeyCredentialRequestOptions {
        let challenge = self.mint_challenge(ChallengePurpose::Authenticate, vec![]);
        let allow = self
            .creds
            .keys()
            .map(|id| AllowCredential {
                type_: "public-key".into(),
                id: b64url(id),
            })
            .collect();
        PublicKeyCredentialRequestOptions {
            challenge,
            rp_id: self.rp_id.clone(),
            timeout_ms: 60_000,
            allow_credentials: allow,
        }
    }

    pub fn finish_authentication(
        &mut self,
        challenge: &str,
        credential_id_b64: &str,
        client_data_json_b64: &str,
        authenticator_data_b64: &str,
        signature_b64: &str,
    ) -> Result<String, PasskeyError> {
        let rec = self
            .challenges
            .remove(challenge)
            .ok_or(PasskeyError::UnknownChallenge)?;
        if rec.purpose != ChallengePurpose::Authenticate {
            return Err(PasskeyError::ChallengeMismatch);
        }
        let client_raw = b64url_decode(client_data_json_b64)?;
        let client = parse_client_data(&client_raw)?;
        if client.challenge != challenge {
            return Err(PasskeyError::ChallengeMismatch);
        }
        if client.type_ != "webauthn.get" {
            return Err(PasskeyError::ClientData(format!(
                "expected webauthn.get, got {}",
                client.type_
            )));
        }
        if !origin_ok(&client.origin, &self.origin) {
            return Err(PasskeyError::ClientData(format!(
                "origin {} not allowed",
                client.origin
            )));
        }

        let cred_id = b64url_decode(credential_id_b64)?;
        let cred = self
            .creds
            .get_mut(&cred_id)
            .ok_or(PasskeyError::UnknownCredential)?;
        let auth_data = b64url_decode(authenticator_data_b64)?;
        let sig = b64url_decode(signature_b64)?;
        let client_hash = Sha256::digest(&client_raw);
        let mut msg = Vec::with_capacity(auth_data.len() + 32);
        msg.extend_from_slice(&auth_data);
        msg.extend_from_slice(&client_hash);

        let vk = P256VerifyingKey::from_public_key_der(&cred.public_key_spki)
            .map_err(|e| PasskeyError::Codec(e.to_string()))?;
        // WebAuthn uses ASN.1 DER ECDSA signatures commonly
        let signature = Signature::from_der(&sig)
            .or_else(|_| Signature::from_slice(&sig))
            .map_err(|e| PasskeyError::Signature(e.to_string()))?;
        vk.verify(&msg, &signature)
            .map_err(|e| PasskeyError::Signature(e.to_string()))?;

        // signCount in authData bytes 33..37
        if auth_data.len() >= 37 {
            let sc =
                u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
            if sc > 0 {
                cred.sign_count = sc;
            }
        }
        Ok(b64url(&cred.credential_id))
    }
}

#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
}

fn parse_client_data(raw: &[u8]) -> Result<ClientData, PasskeyError> {
    serde_json::from_slice(raw).map_err(|e| PasskeyError::ClientData(e.to_string()))
}

fn origin_ok(got: &str, expected: &str) -> bool {
    if got == expected {
        return true;
    }
    // MVP: treat localhost and 127.0.0.1 as equivalent on any port
    let norm = |s: &str| {
        s.replace("http://127.0.0.1", "http://localhost")
            .replace("https://127.0.0.1", "https://localhost")
    };
    let g = norm(got);
    let e = norm(expected);
    if g == e {
        return true;
    }
    // strip ports for compare of host
    let host_of = |s: &str| -> String {
        s.trim_start_matches("http://")
            .trim_start_matches("https://")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string()
    };
    matches!(
        (host_of(&g).as_str(), host_of(&e).as_str()),
        ("localhost", "localhost")
    )
}

pub fn b64url(data: &[u8]) -> String {
    base64_encode_config(data, true)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, PasskeyError> {
    base64_decode_config(s, true).map_err(PasskeyError::Codec)
}

fn base64_encode_config(data: &[u8], url: bool) -> String {
    const STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let table = if url { URL } else { STD };
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(table[((triple >> 18) & 63) as usize] as char);
        out.push(table[((triple >> 12) & 63) as usize] as char);
        if i + 1 < data.len() {
            out.push(table[((triple >> 6) & 63) as usize] as char);
        } else if !url {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(table[(triple & 63) as usize] as char);
        } else if !url {
            out.push('=');
        }
        i += 3;
    }
    // url-safe without padding (WebAuthn)
    if url {
        // already omitted pad
    }
    out
}

fn base64_decode_config(s: &str, url: bool) -> Result<Vec<u8>, String> {
    let mut s = s.replace('\n', "");
    if url {
        s = s.replace('-', "+").replace('_', "/");
    }
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("bad b64 char {}", c)),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'=' {
            break;
        }
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = if bytes[i + 2] == b'=' {
            0
        } else {
            val(bytes[i + 2])?
        };
        let d = if bytes[i + 3] == b'=' {
            0
        } else {
            val(bytes[i + 3])?
        };
        out.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((c << 6) | d);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use rand::rngs::OsRng;

    #[test]
    fn register_and_assert_es256() {
        let mut reg = PasskeyRegistry::new("localhost", "TD", "http://localhost:8788");
        let opts = reg.begin_registration("mike", "Mike");
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        let spki = vk.to_public_key_der().unwrap().as_bytes().to_vec();

        let client = serde_json::json!({
            "type": "webauthn.create",
            "challenge": opts.challenge,
            "origin": "http://localhost:8788"
        });
        let client_raw = serde_json::to_vec(&client).unwrap();
        let mut auth = Vec::new();
        auth.extend_from_slice(&Sha256::digest(b"localhost"));
        auth.push(0x01 | 0x04); // UP + AT
        auth.extend_from_slice(&0u32.to_be_bytes());

        let cred_id = b"cred-1";
        let stored = reg
            .finish_registration(
                &opts.challenge,
                &b64url(cred_id),
                &b64url(&client_raw),
                &b64url(&auth),
                &b64url(&spki),
                "primary",
            )
            .unwrap();
        assert_eq!(stored.credential_id, cred_id);
        assert_eq!(reg.credential_count(), 1);

        let req = reg.begin_authentication();
        let client2 = serde_json::json!({
            "type": "webauthn.get",
            "challenge": req.challenge,
            "origin": "http://localhost:8788"
        });
        let client2_raw = serde_json::to_vec(&client2).unwrap();
        let mut auth2 = Vec::new();
        auth2.extend_from_slice(&Sha256::digest(b"localhost"));
        auth2.push(0x01);
        auth2.extend_from_slice(&1u32.to_be_bytes());
        let client_hash = Sha256::digest(&client2_raw);
        let mut msg = auth2.clone();
        msg.extend_from_slice(&client_hash);
        let sig: Signature = sk.sign(&msg);
        let sig_der = sig.to_der();
        let ok = reg
            .finish_authentication(
                &req.challenge,
                &b64url(cred_id),
                &b64url(&client2_raw),
                &b64url(&auth2),
                &b64url(sig_der.as_bytes()),
            )
            .unwrap();
        assert_eq!(ok, b64url(cred_id));
    }
}
