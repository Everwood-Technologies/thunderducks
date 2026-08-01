use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Stable device id (blake3 of verifying key) — mirrors td_event::DeviceId bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 32]);

impl DeviceId {
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        Self(*blake3::hash(vk.as_bytes()).as_bytes())
    }
}

impl From<td_event::DeviceId> for DeviceId {
    fn from(value: td_event::DeviceId) -> Self {
        Self(value.0)
    }
}

impl From<DeviceId> for td_event::DeviceId {
    fn from(value: DeviceId) -> Self {
        td_event::DeviceId(value.0)
    }
}

impl std::fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceId({})", hex::encode(self.0))
    }
}

#[derive(Clone)]
pub struct DeviceKeypair {
    signing: SigningKey,
    device_id: DeviceId,
}

impl DeviceKeypair {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let device_id = DeviceId::from_verifying_key(&signing.verifying_key());
        Self { signing, device_id }
    }

    /// Reconstruct from the 32-byte ed25519 seed (SigningKey secret).
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let device_id = DeviceId::from_verifying_key(&signing.verifying_key());
        Self { signing, device_id }
    }

    /// Export the 32-byte ed25519 seed for durable node identity.
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn event_device_id(&self) -> td_event::DeviceId {
        self.device_id.into()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn public_bundle(&self) -> DeviceBundle {
        DeviceBundle {
            device_id: self.device_id,
            verifying_key: *self.signing.verifying_key().as_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceBundle {
    pub device_id: DeviceId,
    pub verifying_key: [u8; 32],
}

impl DeviceBundle {
    pub fn verifying_key(&self) -> Result<VerifyingKey, ed25519_dalek::SignatureError> {
        VerifyingKey::from_bytes(&self.verifying_key)
    }
}
