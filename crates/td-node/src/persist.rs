//! Durable node identity + Pond claim + event log + E2EE under a data directory.
//!
//! Layout (when `TD_DATA_DIR` / `--data-dir` is set):
//! ```text
//! <data_dir>/
//!   identity.key          # 32-byte ed25519 seed (mode 0600)
//!   claim.json            # owner claim (no recovery plaintext)
//!   events.sqlite         # signed event DAG (WAL)
//!   e2ee.json             # vodozemac pickles (encrypted blob fields)
//!   meta.json             # ts_counter etc.
//! ```
//!
//! Pair tokens + owner sessions stay in-memory (short-lived by design).

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use td_crypto::{DeviceKeypair, E2eeDevice, E2eeDurablePackage};
use thiserror::Error;

use crate::rpc::ClaimState;

const IDENTITY_FILE: &str = "identity.key";
const CLAIM_FILE: &str = "claim.json";
const EVENTS_DB: &str = "events.sqlite";
const E2EE_FILE: &str = "e2ee.json";
const META_FILE: &str = "meta.json";

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("e2ee: {0}")]
    E2ee(String),
    #[error("invalid identity key length (want 32 bytes, got {0})")]
    BadIdentityLen(usize),
    #[error("invalid identity key hex: {0}")]
    BadIdentityHex(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeMetaDisk {
    #[serde(default)]
    pub ts_counter: u64,
}

/// On-disk claim document. Recovery code plaintext is never stored.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimDisk {
    pub claimed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// blake3 hex of normalized recovery code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at_ms: Option<u64>,
}

impl From<&ClaimState> for ClaimDisk {
    fn from(c: &ClaimState) -> Self {
        Self {
            claimed: c.claimed,
            display_name: c.display_name.clone(),
            recovery_hash: c.recovery_hash.clone(),
            claimed_at_ms: c.claimed_at_ms,
        }
    }
}

impl From<ClaimDisk> for ClaimState {
    fn from(c: ClaimDisk) -> Self {
        ClaimState {
            claimed: c.claimed,
            display_name: c.display_name,
            recovery_hash: c.recovery_hash,
            claimed_at_ms: c.claimed_at_ms,
        }
    }
}

/// Filesystem-backed identity + claim store.
#[derive(Debug, Clone)]
pub struct NodeDataDir {
    root: PathBuf,
}

impl NodeDataDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn identity_path(&self) -> PathBuf {
        self.root.join(IDENTITY_FILE)
    }

    pub fn claim_path(&self) -> PathBuf {
        self.root.join(CLAIM_FILE)
    }

    pub fn events_db_path(&self) -> PathBuf {
        self.root.join(EVENTS_DB)
    }

    pub fn e2ee_path(&self) -> PathBuf {
        self.root.join(E2EE_FILE)
    }

    pub fn meta_path(&self) -> PathBuf {
        self.root.join(META_FILE)
    }

    pub fn ensure_dir(&self) -> Result<(), PersistError> {
        fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    /// Load existing keypair or generate + persist a new one.
    pub fn load_or_create_identity(&self) -> Result<DeviceKeypair, PersistError> {
        self.ensure_dir()?;
        let path = self.identity_path();
        if path.exists() {
            let raw = fs::read(&path)?;
            let seed = parse_identity_bytes(&raw)?;
            return Ok(DeviceKeypair::from_seed_bytes(&seed));
        }
        let kp = DeviceKeypair::generate();
        self.write_identity(&kp)?;
        Ok(kp)
    }

    pub fn write_identity(&self, kp: &DeviceKeypair) -> Result<(), PersistError> {
        self.ensure_dir()?;
        let path = self.identity_path();
        let tmp = path.with_extension("key.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
            }
            f.write_all(&kp.to_seed_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub(crate) fn load_claim(&self) -> Result<ClaimState, PersistError> {
        let path = self.claim_path();
        if !path.exists() {
            return Ok(ClaimState::default());
        }
        let s = fs::read_to_string(&path)?;
        let disk: ClaimDisk = serde_json::from_str(&s)?;
        Ok(disk.into())
    }

    pub(crate) fn save_claim(&self, claim: &ClaimState) -> Result<(), PersistError> {
        self.ensure_dir()?;
        let path = self.claim_path();
        let tmp = path.with_extension("json.tmp");
        let disk = ClaimDisk::from(claim);
        let body = serde_json::to_vec_pretty(&disk)?;
        atomic_write_bytes(&tmp, &path, &body)?;
        Ok(())
    }

    pub(crate) fn load_meta(&self) -> Result<NodeMetaDisk, PersistError> {
        let path = self.meta_path();
        if !path.exists() {
            return Ok(NodeMetaDisk { ts_counter: 1 });
        }
        let s = fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&s)?)
    }

    pub(crate) fn save_meta(&self, meta: &NodeMetaDisk) -> Result<(), PersistError> {
        self.ensure_dir()?;
        let path = self.meta_path();
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(meta)?;
        atomic_write_bytes(&tmp, &path, &body)?;
        Ok(())
    }

    pub(crate) fn load_e2ee(
        &self,
        device_id: td_crypto::DeviceId,
    ) -> Result<E2eeDevice, PersistError> {
        let path = self.e2ee_path();
        if !path.exists() {
            return Ok(E2eeDevice::new(device_id));
        }
        let s = fs::read_to_string(&path)?;
        let pkg: E2eeDurablePackage = serde_json::from_str(&s)?;
        E2eeDevice::import_durable(device_id, &pkg).map_err(|e| PersistError::E2ee(e.to_string()))
    }

    pub(crate) fn save_e2ee(&self, e2ee: &E2eeDevice) -> Result<(), PersistError> {
        self.ensure_dir()?;
        let path = self.e2ee_path();
        let tmp = path.with_extension("json.tmp");
        let pkg = e2ee
            .export_durable()
            .map_err(|e| PersistError::E2ee(e.to_string()))?;
        let body = serde_json::to_vec_pretty(&pkg)?;
        atomic_write_bytes(&tmp, &path, &body)?;
        Ok(())
    }
}

fn atomic_write_bytes(tmp: &Path, final_path: &Path, body: &[u8]) -> Result<(), PersistError> {
    {
        let mut f = fs::File::create(tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        f.write_all(body)?;
        if !body.ends_with(b"\n") {
            f.write_all(b"\n")?;
        }
        f.sync_all()?;
    }
    fs::rename(tmp, final_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(final_path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn parse_identity_bytes(raw: &[u8]) -> Result<[u8; 32], PersistError> {
    // Prefer raw 32-byte seed; also accept hex (64 chars, optional whitespace/newline).
    if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let s = std::str::from_utf8(raw)
        .map_err(|_| PersistError::BadIdentityLen(raw.len()))?
        .trim();
    let bytes = hex::decode(s).map_err(|e| PersistError::BadIdentityHex(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(PersistError::BadIdentityLen(bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn identity_roundtrip_stable_device_id() {
        let dir = std::env::temp_dir().join(format!(
            "td-persist-id-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = NodeDataDir::new(&dir);
        let a = store.load_or_create_identity().unwrap();
        let b = store.load_or_create_identity().unwrap();
        assert_eq!(a.device_id(), b.device_id());
        assert_eq!(a.to_seed_bytes(), b.to_seed_bytes());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "td-persist-claim-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = NodeDataDir::new(&dir);
        let claim = ClaimState {
            claimed: true,
            display_name: Some("Pond Alpha".into()),
            recovery_hash: Some("abc123".into()),
            claimed_at_ms: Some(42),
        };
        store.save_claim(&claim).unwrap();
        let loaded = store.load_claim().unwrap();
        assert!(loaded.claimed);
        assert_eq!(loaded.display_name.as_deref(), Some("Pond Alpha"));
        assert_eq!(loaded.recovery_hash.as_deref(), Some("abc123"));
        assert_eq!(loaded.claimed_at_ms, Some(42));
        // plaintext recovery must never appear on disk
        let raw = fs::read_to_string(store.claim_path()).unwrap();
        assert!(!raw.contains("recovery_code"));
        let _ = fs::remove_dir_all(&dir);
    }
}
