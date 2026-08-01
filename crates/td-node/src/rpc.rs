//! Local node HTTP RPC for CLI + TS web (Wave E).
//!
//! Binds localhost only. In-memory single-device session for MVP smoke.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rand::RngCore;
use td_crypto::{
    DeviceKeypair, E2eeDevice, LinkRegistry, MegolmCiphertext, OlmCiphertext, OlmDeviceKeys,
    PasskeyRegistry, RoomOutboundPackage,
};
use td_event::{
    sign_event, DeviceId, EventId, EventKind, RoomId, RoomRegistry, SignedEvent, UnsignedEvent,
};
use td_net::{accept_once, dial, read_event, write_event, PeerUri};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex, Notify};
use tower_http::cors::{Any, CorsLayer};

use crate::persist::NodeDataDir;
use crate::sync::{DeviceNode, SyncOffer};

/// Room-scoped change signal for wait long-poll + SSE.
#[derive(Debug, Clone)]
struct RoomChange {
    room_hex: String,
    /// Message count at notify time (hint; subscribers re-snapshot).
    #[allow(dead_code)]
    count: usize,
}

/// Fan-out hub: broadcast for SSE subscribers; Notify for wait long-poll.
struct RoomNotify {
    tx: broadcast::Sender<RoomChange>,
    tick: Arc<Notify>,
}

impl RoomNotify {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            tx,
            tick: Arc::new(Notify::new()),
        }
    }

    fn notify(&self, room_hex: &str, count: usize) {
        let _ = self.tx.send(RoomChange {
            room_hex: room_hex.to_string(),
            count,
        });
        self.tick.notify_waiters();
    }

    fn subscribe(&self) -> broadcast::Receiver<RoomChange> {
        self.tx.subscribe()
    }
}

#[derive(Clone)]
pub struct RpcState {
    inner: Arc<Mutex<NodeSession>>,
    notify: Arc<RoomNotify>,
}

/// Known peer endpoints. HTTP RPC = reliable share+delta; P2P = best-effort.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEndpoint {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p2p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc: Option<String>,
}

struct NodeSession {
    keypair: DeviceKeypair,
    node: DeviceNode,
    rooms: RoomRegistry,
    /// peer name -> endpoints (P2P and/or HTTP RPC)
    peers: HashMap<String, PeerEndpoint>,
    link: LinkRegistry,
    passkeys: PasskeyRegistry,
    e2ee: E2eeDevice,
    /// rooms where we own an outbound Megolm session (encrypt path)
    e2ee_rooms: HashMap<String, bool>,
    ts_counter: u64,
    /// local P2P listen URI once started
    p2p_uri: Option<String>,
    /// local HTTP RPC base once serving
    rpc_base: Option<String>,
    /// Pond first-run claim (owner display name + recovery code hash).
    claim: ClaimState,
    /// Active short-lived pairing invites (token -> meta).
    pair_tokens: HashMap<String, PairToken>,
    /// Active owner sessions (token -> meta). Minted by claim or recovery login.
    owner_sessions: HashMap<String, OwnerSession>,
    /// Recovery login failure throttle (in-memory).
    recovery_failures: u32,
    recovery_lock_until: Option<Instant>,
    /// Optional durable store (identity + claim). None = pure in-memory.
    data_dir: Option<NodeDataDir>,
}

impl NodeSession {
    fn new() -> Self {
        Self::from_parts(DeviceKeypair::generate(), ClaimState::default(), None)
    }

    fn from_parts(
        keypair: DeviceKeypair,
        claim: ClaimState,
        data_dir: Option<NodeDataDir>,
    ) -> Self {
        let mut link = LinkRegistry::new(keypair.device_id());
        let _ = link.trust_local(&keypair);
        let node = DeviceNode::from_crypto_device(keypair.device_id());
        let e2ee = E2eeDevice::new(keypair.device_id());
        Self {
            keypair,
            node,
            rooms: RoomRegistry::new(),
            peers: HashMap::new(),
            link,
            passkeys: PasskeyRegistry::localhost_default(),
            e2ee,
            e2ee_rooms: HashMap::new(),
            ts_counter: 1,
            p2p_uri: None,
            rpc_base: None,
            claim,
            pair_tokens: HashMap::new(),
            owner_sessions: HashMap::new(),
            recovery_failures: 0,
            recovery_lock_until: None,
            data_dir,
        }
    }

    fn load_from_data_dir(dir: NodeDataDir) -> Result<Self, String> {
        let keypair = dir
            .load_or_create_identity()
            .map_err(|e| format!("identity: {e}"))?;
        let claim = dir.load_claim().map_err(|e| format!("claim: {e}"))?;
        Ok(Self::from_parts(keypair, claim, Some(dir)))
    }

    fn persist_claim(&self) -> Result<(), String> {
        if let Some(dir) = &self.data_dir {
            dir.save_claim(&self.claim)
                .map_err(|e| format!("persist claim: {e}"))?;
        }
        Ok(())
    }

    fn purge_expired_pair_tokens(&mut self) {
        let now = Instant::now();
        self.pair_tokens.retain(|_, t| t.expires_at > now);
    }

    fn purge_expired_owner_sessions(&mut self) {
        let now = Instant::now();
        self.owner_sessions.retain(|_, s| s.expires_at > now);
    }

    fn mint_owner_session(&mut self, source: &str) -> (String, u64) {
        self.purge_expired_owner_sessions();
        // Cap concurrent owner sessions.
        if self.owner_sessions.len() >= 16 {
            if let Some(oldest) = self
                .owner_sessions
                .iter()
                .min_by_key(|(_, s)| s.created_ms)
                .map(|(k, _)| k.clone())
            {
                self.owner_sessions.remove(&oldest);
            }
        }
        let ttl_secs = 86_400u64; // 24h
        let token = random_token_hex(24);
        self.owner_sessions.insert(
            token.clone(),
            OwnerSession {
                source: source.to_string(),
                created_ms: now_ms(),
                expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
        (token, ttl_secs)
    }

    fn owner_session_valid(&mut self, token: &str) -> bool {
        self.purge_expired_owner_sessions();
        self.owner_sessions
            .get(token)
            .is_some_and(|s| s.expires_at > Instant::now())
    }

    fn revoke_owner_session(&mut self, token: &str) -> bool {
        self.owner_sessions.remove(token).is_some()
    }

    fn recovery_locked(&self) -> Option<u64> {
        let until = self.recovery_lock_until?;
        let now = Instant::now();
        if until > now {
            Some(until.saturating_duration_since(now).as_secs().max(1))
        } else {
            None
        }
    }

    fn note_recovery_failure(&mut self) {
        self.recovery_failures = self.recovery_failures.saturating_add(1);
        if self.recovery_failures >= 5 {
            self.recovery_lock_until = Some(Instant::now() + Duration::from_secs(60));
            self.recovery_failures = 0;
        }
    }

    fn note_recovery_success(&mut self) {
        self.recovery_failures = 0;
        self.recovery_lock_until = None;
    }

    fn next_ts(&mut self) -> u64 {
        self.ts_counter += 1;
        self.ts_counter
    }

    /// Ensure we can encrypt for this room.
    /// B2: one shared outbound Megolm per room (create only if missing outbound).
    /// Auto share-on-send makes multi-node decrypt+shared-send work without Sync.
    fn ensure_room_e2ee(&mut self, room_hex: &str) {
        if self.e2ee.has_outbound(room_hex) {
            self.e2ee_rooms.insert(room_hex.to_string(), true);
            return;
        }
        if self.e2ee_rooms.contains_key(room_hex) {
            // Marked but outbound missing (should not happen) — recreate.
        }
        let _ = self.e2ee.create_group_session(room_hex);
        self.e2ee_rooms.insert(room_hex.to_string(), true);
    }

    fn upsert_peer(&mut self, name: &str, uri: &str, rpc: Option<&str>, p2p: Option<&str>) {
        let mut ep = self.peers.remove(name).unwrap_or(PeerEndpoint {
            name: name.to_string(),
            p2p: None,
            rpc: None,
        });
        let u = uri.trim();
        if u.starts_with("http://") || u.starts_with("https://") {
            ep.rpc = Some(u.trim_end_matches('/').to_string());
        } else if u.starts_with("td://") {
            ep.p2p = Some(u.to_string());
        } else if !u.is_empty() {
            ep.rpc = Some(format!("http://{}", u.trim_end_matches('/')));
        }
        if let Some(r) = rpc {
            let r = r.trim().trim_end_matches('/');
            if !r.is_empty() {
                ep.rpc = Some(if r.starts_with("http") {
                    r.to_string()
                } else {
                    format!("http://{r}")
                });
            }
        }
        if let Some(p) = p2p {
            let p = p.trim();
            if !p.is_empty() {
                ep.p2p = Some(if p.starts_with("td://") {
                    p.to_string()
                } else {
                    format!("td://{p}")
                });
            }
        }
        self.peers.insert(name.to_string(), ep);
    }

    /// Ingest a remote signed event into DAG + room registry.
    fn ingest_remote(&mut self, ev: SignedEvent) -> Result<bool, String> {
        let kind = ev.kind;
        let inserted = self
            .node
            .commit_remote(ev.clone())
            .map_err(|e| e.to_string())?;
        if matches!(kind, EventKind::CreateRoom | EventKind::Membership) {
            let _ = self.rooms.apply_event(ev);
        }
        Ok(inserted)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub device_id: String,
    pub verifying_key: String,
    pub event_count: usize,
    pub rooms: Vec<String>,
    pub linked_devices: Vec<String>,
    pub peers: Vec<PeerInfo>,
    pub passkey_credentials: usize,
    pub e2ee_default: bool,
    pub p2p_uri: Option<String>,
    pub claimed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at_ms: Option<u64>,
    pub pair_tokens_active: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    /// Back-compat single uri (prefers rpc, else p2p).
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p2p: Option<String>,
}

/// Owner claim state for first-run Pond setup.
#[derive(Debug, Clone, Default)]
pub(crate) struct ClaimState {
    pub(crate) claimed: bool,
    pub(crate) display_name: Option<String>,
    /// blake3 hex of recovery code (never store plaintext).
    pub(crate) recovery_hash: Option<String>,
    pub(crate) claimed_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct PairToken {
    label: String,
    expires_at: Instant,
    created_ms: u64,
    redeemed_by: Option<String>,
}

#[derive(Debug, Clone)]
struct OwnerSession {
    source: String,
    created_ms: u64,
    expires_at: Instant,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_token_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn recovery_code_new() -> String {
    let raw = random_token_hex(10);
    format!(
        "{}-{}-{}-{}",
        &raw[0..5],
        &raw[5..10],
        &raw[10..15],
        &raw[15..20]
    )
}

fn hash_recovery(code: &str) -> String {
    let norm = code.trim().to_uppercase().replace([' ', '_'], "");
    hex::encode(blake3::hash(norm.as_bytes()).as_bytes())
}

#[derive(Debug, Deserialize)]
pub struct CreateRoomRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRoomResponse {
    pub room_id: String,
    pub event_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SendRequest {
    pub room_id: String,
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendResponse {
    pub event_id: String,
    pub ts_ms: u64,
    /// Peers that accepted our session key + event delta.
    #[serde(default)]
    pub fanout_ok: usize,
    /// Peers we attempted via HTTP RPC.
    #[serde(default)]
    pub fanout_peers: usize,
    #[serde(default)]
    pub fanout_errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RoomQuery {
    pub room_id: String,
}

#[derive(Debug, Deserialize)]
pub struct WaitMessagesRequest {
    pub room_id: String,
    /// Return immediately if message count differs from this (default 0).
    #[serde(default)]
    pub since_count: usize,
    /// Max wait in milliseconds (clamped 250..=30000, default 15000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageView {
    pub event_id: String,
    pub author: String,
    pub ts_ms: u64,
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessagesResponse {
    pub room_id: String,
    pub messages: Vec<MessageView>,
}

#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub name: String,
    /// Primary uri: `http://…` RPC and/or `td://…` P2P (auto-classified).
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub rpc: Option<String>,
    #[serde(default)]
    pub p2p: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LinkSecondaryRequest {
    /// Optional label for the secondary device (reserved for UX).
    #[serde(default)]
    #[allow(dead_code)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkSecondaryResponse {
    pub primary_device: String,
    pub secondary_device: String,
    pub linked: bool,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn parse_room_id(s: &str) -> Result<RoomId, String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    if b.len() != 32 {
        return Err("room_id must be 32 bytes hex".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(RoomId(a))
}

fn payload_text(ev: &SignedEvent) -> String {
    // Legacy plaintext path: JSON {"text":...} else utf8 lossy
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&ev.payload) {
        if let Some(t) = v.get("text").and_then(|x| x.as_str()) {
            return t.to_string();
        }
    }
    String::from_utf8_lossy(&ev.payload).into_owned()
}

fn decrypt_message_text(e2ee: &mut E2eeDevice, ev: &SignedEvent) -> String {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&ev.payload) {
        if v.get("enc").and_then(|x| x.as_str()) == Some("megolm") {
            let session_id = v
                .get("session_id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            let ciphertext_b64 = v
                .get("ciphertext_b64")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            let ct = MegolmCiphertext {
                sender_device: td_crypto::DeviceId(ev.author_device.0),
                session_id,
                ciphertext_b64,
            };
            if let Ok(plain) = e2ee.megolm_decrypt(&ct) {
                if let Ok(pv) = serde_json::from_slice::<serde_json::Value>(&plain) {
                    if let Some(t) = pv.get("text").and_then(|x| x.as_str()) {
                        return t.to_string();
                    }
                }
                return String::from_utf8_lossy(&plain).into_owned();
            }
            return "[e2ee:decrypt-failed]".into();
        }
        if let Some(t) = v.get("text").and_then(|x| x.as_str()) {
            return t.to_string();
        }
    }
    String::from_utf8_lossy(&ev.payload).into_owned()
}

async fn status(State(st): State<RpcState>) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let rooms = g.node.room_ids().into_iter().map(|r| hex32(&r.0)).collect();
    let linked = g
        .link
        .linked_devices()
        .into_iter()
        .map(|d| hex32(&d.0))
        .collect();
    let peers = g
        .peers
        .values()
        .map(|ep| {
            let uri = ep
                .rpc
                .clone()
                .or_else(|| ep.p2p.clone())
                .unwrap_or_default();
            PeerInfo {
                name: ep.name.clone(),
                uri,
                rpc: ep.rpc.clone(),
                p2p: ep.p2p.clone(),
            }
        })
        .collect();
    g.purge_expired_pair_tokens();
    Json(StatusResponse {
        device_id: hex32(&g.keypair.device_id().0),
        verifying_key: hex::encode(g.keypair.verifying_key().as_bytes()),
        event_count: g.node.event_count(),
        rooms,
        linked_devices: linked,
        peers,
        passkey_credentials: g.passkeys.credential_count(),
        e2ee_default: true,
        p2p_uri: g.p2p_uri.clone(),
        claimed: g.claim.claimed,
        display_name: g.claim.display_name.clone(),
        claimed_at_ms: g.claim.claimed_at_ms,
        pair_tokens_active: g
            .pair_tokens
            .values()
            .filter(|t| t.redeemed_by.is_none())
            .count(),
    })
}

#[derive(Debug, Deserialize)]
struct ClaimRequest {
    display_name: String,
    #[serde(default)]
    recovery_code: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClaimResponse {
    ok: bool,
    claimed: bool,
    display_name: String,
    recovery_code: String,
    device_id: String,
    claimed_at_ms: u64,
    /// Owner session token (also set on first claim so the claimer is unlocked).
    owner_token: String,
    expires_in_secs: u64,
}

#[derive(Debug, Serialize)]
struct ClaimStatusResponse {
    claimed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_at_ms: Option<u64>,
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rpc_base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p_uri: Option<String>,
    /// True when recovery hash is present (login available).
    recovery_login: bool,
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let rest = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer "))?;
    let t = rest.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn extract_owner_token(headers: &HeaderMap) -> Option<String> {
    if let Some(t) = extract_bearer(headers) {
        return Some(t);
    }
    headers
        .get("x-td-owner-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Require a valid owner session. Returns 401 body on failure.
fn require_owner(
    g: &mut NodeSession,
    headers: &HeaderMap,
) -> Result<(), Box<axum::response::Response>> {
    let Some(token) = extract_owner_token(headers) else {
        return Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "owner session required (Authorization: Bearer <token>)".into(),
                }),
            )
                .into_response(),
        ));
    };
    if !g.owner_session_valid(&token) {
        return Err(Box::new(
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "invalid or expired owner session".into(),
                }),
            )
                .into_response(),
        ));
    }
    Ok(())
}

async fn claim_status(State(st): State<RpcState>) -> impl IntoResponse {
    let g = st.inner.lock().await;
    Json(ClaimStatusResponse {
        claimed: g.claim.claimed,
        display_name: g.claim.display_name.clone(),
        claimed_at_ms: g.claim.claimed_at_ms,
        device_id: hex32(&g.keypair.device_id().0),
        rpc_base: g.rpc_base.clone(),
        p2p_uri: g.p2p_uri.clone(),
        recovery_login: g.claim.claimed && g.claim.recovery_hash.is_some(),
    })
}

async fn claim_node(
    State(st): State<RpcState>,
    Json(req): Json<ClaimRequest>,
) -> impl IntoResponse {
    let name = req.display_name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "display_name required (1-64 chars)".into(),
            }),
        )
            .into_response();
    }
    let mut g = st.inner.lock().await;
    if g.claim.claimed {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "node already claimed".into(),
            }),
        )
            .into_response();
    }
    let code = req
        .recovery_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(recovery_code_new);
    if code.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "recovery_code too short".into(),
            }),
        )
            .into_response();
    }
    let at = now_ms();
    g.claim = ClaimState {
        claimed: true,
        display_name: Some(name.clone()),
        recovery_hash: Some(hash_recovery(&code)),
        claimed_at_ms: Some(at),
    };
    if let Err(e) = g.persist_claim() {
        // Roll back in-memory claim so a retry can succeed.
        g.claim = ClaimState::default();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: e,
            }),
        )
            .into_response();
    }
    let (owner_token, expires_in_secs) = g.mint_owner_session("claim");
    Json(ClaimResponse {
        ok: true,
        claimed: true,
        display_name: name,
        recovery_code: code,
        device_id: hex32(&g.keypair.device_id().0),
        claimed_at_ms: at,
        owner_token,
        expires_in_secs,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
struct RecoveryLoginRequest {
    recovery_code: String,
}

#[derive(Debug, Serialize)]
struct RecoveryLoginResponse {
    ok: bool,
    owner_token: String,
    expires_in_secs: u64,
    display_name: Option<String>,
    device_id: String,
}

#[derive(Debug, Serialize)]
struct OwnerSessionStatus {
    ok: bool,
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in_secs: Option<u64>,
    claimed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

async fn recovery_login(
    State(st): State<RpcState>,
    Json(req): Json<RecoveryLoginRequest>,
) -> impl IntoResponse {
    let code = req.recovery_code.trim();
    if code.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "recovery_code required".into(),
            }),
        )
            .into_response();
    }
    let mut g = st.inner.lock().await;
    if let Some(secs) = g.recovery_locked() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorBody {
                error: format!("too many failed attempts; retry in {secs}s"),
            }),
        )
            .into_response();
    }
    if !g.claim.claimed {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "node not claimed".into(),
            }),
        )
            .into_response();
    }
    let Some(expected) = g.claim.recovery_hash.clone() else {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "recovery login not configured".into(),
            }),
        )
            .into_response();
    };
    let got = hash_recovery(code);
    // Constant-time-ish compare on hex strings.
    let ok = got.len() == expected.len()
        && got
            .as_bytes()
            .iter()
            .zip(expected.as_bytes().iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !ok {
        g.note_recovery_failure();
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid recovery code".into(),
            }),
        )
            .into_response();
    }
    g.note_recovery_success();
    let (owner_token, expires_in_secs) = g.mint_owner_session("recovery");
    Json(RecoveryLoginResponse {
        ok: true,
        owner_token,
        expires_in_secs,
        display_name: g.claim.display_name.clone(),
        device_id: hex32(&g.keypair.device_id().0),
    })
    .into_response()
}

async fn owner_session_status(
    State(st): State<RpcState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let token = extract_owner_token(&headers);
    let (authenticated, source, expires_in_secs) = match token {
        Some(t) if g.owner_session_valid(&t) => {
            let meta = g.owner_sessions.get(&t).cloned();
            let (src, exp) = meta
                .map(|m| {
                    let secs = m
                        .expires_at
                        .saturating_duration_since(Instant::now())
                        .as_secs();
                    (Some(m.source), Some(secs))
                })
                .unwrap_or((None, None));
            (true, src, exp)
        }
        _ => (false, None, None),
    };
    Json(OwnerSessionStatus {
        ok: true,
        authenticated,
        source,
        expires_in_secs,
        claimed: g.claim.claimed,
        display_name: g.claim.display_name.clone(),
    })
}

async fn owner_logout(State(st): State<RpcState>, headers: HeaderMap) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let Some(token) = extract_owner_token(&headers) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "owner token required".into(),
            }),
        )
            .into_response();
    };
    let revoked = g.revoke_owner_session(&token);
    Json(serde_json::json!({ "ok": true, "revoked": revoked })).into_response()
}

#[derive(Debug, Deserialize)]
struct PairCreateRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct PairCreateResponse {
    ok: bool,
    token: String,
    label: String,
    expires_in_secs: u64,
    pair_path: String,
    rpc_base: Option<String>,
}

async fn pair_create(
    State(st): State<RpcState>,
    headers: HeaderMap,
    Json(req): Json<PairCreateRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    if !g.claim.claimed {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "claim node before minting pair tokens".into(),
            }),
        )
            .into_response();
    }
    if let Err(resp) = require_owner(&mut g, &headers) {
        return *resp;
    }
    g.purge_expired_pair_tokens();
    let ttl = req.ttl_secs.unwrap_or(600).clamp(60, 3600);
    let label = req
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("device")
        .chars()
        .take(32)
        .collect::<String>();
    let token = random_token_hex(16);
    g.pair_tokens.insert(
        token.clone(),
        PairToken {
            label: label.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
            created_ms: now_ms(),
            redeemed_by: None,
        },
    );
    let rpc_base = g.rpc_base.clone();
    Json(PairCreateResponse {
        ok: true,
        token: token.clone(),
        label,
        expires_in_secs: ttl,
        pair_path: format!("?pair={token}"),
        rpc_base,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
struct PairRedeemRequest {
    token: String,
    #[serde(default)]
    device_label: Option<String>,
}

#[derive(Debug, Serialize)]
struct PairRedeemResponse {
    ok: bool,
    paired: bool,
    label: String,
    pond_name: Option<String>,
    device_id: String,
    rpc_base: Option<String>,
    p2p_uri: Option<String>,
}

async fn pair_redeem(
    State(st): State<RpcState>,
    Json(req): Json<PairRedeemRequest>,
) -> impl IntoResponse {
    let token = req.token.trim().to_string();
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "token required".into(),
            }),
        )
            .into_response();
    }
    let mut g = st.inner.lock().await;
    if !g.claim.claimed {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "node not claimed".into(),
            }),
        )
            .into_response();
    }
    g.purge_expired_pair_tokens();
    let expired_or_missing = match g.pair_tokens.get(&token) {
        None => true,
        Some(entry) => entry.expires_at <= Instant::now(),
    };
    if expired_or_missing {
        g.pair_tokens.remove(&token);
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "invalid or expired pair token".into(),
            }),
        )
            .into_response();
    }
    if g.pair_tokens
        .get(&token)
        .map(|e| e.redeemed_by.is_some())
        .unwrap_or(true)
    {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "pair token already used".into(),
            }),
        )
            .into_response();
    }
    let default_label = g
        .pair_tokens
        .get(&token)
        .map(|e| e.label.clone())
        .unwrap_or_else(|| "device".into());
    let label = req
        .device_label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(32).collect::<String>())
        .unwrap_or(default_label);
    let secondary = DeviceKeypair::generate();
    let secondary_hex = hex32(&secondary.device_id().0);
    let _ = g.link.trust_local(&secondary);
    if let Some(entry) = g.pair_tokens.get_mut(&token) {
        entry.redeemed_by = Some(secondary_hex);
        entry.label = label.clone();
    }
    Json(PairRedeemResponse {
        ok: true,
        paired: true,
        label,
        pond_name: g.claim.display_name.clone(),
        device_id: hex32(&g.keypair.device_id().0),
        rpc_base: g.rpc_base.clone(),
        p2p_uri: g.p2p_uri.clone(),
    })
    .into_response()
}

async fn pair_list(State(st): State<RpcState>) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    g.purge_expired_pair_tokens();
    let now = Instant::now();
    let items: Vec<serde_json::Value> = g
        .pair_tokens
        .iter()
        .map(|(tok, meta)| {
            let secs = meta.expires_at.saturating_duration_since(now).as_secs();
            serde_json::json!({
                "token_prefix": tok.chars().take(8).collect::<String>(),
                "label": meta.label,
                "expires_in_secs": secs,
                "redeemed": meta.redeemed_by.is_some(),
                "created_ms": meta.created_ms,
            })
        })
        .collect();
    Json(serde_json::json!({
        "claimed": g.claim.claimed,
        "tokens": items,
    }))
    .into_response()
}

async fn create_room(
    State(st): State<RpcState>,
    Json(req): Json<CreateRoomRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let ts = g.next_ts();
    let creator = g.keypair.event_device_id();
    let sk = g.keypair.signing_key().clone();
    match g.rooms.create_room(&sk, creator, req.name, ts) {
        Ok((room_id, signed)) => {
            if let Err(e) = g.node.commit_local(signed.clone()) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody {
                        error: e.to_string(),
                    }),
                )
                    .into_response();
            }
            Json(CreateRoomResponse {
                room_id: hex32(&room_id.0),
                event_id: hex32(&signed.id.0),
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn send_message(
    State(st): State<RpcState>,
    Json(req): Json<SendRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let room_id = match parse_room_id(&req.room_id) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })).into_response();
        }
    };
    if let Err(e) = g
        .rooms
        .assert_can_message(&room_id, &g.keypair.event_device_id())
    {
        // If room only lives in node DAG (imported), still allow author messages.
        if g.node.room_event_ids(&room_id).is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    }
    let parents: Vec<EventId> = g.node.tips(&room_id);
    let ts = g.next_ts();
    let room_hex = hex32(&room_id.0);
    g.ensure_room_e2ee(&room_hex);
    // Export FULL outbound pickle BEFORE encrypt (B2 shared room session).
    // Peers import outbound so they encrypt with the same session_id; inbound
    // session_key is included so they can also decrypt. Post-encrypt export
    // would start after this ciphertext and peers would fail to decrypt it.
    let room_outbound = g.e2ee.export_room_outbound(&room_hex).ok();
    let plain = serde_json::to_vec(&serde_json::json!({ "text": req.text })).unwrap_or_default();
    let ct = match g.e2ee.megolm_encrypt(&room_hex, &plain) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("e2ee encrypt: {e}"),
                }),
            )
                .into_response();
        }
    };
    let payload = serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "enc": "megolm",
        "session_id": ct.session_id,
        "ciphertext_b64": ct.ciphertext_b64,
        "sender_device": hex32(&ct.sender_device.0),
    }))
    .unwrap_or_default();
    let unsigned = UnsignedEvent {
        room_id,
        parents,
        kind: EventKind::Message,
        payload,
        author_device: g.keypair.event_device_id(),
        ts_ms: ts,
    };
    let signed = match sign_event(g.keypair.signing_key(), unsigned) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };
    // Keep room registry DAG tips current for membership-aware rooms.
    let _ = g.rooms.apply_event(signed.clone());
    if let Err(e) = g.node.commit_local(signed.clone()) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response();
    }
    let event_id = hex32(&signed.id.0);
    let ts_ms = signed.ts_ms;
    let peers_snapshot: Vec<PeerEndpoint> = g.peers.values().cloned().collect();
    let new_event = signed.clone();
    let full_dag = g.node.list_events(&room_id);
    drop(g);

    // Reliable path: HTTP share Megolm session + delta ingest (full DAG fallback).
    let mut fanout_ok = 0usize;
    let mut fanout_errors = Vec::new();
    let fanout_peers = peers_snapshot.iter().filter(|p| p.rpc.is_some()).count();
    if let Ok(client) = reqwest_client() {
        for ep in &peers_snapshot {
            let Some(rpc) = ep.rpc.as_ref() else {
                continue;
            };
            let peer_base = rpc.trim_end_matches('/').to_string();

            // 1) Olm-wrap + deliver pre-encrypt shared room outbound (B2)
            if let Err(e) = share_megolm_olm_to_peer(
                &st,
                &peer_base,
                &room_hex,
                &client,
                room_outbound.as_ref(),
            )
            .await
            {
                fanout_errors.push(format!("{}: olm-share {e}", ep.name));
                continue;
            }

            // 2) delta: try new event only; if peer missing parents, push full DAG once
            let events_to_send = vec![new_event.clone()];
            let accepted = match client
                .post(format!("{peer_base}/v1/sync/ingest"))
                .json(&serde_json::json!({ "events": events_to_send }))
                .send()
                .await
            {
                Ok(r) => r
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v.get("accepted").and_then(|x| x.as_u64()))
                    .unwrap_or(0),
                Err(e) => {
                    fanout_errors.push(format!("{}: ingest {e}", ep.name));
                    continue;
                }
            };
            if accepted == 0 {
                let _ = client
                    .post(format!("{peer_base}/v1/sync/ingest"))
                    .json(&serde_json::json!({ "events": full_dag }))
                    .send()
                    .await;
            }
            fanout_ok += 1;
        }
    }

    // Best-effort P2P: push only the new event (not full DAG every send).
    for ep in peers_snapshot {
        if let Some(uri) = ep.p2p {
            if let Ok(peer) = PeerUri::parse(&uri) {
                let ev = new_event.clone();
                tokio::spawn(async move {
                    if let Ok(mut sock) = dial(&peer).await {
                        let _ = write_event(&mut sock, &ev).await;
                    }
                });
            }
        }
    }

    // Wake wait long-poll + SSE subscribers on this node.
    {
        let count = {
            let g = st.inner.lock().await;
            g.node.list_messages(&room_id).len()
        };
        notify_room(&st, &room_hex, count);
    }

    Json(SendResponse {
        event_id,
        ts_ms,
        fanout_ok,
        fanout_peers,
        fanout_errors,
    })
    .into_response()
}

async fn list_messages(
    State(st): State<RpcState>,
    Json(req): Json<RoomQuery>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let room_id = match parse_room_id(&req.room_id) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })).into_response();
        }
    };
    let messages = g
        .node
        .list_messages(&room_id)
        .into_iter()
        .map(|ev| {
            let text = decrypt_message_text(&mut g.e2ee, &ev);
            MessageView {
                event_id: hex32(&ev.id.0),
                author: hex32(&ev.author_device.0),
                ts_ms: ev.ts_ms,
                text,
            }
        })
        .collect();
    Json(MessagesResponse {
        room_id: req.room_id,
        messages,
    })
    .into_response()
}

/// Snapshot decrypted messages for a room.
async fn snapshot_messages(st: &RpcState, room_id: &RoomId) -> (usize, Vec<MessageView>) {
    let mut g = st.inner.lock().await;
    let msgs: Vec<MessageView> = g
        .node
        .list_messages(room_id)
        .into_iter()
        .map(|ev| {
            let text = decrypt_message_text(&mut g.e2ee, &ev);
            MessageView {
                event_id: hex32(&ev.id.0),
                author: hex32(&ev.author_device.0),
                ts_ms: ev.ts_ms,
                text,
            }
        })
        .collect();
    (msgs.len(), msgs)
}

fn notify_room(st: &RpcState, room_hex: &str, count: usize) {
    st.notify.notify(room_hex, count);
}

async fn notify_room_from_id(st: &RpcState, room_id: &RoomId) {
    let count = {
        let g = st.inner.lock().await;
        g.node.list_messages(room_id).len()
    };
    notify_room(st, &hex32(&room_id.0), count);
}

/// Long-poll until room message count != since_count or timeout.
/// Notify-driven (not busy-poll); rechecks on room change or timeout.
async fn wait_messages(
    State(st): State<RpcState>,
    Json(req): Json<WaitMessagesRequest>,
) -> impl IntoResponse {
    let room_id = match parse_room_id(&req.room_id) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })).into_response();
        }
    };
    let timeout_ms = req.timeout_ms.unwrap_or(15_000).clamp(250, 30_000);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let since = req.since_count;
    let room_hex = req.room_id.clone();

    loop {
        let (count, messages) = snapshot_messages(&st, &room_id).await;
        if count != since {
            return Json(serde_json::json!({
                "room_id": room_hex,
                "messages": messages,
                "count": count,
                "changed": true,
                "timed_out": false,
            }))
            .into_response();
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Json(serde_json::json!({
                "room_id": room_hex,
                "messages": messages,
                "count": count,
                "changed": false,
                "timed_out": true,
            }))
            .into_response();
        }
        let remaining = deadline - now;
        let notified = st.notify.tick.notified();
        tokio::pin!(notified);
        tokio::select! {
            _ = &mut notified => {}
            _ = tokio::time::sleep(remaining) => {}
        }
    }
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    room_id: String,
}

/// True SSE stream of message snapshots for a room.
/// Events: `snapshot` (initial), `messages` (on change), comment keep-alives.
async fn stream_messages(
    State(st): State<RpcState>,
    Query(q): Query<StreamQuery>,
) -> impl IntoResponse {
    let room_id = match parse_room_id(&q.room_id) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })).into_response();
        }
    };
    let room_hex = q.room_id.clone();
    let mut rx = st.notify.subscribe();

    let (init_count, init_msgs) = snapshot_messages(&st, &room_id).await;
    let init_payload = serde_json::json!({
        "room_id": room_hex,
        "messages": init_msgs,
        "count": init_count,
        "changed": false,
        "event": "snapshot",
    });

    let st2 = st.clone();
    let room_hex2 = room_hex.clone();
    let stream = async_stream::stream! {
        yield Ok::<Event, Infallible>(
            Event::default()
                .event("snapshot")
                .data(init_payload.to_string())
        );
        let mut last_count = init_count;
        loop {
            match rx.recv().await {
                Ok(change) => {
                    if change.room_hex != room_hex2 {
                        continue;
                    }
                    let (count, messages) = snapshot_messages(&st2, &room_id).await;
                    if count == last_count {
                        continue;
                    }
                    last_count = count;
                    let payload = serde_json::json!({
                        "room_id": room_hex2,
                        "messages": messages,
                        "count": count,
                        "changed": true,
                        "event": "messages",
                    });
                    yield Ok(Event::default().event("messages").data(payload.to_string()));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let (count, messages) = snapshot_messages(&st2, &room_id).await;
                    last_count = count;
                    let payload = serde_json::json!({
                        "room_id": room_hex2,
                        "messages": messages,
                        "count": count,
                        "changed": true,
                        "event": "messages",
                        "lagged": true,
                    });
                    yield Ok(Event::default().event("messages").data(payload.to_string()));
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("td-ping"),
        )
        .into_response()
}

async fn add_peer(
    State(st): State<RpcState>,
    Json(req): Json<AddPeerRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let uri = req.uri.clone().unwrap_or_default();
    g.upsert_peer(&req.name, &uri, req.rpc.as_deref(), req.p2p.as_deref());
    let ep = g.peers.get(&req.name).cloned();
    Json(serde_json::json!({ "ok": true, "peer": ep })).into_response()
}

async fn link_secondary(
    State(st): State<RpcState>,
    Json(_req): Json<LinkSecondaryRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let secondary = DeviceKeypair::generate();
    match g.link.create_link_request(&secondary) {
        Ok(request) => match g.link.approve_link(&g.keypair, &request) {
            Ok(approval) => match g.link.apply_approval(&approval) {
                Ok(()) => Json(LinkSecondaryResponse {
                    primary_device: hex32(&g.keypair.device_id().0),
                    secondary_device: hex32(&secondary.device_id().0),
                    linked: g.link.is_linked(&secondary.device_id()),
                })
                .into_response(),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: e.to_string(),
                    }),
                )
                    .into_response(),
            },
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: e.to_string(),
                }),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn list_devices(State(st): State<RpcState>) -> impl IntoResponse {
    let g = st.inner.lock().await;
    let devices: Vec<String> = g
        .link
        .linked_devices()
        .into_iter()
        .map(|d| hex32(&d.0))
        .collect();
    Json(serde_json::json!({ "devices": devices })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterBeginRequest {
    #[serde(default = "default_user")]
    pub user_name: String,
    #[serde(default = "default_display")]
    pub display_name: String,
}

fn default_user() -> String {
    "thunderducks-user".into()
}
fn default_display() -> String {
    "Thunderducks User".into()
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    pub challenge: String,
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub public_key_spki: String,
    #[serde(default = "default_label")]
    pub label: String,
}

fn default_label() -> String {
    "primary".into()
}

#[derive(Debug, Deserialize)]
pub struct PasskeyAuthFinishRequest {
    pub challenge: String,
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

async fn passkey_register_begin(
    State(st): State<RpcState>,
    Json(req): Json<PasskeyRegisterBeginRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let opts = g
        .passkeys
        .begin_registration(&req.user_name, &req.display_name);
    Json(opts).into_response()
}

async fn passkey_register_finish(
    State(st): State<RpcState>,
    Json(req): Json<PasskeyRegisterFinishRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    match g.passkeys.finish_registration(
        &req.challenge,
        &req.credential_id,
        &req.client_data_json,
        &req.authenticator_data,
        &req.public_key_spki,
        &req.label,
    ) {
        Ok(stored) => Json(serde_json::json!({
            "ok": true,
            "credential_id": td_crypto::b64url(&stored.credential_id),
            "label": stored.label,
            "count": g.passkeys.credential_count(),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn passkey_auth_begin(State(st): State<RpcState>) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let opts = g.passkeys.begin_authentication();
    Json(opts).into_response()
}

async fn passkey_auth_finish(
    State(st): State<RpcState>,
    Json(req): Json<PasskeyAuthFinishRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    match g.passkeys.finish_authentication(
        &req.challenge,
        &req.credential_id,
        &req.client_data_json,
        &req.authenticator_data,
        &req.signature,
    ) {
        Ok(cred) => Json(serde_json::json!({"ok": true, "credential_id": cred})).into_response(),
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn passkey_list(State(st): State<RpcState>) -> impl IntoResponse {
    let g = st.inner.lock().await;
    let creds: Vec<_> = g
        .passkeys
        .list_credentials()
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "credential_id": td_crypto::b64url(&c.credential_id),
                "label": c.label,
                "sign_count": c.sign_count,
            })
        })
        .collect();
    Json(serde_json::json!({"credentials": creds})).into_response()
}

#[derive(Debug, Deserialize)]
pub struct SyncOfferRequest {
    pub room_id: String,
    #[serde(default)]
    pub have: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncOfferHttpResponse {
    pub room_id: String,
    pub missing: Vec<SignedEvent>,
}

#[derive(Debug, Deserialize)]
pub struct SyncIngestRequest {
    pub events: Vec<SignedEvent>,
}

#[derive(Debug, Deserialize)]
pub struct SyncPeerRequest {
    /// Peer node HTTP RPC base, e.g. http://127.0.0.1:8789
    pub peer_rpc: String,
    pub room_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionKeyRequest {
    pub room_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionImportRequest {
    /// Legacy plaintext path (kept for smoke/compat). Prefer Olm-wrapped import.
    #[serde(default)]
    pub session_key_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OlmWrappedImportRequest {
    /// Sender curve25519 identity (base64) for Olm inbound establish.
    pub sender_curve25519_b64: String,
    pub olm: OlmCiphertext,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OlmKeysHttp {
    pub device_id: String,
    pub curve25519_b64: String,
    pub one_time_key_b64: String,
}

async fn sync_offer(
    State(st): State<RpcState>,
    Json(req): Json<SyncOfferRequest>,
) -> impl IntoResponse {
    let g = st.inner.lock().await;
    let room_id = match parse_room_id(&req.room_id) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })).into_response();
        }
    };
    let mut have = HashSet::new();
    for h in req.have {
        if let Ok(b) = hex::decode(&h) {
            if b.len() == 32 {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                have.insert(EventId(a));
            }
        }
    }
    let offer = SyncOffer {
        from_device: g.node.device_id,
        room_id,
        tips: g.node.tips(&room_id),
        have: have.into_iter().collect(),
    };
    // Peer is asking us for what they lack: respond with our missing-for-them.
    let resp = g.node.respond_to_offer(&offer);
    Json(SyncOfferHttpResponse {
        room_id: req.room_id,
        missing: resp.missing,
    })
    .into_response()
}

async fn sync_ingest(
    State(st): State<RpcState>,
    Json(req): Json<SyncIngestRequest>,
) -> impl IntoResponse {
    let mut touched: HashSet<[u8; 32]> = HashSet::new();
    let mut accepted = 0usize;
    let mut errors = Vec::new();
    {
        let mut g = st.inner.lock().await;
        for ev in req.events {
            let rid = ev.room_id.0;
            match g.ingest_remote(ev) {
                Ok(true) => {
                    accepted += 1;
                    touched.insert(rid);
                }
                Ok(false) => {}
                Err(e) => errors.push(e),
            }
        }
    }
    for rid in touched {
        notify_room_from_id(&st, &RoomId(rid)).await;
    }
    Json(serde_json::json!({ "accepted": accepted, "errors": errors })).into_response()
}

async fn sync_peer(
    State(st): State<RpcState>,
    Json(req): Json<SyncPeerRequest>,
) -> impl IntoResponse {
    let room_id = match parse_room_id(&req.room_id) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorBody { error: e })).into_response();
        }
    };
    let peer_base = req.peer_rpc.trim_end_matches('/').to_string();
    let room_hex = req.room_id.clone();

    // Snapshot our have-set and events under lock.
    let (our_have, our_events) = {
        let g = st.inner.lock().await;
        let have: Vec<String> = g
            .node
            .room_event_ids(&room_id)
            .into_iter()
            .map(|id| hex32(&id.0))
            .collect();
        let events = g.node.list_events(&room_id);
        (have, events)
    };

    let client = match reqwest_client() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody { error: e }),
            )
                .into_response();
        }
    };

    // Pull missing from peer.
    let pull_body = serde_json::json!({ "room_id": room_hex, "have": our_have });
    let pulled: SyncOfferHttpResponse = match client
        .post(format!("{peer_base}/v1/sync/offer"))
        .json(&pull_body)
        .send()
        .await
    {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorBody {
                        error: format!("peer offer decode: {e}"),
                    }),
                )
                    .into_response();
            }
        },
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: format!("peer offer: {e}"),
                }),
            )
                .into_response();
        }
    };

    let mut accepted_from_peer = 0usize;
    {
        let mut g = st.inner.lock().await;
        for ev in pulled.missing {
            if g.ingest_remote(ev).unwrap_or(false) {
                accepted_from_peer += 1;
            }
        }
    }

    // Push our events to peer ingest.
    let push_body = serde_json::json!({ "events": our_events });
    let pushed_accepted = match client
        .post(format!("{peer_base}/v1/sync/ingest"))
        .json(&push_body)
        .send()
        .await
    {
        Ok(r) => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("accepted").and_then(|x| x.as_u64()))
            .unwrap_or(0),
        Err(_) => 0,
    };

    Json(serde_json::json!({
        "ok": true,
        "accepted_from_peer": accepted_from_peer,
        "pushed_accepted": pushed_accepted,
        "peer_rpc": peer_base,
        "room_id": room_hex,
    }))
    .into_response()
}

async fn export_session(
    State(st): State<RpcState>,
    Json(req): Json<SessionKeyRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    let room_hex = req.room_id;
    g.ensure_room_e2ee(&room_hex);
    match g.e2ee.export_group_session_key(&room_hex) {
        Ok(session_key_b64) => {
            let session_id = g.e2ee.group_session_id(&room_hex).unwrap_or_default();
            Json(serde_json::json!({
                "room_id": room_hex,
                "session_id": session_id,
                "session_key_b64": session_key_b64,
                "sender_device": hex32(&g.keypair.device_id().0),
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

fn parse_crypto_device_id(s: &str) -> Result<td_crypto::DeviceId, String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    if b.len() != 32 {
        return Err("device_id must be 32 bytes hex".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(td_crypto::DeviceId(a))
}

async fn olm_keys_get(State(st): State<RpcState>) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    match g.e2ee.publish_keys() {
        Ok(k) => Json(OlmKeysHttp {
            device_id: hex32(&k.device_id.0),
            curve25519_b64: k.curve25519_b64,
            one_time_key_b64: k.one_time_key_b64,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn import_session(
    State(st): State<RpcState>,
    Json(req): Json<SessionImportRequest>,
) -> impl IntoResponse {
    let Some(key) = req.session_key_b64.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "session_key_b64 required for plaintext import; use /v1/e2ee/import-olm"
                    .into(),
            }),
        )
            .into_response();
    };
    let mut g = st.inner.lock().await;
    match g.e2ee.import_group_session_key(key) {
        Ok(session_id) => Json(serde_json::json!({
            "ok": true,
            "session_id": session_id,
            "path": "plaintext",
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn import_session_olm(
    State(st): State<RpcState>,
    Json(req): Json<OlmWrappedImportRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    match g.e2ee.olm_decrypt(&req.sender_curve25519_b64, &req.olm) {
        Ok(plain) => {
            // B2 preferred: JSON RoomOutboundPackage (shared outbound pickle).
            // Legacy: raw UTF-8 Megolm session_key_b64 (inbound only).
            if let Ok(pkg) = serde_json::from_slice::<RoomOutboundPackage>(&plain) {
                match g.e2ee.import_room_outbound(&pkg) {
                    Ok(session_id) => {
                        g.e2ee_rooms.insert(pkg.room_id.clone(), true);
                        return Json(serde_json::json!({
                            "ok": true,
                            "session_id": session_id,
                            "path": "olm-room-outbound",
                            "room_id": pkg.room_id,
                            "message_index": pkg.message_index,
                            "has_outbound": g.e2ee.has_outbound(&pkg.room_id),
                        }))
                        .into_response();
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorBody {
                                error: format!("import room outbound: {e}"),
                            }),
                        )
                            .into_response();
                    }
                }
            }
            let key = match std::str::from_utf8(&plain) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorBody {
                            error: format!("olm plaintext utf8: {e}"),
                        }),
                    )
                        .into_response();
                }
            };
            match g.e2ee.import_group_session_key(&key) {
                Ok(session_id) => Json(serde_json::json!({
                    "ok": true,
                    "session_id": session_id,
                    "path": "olm",
                }))
                .into_response(),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: e.to_string(),
                    }),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("olm decrypt: {e}"),
            }),
        )
            .into_response(),
    }
}

/// Establish Olm to peer and POST Olm-wrapped room outbound (B2) or legacy key.
/// Prefer `pre_exported` from send path (pre-encrypt snapshot) — do not re-export after ratchet.
async fn share_megolm_olm_to_peer(
    st: &RpcState,
    peer_base: &str,
    room_hex: &str,
    client: &reqwest::Client,
    pre_exported: Option<&RoomOutboundPackage>,
) -> Result<(String, String), String> {
    let peer_base = peer_base.trim_end_matches('/');
    let keys_http: OlmKeysHttp = client
        .get(format!("{peer_base}/v1/e2ee/olm-keys"))
        .send()
        .await
        .map_err(|e| format!("olm-keys: {e}"))?
        .error_for_status()
        .map_err(|e| format!("olm-keys HTTP: {e}"))?
        .json()
        .await
        .map_err(|e| format!("olm-keys decode: {e}"))?;

    let peer_dev = parse_crypto_device_id(&keys_http.device_id)?;
    let their = OlmDeviceKeys {
        device_id: peer_dev,
        curve25519_b64: keys_http.curve25519_b64.clone(),
        one_time_key_b64: keys_http.one_time_key_b64.clone(),
    };

    let (olm_ct, sender_curve, session_id, sender_dev) = {
        let mut g = st.inner.lock().await;
        g.ensure_room_e2ee(room_hex);
        g.e2ee
            .establish_olm_outbound(&their)
            .map_err(|e| e.to_string())?;
        let body = if let Some(pkg) = pre_exported {
            serde_json::to_vec(pkg).map_err(|e| e.to_string())?
        } else {
            let pkg = g
                .e2ee
                .export_room_outbound(room_hex)
                .map_err(|e| e.to_string())?;
            serde_json::to_vec(&pkg).map_err(|e| e.to_string())?
        };
        let ct = g
            .e2ee
            .olm_encrypt(peer_dev, &body)
            .map_err(|e| e.to_string())?;
        let sid = g.e2ee.group_session_id(room_hex).unwrap_or_default();
        let curve = g.e2ee.curve25519_b64();
        let sender = hex32(&g.keypair.device_id().0);
        (ct, curve, sid, sender)
    };

    let resp = client
        .post(format!("{peer_base}/v1/e2ee/import-olm"))
        .json(&serde_json::json!({
            "sender_curve25519_b64": sender_curve,
            "olm": olm_ct,
        }))
        .send()
        .await
        .map_err(|e| format!("import-olm: {e}"))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("import-olm failed: {body}"));
    }
    Ok((session_id, sender_dev))
}

async fn share_session_with_peer(
    State(st): State<RpcState>,
    Json(req): Json<SyncPeerRequest>,
) -> impl IntoResponse {
    let room_hex = req.room_id.clone();
    let peer_base = req.peer_rpc.trim_end_matches('/').to_string();
    let client = match reqwest_client() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody { error: e }),
            )
                .into_response();
        }
    };
    match share_megolm_olm_to_peer(&st, &peer_base, &room_hex, &client, None).await {
        Ok((session_id, sender)) => Json(serde_json::json!({
            "ok": true,
            "session_id": session_id,
            "sender_device": sender,
            "peer_rpc": peer_base,
            "room_id": room_hex,
            "path": "olm-room-outbound",
        }))
        .into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(ErrorBody { error: e })).into_response(),
    }
}

fn reqwest_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())
}

async fn p2p_status(State(st): State<RpcState>) -> impl IntoResponse {
    let g = st.inner.lock().await;
    Json(serde_json::json!({
        "p2p_uri": g.p2p_uri,
        "rpc_base": g.rpc_base,
        "peers": g.peers.values().collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Build the localhost RPC router.
pub fn router(state: RpcState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"ok": true})) }),
        )
        .route("/v1/status", get(status))
        .route("/v1/claim", get(claim_status).post(claim_node))
        .route("/v1/recovery/login", post(recovery_login))
        .route("/v1/owner/session", get(owner_session_status).delete(owner_logout))
        .route("/v1/pair", get(pair_list).post(pair_create))
        .route("/v1/pair/redeem", post(pair_redeem))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/link-secondary", post(link_secondary))
        .route("/v1/passkeys/register/begin", post(passkey_register_begin))
        .route(
            "/v1/passkeys/register/finish",
            post(passkey_register_finish),
        )
        .route("/v1/passkeys/auth/begin", post(passkey_auth_begin))
        .route("/v1/passkeys/auth/finish", post(passkey_auth_finish))
        .route("/v1/passkeys", get(passkey_list))
        .route("/v1/peers", post(add_peer))
        .route("/v1/rooms", post(create_room))
        .route("/v1/messages", post(send_message))
        .route("/v1/messages/list", post(list_messages))
        .route("/v1/messages/wait", post(wait_messages))
        .route("/v1/messages/stream", get(stream_messages))
        .route("/v1/sync/offer", post(sync_offer))
        .route("/v1/sync/ingest", post(sync_ingest))
        .route("/v1/sync/peer", post(sync_peer))
        .route("/v1/e2ee/olm-keys", get(olm_keys_get))
        .route("/v1/e2ee/export-session", post(export_session))
        .route("/v1/e2ee/import-session", post(import_session))
        .route("/v1/e2ee/import-olm", post(import_session_olm))
        .route("/v1/e2ee/share-session", post(share_session_with_peer))
        .route("/v1/p2p", get(p2p_status))
        .layer(cors)
        .with_state(state)
}

pub fn new_state() -> RpcState {
    RpcState {
        inner: Arc::new(Mutex::new(NodeSession::new())),
        notify: Arc::new(RoomNotify::new()),
    }
}

/// Build RPC state loading durable identity + claim from `data_dir`.
pub fn new_state_with_data_dir(data_dir: impl Into<std::path::PathBuf>) -> Result<RpcState, String> {
    let dir = NodeDataDir::new(data_dir.into());
    let session = NodeSession::load_from_data_dir(dir)?;
    Ok(RpcState {
        inner: Arc::new(Mutex::new(session)),
        notify: Arc::new(RoomNotify::new()),
    })
}

async fn start_p2p_listener(state: RpcState) -> Result<String, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let uri = PeerUri::from_tcp_addr(addr).to_string_uri();
    {
        let mut g = state.inner.lock().await;
        g.p2p_uri = Some(uri.clone());
    }
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            let mut sock = match accept_once(&listener).await {
                Ok(s) => s,
                Err(_) => break,
            };
            let st2 = st.clone();
            tokio::spawn(async move {
                while let Ok(ev) = read_event(&mut sock).await {
                    let room_id = ev.room_id;
                    let inserted = {
                        let mut g = st2.inner.lock().await;
                        g.ingest_remote(ev).unwrap_or(false)
                    };
                    if inserted {
                        notify_room_from_id(&st2, &room_id).await;
                    }
                }
            });
        }
    });
    Ok(uri)
}

/// Serve RPC on `bind` (e.g. 127.0.0.1:8788). Returns local addr after bind.
/// In-memory only (tests / smoke). Prefer `serve_with_data_dir` for Pond.
pub async fn serve(bind: &str) -> Result<SocketAddr, std::io::Error> {
    serve_with_optional_data_dir(bind, None).await
}

/// Serve RPC with durable identity + claim under `data_dir`.
pub async fn serve_with_data_dir(
    bind: &str,
    data_dir: impl Into<std::path::PathBuf>,
) -> Result<SocketAddr, std::io::Error> {
    serve_with_optional_data_dir(bind, Some(data_dir.into())).await
}

async fn serve_with_optional_data_dir(
    bind: &str,
    data_dir: Option<std::path::PathBuf>,
) -> Result<SocketAddr, std::io::Error> {
    let state = match data_dir {
        Some(dir) => new_state_with_data_dir(dir).map_err(std::io::Error::other)?,
        None => new_state(),
    };
    let p2p = start_p2p_listener(state.clone())
        .await
        .unwrap_or_else(|_| "td://?".into());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    {
        let mut g = state.inner.lock().await;
        g.rpc_base = Some(format!("http://{addr}"));
    }
    let app = router(state);
    eprintln!("td-node rpc listening on http://{addr} p2p={p2p}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

/// Serve and block (for binary embedding). In-memory only.
pub async fn serve_blocking(bind: &str) -> Result<(), std::io::Error> {
    serve_blocking_with_optional_data_dir(bind, None).await
}

/// Serve and block with durable identity + claim under `data_dir`.
pub async fn serve_blocking_with_data_dir(
    bind: &str,
    data_dir: impl Into<std::path::PathBuf>,
) -> Result<(), std::io::Error> {
    serve_blocking_with_optional_data_dir(bind, Some(data_dir.into())).await
}

async fn serve_blocking_with_optional_data_dir(
    bind: &str,
    data_dir: Option<std::path::PathBuf>,
) -> Result<(), std::io::Error> {
    let state = match data_dir {
        Some(dir) => new_state_with_data_dir(dir).map_err(std::io::Error::other)?,
        None => new_state(),
    };
    let p2p = start_p2p_listener(state.clone()).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let data_note = {
        let g = state.inner.lock().await;
        g.data_dir
            .as_ref()
            .map(|d| format!(" data={}", d.root().display()))
            .unwrap_or_default()
    };
    {
        let mut g = state.inner.lock().await;
        g.rpc_base = Some(format!("http://{addr}"));
    }
    let app = router(state);
    eprintln!("td-node rpc listening on http://{addr} p2p={p2p}{data_note}");
    axum::serve(listener, app).await
}

/// Happy-path in-process exercise used by CLI tests and CI.
pub fn happy_path_script() -> Result<String, String> {
    // Pure sync path without HTTP — validates room/send/recv/link composition.
    let primary = DeviceKeypair::generate();
    let secondary = DeviceKeypair::generate();
    let mut link = LinkRegistry::new(primary.device_id());
    link.trust_local(&primary).map_err(|e| e.to_string())?;
    let req = link
        .create_link_request(&secondary)
        .map_err(|e| e.to_string())?;
    let approval = link
        .approve_link(&primary, &req)
        .map_err(|e| e.to_string())?;
    link.apply_approval(&approval).map_err(|e| e.to_string())?;
    if !link.is_linked(&secondary.device_id()) {
        return Err("secondary not linked".into());
    }

    let mut node = DeviceNode::from_crypto_device(primary.device_id());
    let mut rooms = RoomRegistry::new();
    let (room_id, create_ev) = rooms
        .create_room(primary.signing_key(), primary.event_device_id(), "pond", 1)
        .map_err(|e| e.to_string())?;
    node.commit_local(create_ev).map_err(|e| e.to_string())?;

    let parents = node.tips(&room_id);
    let msg = sign_event(
        primary.signing_key(),
        UnsignedEvent {
            room_id,
            parents,
            kind: EventKind::Message,
            payload: br#"{"text":"hello pond"}"#.to_vec(),
            author_device: primary.event_device_id(),
            ts_ms: 2,
        },
    )
    .map_err(|e| e.to_string())?;
    let _ = rooms.apply_event(msg.clone());
    node.commit_local(msg.clone()).map_err(|e| e.to_string())?;

    let listed = node.list_messages(&room_id);
    if listed.len() != 1 {
        return Err(format!("expected 1 message, got {}", listed.len()));
    }
    if payload_text(&listed[0]) != "hello pond" {
        return Err("message text mismatch".into());
    }

    Ok(format!(
        "ok devices={} room={} msg={}",
        link.linked_devices().len(),
        hex32(&room_id.0),
        hex32(&msg.id.0)
    ))
}

// silence unused import warning for DeviceId in some builds
#[allow(dead_code)]
fn _device_id_ty(_: DeviceId) {}
