//! Local node HTTP RPC for CLI + TS web (Wave E).
//!
//! Default bind is loopback (trust-local). Non-loopback enables **full owner-session
//! authn** for non-public routes plus **per-IP rate limits**. Optional untrusted
//! assist relay + advertised host for tailnet/LAN remote access.

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum::body::Body;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rand::RngCore;
use td_crypto::{
    DeviceKeypair, E2eeDevice, LinkRegistry, MegolmCiphertext, OlmCiphertext, OlmDeviceKeys,
    PasskeyRegistry, RoomOutboundPackage,
};
use td_event::{
    sign_event, EventId, EventKind, RoomId, RoomRegistry, SignedEvent, UnsignedEvent,
};
use td_net::{
    accept_once, dial, noise_read_event, parse_pin_list, quic_accept, quic_dial_with_config,
    quic_listen_with_config, read_event, write_event, write_self_signed_pem, NoiseTcpStream,
    PeerUri, QuicTlsConfig, RelayClient, RelayEnvelope,
};
use axum_server::tls_rustls::RustlsConfig;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex, Notify};
use tower_http::cors::{Any, CorsLayer};

use crate::persist::NodeDataDir;
use crate::sync::{DeviceNode, SyncOffer};

/// Runtime options for serving a Pond node (local or remote-capable).
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// Durable identity + claim directory.
    pub data_dir: Option<PathBuf>,
    /// P2P listen bind (default `127.0.0.1:0`). Use `0.0.0.0:0` or LAN/tailnet IP for remote peers.
    pub p2p_bind: Option<String>,
    /// Host/IP advertised in `p2p_uri` / `rpc_base` (e.g. Tailscale IP or DNS name).
    pub advertise_host: Option<String>,
    /// Optional untrusted assist relay URI (`td://host:port` or `td-noise://…`).
    pub relay_uri: Option<String>,
    /// 32-byte AEAD key for production relay seal (derived from TD_RELAY_KEY).
    pub relay_key: [u8; 32],
    /// When RPC is not loopback-only, require owner session for non-public routes.
    pub require_owner_non_loopback: bool,
    /// Enable per-IP rate limits (default true).
    pub rate_limit: bool,
    /// Prefer Noise_XX for P2P accept/dial when peer URI uses td-noise:// or flag set.
    pub p2p_noise: bool,
    /// Prefer QUIC P2P (`td-quic://`); takes advertise precedence over noise.
    pub p2p_quic: bool,
    /// TLS cert PEM path for in-process HTTPS RPC (`TD_TLS_CERT`).
    pub tls_cert: Option<PathBuf>,
    /// TLS private key PEM path (`TD_TLS_KEY`).
    pub tls_key: Option<PathBuf>,
    /// Generate ephemeral self-signed cert when no cert/key (dev only).
    pub tls_self_signed: bool,
    /// QUIC identity cert PEM (`TD_QUIC_CERT`). Falls back to data-dir generated cert.
    pub quic_cert: Option<PathBuf>,
    /// QUIC identity key PEM (`TD_QUIC_KEY`).
    pub quic_key: Option<PathBuf>,
    /// Comma/space-separated blake3 leaf-cert pins (64 hex) for QUIC peers (`TD_QUIC_PINS`).
    pub quic_pins: Option<String>,
    /// Require client certs on QUIC accept (mTLS). Default true when pins set.
    pub quic_mtls: Option<bool>,
}

impl ServeOptions {
    pub fn from_env() -> Self {
        let data_dir = std::env::var_os("TD_DATA_DIR").map(PathBuf::from);
        let p2p_bind = std::env::var("TD_P2P_BIND").ok().filter(|s| !s.trim().is_empty());
        let advertise_host = std::env::var("TD_ADVERTISE_HOST")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let relay_uri = std::env::var("TD_RELAY_URI")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let relay_key = {
            let material = std::env::var("TD_RELAY_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|s| td_crypto::parse_relay_key_material(&s))
                .unwrap_or_else(|| td_crypto::DEFAULT_RELAY_KEY_MATERIAL.to_vec());
            td_crypto::derive_relay_key(&material)
        };
        // Default on: safer when binding non-loopback.
        let require_owner_non_loopback = std::env::var("TD_REQUIRE_OWNER")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                !(v == "0" || v == "false" || v == "off" || v == "no")
            })
            .unwrap_or(true);
        let rate_limit = std::env::var("TD_RATE_LIMIT")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                !(v == "0" || v == "false" || v == "off" || v == "no")
            })
            .unwrap_or(true);
        let p2p_noise = std::env::var("TD_P2P_NOISE")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                !(v == "0" || v == "false" || v == "off" || v == "no")
            })
            .unwrap_or(false);
        let p2p_quic = std::env::var("TD_P2P_QUIC")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                !(v == "0" || v == "false" || v == "off" || v == "no")
            })
            .unwrap_or(false);
        let tls_cert = std::env::var_os("TD_TLS_CERT").map(PathBuf::from);
        let tls_key = std::env::var_os("TD_TLS_KEY").map(PathBuf::from);
        let tls_self_signed = std::env::var("TD_TLS_SELF_SIGNED")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                !(v == "0" || v == "false" || v == "off" || v == "no")
            })
            .unwrap_or(false);
        let quic_cert = std::env::var_os("TD_QUIC_CERT").map(PathBuf::from);
        let quic_key = std::env::var_os("TD_QUIC_KEY").map(PathBuf::from);
        let quic_pins = std::env::var("TD_QUIC_PINS")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let quic_mtls = std::env::var("TD_QUIC_MTLS").ok().map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        });
        Self {
            data_dir,
            p2p_bind,
            advertise_host,
            relay_uri,
            relay_key,
            require_owner_non_loopback,
            rate_limit,
            p2p_noise,
            p2p_quic,
            tls_cert,
            tls_key,
            tls_self_signed,
            quic_cert,
            quic_key,
            quic_pins,
            quic_mtls,
        }
    }
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            data_dir: None,
            p2p_bind: None,
            advertise_host: None,
            relay_uri: None,
            relay_key: td_crypto::derive_relay_key(td_crypto::DEFAULT_RELAY_KEY_MATERIAL),
            require_owner_non_loopback: true,
            rate_limit: true,
            p2p_noise: false,
            p2p_quic: false,
            tls_cert: None,
            tls_key: None,
            tls_self_signed: false,
            quic_cert: None,
            quic_key: None,
            quic_pins: None,
            quic_mtls: None,
        }
    }
}

fn is_loopback_bind(bind: &str) -> bool {
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    matches!(host, "127.0.0.1" | "localhost" | "::1")
        || host.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

fn advertise_addr(local: SocketAddr, advertise_host: Option<&str>) -> String {
    if let Some(h) = advertise_host.map(str::trim).filter(|s| !s.is_empty()) {
        // host may be DNS or IP; keep port from actual bind
        if h.contains(':') && !h.starts_with('[') {
            // already host:port or ipv6 without brackets — use as-is if it looks complete
            if h.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).is_some()
                && h.matches(':').count() == 1
            {
                return h.to_string();
            }
        }
        return format!("{h}:{}", local.port());
    }
    local.to_string()
}

fn advertise_http_base(local: SocketAddr, advertise_host: Option<&str>, https: bool) -> String {
    let scheme = if https { "https" } else { "http" };
    format!("{scheme}://{}", advertise_addr(local, advertise_host))
}

fn advertise_p2p_uri(
    local: SocketAddr,
    advertise_host: Option<&str>,
    noise: bool,
    quic: bool,
) -> String {
    let adv = advertise_addr(local, advertise_host);
    let scheme = if quic {
        "td-quic"
    } else if noise {
        "td-noise"
    } else {
        "td"
    };
    if adv.starts_with("td://") || adv.starts_with("td-noise://") || adv.starts_with("td-quic://") {
        adv
    } else {
        format!("{scheme}://{adv}")
    }
}

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
    /// When true, non-public routes require owner session (set when RPC bind is non-loopback).
    require_owner: bool,
    /// Per-IP rate limiter (shared).
    rate_limits: Arc<Mutex<RateLimitBook>>,
    /// Master switch for rate limits.
    rate_limit_enabled: bool,
}

/// Sliding-window counters keyed by client IP + bucket name.
#[derive(Debug, Default)]
struct RateLimitBook {
    /// key = "{ip}|{bucket}" -> window
    windows: HashMap<String, RateWindow>,
}

#[derive(Debug, Clone)]
struct RateWindow {
    start: Instant,
    count: u32,
}

#[derive(Debug, Clone, Copy)]
struct RateRule {
    /// Requests allowed per window.
    limit: u32,
    /// Window length.
    window: Duration,
}

impl RateLimitBook {
    fn check(&mut self, ip: &str, bucket: &str, rule: RateRule) -> Result<(), Duration> {
        let key = format!("{ip}|{bucket}");
        let now = Instant::now();
        let entry = self.windows.entry(key).or_insert(RateWindow {
            start: now,
            count: 0,
        });
        if now.duration_since(entry.start) >= rule.window {
            entry.start = now;
            entry.count = 0;
        }
        if entry.count >= rule.limit {
            let retry = rule
                .window
                .checked_sub(now.duration_since(entry.start))
                .unwrap_or(Duration::from_secs(1));
            return Err(retry);
        }
        entry.count += 1;
        // Opportunistic prune when map grows large.
        if self.windows.len() > 4096 {
            let cutoff = now - Duration::from_secs(120);
            self.windows.retain(|_, w| w.start > cutoff);
        }
        Ok(())
    }
}

fn rate_rule_for(path: &str, method: &str) -> RateRule {
    // Sensitive auth / claim paths — tight.
    if path == "/v1/recovery/login" || path == "/v1/claim" && method.eq_ignore_ascii_case("POST") {
        return RateRule {
            limit: 10,
            window: Duration::from_secs(60),
        };
    }
    if path == "/v1/pair/redeem" {
        return RateRule {
            limit: 20,
            window: Duration::from_secs(60),
        };
    }
    // Streaming / long-poll: allow steady traffic but cap.
    if path == "/v1/messages/stream" || path == "/v1/messages/wait" {
        return RateRule {
            limit: 120,
            window: Duration::from_secs(60),
        };
    }
    // Writes vs reads.
    if method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("DELETE")
        || method.eq_ignore_ascii_case("PATCH")
    {
        RateRule {
            limit: 180,
            window: Duration::from_secs(60),
        }
    } else {
        RateRule {
            limit: 600,
            window: Duration::from_secs(60),
        }
    }
}

/// Paths that stay reachable without owner session even when `require_owner` is on.
fn is_public_path(method: &str, path: &str) -> bool {
    match (method.to_ascii_uppercase().as_str(), path) {
        ("GET", "/health") => true,
        ("GET", "/v1/status") => true,
        ("GET", "/v1/claim") => true,
        ("POST", "/v1/claim") => true, // handler rejects if already claimed
        ("POST", "/v1/recovery/login") => true,
        ("GET", "/v1/owner/session") => true,
        ("DELETE", "/v1/owner/session") => true,
        ("POST", "/v1/pair/redeem") => true,
        // Lightweight discovery (no secrets)
        ("GET", "/v1/p2p") => true,
        ("GET", "/v1/remote") => true,
        _ => false,
    }
}

/// Known peer endpoints. HTTP RPC = reliable share+delta; P2P = best-effort.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEndpoint {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p2p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc: Option<String>,
    /// Optional remote device id (hex) for relay Olm fanout targeting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
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
    /// Cached peer Olm identity keys for per-recipient relay seal (v2).
    peer_olm_keys: HashMap<td_crypto::DeviceId, OlmDeviceKeys>,
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
    /// Advertised public/tailnet host for URI rewriting.
    advertise_host: Option<String>,
    /// Configured untrusted assist relay (`td://…` / `td-noise://…`).
    relay_uri: Option<String>,
    /// Production AEAD relay seal key.
    relay_key: [u8; 32],
    /// Prefer Noise for P2P.
    p2p_noise: bool,
    /// Prefer QUIC for P2P.
    p2p_quic: bool,
    /// QUIC TLS policy (identity + pins + mTLS).
    quic_tls: Option<QuicTlsConfig>,
    /// Local QUIC leaf pin (hex) when available.
    quic_pin: Option<String>,
    /// RPC served over HTTPS.
    rpc_tls: bool,
    /// Last relay poll summary (best-effort).
    relay_last_fetch_ms: Option<u64>,
    relay_last_error: Option<String>,
    relay_last_fetched: u32,
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
            peer_olm_keys: HashMap::new(),
            ts_counter: 1,
            p2p_uri: None,
            rpc_base: None,
            claim,
            pair_tokens: HashMap::new(),
            owner_sessions: HashMap::new(),
            recovery_failures: 0,
            recovery_lock_until: None,
            data_dir,
            advertise_host: None,
            relay_uri: None,
            relay_key: td_crypto::derive_relay_key(td_crypto::DEFAULT_RELAY_KEY_MATERIAL),
            p2p_noise: false,
            p2p_quic: false,
            quic_tls: None,
            quic_pin: None,
            rpc_tls: false,
            relay_last_fetch_ms: None,
            relay_last_error: None,
            relay_last_fetched: 0,
        }
    }

    fn apply_remote_opts(&mut self, opts: &ServeOptions) {
        if let Some(h) = opts.advertise_host.clone() {
            self.advertise_host = Some(h);
        }
        if let Some(r) = opts.relay_uri.clone() {
            self.relay_uri = Some(r);
        }
        self.relay_key = opts.relay_key;
        self.p2p_noise = opts.p2p_noise;
        self.p2p_quic = opts.p2p_quic;
        // quic_tls filled in prepare_serve after data_dir known
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

    /// Remember peer Olm keys for per-recipient relay seal.
    fn remember_peer_olm(&mut self, keys: OlmDeviceKeys) {
        self.peer_olm_keys.insert(keys.device_id, keys);
    }

    /// Ensure outbound Olm to peer using cached keys (no network).
    fn ensure_olm_to(&mut self, peer: td_crypto::DeviceId) -> Result<(), String> {
        if self.e2ee.has_olm_session(peer) {
            return Ok(());
        }
        let keys = self
            .peer_olm_keys
            .get(&peer)
            .cloned()
            .ok_or_else(|| format!("no olm keys cached for peer {}", hex::encode(peer.0)))?;
        self.e2ee
            .establish_olm_outbound(&keys)
            .map_err(|e| e.to_string())
    }

    /// Relay fanout recipients: linked secondaries + peers with known device_id + olm cache.
    fn relay_recipients(&self) -> Vec<td_crypto::DeviceId> {
        let mut out = Vec::new();
        let self_id = self.keypair.device_id();
        for d in self.link.linked_devices() {
            if d != self_id {
                out.push(d);
            }
        }
        for ep in self.peers.values() {
            if let Some(hex_id) = ep.device_id.as_deref() {
                if let Ok(id) = parse_crypto_device_id(hex_id) {
                    if id != self_id && !out.contains(&id) {
                        out.push(id);
                    }
                }
            }
        }
        for id in self.peer_olm_keys.keys() {
            if *id != self_id && !out.contains(id) {
                out.push(*id);
            }
        }
        out
    }

    /// Seal one event for one recipient: Olm v2 preferred, AEAD v1 fallback.
    fn seal_event_for_recipient(
        &mut self,
        ev: &SignedEvent,
        recip: td_crypto::DeviceId,
    ) -> Result<(Vec<u8>, &'static str), String> {
        match self.ensure_olm_to(recip) {
            Ok(()) => {
                let ct = DeviceNode::seal_for_relay_olm(&mut self.e2ee, recip, ev)
                    .map_err(|e| e.to_string())?;
                Ok((ct, "olm-v2"))
            }
            Err(_) => {
                let ct =
                    DeviceNode::seal_for_relay(ev, &self.relay_key).map_err(|e| e.to_string())?;
                Ok((ct, "aead-v1"))
            }
        }
    }

    fn upsert_peer(&mut self, name: &str, uri: &str, rpc: Option<&str>, p2p: Option<&str>) {
        let mut ep = self.peers.remove(name).unwrap_or(PeerEndpoint {
            name: name.to_string(),
            p2p: None,
            rpc: None,
            device_id: None,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_uri: Option<String>,
    pub require_owner: bool,
    pub rate_limit: bool,
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
    /// Optional peer device id (hex) for relay Olm targeting.
    #[serde(default)]
    pub device_id: Option<String>,
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
        rpc_base: g.rpc_base.clone(),
        advertise_host: g.advertise_host.clone(),
        relay_uri: g.relay_uri.clone(),
        require_owner: st.require_owner,
        rate_limit: st.rate_limit_enabled,
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

/// When node is in remote/non-loopback mode, require owner for non-public routes.
fn require_owner_if_remote(
    st: &RpcState,
    g: &mut NodeSession,
    headers: &HeaderMap,
) -> Result<(), Box<axum::response::Response>> {
    if st.require_owner {
        require_owner(g, headers)
    } else {
        Ok(())
    }
}

/// Extract owner token from headers, or `owner_token` query (SSE EventSource).
fn extract_owner_token_flexible(headers: &HeaderMap, query_token: Option<&str>) -> Option<String> {
    if let Some(t) = extract_owner_token(headers) {
        return Some(t);
    }
    query_token
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn require_owner_token(
    g: &mut NodeSession,
    token: Option<String>,
) -> Result<(), Box<Response>> {
    let Some(token) = token else {
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

async fn authn_rate_middleware(
    State(st): State<RpcState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let ip = addr.ip().to_string();

    // Rate limit first (including public routes).
    if st.rate_limit_enabled {
        let rule = rate_rule_for(&path, &method);
        let mut book = st.rate_limits.lock().await;
        if let Err(retry) = book.check(&ip, &path, rule) {
            let secs = retry.as_secs().max(1);
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorBody {
                    error: format!("rate limit exceeded; retry in ~{secs}s"),
                }),
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert("retry-after", v);
            }
            return resp;
        }
    }

    // Full owner authn when non-loopback gate is on.
    if st.require_owner && !is_public_path(&method, &path) {
        // Allow owner_token query for EventSource (cannot set Authorization).
        let q_token = req.uri().query().and_then(|q| {
            q.split('&').find_map(|pair| {
                let mut it = pair.splitn(2, '=');
                let k = it.next()?;
                let v = it.next().unwrap_or("");
                if k == "owner_token" {
                    Some(v.to_string())
                } else {
                    None
                }
            })
        });
        let headers = req.headers().clone();
        let token = extract_owner_token_flexible(&headers, q_token.as_deref());
        let mut g = st.inner.lock().await;
        if let Err(resp) = require_owner_token(&mut g, token) {
            return *resp;
        }
    }

    next.run(req).await
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
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorBody {
                error: format!("too many failed attempts; retry in {secs}s"),
            }),
        )
            .into_response();
        if let Ok(v) = HeaderValue::from_str(&secs.max(1).to_string()) {
            resp.headers_mut().insert("retry-after", v);
        }
        return resp;
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
    let quic_tls = {
        let g = st.inner.lock().await;
        g.quic_tls.clone()
    };
    for ep in peers_snapshot {
        if let Some(uri) = ep.p2p {
            if let Ok(peer) = PeerUri::parse(&uri) {
                let ev = new_event.clone();
                let qtls = quic_tls.clone();
                tokio::spawn(async move {
                    if peer.quic {
                        if let Some(cfg) = qtls {
                            if let Ok(mut stream) = quic_dial_with_config(&peer, &cfg).await {
                                let _ = stream.write_event(&ev).await;
                            }
                        }
                    } else if let Ok(mut sock) = dial(&peer).await {
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
    headers: HeaderMap,
    Json(req): Json<AddPeerRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    if let Err(resp) = require_owner_if_remote(&st, &mut g, &headers) {
        return *resp;
    }
    let uri = req.uri.clone().unwrap_or_default();
    g.upsert_peer(&req.name, &uri, req.rpc.as_deref(), req.p2p.as_deref());
    if let Some(did) = req.device_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(ep) = g.peers.get_mut(&req.name) {
            ep.device_id = Some(did.to_string());
        }
    }
    let ep = g.peers.get(&req.name).cloned();
    Json(serde_json::json!({ "ok": true, "peer": ep })).into_response()
}

async fn link_secondary(
    State(st): State<RpcState>,
    headers: HeaderMap,
    Json(_req): Json<LinkSecondaryRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    if let Err(resp) = require_owner_if_remote(&st, &mut g, &headers) {
        return *resp;
    }
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


#[derive(Debug, Deserialize)]
struct TrustOlmKeysRequest {
    device_id: String,
    curve25519_b64: String,
    one_time_key_b64: String,
    /// Optional peer name to stamp device_id onto.
    #[serde(default)]
    peer_name: Option<String>,
}

/// Register a peer's Olm identity keys for per-recipient relay seal (v2).
async fn trust_olm_keys(
    State(st): State<RpcState>,
    headers: HeaderMap,
    Json(req): Json<TrustOlmKeysRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    if let Err(resp) = require_owner_if_remote(&st, &mut g, &headers) {
        if st.require_owner {
            return *resp;
        }
    }
    let peer_dev = match parse_crypto_device_id(&req.device_id) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody { error: e }),
            )
                .into_response();
        }
    };
    let keys = OlmDeviceKeys {
        device_id: peer_dev,
        curve25519_b64: req.curve25519_b64,
        one_time_key_b64: req.one_time_key_b64,
    };
    match g.e2ee.establish_olm_outbound(&keys) {
        Ok(()) => {
            g.remember_peer_olm(keys);
            if let Some(name) = req.peer_name.as_deref() {
                if let Some(ep) = g.peers.get_mut(name) {
                    ep.device_id = Some(hex32(&peer_dev.0));
                }
            }
            Json(serde_json::json!({
                "ok": true,
                "device_id": hex32(&peer_dev.0),
                "olm_ready": true,
                "relay_seal": "olm-v2",
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
        g.remember_peer_olm(their.clone());
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
        "advertise_host": g.advertise_host,
        "relay_uri": g.relay_uri,
        "relay_last_fetch_ms": g.relay_last_fetch_ms,
        "relay_last_error": g.relay_last_error,
        "relay_last_fetched": g.relay_last_fetched,
        "require_owner": st.require_owner,
        "rate_limit": st.rate_limit_enabled,
        "p2p_noise": g.p2p_noise,
        "p2p_quic": g.p2p_quic,
        "quic_pin": g.quic_pin,
        "quic_mtls": g.quic_tls.as_ref().map(|c| c.require_client_auth).unwrap_or(false),
        "quic_pins": g.quic_tls.as_ref().map(|c| c.peer_pins.len()).unwrap_or(0),
        "rpc_tls": g.rpc_tls,
        "relay_seal": "olm-v2+aead-v1",
        "peers": g.peers.values().collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn remote_status(State(st): State<RpcState>) -> impl IntoResponse {
    p2p_status(State(st)).await
}

async fn relay_poll_now(State(st): State<RpcState>, headers: HeaderMap) -> impl IntoResponse {
    {
        let mut g = st.inner.lock().await;
        if let Err(resp) = require_owner_if_remote(&st, &mut g, &headers) {
            if st.require_owner {
                return *resp;
            }
        }
        if g.relay_uri.is_none() {
            return (
                StatusCode::CONFLICT,
                Json(ErrorBody {
                    error: "no relay configured (TD_RELAY_URI)".into(),
                }),
            )
                .into_response();
        }
    }
    match poll_relay_once(&st).await {
        Ok(n) => Json(serde_json::json!({"ok": true, "fetched": n})).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody { error: e }),
        )
            .into_response(),
    }
}

async fn relay_push_now(State(st): State<RpcState>, headers: HeaderMap) -> impl IntoResponse {
    {
        let mut g = st.inner.lock().await;
        if let Err(resp) = require_owner_if_remote(&st, &mut g, &headers) {
            if st.require_owner {
                return *resp;
            }
        }
        if g.relay_uri.is_none() {
            return (
                StatusCode::CONFLICT,
                Json(ErrorBody {
                    error: "no relay configured (TD_RELAY_URI)".into(),
                }),
            )
                .into_response();
        }
    }
    match push_outbox_to_relay(&st).await {
        Ok(n) => Json(serde_json::json!({"ok": true, "pushed": n})).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody { error: e }),
        )
            .into_response(),
    }
}


// --- Appliance: OTA + Wi-Fi wizard (first slice) ---

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WifiState {
    /// Configured SSID (never stores PSK in status responses).
    ssid: Option<String>,
    /// true if a PSK is stored (disk or memory).
    has_psk: bool,
    /// last apply result message
    last_apply: Option<String>,
    last_apply_ok: Option<bool>,
    /// Interface name hint (nl80211 later)
    iface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OtaManifest {
    /// Semver or git describe of available update.
    version: String,
    /// Download URL for release tarball (signed channel later).
    url: String,
    /// Optional sha256 hex of artifact.
    #[serde(default)]
    sha256: Option<String>,
    /// Optional ed25519 signature over "{version}\\n{url}\\n{sha256}" (hex).
    #[serde(default)]
    signature: Option<String>,
    /// Channel name (stable/beta).
    #[serde(default = "default_ota_channel")]
    channel: String,
}

fn default_ota_channel() -> String {
    "stable".into()
}

fn wifi_state_path(data: &Option<NodeDataDir>) -> Option<PathBuf> {
    data.as_ref().map(|d| d.root().join("wifi.json"))
}

fn ota_state_path(data: &Option<NodeDataDir>) -> Option<PathBuf> {
    data.as_ref().map(|d| d.root().join("ota-state.json"))
}

fn load_wifi_state(data: &Option<NodeDataDir>) -> WifiState {
    let mut st = WifiState {
        iface: std::env::var("TD_WIFI_IFACE").unwrap_or_else(|_| "wlan0".into()),
        ..Default::default()
    };
    if let Some(p) = wifi_state_path(data) {
        if let Ok(raw) = std::fs::read_to_string(&p) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                st.ssid = v.get("ssid").and_then(|x| x.as_str()).map(|s| s.to_string());
                st.has_psk = v.get("psk").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
                if let Some(i) = v.get("iface").and_then(|x| x.as_str()) {
                    st.iface = i.to_string();
                }
                st.last_apply = v.get("last_apply").and_then(|x| x.as_str()).map(|s| s.to_string());
                st.last_apply_ok = v.get("last_apply_ok").and_then(|x| x.as_bool());
            }
        }
    }
    st
}

fn save_wifi_disk(data: &Option<NodeDataDir>, ssid: &str, psk: &str, iface: &str, last_apply: &str, ok: bool) -> Result<(), String> {
    let Some(p) = wifi_state_path(data) else {
        return Err("no data dir — wifi config not durable".into());
    };
    let v = serde_json::json!({
        "ssid": ssid,
        "psk": psk,
        "iface": iface,
        "last_apply": last_apply,
        "last_apply_ok": ok,
    });
    std::fs::write(&p, serde_json::to_vec_pretty(&v).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

async fn wifi_status(State(st): State<RpcState>) -> impl IntoResponse {
    let g = st.inner.lock().await;
    let wifi = load_wifi_state(&g.data_dir);
    Json(serde_json::json!({
        "ok": true,
        "ssid": wifi.ssid,
        "has_psk": wifi.has_psk,
        "iface": wifi.iface,
        "last_apply": wifi.last_apply,
        "last_apply_ok": wifi.last_apply_ok,
        "backend": "nmcli-or-stub",
        "note": "First slice: stores config + best-effort nmcli apply when available",
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct WifiScanRequest {
    #[serde(default)]
    iface: Option<String>,
}

async fn wifi_scan(
    State(st): State<RpcState>,
    headers: HeaderMap,
    Json(req): Json<WifiScanRequest>,
) -> impl IntoResponse {
    {
        let mut g = st.inner.lock().await;
        if let Err(resp) = require_owner_if_remote(&st, &mut g, &headers) {
            if st.require_owner {
                return *resp;
            }
        }
    }
    let iface = req
        .iface
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| std::env::var("TD_WIFI_IFACE").unwrap_or_else(|_| "wlan0".into()));
    // Best-effort nmcli; fall back to empty list with note.
    let output = tokio::process::Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "SSID,SIGNAL,SECURITY,BARS",
            "dev",
            "wifi",
            "list",
            "ifname",
            &iface,
        ])
        .output()
        .await;
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut networks = Vec::new();
            for line in text.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.is_empty() || parts[0].is_empty() {
                    continue;
                }
                networks.push(serde_json::json!({
                    "ssid": parts[0],
                    "signal": parts.get(1).copied().unwrap_or(""),
                    "security": parts.get(2).copied().unwrap_or(""),
                    "bars": parts.get(3).copied().unwrap_or(""),
                }));
            }
            Json(serde_json::json!({
                "ok": true,
                "iface": iface,
                "networks": networks,
                "backend": "nmcli",
            }))
            .into_response()
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Json(serde_json::json!({
                "ok": true,
                "iface": iface,
                "networks": [],
                "backend": "stub",
                "note": if err.is_empty() { "nmcli unavailable or no wifi device".into() } else { err },
            }))
            .into_response()
        }
        Err(e) => Json(serde_json::json!({
            "ok": true,
            "iface": iface,
            "networks": [],
            "backend": "stub",
            "note": format!("nmcli not found: {e}"),
        }))
        .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct WifiApplyRequest {
    ssid: String,
    #[serde(default)]
    psk: Option<String>,
    #[serde(default)]
    iface: Option<String>,
}

async fn wifi_apply(
    State(st): State<RpcState>,
    headers: HeaderMap,
    Json(req): Json<WifiApplyRequest>,
) -> impl IntoResponse {
    let ssid = req.ssid.trim().to_string();
    if ssid.is_empty() || ssid.len() > 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "ssid required (1-32 chars)".into(),
            }),
        )
            .into_response();
    }
    let psk = req.psk.unwrap_or_default();
    let iface = req
        .iface
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| std::env::var("TD_WIFI_IFACE").unwrap_or_else(|_| "wlan0".into()));

    {
        let mut g = st.inner.lock().await;
        // Always require owner for wifi apply (credential write).
        if let Err(resp) = require_owner(&mut g, &headers) {
            return *resp;
        }
        if let Err(e) = save_wifi_disk(&g.data_dir, &ssid, &psk, &iface, "pending", false) {
            // allow in-memory-only when no data dir
            if g.data_dir.is_some() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody { error: e }),
                )
                    .into_response();
            }
        }
    }

    // Best-effort NetworkManager apply.
    let mut cmd = tokio::process::Command::new("nmcli");
    cmd.args(["dev", "wifi", "connect", &ssid, "ifname", &iface]);
    if !psk.is_empty() {
        cmd.args(["password", &psk]);
    }
    let apply = cmd.output().await;
    let (ok, msg) = match apply {
        Ok(out) if out.status.success() => {
            let m = String::from_utf8_lossy(&out.stdout).trim().to_string();
            (true, if m.is_empty() { "connected".into() } else { m })
        }
        Ok(out) => {
            let m = String::from_utf8_lossy(&out.stderr).trim().to_string();
            (
                false,
                if m.is_empty() {
                    format!("nmcli exit {}", out.status)
                } else {
                    m
                },
            )
        }
        Err(e) => (
            false,
            format!("nmcli not available ({e}); config saved for later apply"),
        ),
    };

    {
        let g = st.inner.lock().await;
        let _ = save_wifi_disk(&g.data_dir, &ssid, &psk, &iface, &msg, ok);
    }

    Json(serde_json::json!({
        "ok": ok,
        "ssid": ssid,
        "iface": iface,
        "message": msg,
        "persisted": true,
    }))
    .into_response()
}

fn current_package_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn ota_channel() -> String {
    std::env::var("TD_OTA_CHANNEL").unwrap_or_else(|_| "stable".into())
}

fn ota_manifest_url() -> Option<String> {
    std::env::var("TD_OTA_MANIFEST_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn ota_pubkey() -> Option<[u8; 32]> {
    let s = std::env::var("TD_OTA_PUBKEY").ok()?;
    let t = s.trim();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn verify_ota_manifest(m: &OtaManifest) -> Result<(), String> {
    let Some(pk) = ota_pubkey() else {
        // No pubkey configured → accept unsigned manifests (dev).
        return Ok(());
    };
    let Some(sig_hex) = m.signature.as_deref() else {
        return Err("manifest missing signature (TD_OTA_PUBKEY set)".into());
    };
    if sig_hex.len() != 128 || !sig_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid signature hex".into());
    }
    let mut sig = [0u8; 64];
    for i in 0..64 {
        sig[i] = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "bad sig hex".to_string())?;
    }
    let sha = m.sha256.clone().unwrap_or_default();
    let msg = format!("{}\n{}\n{}", m.version, m.url, sha);
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(&sig);
    vk.verify(msg.as_bytes(), &signature)
        .map_err(|_| "OTA manifest signature invalid".to_string())
}

fn ota_auto_apply_enabled() -> bool {
    match std::env::var("TD_OTA_AUTO_APPLY") {
        Ok(s) => {
            let t = s.trim().to_ascii_lowercase();
            !(t.is_empty() || t == "0" || t == "false" || t == "no" || t == "off")
        }
        // Default on when data dir + path unit are the Pond DIY path.
        Err(_) => true,
    }
}

fn ota_pending_path(data: &Option<NodeDataDir>) -> Option<PathBuf> {
    data.as_ref().map(|d| d.root().join("ota").join("pending.json"))
}

fn ota_last_apply_path(data: &Option<NodeDataDir>) -> Option<PathBuf> {
    data.as_ref().map(|d| d.root().join("ota").join("last-apply.json"))
}

async fn ota_status(State(st): State<RpcState>) -> impl IntoResponse {
    let g = st.inner.lock().await;
    let mut available = None;
    let mut last_check = None;
    let mut last_error = None;
    let mut staged = None;
    let mut last_apply = None;
    let mut last_apply_ok = None;
    let mut last_apply_ms = None;
    let mut installed_version = None;
    let mut previous_version = None;
    let mut previous_path = None;
    let mut previous_saved_ms = None;
    let mut last_action = None;
    let mut last_rollback_ms = None;
    let mut last_rollback_version = None;
    let mut can_rollback = false;
    if let Some(p) = ota_state_path(&g.data_dir) {
        if let Ok(raw) = std::fs::read_to_string(p) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                last_check = v.get("last_check_ms").and_then(|x| x.as_u64());
                last_error = v.get("last_error").and_then(|x| x.as_str()).map(|s| s.to_string());
                staged = v.get("staged_path").and_then(|x| x.as_str()).map(|s| s.to_string());
                last_apply = v.get("last_apply").and_then(|x| x.as_str()).map(|s| s.to_string());
                last_apply_ok = v.get("last_apply_ok").and_then(|x| x.as_bool());
                last_apply_ms = v.get("last_apply_ms").and_then(|x| x.as_u64());
                installed_version = v
                    .get("installed_version")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                previous_version = v
                    .get("previous_version")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                previous_path = v
                    .get("previous_path")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                previous_saved_ms = v.get("previous_saved_ms").and_then(|x| x.as_u64());
                last_action = v
                    .get("last_action")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                last_rollback_ms = v.get("last_rollback_ms").and_then(|x| x.as_u64());
                last_rollback_version = v
                    .get("last_rollback_version")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                if let Some(a) = v.get("available") {
                    available = serde_json::from_value::<OtaManifest>(a.clone()).ok();
                }
            }
        }
    }
    // Prefer live previous binary on disk over state alone.
    if let Some(dir) = g.data_dir.as_ref() {
        let prev_bin = dir.root().join("ota").join("previous").join("tducks.bin");
        let meta = dir.root().join("ota").join("previous").join("meta.json");
        if prev_bin.is_file() {
            can_rollback = true;
            if previous_path.is_none() {
                previous_path = Some(prev_bin.display().to_string());
            }
            if previous_version.is_none() {
                if let Ok(raw) = std::fs::read_to_string(&meta) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                        previous_version = v
                            .get("version")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string());
                        if previous_saved_ms.is_none() {
                            previous_saved_ms = v.get("saved_ms").and_then(|x| x.as_u64());
                        }
                    }
                }
            }
        } else if let Some(ref p) = previous_path {
            can_rollback = PathBuf::from(p).is_file();
        }
    }
    let pending = ota_pending_path(&g.data_dir)
        .map(|p| p.exists())
        .unwrap_or(false);
    let mut helper_result = None;
    if let Some(p) = ota_last_apply_path(&g.data_dir) {
        if let Ok(raw) = std::fs::read_to_string(p) {
            helper_result = serde_json::from_str::<serde_json::Value>(&raw).ok();
        }
    }
    Json(serde_json::json!({
        "ok": true,
        "current_version": current_package_version(),
        "channel": ota_channel(),
        "manifest_url": ota_manifest_url(),
        "signature_required": ota_pubkey().is_some(),
        "auto_apply": ota_auto_apply_enabled(),
        "pending": pending,
        "last_check_ms": last_check,
        "available": available,
        "staged_path": staged,
        "last_apply": last_apply,
        "last_apply_ok": last_apply_ok,
        "last_apply_ms": last_apply_ms,
        "installed_version": installed_version,
        "previous_version": previous_version,
        "previous_path": previous_path,
        "previous_saved_ms": previous_saved_ms,
        "can_rollback": can_rollback,
        "last_action": last_action,
        "last_rollback_ms": last_rollback_ms,
        "last_rollback_version": last_rollback_version,
        "helper_result": helper_result,
        "last_error": last_error,
    }))
    .into_response()
}

async fn ota_check(State(st): State<RpcState>, headers: HeaderMap) -> impl IntoResponse {
    {
        let mut g = st.inner.lock().await;
        if let Err(resp) = require_owner(&mut g, &headers) {
            return *resp;
        }
    }
    let Some(url) = ota_manifest_url() else {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "TD_OTA_MANIFEST_URL not configured".into(),
            }),
        )
            .into_response();
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
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: format!("manifest fetch failed: {e}"),
                }),
            )
                .into_response();
        }
    };
    if !resp.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody {
                error: format!("manifest HTTP {}", resp.status()),
            }),
        )
            .into_response();
    }
    let manifest: OtaManifest = match resp.json().await {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: format!("manifest decode: {e}"),
                }),
            )
                .into_response();
        }
    };
    if let Err(e) = verify_ota_manifest(&manifest) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody { error: e }),
        )
            .into_response();
    }
    let now = now_ms();
    {
        let g = st.inner.lock().await;
        if let Some(p) = ota_state_path(&g.data_dir) {
            let v = serde_json::json!({
                "last_check_ms": now,
                "available": manifest,
                "last_error": null,
            });
            let _ = std::fs::write(p, serde_json::to_vec_pretty(&v).unwrap_or_default());
        }
    }
    let newer = manifest.version != current_package_version();
    Json(serde_json::json!({
        "ok": true,
        "current_version": current_package_version(),
        "available": manifest,
        "update_available": newer,
        "checked_at_ms": now,
    }))
    .into_response()
}

async fn ota_apply(State(st): State<RpcState>, headers: HeaderMap) -> impl IntoResponse {
    {
        let mut g = st.inner.lock().await;
        if let Err(resp) = require_owner(&mut g, &headers) {
            return *resp;
        }
    }
    // First slice: download artifact to data dir staging; operator restarts / install script applies.
    let g = st.inner.lock().await;
    let Some(dir) = g.data_dir.as_ref() else {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "data dir required for OTA staging".into(),
            }),
        )
            .into_response();
    };
    let state_path = dir.root().join("ota-state.json");
    let raw = match std::fs::read_to_string(&state_path) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorBody {
                    error: "run POST /v1/ota/check first".into(),
                }),
            )
                .into_response();
        }
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
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
    let Some(avail) = v.get("available").cloned() else {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "no available update in ota-state".into(),
            }),
        )
            .into_response();
    };
    let manifest: OtaManifest = match serde_json::from_value(avail) {
        Ok(m) => m,
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
    drop(g);

    if let Err(e) = verify_ota_manifest(&manifest) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody { error: e }),
        )
            .into_response();
    }

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
    let bytes = match client.get(&manifest.url).send().await {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorBody {
                        error: format!("download body: {e}"),
                    }),
                )
                    .into_response();
            }
        },
        Ok(r) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: format!("download HTTP {}", r.status()),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody {
                    error: format!("download failed: {e}"),
                }),
            )
                .into_response();
        }
    };

    if let Some(want) = manifest.sha256.as_deref() {
        // Field name historical; value is blake3 hex of artifact bytes.
        let got = hex::encode(blake3::hash(&bytes).as_bytes());
        let want = want.trim().to_ascii_lowercase();
        if want != got {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "artifact hash mismatch (expected blake3 hex)".into(),
                }),
            )
                .into_response();
        }
    }

    let g = st.inner.lock().await;
    let stage_dir = g.data_dir.as_ref().unwrap().root().join("ota");
    if let Err(e) = std::fs::create_dir_all(&stage_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response();
    }
    let stage_path = stage_dir.join(format!("tducks-{}.bin", manifest.version));
    if let Err(e) = std::fs::write(&stage_path, &bytes) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: e.to_string(),
            }),
        )
            .into_response();
    }
    let staged = stage_path.display().to_string();
    let data_root = g.data_dir.as_ref().unwrap().root().to_path_buf();
    let state_path = data_root.join("ota-state.json");
    let ota_dir = data_root.join("ota");
    let pending_path = ota_dir.join("pending.json");
    let auto = ota_auto_apply_enabled();
    // Request body: optional restart override via query is not used; env TD_OTA_RESTART default true.
    let do_restart = match std::env::var("TD_OTA_RESTART") {
        Ok(s) => {
            let t = s.trim().to_ascii_lowercase();
            !(t == "0" || t == "false" || t == "no" || t == "off")
        }
        Err(_) => true,
    };

    let mut apply_mode = "staged";
    let mut apply_note = "Artifact staged only (TD_OTA_AUTO_APPLY=false). Install manually or enable auto-apply.".to_string();
    let mut pending_written = false;
    let mut helper_started = false;
    let mut helper_error: Option<String> = None;

    if auto {
        let pending = serde_json::json!({
            "action": "apply",
            "version": manifest.version,
            "staged_path": staged,
            "restart": do_restart,
            "requested_ms": now_ms(),
        });
        if let Err(e) = std::fs::write(
            &pending_path,
            serde_json::to_vec_pretty(&pending).unwrap_or_default(),
        ) {
            helper_error = Some(format!("write pending.json: {e}"));
        } else {
            pending_written = true;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&pending_path, std::fs::Permissions::from_mode(0o640));
            }
            apply_mode = "pending";

            // Best-effort kick if path unit is not watching (dev / partial installs).
            let kick = tokio::process::Command::new("systemctl")
                .args(["start", "tducks-ota-apply.service"])
                .output()
                .await;
            match kick {
                Ok(out) if out.status.success() => {
                    helper_started = true;
                    apply_mode = "applying";
                    apply_note = "tducks-ota-apply.service started (install + restart)".into();
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    // Path unit may pick it up shortly even if start failed (unit missing).
                    helper_error = Some(if err.is_empty() {
                        format!("systemctl start exit {}", out.status)
                    } else {
                        err
                    });
                    apply_note = format!(
                        "pending.json written; systemctl start failed ({}) — ensure tducks-ota-apply.path is enabled",
                        helper_error.as_deref().unwrap_or("?")
                    );
                }
                Err(e) => {
                    helper_error = Some(format!("systemctl not available: {e}"));
                    apply_note = "pending.json written; no systemctl — run scripts/tducks-ota-apply.sh as root".into();
                }
            }
        }
    }

    let v = serde_json::json!({
        "last_check_ms": now_ms(),
        "available": manifest,
        "staged_path": staged,
        "last_error": helper_error,
        "last_apply": apply_note,
        "last_apply_ok": pending_written || !auto,
        "pending": if pending_written {
            serde_json::json!({
                "path": pending_path.display().to_string(),
                "restart": do_restart,
            })
        } else {
            serde_json::Value::Null
        },
    });
    let _ = std::fs::write(state_path, serde_json::to_vec_pretty(&v).unwrap_or_default());
    drop(g);

    Json(serde_json::json!({
        "ok": true,
        "staged_path": staged,
        "version": manifest.version,
        "bytes": bytes.len(),
        "auto_apply": auto,
        "restart": do_restart,
        "pending_written": pending_written,
        "helper_started": helper_started,
        "mode": apply_mode,
        "note": apply_note,
        "helper_error": helper_error,
    }))
    .into_response()
}

/// Roll back to the previous binary saved by the last successful apply.
async fn ota_rollback(State(st): State<RpcState>, headers: HeaderMap) -> impl IntoResponse {
    {
        let mut g = st.inner.lock().await;
        if let Err(resp) = require_owner(&mut g, &headers) {
            return *resp;
        }
    }

    let g = st.inner.lock().await;
    let Some(dir) = g.data_dir.as_ref() else {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "data dir required for OTA rollback".into(),
            }),
        )
            .into_response();
    };

    let data_root = dir.root().to_path_buf();
    let ota_dir = data_root.join("ota");
    let prev_bin = ota_dir.join("previous").join("tducks.bin");
    let prev_meta = ota_dir.join("previous").join("meta.json");
    let pending_path = ota_dir.join("pending.json");
    let state_path = data_root.join("ota-state.json");

    if pending_path.exists() {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "OTA pending already exists; wait for apply/rollback to finish".into(),
            }),
        )
            .into_response();
    }

    if !prev_bin.is_file() {
        return (
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "no previous binary available for rollback".into(),
            }),
        )
            .into_response();
    }

    let mut previous_version = "unknown".to_string();
    if let Ok(raw) = std::fs::read_to_string(&prev_meta) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(ver) = v.get("version").and_then(|x| x.as_str()) {
                if !ver.is_empty() {
                    previous_version = ver.to_string();
                }
            }
        }
    }
    // Fallback: ota-state.json
    if previous_version == "unknown" {
        if let Ok(raw) = std::fs::read_to_string(&state_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(ver) = v.get("previous_version").and_then(|x| x.as_str()) {
                    if !ver.is_empty() {
                        previous_version = ver.to_string();
                    }
                }
            }
        }
    }

    let from_version = {
        if let Ok(raw) = std::fs::read_to_string(&state_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                v.get("installed_version")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(current_package_version)
            } else {
                current_package_version()
            }
        } else {
            current_package_version()
        }
    };

    let do_restart = match std::env::var("TD_OTA_RESTART") {
        Ok(s) => {
            let t = s.trim().to_ascii_lowercase();
            !(t == "0" || t == "false" || t == "no" || t == "off")
        }
        Err(_) => true,
    };

    let pending = serde_json::json!({
        "action": "rollback",
        "version": previous_version,
        "from_version": from_version,
        "staged_path": prev_bin.display().to_string(),
        "restart": do_restart,
        "requested_ms": now_ms(),
    });

    if let Err(e) = std::fs::create_dir_all(&ota_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("create ota dir: {e}"),
            }),
        )
            .into_response();
    }
    if let Err(e) = std::fs::write(
        &pending_path,
        serde_json::to_vec_pretty(&pending).unwrap_or_default(),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("write pending.json: {e}"),
            }),
        )
            .into_response();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&pending_path, std::fs::Permissions::from_mode(0o640));
    }

    let mut helper_started = false;
    let mut helper_error: Option<String> = None;
    let (apply_mode, apply_note) = {
        let kick = tokio::process::Command::new("systemctl")
            .args(["start", "tducks-ota-apply.service"])
            .output()
            .await;
        match kick {
            Ok(out) if out.status.success() => {
                helper_started = true;
                (
                    "rolling_back",
                    "tducks-ota-apply.service started (rollback + restart)".to_string(),
                )
            }
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                helper_error = Some(if err.is_empty() {
                    format!("systemctl start exit {}", out.status)
                } else {
                    err
                });
                (
                    "pending",
                    format!(
                        "pending.json written; systemctl start failed ({}) — ensure tducks-ota-apply.path is enabled",
                        helper_error.as_deref().unwrap_or("?")
                    ),
                )
            }
            Err(e) => {
                helper_error = Some(format!("systemctl not available: {e}"));
                (
                    "pending",
                    "pending.json written; no systemctl — run scripts/tducks-ota-apply.sh as root"
                        .to_string(),
                )
            }
        }
    };

    // Merge note into ota-state without wiping previous_* fields.
    let mut st_val = serde_json::json!({});
    if let Ok(raw) = std::fs::read_to_string(&state_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            st_val = v;
        }
    }
    if let Some(obj) = st_val.as_object_mut() {
        obj.insert("last_apply".into(), serde_json::json!(apply_note));
        obj.insert("last_apply_ok".into(), serde_json::json!(true));
        obj.insert("last_error".into(), serde_json::json!(helper_error));
        obj.insert(
            "pending".into(),
            serde_json::json!({
                "action": "rollback",
                "path": pending_path.display().to_string(),
                "restart": do_restart,
                "version": previous_version,
            }),
        );
    }
    let _ = std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&st_val).unwrap_or_default(),
    );
    drop(g);

    Json(serde_json::json!({
        "ok": true,
        "action": "rollback",
        "version": previous_version,
        "from_version": from_version,
        "staged_path": prev_bin.display().to_string(),
        "restart": do_restart,
        "pending_written": true,
        "helper_started": helper_started,
        "mode": apply_mode,
        "note": apply_note,
        "helper_error": helper_error,
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
        .route("/v1/e2ee/trust-keys", post(trust_olm_keys))
        .route("/v1/e2ee/export-session", post(export_session))
        .route("/v1/e2ee/import-session", post(import_session))
        .route("/v1/e2ee/import-olm", post(import_session_olm))
        .route("/v1/e2ee/share-session", post(share_session_with_peer))
        .route("/v1/p2p", get(p2p_status))
        .route("/v1/remote", get(remote_status))
        .route("/v1/relay/poll", post(relay_poll_now))
        .route("/v1/relay/push", post(relay_push_now))
        .route("/v1/wifi", get(wifi_status))
        .route("/v1/wifi/scan", post(wifi_scan))
        .route("/v1/wifi/apply", post(wifi_apply))
        .route("/v1/ota", get(ota_status))
        .route("/v1/ota/check", post(ota_check))
        .route("/v1/ota/apply", post(ota_apply))
        .route("/v1/ota/rollback", post(ota_rollback))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authn_rate_middleware,
        ))
        .layer(cors)
        .with_state(state)
}

pub fn new_state() -> RpcState {
    RpcState {
        inner: Arc::new(Mutex::new(NodeSession::new())),
        notify: Arc::new(RoomNotify::new()),
        require_owner: false,
        rate_limits: Arc::new(Mutex::new(RateLimitBook::default())),
        rate_limit_enabled: true,
    }
}

/// Build RPC state loading durable identity + claim from `data_dir`.
pub fn new_state_with_data_dir(data_dir: impl Into<std::path::PathBuf>) -> Result<RpcState, String> {
    new_state_with_options(ServeOptions {
        data_dir: Some(data_dir.into()),
        ..Default::default()
    })
}

/// Build RPC state from full serve options.
pub fn new_state_with_options(opts: ServeOptions) -> Result<RpcState, String> {
    let mut session = if let Some(dir) = opts.data_dir.clone() {
        NodeSession::load_from_data_dir(NodeDataDir::new(dir))?
    } else {
        NodeSession::new()
    };
    session.apply_remote_opts(&opts);
    // require_owner decided at serve() from bind + flag; default false here.
    Ok(RpcState {
        inner: Arc::new(Mutex::new(session)),
        notify: Arc::new(RoomNotify::new()),
        require_owner: false,
        rate_limits: Arc::new(Mutex::new(RateLimitBook::default())),
        rate_limit_enabled: opts.rate_limit,
    })
}

async fn start_p2p_listener(
    state: RpcState,
    p2p_bind: &str,
    advertise_host: Option<&str>,
) -> Result<String, std::io::Error> {
    let (noise, quic) = {
        let g = state.inner.lock().await;
        (g.p2p_noise, g.p2p_quic)
    };

    if quic {
        let qcfg = {
            let g = state.inner.lock().await;
            g.quic_tls
                .clone()
                .unwrap_or_else(|| QuicTlsConfig::insecure_ephemeral().expect("ephemeral quic"))
        };
        let (endpoint, addr) = quic_listen_with_config(p2p_bind, &qcfg)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let uri = advertise_p2p_uri(addr, advertise_host, false, true);
        {
            let mut g = state.inner.lock().await;
            g.p2p_uri = Some(uri.clone());
        }
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let mut stream = match quic_accept(&endpoint).await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let st2 = st.clone();
                tokio::spawn(async move {
                    while let Ok(ev) = stream.read_event().await {
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
        return Ok(uri);
    }

    let listener = TcpListener::bind(p2p_bind).await?;
    let addr = listener.local_addr()?;
    let uri = advertise_p2p_uri(addr, advertise_host, noise, false);
    {
        let mut g = state.inner.lock().await;
        g.p2p_uri = Some(uri.clone());
    }
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            let sock = match accept_once(&listener).await {
                Ok(s) => s,
                Err(_) => break,
            };
            let st2 = st.clone();
            tokio::spawn(async move {
                if noise {
                    let mut ns = match NoiseTcpStream::handshake_responder(sock).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    while let Ok(ev) = noise_read_event(&mut ns).await {
                        let room_id = ev.room_id;
                        let inserted = {
                            let mut g = st2.inner.lock().await;
                            g.ingest_remote(ev).unwrap_or(false)
                        };
                        if inserted {
                            notify_room_from_id(&st2, &room_id).await;
                        }
                    }
                } else {
                    let mut sock = sock;
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
                }
            });
        }
    });
    Ok(uri)
}

async fn poll_relay_once(state: &RpcState) -> Result<u32, String> {
    let (relay_uri, device_id) = {
        let g = state.inner.lock().await;
        let uri = g
            .relay_uri
            .clone()
            .ok_or_else(|| "no relay configured".to_string())?;
        (uri, g.keypair.event_device_id())
    };
    let peer = PeerUri::parse(&relay_uri).map_err(|e| e.to_string())?;
    let mut client = RelayClient::connect(&peer)
        .await
        .map_err(|e| e.to_string())?;
    let items = client
        .fetch(device_id, 0, 64)
        .await
        .map_err(|e| e.to_string())?;
    let mut acked = Vec::new();
    let mut inserted = 0u32;
    for env in items {
        let opened = {
            let mut g = state.inner.lock().await;
            let key = g.relay_key;
            DeviceNode::open_from_relay_auto(&mut g.e2ee, Some(&key), &env.ciphertext)
        };
        match opened {
            Ok(ev) => {
                let room_id = ev.room_id;
                let ok = {
                    let mut g = state.inner.lock().await;
                    g.ingest_remote(ev).unwrap_or(false)
                };
                if ok {
                    inserted += 1;
                    notify_room_from_id(state, &room_id).await;
                }
                acked.push(env.envelope_id);
            }
            Err(e) => {
                let mut g = state.inner.lock().await;
                g.relay_last_error = Some(format!("open envelope: {e}"));
            }
        }
    }
    if !acked.is_empty() {
        let _ = client.ack(device_id, acked).await;
    }
    {
        let mut g = state.inner.lock().await;
        g.relay_last_fetch_ms = Some(now_ms());
        g.relay_last_fetched = inserted;
        if inserted > 0 {
            g.relay_last_error = None;
        }
    }
    Ok(inserted)
}

fn spawn_relay_poller(state: RpcState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            let has = {
                let g = state.inner.lock().await;
                g.relay_uri.is_some()
            };
            if !has {
                continue;
            }
            if let Err(e) = poll_relay_once(&state).await {
                let mut g = state.inner.lock().await;
                g.relay_last_error = Some(e);
                g.relay_last_fetch_ms = Some(now_ms());
            }
        }
    });
}

/// Push sealed local outbox events to the configured relay.
/// Prefer per-recipient Olm (v2); fall back to shared AEAD (v1) when no Olm session.
async fn push_outbox_to_relay(state: &RpcState) -> Result<u32, String> {
    let (relay_uri, sender, sealed) = {
        let mut g = state.inner.lock().await;
        let uri = g
            .relay_uri
            .clone()
            .ok_or_else(|| "no relay configured".to_string())?;
        let sender = g.keypair.event_device_id();
        let recipients = g.relay_recipients();
        // Drain a bounded number from outbox for relay assist.
        let mut events = Vec::new();
        for _ in 0..16 {
            match g.node.pop_outbox() {
                Some(ev) => events.push(ev),
                None => break,
            }
        }
        if events.is_empty() || recipients.is_empty() {
            return Ok(0);
        }
        let mut sealed: Vec<(td_event::DeviceId, Option<td_event::RoomId>, u64, Vec<u8>)> =
            Vec::new();
        for ev in &events {
            for recip in &recipients {
                let (ct, _mode) = g.seal_event_for_recipient(ev, *recip)?;
                sealed.push(((*recip).into(), Some(ev.room_id), ev.ts_ms, ct));
            }
        }
        (uri, sender, sealed)
    };
    if sealed.is_empty() {
        return Ok(0);
    }
    let peer = PeerUri::parse(&relay_uri).map_err(|e| e.to_string())?;
    let mut client = RelayClient::connect(&peer)
        .await
        .map_err(|e| e.to_string())?;
    let mut n = 0u32;
    for (recip, room, ts, ct) in sealed {
        let env = RelayEnvelope::new(recip, sender, room, ct, ts);
        client.put(env).await.map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}



fn build_quic_tls_config(opts: &ServeOptions, data_dir: Option<&PathBuf>) -> Result<Option<QuicTlsConfig>, String> {
    if !opts.p2p_quic {
        return Ok(None);
    }
    let pins = match &opts.quic_pins {
        Some(s) => parse_pin_list(s).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    let mtls = opts.quic_mtls.unwrap_or(!pins.is_empty());

    let (cert, key) = match (&opts.quic_cert, &opts.quic_key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        (None, None) => {
            // Prefer durable identity under data dir; else ephemeral.
            if let Some(dir) = data_dir {
                let c = dir.join("quic-cert.pem");
                let k = dir.join("quic-key.pem");
                if c.is_file() && k.is_file() {
                    (c, k)
                } else {
                    let mut cfg = write_self_signed_pem(&c, &k).map_err(|e| e.to_string())?;
                    cfg = cfg.with_pins(pins).with_mtls(mtls);
                    return Ok(Some(cfg));
                }
            } else {
                let mut cfg = QuicTlsConfig::insecure_ephemeral().map_err(|e| e.to_string())?;
                if !pins.is_empty() {
                    cfg = cfg.with_pins(pins).with_mtls(mtls);
                }
                return Ok(Some(cfg));
            }
        }
        _ => {
            return Err("both TD_QUIC_CERT and TD_QUIC_KEY required (or neither)".into());
        }
    };

    let mut cfg =
        QuicTlsConfig::from_pem_files(&cert, &key, pins, mtls).map_err(|e| e.to_string())?;
    // from_pem_files sets insecure when no pins; honor explicit mtls/pins
    if mtls {
        cfg = cfg.with_mtls(true);
    }
    Ok(Some(cfg))
}

fn ensure_rustls_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Load rustls config from PEM files or generate ephemeral self-signed.
async fn load_tls_config(
    cert: Option<&PathBuf>,
    key: Option<&PathBuf>,
    self_signed: bool,
) -> Result<Option<RustlsConfig>, std::io::Error> {
    ensure_rustls_provider();
    match (cert, key) {
        (Some(c), Some(k)) => {
            let cfg = RustlsConfig::from_pem_file(c, k)
                .await
                .map_err(|e| std::io::Error::other(format!("tls cert/key: {e}")))?;
            Ok(Some(cfg))
        }
        (None, None) if self_signed => {
            let (certs, key_der) = generate_self_signed_rpc_cert()
                .map_err(|e| std::io::Error::other(format!("self-signed tls: {e}")))?;
            let cfg = RustlsConfig::from_der(certs, key_der)
                .await
                .map_err(|e| std::io::Error::other(format!("tls der: {e}")))?;
            Ok(Some(cfg))
        }
        (None, None) => Ok(None),
        _ => Err(std::io::Error::other(
            "both TD_TLS_CERT and TD_TLS_KEY required (or TD_TLS_SELF_SIGNED=true)",
        )),
    }
}

fn generate_self_signed_rpc_cert() -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    ensure_rustls_provider();
    use rcgen::{CertificateParams, KeyPair, SanType};
    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(vec!["localhost".into(), "td-pond".into()])
        .map_err(|e| e.to_string())?;
    params.subject_alt_names.push(
        SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e: rcgen::Error| e.to_string())?,
        ),
    );
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    Ok((vec![cert.der().to_vec()], key_pair.serialize_der()))
}

/// Serve RPC on `bind` (e.g. 127.0.0.1:8788). Returns local addr after bind.
/// In-memory only (tests / smoke). Prefer `serve_with_options` for Pond.
pub async fn serve(bind: &str) -> Result<SocketAddr, std::io::Error> {
    serve_with_options(bind, ServeOptions::default()).await
}

/// Serve RPC with durable identity + claim under `data_dir`.
pub async fn serve_with_data_dir(
    bind: &str,
    data_dir: impl Into<std::path::PathBuf>,
) -> Result<SocketAddr, std::io::Error> {
    serve_with_options(
        bind,
        ServeOptions {
            data_dir: Some(data_dir.into()),
            ..Default::default()
        },
    )
    .await
}

/// Serve RPC with full remote-access options.
pub async fn serve_with_options(
    bind: &str,
    opts: ServeOptions,
) -> Result<SocketAddr, std::io::Error> {
    let prepared = prepare_serve(bind, opts).await?;
    let scheme = if prepared.tls.is_some() { "https" } else { "http" };
    eprintln!(
        "td-node rpc listening on {scheme}://{} p2p={}",
        prepared.addr, prepared.p2p
    );
    let app = router(prepared.state);
    let addr = prepared.addr;
    tokio::spawn(async move {
        let _ = run_rpc_server(prepared.listener, prepared.tls, app).await;
    });
    Ok(addr)
}

/// Serve and block (for binary embedding). In-memory only.
pub async fn serve_blocking(bind: &str) -> Result<(), std::io::Error> {
    serve_blocking_with_options(bind, ServeOptions::default()).await
}

/// Serve and block with durable identity + claim under `data_dir`.
pub async fn serve_blocking_with_data_dir(
    bind: &str,
    data_dir: impl Into<std::path::PathBuf>,
) -> Result<(), std::io::Error> {
    serve_blocking_with_options(
        bind,
        ServeOptions {
            data_dir: Some(data_dir.into()),
            ..Default::default()
        },
    )
    .await
}

/// Serve and block with full options (CLI entrypoint).
pub async fn serve_blocking_with_options(
    bind: &str,
    opts: ServeOptions,
) -> Result<(), std::io::Error> {
    let prepared = prepare_serve(bind, opts).await?;
    let notes = {
        let g = prepared.state.inner.lock().await;
        let data = g
            .data_dir
            .as_ref()
            .map(|d| format!(" data={}", d.root().display()))
            .unwrap_or_default();
        let relay = g
            .relay_uri
            .as_ref()
            .map(|r| format!(" relay={r}"))
            .unwrap_or_default();
        let adv = g
            .advertise_host
            .as_ref()
            .map(|h| format!(" advertise={h}"))
            .unwrap_or_default();
        let own = if prepared.state.require_owner {
            " owner_gate=on"
        } else {
            " owner_gate=off"
        };
        let tls = if g.rpc_tls { " tls=on" } else { " tls=off" };
        let p2p_mode = if g.p2p_quic {
            " p2p=quic"
        } else if g.p2p_noise {
            " p2p=noise"
        } else {
            " p2p=tcp"
        };
        format!("{data}{relay}{adv}{own}{tls}{p2p_mode}")
    };
    let scheme = if prepared.tls.is_some() { "https" } else { "http" };
    eprintln!(
        "td-node rpc listening on {scheme}://{} p2p={}{notes}",
        prepared.addr, prepared.p2p
    );
    let app = router(prepared.state);
    run_rpc_server(prepared.listener, prepared.tls, app).await
}

struct PreparedServe {
    state: RpcState,
    p2p: String,
    listener: tokio::net::TcpListener,
    addr: SocketAddr,
    tls: Option<RustlsConfig>,
}

async fn run_rpc_server(
    listener: tokio::net::TcpListener,
    tls: Option<RustlsConfig>,
    app: axum::Router,
) -> Result<(), std::io::Error> {
    let make = app.into_make_service_with_connect_info::<SocketAddr>();
    match tls {
        Some(cfg) => {
            let std_listener = listener.into_std()?;
            std_listener.set_nonblocking(true)?;
            axum_server::from_tcp_rustls(std_listener, cfg)
                .serve(make)
                .await
        }
        None => axum::serve(listener, make).await,
    }
}

async fn prepare_serve(bind: &str, opts: ServeOptions) -> Result<PreparedServe, std::io::Error> {
    let require_owner = opts.require_owner_non_loopback && !is_loopback_bind(bind);
    let advertise = opts.advertise_host.clone();
    let p2p_bind = opts
        .p2p_bind
        .clone()
        .unwrap_or_else(|| "127.0.0.1:0".into());
    let tls_cert = opts.tls_cert.clone();
    let tls_key = opts.tls_key.clone();
    let tls_self_signed = opts.tls_self_signed;
    let mut state = new_state_with_options(opts.clone()).map_err(std::io::Error::other)?;
    state.require_owner = require_owner;
    let tls = load_tls_config(tls_cert.as_ref(), tls_key.as_ref(), tls_self_signed).await?;
    let https = tls.is_some();
    {
        let mut g = state.inner.lock().await;
        g.rpc_tls = https;
        let data_root = g.data_dir.as_ref().map(|d| d.root().to_path_buf());
        let qcfg = build_quic_tls_config(&opts, data_root.as_ref()).map_err(std::io::Error::other)?;
        if let Some(ref c) = qcfg {
            g.quic_pin = c.local_pin_hex();
        }
        g.quic_tls = qcfg;
    }
    let p2p = start_p2p_listener(state.clone(), &p2p_bind, advertise.as_deref()).await?;
    spawn_relay_poller(state.clone());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    {
        let mut g = state.inner.lock().await;
        g.rpc_base = Some(advertise_http_base(addr, advertise.as_deref(), https));
    }
    Ok(PreparedServe {
        state,
        p2p,
        listener,
        addr,
        tls,
    })
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

