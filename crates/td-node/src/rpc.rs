//! Local node HTTP RPC for CLI + TS web (Wave E).
//!
//! Binds localhost only. In-memory single-device session for MVP smoke.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use td_crypto::{DeviceKeypair, E2eeDevice, LinkRegistry, MegolmCiphertext, PasskeyRegistry};
use td_event::{
    sign_event, DeviceId, EventId, EventKind, RoomId, RoomRegistry, SignedEvent, UnsignedEvent,
};
use td_net::{accept_once, dial, read_event, write_event, PeerUri};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

use crate::sync::{DeviceNode, SyncOffer};

#[derive(Clone)]
pub struct RpcState {
    inner: Arc<Mutex<NodeSession>>,
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
}

impl NodeSession {
    fn new() -> Self {
        let keypair = DeviceKeypair::generate();
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
        }
    }

    fn next_ts(&mut self) -> u64 {
        self.ts_counter += 1;
        self.ts_counter
    }

    /// Ensure we can encrypt for this room (per-sender outbound Megolm).
    /// Auto share-on-send makes multi-node decrypt work without a Sync button.
    fn ensure_room_e2ee(&mut self, room_hex: &str) {
        if self.e2ee_rooms.contains_key(room_hex) {
            return;
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
    let g = st.inner.lock().await;
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
    })
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
    // Export BEFORE encrypt: Megolm session_key() is at the current ratchet
    // index; post-encrypt export starts after this ciphertext and peers fail.
    let session_key_b64 = g.e2ee.export_group_session_key(&room_hex).ok();
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

            // 1) share current outbound Megolm key so peer can decrypt our sends
            if let Some(ref key) = session_key_b64 {
                match client
                    .post(format!("{peer_base}/v1/e2ee/import-session"))
                    .json(&serde_json::json!({ "session_key_b64": key }))
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => {}
                    Ok(r) => {
                        fanout_errors.push(format!("{}: import HTTP {}", ep.name, r.status()));
                        continue;
                    }
                    Err(e) => {
                        fanout_errors.push(format!("{}: import {e}", ep.name));
                        continue;
                    }
                }
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

/// Long-poll until room message count != since_count or timeout.
/// Returns the full message list (same shape as /v1/messages/list) plus wait metadata.
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
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let since = req.since_count;

    loop {
        let (count, messages) = {
            let mut g = st.inner.lock().await;
            let msgs: Vec<MessageView> = g
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
            (msgs.len(), msgs)
        };
        if count != since {
            return Json(serde_json::json!({
                "room_id": req.room_id,
                "messages": messages,
                "count": count,
                "changed": true,
                "timed_out": false,
            }))
            .into_response();
        }
        if tokio::time::Instant::now() >= deadline {
            return Json(serde_json::json!({
                "room_id": req.room_id,
                "messages": messages,
                "count": count,
                "changed": false,
                "timed_out": true,
            }))
            .into_response();
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
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
    pub session_key_b64: String,
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
    let mut g = st.inner.lock().await;
    let mut accepted = 0usize;
    let mut errors = Vec::new();
    for ev in req.events {
        match g.ingest_remote(ev) {
            Ok(true) => accepted += 1,
            Ok(false) => {}
            Err(e) => errors.push(e),
        }
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

async fn import_session(
    State(st): State<RpcState>,
    Json(req): Json<SessionImportRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    match g.e2ee.import_group_session_key(&req.session_key_b64) {
        Ok(session_id) => {
            Json(serde_json::json!({ "ok": true, "session_id": session_id })).into_response()
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

async fn share_session_with_peer(
    State(st): State<RpcState>,
    Json(req): Json<SyncPeerRequest>,
) -> impl IntoResponse {
    // Export our megolm key for room and POST import to peer (localhost demo path).
    let room_hex = req.room_id.clone();
    let peer_base = req.peer_rpc.trim_end_matches('/').to_string();
    let (session_key_b64, session_id, sender) = {
        let mut g = st.inner.lock().await;
        g.ensure_room_e2ee(&room_hex);
        match g.e2ee.export_group_session_key(&room_hex) {
            Ok(k) => (
                k,
                g.e2ee.group_session_id(&room_hex).unwrap_or_default(),
                hex32(&g.keypair.device_id().0),
            ),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: e.to_string(),
                    }),
                )
                    .into_response();
            }
        }
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
    match client
        .post(format!("{peer_base}/v1/e2ee/import-session"))
        .json(&serde_json::json!({ "session_key_b64": session_key_b64 }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => Json(serde_json::json!({
            "ok": true,
            "session_id": session_id,
            "sender_device": sender,
            "peer_rpc": peer_base,
            "room_id": room_hex,
        }))
        .into_response(),
        Ok(r) => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody {
                error: format!("peer import HTTP {}", r.status()),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorBody {
                error: format!("peer import: {e}"),
            }),
        )
            .into_response(),
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
        .route("/v1/sync/offer", post(sync_offer))
        .route("/v1/sync/ingest", post(sync_ingest))
        .route("/v1/sync/peer", post(sync_peer))
        .route("/v1/e2ee/export-session", post(export_session))
        .route("/v1/e2ee/import-session", post(import_session))
        .route("/v1/e2ee/share-session", post(share_session_with_peer))
        .route("/v1/p2p", get(p2p_status))
        .layer(cors)
        .with_state(state)
}

pub fn new_state() -> RpcState {
    RpcState {
        inner: Arc::new(Mutex::new(NodeSession::new())),
    }
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
                loop {
                    match read_event(&mut sock).await {
                        Ok(ev) => {
                            let mut g = st2.inner.lock().await;
                            let _ = g.ingest_remote(ev);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    Ok(uri)
}

/// Serve RPC on `bind` (e.g. 127.0.0.1:8788). Returns local addr after bind.
pub async fn serve(bind: &str) -> Result<SocketAddr, std::io::Error> {
    let state = new_state();
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

/// Serve and block (for binary embedding).
pub async fn serve_blocking(bind: &str) -> Result<(), std::io::Error> {
    let state = new_state();
    let p2p = start_p2p_listener(state.clone()).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    {
        let mut g = state.inner.lock().await;
        g.rpc_base = Some(format!("http://{addr}"));
    }
    let app = router(state);
    eprintln!("td-node rpc listening on http://{addr} p2p={p2p}");
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
