//! Local node HTTP RPC for CLI + TS web (Wave E).
//!
//! Binds localhost only. In-memory single-device session for MVP smoke.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use td_crypto::{DeviceKeypair, LinkRegistry};
use td_event::{
    sign_event, DeviceId, EventId, EventKind, RoomId, RoomRegistry, SignedEvent, UnsignedEvent,
};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

use crate::sync::DeviceNode;

#[derive(Clone)]
pub struct RpcState {
    inner: Arc<Mutex<NodeSession>>,
}

struct NodeSession {
    keypair: DeviceKeypair,
    node: DeviceNode,
    rooms: RoomRegistry,
    /// room_id hex -> last parents (tips) cache via node
    peers: HashMap<String, String>,
    link: LinkRegistry,
    ts_counter: u64,
}

impl NodeSession {
    fn new() -> Self {
        let keypair = DeviceKeypair::generate();
        let mut link = LinkRegistry::new(keypair.device_id());
        let _ = link.trust_local(&keypair);
        let node = DeviceNode::from_crypto_device(keypair.device_id());
        Self {
            keypair,
            node,
            rooms: RoomRegistry::new(),
            peers: HashMap::new(),
            link,
            ts_counter: 1,
        }
    }

    fn next_ts(&mut self) -> u64 {
        self.ts_counter += 1;
        self.ts_counter
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub uri: String,
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
}

#[derive(Debug, Deserialize)]
pub struct RoomQuery {
    pub room_id: String,
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
    pub uri: String,
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
    // Try JSON {"text":...} else utf8 lossy
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&ev.payload) {
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
        .iter()
        .map(|(name, uri)| PeerInfo {
            name: name.clone(),
            uri: uri.clone(),
        })
        .collect();
    Json(StatusResponse {
        device_id: hex32(&g.keypair.device_id().0),
        verifying_key: hex::encode(g.keypair.verifying_key().as_bytes()),
        event_count: g.node.event_count(),
        rooms,
        linked_devices: linked,
        peers,
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
    let payload = serde_json::to_vec(&serde_json::json!({ "text": req.text })).unwrap_or_default();
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
    Json(SendResponse {
        event_id: hex32(&signed.id.0),
        ts_ms: signed.ts_ms,
    })
    .into_response()
}

async fn list_messages(
    State(st): State<RpcState>,
    Json(req): Json<RoomQuery>,
) -> impl IntoResponse {
    let g = st.inner.lock().await;
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
        .map(|ev| MessageView {
            event_id: hex32(&ev.id.0),
            author: hex32(&ev.author_device.0),
            ts_ms: ev.ts_ms,
            text: payload_text(&ev),
        })
        .collect();
    Json(MessagesResponse {
        room_id: req.room_id,
        messages,
    })
    .into_response()
}

async fn add_peer(
    State(st): State<RpcState>,
    Json(req): Json<AddPeerRequest>,
) -> impl IntoResponse {
    let mut g = st.inner.lock().await;
    g.peers.insert(req.name.clone(), req.uri.clone());
    Json(serde_json::json!({ "ok": true, "name": req.name, "uri": req.uri })).into_response()
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
        .route("/v1/peers", post(add_peer))
        .route("/v1/rooms", post(create_room))
        .route("/v1/messages", post(send_message))
        .route("/v1/messages/list", post(list_messages))
        .layer(cors)
        .with_state(state)
}

pub fn new_state() -> RpcState {
    RpcState {
        inner: Arc::new(Mutex::new(NodeSession::new())),
    }
}

/// Serve RPC on `bind` (e.g. 127.0.0.1:8788). Returns local addr after bind.
pub async fn serve(bind: &str) -> Result<SocketAddr, std::io::Error> {
    let state = new_state();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

/// Serve and block (for binary embedding).
pub async fn serve_blocking(bind: &str) -> Result<(), std::io::Error> {
    let state = new_state();
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    eprintln!("td-node rpc listening on http://{addr}");
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
