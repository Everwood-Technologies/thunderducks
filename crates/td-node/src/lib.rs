//! Node runtime: multi-device sync + local HTTP RPC (Waves D2 + E).

mod persist;
mod rpc;
mod sync;

pub use persist::{ClaimDisk, NodeDataDir, PersistError};
pub use rpc::{
    happy_path_script, new_state, new_state_with_data_dir, new_state_with_options, router, serve,
    serve_blocking, serve_blocking_with_data_dir, serve_blocking_with_options, serve_with_data_dir,
    serve_with_options, CreateRoomRequest, CreateRoomResponse, MessageView, MessagesResponse,
    RpcState, SendRequest, SendResponse, ServeOptions, StatusResponse,
};
pub use sync::{DeviceNode, SyncError, SyncOffer, SyncResponse};

/// Crate smoke marker used by CI.
pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;
    use td_crypto::DeviceKeypair;
    use td_event::{sign_event, EventKind, RoomId, UnsignedEvent};

    fn msg(
        kp: &DeviceKeypair,
        room: RoomId,
        parents: Vec<td_event::EventId>,
        ts: u64,
        body: &[u8],
    ) -> td_event::SignedEvent {
        sign_event(
            kp.signing_key(),
            UnsignedEvent {
                room_id: room,
                parents,
                kind: EventKind::Message,
                payload: body.to_vec(),
                author_device: kp.event_device_id(),
                ts_ms: ts,
            },
        )
        .unwrap()
    }

    #[test]
    fn smoke_name() {
        assert_eq!(crate_name(), "td-node");
    }

    #[test]
    fn two_devices_converge_after_partition() {
        let a_kp = DeviceKeypair::generate();
        let b_kp = DeviceKeypair::generate();
        let mut a = DeviceNode::from_crypto_device(a_kp.device_id());
        let mut b = DeviceNode::from_crypto_device(b_kp.device_id());
        let room = RoomId::from_bytes([7u8; 32]);

        let create = sign_event(
            a_kp.signing_key(),
            UnsignedEvent {
                room_id: room,
                parents: vec![],
                kind: EventKind::CreateRoom,
                payload: br#"{"name":"pond"}"#.to_vec(),
                author_device: a_kp.event_device_id(),
                ts_ms: 1,
            },
        )
        .unwrap();
        a.commit_local(create.clone()).unwrap();
        b.commit_remote(create.clone()).unwrap();

        let m1 = msg(&a_kp, room, vec![create.id], 2, b"from-a-1");
        a.commit_local(m1.clone()).unwrap();
        let m2 = msg(&a_kp, room, vec![m1.id], 3, b"from-a-2");
        a.commit_local(m2.clone()).unwrap();

        let mb = msg(&b_kp, room, vec![create.id], 4, b"from-b");
        b.commit_local(mb.clone()).unwrap();

        assert_ne!(a.tip_set(&room), b.tip_set(&room));
        DeviceNode::converge_with(&mut a, &mut b, room).unwrap();
        assert_eq!(a.event_count(), 4);
        assert_eq!(b.event_count(), 4);
        assert_eq!(a.room_event_ids(&room), b.room_event_ids(&room));
        let tips_a = a.tip_set(&room);
        assert!(tips_a.contains(&m2.id));
        assert!(tips_a.contains(&mb.id));
        assert_eq!(tips_a, b.tip_set(&room));
    }

    #[test]
    fn outbox_queues_local_and_relay_seal_hides_payload() {
        let kp = DeviceKeypair::generate();
        let mut node = DeviceNode::from_crypto_device(kp.device_id());
        let room = RoomId::from_bytes([1u8; 32]);
        let create = sign_event(
            kp.signing_key(),
            UnsignedEvent {
                room_id: room,
                parents: vec![],
                kind: EventKind::CreateRoom,
                payload: b"{}".to_vec(),
                author_device: kp.event_device_id(),
                ts_ms: 1,
            },
        )
        .unwrap();
        node.commit_local(create.clone()).unwrap();
        assert_eq!(node.outbox_len(), 1);
        let ev = node.pop_outbox().unwrap();
        let pad = 0x3C;
        let ct = DeviceNode::seal_for_relay(&ev, pad).unwrap();
        assert!(!ct.windows(2).any(|w| w == b"{}"));
        let opened = DeviceNode::open_from_relay(&ct, pad).unwrap();
        assert_eq!(opened.id, create.id);
    }

    #[test]
    fn inbox_holds_until_parent_arrives() {
        let kp = DeviceKeypair::generate();
        let mut node = DeviceNode::from_crypto_device(kp.device_id());
        let room = RoomId::from_bytes([2u8; 32]);
        let create = sign_event(
            kp.signing_key(),
            UnsignedEvent {
                room_id: room,
                parents: vec![],
                kind: EventKind::CreateRoom,
                payload: b"{}".to_vec(),
                author_device: kp.event_device_id(),
                ts_ms: 1,
            },
        )
        .unwrap();
        let child = msg(&kp, room, vec![create.id], 2, b"child");
        assert!(!node.commit_remote(child.clone()).unwrap());
        assert_eq!(node.inbox_len(), 1);
        assert_eq!(node.event_count(), 0);
        node.commit_remote(create).unwrap();
        assert_eq!(node.event_count(), 2);
        assert_eq!(node.inbox_len(), 0);
        assert!(node.has_event(&child.id));
    }

    #[test]
    fn happy_path_link_room_send_recv() {
        let out = happy_path_script().expect("happy path");
        assert!(out.starts_with("ok "), "{out}");
    }

    #[test]
    fn rpc_http_status_room_send_list() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let addr = serve("127.0.0.1:0").await.expect("bind rpc");
            let base = format!("http://{addr}");

            let client = reqwest::Client::new();
            let health: serde_json::Value = client
                .get(format!("{base}/health"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(health["ok"], true);

            let st: StatusResponse = client
                .get(format!("{base}/v1/status"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(st.device_id.len(), 64);

            let link: serde_json::Value = client
                .post(format!("{base}/v1/devices/link-secondary"))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(link["linked"], true);

            let room: CreateRoomResponse = client
                .post(format!("{base}/v1/rooms"))
                .json(&serde_json::json!({"name": "nest"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(room.room_id.len(), 64);

            let _peer: serde_json::Value = client
                .post(format!("{base}/v1/peers"))
                .json(&serde_json::json!({"name": "bob", "uri": "td://127.0.0.1:9"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();

            let sent: SendResponse = client
                .post(format!("{base}/v1/messages"))
                .json(&serde_json::json!({"room_id": room.room_id, "text": "honk"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(sent.event_id.len(), 64);

            let msgs: MessagesResponse = client
                .post(format!("{base}/v1/messages/list"))
                .json(&serde_json::json!({"room_id": room.room_id}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(msgs.messages.len(), 1);
            assert_eq!(msgs.messages[0].text, "honk");
            assert!(!st.claimed);

            let claim: serde_json::Value = client
                .post(format!("{base}/v1/claim"))
                .json(&serde_json::json!({"display_name": "Test Pond"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(claim["ok"], true);
            assert_eq!(claim["claimed"], true);
            assert!(claim["recovery_code"].as_str().unwrap().len() >= 8);
            let owner_token = claim["owner_token"].as_str().unwrap().to_string();
            assert!(owner_token.len() >= 32);

            let st2: StatusResponse = client
                .get(format!("{base}/v1/status"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert!(st2.claimed);
            assert_eq!(st2.display_name.as_deref(), Some("Test Pond"));

            // Pair mint requires owner session.
            let unauth = client
                .post(format!("{base}/v1/pair"))
                .json(&serde_json::json!({"label": "phone", "ttl_secs": 120}))
                .send()
                .await
                .unwrap();
            assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

            let pair: serde_json::Value = client
                .post(format!("{base}/v1/pair"))
                .header("Authorization", format!("Bearer {owner_token}"))
                .json(&serde_json::json!({"label": "phone", "ttl_secs": 120}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(pair["ok"], true);
            let token = pair["token"].as_str().unwrap().to_string();
            assert_eq!(token.len(), 32);

            let redeem: serde_json::Value = client
                .post(format!("{base}/v1/pair/redeem"))
                .json(&serde_json::json!({
                    "token": token,
                    "device_label": "Mike Phone"
                }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(redeem["paired"], true);
            assert_eq!(redeem["pond_name"], "Test Pond");
        });
    }

    #[test]
    fn claim_survives_restart_with_data_dir() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dir = std::env::temp_dir().join(format!(
                "td-claim-dur-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            let client = reqwest::Client::new();

            // Boot 1: claim
            let addr1 = serve_with_data_dir("127.0.0.1:0", &dir)
                .await
                .expect("bind 1");
            let base1 = format!("http://{addr1}");
            let claim: serde_json::Value = client
                .post(format!("{base1}/v1/claim"))
                .json(&serde_json::json!({"display_name": "Durable Pond"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(claim["ok"], true);
            let device_id = claim["device_id"].as_str().unwrap().to_string();
            let recovery = claim["recovery_code"].as_str().unwrap().to_string();
            assert!(recovery.len() >= 8);

            // Drop server by letting it go out of scope... we need a second process-like restart.
            // serve_with_data_dir spawns in background; start a second listener on new port
            // loading the same data dir (simulates restart; first may still run — claim is durable).
            let addr2 = serve_with_data_dir("127.0.0.1:0", &dir)
                .await
                .expect("bind 2");
            let base2 = format!("http://{addr2}");

            let st: StatusResponse = client
                .get(format!("{base2}/v1/status"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert!(st.claimed);
            assert_eq!(st.display_name.as_deref(), Some("Durable Pond"));
            assert_eq!(st.device_id, device_id);

            let cs: serde_json::Value = client
                .get(format!("{base2}/v1/claim"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(cs["claimed"], true);
            assert_eq!(cs["display_name"], "Durable Pond");
            assert_eq!(cs["device_id"], device_id);

            // Second claim must conflict
            let again = client
                .post(format!("{base2}/v1/claim"))
                .json(&serde_json::json!({"display_name": "Nope"}))
                .send()
                .await
                .unwrap();
            assert_eq!(again.status(), reqwest::StatusCode::CONFLICT);

            // Disk layout sanity
            assert!(dir.join("identity.key").is_file());
            assert!(dir.join("claim.json").is_file());
            let claim_raw = std::fs::read_to_string(dir.join("claim.json")).unwrap();
            assert!(claim_raw.contains("Durable Pond"));
            assert!(!claim_raw.contains(&recovery));
            assert!(!claim_raw.to_lowercase().contains("recovery_code"));

            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn recovery_login_mints_owner_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let dir = std::env::temp_dir().join(format!(
                "td-recovery-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let client = reqwest::Client::new();

            let addr = serve_with_data_dir("127.0.0.1:0", &dir)
                .await
                .expect("bind");
            let base = format!("http://{addr}");

            let claim: serde_json::Value = client
                .post(format!("{base}/v1/claim"))
                .json(&serde_json::json!({"display_name": "Recover Me"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let recovery = claim["recovery_code"].as_str().unwrap().to_string();
            let claim_owner = claim["owner_token"].as_str().unwrap().to_string();

            // Wrong code → 401
            let bad = client
                .post(format!("{base}/v1/recovery/login"))
                .json(&serde_json::json!({"recovery_code": "AAAA-BBBB-CCCC-DDDD"}))
                .send()
                .await
                .unwrap();
            assert_eq!(bad.status(), reqwest::StatusCode::UNAUTHORIZED);

            // Fresh process-like restart: new listener, same data dir (sessions wiped).
            let addr2 = serve_with_data_dir("127.0.0.1:0", &dir)
                .await
                .expect("bind2");
            let base2 = format!("http://{addr2}");

            // Old claim-minted token invalid on new process
            let stale = client
                .get(format!("{base2}/v1/owner/session"))
                .header("Authorization", format!("Bearer {claim_owner}"))
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap();
            assert_eq!(stale["authenticated"], false);

            let login: serde_json::Value = client
                .post(format!("{base2}/v1/recovery/login"))
                .json(&serde_json::json!({"recovery_code": recovery}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(login["ok"], true);
            let owner = login["owner_token"].as_str().unwrap().to_string();
            assert!(owner.len() >= 32);
            assert_eq!(login["display_name"], "Recover Me");

            let sess: serde_json::Value = client
                .get(format!("{base2}/v1/owner/session"))
                .header("Authorization", format!("Bearer {owner}"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(sess["authenticated"], true);
            assert_eq!(sess["source"], "recovery");

            let pair: serde_json::Value = client
                .post(format!("{base2}/v1/pair"))
                .header("x-td-owner-token", &owner)
                .json(&serde_json::json!({"label": "after-recovery"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(pair["ok"], true);

            let logout: serde_json::Value = client
                .delete(format!("{base2}/v1/owner/session"))
                .header("Authorization", format!("Bearer {owner}"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(logout["revoked"], true);

            let after = client
                .post(format!("{base2}/v1/pair"))
                .header("Authorization", format!("Bearer {owner}"))
                .json(&serde_json::json!({"label": "nope"}))
                .send()
                .await
                .unwrap();
            assert_eq!(after.status(), reqwest::StatusCode::UNAUTHORIZED);

            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn remote_advertise_and_owner_gate_on_non_loopback() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = reqwest::Client::new();

            // Loopback: advertise host rewrites rpc_base / p2p_uri; owner gate off.
            let opts = ServeOptions {
                advertise_host: Some("pond.tailnet".into()),
                p2p_bind: Some("127.0.0.1:0".into()),
                require_owner_non_loopback: true,
                ..Default::default()
            };
            let addr = serve_with_options("127.0.0.1:0", opts)
                .await
                .expect("bind loopback");
            let base = format!("http://{addr}");
            let st: serde_json::Value = client
                .get(format!("{base}/v1/status"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(st["require_owner"], false);
            assert_eq!(st["advertise_host"], "pond.tailnet");
            let rpc_base = st["rpc_base"].as_str().unwrap();
            assert!(rpc_base.starts_with("http://pond.tailnet:"), "{rpc_base}");
            let p2p = st["p2p_uri"].as_str().unwrap();
            assert!(p2p.starts_with("td://pond.tailnet:"), "{p2p}");

            // add_peer allowed without owner on loopback
            let peer_ok = client
                .post(format!("{base}/v1/peers"))
                .json(&serde_json::json!({"name": "bob", "uri": "td://127.0.0.1:9"}))
                .send()
                .await
                .unwrap();
            assert!(peer_ok.status().is_success());

            // Non-loopback bind: full owner gate on non-public routes.
            let opts2 = ServeOptions {
                advertise_host: Some("100.64.0.2".into()),
                p2p_bind: Some("127.0.0.1:0".into()),
                require_owner_non_loopback: true,
                rate_limit: true,
                ..Default::default()
            };
            let addr2 = serve_with_options("0.0.0.0:0", opts2)
                .await
                .expect("bind all");
            // Hit via loopback address of the ephemeral port.
            let base2 = format!("http://127.0.0.1:{}", addr2.port());
            let st2: serde_json::Value = client
                .get(format!("{base2}/v1/status"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(st2["require_owner"], true);
            assert_eq!(st2["rate_limit"], true);
            assert_eq!(st2["advertise_host"], "100.64.0.2");

            let denied = client
                .post(format!("{base2}/v1/peers"))
                .json(&serde_json::json!({"name": "eve", "uri": "td://1.2.3.4:9"}))
                .send()
                .await
                .unwrap();
            assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);

            // Chat paths also gated when require_owner is on.
            let chat_denied = client
                .post(format!("{base2}/v1/rooms"))
                .json(&serde_json::json!({"name": "nope"}))
                .send()
                .await
                .unwrap();
            assert_eq!(chat_denied.status(), reqwest::StatusCode::UNAUTHORIZED);

            // Claim mints owner token → admin + chat works.
            let claim: serde_json::Value = client
                .post(format!("{base2}/v1/claim"))
                .json(&serde_json::json!({"display_name": "Remote Pond"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let owner = claim["owner_token"].as_str().unwrap();
            let allowed = client
                .post(format!("{base2}/v1/peers"))
                .header("Authorization", format!("Bearer {owner}"))
                .json(&serde_json::json!({"name": "alice", "uri": "td://100.64.0.3:9"}))
                .send()
                .await
                .unwrap();
            assert!(allowed.status().is_success());

            let room: serde_json::Value = client
                .post(format!("{base2}/v1/rooms"))
                .header("Authorization", format!("Bearer {owner}"))
                .json(&serde_json::json!({"name": "pond"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert!(room["room_id"].as_str().unwrap().len() == 64);

            let remote: serde_json::Value = client
                .get(format!("{base2}/v1/remote"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(remote["require_owner"], true);
            assert_eq!(remote["advertise_host"], "100.64.0.2");
        });
    }

    #[test]
    fn rate_limit_blocks_tight_bucket() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = reqwest::Client::new();
            let opts = ServeOptions {
                rate_limit: true,
                ..Default::default()
            };
            let addr = serve_with_options("127.0.0.1:0", opts)
                .await
                .expect("bind");
            let base = format!("http://{addr}");

            // Claim once, then spam POST /v1/claim (tight 10/min bucket).
            // Already-claimed returns 409 until the middleware rate limit trips (avoids
            // conflating with recovery-login failure lockout).
            let claim: serde_json::Value = client
                .post(format!("{base}/v1/claim"))
                .json(&serde_json::json!({"display_name": "Rate Pond"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(claim["ok"], true);

            let mut saw_429 = false;
            for _ in 0..20 {
                let r = client
                    .post(format!("{base}/v1/claim"))
                    .json(&serde_json::json!({"display_name": "Rate Pond"}))
                    .send()
                    .await
                    .unwrap();
                if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    saw_429 = true;
                    assert!(
                        r.headers().get("retry-after").is_some(),
                        "rate-limit 429 should include Retry-After"
                    );
                    break;
                }
                // 409 conflict while still under the window is expected
                assert!(
                    r.status() == reqwest::StatusCode::CONFLICT
                        || r.status().is_success(),
                    "unexpected status {}",
                    r.status()
                );
            }
            assert!(saw_429, "expected 429 after exceeding claim rate limit");

            // Disable rate limit → no 429 on status spam (sanity for flag).
            let opts2 = ServeOptions {
                rate_limit: false,
                ..Default::default()
            };
            let addr2 = serve_with_options("127.0.0.1:0", opts2)
                .await
                .expect("bind2");
            let base2 = format!("http://{addr2}");
            let st: serde_json::Value = client
                .get(format!("{base2}/v1/status"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(st["rate_limit"], false);
            for _ in 0..30 {
                let r = client
                    .get(format!("{base2}/v1/status"))
                    .send()
                    .await
                    .unwrap();
                assert!(r.status().is_success());
            }
        });
    }
}
