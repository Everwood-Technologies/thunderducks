//! Node runtime: multi-device sync + local HTTP RPC (Waves D2 + E).

mod rpc;
mod sync;

pub use rpc::{
    happy_path_script, new_state, router, serve, serve_blocking, CreateRoomRequest,
    CreateRoomResponse, MessageView, MessagesResponse, RpcState, SendRequest, SendResponse,
    StatusResponse,
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

            let pair: serde_json::Value = client
                .post(format!("{base}/v1/pair"))
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
}
