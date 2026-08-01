//! Node runtime: multi-device sync, outbox/inbox, DAG convergence (Wave D2).

mod sync;

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

        // shared create on both (bootstrap as if already linked/same user room)
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

        // partition: A authors two messages offline from B
        let m1 = msg(&a_kp, room, vec![create.id], 2, b"from-a-1");
        a.commit_local(m1.clone()).unwrap();
        let m2 = msg(&a_kp, room, vec![m1.id], 3, b"from-a-2");
        a.commit_local(m2.clone()).unwrap();

        // B authors one message offline from A
        let mb = msg(&b_kp, room, vec![create.id], 4, b"from-b");
        b.commit_local(mb.clone()).unwrap();

        assert_ne!(a.tip_set(&room), b.tip_set(&room));
        assert_eq!(a.event_count(), 3);
        assert_eq!(b.event_count(), 2);

        // reconnect + sync
        DeviceNode::converge_with(&mut a, &mut b, room).unwrap();

        assert_eq!(a.event_count(), 4);
        assert_eq!(b.event_count(), 4);
        assert_eq!(a.room_event_ids(&room), b.room_event_ids(&room));
        // both tips should include m2 and mb (fork)
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
        // child first
        assert!(!node.commit_remote(child.clone()).unwrap());
        assert_eq!(node.inbox_len(), 1);
        assert_eq!(node.event_count(), 0);
        node.commit_remote(create).unwrap();
        assert_eq!(node.event_count(), 2);
        assert_eq!(node.inbox_len(), 0);
        assert!(node.has_event(&child.id));
    }
}
