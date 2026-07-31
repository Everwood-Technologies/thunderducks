//! Signed events, per-room causal DAG, and SQLite-backed store.
//!
//! Events are content-addressed by blake3 of the canonical signed payload.
//! Duplicate ingest is idempotent. No global consensus / blockchain.

mod dag;
mod event;
mod room;
mod store;

pub use dag::{DagError, RoomDag};
pub use event::{
    canonical_bytes, event_id_from_bytes, sign_event, verify_event, DeviceId, EventId, EventKind,
    RoomId, SignedEvent, UnsignedEvent,
};
pub use room::{
    room_id_from_parts, CreateRoomPayload, MemberState, MembershipAction, MembershipPayload,
    RoomError, RoomRegistry, RoomState,
};
pub use store::{EventStore, MemoryStore, SqliteStore, StoreError};

/// Crate smoke marker used by CI.
pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn smoke_name() {
        assert_eq!(crate_name(), "td-event");
    }

    #[test]
    fn sign_verify_and_content_address() {
        let sk = keypair();
        let vk = sk.verifying_key();
        let unsigned = UnsignedEvent {
            room_id: RoomId::from_bytes([1u8; 32]),
            parents: vec![],
            kind: EventKind::Message,
            payload: br#"{"text":"honk"}"#.to_vec(),
            author_device: DeviceId::from_verifying_key(&vk),
            ts_ms: 1,
        };
        let signed = sign_event(&sk, unsigned).expect("sign");
        verify_event(&signed).expect("verify");
        let id2 = event_id_from_bytes(&canonical_bytes(&signed));
        assert_eq!(signed.id, id2);
    }

    #[test]
    fn reject_bad_signature() {
        let sk = keypair();
        let vk = sk.verifying_key();
        let unsigned = UnsignedEvent {
            room_id: RoomId::from_bytes([2u8; 32]),
            parents: vec![],
            kind: EventKind::Message,
            payload: b"x".to_vec(),
            author_device: DeviceId::from_verifying_key(&vk),
            ts_ms: 1,
        };
        let mut signed = sign_event(&sk, unsigned).unwrap();
        signed.signature[0] ^= 0xff;
        assert!(verify_event(&signed).is_err());
    }

    #[test]
    fn dag_insert_and_dup_drop() {
        let sk = keypair();
        let vk = sk.verifying_key();
        let room = RoomId::from_bytes([3u8; 32]);
        let mut dag = RoomDag::new(room);
        let e1 = sign_event(
            &sk,
            UnsignedEvent {
                room_id: room,
                parents: vec![],
                kind: EventKind::CreateRoom,
                payload: b"{}".to_vec(),
                author_device: DeviceId::from_verifying_key(&vk),
                ts_ms: 1,
            },
        )
        .unwrap();
        assert!(dag.ingest(e1.clone()).unwrap());
        assert!(!dag.ingest(e1.clone()).unwrap(), "dup must be false");
        let e2 = sign_event(
            &sk,
            UnsignedEvent {
                room_id: room,
                parents: vec![e1.id],
                kind: EventKind::Message,
                payload: b"hi".to_vec(),
                author_device: DeviceId::from_verifying_key(&vk),
                ts_ms: 2,
            },
        )
        .unwrap();
        assert!(dag.ingest(e2).unwrap());
        assert_eq!(dag.len(), 2);
    }

    #[test]
    fn sqlite_crash_safe_reopen() {
        let dir = std::env::temp_dir().join(format!("td-event-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.sqlite");

        let sk = keypair();
        let vk = sk.verifying_key();
        let room = RoomId::from_bytes([4u8; 32]);
        let e = sign_event(
            &sk,
            UnsignedEvent {
                room_id: room,
                parents: vec![],
                kind: EventKind::Message,
                payload: b"persist".to_vec(),
                author_device: DeviceId::from_verifying_key(&vk),
                ts_ms: 9,
            },
        )
        .unwrap();
        let id = e.id;

        {
            let mut store = SqliteStore::open(&path).unwrap();
            assert!(store.put(e.clone()).unwrap());
            assert!(!store.put(e).unwrap(), "duplicate put is idempotent");
        }

        let store2 = SqliteStore::open(&path).unwrap();
        let loaded = store2.get(&id).unwrap().expect("survives reopen");
        verify_event(&loaded).unwrap();
        assert_eq!(loaded.payload, b"persist");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn room_create_invite_join_and_reject_non_member() {
        let creator_sk = keypair();
        let creator = DeviceId::from_verifying_key(&creator_sk.verifying_key());
        let peer_sk = keypair();
        let peer = DeviceId::from_verifying_key(&peer_sk.verifying_key());
        let stranger_sk = keypair();
        let stranger = DeviceId::from_verifying_key(&stranger_sk.verifying_key());

        let mut reg = RoomRegistry::new();
        let (room_id, _) = reg.create_room(&creator_sk, creator, "pond", 1).unwrap();
        assert!(reg.get(&room_id).unwrap().is_joined(&creator));

        reg.membership_event(
            &creator_sk,
            room_id,
            creator,
            peer,
            MembershipAction::Invite,
            2,
        )
        .unwrap();
        assert_eq!(
            reg.get(&room_id).unwrap().member_state(&peer),
            Some(&MemberState::Invited)
        );

        reg.membership_event(&peer_sk, room_id, peer, peer, MembershipAction::Join, 3)
            .unwrap();
        assert!(reg.get(&room_id).unwrap().is_joined(&peer));

        // stranger cannot message
        assert!(reg.assert_can_message(&room_id, &stranger).is_err());

        // banned cannot rejoin
        reg.membership_event(
            &creator_sk,
            room_id,
            creator,
            peer,
            MembershipAction::Ban,
            4,
        )
        .unwrap();
        let join_again =
            reg.membership_event(&peer_sk, room_id, peer, peer, MembershipAction::Join, 5);
        assert!(join_again.is_err());
    }

    #[test]
    fn room_rejects_evil_membership_from_outsider() {
        let creator_sk = keypair();
        let creator = DeviceId::from_verifying_key(&creator_sk.verifying_key());
        let evil_sk = keypair();
        let evil = DeviceId::from_verifying_key(&evil_sk.verifying_key());

        let mut reg = RoomRegistry::new();
        let (room_id, _) = reg.create_room(&creator_sk, creator, "nest", 10).unwrap();

        let bad = reg.membership_event(&evil_sk, room_id, evil, evil, MembershipAction::Invite, 11);
        assert!(bad.is_err());
    }
}
