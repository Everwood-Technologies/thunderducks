//! P1.2 operator demo: two distinct users (Alice + Bob) exchange signed events
//! over real localhost TCP P2P frames (no shared process memory, no relay).
//!
//! ```bash
//! cargo run -p td-node --example two_user_p2p
//! ```

use std::time::Duration;
use td_crypto::DeviceKeypair;
use td_event::{sign_event, verify_event, EventKind, RoomId, UnsignedEvent};
use td_net::{accept_once, dial, read_event, write_event, PeerUri};
use td_node::DeviceNode;
use tokio::net::TcpListener;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice_kp = DeviceKeypair::generate();
    let bob_kp = DeviceKeypair::generate();
    let mut alice = DeviceNode::from_crypto_device(alice_kp.device_id());
    let mut bob = DeviceNode::from_crypto_device(bob_kp.device_id());

    assert_ne!(
        alice_kp.device_id().0,
        bob_kp.device_id().0,
        "two distinct user devices"
    );

    let room = RoomId::from_bytes([0xA1; 32]);

    // Alice creates the room and a 1:1 message.
    let create = sign_event(
        alice_kp.signing_key(),
        UnsignedEvent {
            room_id: room,
            parents: vec![],
            kind: EventKind::CreateRoom,
            payload: br#"{"name":"p2p-pond","users":["alice","bob"]}"#.to_vec(),
            author_device: alice_kp.event_device_id(),
            ts_ms: 1,
        },
    )?;
    alice.commit_local(create.clone())?;

    let msg = sign_event(
        alice_kp.signing_key(),
        UnsignedEvent {
            room_id: room,
            parents: vec![create.id],
            kind: EventKind::Message,
            payload: br#"{"text":"hello-bob-via-p2p"}"#.to_vec(),
            author_device: alice_kp.event_device_id(),
            ts_ms: 2,
        },
    )?;
    alice.commit_local(msg.clone())?;

    // Bob listens; Alice dials and ships create + message as framed events.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let bob_uri = PeerUri::from_tcp_addr(addr);
    println!("bob listening on {}", bob_uri.to_string_uri());

    let bob_task = tokio::spawn(async move {
        let mut sock = accept_once(&listener).await.expect("accept");
        let mut received = Vec::new();
        // expect 2 events
        for _ in 0..2 {
            let ev = read_event(&mut sock).await.expect("read");
            verify_event(&ev).expect("verify");
            received.push(ev);
        }
        // ack last id back so alice knows delivery completed
        write_event(&mut sock, received.last().expect("one"))
            .await
            .expect("ack");
        received
    });

    // small yield so accept is armed
    tokio::task::yield_now().await;

    let mut alice_sock = timeout(Duration::from_secs(2), dial(&bob_uri)).await??;
    // drain outbox in parent-before-child order via list_events
    for ev in alice.list_events(&room) {
        write_event(&mut alice_sock, &ev).await?;
        println!(
            "alice -> bob event kind={:?} id={}",
            ev.kind,
            hex::encode(ev.id.0)
        );
    }
    let ack = timeout(Duration::from_secs(2), read_event(&mut alice_sock)).await??;
    assert_eq!(ack.id, msg.id, "bob ack must be the message tip");

    let received = timeout(Duration::from_secs(2), bob_task).await??;
    assert_eq!(received.len(), 2);
    for ev in received {
        bob.commit_remote(ev)?;
    }

    // Bob replies over a reverse P2P connection (alice listens this time).
    let reply = sign_event(
        bob_kp.signing_key(),
        UnsignedEvent {
            room_id: room,
            parents: vec![msg.id],
            kind: EventKind::Message,
            payload: br#"{"text":"hello-alice-via-p2p"}"#.to_vec(),
            author_device: bob_kp.event_device_id(),
            ts_ms: 3,
        },
    )?;
    bob.commit_local(reply.clone())?;

    let listener2 = TcpListener::bind("127.0.0.1:0").await?;
    let addr2 = listener2.local_addr()?;
    let alice_uri = PeerUri::from_tcp_addr(addr2);
    println!("alice listening on {}", alice_uri.to_string_uri());

    let alice_recv = tokio::spawn(async move {
        let mut sock = accept_once(&listener2).await.expect("accept2");
        let ev = read_event(&mut sock).await.expect("read reply");
        verify_event(&ev).expect("verify reply");
        write_event(&mut sock, &ev).await.expect("ack reply");
        ev
    });
    tokio::task::yield_now().await;

    let mut bob_sock = timeout(Duration::from_secs(2), dial(&alice_uri)).await??;
    write_event(&mut bob_sock, &reply).await?;
    let _ = timeout(Duration::from_secs(2), read_event(&mut bob_sock)).await??;
    let got = timeout(Duration::from_secs(2), alice_recv).await??;
    alice.commit_remote(got)?;

    // Both users must share the same room event set (2-user P2P path).
    assert_eq!(alice.room_event_ids(&room), bob.room_event_ids(&room));
    assert_eq!(alice.event_count(), 3);
    assert_eq!(bob.event_count(), 3);
    assert_eq!(alice.tip_set(&room), bob.tip_set(&room));
    assert!(alice.tip_set(&room).contains(&reply.id));

    let texts: Vec<String> = alice
        .list_messages(&room)
        .into_iter()
        .map(|e| String::from_utf8_lossy(&e.payload).into_owned())
        .collect();
    assert!(texts.iter().any(|t| t.contains("hello-bob-via-p2p")));
    assert!(texts.iter().any(|t| t.contains("hello-alice-via-p2p")));

    println!("ok two_user_p2p events=3 room={}", hex::encode(room.0));
    println!("alice_device={}", hex::encode(alice.device_id.0));
    println!("bob_device={}", hex::encode(bob.device_id.0));
    Ok(())
}
