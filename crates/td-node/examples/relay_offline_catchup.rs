//! P1.3 operator demo: Bob offline → Alice deposits opaque ciphertext on relay →
//! Bob fetches/decrypts/acks → later direct P2P works without relay.
//!
//! Spawns `td-relay` as a child process (real binary), not an in-process mock.
//!
//! ```bash
//! cargo build -p td-relay
//! cargo run -p td-node --example relay_offline_catchup
//! ```

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use td_crypto::DeviceKeypair;
use td_event::{sign_event, verify_event, EventKind, RoomId, UnsignedEvent};
use td_net::{accept_once, dial, read_event, write_event, PeerUri, RelayClient, RelayEnvelope};
use td_node::DeviceNode;
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};

struct RelayProc {
    child: Child,
    uri: PeerUri,
    db: PathBuf,
}

impl Drop for RelayProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.db);
    }
}

fn resolve_td_relay_bin() -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(explicit) = std::env::var("TD_RELAY_BIN") {
        return Ok(explicit);
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    // CARGO_MANIFEST_DIR = .../crates/td-node → repo root target/
    let mut from_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    from_manifest.pop(); // crates
    from_manifest.pop(); // repo root
    from_manifest.push("target");
    from_manifest.push("debug");
    from_manifest.push("td-relay");
    candidates.push(from_manifest);

    // cwd-relative (CI often runs from repo root)
    candidates.push(PathBuf::from("target/debug/td-relay"));
    candidates.push(PathBuf::from("./target/debug/td-relay"));

    // current_exe dir siblings (when invoked as target/debug/examples/relay_offline_catchup)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // .../target/debug/examples → .../target/debug/td-relay
            let mut p = exe_dir.to_path_buf();
            if p.file_name().and_then(|s| s.to_str()) == Some("examples") {
                p.pop();
            }
            p.push("td-relay");
            candidates.push(p);
            // also one more up just in case
            let mut p2 = exe_dir.to_path_buf();
            p2.pop();
            p2.push("td-relay");
            candidates.push(p2);
        }
    }

    for c in &candidates {
        if c.is_file() {
            return Ok(c.to_string_lossy().into_owned());
        }
    }

    Err(format!(
        "td-relay binary not found; tried: {:?} — run: cargo build -p td-relay --bins",
        candidates,
    )
    .into())
}

fn spawn_relay_binary() -> Result<RelayProc, Box<dyn std::error::Error>> {
    // Pick a free port.
    let port = {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std_listener.local_addr()?.port()
    };
    let bind = format!("127.0.0.1:{port}");
    let db = std::env::temp_dir().join(format!("td-p13-relay-{port}.sqlite"));
    let _ = std::fs::remove_file(&db);

    let bin = resolve_td_relay_bin()?;
    if !PathBuf::from(&bin).exists() {
        return Err(format!(
            "td-relay binary missing at {bin}; run: cargo build -p td-relay --bins"
        )
        .into());
    }

    let child = Command::new(&bin)
        .args(["--bind", &bind, "--db", db.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let uri = PeerUri {
        host: "127.0.0.1".into(),
        port,
        noise: false,
        quic: false,
    };
    Ok(RelayProc { child, uri, db })
}

async fn wait_relay(uri: &PeerUri) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..50 {
        if RelayClient::connect(uri).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
    Err("relay did not become ready".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relay = spawn_relay_binary()?;
    wait_relay(&relay.uri).await?;
    println!("relay up {}", relay.uri.to_string_uri());

    let alice_kp = DeviceKeypair::generate();
    let bob_kp = DeviceKeypair::generate();
    let mut alice = DeviceNode::from_crypto_device(alice_kp.device_id());
    let mut bob = DeviceNode::from_crypto_device(bob_kp.device_id());
    let mut alice_e2ee = td_crypto::E2eeDevice::new(alice_kp.device_id());
    let mut bob_e2ee = td_crypto::E2eeDevice::new(bob_kp.device_id());
    let bob_keys = bob_e2ee.publish_keys()?;
    alice_e2ee.establish_olm_outbound(&bob_keys)?;
    let room = RoomId::from_bytes([0xB0; 32]);
    let secret = b"OFFLINE_CATCHUP_SECRET_HONK";

    let create = sign_event(
        alice_kp.signing_key(),
        UnsignedEvent {
            room_id: room,
            parents: vec![],
            kind: EventKind::CreateRoom,
            payload: br#"{"name":"relay-pond"}"#.to_vec(),
            author_device: alice_kp.event_device_id(),
            ts_ms: 1,
        },
    )?;
    alice.commit_local(create.clone())?;
    // Bob already knows create (invite path); only message is offline.
    bob.commit_remote(create.clone())?;

    let offline_msg = sign_event(
        alice_kp.signing_key(),
        UnsignedEvent {
            room_id: room,
            parents: vec![create.id],
            kind: EventKind::Message,
            payload: secret.to_vec(),
            author_device: alice_kp.event_device_id(),
            ts_ms: 2,
        },
    )?;
    alice.commit_local(offline_msg.clone())?;

    // Alice cannot reach Bob (Bob offline) → per-recipient Olm seal + put on relay.
    let ciphertext =
        DeviceNode::seal_for_relay_olm(&mut alice_e2ee, bob_kp.device_id(), &offline_msg)?;
    assert_eq!(ciphertext[0], td_crypto::RELAY_SEAL_V2_OLM);
    assert!(
        !ciphertext.windows(secret.len()).any(|w| w == secret),
        "ciphertext must hide plaintext marker"
    );
    let env = RelayEnvelope::new(bob.device_id, alice.device_id, Some(room), ciphertext, 2);

    {
        let mut c = RelayClient::connect(&relay.uri).await?;
        c.put(env.clone()).await?;
        println!("alice put envelope {}", hex::encode(env.envelope_id));
    }

    // Bob still offline: must not have the message yet.
    assert!(!bob.has_event(&offline_msg.id));
    assert_ne!(alice.tip_set(&room), bob.tip_set(&room));

    // Bob comes online → fetch → open → commit → ack.
    {
        let mut c = RelayClient::connect(&relay.uri).await?;
        let items = c.fetch(bob.device_id, 0, 10).await?;
        assert_eq!(items.len(), 1, "bob should see one pending envelope");
        let opened = DeviceNode::open_from_relay_auto(&mut bob_e2ee, None, &items[0].ciphertext)?;
        verify_event(&opened)?;
        assert_eq!(opened.id, offline_msg.id);
        assert_eq!(opened.payload, secret);
        bob.commit_remote(opened)?;
        c.ack(bob.device_id, vec![items[0].envelope_id]).await?;
        let after = c.fetch(bob.device_id, 0, 10).await?;
        assert!(after.is_empty(), "ack should clear relay queue");
        println!("bob fetched+acked offline message");
    }

    assert_eq!(alice.tip_set(&room), bob.tip_set(&room));
    assert_eq!(alice.room_event_ids(&room), bob.room_event_ids(&room));

    // Phase 2: both online — direct P2P without relay for a new message.
    let live = sign_event(
        bob_kp.signing_key(),
        UnsignedEvent {
            room_id: room,
            parents: vec![offline_msg.id],
            kind: EventKind::Message,
            payload: br#"{"text":"now-direct-p2p"}"#.to_vec(),
            author_device: bob_kp.event_device_id(),
            ts_ms: 3,
        },
    )?;
    bob.commit_local(live.clone())?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let alice_uri = PeerUri::from_tcp_addr(listener.local_addr()?);
    let alice_task = tokio::spawn(async move {
        let mut sock = accept_once(&listener).await.expect("accept");
        let ev = read_event(&mut sock).await.expect("read");
        verify_event(&ev).expect("verify");
        write_event(&mut sock, &ev).await.expect("ack");
        ev
    });
    tokio::task::yield_now().await;
    let mut bob_sock = timeout(Duration::from_secs(2), dial(&alice_uri)).await??;
    write_event(&mut bob_sock, &live).await?;
    let _ = timeout(Duration::from_secs(2), read_event(&mut bob_sock)).await??;
    let got = timeout(Duration::from_secs(2), alice_task).await??;
    alice.commit_remote(got)?;

    assert_eq!(alice.tip_set(&room), bob.tip_set(&room));
    assert!(alice.tip_set(&room).contains(&live.id));
    assert_eq!(alice.event_count(), 3);
    assert_eq!(bob.event_count(), 3);

    // Relay queue still empty after direct path (no new puts).
    {
        let mut c = RelayClient::connect(&relay.uri).await?;
        let leftover = c.fetch(alice.device_id, 0, 10).await?;
        assert!(leftover.is_empty());
        let leftover_b = c.fetch(bob.device_id, 0, 10).await?;
        assert!(leftover_b.is_empty());
    }

    // Best-effort: relay DB file should not contain plaintext secret.
    if relay.db.exists() {
        let bytes = std::fs::read(&relay.db)?;
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret),
            "relay sqlite must not store plaintext marker"
        );
        println!("relay db plaintext-free ok");
    }

    println!(
        "ok relay_offline_catchup room={} relay={}",
        hex::encode(room.0),
        relay.uri.to_string_uri()
    );
    Ok(())
}
