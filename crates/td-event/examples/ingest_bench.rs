//! Signed-event ingest throughput (honest numbers for docs/bench.md).
//!
//! ```bash
//! cargo run -p td-event --example ingest_bench --release
//! TD_BENCH_N=20000 cargo run -p td-event --example ingest_bench --release
//! ```

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Instant;
use td_event::{sign_event, DeviceId, EventKind, RoomDag, RoomId, UnsignedEvent};

fn main() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let author = DeviceId::from_verifying_key(&vk);
    let room = RoomId::from_bytes([9u8; 32]);
    let n: u64 = std::env::var("TD_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000);

    let mut events = Vec::with_capacity(n as usize);
    let mut parents = vec![];
    let t_sign0 = Instant::now();
    for i in 0..n {
        let ev = sign_event(
            &sk,
            UnsignedEvent {
                room_id: room,
                parents: parents.clone(),
                kind: if i == 0 {
                    EventKind::CreateRoom
                } else {
                    EventKind::Message
                },
                payload: format!(r#"{{"i":{i}}}"#).into_bytes(),
                author_device: author,
                ts_ms: i + 1,
            },
        )
        .expect("sign");
        parents = vec![ev.id];
        events.push(ev);
    }
    let sign_dt = t_sign0.elapsed();

    let mut dag = RoomDag::new(room);
    let t0 = Instant::now();
    for ev in events {
        dag.ingest(ev).expect("ingest");
    }
    let dt = t0.elapsed();
    let eps = (n as f64) / dt.as_secs_f64().max(1e-9);
    let sign_eps = (n as f64) / sign_dt.as_secs_f64().max(1e-9);
    println!(
        "td-event ingest_bench n={n} sign_eps={sign_eps:.1} ingest_eps={eps:.1} ingest_ms={:.3}",
        dt.as_secs_f64() * 1000.0
    );
}
