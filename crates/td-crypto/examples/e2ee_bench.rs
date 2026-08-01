//! E2EE group message path bench (Megolm encrypt + multi-device decrypt).
//!
//! ```bash
//! cargo run -p td-crypto --example e2ee_bench --release
//! ```

use std::time::Instant;
use td_crypto::{fanout_megolm_key, DeviceKeypair, E2eeDevice};

fn main() {
    let n: u64 = std::env::var("TD_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000);

    let a = DeviceKeypair::generate();
    let b = DeviceKeypair::generate();
    let c = DeviceKeypair::generate();
    let mut alice = E2eeDevice::new(a.device_id());
    let mut bob = E2eeDevice::new(b.device_id());
    let mut carol = E2eeDevice::new(c.device_id());
    let bob_keys = bob.publish_keys().unwrap();
    let carol_keys = carol.publish_keys().unwrap();
    alice.establish_olm_outbound(&bob_keys).unwrap();
    alice.establish_olm_outbound(&carol_keys).unwrap();
    let room = "bench-room";
    let _ = alice.create_group_session(room);
    let recipients = [alice.device_id, bob.device_id, carol.device_id];
    let fanout = fanout_megolm_key(&mut alice, room, &recipients).unwrap();
    for ct in &fanout {
        if ct.recipient_device == bob.device_id {
            let key = bob.olm_decrypt(&alice.curve25519_b64(), ct).unwrap();
            bob.import_group_session_key(std::str::from_utf8(&key).unwrap())
                .unwrap();
        } else if ct.recipient_device == carol.device_id {
            let key = carol.olm_decrypt(&alice.curve25519_b64(), ct).unwrap();
            carol
                .import_group_session_key(std::str::from_utf8(&key).unwrap())
                .unwrap();
        }
    }

    let payload = br#"{"text":"bench-honk"}"#;
    let t0 = Instant::now();
    for i in 0..n {
        let mut msg_payload = payload.to_vec();
        msg_payload.extend_from_slice(&i.to_le_bytes());
        let ct = alice.megolm_encrypt(room, &msg_payload).unwrap();
        let _ = bob.megolm_decrypt(&ct).unwrap();
        let _ = carol.megolm_decrypt(&ct).unwrap();
    }
    let dt = t0.elapsed();
    let mps = (n as f64) / dt.as_secs_f64().max(1e-9);
    println!(
        "td-crypto e2ee_group_bench n={n} group_msg_per_s={mps:.1} elapsed_ms={:.3} (encrypt+2x decrypt)",
        dt.as_secs_f64() * 1000.0
    );
}
