//! Optional untrusted store-and-forward assist relay.
//!
//! Stores **opaque ciphertext envelopes only**. No plaintext event API.
//! Rate-limits puts per sender device.

use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use td_event::DeviceId;
use td_net::{read_json, write_json, PeerUri, RelayEnvelope, RelayRequest, RelayResponse};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Error)]
enum RelayError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("rate limited")]
    RateLimited,
    #[error("envelope too large")]
    TooLarge,
    #[error("bad request: {0}")]
    BadRequest(String),
}

const MAX_CIPHERTEXT: usize = 256 * 1024;
const DEFAULT_RATE: u32 = 32;
const RATE_WINDOW: Duration = Duration::from_secs(1);
const DEFAULT_FETCH_LIMIT: u32 = 64;

struct RateLimiter {
    window_start: Instant,
    counts: HashMap<[u8; 32], u32>,
    max_per_window: u32,
}

impl RateLimiter {
    fn new(max_per_window: u32) -> Self {
        Self {
            window_start: Instant::now(),
            counts: HashMap::new(),
            max_per_window,
        }
    }

    fn allow(&mut self, sender: &DeviceId) -> bool {
        if self.window_start.elapsed() >= RATE_WINDOW {
            self.window_start = Instant::now();
            self.counts.clear();
        }
        let c = self.counts.entry(sender.0).or_insert(0);
        if *c >= self.max_per_window {
            return false;
        }
        *c += 1;
        true
    }
}

struct EnvelopeStore {
    conn: Mutex<Connection>,
}

impl EnvelopeStore {
    fn open(path: impl AsRef<Path>) -> Result<Self, RelayError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS envelopes (
              envelope_id BLOB PRIMARY KEY NOT NULL,
              recipient BLOB NOT NULL,
              sender BLOB NOT NULL,
              room_id BLOB,
              ciphertext BLOB NOT NULL,
              ts_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_env_recip_ts
              ON envelopes(recipient, ts_ms);
            "#,
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self, RelayError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS envelopes (
              envelope_id BLOB PRIMARY KEY NOT NULL,
              recipient BLOB NOT NULL,
              sender BLOB NOT NULL,
              room_id BLOB,
              ciphertext BLOB NOT NULL,
              ts_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_env_recip_ts
              ON envelopes(recipient, ts_ms);
            "#,
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn put(&self, env: &RelayEnvelope) -> Result<bool, RelayError> {
        if env.ciphertext.len() > MAX_CIPHERTEXT {
            return Err(RelayError::TooLarge);
        }
        // Integrity: reject tampered envelope_id
        let expected = RelayEnvelope::new(
            env.recipient_device,
            env.sender_device,
            env.room_id,
            env.ciphertext.clone(),
            env.ts_ms,
        );
        if expected.envelope_id != env.envelope_id {
            return Err(RelayError::BadRequest("envelope_id mismatch".into()));
        }
        let conn = self.conn.lock().expect("store lock");
        let room = env.room_id.map(|r| r.0.to_vec());
        let changed = conn.execute(
            r#"INSERT OR IGNORE INTO envelopes
               (envelope_id, recipient, sender, room_id, ciphertext, ts_ms)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![
                env.envelope_id.as_slice(),
                env.recipient_device.0.as_slice(),
                env.sender_device.0.as_slice(),
                room,
                env.ciphertext.as_slice(),
                env.ts_ms as i64
            ],
        )?;
        Ok(changed == 1)
    }

    fn fetch(
        &self,
        recipient: &DeviceId,
        since_ts: u64,
        limit: u32,
    ) -> Result<Vec<RelayEnvelope>, RelayError> {
        let limit = limit.clamp(1, DEFAULT_FETCH_LIMIT) as i64;
        let conn = self.conn.lock().expect("store lock");
        let mut stmt = conn.prepare(
            r#"SELECT envelope_id, recipient, sender, room_id, ciphertext, ts_ms
               FROM envelopes
               WHERE recipient = ?1 AND ts_ms >= ?2
               ORDER BY ts_ms ASC
               LIMIT ?3"#,
        )?;
        let rows = stmt.query_map(
            params![recipient.0.as_slice(), since_ts as i64, limit],
            |row| {
                let eid: Vec<u8> = row.get(0)?;
                let recip: Vec<u8> = row.get(1)?;
                let sender: Vec<u8> = row.get(2)?;
                let room: Option<Vec<u8>> = row.get(3)?;
                let ct: Vec<u8> = row.get(4)?;
                let ts: i64 = row.get(5)?;
                Ok((eid, recip, sender, room, ct, ts))
            },
        )?;
        let mut out = Vec::new();
        for r in rows {
            let (eid, recip, sender, room, ct, ts) = r?;
            let mut envelope_id = [0u8; 32];
            let mut recipient_b = [0u8; 32];
            let mut sender_b = [0u8; 32];
            if eid.len() != 32 || recip.len() != 32 || sender.len() != 32 {
                continue;
            }
            envelope_id.copy_from_slice(&eid);
            recipient_b.copy_from_slice(&recip);
            sender_b.copy_from_slice(&sender);
            let room_id = room.and_then(|b| {
                if b.len() == 32 {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    Some(td_event::RoomId(a))
                } else {
                    None
                }
            });
            out.push(RelayEnvelope {
                envelope_id,
                recipient_device: DeviceId(recipient_b),
                sender_device: DeviceId(sender_b),
                room_id,
                ciphertext: ct,
                ts_ms: ts as u64,
            });
        }
        Ok(out)
    }

    fn ack(&self, recipient: &DeviceId, ids: &[[u8; 32]]) -> Result<usize, RelayError> {
        let conn = self.conn.lock().expect("store lock");
        let mut n = 0usize;
        for id in ids {
            let changed = conn.execute(
                "DELETE FROM envelopes WHERE envelope_id = ?1 AND recipient = ?2",
                params![id.as_slice(), recipient.0.as_slice()],
            )?;
            n += changed;
        }
        Ok(n)
    }

    /// Debug/test helper: does any stored ciphertext equal needle? (must be false for plaintext)
    #[cfg(test)]
    fn ciphertext_contains_bytes(&self, needle: &[u8]) -> Result<bool, RelayError> {
        let conn = self.conn.lock().expect("store lock");
        let mut stmt = conn.prepare("SELECT ciphertext FROM envelopes")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for r in rows {
            let ct = r?;
            if ct.windows(needle.len()).any(|w| w == needle) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(test)]
    fn count(&self) -> Result<usize, RelayError> {
        let conn = self.conn.lock().expect("store lock");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))?;
        Ok(n as usize)
    }
}

struct RelayState {
    store: EnvelopeStore,
    limiter: Mutex<RateLimiter>,
}

impl RelayState {
    fn handle(&self, req: RelayRequest) -> Result<RelayResponse, RelayError> {
        match req {
            RelayRequest::Put { envelope } => {
                if !self
                    .limiter
                    .lock()
                    .expect("limiter")
                    .allow(&envelope.sender_device)
                {
                    return Err(RelayError::RateLimited);
                }
                self.store.put(&envelope)?;
                Ok(RelayResponse::Ok)
            }
            RelayRequest::Fetch {
                recipient,
                since_ts,
                limit,
            } => {
                let items = self.store.fetch(&recipient, since_ts, limit)?;
                Ok(RelayResponse::Envelopes { items })
            }
            RelayRequest::Ack {
                recipient,
                envelope_ids,
            } => {
                self.store.ack(&recipient, &envelope_ids)?;
                Ok(RelayResponse::Ok)
            }
        }
    }
}

async fn handle_conn(mut sock: TcpStream, state: Arc<RelayState>) {
    loop {
        let req: RelayRequest = match read_json(&mut sock).await {
            Ok(r) => r,
            Err(_) => break,
        };
        let resp = match state.handle(req) {
            Ok(r) => r,
            Err(RelayError::RateLimited) => RelayResponse::Err {
                message: "rate limited".into(),
            },
            Err(e) => RelayResponse::Err {
                message: e.to_string(),
            },
        };
        if write_json(&mut sock, &resp).await.is_err() {
            break;
        }
    }
}

async fn serve(listener: TcpListener, state: Arc<RelayState>) -> Result<(), RelayError> {
    loop {
        let (sock, _) = listener.accept().await?;
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            handle_conn(sock, st).await;
        });
    }
}

fn parse_args(args: &[String]) -> (String, PathBuf) {
    let mut bind = "127.0.0.1:7700".to_string();
    let mut db = PathBuf::from("td-relay.sqlite");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" if i + 1 < args.len() => {
                bind = args[i + 1].clone();
                i += 2;
            }
            "--db" if i + 1 < args.len() => {
                db = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            _ => i += 1,
        }
    }
    (bind, db)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let (bind, db_path) = parse_args(&args);
    let store = EnvelopeStore::open(&db_path)?;
    let state = Arc::new(RelayState {
        store,
        limiter: Mutex::new(RateLimiter::new(DEFAULT_RATE)),
    });
    let listener = TcpListener::bind(&bind).await?;
    let local = listener.local_addr()?;
    eprintln!(
        "td-relay {} listening on {} db={}",
        env!("CARGO_PKG_VERSION"),
        PeerUri::from_tcp_addr(local).to_string_uri(),
        db_path.display()
    );
    serve(listener, state).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use td_crypto::DeviceKeypair;
    use td_event::{sign_event, EventKind, RoomId, UnsignedEvent};
    use td_net::{RelayClient, RelayEnvelope};
    use tokio::runtime::Runtime;

    fn spawn_relay(rt: &Runtime) -> (PeerUri, Arc<RelayState>) {
        let listener = rt.block_on(async { TcpListener::bind("127.0.0.1:0").await.unwrap() });
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(RelayState {
            store: EnvelopeStore::open_in_memory().unwrap(),
            limiter: Mutex::new(RateLimiter::new(1000)),
        });
        let st = Arc::clone(&state);
        rt.spawn(async move {
            let _ = serve(listener, st).await;
        });
        (PeerUri::from_tcp_addr(addr), state)
    }

    #[test]
    fn peer_offline_catchup_via_relay_no_plaintext_in_db() {
        let rt = Runtime::new().unwrap();
        let (uri, state) = spawn_relay(&rt);

        let alice = DeviceKeypair::generate();
        let bob = DeviceKeypair::generate();
        let room = RoomId::from_bytes([42u8; 32]);
        let plaintext_marker = b"SUPER_SECRET_HONK_PLAINTEXT";

        // Alice builds a real signed event, then "encrypts" by wrapping as opaque blob.
        // MVP: outer layer is opaque; inner may be signed event JSON for catch-up tests.
        let signed = sign_event(
            alice.signing_key(),
            UnsignedEvent {
                room_id: room,
                parents: vec![],
                kind: EventKind::Message,
                payload: plaintext_marker.to_vec(),
                author_device: alice.event_device_id(),
                ts_ms: 10,
            },
        )
        .unwrap();
        let inner = serde_json::to_vec(&signed).unwrap();
        // Opaque ciphertext fixture (production clients use ChaCha20-Poly1305 seal).
        let mut ciphertext = Vec::with_capacity(1 + 12 + inner.len() + 16);
        ciphertext.push(0x01);
        ciphertext.extend_from_slice(&[0u8; 12]); // fake nonce
        ciphertext.extend_from_slice(&inner.iter().map(|b| b.wrapping_add(1)).collect::<Vec<_>>());
        ciphertext.extend_from_slice(&[0u8; 16]); // fake tag
        assert!(
            !ciphertext
                .windows(plaintext_marker.len())
                .any(|w| w == plaintext_marker),
            "test setup must hide plaintext in ciphertext"
        );

        let env = RelayEnvelope::new(
            bob.event_device_id(),
            alice.event_device_id(),
            Some(room),
            ciphertext.clone(),
            10,
        );

        rt.block_on(async {
            let mut client = RelayClient::connect(&uri).await.unwrap();
            client.put(env.clone()).await.unwrap();

            // Bob was offline; now fetches
            let items = client.fetch(bob.event_device_id(), 0, 10).await.unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].envelope_id, env.envelope_id);
            assert_eq!(items[0].ciphertext, ciphertext);

            // recover signed event locally
            let recovered: Vec<u8> = items[0].ciphertext.iter().map(|b| b ^ pad).collect();
            let ev: td_event::SignedEvent = serde_json::from_slice(&recovered).unwrap();
            td_event::verify_event(&ev).unwrap();
            assert_eq!(ev.payload, plaintext_marker);

            client
                .ack(bob.event_device_id(), vec![items[0].envelope_id])
                .await
                .unwrap();
            let after = client.fetch(bob.event_device_id(), 0, 10).await.unwrap();
            assert!(after.is_empty());
        });

        // Relay DB must not contain plaintext marker
        assert!(!state
            .store
            .ciphertext_contains_bytes(plaintext_marker)
            .unwrap());
        // After ack, store empty
        assert_eq!(state.store.count().unwrap(), 0);
    }

    #[test]
    fn rate_limit_puts() {
        let store = EnvelopeStore::open_in_memory().unwrap();
        let state = RelayState {
            store,
            limiter: Mutex::new(RateLimiter::new(2)),
        };
        let alice = DeviceKeypair::generate().event_device_id();
        let bob = DeviceKeypair::generate().event_device_id();
        for i in 0..2 {
            let env = RelayEnvelope::new(bob, alice, None, vec![i], i as u64);
            assert!(matches!(
                state.handle(RelayRequest::Put { envelope: env }),
                Ok(RelayResponse::Ok)
            ));
        }
        let env = RelayEnvelope::new(bob, alice, None, vec![9], 9);
        let err = state.handle(RelayRequest::Put { envelope: env });
        assert!(matches!(err, Err(RelayError::RateLimited)));
    }

    #[test]
    fn smoke_version() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
