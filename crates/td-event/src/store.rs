use crate::event::EventError;
use crate::event::{verify_event, EventId, SignedEvent};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Event(#[from] EventError),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub trait EventStore {
    fn put(&mut self, ev: SignedEvent) -> Result<bool, StoreError>;
    fn get(&self, id: &EventId) -> Result<Option<SignedEvent>, StoreError>;
}

#[derive(Default)]
pub struct MemoryStore {
    map: HashMap<EventId, SignedEvent>,
}

impl EventStore for MemoryStore {
    fn put(&mut self, ev: SignedEvent) -> Result<bool, StoreError> {
        verify_event(&ev)?;
        if self.map.contains_key(&ev.id) {
            return Ok(false);
        }
        self.map.insert(ev.id, ev);
        Ok(true)
    }

    fn get(&self, id: &EventId) -> Result<Option<SignedEvent>, StoreError> {
        Ok(self.map.get(id).cloned())
    }
}

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS events (
              id BLOB PRIMARY KEY NOT NULL,
              room_id BLOB NOT NULL,
              body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_room ON events(room_id);
            "#,
        )?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS events (
              id BLOB PRIMARY KEY NOT NULL,
              room_id BLOB NOT NULL,
              body TEXT NOT NULL
            );
            "#,
        )?;
        Ok(Self { conn })
    }

    /// All events in parent-count / ts order (best-effort causal load order).
    pub fn list_all(&self) -> Result<Vec<SignedEvent>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT body FROM events")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            let body = r?;
            let ev: SignedEvent = serde_json::from_str(&body).map_err(EventError::from)?;
            verify_event(&ev)?;
            out.push(ev);
        }
        out.sort_by(|a, b| {
            a.parents
                .len()
                .cmp(&b.parents.len())
                .then(a.ts_ms.cmp(&b.ts_ms))
        });
        Ok(out)
    }

    pub fn count(&self) -> Result<usize, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(n as usize)
    }
}

impl EventStore for SqliteStore {
    fn put(&mut self, ev: SignedEvent) -> Result<bool, StoreError> {
        verify_event(&ev)?;
        let body = serde_json::to_string(&ev).map_err(EventError::from)?;
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO events (id, room_id, body) VALUES (?1, ?2, ?3)",
            params![ev.id.0.as_slice(), ev.room_id.0.as_slice(), body],
        )?;
        Ok(changed == 1)
    }

    fn get(&self, id: &EventId) -> Result<Option<SignedEvent>, StoreError> {
        let body: Option<String> = self
            .conn
            .query_row(
                "SELECT body FROM events WHERE id = ?1",
                params![id.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match body {
            None => Ok(None),
            Some(s) => {
                let ev: SignedEvent = serde_json::from_str(&s).map_err(EventError::from)?;
                verify_event(&ev)?;
                Ok(Some(ev))
            }
        }
    }
}
