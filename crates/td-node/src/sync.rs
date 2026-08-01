//! Multi-device sync: outbox/inbox + per-room DAG convergence (Wave D2).
//!
//! After a partition, devices exchange missing events (directly or via relay
//! ciphertext catch-up) until room DAGs converge on the same tip set.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use td_crypto::DeviceId as CryptoDeviceId;
use td_event::{
    verify_event, DeviceId, EventId, EventKind, RoomDag, RoomId, SignedEvent, StoreError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Event(#[from] td_event::EventError),
    #[error(transparent)]
    Dag(#[from] td_event::DagError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("unknown room {0:?}")]
    UnknownRoom(RoomId),
    #[error("decode envelope: {0}")]
    Decode(String),
}

/// Wire bundle for tip-based catch-up (plaintext at device boundary only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOffer {
    pub from_device: DeviceId,
    pub room_id: RoomId,
    pub tips: Vec<EventId>,
    pub have: Vec<EventId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub room_id: RoomId,
    pub missing: Vec<SignedEvent>,
}

/// Local node view for one device: event log + room DAGs + outbox/inbox.
pub struct DeviceNode {
    pub device_id: DeviceId,
    /// All accepted events by id (verified).
    events: HashMap<EventId, SignedEvent>,
    dags: HashMap<[u8; 32], RoomDag>,
    outbox: VecDeque<SignedEvent>,
    inbox: VecDeque<SignedEvent>,
}

impl DeviceNode {
    pub fn new(device_id: impl Into<DeviceId>) -> Self {
        Self {
            device_id: device_id.into(),
            events: HashMap::new(),
            dags: HashMap::new(),
            outbox: VecDeque::new(),
            inbox: VecDeque::new(),
        }
    }

    pub fn from_crypto_device(id: CryptoDeviceId) -> Self {
        Self::new(DeviceId(id.0))
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
    }

    pub fn tips(&self, room_id: &RoomId) -> Vec<EventId> {
        self.dags
            .get(&room_id.0)
            .map(|d| d.tips())
            .unwrap_or_default()
    }

    pub fn has_event(&self, id: &EventId) -> bool {
        self.events.contains_key(id)
    }

    pub fn get_event(&self, id: &EventId) -> Option<&SignedEvent> {
        self.events.get(id)
    }

    pub fn room_event_ids(&self, room_id: &RoomId) -> HashSet<EventId> {
        self.events
            .values()
            .filter(|e| e.room_id == *room_id)
            .map(|e| e.id)
            .collect()
    }

    /// Author a local event: append to DAG, store, queue outbox.
    pub fn commit_local(&mut self, ev: SignedEvent) -> Result<bool, SyncError> {
        verify_event(&ev)?;
        self.ingest_event(ev.clone(), true)
    }

    /// Apply a remote event (P2P or decrypted relay payload).
    pub fn commit_remote(&mut self, ev: SignedEvent) -> Result<bool, SyncError> {
        verify_event(&ev)?;
        self.ingest_event(ev, false)
    }

    fn ingest_event(&mut self, ev: SignedEvent, to_outbox: bool) -> Result<bool, SyncError> {
        if self.events.contains_key(&ev.id) {
            return Ok(false);
        }
        // Ensure parents present; if not, still hold in inbox for later (simple MVP: require parents)
        for p in &ev.parents {
            if !self.events.contains_key(p) {
                // park until parents arrive
                if !self.inbox.iter().any(|e| e.id == ev.id) {
                    self.inbox.push_back(ev);
                }
                return Ok(false);
            }
        }
        let dag = self
            .dags
            .entry(ev.room_id.0)
            .or_insert_with(|| RoomDag::new(ev.room_id));
        let inserted = dag.ingest(ev.clone())?;
        if inserted {
            self.events.insert(ev.id, ev.clone());
            if to_outbox {
                self.outbox.push_back(ev);
            }
            self.drain_inbox()?;
        }
        Ok(inserted)
    }

    fn drain_inbox(&mut self) -> Result<(), SyncError> {
        let mut progress = true;
        while progress {
            progress = false;
            let mut rest = VecDeque::new();
            while let Some(ev) = self.inbox.pop_front() {
                if self.events.contains_key(&ev.id) {
                    continue;
                }
                let parents_ok = ev.parents.iter().all(|p| self.events.contains_key(p));
                if !parents_ok {
                    rest.push_back(ev);
                    continue;
                }
                let dag = self
                    .dags
                    .entry(ev.room_id.0)
                    .or_insert_with(|| RoomDag::new(ev.room_id));
                if dag.ingest(ev.clone())? {
                    self.events.insert(ev.id, ev);
                    progress = true;
                }
            }
            self.inbox = rest;
        }
        Ok(())
    }

    pub fn pop_outbox(&mut self) -> Option<SignedEvent> {
        self.outbox.pop_front()
    }

    pub fn peek_outbox(&self) -> Vec<SignedEvent> {
        self.outbox.iter().cloned().collect()
    }

    /// Events this node has that `peer_have` lacks, for a room (ancestors of tips closure).
    pub fn missing_for_peer(
        &self,
        room_id: &RoomId,
        peer_have: &HashSet<EventId>,
    ) -> Vec<SignedEvent> {
        let mut missing: Vec<SignedEvent> = self
            .events
            .values()
            .filter(|e| e.room_id == *room_id && !peer_have.contains(&e.id))
            .cloned()
            .collect();
        // parent-before-child order (simple Kahn-ish by parent count then ts)
        missing.sort_by(|a, b| {
            a.parents
                .len()
                .cmp(&b.parents.len())
                .then(a.ts_ms.cmp(&b.ts_ms))
        });
        missing
    }

    pub fn build_offer(&self, room_id: RoomId) -> SyncOffer {
        let have: Vec<EventId> = self.room_event_ids(&room_id).into_iter().collect();
        SyncOffer {
            from_device: self.device_id,
            room_id,
            tips: self.tips(&room_id),
            have,
        }
    }

    pub fn respond_to_offer(&self, offer: &SyncOffer) -> SyncResponse {
        let peer_have: HashSet<EventId> = offer.have.iter().copied().collect();
        let missing = self.missing_for_peer(&offer.room_id, &peer_have);
        SyncResponse {
            room_id: offer.room_id,
            missing,
        }
    }

    pub fn apply_sync_response(&mut self, resp: SyncResponse) -> Result<usize, SyncError> {
        let mut n = 0;
        for ev in resp.missing {
            if self.commit_remote(ev)? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Encode a signed event as opaque relay ciphertext (device-side).
    /// MVP uses a trivial stream XOR — real path wraps Megolm/Olm ciphertext.
    pub fn seal_for_relay(ev: &SignedEvent, pad: u8) -> Result<Vec<u8>, SyncError> {
        let raw = serde_json::to_vec(ev)?;
        Ok(raw.into_iter().map(|b| b ^ pad).collect())
    }

    pub fn open_from_relay(ciphertext: &[u8], pad: u8) -> Result<SignedEvent, SyncError> {
        let raw: Vec<u8> = ciphertext.iter().map(|b| b ^ pad).collect();
        let ev: SignedEvent =
            serde_json::from_slice(&raw).map_err(|e| SyncError::Decode(e.to_string()))?;
        verify_event(&ev)?;
        Ok(ev)
    }

    /// Bidirectional sync helper: each side sends missing events to the other.
    pub fn converge_with(
        a: &mut DeviceNode,
        b: &mut DeviceNode,
        room_id: RoomId,
    ) -> Result<(), SyncError> {
        let offer_a = a.build_offer(room_id);
        let offer_b = b.build_offer(room_id);
        let resp_for_a = b.respond_to_offer(&offer_a);
        let resp_for_b = a.respond_to_offer(&offer_b);
        a.apply_sync_response(resp_for_a)?;
        b.apply_sync_response(resp_for_b)?;
        Ok(())
    }

    pub fn tip_set(&self, room_id: &RoomId) -> HashSet<EventId> {
        self.tips(room_id).into_iter().collect()
    }

    pub fn room_ids(&self) -> Vec<RoomId> {
        self.dags.keys().map(|k| RoomId(*k)).collect()
    }

    pub fn seed_create(&mut self, ev: SignedEvent) -> Result<(), SyncError> {
        assert_eq!(ev.kind, EventKind::CreateRoom);
        self.commit_local(ev)?;
        // create is local authorship; clear outbox if used as bootstrap fixture via remote path
        Ok(())
    }

    /// Room messages in causal-ish order (parent count, then ts).
    pub fn list_messages(&self, room_id: &RoomId) -> Vec<SignedEvent> {
        let mut msgs: Vec<SignedEvent> = self
            .events
            .values()
            .filter(|e| e.room_id == *room_id && e.kind == EventKind::Message)
            .cloned()
            .collect();
        msgs.sort_by(|a, b| {
            a.parents
                .len()
                .cmp(&b.parents.len())
                .then(a.ts_ms.cmp(&b.ts_ms))
        });
        msgs
    }

    pub fn list_events(&self, room_id: &RoomId) -> Vec<SignedEvent> {
        let mut evs: Vec<SignedEvent> = self
            .events
            .values()
            .filter(|e| e.room_id == *room_id)
            .cloned()
            .collect();
        evs.sort_by(|a, b| {
            a.parents
                .len()
                .cmp(&b.parents.len())
                .then(a.ts_ms.cmp(&b.ts_ms))
        });
        evs
    }
}
