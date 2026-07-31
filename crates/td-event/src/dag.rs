use crate::event::EventError;
use crate::event::{verify_event, EventId, RoomId, SignedEvent};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DagError {
    #[error(transparent)]
    Event(#[from] EventError),
    #[error("room mismatch")]
    RoomMismatch,
    #[error("missing parent {0:?}")]
    MissingParent(EventId),
}

/// In-memory per-room causal DAG.
#[derive(Debug, Default)]
pub struct RoomDag {
    room_id: Option<RoomId>,
    events: HashMap<EventId, SignedEvent>,
    children: HashMap<EventId, Vec<EventId>>,
}

impl RoomDag {
    pub fn new(room_id: RoomId) -> Self {
        Self {
            room_id: Some(room_id),
            events: HashMap::new(),
            children: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn get(&self, id: &EventId) -> Option<&SignedEvent> {
        self.events.get(id)
    }

    pub fn tips(&self) -> Vec<EventId> {
        // tips = events with no children
        self.events
            .keys()
            .filter(|id| self.children.get(id).map(|v| v.is_empty()).unwrap_or(true))
            .copied()
            .collect()
    }

    /// Ingest a verified event. Returns Ok(true) if newly inserted, Ok(false) if duplicate.
    pub fn ingest(&mut self, ev: SignedEvent) -> Result<bool, DagError> {
        verify_event(&ev)?;
        if let Some(rid) = self.room_id {
            if ev.room_id != rid {
                return Err(DagError::RoomMismatch);
            }
        } else {
            self.room_id = Some(ev.room_id);
        }
        if self.events.contains_key(&ev.id) {
            return Ok(false);
        }
        for p in &ev.parents {
            if !self.events.contains_key(p) {
                return Err(DagError::MissingParent(*p));
            }
        }
        for p in &ev.parents {
            self.children.entry(*p).or_default().push(ev.id);
        }
        self.events.insert(ev.id, ev);
        Ok(true)
    }
}
