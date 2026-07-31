//! Room create / membership as signed event payloads (Wave C2).

use crate::dag::{DagError, RoomDag};
use crate::event::{
    sign_event, verify_event, DeviceId, EventError, EventId, EventKind, RoomId, SignedEvent,
    UnsignedEvent,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoomError {
    #[error(transparent)]
    Event(#[from] EventError),
    #[error(transparent)]
    Dag(#[from] DagError),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("not a member: {0:?}")]
    NotMember(DeviceId),
    #[error("unknown room")]
    UnknownRoom,
    #[error("invalid membership transition")]
    InvalidTransition,
    #[error("unauthorized membership change")]
    Unauthorized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipAction {
    Join,
    Invite,
    Leave,
    Ban,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoomPayload {
    pub creator: DeviceId,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipPayload {
    pub target: DeviceId,
    pub action: MembershipAction,
    pub actor: DeviceId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberState {
    Invited,
    Joined,
    Left,
    Banned,
}

#[derive(Debug)]
pub struct RoomState {
    pub room_id: RoomId,
    pub name: String,
    pub creator: DeviceId,
    members: HashMap<DeviceId, MemberState>,
    dag: RoomDag,
    tips: Vec<EventId>,
}

impl RoomState {
    pub fn is_joined(&self, d: &DeviceId) -> bool {
        matches!(self.members.get(d), Some(MemberState::Joined))
    }

    pub fn joined_devices(&self) -> Vec<DeviceId> {
        self.members
            .iter()
            .filter_map(|(id, st)| {
                if *st == MemberState::Joined {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn member_state(&self, d: &DeviceId) -> Option<&MemberState> {
        self.members.get(d)
    }

    pub fn tips(&self) -> &[EventId] {
        &self.tips
    }

    pub fn dag_len(&self) -> usize {
        self.dag.len()
    }
}

/// In-memory room registry folding membership from the event DAG.
#[derive(Default)]
pub struct RoomRegistry {
    rooms: HashMap<[u8; 32], RoomState>,
}

impl RoomRegistry {
    pub fn new() -> Self {
        Self {
            rooms: HashMap::new(),
        }
    }

    pub fn get(&self, room_id: &RoomId) -> Option<&RoomState> {
        self.rooms.get(&room_id.0)
    }

    pub fn create_room(
        &mut self,
        sk: &SigningKey,
        creator: DeviceId,
        name: impl Into<String>,
        ts_ms: u64,
    ) -> Result<(RoomId, SignedEvent), RoomError> {
        // room id = blake3(creator || name || ts)
        let name = name.into();
        let mut material = Vec::new();
        material.extend_from_slice(&creator.0);
        material.extend_from_slice(name.as_bytes());
        material.extend_from_slice(&ts_ms.to_le_bytes());
        let room_id = RoomId(*blake3::hash(&material).as_bytes());

        let payload = CreateRoomPayload {
            creator,
            name: name.clone(),
        };
        let unsigned = UnsignedEvent {
            room_id,
            parents: vec![],
            kind: EventKind::CreateRoom,
            payload: serde_json::to_vec(&payload)?,
            author_device: creator,
            ts_ms,
        };
        let signed = sign_event(sk, unsigned)?;
        self.apply_event(signed.clone())?;
        Ok((room_id, signed))
    }

    pub fn membership_event(
        &mut self,
        sk: &SigningKey,
        room_id: RoomId,
        actor: DeviceId,
        target: DeviceId,
        action: MembershipAction,
        ts_ms: u64,
    ) -> Result<SignedEvent, RoomError> {
        let room = self.rooms.get(&room_id.0).ok_or(RoomError::UnknownRoom)?;
        // Only joined members (or creator via joined) can invite/kick; target can leave if joined/invited
        match action {
            MembershipAction::Invite | MembershipAction::Ban => {
                if !room.is_joined(&actor) {
                    return Err(RoomError::Unauthorized);
                }
            }
            MembershipAction::Join => {
                // allow join if invited or creator bootstrap already joined
                let st = room.member_state(&target);
                if actor != target {
                    return Err(RoomError::Unauthorized);
                }
                if !matches!(st, Some(MemberState::Invited) | Some(MemberState::Joined)) {
                    // allow first-time join only if already invited
                    if !matches!(st, Some(MemberState::Invited)) {
                        return Err(RoomError::InvalidTransition);
                    }
                }
            }
            MembershipAction::Leave => {
                if actor != target
                    || !matches!(
                        room.member_state(&target),
                        Some(MemberState::Joined) | Some(MemberState::Invited)
                    )
                {
                    return Err(RoomError::Unauthorized);
                }
            }
        }

        let parents = room.tips().to_vec();
        let payload = MembershipPayload {
            target,
            action,
            actor,
        };
        let unsigned = UnsignedEvent {
            room_id,
            parents,
            kind: EventKind::Membership,
            payload: serde_json::to_vec(&payload)?,
            author_device: actor,
            ts_ms,
        };
        let signed = sign_event(sk, unsigned)?;
        self.apply_event(signed.clone())?;
        Ok(signed)
    }

    pub fn apply_event(&mut self, ev: SignedEvent) -> Result<bool, RoomError> {
        verify_event(&ev)?;
        match ev.kind {
            EventKind::CreateRoom => {
                let payload: CreateRoomPayload = serde_json::from_slice(&ev.payload)?;
                if self.rooms.contains_key(&ev.room_id.0) {
                    // idempotent if same create
                    let room = self.rooms.get_mut(&ev.room_id.0).unwrap();
                    let inserted = room.dag.ingest(ev.clone())?;
                    if inserted {
                        room.tips = room.dag.tips();
                    }
                    return Ok(inserted);
                }
                let mut dag = RoomDag::new(ev.room_id);
                dag.ingest(ev.clone())?;
                let mut members = HashMap::new();
                members.insert(payload.creator, MemberState::Joined);
                let tips = dag.tips();
                self.rooms.insert(
                    ev.room_id.0,
                    RoomState {
                        room_id: ev.room_id,
                        name: payload.name,
                        creator: payload.creator,
                        members,
                        dag,
                        tips,
                    },
                );
                Ok(true)
            }
            EventKind::Membership => {
                let payload: MembershipPayload = serde_json::from_slice(&ev.payload)?;
                let room = self
                    .rooms
                    .get_mut(&ev.room_id.0)
                    .ok_or(RoomError::UnknownRoom)?;
                // reject evil: banned cannot rejoin via join without invite path handled below
                let inserted = room.dag.ingest(ev.clone())?;
                if !inserted {
                    return Ok(false);
                }
                match payload.action {
                    MembershipAction::Invite => {
                        if matches!(room.members.get(&payload.target), Some(MemberState::Banned)) {
                            return Err(RoomError::InvalidTransition);
                        }
                        room.members.insert(payload.target, MemberState::Invited);
                    }
                    MembershipAction::Join => {
                        if matches!(room.members.get(&payload.target), Some(MemberState::Banned)) {
                            return Err(RoomError::InvalidTransition);
                        }
                        room.members.insert(payload.target, MemberState::Joined);
                    }
                    MembershipAction::Leave => {
                        room.members.insert(payload.target, MemberState::Left);
                    }
                    MembershipAction::Ban => {
                        room.members.insert(payload.target, MemberState::Banned);
                    }
                }
                room.tips = room.dag.tips();
                Ok(true)
            }
            _ => {
                // other kinds attach to dag if room exists
                let room = self
                    .rooms
                    .get_mut(&ev.room_id.0)
                    .ok_or(RoomError::UnknownRoom)?;
                if !room.is_joined(&ev.author_device) {
                    return Err(RoomError::NotMember(ev.author_device));
                }
                let inserted = room.dag.ingest(ev)?;
                if inserted {
                    room.tips = room.dag.tips();
                }
                Ok(inserted)
            }
        }
    }

    /// Helper: reject events from non-members for message kind at registry boundary.
    pub fn assert_can_message(&self, room_id: &RoomId, author: &DeviceId) -> Result<(), RoomError> {
        let room = self.get(room_id).ok_or(RoomError::UnknownRoom)?;
        if room.is_joined(author) {
            Ok(())
        } else {
            Err(RoomError::NotMember(*author))
        }
    }
}

/// Deterministic room id helper for tests.
pub fn room_id_from_parts(creator: &DeviceId, name: &str, ts_ms: u64) -> RoomId {
    let mut material = Vec::new();
    material.extend_from_slice(&creator.0);
    material.extend_from_slice(name.as_bytes());
    material.extend_from_slice(&ts_ms.to_le_bytes());
    RoomId(*blake3::hash(&material).as_bytes())
}
