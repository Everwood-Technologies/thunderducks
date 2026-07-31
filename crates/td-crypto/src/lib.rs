//! Device identity keys and local device-linking (Wave B2).
//!
//! E2EE (vodozemac) arrives in Wave C; this crate owns device keypairs,
//! device ids, and an offline multi-device link approval flow.

mod device;
mod link;

pub use device::{DeviceBundle, DeviceId, DeviceKeypair};
pub use link::{DeviceLinkPayload, LinkError, LinkRegistry};

/// Crate smoke marker used by CI.
pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;
    use td_event::{sign_event, verify_event, EventKind, RoomId, UnsignedEvent};

    #[test]
    fn smoke_name() {
        assert_eq!(crate_name(), "td-crypto");
    }

    #[test]
    fn two_devices_link_without_network() {
        let primary = DeviceKeypair::generate();
        let secondary = DeviceKeypair::generate();

        let mut reg = LinkRegistry::new(primary.device_id());
        // primary is self-trusted
        reg.trust_local(&primary).unwrap();

        let request = reg.create_link_request(&secondary).unwrap();
        // primary approves secondary offline
        let approval = reg.approve_link(&primary, &request).unwrap();
        reg.apply_approval(&approval).unwrap();

        assert!(reg.is_linked(&secondary.device_id()));
        assert_eq!(reg.linked_devices().len(), 2);
    }

    #[test]
    fn linked_device_can_sign_events() {
        let a = DeviceKeypair::generate();
        let room = RoomId::from_bytes([7u8; 32]);
        let unsigned = UnsignedEvent {
            room_id: room,
            parents: vec![],
            kind: EventKind::Message,
            payload: b"from-device".to_vec(),
            author_device: a.event_device_id(),
            ts_ms: 42,
        };
        let signed = sign_event(a.signing_key(), unsigned).unwrap();
        verify_event(&signed).unwrap();
        assert_eq!(signed.author_device, a.event_device_id());
    }
}
