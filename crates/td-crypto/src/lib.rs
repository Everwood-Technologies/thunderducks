//! Device identity keys, device-linking, and vodozemac E2EE (Wave B2 + C1).

mod device;
mod e2ee;
mod link;

pub use device::{DeviceBundle, DeviceId, DeviceKeypair};
pub use e2ee::{
    fanout_megolm_key, E2eeDevice, E2eeError, MegolmCiphertext, OlmCiphertext, OlmDeviceKeys,
};
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
        reg.trust_local(&primary).unwrap();

        let request = reg.create_link_request(&secondary).unwrap();
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

    #[test]
    fn olm_1to1_roundtrip() {
        let a_kp = DeviceKeypair::generate();
        let b_kp = DeviceKeypair::generate();
        let mut alice = E2eeDevice::new(a_kp.device_id());
        let mut bob = E2eeDevice::new(b_kp.device_id());

        let bob_keys = bob.publish_keys().unwrap();
        alice.establish_olm_outbound(&bob_keys).unwrap();

        let ct = alice
            .olm_encrypt(bob.device_id, b"keep it between us")
            .unwrap();
        let plain = bob.olm_decrypt(&alice.curve25519_b64(), &ct).unwrap();
        assert_eq!(plain, b"keep it between us");

        // reply establishes full duplex
        let reply = bob.olm_encrypt(alice.device_id, b"roger").unwrap();
        let got = alice.olm_decrypt(&bob.curve25519_b64(), &reply).unwrap();
        assert_eq!(got, b"roger");
    }

    #[test]
    fn megolm_group_three_devices() {
        let a = DeviceKeypair::generate();
        let b = DeviceKeypair::generate();
        let c = DeviceKeypair::generate();
        let mut alice = E2eeDevice::new(a.device_id());
        let mut bob = E2eeDevice::new(b.device_id());
        let mut carol = E2eeDevice::new(c.device_id());

        // Olm channels Alice->Bob and Alice->Carol for key fanout
        let bob_keys = bob.publish_keys().unwrap();
        let carol_keys = carol.publish_keys().unwrap();
        alice.establish_olm_outbound(&bob_keys).unwrap();
        alice.establish_olm_outbound(&carol_keys).unwrap();

        let room = "room-group-1";
        let _sid = alice.create_group_session(room);
        let recipients = [alice.device_id, bob.device_id, carol.device_id];
        let fanout = fanout_megolm_key(&mut alice, room, &recipients).unwrap();
        assert_eq!(fanout.len(), 2);

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

        let msg = alice.megolm_encrypt(room, b"honk all y'all").unwrap();
        let b_plain = bob.megolm_decrypt(&msg).unwrap();
        let c_plain = carol.megolm_decrypt(&msg).unwrap();
        assert_eq!(b_plain, b"honk all y'all");
        assert_eq!(c_plain, b"honk all y'all");
        // sender can also decrypt via self inbound
        let a_plain = alice.megolm_decrypt(&msg).unwrap();
        assert_eq!(a_plain, b"honk all y'all");
    }
}
