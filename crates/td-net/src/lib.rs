//! Framed P2P event exchange over TCP (Wave B3).
//!
//! QUIC/Noise come later; MVP path is length-prefixed JSON SignedEvent frames
//! on localhost/manual peer URI (`td://host:port`).

mod frame;
mod peer;

pub use frame::{read_event, write_event, FrameError};
pub use peer::{accept_once, dial, serve_exchange, PeerError, PeerUri};

/// Crate smoke marker used by CI.
pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;
    use td_crypto::DeviceKeypair;
    use td_event::{sign_event, verify_event, EventKind, RoomId, UnsignedEvent};
    use tokio::runtime::Runtime;

    #[test]
    fn smoke_name() {
        assert_eq!(crate_name(), "td-net");
    }

    #[test]
    fn two_processes_exchange_signed_event_localhost() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let ev = read_event(&mut socket).await.unwrap();
                verify_event(&ev).unwrap();
                // echo ack by writing same event back
                write_event(&mut socket, &ev).await.unwrap();
                ev
            });

            let kp = DeviceKeypair::generate();
            let room = RoomId::from_bytes([9u8; 32]);
            let unsigned = UnsignedEvent {
                room_id: room,
                parents: vec![],
                kind: EventKind::Message,
                payload: b"p2p-honk".to_vec(),
                author_device: kp.event_device_id(),
                ts_ms: 100,
            };
            let signed = sign_event(kp.signing_key(), unsigned).unwrap();

            let mut client = dial(&PeerUri::from_tcp_addr(addr)).await.unwrap();
            write_event(&mut client, &signed).await.unwrap();
            let echoed = read_event(&mut client).await.unwrap();
            verify_event(&echoed).unwrap();
            assert_eq!(echoed.id, signed.id);
            assert_eq!(echoed.payload, b"p2p-honk");

            let server_ev = server.await.unwrap();
            assert_eq!(server_ev.id, signed.id);
        });
    }
}
