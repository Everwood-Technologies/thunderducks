//! Framed P2P event exchange + opaque relay assist protocol (Waves B3 + D1).
//!
//! Transport:
//! - plain TCP length-prefixed JSON (`td://`) — default localhost/DIY
//! - **Noise_XX** over TCP (`td-noise://`)
//! - **QUIC** (`td-quic://`) with optional blake3 cert pins + mTLS

mod frame;
mod noise;
mod peer;
mod quic;
mod relay_client;
mod relay_proto;

pub use frame::{read_event, write_event, FrameError};
pub use noise::{
    noise_read_event, noise_read_json, noise_write_event, noise_write_json, NoiseError,
    NoiseTcpStream,
};
pub use peer::{accept_once, dial, serve_exchange, PeerError, PeerUri};
pub use quic::{
    cert_pin_blake3, cert_pin_hex, is_quic_uri, load_pem_identity, parse_pin_list, quic_accept,
    quic_dial, quic_dial_with_config, quic_listen, quic_listen_with_config, self_signed_cert,
    write_self_signed_pem, QuicError, QuicStream, QuicTlsConfig,
};
pub use relay_client::{RelayClient, RelayClientError};
pub use relay_proto::{
    read_json, write_json, RelayEnvelope, RelayProtoError, RelayRequest, RelayResponse,
};

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

    #[test]
    fn envelope_id_is_content_addressed() {
        let a = DeviceKeypair::generate().event_device_id();
        let b = DeviceKeypair::generate().event_device_id();
        let e1 = RelayEnvelope::new(a, b, None, b"cipher".to_vec(), 1);
        let e2 = RelayEnvelope::new(a, b, None, b"cipher".to_vec(), 1);
        let e3 = RelayEnvelope::new(a, b, None, b"other".to_vec(), 1);
        assert_eq!(e1.envelope_id, e2.envelope_id);
        assert_ne!(e1.envelope_id, e3.envelope_id);
    }
}
