//! QUIC P2P transport (first slice).
//!
//! URI: `td-quic://host:port`
//!
//! Frames above QUIC stay length-prefixed JSON signed events (same as TCP).
//! TLS is rustls with a self-signed server cert by default (dev / pond LAN).
//!
//! ALPN: `td-p2p/1`

use crate::frame::{read_event, write_event, FrameError};
use crate::peer::{PeerError, PeerUri};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use td_event::SignedEvent;
use thiserror::Error;

const ALPN: &[u8] = b"td-p2p/1";

/// Ensure a process-level rustls CryptoProvider is installed (ring).
fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("quic: {0}")]
    Quinn(String),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid peer uri: {0}")]
    InvalidUri(String),
    #[error("connection closed")]
    Closed,
    #[error("tls: {0}")]
    Tls(String),
}

impl From<PeerError> for QuicError {
    fn from(e: PeerError) -> Self {
        Self::InvalidUri(e.to_string())
    }
}

fn map_q<E: std::fmt::Display>(e: E) -> QuicError {
    QuicError::Quinn(e.to_string())
}

/// Generate a self-signed cert for pond QUIC (dev / LAN).
fn self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), QuicError> {
    ensure_crypto_provider();
    let key_pair = KeyPair::generate().map_err(|e| QuicError::Tls(e.to_string()))?;
    let mut params = CertificateParams::new(vec!["localhost".into(), "td-pond".into()])
        .map_err(|e| QuicError::Tls(e.to_string()))?;
    params.subject_alt_names.push(SanType::DnsName(
        "localhost"
            .try_into()
            .map_err(|e: rcgen::Error| QuicError::Tls(e.to_string()))?,
    ));
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| QuicError::Tls(e.to_string()))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok((vec![cert_der], key_der))
}

fn server_config() -> Result<ServerConfig, QuicError> {
    ensure_crypto_provider();
    let (certs, key) = self_signed_cert()?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| QuicError::Tls(e.to_string()))?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut server = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| QuicError::Tls(e.to_string()))?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(64u32.into());
    server.transport_config(Arc::new(transport));
    Ok(server)
}

/// Client that skips cert verification (pond self-signed / first slice).
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> Result<ClientConfig, QuicError> {
    ensure_crypto_provider();
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| QuicError::Tls(e.to_string()))?;
    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

/// Open a QUIC server endpoint on `bind` (e.g. `0.0.0.0:0`).
pub async fn quic_listen(bind: &str) -> Result<(Endpoint, SocketAddr), QuicError> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| QuicError::InvalidUri(format!("{bind}: {e}")))?;
    let endpoint = Endpoint::server(server_config()?, addr).map_err(map_q)?;
    let local = endpoint.local_addr().map_err(map_q)?;
    Ok((endpoint, local))
}

/// Bidirectional framed stream over QUIC.
///
/// Holds `Endpoint` + `Connection` so the UDP socket stays alive for the stream lifetime.
pub struct QuicStream {
    /// Keep endpoint alive (client-side especially — dropping it closes the conn).
    _endpoint: Endpoint,
    _conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl QuicStream {
    pub async fn write_event(&mut self, ev: &SignedEvent) -> Result<(), QuicError> {
        write_event(&mut self.send, ev).await?;
        Ok(())
    }

    pub async fn read_event(&mut self) -> Result<SignedEvent, QuicError> {
        Ok(read_event(&mut self.recv).await?)
    }
}

/// Dial a peer over QUIC and open a bidirectional stream.
pub async fn quic_dial(uri: &PeerUri) -> Result<QuicStream, QuicError> {
    if !uri.quic {
        return Err(QuicError::InvalidUri(
            "expected td-quic:// peer uri".into(),
        ));
    }
    let addr: SocketAddr = uri
        .socket_addr()
        .parse()
        .map_err(|e| QuicError::InvalidUri(format!("{}: {e}", uri.socket_addr())))?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(map_q)?;
    endpoint.set_default_client_config(client_config()?);
    let conn = endpoint
        .connect(addr, "td-pond")
        .map_err(map_q)?
        .await
        .map_err(map_q)?;
    let (send, recv) = conn.open_bi().await.map_err(map_q)?;
    Ok(QuicStream {
        _endpoint: endpoint,
        _conn: conn,
        send,
        recv,
    })
}

/// Accept one inbound QUIC connection and its first bi stream.
///
/// Clones the endpoint handle so the stream keeps the UDP socket alive.
pub async fn quic_accept(endpoint: &Endpoint) -> Result<QuicStream, QuicError> {
    let incoming = endpoint.accept().await.ok_or(QuicError::Closed)?;
    let conn = incoming.await.map_err(map_q)?;
    let (send, recv) = conn.accept_bi().await.map_err(map_q)?;
    Ok(QuicStream {
        _endpoint: endpoint.clone(),
        _conn: conn,
        send,
        recv,
    })
}

/// Parse helper: true when URI scheme is td-quic.
pub fn is_quic_uri(s: &str) -> bool {
    s.trim().starts_with("td-quic://")
}

#[cfg(test)]
mod tests {
    use super::*;
    use td_crypto::DeviceKeypair;
    use td_event::{sign_event, EventKind, RoomId, UnsignedEvent};

    #[tokio::test]
    async fn quic_roundtrip_signed_event() {
        let (ep, addr) = quic_listen("127.0.0.1:0").await.unwrap();
        let uri = PeerUri {
            host: addr.ip().to_string(),
            port: addr.port(),
            noise: false,
            quic: true,
        };

        let server = tokio::spawn(async move {
            let mut s = quic_accept(&ep).await.expect("quic accept");
            let ev = s.read_event().await.expect("server read");
            s.write_event(&ev).await.expect("server write");
            // Hold the connection until the client finishes reading / drops.
            let _ = s.read_event().await;
            ev
        });

        // Ensure accept is armed before dial.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let kp = DeviceKeypair::generate();
        let signed = sign_event(
            kp.signing_key(),
            UnsignedEvent {
                room_id: RoomId::from_bytes([0x51u8; 32]),
                parents: vec![],
                kind: EventKind::Message,
                payload: b"quic-honk".to_vec(),
                author_device: kp.event_device_id(),
                ts_ms: 7,
            },
        )
        .unwrap();

        let mut client = quic_dial(&uri).await.expect("quic dial");
        client.write_event(&signed).await.expect("client write");
        let got = client.read_event().await.expect("client read");
        assert_eq!(got.id, signed.id);
        assert_eq!(got.payload, b"quic-honk");
        drop(client);
        let server_ev = server.await.expect("server task");
        assert_eq!(server_ev.id, signed.id);
    }
}
