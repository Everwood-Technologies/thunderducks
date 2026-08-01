//! QUIC P2P transport.
//!
//! URI: `td-quic://host:port`
//!
//! Frames above QUIC stay length-prefixed JSON signed events (same as TCP).
//! TLS is rustls; default is self-signed identity (dev / pond LAN).
//! Production peers: **blake3 cert pins** + optional **mTLS** (`QuicTlsConfig`).
//!
//! ALPN: `td-p2p/1`
//!
//! Pin format: lowercase hex blake3 of the **leaf certificate DER** (64 hex chars).

use crate::frame::{read_event, write_event, FrameError};
use crate::peer::{PeerError, PeerUri};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use std::net::SocketAddr;
use std::path::Path;
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
    #[error("pin: {0}")]
    Pin(String),
}

impl From<PeerError> for QuicError {
    fn from(e: PeerError) -> Self {
        Self::InvalidUri(e.to_string())
    }
}

fn map_q<E: std::fmt::Display>(e: E) -> QuicError {
    QuicError::Quinn(e.to_string())
}

/// blake3 pin of a leaf certificate DER (32 bytes).
pub fn cert_pin_blake3(cert: &CertificateDer<'_>) -> [u8; 32] {
    *blake3::hash(cert.as_ref()).as_bytes()
}

/// Hex (lowercase) form of [`cert_pin_blake3`].
pub fn cert_pin_hex(cert: &CertificateDer<'_>) -> String {
    hex::encode(cert_pin_blake3(cert))
}

/// Parse comma/whitespace-separated 64-hex blake3 pins.
pub fn parse_pin_list(s: &str) -> Result<Vec<[u8; 32]>, QuicError> {
    let mut out = Vec::new();
    for part in s.split(|c: char| c == ',' || c.is_whitespace()) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let bytes = hex::decode(p).map_err(|e| QuicError::Pin(format!("bad pin hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(QuicError::Pin(format!(
                "pin must be 32 bytes (64 hex), got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        out.push(arr);
    }
    Ok(out)
}

fn pin_allowed(pins: &[[u8; 32]], cert: &CertificateDer<'_>) -> bool {
    if pins.is_empty() {
        return false;
    }
    let got = cert_pin_blake3(cert);
    pins.iter().any(|p| p == &got)
}

/// TLS identity + pin / mTLS policy for QUIC.
pub struct QuicTlsConfig {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// Allowed peer leaf-cert blake3 pins. When non-empty, peers must match.
    pub peer_pins: Vec<[u8; 32]>,
    /// Require and verify client certificates (mTLS).
    pub require_client_auth: bool,
    /// Dev-only: skip server cert verification when `peer_pins` is empty.
    pub insecure_skip_verify: bool,
    /// SNI / server name used on dial (default `td-pond`).
    pub server_name: String,
}

impl Clone for QuicTlsConfig {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
            peer_pins: self.peer_pins.clone(),
            require_client_auth: self.require_client_auth,
            insecure_skip_verify: self.insecure_skip_verify,
            server_name: self.server_name.clone(),
        }
    }
}

impl std::fmt::Debug for QuicTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTlsConfig")
            .field("certs", &self.certs.len())
            .field("peer_pins", &self.peer_pins.len())
            .field("require_client_auth", &self.require_client_auth)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("server_name", &self.server_name)
            .field("local_pin", &self.local_pin_hex())
            .finish()
    }
}

impl QuicTlsConfig {
    /// Dev default: ephemeral self-signed, skip verify, no mTLS.
    pub fn insecure_ephemeral() -> Result<Self, QuicError> {
        let (certs, key) = self_signed_cert()?;
        Ok(Self {
            certs,
            key,
            peer_pins: vec![],
            require_client_auth: false,
            insecure_skip_verify: true,
            server_name: "td-pond".into(),
        })
    }

    /// Production-ish: identity PEMs + pin list + optional mTLS.
    pub fn from_pem_files(
        cert_path: &Path,
        key_path: &Path,
        peer_pins: Vec<[u8; 32]>,
        require_client_auth: bool,
    ) -> Result<Self, QuicError> {
        let (certs, key) = load_pem_identity(cert_path, key_path)?;
        let insecure = peer_pins.is_empty() && !require_client_auth;
        Ok(Self {
            certs,
            key,
            peer_pins,
            require_client_auth,
            insecure_skip_verify: insecure,
            server_name: "td-pond".into(),
        })
    }

    pub fn local_pin(&self) -> Option<[u8; 32]> {
        self.certs.first().map(cert_pin_blake3)
    }

    pub fn local_pin_hex(&self) -> Option<String> {
        self.certs.first().map(cert_pin_hex)
    }

    pub fn with_pins(mut self, pins: Vec<[u8; 32]>) -> Self {
        self.peer_pins = pins;
        if !self.peer_pins.is_empty() {
            self.insecure_skip_verify = false;
        }
        self
    }

    pub fn with_mtls(mut self, on: bool) -> Self {
        self.require_client_auth = on;
        if on {
            self.insecure_skip_verify = false;
        }
        self
    }
}

/// Load cert chain + private key from PEM files.
pub fn load_pem_identity(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), QuicError> {
    ensure_crypto_provider();
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| QuicError::Tls(format!("cert pem: {e}")))?;
    if certs.is_empty() {
        return Err(QuicError::Tls("no certificates in cert pem".into()));
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| QuicError::Tls(format!("key pem: {e}")))?
        .ok_or_else(|| QuicError::Tls("no private key in key pem".into()))?;
    Ok((certs, key))
}

/// Generate a self-signed cert for pond QUIC (dev / LAN).
pub fn self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), QuicError>
{
    ensure_crypto_provider();
    let key_pair = KeyPair::generate().map_err(|e| QuicError::Tls(e.to_string()))?;
    let mut params = CertificateParams::new(vec!["localhost".into(), "td-pond".into()])
        .map_err(|e| QuicError::Tls(e.to_string()))?;
    params.subject_alt_names.push(SanType::DnsName(
        "localhost"
            .try_into()
            .map_err(|e: rcgen::Error| QuicError::Tls(e.to_string()))?,
    ));
    params.subject_alt_names.push(SanType::DnsName(
        "td-pond"
            .try_into()
            .map_err(|e: rcgen::Error| QuicError::Tls(e.to_string()))?,
    ));
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| QuicError::Tls(e.to_string()))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok((vec![cert_der], key_der))
}

/// Write a fresh self-signed identity to PEM paths; returns config.
pub fn write_self_signed_pem(cert_path: &Path, key_path: &Path) -> Result<QuicTlsConfig, QuicError> {
    let (certs, key) = self_signed_cert()?;
    let cert_pem = {
        let mut out = String::new();
        for c in &certs {
            out.push_str("-----BEGIN CERTIFICATE-----\n");
            let b64 = base64_std(c.as_ref());
            for chunk in b64.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(chunk).unwrap());
                out.push('\n');
            }
            out.push_str("-----END CERTIFICATE-----\n");
        }
        out
    };
    // PKCS#8 PEM for key
    let key_raw = match &key {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        PrivateKeyDer::Sec1(k) => k.secret_sec1_der().to_vec(),
        PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der().to_vec(),
        _ => return Err(QuicError::Tls("unsupported key type for pem export".into())),
    };
    let key_pem = {
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        let b64 = base64_std(&key_raw);
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out
    };
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_path, cert_pem)?;
    std::fs::write(key_path, key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644));
    }
    Ok(QuicTlsConfig {
        certs,
        key,
        peer_pins: vec![],
        require_client_auth: false,
        insecure_skip_verify: true,
        server_name: "td-pond".into(),
    })
}

fn base64_std(data: &[u8]) -> String {
    // Minimal base64 without extra dep — use a tiny encoder.
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize]);
        out.push(T[((n >> 12) & 63) as usize]);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize]
        } else {
            b'='
        });
    }
    String::from_utf8(out).expect("base64 alphabet is ascii")
}

// --- verifiers ---

#[derive(Debug)]
struct PinOrSkipServerVerifier {
    pins: Vec<[u8; 32]>,
    skip: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinOrSkipServerVerifier {
    fn new(pins: Vec<[u8; 32]>, skip: bool) -> Arc<Self> {
        Arc::new(Self {
            pins,
            skip,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }
}

impl ServerCertVerifier for PinOrSkipServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if !self.pins.is_empty() {
            if pin_allowed(&self.pins, end_entity) {
                return Ok(ServerCertVerified::assertion());
            }
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        if self.skip {
            return Ok(ServerCertVerified::assertion());
        }
        Err(TlsError::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct PinClientCertVerifier {
    pins: Vec<[u8; 32]>,
    /// When pins empty, accept any client cert that presents (signature still checked by rustls).
    allow_any: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
    subjects: Vec<DistinguishedName>,
}

impl PinClientCertVerifier {
    fn new(pins: Vec<[u8; 32]>, allow_any: bool) -> Arc<Self> {
        Arc::new(Self {
            pins,
            allow_any,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            subjects: Vec::new(),
        })
    }
}

impl ClientCertVerifier for PinClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if !self.pins.is_empty() {
            if pin_allowed(&self.pins, end_entity) {
                return Ok(ClientCertVerified::assertion());
            }
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        if self.allow_any {
            return Ok(ClientCertVerified::assertion());
        }
        Err(TlsError::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn server_config(cfg: &QuicTlsConfig) -> Result<ServerConfig, QuicError> {
    ensure_crypto_provider();
    let certs = cfg.certs.clone();
    let key = cfg.key.clone_key();
    let mut server_crypto = if cfg.require_client_auth {
        let verifier = PinClientCertVerifier::new(cfg.peer_pins.clone(), cfg.peer_pins.is_empty());
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| QuicError::Tls(e.to_string()))?
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| QuicError::Tls(e.to_string()))?
    };
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

fn client_config(cfg: &QuicTlsConfig) -> Result<ClientConfig, QuicError> {
    ensure_crypto_provider();
    let verifier =
        PinOrSkipServerVerifier::new(cfg.peer_pins.clone(), cfg.insecure_skip_verify);
    let builder = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(verifier);
    let mut crypto = if cfg.require_client_auth || !cfg.certs.is_empty() {
        // Always present client identity when we have one (enables mTLS when server asks).
        builder
            .with_client_auth_cert(cfg.certs.clone(), cfg.key.clone_key())
            .map_err(|e| QuicError::Tls(format!("client auth cert: {e}")))?
    } else {
        builder.with_no_client_auth()
    };
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| QuicError::Tls(e.to_string()))?;
    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

/// Open a QUIC server endpoint on `bind` (e.g. `0.0.0.0:0`) with optional TLS policy.
pub async fn quic_listen(bind: &str) -> Result<(Endpoint, SocketAddr), QuicError> {
    quic_listen_with_config(bind, &QuicTlsConfig::insecure_ephemeral()?).await
}

pub async fn quic_listen_with_config(
    bind: &str,
    cfg: &QuicTlsConfig,
) -> Result<(Endpoint, SocketAddr), QuicError> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| QuicError::InvalidUri(format!("{bind}: {e}")))?;
    let endpoint = Endpoint::server(server_config(cfg)?, addr).map_err(map_q)?;
    let local = endpoint.local_addr().map_err(map_q)?;
    Ok((endpoint, local))
}

/// Bidirectional framed stream over QUIC.
///
/// Holds `Endpoint` + `Connection` so the UDP socket stays alive for the stream lifetime.
#[derive(Debug)]
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

/// Dial a peer over QUIC (insecure ephemeral client identity).
pub async fn quic_dial(uri: &PeerUri) -> Result<QuicStream, QuicError> {
    quic_dial_with_config(uri, &QuicTlsConfig::insecure_ephemeral()?).await
}

/// Dial with explicit TLS policy (pins / mTLS / identity).
pub async fn quic_dial_with_config(
    uri: &PeerUri,
    cfg: &QuicTlsConfig,
) -> Result<QuicStream, QuicError> {
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
    endpoint.set_default_client_config(client_config(cfg)?);
    let server_name = cfg.server_name.as_str();
    let conn = endpoint
        .connect(addr, server_name)
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

    fn sample_event(payload: &[u8]) -> SignedEvent {
        let kp = DeviceKeypair::generate();
        sign_event(
            kp.signing_key(),
            UnsignedEvent {
                room_id: RoomId::from_bytes([0x51u8; 32]),
                parents: vec![],
                kind: EventKind::Message,
                payload: payload.to_vec(),
                author_device: kp.event_device_id(),
                ts_ms: 7,
            },
        )
        .unwrap()
    }

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
            let _ = s.read_event().await;
            ev
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let signed = sample_event(b"quic-honk");
        let mut client = quic_dial(&uri).await.expect("quic dial");
        client.write_event(&signed).await.expect("client write");
        let got = client.read_event().await.expect("client read");
        assert_eq!(got.id, signed.id);
        assert_eq!(got.payload, b"quic-honk");
        drop(client);
        let server_ev = server.await.expect("server task");
        assert_eq!(server_ev.id, signed.id);
    }

    #[tokio::test]
    async fn quic_pin_accepts_matching_peer() {
        let server_id = QuicTlsConfig::insecure_ephemeral().unwrap();
        let pin = server_id.local_pin().unwrap();
        let server_cfg = server_id.clone().with_pins(vec![pin]).with_mtls(true);

        // Client must present a cert whose pin is allowed on server.
        let client_id = QuicTlsConfig::insecure_ephemeral().unwrap();
        let client_pin = client_id.local_pin().unwrap();
        // Server allows this client pin; client pins the server.
        let server_cfg = QuicTlsConfig {
            peer_pins: vec![client_pin],
            ..server_cfg
        };
        let client_cfg = client_id.with_pins(vec![pin]).with_mtls(true);

        let (ep, addr) = quic_listen_with_config("127.0.0.1:0", &server_cfg)
            .await
            .unwrap();
        let uri = PeerUri::from_tcp_addr_quic(addr);

        let server = tokio::spawn(async move {
            let mut s = quic_accept(&ep).await.expect("accept");
            let ev = s.read_event().await.expect("read");
            s.write_event(&ev).await.expect("write");
            let _ = s.read_event().await;
            ev
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let signed = sample_event(b"pinned");
        let mut client = quic_dial_with_config(&uri, &client_cfg)
            .await
            .expect("dial pinned");
        client.write_event(&signed).await.unwrap();
        let got = client.read_event().await.unwrap();
        assert_eq!(got.payload, b"pinned");
        drop(client);
        assert_eq!(server.await.unwrap().id, signed.id);
    }

    #[tokio::test]
    async fn quic_pin_rejects_wrong_server() {
        let server_cfg = QuicTlsConfig::insecure_ephemeral()
            .unwrap()
            .with_mtls(false);
        let wrong_pin = [0xABu8; 32];
        let client_cfg = QuicTlsConfig::insecure_ephemeral()
            .unwrap()
            .with_pins(vec![wrong_pin]);

        let (ep, addr) = quic_listen_with_config("127.0.0.1:0", &server_cfg)
            .await
            .unwrap();
        let uri = PeerUri::from_tcp_addr_quic(addr);

        let _server = tokio::spawn(async move {
            // Accept may fail during handshake when client aborts — that's ok.
            let _ = quic_accept(&ep).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let err = quic_dial_with_config(&uri, &client_cfg)
            .await
            .expect_err("must reject bad pin");
        let msg = err.to_string();
        assert!(
            msg.contains("pin")
                || msg.contains("TLS")
                || msg.contains("tls")
                || msg.contains("quic")
                || msg.contains("Connection"),
            "unexpected err: {msg}"
        );
    }

    #[tokio::test]
    async fn quic_mtls_rejects_unknown_client() {
        let server_id = QuicTlsConfig::insecure_ephemeral().unwrap();
        let server_pin = server_id.local_pin().unwrap();
        // Server only trusts a pin that is NOT the client we will use.
        let only_trusted = [0x11u8; 32];
        let server_cfg = QuicTlsConfig {
            peer_pins: vec![only_trusted],
            require_client_auth: true,
            insecure_skip_verify: false,
            ..server_id
        };

        let client_cfg = QuicTlsConfig::insecure_ephemeral()
            .unwrap()
            .with_pins(vec![server_pin])
            .with_mtls(true);

        let (ep, addr) = quic_listen_with_config("127.0.0.1:0", &server_cfg)
            .await
            .unwrap();
        let uri = PeerUri::from_tcp_addr_quic(addr);
        let server = tokio::spawn(async move { quic_accept(&ep).await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client_res = quic_dial_with_config(&uri, &client_cfg).await;
        // Drive the connection briefly so the server finishes cert checks.
        let client_io_failed = match client_res {
            Err(_) => true,
            Ok(mut c) => {
                if c.write_event(&sample_event(b"should-fail")).await.is_err() {
                    true
                } else {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    // Connection may die on next IO after server rejects.
                    c.read_event().await.is_err()
                }
            }
        };
        let server_res = server.await.expect("server task");

        // Either side must observe the pin failure (client dial/IO or server accept).
        let server_failed = server_res.is_err();
        assert!(
            client_io_failed || server_failed,
            "mTLS must reject unknown client pin (client_io_failed={client_io_failed} server_failed={server_failed})"
        );
    }

    #[test]
    fn parse_pins_roundtrip() {
        let (certs, _) = self_signed_cert().unwrap();
        let hex = cert_pin_hex(&certs[0]);
        let list = parse_pin_list(&format!("{hex}, {hex}")).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], cert_pin_blake3(&certs[0]));
    }
}
