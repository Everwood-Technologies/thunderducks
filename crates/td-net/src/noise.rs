//! Noise transport for P2P and relay TCP (Noise_XX_25519_ChaChaPoly_BLAKE2s).
//!
//! Wraps a `TcpStream` after a mutual handshake. Frames above this layer stay
//! length-prefixed JSON; Noise provides transport confidentiality + integrity.
//!
//! Pattern **XX**: both sides send ephemeral + static keys (no prior knowledge).
//! Static keys are ephemeral per process unless the caller injects a fixed secret.

use snow::params::NoiseParams;
use snow::{Builder, TransportState};
use std::sync::OnceLock;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_NOISE_MSG: usize = 65535;
const TAG_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("noise: {0}")]
    Snow(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("handshake incomplete")]
    Incomplete,
    #[error("payload too large")]
    TooLarge,
    #[error("connection closed")]
    Closed,
}

fn noise_params() -> &'static NoiseParams {
    static P: OnceLock<NoiseParams> = OnceLock::new();
    P.get_or_init(|| {
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("valid noise pattern")
    })
}

fn map_snow(e: snow::Error) -> NoiseError {
    NoiseError::Snow(e.to_string())
}

/// Bidirectional Noise-secured stream over TCP.
pub struct NoiseTcpStream {
    tcp: TcpStream,
    transport: TransportState,
    /// Leftover decrypted bytes from a previous read_exact-style fill.
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl NoiseTcpStream {
    /// Initiator handshake (client / dialer).
    pub async fn handshake_initiator(mut tcp: TcpStream) -> Result<Self, NoiseError> {
        let builder = Builder::new(noise_params().clone());
        let static_key = builder.generate_keypair().map_err(map_snow)?;
        let state = builder
            .local_private_key(&static_key.private)
            .build_initiator()
            .map_err(map_snow)?;
        let transport = run_xx_handshake(&mut tcp, state, true).await?;
        Ok(Self {
            tcp,
            transport,
            read_buf: Vec::new(),
            read_pos: 0,
        })
    }

    /// Responder handshake (server / acceptor).
    pub async fn handshake_responder(mut tcp: TcpStream) -> Result<Self, NoiseError> {
        let builder = Builder::new(noise_params().clone());
        let static_key = builder.generate_keypair().map_err(map_snow)?;
        let state = builder
            .local_private_key(&static_key.private)
            .build_responder()
            .map_err(map_snow)?;
        let transport = run_xx_handshake(&mut tcp, state, false).await?;
        Ok(Self {
            tcp,
            transport,
            read_buf: Vec::new(),
            read_pos: 0,
        })
    }

    /// Write a full application message (length-prefixed Noise transport frame).
    pub async fn write_msg(&mut self, payload: &[u8]) -> Result<(), NoiseError> {
        if payload.len() + TAG_LEN > MAX_NOISE_MSG {
            return Err(NoiseError::TooLarge);
        }
        let mut buf = vec![0u8; payload.len() + TAG_LEN];
        let n = self
            .transport
            .write_message(payload, &mut buf)
            .map_err(map_snow)?;
        let len = n as u16;
        self.tcp.write_u16(len).await?;
        self.tcp.write_all(&buf[..n]).await?;
        self.tcp.flush().await?;
        Ok(())
    }

    /// Read one application message.
    pub async fn read_msg(&mut self) -> Result<Vec<u8>, NoiseError> {
        let len = match self.tcp.read_u16().await {
            Ok(n) => n as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(NoiseError::Closed)
            }
            Err(e) => return Err(e.into()),
        };
        if len > MAX_NOISE_MSG {
            return Err(NoiseError::TooLarge);
        }
        let mut enc = vec![0u8; len];
        self.tcp.read_exact(&mut enc).await?;
        let mut out = vec![0u8; len];
        let n = self
            .transport
            .read_message(&enc, &mut out)
            .map_err(map_snow)?;
        out.truncate(n);
        Ok(out)
    }

    /// AsyncWrite-style: encrypt and send raw bytes as one Noise message.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), NoiseError> {
        // Chunk large payloads.
        let max_plain = MAX_NOISE_MSG - TAG_LEN - 4;
        let mut off = 0;
        while off < data.len() {
            let end = (off + max_plain).min(data.len());
            self.write_msg(&data[off..end]).await?;
            off = end;
        }
        Ok(())
    }

    /// Fill `buf` exactly (like read_exact) from decrypted stream.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), NoiseError> {
        let mut filled = 0;
        while filled < buf.len() {
            if self.read_pos < self.read_buf.len() {
                let n = (self.read_buf.len() - self.read_pos).min(buf.len() - filled);
                buf[filled..filled + n]
                    .copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                filled += n;
                continue;
            }
            let msg = self.read_msg().await?;
            self.read_buf = msg;
            self.read_pos = 0;
            if self.read_buf.is_empty() {
                return Err(NoiseError::Closed);
            }
        }
        Ok(())
    }
}

async fn run_xx_handshake(
    tcp: &mut TcpStream,
    mut state: snow::HandshakeState,
    initiator: bool,
) -> Result<TransportState, NoiseError> {
    let mut buf = vec![0u8; MAX_NOISE_MSG];
    // XX: -> e, <- e es s ss, -> s es  (3 messages)
    if initiator {
        // msg 1
        let n = state.write_message(&[], &mut buf).map_err(map_snow)?;
        write_raw(tcp, &buf[..n]).await?;
        // msg 2
        let msg = read_raw(tcp).await?;
        state.read_message(&msg, &mut buf).map_err(map_snow)?;
        // msg 3
        let n = state.write_message(&[], &mut buf).map_err(map_snow)?;
        write_raw(tcp, &buf[..n]).await?;
    } else {
        // msg 1
        let msg = read_raw(tcp).await?;
        state.read_message(&msg, &mut buf).map_err(map_snow)?;
        // msg 2
        let n = state.write_message(&[], &mut buf).map_err(map_snow)?;
        write_raw(tcp, &buf[..n]).await?;
        // msg 3
        let msg = read_raw(tcp).await?;
        state.read_message(&msg, &mut buf).map_err(map_snow)?;
    }
    state.into_transport_mode().map_err(map_snow)
}

async fn write_raw(tcp: &mut TcpStream, data: &[u8]) -> Result<(), NoiseError> {
    let len = data.len() as u16;
    tcp.write_u16(len).await?;
    tcp.write_all(data).await?;
    tcp.flush().await?;
    Ok(())
}

async fn read_raw(tcp: &mut TcpStream) -> Result<Vec<u8>, NoiseError> {
    let len = tcp.read_u16().await? as usize;
    if len > MAX_NOISE_MSG {
        return Err(NoiseError::TooLarge);
    }
    let mut buf = vec![0u8; len];
    tcp.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Length-prefixed JSON over Noise (relay + generic RPC-ish frames).
pub async fn noise_write_json<T: serde::Serialize>(
    s: &mut NoiseTcpStream,
    v: &T,
) -> Result<(), NoiseError> {
    let body = serde_json::to_vec(v).map_err(|e| NoiseError::Snow(e.to_string()))?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    s.write_all(&frame).await
}

pub async fn noise_read_json<T: serde::de::DeserializeOwned>(
    s: &mut NoiseTcpStream,
) -> Result<T, NoiseError> {
    let mut len_buf = [0u8; 4];
    s.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(NoiseError::TooLarge);
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| NoiseError::Snow(e.to_string()))
}

/// SignedEvent frames over Noise (P2P path).
pub async fn noise_write_event(
    s: &mut NoiseTcpStream,
    ev: &td_event::SignedEvent,
) -> Result<(), NoiseError> {
    noise_write_json(s, ev).await
}

pub async fn noise_read_event(s: &mut NoiseTcpStream) -> Result<td_event::SignedEvent, NoiseError> {
    noise_read_json(s).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn noise_roundtrip_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut s = NoiseTcpStream::handshake_responder(tcp).await.unwrap();
            let msg = s.read_msg().await.unwrap();
            assert_eq!(msg, b"honk-secure");
            s.write_msg(b"ack").await.unwrap();
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut c = NoiseTcpStream::handshake_initiator(tcp).await.unwrap();
        c.write_msg(b"honk-secure").await.unwrap();
        let reply = c.read_msg().await.unwrap();
        assert_eq!(reply, b"ack");
        server.await.unwrap();
    }
}
