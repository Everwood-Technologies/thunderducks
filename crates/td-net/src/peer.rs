use crate::frame::{read_event, write_event, FrameError};
use std::net::SocketAddr;
use td_event::SignedEvent;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Error)]
pub enum PeerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("invalid peer uri: {0}")]
    InvalidUri(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerUri {
    pub host: String,
    pub port: u16,
    /// When true, dial/accept should use Noise_XX transport.
    pub noise: bool,
    /// When true, dial/accept should use QUIC (`td-quic://`).
    pub quic: bool,
}

impl PeerUri {
    pub fn parse(s: &str) -> Result<Self, PeerError> {
        // td://host:port | td-noise://host:port | td-quic://host:port | host:port
        let (rest, noise, quic) = if let Some(r) = s.strip_prefix("td-quic://") {
            (r, false, true)
        } else if let Some(r) = s.strip_prefix("td-noise://") {
            (r, true, false)
        } else if let Some(r) = s.strip_prefix("td://") {
            (r, false, false)
        } else {
            (s, false, false)
        };
        let (host, port_s) = rest
            .rsplit_once(':')
            .ok_or_else(|| PeerError::InvalidUri(s.to_string()))?;
        let port: u16 = port_s
            .parse()
            .map_err(|_| PeerError::InvalidUri(s.to_string()))?;
        Ok(Self {
            host: host.to_string(),
            port,
            noise,
            quic,
        })
    }

    pub fn from_tcp_addr(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
            noise: false,
            quic: false,
        }
    }

    pub fn from_tcp_addr_noise(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
            noise: true,
            quic: false,
        }
    }

    pub fn from_tcp_addr_quic(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
            noise: false,
            quic: true,
        }
    }

    pub fn to_string_uri(&self) -> String {
        if self.quic {
            format!("td-quic://{}:{}", self.host, self.port)
        } else if self.noise {
            format!("td-noise://{}:{}", self.host, self.port)
        } else {
            format!("td://{}:{}", self.host, self.port)
        }
    }

    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub async fn dial(uri: &PeerUri) -> Result<TcpStream, PeerError> {
    Ok(TcpStream::connect(uri.socket_addr()).await?)
}

pub async fn accept_once(listener: &TcpListener) -> Result<TcpStream, PeerError> {
    let (s, _) = listener.accept().await?;
    Ok(s)
}

/// Simple one-shot: listen, read one event, write it back.
pub async fn serve_exchange(addr: &str) -> Result<(PeerUri, SignedEvent), PeerError> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let mut sock = accept_once(&listener).await?;
    let ev = read_event(&mut sock).await?;
    write_event(&mut sock, &ev).await?;
    Ok((PeerUri::from_tcp_addr(local), ev))
}
