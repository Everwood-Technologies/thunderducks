//! Thin client for untrusted assist relays.

use crate::peer::{dial, PeerError, PeerUri};
use crate::relay_proto::{
    read_json, write_json, RelayEnvelope, RelayProtoError, RelayRequest, RelayResponse,
};
use td_event::DeviceId;
use thiserror::Error;
use tokio::net::TcpStream;

#[derive(Debug, Error)]
pub enum RelayClientError {
    #[error(transparent)]
    Peer(#[from] PeerError),
    #[error(transparent)]
    Proto(#[from] RelayProtoError),
    #[error("relay error: {0}")]
    Remote(String),
    #[error("unexpected response")]
    Unexpected,
}

pub struct RelayClient {
    stream: TcpStream,
}

impl RelayClient {
    pub async fn connect(uri: &PeerUri) -> Result<Self, RelayClientError> {
        Ok(Self {
            stream: dial(uri).await?,
        })
    }

    pub async fn put(&mut self, envelope: RelayEnvelope) -> Result<(), RelayClientError> {
        write_json(&mut self.stream, &RelayRequest::Put { envelope }).await?;
        match read_json::<_, RelayResponse>(&mut self.stream).await? {
            RelayResponse::Ok => Ok(()),
            RelayResponse::Err { message } => Err(RelayClientError::Remote(message)),
            _ => Err(RelayClientError::Unexpected),
        }
    }

    pub async fn fetch(
        &mut self,
        recipient: DeviceId,
        since_ts: u64,
        limit: u32,
    ) -> Result<Vec<RelayEnvelope>, RelayClientError> {
        write_json(
            &mut self.stream,
            &RelayRequest::Fetch {
                recipient,
                since_ts,
                limit,
            },
        )
        .await?;
        match read_json::<_, RelayResponse>(&mut self.stream).await? {
            RelayResponse::Envelopes { items } => Ok(items),
            RelayResponse::Err { message } => Err(RelayClientError::Remote(message)),
            _ => Err(RelayClientError::Unexpected),
        }
    }

    pub async fn ack(
        &mut self,
        recipient: DeviceId,
        envelope_ids: Vec<[u8; 32]>,
    ) -> Result<(), RelayClientError> {
        write_json(
            &mut self.stream,
            &RelayRequest::Ack {
                recipient,
                envelope_ids,
            },
        )
        .await?;
        match read_json::<_, RelayResponse>(&mut self.stream).await? {
            RelayResponse::Ok => Ok(()),
            RelayResponse::Err { message } => Err(RelayClientError::Remote(message)),
            _ => Err(RelayClientError::Unexpected),
        }
    }
}
