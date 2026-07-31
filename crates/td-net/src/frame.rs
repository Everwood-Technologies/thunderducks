use bytes::BytesMut;
use td_event::SignedEvent;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum FrameError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("frame too large: {0} bytes")]
    TooLarge(u32),
    #[error("connection closed")]
    Closed,
}

const MAX_FRAME: u32 = 16 * 1024 * 1024;

pub async fn write_event<W: AsyncWrite + Unpin>(
    w: &mut W,
    ev: &SignedEvent,
) -> Result<(), FrameError> {
    let body = serde_json::to_vec(ev)?;
    let len = body.len() as u32;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    w.write_u32(len).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_event<R: AsyncRead + Unpin>(r: &mut R) -> Result<SignedEvent, FrameError> {
    let len = match r.read_u32().await {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(e.into()),
    };
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = BytesMut::zeroed(len as usize);
    r.read_exact(&mut buf).await?;
    let ev: SignedEvent = serde_json::from_slice(&buf)?;
    Ok(ev)
}
