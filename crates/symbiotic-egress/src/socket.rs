//! Bounded big-endian u32 length-prefixed JSON over a local Unix socket.
use crate::{EgressClient, EgressError, PROTOCOL_VERSION, Request, Response};
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use std::{path::PathBuf, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read exactly one frame; refuse an oversized length before allocating its body.
pub async fn read_frame<T: DeserializeOwned>(
    reader: &mut (impl AsyncRead + Unpin),
    max_bytes: u32,
) -> Result<T, EgressError> {
    let len = reader
        .read_u32()
        .await
        .map_err(|_| EgressError::Transport)?;
    if len == 0 || len > max_bytes {
        return Err(EgressError::LimitExceeded);
    }
    let mut bytes = vec![0; len as usize];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|_| EgressError::Transport)?;
    serde_json::from_slice(&bytes).map_err(|_| EgressError::InvalidRequest)
}

/// Write one bounded frame. Serialization uses a capped writer.
pub async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
    max_bytes: u32,
) -> Result<(), EgressError> {
    struct Capped {
        bytes: Vec<u8>,
        max: usize,
    }
    impl std::io::Write for Capped {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len().saturating_add(buf.len()) > self.max {
                return Err(std::io::Error::other("frame limit"));
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut buffer = Capped {
        bytes: Vec::new(),
        max: max_bytes as usize,
    };
    serde_json::to_writer(&mut buffer, value).map_err(|_| EgressError::LimitExceeded)?;
    writer
        .write_u32(buffer.bytes.len() as u32)
        .await
        .map_err(|_| EgressError::Transport)?;
    writer
        .write_all(&buffer.bytes)
        .await
        .map_err(|_| EgressError::Transport)?;
    Ok(())
}

/// Configurable local transport. A timeout does not authorize another provider attempt.
#[derive(Clone, Debug)]
pub struct UnixEgressClient {
    /// Socket in an owner-only directory.
    pub path: PathBuf,
    /// Maximum encoded request and response bytes.
    pub max_frame_bytes: u32,
    /// Total exchange timeout.
    pub timeout: Duration,
}

#[async_trait]
impl EgressClient for UnixEgressClient {
    async fn exchange(&self, request: Request) -> Result<Response, EgressError> {
        tokio::time::timeout(self.timeout, async {
            use std::os::unix::fs::MetadataExt;
            let parent = self.path.parent().ok_or(EgressError::Unauthorized)?;
            let metadata =
                std::fs::symlink_metadata(parent).map_err(|_| EgressError::Unauthorized)?;
            // SAFETY: geteuid has no preconditions and does not access memory.
            let uid = unsafe { libc::geteuid() };
            if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                return Err(EgressError::Unauthorized);
            }
            let mut stream = tokio::net::UnixStream::connect(&self.path)
                .await
                .map_err(|_| EgressError::Transport)?;
            if stream
                .peer_cred()
                .map_err(|_| EgressError::Unauthorized)?
                .uid()
                != uid
            {
                return Err(EgressError::Unauthorized);
            }
            let response: Response = {
                write_frame(&mut stream, &request, self.max_frame_bytes).await?;
                read_frame(&mut stream, self.max_frame_bytes).await?
            };
            if response.version != PROTOCOL_VERSION {
                return Err(EgressError::Version);
            }
            Ok(response)
        })
        .await
        .map_err(|_| EgressError::Transport)?
    }
}
