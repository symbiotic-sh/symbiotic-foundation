//! App-owned thread-mode egress through the existing credential boundary.

use crate::CredentialProcess;
use async_trait::async_trait;
use symbiotic_egress::{
    EgressClient, EgressError, PROTOCOL_VERSION, Request, Response, encode_frame,
};

/// Cloneable in-process client using the same protocol handler as the socket server.
/// Each exchange runs on a Foundation-owned Tokio task. Dropping the caller's
/// future leaves that task running, including completion and receipt persistence.
#[derive(Clone)]
pub struct InProcessEgressClient {
    process: CredentialProcess,
}

impl InProcessEgressClient {
    /// Attach to a process opened through [`CredentialProcess::open`], which applies
    /// process protection before loading secrets. No socket is bound or required.
    pub fn new(process: CredentialProcess) -> Self {
        Self { process }
    }
}

#[async_trait]
impl EgressClient for InProcessEgressClient {
    async fn exchange(&self, request: Request) -> Result<Response, EgressError> {
        let limit = self.process.config().max_frame_bytes;
        let bytes = encode_frame(&request, limit)?;
        // Check wire decodability (including nesting limits), but validate the
        // original typed request: JSON turns nonfinite temperatures into null.
        if serde_json::from_slice::<Request>(&bytes).is_err() {
            return Ok(Response {
                version: PROTOCOL_VERSION,
                result: Err(EgressError::InvalidRequest),
            });
        }
        let process = self.process.clone();
        tokio::spawn(async move {
            let response = process.handle(request).await;
            match encode_frame(&response, limit) {
                Ok(_) => response,
                Err(error) => Response {
                    version: response.version,
                    result: Err(error),
                },
            }
        })
        .await
        .map_err(|_| EgressError::Transport)
    }
}
