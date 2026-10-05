//! App-owned thread-mode egress through the existing credential boundary.

use crate::CredentialProcess;
use async_trait::async_trait;
use std::sync::Arc;
use symbiotic_egress::{
    EgressClient, EgressError, PROTOCOL_VERSION, ProviderOutput, Request, Response, encode_frame,
};

pub(crate) type AnswerValidator = Arc<dyn Fn(&ProviderOutput) -> bool + Send + Sync>;

/// Cloneable in-process client using the same protocol handler as the socket server.
/// Each exchange runs on a Foundation-owned Tokio task. Dropping the caller's
/// future leaves that task running, including completion and receipt persistence.
#[derive(Clone)]
pub struct InProcessEgressClient {
    process: CredentialProcess,
    answer_validator: Option<AnswerValidator>,
}

impl InProcessEgressClient {
    /// Attach to a process opened through [`CredentialProcess::open`], which applies
    /// process protection before loading secrets. No socket is bound or required.
    pub fn new(process: CredentialProcess) -> Self {
        Self {
            process,
            answer_validator: None,
        }
    }

    /// Validate each direct provider answer before committing egress completion.
    /// Return false to report `EgressError::Provider { status: None }` with no output:
    /// the failed-send debit remains, while observed usage still governs spend.
    /// The callback must finish promptly and runs on Foundation's task even if the
    /// caller drops its future. It is not invoked for failed sends or signed jobs.
    /// Socket exchanges and clients without a validator keep their existing behavior.
    pub fn with_answer_validation<F>(mut self, validate: F) -> Self
    where
        F: Fn(&ProviderOutput) -> bool + Send + Sync + 'static,
    {
        self.answer_validator = Some(Arc::new(validate));
        self
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
        let answer_validator = self.answer_validator.clone();
        tokio::spawn(async move {
            let response = process
                .handle_with_answer_validation(request, answer_validator)
                .await;
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
