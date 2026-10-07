//! Authenticated job operations shared by socket and in-process clients.
use crate::{
    AdmissionKey, EgressClient, EgressError, Operation, PROTOCOL_VERSION, ProviderPayload, Reply,
    Request, SignedAttempt,
};
use serde::{Deserialize, Serialize};
pub use symbiotic_queue::jobs::{
    AckResult, DeliveryToken, Disposition, Enqueued, JobDiagnostic, JobError, JobId, JobRecord,
    JobScope, JobState, Selector,
};

/// One model invocation. The signed invocation ID is its stable scoped key.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnqueueJob {
    /// Optional cancellation label.
    pub group: Option<String>,
    /// Input owners, for erasure.
    pub owners: Vec<String>,
    /// Initial durable authority.
    pub admission: SignedAttempt,
    /// Exact provider input covered by the authority digest.
    pub payload: ProviderPayload,
}

/// Only the Memory subset of job operations; no worker or settlement instructions.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", content = "body", rename_all = "snake_case")]
pub enum JobsCommand {
    /// Atomic keyed enqueue.
    EnqueueJobs(Vec<EnqueueJob>),
    /// Successor authority for an unsent job.
    AdmitJob {
        /// Job within the authenticated request scope.
        job: JobId,
        /// Newly signed authority for the same frozen invocation.
        admission: Box<SignedAttempt>,
    },
    /// Final deliveries first, then non-confirmable admission notices, within both bounds.
    Completions {
        /// Exclusive notice ID cursor; omitted requests start at the first notice.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<String>,
        /// Maximum number of final deliveries and notices combined.
        limit: usize,
        /// Maximum encoded completion-body bytes.
        max_bytes: usize,
        /// Long-poll duration, bounded by the process exchange timeout.
        wait_seconds: u64,
    },
    /// Atomic fenced confirmation.
    AckJobs(Vec<(DeliveryToken, Disposition)>),
    /// Cancel waiting work or signal sent work through its heartbeat.
    CancelJobs(Selector),
    /// Erase an input owner's waiting and saved copies within the signed scope.
    PurgeOwner(String),
    /// Content-free per-job status (queue design §13).
    JobStatus(JobId),
}

/// Complete authenticated job request. The MAC binds scope, operation and body.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobsRequest {
    /// Authorized namespace, including restore incarnation.
    pub scope: JobScope,
    /// Exact operation.
    pub command: JobsCommand,
}

/// Domain-separated job authentication; knowledge of IDs conveys no authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedJobsRequest {
    /// Complete request.
    pub request: JobsRequest,
    /// HMAC-SHA256 over the typed request.
    pub authentication: String,
}

impl AdmissionKey {
    /// Authenticate a job operation after the caller's authority checks.
    pub fn sign_jobs(&self, request: JobsRequest) -> Result<SignedJobsRequest, EgressError> {
        let authentication = self.sign(b"symbiotic-egress/v4/jobs\0", &request)?;
        Ok(SignedJobsRequest {
            request,
            authentication,
        })
    }
    /// Verify scope, operation and body together in constant time.
    pub fn verify_jobs(&self, signed: &SignedJobsRequest) -> Result<(), EgressError> {
        self.verify(
            b"symbiotic-egress/v4/jobs\0",
            &signed.request,
            &signed.authentication,
        )
    }
}

impl SignedJobsRequest {
    /// Convert to the matching versioned wire operation.
    pub fn operation(self) -> Operation {
        match self.request.command {
            JobsCommand::EnqueueJobs(_) => Operation::EnqueueJobs(Box::new(self)),
            JobsCommand::AdmitJob { .. } => Operation::AdmitJob(Box::new(self)),
            JobsCommand::Completions { .. } => Operation::Completions(Box::new(self)),
            JobsCommand::AckJobs(_) => Operation::AckJobs(Box::new(self)),
            JobsCommand::CancelJobs(_) => Operation::CancelJobs(Box::new(self)),
            JobsCommand::PurgeOwner(_) => Operation::PurgeOwner(Box::new(self)),
            JobsCommand::JobStatus(_) => Operation::JobStatus(Box::new(self)),
        }
    }
}

/// Final metadata and the ledger's sole recovery answer; no second stored copy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobDelivery {
    /// Fenced final delivery.
    pub delivery: symbiotic_queue::jobs::Delivery,
    /// Canonical model response, including measured usage in its trace.
    pub output: Option<serde_json::Value>,
}

/// Bounded completions. Notices carry no confirmation token and never starve finals.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobsCompletions {
    /// Oldest eligible final jobs first.
    pub items: Vec<JobDelivery>,
    /// Waiting jobs that need successor authority.
    pub notices: Vec<JobDiagnostic>,
    /// Last returned notice ID, or the request cursor when no notice fits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// Typed job replies; errors preserve the queue's static code and scoped identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "reply", content = "body", rename_all = "snake_case")]
pub enum JobsReply {
    /// Batch enqueue dispositions.
    Enqueued(Vec<Enqueued>),
    /// Successor stored.
    Admitted,
    /// Bounded final deliveries and notices.
    Completions(JobsCompletions),
    /// Fenced confirmation dispositions.
    Acked(Vec<AckResult>),
    /// Number of jobs affected by cancellation.
    Cancelled(usize),
    /// Number of jobs affected by owner erasure.
    Purged(usize),
    /// Scoped content-free status; absent IDs return a typed NotFound error.
    Status(Box<JobRecord>),
}

/// Transport/authentication or queue failure, always visible to the caller.
#[derive(Debug, thiserror::Error)]
pub enum JobsClientError {
    /// Boundary or transport failure.
    #[error(transparent)]
    Egress(#[from] EgressError),
    /// Store operation failure.
    #[error(transparent)]
    Job(#[from] JobError),
}

/// The same authenticated Jobs API on either egress transport.
pub struct JobsClient<C> {
    client: C,
    scope: JobScope,
    key: AdmissionKey,
}
impl<C: EgressClient> JobsClient<C> {
    /// Bind an egress client to one authorized scope and signing key.
    pub fn new(client: C, scope: JobScope, key: AdmissionKey) -> Self {
        Self { client, scope, key }
    }
    /// Atomically enqueue model invocations, joining existing scoped keys.
    pub async fn enqueue(&self, jobs: Vec<EnqueueJob>) -> Result<Vec<Enqueued>, JobsClientError> {
        match self.request(JobsCommand::EnqueueJobs(jobs)).await? {
            JobsReply::Enqueued(items) => Ok(items),
            _ => Err(EgressError::InvalidRequest.into()),
        }
    }
    /// Attach successor authority to an unsent invocation.
    pub async fn admit(&self, job: JobId, admission: SignedAttempt) -> Result<(), JobsClientError> {
        match self
            .request(JobsCommand::AdmitJob {
                job,
                admission: Box::new(admission),
            })
            .await?
        {
            JobsReply::Admitted => Ok(()),
            _ => Err(EgressError::InvalidRequest.into()),
        }
    }
    /// Fetch bounded final deliveries and admission notices, optionally long-polling.
    /// Pass the response `after` to continue notices; None restarts the notice scan.
    /// Final deliveries are polled independently of the notice cursor.
    pub async fn completions(
        &self,
        limit: usize,
        max_bytes: usize,
        wait_seconds: u64,
        after: Option<String>,
    ) -> Result<JobsCompletions, JobsClientError> {
        match self
            .request(JobsCommand::Completions {
                after,
                limit,
                max_bytes,
                wait_seconds,
            })
            .await?
        {
            JobsReply::Completions(page) => Ok(page),
            _ => Err(EgressError::InvalidRequest.into()),
        }
    }
    /// Confirm durable consumer dispositions with issued delivery fences.
    pub async fn ack(
        &self,
        items: Vec<(DeliveryToken, Disposition)>,
    ) -> Result<Vec<AckResult>, JobsClientError> {
        match self.request(JobsCommand::AckJobs(items)).await? {
            JobsReply::Acked(items) => Ok(items),
            _ => Err(EgressError::InvalidRequest.into()),
        }
    }
    /// Cancel waiting jobs or signal running jobs through their heartbeat.
    pub async fn cancel(&self, target: Selector) -> Result<usize, JobsClientError> {
        match self.request(JobsCommand::CancelJobs(target)).await? {
            JobsReply::Cancelled(count) => Ok(count),
            _ => Err(EgressError::InvalidRequest.into()),
        }
    }
    /// Erase an input owner's job copies and recovery answers, preserving accounting.
    pub async fn purge_owner(&self, owner: String) -> Result<usize, JobsClientError> {
        match self.request(JobsCommand::PurgeOwner(owner)).await? {
            JobsReply::Purged(count) => Ok(count),
            _ => Err(EgressError::InvalidRequest.into()),
        }
    }
    /// Read content-free scoped lifecycle and receipt metadata.
    pub async fn status(&self, job: JobId) -> Result<Box<JobRecord>, JobsClientError> {
        match self.request(JobsCommand::JobStatus(job)).await? {
            JobsReply::Status(row) => Ok(row),
            _ => Err(EgressError::InvalidRequest.into()),
        }
    }
    /// Submit one bounded job operation; a transport failure never authorizes resubmission of paid work.
    pub async fn request(&self, command: JobsCommand) -> Result<JobsReply, JobsClientError> {
        let operation = self
            .key
            .sign_jobs(JobsRequest {
                scope: self.scope.clone(),
                command,
            })?
            .operation();
        let response = self
            .client
            .exchange(Request {
                version: PROTOCOL_VERSION,
                operation,
            })
            .await?;
        if response.version != PROTOCOL_VERSION {
            return Err(EgressError::Version.into());
        }
        match response.result? {
            Reply::Jobs(result) => Ok(result?),
            _ => Err(EgressError::InvalidRequest.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_notice_cursor_round_trips_authenticated_wire() {
        let key = AdmissionKey::new(b"synthetic-job-signing-key-32-bytes".to_vec()).unwrap();
        let cursor = "notice-\"\\\n";
        let signed = key
            .sign_jobs(JobsRequest {
                scope: JobScope {
                    tenant: "tenant".into(),
                    incarnation: "incarnation".into(),
                    queue: "jobs".into(),
                },
                command: JobsCommand::Completions {
                    after: Some(cursor.into()),
                    limit: 2,
                    max_bytes: 1024,
                    wait_seconds: 0,
                },
            })
            .unwrap();
        let request = Request {
            version: PROTOCOL_VERSION,
            operation: signed.operation(),
        };
        let bytes = crate::encode_frame(&request, 4096).unwrap();
        let decoded: Request = serde_json::from_slice(&bytes).unwrap();
        let Operation::Completions(mut signed) = decoded.operation else {
            panic!("completion wire operation")
        };
        key.verify_jobs(&signed).unwrap();
        let JobsCommand::Completions { after, .. } = &mut signed.request.command else {
            panic!("completion command")
        };
        assert_eq!(after.as_deref(), Some(cursor));
        *after = Some("other-notice".into());
        assert_eq!(key.verify_jobs(&signed), Err(EgressError::Unauthorized));
        let reply = JobsReply::Completions(JobsCompletions {
            items: Vec::new(),
            notices: Vec::new(),
            after: Some(cursor.into()),
        });
        let bytes = crate::encode_frame(&reply, 4096).unwrap();
        let JobsReply::Completions(page) = serde_json::from_slice(&bytes).unwrap() else {
            panic!("completion reply")
        };
        assert_eq!(page.after.as_deref(), Some(cursor));
        // Missing optional fields preserve the existing request and response encodings.
        let old =
            br#"{"operation":"completions","body":{"limit":2,"max_bytes":1024,"wait_seconds":0}}"#;
        let command: JobsCommand = serde_json::from_slice(old).unwrap();
        assert!(matches!(
            command,
            JobsCommand::Completions { after: None, .. }
        ));
        assert_eq!(crate::encode_frame(&command, 4096).unwrap(), old);
        let old = br#"{"items":[],"notices":[]}"#;
        let page: JobsCompletions = serde_json::from_slice(old).unwrap();
        assert!(page.after.is_none());
        assert_eq!(crate::encode_frame(&page, 4096).unwrap(), old);
    }

    #[test]
    fn owner_purge_round_trips_signed_wire_request_and_reply() {
        let key = AdmissionKey::new(b"synthetic-job-signing-key-32-bytes".to_vec()).unwrap();
        let signed = key
            .sign_jobs(JobsRequest {
                scope: JobScope {
                    tenant: "tenant".into(),
                    incarnation: "incarnation".into(),
                    queue: "jobs".into(),
                },
                command: JobsCommand::PurgeOwner("input-owner".into()),
            })
            .unwrap();
        let request = Request {
            version: PROTOCOL_VERSION,
            operation: signed.operation(),
        };
        let bytes = crate::encode_frame(&request, 4096).unwrap();
        let decoded: Request = serde_json::from_slice(&bytes).unwrap();
        let Operation::PurgeOwner(mut decoded) = decoded.operation else {
            panic!("owner purge wire operation")
        };
        key.verify_jobs(&decoded).unwrap();
        assert!(
            matches!(&decoded.request.command, JobsCommand::PurgeOwner(owner) if owner == "input-owner")
        );
        decoded.request.command = JobsCommand::PurgeOwner("other-owner".into());
        assert_eq!(key.verify_jobs(&decoded), Err(EgressError::Unauthorized));
        let reply = JobsReply::Purged(2);
        let bytes = crate::encode_frame(&reply, 4096).unwrap();
        assert_eq!(bytes, br#"{"reply":"purged","body":2}"#);
        assert!(matches!(
            serde_json::from_slice::<JobsReply>(&bytes).unwrap(),
            JobsReply::Purged(2)
        ));
    }
}
