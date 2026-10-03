//! Generic job records and atomic transitions, independent of the runner.
//!
//! IDs and all operations are scoped to a tenant, restore incarnation and queue.
//! Enqueue/claim order is `(created_at, id)`; final deliveries use `(finished_at,
//! id)`, ahead of admission notices. Diagnostic cursors use ascending IDs.
//! Backends own atomicity: an error must roll back every write in an operation.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use symbiotic_core::{BindingIdentity, DiagnosticCode, QueueItemId};
use thiserror::Error;

/// Authorization namespace supplied by the trusted host, never by an unverified client.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobScope {
    /// Tenant namespace.
    pub tenant: String,
    /// Restore incarnation.
    pub incarnation: String,
    /// Queue within the tenant.
    pub queue: String,
}

/// Scoped durable identity; the job key is the logical invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobId {
    /// Authorization namespace.
    pub scope: JobScope,
    /// Opaque row identity.
    pub id: String,
}

/// Scheduling class; untagged jobs are background.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Priority {
    /// Latency-sensitive work.
    Interactive,
    /// Bulk work, FIFO within the class.
    #[default]
    Background,
}

/// Per-app claim policy. Running work is never preempted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PriorityPolicy {
    /// FIFO regardless of class.
    Fifo,
    /// Interactive work first.
    StrictClasses,
    /// Reserve this many concurrent slots for waiting background work.
    BackgroundShare { minimum_slots: usize },
}

/// Versioned store policy, supplied by the owning app.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobConfig {
    /// Supported configuration format (1).
    pub version: u32,
    /// Maximum atomic enqueue/ack batch (64).
    pub max_batch: usize,
    /// Maximum delivery/diagnostic/claim page (64).
    pub max_page: usize,
    /// Maximum serialized delivery page (1 MiB).
    pub max_page_bytes: usize,
    /// Hard unfinished-job count bound (1024).
    pub max_pending_items: usize,
    /// Hard unfinished input-byte bound, including metadata/checkpoints (16 MiB).
    pub max_pending_bytes: usize,
    /// Delivery lease length (30 seconds).
    pub delivery_lease_seconds: u64,
    /// Claim lease length (30 seconds).
    pub claim_lease_seconds: u64,
    /// Final-result retention without an explicit deadline (7 days).
    pub retention_seconds: u64,
    /// Maximum checkpoint (64 KiB).
    pub max_checkpoint_bytes: usize,
    /// Maximum expired results deleted in one maintenance pass (64).
    pub maintenance_batch: usize,
    /// Per-app scheduling policy (one background slot by default).
    pub priority: PriorityPolicy,
}

impl Default for JobConfig {
    fn default() -> Self {
        Self {
            version: 1,
            max_batch: 64,
            max_page: 64,
            max_page_bytes: 1024 * 1024,
            max_pending_items: 1024,
            max_pending_bytes: 16 * 1024 * 1024,
            delivery_lease_seconds: 30,
            claim_lease_seconds: 30,
            retention_seconds: 7 * 24 * 60 * 60,
            max_checkpoint_bytes: 64 * 1024,
            maintenance_batch: 64,
            priority: PriorityPolicy::BackgroundShare { minimum_slots: 1 },
        }
    }
}

/// One admission, verified by the authority owner before entering the store.
/// Signature verification/current-grant checks belong to PR 4, inside acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdmission {
    /// Monotonically increasing admission ordinal, independent of paid attempts.
    pub ordinal: u32,
    /// Frozen execution binding.
    pub binding: BindingIdentity,
    /// Authority deadline, independent of result retention.
    pub authority_until: DateTime<Utc>,
    /// Signed envelope bytes (no provider credentials).
    pub signed: Vec<u8>,
}

/// Attempt ceiling frozen on first enqueue; successors cannot renew it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLimits {
    /// Maximum execution attempts, at least one.
    pub max_attempts: u32,
}

/// Execution owner, needed to distinguish reclaimable handler leases from paid uncertainty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Execution {
    /// Product handler with no paid transport.
    Handler,
    /// Model transport; expired leases require ledger reconciliation in PR 3.
    Model,
}

/// One immutable keyed invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    /// Idempotency key, unique within the scope.
    pub key: String,
    /// Optional cancellation/status label.
    pub group: Option<String>,
    /// Opaque input-owner tags; any match erases all recovery copies.
    pub owners: Vec<String>,
    /// Handler kind used to scope claims.
    pub kind: String,
    /// Execution/recovery owner.
    pub execution: Execution,
    /// Per-app scheduling class; absent wire classes default to background.
    #[serde(default)]
    pub priority: Priority,
    /// Full waiting copy.
    pub payload: Value,
    /// Frozen execution limits.
    pub limits: JobLimits,
    /// Optional first signed admission.
    pub admission: Option<SignedAdmission>,
    /// Limits final-result availability only.
    pub recovery_until: Option<DateTime<Utc>>,
}

/// Durable lifecycle, including separate confirmation dispositions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum JobState {
    /// Waiting for a claim.
    Pending,
    /// Authority expired; unfinished.
    AwaitingAdmission,
    /// Leased to a worker.
    Running,
    /// Charge may exist; cannot be claimed blindly.
    Uncertain,
    /// Final success.
    Succeeded,
    /// Final failure.
    Failed,
    /// Final cancellation.
    Cancelled,
    /// Final refusal.
    Refused,
    /// Erased input/output.
    Purged,
    /// Consumer saved the result.
    Accepted,
    /// Consumer rejected the result.
    Discarded,
}

impl JobState {
    /// Whether execution/reconciliation still needs the waiting copy.
    pub fn unfinished(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::AwaitingAdmission | Self::Running | Self::Uncertain
        )
    }
    /// Whether a confirmation already won.
    pub fn acked(self) -> bool {
        matches!(self, Self::Accepted | Self::Discarded)
    }
}

/// Origin of a final answer; paid output is owned exclusively by the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ResultOrigin {
    /// Ledger owns the saved answer and receipt.
    Paid,
    /// Independent recovery copy of a response-cache hit.
    Cache,
    /// Product-handler output; no receipt required.
    Handler,
}

/// Canonical job row. Confirmed rows are content-free tombstones.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    /// Scoped row identity.
    pub id: JobId,
    /// Logical invocation key.
    pub key: String,
    /// Digest retained after payload deletion.
    pub digest: String,
    /// Status/cancellation group.
    pub group: Option<String>,
    /// Input provenance.
    pub owners: Vec<String>,
    /// Handler kind.
    pub kind: String,
    /// Execution/recovery owner.
    pub execution: Execution,
    /// Scheduling class.
    pub priority: Priority,
    /// Current lifecycle.
    pub state: JobState,
    /// Final state retained after confirmation.
    pub final_state: Option<JobState>,
    /// Waiting copy; never removed solely because an unfinished job is old.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_value"
    )]
    pub payload: Option<Value>,
    /// Frozen ceiling.
    pub max_attempts: u32,
    /// Latest admission (successors replace expired envelopes).
    pub admission: Option<SignedAdmission>,
    /// Monotonic claim fence.
    pub generation: u64,
    /// Current claim deadline.
    pub lease_until: Option<DateTime<Utc>>,
    /// Handler checkpoint, deleted with payload.
    pub checkpoint: Option<Vec<u8>>,
    /// Cancellation intent for running work.
    pub cancel_requested: bool,
    /// Sticky erasure fence checked before every result commit.
    pub purged: bool,
    /// Cache/handler recovery copy; never contains paid output.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_value"
    )]
    pub output: Option<Value>,
    /// Result provenance.
    pub origin: Option<ResultOrigin>,
    /// Optional accounting reference, with no copied usage.
    pub receipt: Option<String>,
    /// Final-result availability deadline.
    pub recovery_until: Option<DateTime<Utc>>,
    /// Whether recovery output has expired.
    pub result_expired: bool,
    /// Enqueue order timestamp.
    pub created_at: DateTime<Utc>,
    /// Final-delivery order timestamp.
    pub finished_at: Option<DateTime<Utc>>,
    /// Latest delivery ordinal; older issued ordinals remain confirmable.
    pub delivery_generation: u64,
    /// Delivery overlap reduction only, not an acknowledgement fence.
    pub delivery_until: Option<DateTime<Utc>>,
    /// Static failure diagnostic, never provider text.
    pub diagnostic: Option<DiagnosticCode>,
}

// Missing means erased/unavailable; a present JSON null is valid generic data.
// One decoder owns this distinction for both waiting copies and saved answers.
fn deserialize_present_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

impl JobRecord {
    /// One-based execution claim ordinal, derived from the fence rather than copied.
    /// Admission refresh consumes no claim generation or attempt allowance.
    pub fn attempt(&self) -> u64 {
        self.generation
    }

    // Waiting work and expired unpaid claims can stop without ledger reconciliation.
    // Cancel and erasure use the same rule so neither strands an expired handler.
    fn can_stop_without_accounting(&self, now: DateTime<Utc>) -> bool {
        matches!(self.state, JobState::Pending | JobState::AwaitingAdmission)
            || self.state == JobState::Running
                && self.execution == Execution::Handler
                && self.lease_until.is_some_and(|until| until <= now)
    }

    /// Only product-handler leases can be reclaimed without ledger evidence.
    #[doc(hidden)]
    pub fn claimable(&self, now: DateTime<Utc>) -> bool {
        self.state == JobState::Pending
            || self.state == JobState::Running
                && self.execution == Execution::Handler
                && self.lease_until.is_some_and(|until| until <= now)
    }
}

/// Keyed enqueue result.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Enqueued {
    /// Newly inserted job.
    Inserted(JobId),
    /// Existing unfinished or unconfirmed final job.
    Joined(JobId),
    /// Confirmed content-free tombstone.
    AlreadyDone(Box<JobRecord>),
}

/// Consumer disposition; first confirmation wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Disposition {
    /// Durably saved by the consumer.
    Accepted,
    /// Consumer refused the answer.
    Discarded,
}

/// Scoped issued delivery ordinal, authenticated by the transport in PR 4.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryToken {
    /// Delivered job.
    pub job: JobId,
    /// One-based delivery ordinal.
    pub generation: u64,
}

/// Final completion or admission notice; notices have no confirmable token.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    /// Snapshot of the job (payload/admission/checkpoint are not disclosed).
    pub completion: JobRecord,
    /// Only final results receive a token.
    pub token: Option<DeliveryToken>,
}

/// One confirmation result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AckResult {
    /// This confirmation won.
    Acked(Disposition),
    /// A prior confirmation won.
    AlreadyAcked(Disposition),
}

/// Counts rebuilt from canonical job rows; no usage is copied here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSummary {
    /// Number of jobs in each lifecycle/disposition.
    pub counts: BTreeMap<JobState, usize>,
    /// Creation time of the oldest Pending job.
    pub oldest_pending: Option<DateTime<Utc>>,
}

/// Bounded operational diagnostic.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobDiagnostic {
    /// Affected identity.
    pub id: JobId,
    /// Failed, Uncertain or AwaitingAdmission.
    pub state: JobState,
    /// Static cause, if available.
    pub code: Option<DiagnosticCode>,
}

/// Bounded diagnostic page in ascending ID order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticPage {
    /// At most the requested count.
    pub items: Vec<JobDiagnostic>,
    /// Last returned ID; use as the exclusive next cursor.
    pub after: Option<String>,
}

/// Cancellation target within the authorized scope.
#[derive(Clone, Debug)]
pub enum Selector {
    /// Explicit scoped identities.
    Ids(Vec<JobId>),
    /// Every matching group row, processed atomically.
    Group(String),
}

/// Hard pending utilization, derived from unfinished canonical rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingUsage {
    /// Unfinished job count (including Running and Uncertain).
    pub items: usize,
    /// Retained unfinished input bytes, including metadata/checkpoints.
    pub bytes: usize,
}

/// Ledger-owner evidence used only inside the shared acceptance/settlement transaction.
/// This is an internal trusted-host operation, never an instruction from a client.
#[derive(Clone, Debug)]
pub enum JobResolution {
    /// Reservation may have dispatched; preserve input for reconciliation.
    Uncertain { receipt: String },
    /// Trusted ledger/adapter established zero charge or durable pre-dispatch release.
    KnownZeroCharge { receipt: String },
    /// Ledger already holds a committed paid result, including direct-call recovery.
    PaidResult {
        receipt: String,
        recovery_until: Option<DateTime<Utc>>,
    },
    /// Reconciliation established a terminal failure.
    Failed {
        receipt: String,
        diagnostic: DiagnosticCode,
    },
}

/// Atomic store operations. Runner/recovery and ledger ownership stay outside this module.
#[derive(Clone, Debug)]
pub enum JobRequest {
    /// All-or-none enqueue; joined keys consume no additional capacity.
    Enqueue(Vec<JobSpec>),
    /// Replace an expired admission under the same invocation and frozen ceiling.
    Admit {
        job: JobId,
        admission: SignedAdmission,
    },
    /// Claim one job within handler kinds, given currently available account slots.
    Claim {
        kinds: Vec<String>,
        slots_available: usize,
        background_in_flight: usize,
    },
    /// Inspect a bounded claim page before obtaining the existing account slot.
    Candidates {
        kinds: Vec<String>,
        background_in_flight: usize,
        limit: usize,
        max_bytes: usize,
    },
    /// Claim the inspected job inside the account owner's acceptance transaction.
    /// The trusted caller holds its account/handler slot; the store is not a limiter.
    ClaimJob(JobId),
    /// Current-grant rejection before handoff; consumes no execution attempt.
    AwaitAdmission(JobId),
    /// Extend a live claim without changing its generation.
    Heartbeat { job: JobId, generation: u64 },
    /// Save bounded progress under a live generation.
    Checkpoint {
        job: JobId,
        generation: u64,
        bytes: Vec<u8>,
    },
    /// Set a final result or Uncertain under a live generation.
    Complete {
        job: JobId,
        generation: u64,
        state: JobState,
        origin: ResultOrigin,
        output: Option<Value>,
        receipt: Option<String>,
        diagnostic: Option<DiagnosticCode>,
    },
    /// Resolve a paid job using verified ledger evidence, including an expired claim.
    Resolve {
        job: JobId,
        generation: u64,
        resolution: JobResolution,
    },
    /// Final results first, then unconfirmable admission notices; serialized byte bound.
    Completions { limit: usize, max_bytes: usize },
    /// Atomic batch confirm; paid-output discard participates via the transaction seam.
    Ack(Vec<(DeliveryToken, Disposition)>),
    /// Finalize waiting work, signal running work; never retries cancelled work.
    Cancel(Selector),
    /// Sticky owner erasure, including concurrent/late completion writes.
    PurgeOwner(String),
    /// Read a summary row.
    Status(String),
    /// Rebuild one summary from canonical rows.
    RebuildSummary(String),
    /// Page static diagnostics.
    Diagnostics {
        group: String,
        after: Option<String>,
        limit: usize,
    },
    /// Expire at most the configured number of final recovery copies.
    Maintain,
    /// Authorized internal lookup for runner/reconciliation.
    Get(JobId),
    /// Derived pending count/bytes for backpressure.
    PendingUsage,
}

/// Result matching the requested operation.
#[derive(Clone, Debug)]
pub enum JobResponse {
    /// Keyed batch dispositions.
    Enqueued(Vec<Enqueued>),
    /// Claimed or internally fetched row.
    Job(Option<Box<JobRecord>>),
    /// Bounded candidate snapshots for the runner/account owner.
    Candidates(Vec<JobRecord>),
    /// Final results and admission notices.
    Deliveries(Vec<Delivery>),
    /// Confirmation dispositions.
    Acks(Vec<AckResult>),
    /// Cancellation/purge/maintenance changed this many rows.
    Changed(usize),
    /// Group status.
    Summary(GroupSummary),
    /// Paged static diagnostics.
    Diagnostics(DiagnosticPage),
    /// Pending utilization.
    Usage(PendingUsage),
    /// Successful single-row write.
    Done,
}

/// Visible failures; messages contain static codes or scoped IDs, never content.
#[derive(Debug, Error)]
pub enum JobError {
    /// Request crossed tenant/incarnation/queue authorization scope.
    #[error("job scope refused")]
    Scope,
    /// No authorized job exists.
    #[error("job not found")]
    NotFound,
    /// Same key with different input.
    #[error("job key conflict")]
    KeyConflict,
    /// Hard pending bound reached.
    #[error("job queue full")]
    QueueFull,
    /// An eligible completion cannot fit individually in the requested page.
    #[error("completion exceeds page byte bound: {job:?} ({bytes} bytes)")]
    CompletionTooLarge { job: JobId, bytes: usize },
    /// An inspected job cannot fit individually in the requested candidate page.
    #[error("claim candidate exceeds page byte bound: {job:?} ({bytes} bytes)")]
    CandidateTooLarge { job: JobId, bytes: usize },
    /// Invalid configuration, state transition, admission or page bound.
    #[error("invalid job request")]
    InvalidRequest,
    /// Expired or superseded claim.
    #[error("stale job claim")]
    StaleClaim,
    /// An unfinished admission notice cannot be acknowledged.
    #[error("cannot confirm an unfinished job")]
    NotFinal,
    /// The caller-selected backend does not provide a job store.
    #[error("job store unavailable")]
    Unavailable,
    /// Backend/serialization failure.
    #[error("job storage failure")]
    Storage,
}

/// Backend row selection; all operational pages are bounded at the storage read.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub enum JobQuery {
    /// Scoped group scan (for atomic group cancel/rebuild).
    Group(String),
    /// Scoped owner matches (for atomic erasure).
    Owner(String),
    /// Waiting claims in a specific class, FIFO.
    Pending {
        kinds: Vec<String>,
        priority: Option<Priority>,
    },
    /// Unleased final deliveries, oldest first.
    Final,
    /// Admission notices, FIFO after final results.
    Notices,
    /// Final recovery copies past deadline.
    Expired,
    /// Static diagnostic states, ascending ID.
    Diagnostics {
        group: String,
        after: Option<String>,
    },
}

/// Storage primitives for the single shared transition mechanism.
/// Implementations must be inside a rollback-capable transaction.
#[doc(hidden)]
pub trait JobRows {
    /// Read by scoped identity.
    fn get(&mut self, id: &JobId) -> Result<Option<JobRecord>, JobError>;
    /// Read by scoped invocation key.
    fn by_key(&mut self, scope: &JobScope, key: &str) -> Result<Option<JobRecord>, JobError>;
    /// Read a bounded selection.
    fn select(
        &mut self,
        scope: &JobScope,
        query: JobQuery,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<JobRecord>, JobError>;
    /// Write canonical row and update its group summary atomically.
    fn save(&mut self, row: JobRecord) -> Result<(), JobError>;
    /// Count unfinished rows and bytes.
    fn usage(&mut self, scope: &JobScope) -> Result<PendingUsage, JobError>;
    /// Read or rebuild the group summary.
    fn summary(
        &mut self,
        scope: &JobScope,
        group: &str,
        rebuild: bool,
    ) -> Result<GroupSummary, JobError>;
}

fn deadline(now: DateTime<Utc>, seconds: u64) -> Result<DateTime<Utc>, JobError> {
    i64::try_from(seconds)
        .ok()
        .and_then(Duration::try_seconds)
        .and_then(|d| now.checked_add_signed(d))
        .ok_or(JobError::InvalidRequest)
}

fn scoped(scope: &JobScope, job: &JobId) -> Result<(), JobError> {
    if &job.scope == scope {
        Ok(())
    } else {
        Err(JobError::Scope)
    }
}

fn get(rows: &mut impl JobRows, scope: &JobScope, id: &JobId) -> Result<JobRecord, JobError> {
    scoped(scope, id)?;
    rows.get(id)?.ok_or(JobError::NotFound)
}

fn live(row: &JobRecord, generation: u64, now: DateTime<Utc>) -> Result<(), JobError> {
    if row.state == JobState::Running
        && row.generation == generation
        && row.lease_until.is_some_and(|until| until > now)
    {
        Ok(())
    } else {
        Err(JobError::StaleClaim)
    }
}

fn delete_copies(row: &mut JobRecord) {
    row.payload = None;
    row.checkpoint = None;
    row.admission = None;
    row.output = None;
}

fn finish(
    row: &mut JobRecord,
    state: JobState,
    now: DateTime<Utc>,
    config: &JobConfig,
) -> Result<(), JobError> {
    row.state = state;
    row.finished_at = Some(now);
    row.lease_until = None;
    row.checkpoint = None;
    row.admission = None;
    if row.recovery_until.is_none() {
        row.recovery_until = Some(deadline(now, config.retention_seconds)?);
    }
    if row.recovery_until.is_some_and(|until| until <= now) {
        row.result_expired = true;
        delete_copies(row);
    }
    Ok(())
}

fn page(config: &JobConfig, limit: usize) -> Result<(), JobError> {
    if limit == 0 || limit > config.max_page {
        Err(JobError::InvalidRequest)
    } else {
        Ok(())
    }
}

// One byte-bound owner for all JSON-array pages: reject an individually oversized
// row, and defer a row that only exceeds the remaining aggregate page budget.
fn page_bytes(
    item: &impl Serialize,
    used: usize,
    max_bytes: usize,
    comma: bool,
    oversized: impl FnOnce(usize) -> JobError,
) -> Result<Option<usize>, JobError> {
    let size = serde_json::to_vec(item)
        .map_err(|_| JobError::Storage)?
        .len();
    let individual = size.checked_add(2).ok_or(JobError::InvalidRequest)?;
    if individual > max_bytes {
        return Err(oversized(individual));
    }
    let required = used
        .checked_add(size)
        .and_then(|b| b.checked_add(usize::from(comma)))
        .ok_or(JobError::InvalidRequest)?;
    Ok((required <= max_bytes).then_some(required))
}

/// Derive retained-input utilization from the canonical row; no byte projection is stored.
#[doc(hidden)]
pub fn job_input_bytes(row: &JobRecord) -> Result<usize, JobError> {
    if !row.state.unfinished() {
        return Ok(0);
    }
    serde_json::to_vec(&(
        &row.id.scope,
        &row.key,
        &row.group,
        &row.owners,
        &row.kind,
        row.execution,
        row.priority,
        &row.payload,
        &row.admission,
        &row.checkpoint,
        row.max_attempts,
    ))
    .map(|bytes| bytes.len())
    .map_err(|_| JobError::Storage)
}

// Every retained-input write uses this owner, so successors/checkpoints cannot
// bypass enqueue's hard bound. Utilization is derived, never stored separately.
fn save_job(rows: &mut impl JobRows, config: &JobConfig, row: JobRecord) -> Result<(), JobError> {
    let new_bytes = job_input_bytes(&row)?;
    let old = rows.get(&row.id)?;
    let old_items = usize::from(old.as_ref().is_some_and(|r| r.state.unfinished()));
    let old_bytes = old.as_ref().map(job_input_bytes).transpose()?.unwrap_or(0);
    let new_items = usize::from(row.state.unfinished());
    if new_items > old_items || new_bytes > old_bytes {
        let usage = rows.usage(&row.id.scope)?;
        let items = usage
            .items
            .checked_sub(old_items)
            .and_then(|n| n.checked_add(new_items))
            .ok_or(JobError::Storage)?;
        let bytes = usage
            .bytes
            .checked_sub(old_bytes)
            .and_then(|n| n.checked_add(new_bytes))
            .ok_or(JobError::Storage)?;
        if items > config.max_pending_items || bytes > config.max_pending_bytes {
            return Err(JobError::QueueFull);
        }
    }
    rows.save(row)
}

// The account slot owner supplies its current background concurrency. This
// derives claim order without adding another limiter or a stored scheduler copy.
fn candidates(
    rows: &mut impl JobRows,
    scope: &JobScope,
    config: &JobConfig,
    now: DateTime<Utc>,
    kinds: Vec<String>,
    background_in_flight: usize,
    limit: usize,
) -> Result<Vec<JobRecord>, JobError> {
    if kinds.is_empty() {
        return Err(JobError::InvalidRequest);
    }
    let priority = match config.priority {
        PriorityPolicy::Fifo => None,
        PriorityPolicy::StrictClasses => Some(Priority::Interactive),
        PriorityPolicy::BackgroundShare { minimum_slots } => {
            Some(if background_in_flight < minimum_slots {
                Priority::Background
            } else {
                Priority::Interactive
            })
        }
    };
    let mut selected = rows.select(
        scope,
        JobQuery::Pending {
            kinds: kinds.clone(),
            priority,
        },
        now,
        limit,
    )?;
    if selected.is_empty() && priority.is_some() {
        selected = rows.select(
            scope,
            JobQuery::Pending {
                kinds,
                priority: None,
            },
            now,
            limit,
        )?;
    }
    Ok(selected)
}

fn claim_job(
    rows: &mut impl JobRows,
    config: &JobConfig,
    now: DateTime<Utc>,
    mut row: JobRecord,
) -> Result<Option<JobRecord>, JobError> {
    if !row.claimable(now) {
        return Ok(None);
    }
    if row.cancel_requested && row.can_stop_without_accounting(now) {
        let state = if row.purged {
            JobState::Purged
        } else {
            JobState::Cancelled
        };
        finish(&mut row, state, now, config)?;
        delete_copies(&mut row);
        save_job(rows, config, row)?;
        return Ok(None);
    }
    if row
        .admission
        .as_ref()
        .is_some_and(|a| a.authority_until <= now)
    {
        row.state = JobState::AwaitingAdmission;
        save_job(rows, config, row)?;
        return Ok(None);
    }
    if row.generation >= u64::from(row.max_attempts) {
        finish(&mut row, JobState::Refused, now, config)?;
        save_job(rows, config, row)?;
        return Ok(None);
    }
    row.state = JobState::Running;
    row.generation = row
        .generation
        .checked_add(1)
        .ok_or(JobError::InvalidRequest)?;
    row.lease_until = Some(deadline(now, config.claim_lease_seconds)?);
    save_job(rows, config, row.clone())?;
    Ok(Some(row))
}

/// Apply one operation with the same lifecycle/bounds/fences for every backend.
/// Errors require rollback, including delivery leases and summary writes.
#[doc(hidden)]
pub fn apply_job_request(
    rows: &mut impl JobRows,
    scope: &JobScope,
    config: &JobConfig,
    now: DateTime<Utc>,
    request: JobRequest,
) -> Result<JobResponse, JobError> {
    if config.version != 1
        || config.max_batch == 0
        || config.max_page == 0
        || config.max_page_bytes < 2
        || config.maintenance_batch == 0
        || config.claim_lease_seconds == 0
        || config.delivery_lease_seconds == 0
        || [&scope.tenant, &scope.incarnation, &scope.queue]
            .iter()
            .any(|s| s.is_empty())
    {
        return Err(JobError::InvalidRequest);
    }
    // Reject overflowing time policies before any writes or attempt consumption.
    deadline(now, config.claim_lease_seconds)?;
    deadline(now, config.delivery_lease_seconds)?;
    deadline(now, config.retention_seconds)?;
    match request {
        JobRequest::Enqueue(specs) => {
            if specs.len() > config.max_batch {
                return Err(JobError::InvalidRequest);
            }
            let mut outcomes = Vec::with_capacity(specs.len());
            for spec in specs {
                if spec.key.is_empty() || spec.kind.is_empty() || spec.limits.max_attempts == 0 {
                    return Err(JobError::InvalidRequest);
                }
                if let Some(a) = &spec.admission {
                    validate_admission(scope, a)?;
                }
                let payload = serde_json::to_vec(&spec.payload).map_err(|_| JobError::Storage)?;
                let digest = hex::encode(Sha256::digest(&payload));
                if let Some(row) = rows.by_key(scope, &spec.key)? {
                    if row.digest != digest {
                        return Err(JobError::KeyConflict);
                    }
                    outcomes.push(if row.state.acked() {
                        Enqueued::AlreadyDone(Box::new(row))
                    } else {
                        Enqueued::Joined(row.id)
                    });
                    continue;
                }
                let id = JobId {
                    scope: scope.clone(),
                    id: QueueItemId::new().0,
                };
                let state = if spec
                    .admission
                    .as_ref()
                    .is_some_and(|a| a.authority_until <= now)
                {
                    JobState::AwaitingAdmission
                } else {
                    JobState::Pending
                };
                save_job(
                    rows,
                    config,
                    JobRecord {
                        id: id.clone(),
                        key: spec.key,
                        digest,
                        group: spec.group,
                        owners: spec.owners,
                        kind: spec.kind,
                        execution: spec.execution,
                        priority: spec.priority,
                        state,
                        final_state: None,
                        payload: Some(spec.payload),
                        max_attempts: spec.limits.max_attempts,
                        admission: spec.admission,
                        generation: 0,
                        lease_until: None,
                        checkpoint: None,
                        cancel_requested: false,
                        purged: false,
                        output: None,
                        origin: None,
                        receipt: None,
                        recovery_until: spec.recovery_until,
                        result_expired: false,
                        created_at: now,
                        finished_at: None,
                        delivery_generation: 0,
                        delivery_until: None,
                        diagnostic: None,
                    },
                )?;
                outcomes.push(Enqueued::Inserted(id));
            }
            Ok(JobResponse::Enqueued(outcomes))
        }
        JobRequest::Admit { job, admission } => {
            scoped(scope, &job)?;
            validate_admission(scope, &admission)?;
            let mut row = get(rows, scope, &job)?;
            if row.state != JobState::AwaitingAdmission || admission.authority_until <= now {
                return Err(JobError::InvalidRequest);
            }
            if let Some(previous) = &row.admission
                && (previous.binding != admission.binding || admission.ordinal <= previous.ordinal)
            {
                return Err(JobError::InvalidRequest);
            }
            row.admission = Some(admission);
            row.state = JobState::Pending;
            save_job(rows, config, row)?;
            Ok(JobResponse::Done)
        }
        JobRequest::Claim {
            kinds,
            slots_available,
            background_in_flight,
        } => {
            if kinds.is_empty() {
                return Err(JobError::InvalidRequest);
            }
            if slots_available == 0 {
                return Ok(JobResponse::Job(None));
            }
            let candidates = candidates(
                rows,
                scope,
                config,
                now,
                kinds,
                background_in_flight,
                config.max_page,
            )?;
            for row in candidates {
                if let Some(row) = claim_job(rows, config, now, row)? {
                    return Ok(JobResponse::Job(Some(Box::new(row))));
                }
            }
            Ok(JobResponse::Job(None))
        }
        JobRequest::Candidates {
            kinds,
            background_in_flight,
            limit,
            max_bytes,
        } => {
            page(config, limit)?;
            if max_bytes < 2 || max_bytes > config.max_page_bytes {
                return Err(JobError::InvalidRequest);
            }
            let selected =
                candidates(rows, scope, config, now, kinds, background_in_flight, limit)?;
            let mut page = Vec::new();
            let mut bytes: usize = 2;
            for row in selected {
                let Some(required) =
                    page_bytes(&row, bytes, max_bytes, !page.is_empty(), |bytes| {
                        JobError::CandidateTooLarge {
                            job: row.id.clone(),
                            bytes,
                        }
                    })?
                else {
                    break;
                };
                bytes = required;
                page.push(row);
            }
            Ok(JobResponse::Candidates(page))
        }
        JobRequest::ClaimJob(job) => {
            let row = get(rows, scope, &job)?;
            Ok(JobResponse::Job(
                claim_job(rows, config, now, row)?.map(Box::new),
            ))
        }
        JobRequest::AwaitAdmission(job) => {
            let mut row = get(rows, scope, &job)?;
            if row.state != JobState::Pending || row.admission.is_none() {
                return Err(JobError::InvalidRequest);
            }
            row.state = JobState::AwaitingAdmission;
            save_job(rows, config, row)?;
            Ok(JobResponse::Done)
        }
        JobRequest::Heartbeat { job, generation } => {
            let mut row = get(rows, scope, &job)?;
            live(&row, generation, now)?;
            row.lease_until = Some(deadline(now, config.claim_lease_seconds)?);
            save_job(rows, config, row)?;
            Ok(JobResponse::Done)
        }
        JobRequest::Checkpoint {
            job,
            generation,
            bytes,
        } => {
            let mut row = get(rows, scope, &job)?;
            live(&row, generation, now)?;
            if bytes.len() > config.max_checkpoint_bytes
                || row.purged
                || row.execution != Execution::Handler
            {
                return Err(JobError::InvalidRequest);
            }
            row.checkpoint = Some(bytes);
            save_job(rows, config, row)?;
            Ok(JobResponse::Done)
        }
        JobRequest::Complete {
            job,
            generation,
            state,
            origin,
            output,
            receipt,
            diagnostic,
        } => {
            let mut row = get(rows, scope, &job)?;
            if origin == ResultOrigin::Cache {
                if row.state == JobState::Purged && generation == 0 && row.generation == 0 {
                    return Ok(JobResponse::Done);
                }
                if row.state != JobState::Pending
                    || state != JobState::Succeeded
                    || generation != 0
                    || row.generation != 0
                {
                    return Err(JobError::InvalidRequest);
                }
            } else {
                live(&row, generation, now)?;
            }
            if origin == ResultOrigin::Paid && row.execution != Execution::Model
                || origin == ResultOrigin::Handler && row.execution != Execution::Handler
                || state == JobState::Uncertain && row.execution != Execution::Model
            {
                return Err(JobError::InvalidRequest);
            }
            if !matches!(
                state,
                JobState::Succeeded
                    | JobState::Failed
                    | JobState::Cancelled
                    | JobState::Refused
                    | JobState::Uncertain
            ) || origin == ResultOrigin::Paid && output.is_some()
                || origin == ResultOrigin::Paid && receipt.is_none()
                || origin != ResultOrigin::Paid && receipt.is_some()
                || state == JobState::Succeeded
                    && origin != ResultOrigin::Paid
                    && output.is_none()
                    && !row.purged
                    && !row.recovery_until.is_some_and(|until| until <= now)
            {
                return Err(JobError::InvalidRequest);
            }
            row.origin = Some(origin);
            row.receipt = receipt;
            row.diagnostic = diagnostic;
            if row.purged {
                finish(&mut row, JobState::Purged, now, config)?;
                delete_copies(&mut row);
            } else if state == JobState::Uncertain {
                row.state = state;
                row.lease_until = None;
            } else {
                row.output = output;
                let state = if row.cancel_requested {
                    JobState::Cancelled
                } else {
                    state
                };
                finish(&mut row, state, now, config)?;
            }
            save_job(rows, config, row)?;
            Ok(JobResponse::Done)
        }
        JobRequest::Resolve {
            job,
            generation,
            resolution,
        } => {
            let mut row = get(rows, scope, &job)?;
            if row.execution != Execution::Model
                || !row.state.unfinished()
                || row.generation != generation
            {
                return Err(JobError::StaleClaim);
            }
            row.origin = Some(ResultOrigin::Paid);
            match resolution {
                JobResolution::Uncertain { receipt } => {
                    if row.state != JobState::Running && row.state != JobState::Uncertain {
                        return Err(JobError::InvalidRequest);
                    }
                    row.receipt = Some(receipt);
                    row.state = JobState::Uncertain;
                    row.lease_until = None;
                    row.diagnostic = Some(DiagnosticCode::SpendReconciliationRequired);
                }
                JobResolution::KnownZeroCharge { receipt } => {
                    if row.state != JobState::Running && row.state != JobState::Uncertain {
                        return Err(JobError::InvalidRequest);
                    }
                    row.receipt = Some(receipt);
                    row.lease_until = None;
                    row.diagnostic = None;
                    if row.purged {
                        finish(&mut row, JobState::Purged, now, config)?;
                    } else if row.cancel_requested {
                        finish(&mut row, JobState::Cancelled, now, config)?;
                        delete_copies(&mut row);
                    } else if row.generation >= u64::from(row.max_attempts) {
                        row.diagnostic = Some(DiagnosticCode::AttemptBudgetExhausted);
                        finish(&mut row, JobState::Refused, now, config)?;
                    } else {
                        row.state = JobState::Pending;
                    }
                }
                JobResolution::PaidResult {
                    receipt,
                    recovery_until,
                } => {
                    row.receipt = Some(receipt);
                    row.diagnostic = None;
                    if let Some(until) = recovery_until {
                        row.recovery_until = Some(
                            row.recovery_until
                                .map_or(until, |current| current.min(until)),
                        );
                    }
                    let state = if row.purged {
                        JobState::Purged
                    } else if row.cancel_requested {
                        JobState::Cancelled
                    } else {
                        JobState::Succeeded
                    };
                    finish(&mut row, state, now, config)?;
                }
                JobResolution::Failed {
                    receipt,
                    diagnostic,
                } => {
                    row.receipt = Some(receipt);
                    row.diagnostic = Some(diagnostic);
                    let state = if row.purged {
                        JobState::Purged
                    } else if row.cancel_requested {
                        JobState::Cancelled
                    } else {
                        JobState::Failed
                    };
                    finish(&mut row, state, now, config)?;
                }
            }
            if row.purged {
                delete_copies(&mut row);
            }
            save_job(rows, config, row)?;
            Ok(JobResponse::Done)
        }
        JobRequest::Completions { limit, max_bytes } => {
            page(config, limit)?;
            if max_bytes < 2 || max_bytes > config.max_page_bytes {
                return Err(JobError::InvalidRequest);
            }
            let mut candidates = rows.select(scope, JobQuery::Final, now, limit)?;
            if candidates.len() < limit {
                candidates.extend(rows.select(
                    scope,
                    JobQuery::Notices,
                    now,
                    limit - candidates.len(),
                )?);
            }
            let mut deliveries = Vec::new();
            let mut bytes: usize = 2; // JSON array brackets, plus commas between deliveries.
            for mut row in candidates {
                let final_result = !row.state.unfinished();
                if final_result && row.recovery_until.is_some_and(|until| until <= now) {
                    row.result_expired = true;
                    delete_copies(&mut row);
                }
                let token = if final_result {
                    row.delivery_generation = row
                        .delivery_generation
                        .checked_add(1)
                        .ok_or(JobError::InvalidRequest)?;
                    row.delivery_until = Some(deadline(now, config.delivery_lease_seconds)?);
                    Some(DeliveryToken {
                        job: row.id.clone(),
                        generation: row.delivery_generation,
                    })
                } else {
                    None
                };
                let mut completion = row.clone();
                completion.payload = None;
                completion.checkpoint = None;
                completion.admission = None;
                let delivery = Delivery { completion, token };
                let Some(required) = page_bytes(
                    &delivery,
                    bytes,
                    max_bytes,
                    !deliveries.is_empty(),
                    |bytes| JobError::CompletionTooLarge {
                        job: row.id.clone(),
                        bytes,
                    },
                )?
                else {
                    break;
                };
                bytes = required;
                if final_result {
                    save_job(rows, config, row)?;
                }
                deliveries.push(delivery);
            }
            Ok(JobResponse::Deliveries(deliveries))
        }
        JobRequest::Ack(acks) => {
            if acks.len() > config.max_batch
                || serde_json::to_vec(&acks)
                    .map_err(|_| JobError::Storage)?
                    .len()
                    > config.max_page_bytes
            {
                return Err(JobError::InvalidRequest);
            }
            // Scope checks for the entire request precede every lookup/write.
            for (token, _) in &acks {
                scoped(scope, &token.job)?;
            }
            let mut results = Vec::with_capacity(acks.len());
            for (token, disposition) in acks {
                let mut row = get(rows, scope, &token.job)?;
                if row.state.unfinished() {
                    return Err(JobError::NotFinal);
                }
                if token.generation == 0 || token.generation > row.delivery_generation {
                    return Err(JobError::InvalidRequest);
                }
                if row.state.acked() {
                    results.push(AckResult::AlreadyAcked(
                        if row.state == JobState::Accepted {
                            Disposition::Accepted
                        } else {
                            Disposition::Discarded
                        },
                    ));
                } else {
                    row.final_state = Some(row.state);
                    row.state = match disposition {
                        Disposition::Accepted => JobState::Accepted,
                        Disposition::Discarded => JobState::Discarded,
                    };
                    delete_copies(&mut row);
                    row.owners.clear();
                    row.delivery_until = None;
                    save_job(rows, config, row)?;
                    results.push(AckResult::Acked(disposition));
                }
            }
            Ok(JobResponse::Acks(results))
        }
        JobRequest::Cancel(selector) => {
            let selected = match selector {
                Selector::Ids(ids) => {
                    if ids.len() > config.max_batch {
                        return Err(JobError::InvalidRequest);
                    }
                    for id in &ids {
                        scoped(scope, id)?;
                    }
                    ids.iter()
                        .map(|id| get(rows, scope, id))
                        .collect::<Result<Vec<_>, _>>()?
                }
                Selector::Group(group) => {
                    rows.select(scope, JobQuery::Group(group), now, usize::MAX)?
                }
            };
            let mut changed = 0;
            for mut row in selected {
                if !row.state.unfinished() {
                    continue;
                }
                if row.can_stop_without_accounting(now) {
                    finish(&mut row, JobState::Cancelled, now, config)?;
                    delete_copies(&mut row);
                } else {
                    row.cancel_requested = true;
                }
                save_job(rows, config, row)?;
                changed += 1;
            }
            Ok(JobResponse::Changed(changed))
        }
        JobRequest::PurgeOwner(owner) => {
            let selected = rows.select(scope, JobQuery::Owner(owner), now, usize::MAX)?;
            let count = selected.len();
            for mut row in selected {
                row.purged = true;
                row.cancel_requested = true;
                delete_copies(&mut row);
                if row.can_stop_without_accounting(now)
                    || row.state != JobState::Running
                        && row.state != JobState::Uncertain
                        && !row.state.acked()
                {
                    finish(&mut row, JobState::Purged, now, config)?;
                }
                save_job(rows, config, row)?;
            }
            Ok(JobResponse::Changed(count))
        }
        JobRequest::Status(group) => Ok(JobResponse::Summary(rows.summary(scope, &group, false)?)),
        JobRequest::RebuildSummary(group) => {
            Ok(JobResponse::Summary(rows.summary(scope, &group, true)?))
        }
        JobRequest::Diagnostics {
            group,
            after,
            limit,
        } => {
            page(config, limit)?;
            let selected =
                rows.select(scope, JobQuery::Diagnostics { group, after }, now, limit)?;
            let after = selected.last().map(|r| r.id.id.clone());
            let items = selected
                .into_iter()
                .map(|r| JobDiagnostic {
                    id: r.id,
                    state: r.state,
                    code: r.diagnostic,
                })
                .collect();
            Ok(JobResponse::Diagnostics(DiagnosticPage { items, after }))
        }
        JobRequest::Maintain => {
            let selected = rows.select(scope, JobQuery::Expired, now, config.maintenance_batch)?;
            let count = selected.len();
            for mut row in selected {
                row.result_expired = true;
                delete_copies(&mut row);
                save_job(rows, config, row)?;
            }
            Ok(JobResponse::Changed(count))
        }
        JobRequest::Get(id) => Ok(JobResponse::Job(Some(Box::new(get(rows, scope, &id)?)))),
        JobRequest::PendingUsage => Ok(JobResponse::Usage(rows.usage(scope)?)),
    }
}

fn validate_admission(scope: &JobScope, admission: &SignedAdmission) -> Result<(), JobError> {
    if admission.binding.tenant.0 != scope.tenant {
        return Err(JobError::Scope);
    }
    if admission.ordinal == 0 || !admission.binding.is_valid() || admission.signed.is_empty() {
        return Err(JobError::InvalidRequest);
    }
    Ok(())
}

/// Adjust a rebuildable summary after one canonical row transition.
#[doc(hidden)]
pub fn summary_transition(
    summary: &mut GroupSummary,
    old: Option<&JobRecord>,
    new: &JobRecord,
) -> Result<(), JobError> {
    if let Some(old) = old {
        let count = summary
            .counts
            .get_mut(&old.state)
            .ok_or(JobError::Storage)?;
        *count = count.checked_sub(1).ok_or(JobError::Storage)?;
        if *count == 0 {
            summary.counts.remove(&old.state);
        }
    }
    *summary.counts.entry(new.state).or_default() += 1;
    Ok(())
}
