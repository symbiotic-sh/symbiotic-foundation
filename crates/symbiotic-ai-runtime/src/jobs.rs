//! Durable model jobs on the canonical spend connection. Paid answers stay in
//! the ledger; deliveries borrow them and never persist a second result copy.
use crate::{ModelBinding, ModelError, Runtime, SpendReservation, SpendState, model, spend};
use chrono::Utc;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use symbiotic_core::DiagnosticCode;
use symbiotic_queue::{
    jobs::*,
    runner::{JobRunner, RunnerConfig, RunnerError},
};
use symbiotic_trace::UsageTrace;
use tokio::sync::watch;

fn storage(_: impl std::fmt::Debug) -> ModelError {
    ModelError::Queue(DiagnosticCode::SpendLedgerUnavailable)
}

/// Final delivery plus the ledger's sole paid recovery answer. The answer is
/// absent after expiry, confirmation or purge; accounting remains queryable.
#[derive(Debug, serde::Serialize)]
pub struct ModelDelivery {
    /// Job metadata and confirmation token.
    pub delivery: Delivery,
    /// Same-invocation answer, with no cache reuse across keys.
    pub output: Option<serde_json::Value>,
}

/// One trusted scoped job API on the runtime's ledger connection.
#[derive(Clone)]
pub struct ModelJobs {
    runtime: Runtime,
    ledger: Arc<spend::SqliteSpendLedger>,
    scope: JobScope,
    config: JobConfig,
}

impl Runtime {
    /// Open model jobs in an authenticated tenant/incarnation/queue namespace.
    /// A persistent runtime is required, as for direct paid execution.
    pub fn model_jobs(&self, scope: JobScope, config: JobConfig) -> Result<ModelJobs, JobError> {
        let jobs = ModelJobs {
            runtime: self.clone(),
            ledger: self.inner.job_ledger.clone().ok_or(JobError::Unavailable)?,
            scope,
            config,
        };
        jobs.request_sync(JobRequest::PendingUsage)?;
        Ok(jobs)
    }
}

/// Encode the complete request and frozen credential-free execution binding as
/// the job's canonical waiting copy. This is operational input, not another store.
pub fn model_job_payload<P>(
    binding: &ModelBinding<P>,
    request: &impl serde::Serialize,
) -> Result<Vec<u8>, JobError> {
    let identity = binding
        .identity
        .as_ref()
        .filter(|id| id.is_valid())
        .ok_or(JobError::InvalidRequest)?;
    serde_json::to_vec(&serde_json::json!({"binding": identity, "sharing": binding.account_sharing_key, "request": request})).map_err(|_| JobError::Storage)
}
fn input(
    payload: &[u8],
) -> Result<
    (
        crate::BindingIdentity,
        Option<crate::AccountSharingKey>,
        serde_json::Value,
    ),
    JobError,
> {
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| JobError::InvalidRequest)?;
    let identity = serde_json::from_value(
        value
            .get("binding")
            .ok_or(JobError::InvalidRequest)?
            .clone(),
    )
    .map_err(|_| JobError::InvalidRequest)?;
    let sharing = serde_json::from_value(
        value
            .get("sharing")
            .ok_or(JobError::InvalidRequest)?
            .clone(),
    )
    .map_err(|_| JobError::InvalidRequest)?;
    Ok((
        identity,
        sharing,
        value
            .get("request")
            .ok_or(JobError::InvalidRequest)?
            .clone(),
    ))
}
fn paid_resolution(
    tx: &Transaction<'_>,
    receipt: &crate::SpendReceipt,
    now: chrono::DateTime<Utc>,
    max_bytes: usize,
) -> Result<JobResolution, JobError> {
    let bytes: usize = tx.query_row("SELECT coalesce(length(CAST(recovery AS BLOB)),0) FROM spend_receipts WHERE reference=?1", [receipt.reservation.reference.as_str()], |r| r.get(0)).map_err(|_| JobError::Storage)?;
    if bytes > max_bytes {
        tx.execute(
            "UPDATE spend_receipts SET recovery=NULL,recovery_expires_at=NULL WHERE reference=?1",
            [receipt.reservation.reference.as_str()],
        )
        .map_err(|_| JobError::Storage)?;
        return Ok(JobResolution::Failed {
            receipt: receipt.reservation.reference.as_str().into(),
            diagnostic: DiagnosticCode::QueueResultTooLarge,
        });
    }
    let deadline: Option<String> = tx
        .query_row(
            "SELECT recovery_expires_at FROM spend_receipts WHERE reference=?1",
            [receipt.reservation.reference.as_str()],
            |r| r.get(0),
        )
        .map_err(|_| JobError::Storage)?;
    let deadline = deadline
        .map(|s| chrono::DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)))
        .transpose()
        .map_err(|_| JobError::Storage)?;
    Ok(JobResolution::PaidResult {
        receipt: receipt.reservation.reference.as_str().into(),
        recovery_until: Some(deadline.unwrap_or(now)),
    })
}

// This canonical registration survives confirmation and erasure: neither removes
// the kind's single binding. IMMEDIATE transactions serialize registration/enqueue.
fn bind_kind(
    tx: &Transaction<'_>,
    scope: &JobScope,
    kind: &str,
    identity: &crate::BindingIdentity,
    sharing: &Option<crate::AccountSharingKey>,
) -> Result<(), JobError> {
    let scope = serde_json::to_string(scope).map_err(|_| JobError::Storage)?;
    let binding = serde_json::to_string(&(identity, sharing)).map_err(|_| JobError::Storage)?;
    let previous: Option<String> = tx
        .query_row(
            "SELECT binding FROM model_job_bindings WHERE scope=?1 AND kind=?2",
            params![scope, kind],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| JobError::Storage)?;
    if previous
        .as_ref()
        .is_some_and(|previous| previous != &binding)
    {
        return Err(JobError::KeyConflict);
    }
    tx.execute(
        "INSERT OR IGNORE INTO model_job_bindings(scope,kind,binding) VALUES (?1,?2,?3)",
        params![scope, kind, binding],
    )
    .map_err(|_| JobError::Storage)?;
    Ok(())
}

impl ModelJobs {
    /// D1 invocation key for direct execution/recovery of this scoped job.
    /// The scope and caller key identify one invocation across job attempts.
    pub fn invocation_key(&self, key: &str) -> Result<String, JobError> {
        spend::job_invocation_key(&self.scope, key).map_err(|_| JobError::Storage)
    }
    fn transaction<T>(
        &self,
        f: impl FnOnce(&mut Transaction<'_>, chrono::DateTime<Utc>) -> Result<T, JobError>,
    ) -> Result<T, JobError> {
        let mut conn = self.ledger.0.lock().map_err(|_| JobError::Storage)?;
        let mut tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| JobError::Storage)?;
        let now = Utc::now();
        let result = f(&mut tx, now)?;
        tx.commit().map_err(|_| JobError::Storage)?;
        Ok(result)
    }
    fn op(
        &self,
        tx: &mut Transaction<'_>,
        now: chrono::DateTime<Utc>,
        request: JobRequest,
    ) -> Result<JobResponse, JobError> {
        symbiotic_queue_sqlite::jobs::jobs_in_transaction(
            tx,
            &self.scope,
            &self.config,
            now,
            request,
        )
    }
    /// Execute one bounded store operation. Ack, owner erasure and expiry discard
    /// ledger recovery in the same transaction as job-copy deletion.
    /// Use [`Self::completions`] for paid-answer delivery with its byte preflight.
    pub async fn request(&self, request: JobRequest) -> Result<JobResponse, JobError> {
        if !matches!(
            request,
            JobRequest::Enqueue(_)
                | JobRequest::Ack(_)
                | JobRequest::Cancel(_)
                | JobRequest::PurgeOwner(_)
                | JobRequest::Diagnostics { .. }
                | JobRequest::Maintain
                | JobRequest::Get(_)
                | JobRequest::PendingUsage
        ) {
            return Err(JobError::InvalidRequest);
        }
        let jobs = self.clone();
        tokio::task::spawn_blocking(move || jobs.request_sync(request))
            .await
            .map_err(|_| JobError::Storage)?
    }
    fn request_sync(&self, request: JobRequest) -> Result<JobResponse, JobError> {
        if let JobRequest::Enqueue(specs) = &request {
            if specs.len() > self.config.max_batch {
                return Err(JobError::InvalidRequest);
            }
            for spec in specs {
                if spec.execution != Execution::Model {
                    return Err(JobError::InvalidRequest);
                }
                let (identity, sharing, _) = input(&spec.payload)?;
                if !identity.is_valid()
                    || identity.tenant.0 != self.scope.tenant
                    || crate::account_scope(&identity, sharing.as_ref()).is_err()
                {
                    return Err(JobError::InvalidRequest);
                }
            }
        }
        let purging = matches!(request, JobRequest::PurgeOwner(_));
        if matches!(
            request,
            JobRequest::Completions { .. }
                | JobRequest::Resolve { .. }
                | JobRequest::ClaimPaid { .. }
                | JobRequest::Claim { .. }
                | JobRequest::ClaimJob(_)
        ) {
            return Err(JobError::InvalidRequest);
        }
        self.transaction(|tx, now| {
            if let JobRequest::Enqueue(specs) = &request {
                for spec in specs {
                    let (identity, sharing, _) = input(&spec.payload)?;
                    bind_kind(tx, &self.scope, &spec.kind, &identity, &sharing)?;
                }
            }
            let affected = symbiotic_queue_sqlite::jobs::paid_copies_for_request(tx, &self.scope, &self.config, now, &request)?;
            let response = self.op(tx, now, request)?;
            for row in affected {
                let receipt = match row.receipt {
                    reference if !(purging && row.state.unfinished()) => reference,
                    _ if purging && row.execution == Execution::Model && row.payload.is_some() => {
                        let (identity, sharing, _) = input(row.payload.as_deref().ok_or(JobError::InvalidRequest)?)?;
                        let account = crate::account_scope(&identity, sharing.as_ref()).map_err(|_| JobError::Storage)?;
                        let invocation = model::execution_invocation_identity(&identity, &self.invocation_key(&row.key)?).map_err(|_| JobError::Storage)?;
                        spend::invocation_in(tx, &account, &invocation).map_err(|_| JobError::Storage)?.map(|r| r.reservation.reference.as_str().to_string())
                    }
                    _ => row.receipt,
                };
                if let Some(receipt) = receipt
                    && let JobResponse::Job(Some(row)) = self.op(tx, now, JobRequest::Get(row.id))?
                    && (row.state.acked() || row.purged || row.result_expired) {
                    tx.execute("UPDATE spend_receipts SET recovery=NULL,recovery_expires_at=NULL WHERE reference=?1", [&receipt]).map_err(|_| JobError::Storage)?;
                }
            }
            Ok(response)
        })
    }
    /// Deliver oldest final jobs within both bounds. Ledger answer sizes are
    /// preflighted before loading content or committing any delivery lease.
    pub async fn completions(
        &self,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<ModelDelivery>, JobError> {
        let jobs = self.clone();
        tokio::task::spawn_blocking(move || jobs.completions_sync(limit, max_bytes))
            .await
            .map_err(|_| JobError::Storage)?
    }
    fn completions_sync(
        &self,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<ModelDelivery>, JobError> {
        if limit == 0
            || limit > self.config.max_page
            || max_bytes < 2
            || max_bytes > self.config.max_page_bytes
        {
            return Err(JobError::InvalidRequest);
        }
        self.transaction(|tx, now| {
            let mut items = Vec::new();
            let mut total = 2usize;
            for _ in 0..limit {
                tx.execute_batch("SAVEPOINT model_delivery").map_err(|_| JobError::Storage)?;
                let JobResponse::Deliveries(page) = symbiotic_queue_sqlite::jobs::jobs_in_transaction(tx, &self.scope, &self.config, now, JobRequest::Completions { limit: 1, max_bytes: self.config.max_page_bytes })? else { return Err(JobError::InvalidRequest) };
                let Some(mut delivery) = page.items.into_iter().next() else {
                    tx.execute_batch("RELEASE model_delivery").map_err(|_| JobError::Storage)?;
                    break;
                };
                let receipt = delivery.completion.receipt.clone();
                let reference = receipt.as_deref();
                let len: usize = match reference {
                    Some(reference) if !delivery.completion.result_expired && !delivery.completion.purged => tx.query_row("SELECT coalesce(length(CAST(recovery AS BLOB)),4) FROM spend_receipts WHERE reference=?1 AND recovery_expires_at>?2", params![reference, now.to_rfc3339()], |r| r.get(0)).optional().map_err(|_| JobError::Storage)?.unwrap_or(4),
                    _ => 4,
                };
                // Wire shape is {delivery,output}; recovery is canonical compact JSON.
                let bytes = encoded_bytes(&delivery)?.checked_add(len).and_then(|n| n.checked_add(23)).ok_or(JobError::Storage)?;
                if bytes + 2 > max_bytes { return Err(JobError::CompletionTooLarge { job: delivery.completion.id, bytes: bytes + 2 }); }
                let next = total.checked_add(bytes + usize::from(!items.is_empty())).ok_or(JobError::Storage)?;
                if next > max_bytes {
                    tx.execute_batch("ROLLBACK TO model_delivery; RELEASE model_delivery").map_err(|_| JobError::Storage)?;
                    break;
                }
                let output = match reference {
                    Some(reference) if !delivery.completion.result_expired && !delivery.completion.purged => spend::receipt_in(tx, &crate::SpendReceiptRef::new(reference).map_err(|_| JobError::Storage)?).map_err(|_| JobError::Storage)?.and_then(|r| r.recovery),
                    _ => None,
                };
                if output.is_none() && delivery.completion.origin == Some(ResultOrigin::Paid)
                    && matches!(delivery.completion.state, JobState::Succeeded | JobState::Cancelled)
                    && delivery.completion.diagnostic.is_none() {
                    delivery.completion.result_expired = true;
                }
                if delivery.completion.result_expired && let Some(reference) = reference {
                    tx.execute("UPDATE spend_receipts SET recovery=NULL,recovery_expires_at=NULL WHERE reference=?1", [reference]).map_err(|_| JobError::Storage)?;
                }
                tx.execute_batch("RELEASE model_delivery").map_err(|_| JobError::Storage)?;
                total = next;
                items.push(ModelDelivery { delivery, output });
            }
            Ok(items)
        })
    }

    async fn maintain(
        self,
        mut stop: watch::Receiver<bool>,
        interval: Duration,
    ) -> Result<(), RunnerError> {
        let mut timer = tokio::time::interval(interval);
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            tokio::select! {
                _ = stop.changed() => {},
                _ = timer.tick() => {
                    let jobs = self.clone();
                    tokio::task::spawn_blocking(move || jobs.request_sync(JobRequest::Maintain)).await.map_err(|_| RunnerError::WorkerTask)??;
                }
            }
        }
    }

    async fn recover(&self, kind: String) -> Result<(), JobError> {
        let mut after = None;
        loop {
            let jobs = self.clone();
            let kind = kind.clone();
            let cursor = after.clone();
            let (count, last) = tokio::task::spawn_blocking(move || jobs.transaction(|tx, now| {
                let JobResponse::Candidates(rows) = jobs.op(tx, now, JobRequest::RecoveryCandidates { kinds: vec![kind], after: cursor, limit: jobs.config.max_page, max_bytes: jobs.config.max_page_bytes })? else { return Err(JobError::InvalidRequest) };
                let count = rows.len();
                let last = rows.last().map(|r| r.id.id.clone());
                for row in rows {
                    let reference = crate::SpendReceiptRef::new(row.receipt.as_deref().ok_or(JobError::Storage)?).map_err(|_| JobError::Storage)?;
                    let receipt = spend::receipt_in(tx, &reference).map_err(|_| JobError::Storage)?.ok_or(JobError::Storage)?;
                    let resolution = if receipt.output.is_some() {
                        paid_resolution(tx, &receipt, now, jobs.config.max_result_bytes)?
                    } else if receipt.state == SpendState::Released {
                        JobResolution::KnownZeroCharge { receipt: receipt.reservation.reference.as_str().into() }
                    } else if receipt.state == SpendState::Settled {
                        JobResolution::Failed { receipt: receipt.reservation.reference.as_str().into(), diagnostic: DiagnosticCode::InvocationCompleted }
                    } else { JobResolution::Uncertain { receipt: receipt.reservation.reference.as_str().into() } };
                    jobs.op(tx, now, JobRequest::Resolve { job: row.id.clone(), generation: row.generation, resolution })?;
                    if row.purged || row.recovery_until.is_some_and(|until| until <= now) && receipt.output.is_some() {
                        tx.execute("UPDATE spend_receipts SET recovery=NULL,recovery_expires_at=NULL WHERE reference=?1", [receipt.reservation.reference.as_str()]).map_err(|_| JobError::Storage)?;
                    }
                }
                Ok((count, last))
            })).await.map_err(|_| JobError::Storage)??;
            if count == 0 {
                return Ok(());
            }
            after = last;
        }
    }
}

#[derive(Clone)]
struct Claim {
    id: JobId,
    generation: u64,
    receipt: String,
    max_attempts: u32,
}
struct ClaimOwner {
    jobs: ModelJobs,
    candidate: JobId,
    claim: Mutex<Option<Claim>>,
    heartbeat: Duration,
    finished: AtomicBool,
    stop: watch::Receiver<bool>,
}
impl ClaimOwner {
    fn claim_record(&self) -> Result<Claim, ModelError> {
        self.claim
            .lock()
            .map_err(storage)?
            .clone()
            .ok_or_else(|| storage(()))
    }
    fn previous_in(
        &self,
        tx: &mut Transaction<'_>,
        now: chrono::DateTime<Utc>,
        reservation: &SpendReservation,
    ) -> Result<(bool, Option<crate::SpendReceipt>), JobError> {
        let JobResponse::Job(Some(current)) =
            self.jobs
                .op(tx, now, JobRequest::Get(self.candidate.clone()))?
        else {
            return Err(JobError::NotFound);
        };
        if current.state != JobState::Pending {
            return Ok((true, None));
        }
        let previous = spend::invocation_in(tx, &reservation.account, &reservation.invocation)
            .map_err(|_| JobError::Storage)?;
        if previous
            .as_ref()
            .is_some_and(|r| r.reservation.binding != reservation.binding)
        {
            return Err(JobError::KeyConflict);
        }
        if let Some(receipt) = &previous
            && receipt.output.is_some()
        {
            self.resolve(
                tx,
                &current.id,
                current.generation,
                now,
                paid_resolution(tx, receipt, now, self.jobs.config.max_result_bytes)?,
            )?;
            if current.purged || current.recovery_until.is_some_and(|until| until <= now) {
                tx.execute("UPDATE spend_receipts SET recovery=NULL,recovery_expires_at=NULL WHERE reference=?1", [receipt.reservation.reference.as_str()]).map_err(|_| JobError::Storage)?;
            }
            return Ok((true, None));
        }
        Ok((false, previous))
    }
    fn resolve(
        &self,
        tx: &mut Transaction<'_>,
        job: &JobId,
        generation: u64,
        now: chrono::DateTime<Utc>,
        resolution: JobResolution,
    ) -> Result<(), JobError> {
        self.jobs.op(
            tx,
            now,
            JobRequest::Resolve {
                job: job.clone(),
                generation,
                resolution,
            },
        )?;
        Ok(())
    }
}
impl model::ModelJob for ClaimOwner {
    fn recover(&self, reservation: &SpendReservation) -> Result<bool, ModelError> {
        let recovered = self
            .jobs
            .transaction(|tx, now| self.previous_in(tx, now, reservation).map(|(done, _)| done))
            .map_err(storage)?;
        if recovered {
            self.finished.store(true, Ordering::SeqCst);
        }
        Ok(recovered)
    }
    fn claim(
        &self,
        reservation: &SpendReservation,
        limit: u32,
    ) -> Result<Option<Vec<u8>>, ModelError> {
        if *self.stop.borrow() {
            self.finished.store(true, Ordering::SeqCst);
            return Ok(None);
        }
        let result = self.jobs.transaction(|tx, now| {
            let (done, previous) = self.previous_in(tx, now, reservation)?;
            if done {
                return Ok(None);
            }
            if let Some(receipt) = previous
                && receipt.state == SpendState::Unknown
            {
                let JobResponse::Job(Some(row)) = self.jobs.op(
                    tx,
                    now,
                    JobRequest::ClaimPaid {
                        job: self.candidate.clone(),
                        receipt: receipt.reservation.reference.as_str().into(),
                    },
                )?
                else {
                    return Ok(None);
                };
                self.resolve(
                    tx,
                    &row.id,
                    row.generation,
                    now,
                    JobResolution::Uncertain {
                        receipt: receipt.reservation.reference.as_str().into(),
                    },
                )?;
                return Ok(None);
            }
            let JobResponse::Job(row) = self.jobs.op(
                tx,
                now,
                JobRequest::ClaimPaid {
                    job: self.candidate.clone(),
                    receipt: reservation.reference.as_str().into(),
                },
            )?
            else {
                return Err(JobError::InvalidRequest);
            };
            let Some(row) = row else {
                return Ok(None);
            };
            let accepted = spend::SqliteSpendLedger::reserve_with_limit_in(
                tx,
                reservation,
                Some(row.max_attempts.min(limit)),
                false,
            )
            .map_err(|error| JobError::Execution(error.code()))?;
            if !accepted {
                return Err(JobError::Storage);
            }
            Ok(Some(*row))
        });
        let result = match result {
            Ok(result) => result,
            Err(JobError::Execution(
                code @ (DiagnosticCode::SpendBudgetExhausted
                | DiagnosticCode::AttemptBudgetExhausted),
            )) => {
                model::ModelJob::refuse(self, code)?;
                return Ok(None);
            }
            Err(JobError::Execution(code)) => return Err(ModelError::Queue(code)),
            Err(error) => return Err(storage(error)),
        };
        let payload = result
            .as_ref()
            .map(|row| {
                let (_, _, request) =
                    input(row.payload.as_deref().ok_or(JobError::InvalidRequest)?)?;
                serde_json::to_vec(&request).map_err(|_| JobError::Storage)
            })
            .transpose()
            .map_err(storage)?;
        *self.claim.lock().map_err(storage)? = result
            .map(|row| {
                Ok(Claim {
                    id: row.id,
                    generation: row.generation,
                    receipt: row.receipt.ok_or_else(|| storage(()))?,
                    max_attempts: row.max_attempts,
                })
            })
            .transpose()?;
        if payload.is_none() {
            self.finished.store(true, Ordering::SeqCst);
        }
        Ok(payload)
    }
    fn heartbeat(&self) -> Result<bool, ModelError> {
        let (job, generation) = {
            let claim = self.claim.lock().map_err(storage)?;
            let claim = claim.as_ref().ok_or_else(|| storage(()))?;
            (claim.id.clone(), claim.generation)
        };
        self.jobs
            .transaction(|tx, now| {
                match self
                    .jobs
                    .op(tx, now, JobRequest::Heartbeat { job, generation })?
                {
                    JobResponse::Heartbeat(cancel) => Ok(cancel),
                    _ => Err(JobError::InvalidRequest),
                }
            })
            .map_err(|error| {
                if error == JobError::StaleClaim {
                    ModelError::Queue(DiagnosticCode::QueueFailure)
                } else {
                    storage(error)
                }
            })
    }
    fn finish(
        &self,
        state: SpendState,
        usage: Option<UsageTrace>,
        mut output: Option<serde_json::Value>,
        mut failure: Option<DiagnosticCode>,
        retry: bool,
    ) -> Result<(), ModelError> {
        let row = self.claim_record()?;
        let oversized = output
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(storage)?
            .is_some_and(|bytes| bytes.len() > self.jobs.config.max_result_bytes);
        let evidence = output
            .as_ref()
            .map(|_| serde_json::json!({"output_received": true}));
        if oversized {
            output = None;
            failure = Some(DiagnosticCode::QueueResultTooLarge);
        }
        let reference = crate::SpendReceiptRef::new(&row.receipt)?;
        self.jobs
            .transaction(|tx, now| {
                let JobResponse::Job(Some(current)) =
                    self.jobs.op(tx, now, JobRequest::Get(row.id.clone()))?
                else {
                    return Err(JobError::NotFound);
                };
                if current.generation != row.generation {
                    return Err(JobError::StaleClaim);
                }
                spend::SqliteSpendLedger::save_recovery_in(
                    tx,
                    &reference,
                    &output,
                    self.jobs.ledger.retention(),
                    current.recovery_until,
                    !current.purged,
                    now,
                )
                .map_err(|_| JobError::Storage)?;
                spend::SqliteSpendLedger::finish_in(tx, &reference, state, usage, evidence)
                    .map_err(|_| JobError::Storage)?;
                if output.is_none() && current.cancel_requested && !current.purged {
                    self.jobs.op(
                        tx,
                        now,
                        JobRequest::Complete {
                            job: current.id.clone(),
                            generation: current.generation,
                            state: JobState::Cancelled,
                            origin: ResultOrigin::Paid,
                            output: None,
                            receipt: Some(reference.as_str().into()),
                            diagnostic: failure,
                        },
                    )?;
                    return Ok(());
                }
                let resolution = if output.is_some() {
                    let receipt = spend::receipt_in(tx, &reference)
                        .map_err(|_| JobError::Storage)?
                        .ok_or(JobError::Storage)?;
                    paid_resolution(tx, &receipt, now, self.jobs.config.max_result_bytes)?
                } else if state == SpendState::Released && retry {
                    JobResolution::KnownZeroCharge {
                        receipt: reference.as_str().into(),
                    }
                } else if state == SpendState::Unknown && !oversized {
                    JobResolution::Uncertain {
                        receipt: reference.as_str().into(),
                    }
                } else {
                    JobResolution::Failed {
                        receipt: reference.as_str().into(),
                        diagnostic: failure.ok_or(JobError::InvalidRequest)?,
                    }
                };
                self.resolve(tx, &current.id, current.generation, now, resolution)
            })
            .map_err(storage)?;
        self.finished.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn release(&self) -> Result<(), ModelError> {
        let row = self.claim_record()?;
        let reference = crate::SpendReceiptRef::new(&row.receipt)?;
        // The shared release owner records durable pre-dispatch evidence.
        self.jobs
            .transaction(|tx, now| {
                spend::SqliteSpendLedger::release_in(tx, &reference)
                    .map_err(|_| JobError::Storage)?;
                self.resolve(
                    tx,
                    &row.id,
                    row.generation,
                    now,
                    JobResolution::KnownZeroCharge {
                        receipt: reference.as_str().into(),
                    },
                )
            })
            .map_err(storage)?;
        self.finished.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn refuse(&self, code: DiagnosticCode) -> Result<(), ModelError> {
        self.jobs
            .transaction(|tx, now| {
                self.jobs.op(
                    tx,
                    now,
                    JobRequest::RefusePending {
                        job: self.candidate.clone(),
                        diagnostic: code,
                    },
                )?;
                Ok(())
            })
            .map_err(storage)?;
        self.finished.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn eligible(&self) -> Result<bool, ModelError> {
        let eligible = !*self.stop.borrow()
            && self
                .jobs
                .transaction(|tx, now| {
                    let JobResponse::Job(Some(row)) =
                        self.jobs
                            .op(tx, now, JobRequest::Get(self.candidate.clone()))?
                    else {
                        return Err(JobError::NotFound);
                    };
                    Ok(row.state == JobState::Pending && !row.cancel_requested && !row.purged)
                })
                .map_err(storage)?;
        if !eligible {
            self.finished.store(true, Ordering::SeqCst);
        }
        Ok(eligible)
    }
    fn can_retry(&self, limit: u32) -> Result<bool, ModelError> {
        let claim = self.claim_record()?;
        if claim.generation >= u64::from(claim.max_attempts.min(limit)) {
            return Ok(false);
        }
        if self.heartbeat()? {
            return Ok(false);
        }
        self.jobs
            .transaction(|tx, _| {
                let reference =
                    crate::SpendReceiptRef::new(&claim.receipt).map_err(|_| JobError::Storage)?;
                let receipt = spend::receipt_in(tx, &reference)
                    .map_err(|_| JobError::Storage)?
                    .ok_or(JobError::Storage)?;
                Ok(receipt
                    .attempt_limit
                    .is_none_or(|limit| receipt.attempts_used < limit))
            })
            .map_err(storage)
    }
    fn attempt(&self) -> Result<u32, ModelError> {
        u32::try_from(self.claim_record()?.generation).map_err(storage)
    }
    fn heartbeat_interval(&self) -> Duration {
        self.heartbeat
    }
}

macro_rules! model_runner {
    ($name:ident, $bind:ident, $call:ident, $provider:ident, $request:ty, $doc:literal) => {
        impl ModelJobs {
            #[doc = $doc]
            pub async fn $name<P>(&self, binding: ModelBinding<P>, config: RunnerConfig, kind: String) -> Result<JobRunner, RunnerError>
            where P: crate::$provider + Clone + 'static {
                let bound = self.runtime.bind(binding.provider.descriptor(), &binding).map_err(|_| JobError::InvalidRequest)?;
                let heartbeat = config.heartbeat_interval_ms.map(Duration::from_millis).unwrap_or(Duration::from_secs(self.config.claim_lease_seconds) / 3);
                if config.version != 1 || config.worker_count == 0 || config.poll_interval_ms == 0 || config.maintenance_interval_ms == 0 || heartbeat.is_zero() || heartbeat > Duration::from_secs(self.config.claim_lease_seconds) / 2 || kind.is_empty() || binding.accepted_spend.is_some() || bound.policy.request_debug_dir.is_some() || bound.sinks.identity.tenant.0 != self.scope.tenant {
                    return Err(JobError::InvalidRequest.into());
                }
                self.transaction(|tx, _| bind_kind(tx, &self.scope, &kind, &bound.sinks.identity, &binding.account_sharing_key))?;
                let jobs = self.clone();
                let maintenance = self.clone();
                let poll = Duration::from_millis(config.poll_interval_ms);
                Ok(JobRunner::start_owned(config.worker_count, move |mut stop| {
                    let jobs = jobs.clone(); let binding = binding.clone(); let kind = kind.clone();
                    async move {
                        loop {
                            if *stop.borrow() { return Ok(()); }
                            jobs.recover(kind.clone()).await?;
                            let query = jobs.clone(); let query_kind = kind.clone();
                            let response = tokio::task::spawn_blocking(move || query.request_sync(JobRequest::Candidates { kinds: vec![query_kind], limit: 1, max_bytes: query.config.max_page_bytes })).await.map_err(|_| RunnerError::WorkerTask)??;
                            let JobResponse::Candidates(rows) = response else { return Err(JobError::InvalidRequest.into()) };
                            if let Some(mut candidate) = rows.into_iter().next() {
                                if candidate.execution != Execution::Model { return Err(JobError::InvalidRequest.into()); }
                                let owner = Arc::new(ClaimOwner { jobs: jobs.clone(), candidate: candidate.id.clone(), claim: Mutex::new(None), heartbeat, finished: AtomicBool::new(false), stop: stop.clone() });
                                let request = {
                                    let payload = candidate.payload.take().ok_or(JobError::InvalidRequest)?;
                                    input(&payload).and_then(|(_, _, request)| serde_json::from_value::<$request>(request).map_err(|_| JobError::InvalidRequest))
                                };
                                let result = match request {
                                    Ok(request) => {
                                        let mut binding = binding.clone().with_invocation(jobs.invocation_key(&candidate.key)?);
                                        binding.job_owner = Some(owner.clone());
                                        jobs.runtime.$bind(binding).map_err(|_| JobError::InvalidRequest)?.$call(request).await
                                    }
                                    Err(_) => { model::ModelJob::refuse(owner.as_ref(), DiagnosticCode::InvalidConfiguration).map_err(|_| JobError::Storage)?; continue; }
                                };
                                if let Err(ModelError::InvalidRequest(code)) = &result
                                    && !owner.finished.load(Ordering::SeqCst) {
                                    model::ModelJob::refuse(owner.as_ref(), *code).map_err(|_| JobError::Storage)?;
                                    continue;
                                }
                                if let Err(error) = result
                                    && (!owner.finished.load(Ordering::SeqCst) || matches!(error, ModelError::Queue(_)) && error.code() != DiagnosticCode::InvocationCompleted) {
                                    return Err(JobError::Execution(error.code()).into());
                                }
                            } else {
                                tokio::select! { _ = stop.changed() => {}, _ = tokio::time::sleep(poll) => {} }
                            }
                        }
                    }
                }, move |rx| maintenance.maintain(rx, Duration::from_millis(config.maintenance_interval_ms))))
            }
        }
    };
}
model_runner!(
    start_chat,
    chat,
    chat,
    ChatProvider,
    crate::ChatRequest,
    "Start chat workers without caller resubmission."
);
model_runner!(
    start_embedding,
    embedding,
    embed,
    EmbeddingProvider,
    crate::EmbeddingRequest,
    "Start embedding workers without caller resubmission."
);
model_runner!(
    start_rerank,
    rerank,
    rerank,
    RerankProvider,
    crate::RerankRequest,
    "Start reranking workers without caller resubmission."
);
model_runner!(
    start_classifier,
    classifier,
    classify,
    ClassifierProvider,
    crate::ClassifyRequest,
    "Start classifier workers without caller resubmission."
);

#[cfg(test)]
mod review_tests {
    use super::*;

    #[tokio::test]
    async fn review_17_claim_retains_only_metadata_for_heartbeats() {
        let dir = tempfile::tempdir().expect("temp directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("permissions");
        }
        let runtime = Runtime::open(crate::RuntimeConfig {
            state_dir: Some(dir.path().into()),
            ..Default::default()
        })
        .expect("runtime");
        let jobs = runtime
            .model_jobs(
                JobScope {
                    tenant: "tenant".into(),
                    incarnation: "1".into(),
                    queue: "q".into(),
                },
                JobConfig::default(),
            )
            .expect("jobs");
        let binding = ModelBinding::new(model::StaticChatProvider::new("response"))
            .with_identity(crate::BindingIdentity::new("tenant", "p", "1", "a"));
        let spec = JobSpec {
            key: "key".into(),
            group: None,
            owners: vec![],
            kind: "chat".into(),
            execution: Execution::Model,
            payload: model_job_payload(&binding, &serde_json::json!({"data": "x".repeat(65536)}))
                .expect("payload"),
            limits: JobLimits { max_attempts: 1 },
            recovery_until: None,
        };
        let JobResponse::Enqueued(rows) = jobs
            .request(JobRequest::Enqueue(vec![spec]))
            .await
            .expect("enqueue")
        else {
            panic!("enqueue response")
        };
        let Enqueued::Inserted(id) = &rows[0] else {
            panic!("inserted")
        };
        let JobResponse::Job(Some(candidate)) = jobs
            .request(JobRequest::Get(id.clone()))
            .await
            .expect("row")
        else {
            panic!("row response")
        };
        let (_stop, stop) = watch::channel(false);
        let owner = ClaimOwner {
            jobs,
            candidate: candidate.id.clone(),
            claim: Mutex::new(None),
            heartbeat: Duration::from_millis(10),
            finished: AtomicBool::new(false),
            stop,
        };
        let reservation = SpendReservation {
            reference: crate::SpendReceiptRef::new("metadata-test").expect("reference"),
            account: "account".into(),
            invocation: "invocation".into(),
            binding: "binding".into(),
            request_limit: None,
        };
        assert!(
            model::ModelJob::claim(&owner, &reservation, 1)
                .expect("claim")
                .is_some()
        );
        assert!(
            std::mem::size_of_val(&owner.claim_record().expect("metadata"))
                < std::mem::size_of::<JobRecord>()
        );
        assert!(!model::ModelJob::heartbeat(&owner).expect("heartbeat"));
    }
}
