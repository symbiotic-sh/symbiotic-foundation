//! Generic handler workers. SQLite owns recovery, cancellation intent and claim fences.

use crate::{QueueBackend, jobs::*};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use symbiotic_core::DiagnosticCode;
use thiserror::Error;
use tokio::{
    sync::watch,
    task::{JoinHandle, JoinSet},
};

/// Versioned worker policy. Lease length comes solely from [`JobConfig`];
/// its existing 30-second claim default remains provisional for the runner.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    /// Supported configuration format (1).
    pub version: u32,
    /// Concurrent handlers (4; PROVISIONAL).
    pub worker_count: usize,
    /// Store polling period for new work and external cancellation (100 ms; PROVISIONAL).
    pub poll_interval_ms: u64,
    /// Independent bounded maintenance period (60 seconds; PROVISIONAL).
    pub maintenance_interval_ms: u64,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            version: 1,
            worker_count: 4,
            poll_interval_ms: 100,
            maintenance_interval_ms: 60_000,
        }
    }
}

/// Cooperative cancellation; a handler decides how to finish work already started.
#[derive(Clone, Debug)]
pub struct CancelToken(watch::Receiver<bool>);

impl CancelToken {
    /// Whether cancellation was requested or the execution owner is gone.
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow() || self.0.has_changed().is_err()
    }

    /// Wait for cancellation without losing a signal sent before this call.
    pub async fn cancelled(&self) {
        let mut rx = self.0.clone();
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Claim identity and cooperative cancellation supplied to a handler.
#[derive(Clone, Debug)]
pub struct JobContext {
    /// Scoped durable identity.
    pub id: JobId,
    /// Caller idempotency key.
    pub key: String,
    /// One-based claim ordinal; also the stale-write fence.
    pub attempt: u64,
    /// Cancellation requested by the consumer or input erasure.
    pub cancel: CancelToken,
}

/// Static handler failure, safe to retain without input or error text.
#[derive(Clone, Copy, Debug, Error)]
#[error("{code}")]
pub struct JobFailure {
    /// Durable failure diagnostic.
    pub code: DiagnosticCode,
}

/// Product work with opaque, exactly round-tripping bytes and no spend receipt.
/// Handler failures are final; cancellation never causes a retry.
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// Execute one claim. Work already sent must finish under its own timeout;
    /// cancellation alone never drops this future.
    async fn run(&self, ctx: &JobContext, payload: &[u8]) -> Result<Vec<u8>, JobFailure>;
}

/// Visible runner failures; worker errors are collected while running handlers drain.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// Store/configuration failure.
    #[error(transparent)]
    Store(#[from] JobError),
    /// First monitoring failure and total failures while the handler drains.
    #[error("job monitoring failed {count} times; first cause: {cause}")]
    Monitoring {
        /// First store/configuration cause.
        cause: JobError,
        /// Total failed monitoring operations, including the first.
        count: usize,
    },
    /// Handler panicked; the runner attempts a fenced final failure without retry.
    #[error("job handler panicked: {0:?}")]
    HandlerPanicked(JobId),
    /// A worker task failed outside the handler boundary.
    #[error("job worker task failed")]
    WorkerTask,
    /// All failures from a stopped runner, including failures while draining.
    #[error("job runner failed: {0:?}")]
    Workers(Vec<RunnerError>),
}

struct Shared {
    backend: Arc<dyn QueueBackend>,
    scope: JobScope,
    jobs: JobConfig,
    kind: String,
    handler: Arc<dyn JobHandler>,
    poll: Duration,
}

impl Shared {
    async fn op(&self, request: JobRequest) -> Result<JobResponse, JobError> {
        self.backend
            .jobs(&self.scope, &self.jobs, Utc::now(), request)
            .await
    }

    async fn current(&self, claim: &JobRecord) -> Result<Box<JobRecord>, JobError> {
        match self.op(JobRequest::Get(claim.id.clone())).await? {
            JobResponse::Job(Some(row))
                if row.state == JobState::Running
                    && row.generation == claim.generation
                    && row.lease_until.is_some_and(|until| until > Utc::now()) =>
            {
                Ok(row)
            }
            JobResponse::Job(_) => Err(JobError::StaleClaim),
            _ => Err(JobError::InvalidRequest),
        }
    }

    async fn execute(self: &Arc<Self>, mut claim: JobRecord) -> Result<(), RunnerError> {
        if claim.execution != Execution::Handler {
            return Err(JobError::InvalidRequest.into());
        }
        claim.payload = None;
        let (cancel, rx) = watch::channel(false);
        let shared = self.clone();
        let row = claim.clone();
        // JoinSet supplies the panic boundary and aborts the task if its owning
        // worker is itself aborted. Ordinary cancel/shutdown always drains it.
        let mut task = JoinSet::new();
        task.spawn(async move {
            let current = shared.current(&row).await?;
            if current.cancel_requested || current.purged {
                return Ok::<_, JobError>(None);
            }
            let payload = current.payload.as_deref().ok_or(JobError::InvalidRequest)?;
            let ctx = JobContext {
                id: row.id,
                key: row.key,
                attempt: row.generation,
                cancel: CancelToken(rx),
            };
            Ok(Some(shared.handler.run(&ctx, payload).await))
        });
        let mut renew =
            tokio::time::interval(Duration::from_secs(self.jobs.claim_lease_seconds) / 3);
        let mut poll = tokio::time::interval(self.poll);
        let mut errors = Vec::new();
        let outcome = loop {
            let check = tokio::select! {
                result = task.join_next() => break result,
                _ = renew.tick() => self.op(JobRequest::Heartbeat { job: claim.id.clone(), generation: claim.generation }).await.map(|response| {
                    if matches!(response, JobResponse::Done) { Ok(()) } else { Err(JobError::InvalidRequest) }
                }).and_then(|r| r),
                _ = poll.tick(), if errors.is_empty() => self.signal_cancel(&claim, &cancel).await,
            };
            if let Err(error) = check {
                // Count monitoring failures while asking work to stop. Once cancellation
                // is signalled, polling adds nothing; scheduled heartbeats must
                // still protect draining work until the store fences the claim.
                let fenced = matches!(error, JobError::StaleClaim);
                match errors.first_mut() {
                    Some(RunnerError::Monitoring { count, .. }) => *count += 1,
                    _ => errors.push(RunnerError::Monitoring {
                        cause: error,
                        count: 1,
                    }),
                }
                cancel.send_replace(true);
                if fenced {
                    break task.join_next().await;
                }
            }
        };
        let (state, output, diagnostic) = match outcome {
            Some(Ok(Ok(Some(Ok(output))))) if output.len() > self.jobs.max_result_bytes => {
                errors.push(
                    JobError::ResultTooLarge {
                        job: claim.id.clone(),
                        bytes: output.len(),
                    }
                    .into(),
                );
                (JobState::Failed, None, Some(DiagnosticCode::QueueFailure))
            }
            Some(Ok(Ok(Some(Ok(output))))) => (JobState::Succeeded, Some(output), None),
            Some(Ok(Ok(Some(Err(failure))))) => (JobState::Failed, None, Some(failure.code)),
            Some(Ok(Ok(None))) => (JobState::Cancelled, None, None),
            Some(Ok(Err(error))) => {
                errors.push(error.into());
                return Err(RunnerError::Workers(errors));
            }
            Some(Err(_)) => {
                errors.push(RunnerError::HandlerPanicked(claim.id.clone()));
                (JobState::Failed, None, Some(DiagnosticCode::QueueFailure))
            }
            None => {
                errors.push(RunnerError::WorkerTask);
                return Err(RunnerError::Workers(errors));
            }
        };
        // Finished work, including a panic, always reaches the store's claim fence.
        match self
            .op(JobRequest::Complete {
                job: claim.id,
                generation: claim.generation,
                state,
                origin: ResultOrigin::Handler,
                output,
                receipt: None,
                diagnostic,
            })
            .await
        {
            Ok(JobResponse::Done) => {}
            Ok(_) => errors.push(JobError::InvalidRequest.into()),
            Err(error) => errors.push(error.into()),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(RunnerError::Workers(errors))
        }
    }

    async fn signal_cancel(
        &self,
        claim: &JobRecord,
        cancel: &watch::Sender<bool>,
    ) -> Result<(), JobError> {
        let row = self.current(claim).await?;
        if row.cancel_requested || row.purged {
            cancel.send_replace(true);
        }
        Ok(())
    }

    async fn maintain(
        self: Arc<Self>,
        mut stop: watch::Receiver<bool>,
        interval: Duration,
    ) -> Result<(), RunnerError> {
        let mut timer = tokio::time::interval(interval);
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = stop.changed() => continue,
                _ = timer.tick() => {
                    if !matches!(self.op(JobRequest::Maintain).await?, JobResponse::Changed(_)) {
                        return Err(JobError::InvalidRequest.into());
                    }
                }
            }
        }
    }

    async fn worker(self: Arc<Self>, mut stop: watch::Receiver<bool>) -> Result<(), RunnerError> {
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            match self
                .op(JobRequest::Claim {
                    kinds: vec![self.kind.clone()],
                    slots_available: 1,
                })
                .await?
            {
                JobResponse::Job(Some(row)) => self.execute(*row).await?,
                JobResponse::Job(None) => {
                    tokio::select! {
                        _ = tokio::time::sleep(self.poll) => {},
                        _ = stop.changed() => {},
                    }
                }
                _ => return Err(JobError::InvalidRequest.into()),
            }
        }
    }
}

/// Owns a fixed number of workers for one generic handler kind in one scope.
/// Dropping it stops new claims; running handlers finish. Use [`Self::shutdown`]
/// or [`Self::wait`] to observe errors. Model kinds belong to PR 3's ledger owner.
pub struct JobRunner {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), RunnerError>>>,
}

impl JobRunner {
    /// Validate policy/store availability, then start workers without consumer resubmission.
    /// The kind must be reserved for [`Execution::Handler`] jobs.
    pub async fn start(
        backend: Arc<dyn QueueBackend>,
        scope: JobScope,
        jobs: JobConfig,
        config: RunnerConfig,
        kind: String,
        handler: Arc<dyn JobHandler>,
    ) -> Result<Self, RunnerError> {
        if config.version != 1
            || config.worker_count == 0
            || config.poll_interval_ms == 0
            || config.maintenance_interval_ms == 0
            || kind.is_empty()
        {
            return Err(JobError::InvalidRequest.into());
        }
        let shared = Arc::new(Shared {
            backend,
            scope,
            jobs,
            kind,
            handler,
            poll: Duration::from_millis(config.poll_interval_ms),
        });
        if !matches!(
            shared.op(JobRequest::PendingUsage).await?,
            JobResponse::Usage(_)
        ) {
            return Err(JobError::InvalidRequest.into());
        }
        let (stop, rx) = watch::channel(false);
        let workers = shared.clone();
        let stopped = stop.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            tasks.spawn(workers.clone().maintain(
                rx.clone(),
                Duration::from_millis(config.maintenance_interval_ms),
            ));
            for _ in 0..config.worker_count {
                tasks.spawn(workers.clone().worker(rx.clone()));
            }
            let mut errors = Vec::new();
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => errors.push(error),
                    Err(_) => errors.push(RunnerError::WorkerTask),
                }
                if !errors.is_empty() {
                    stopped.send_replace(true);
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(RunnerError::Workers(errors))
            }
        });
        Ok(Self {
            stop,
            task: Some(task),
        })
    }

    /// Stop claiming and await running handlers and all worker errors.
    pub async fn shutdown(self) -> Result<(), RunnerError> {
        self.stop.send_replace(true);
        self.wait().await
    }

    /// Await worker failure. Use [`Self::shutdown`] to stop normally.
    pub async fn wait(mut self) -> Result<(), RunnerError> {
        self.task
            .take()
            .ok_or(RunnerError::WorkerTask)?
            .await
            .map_err(|_| RunnerError::WorkerTask)?
    }
}

impl Drop for JobRunner {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
