//! The persistent backend with periodic retention sweeps.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use symbiotic_core::{QueueId, QueueItemId};
use symbiotic_model::{DirResponseCache, ModelError};
use symbiotic_queue::{
    ClaimRequest, EnqueueOutcome, EnqueueRequest, FailOutcome, Failure, QueueBackend, QueueError,
    QueueItem,
};
use symbiotic_queue_sqlite::SqliteQueue;

/// Finished calls between two sweeps.
const SWEEP_EVERY: u64 = 10_000;

const ORPHANED: symbiotic_core::DiagnosticCode = symbiotic_core::DiagnosticCode::StaleQueueItem;

/// How long and how much of the response cache the sweep keeps.
pub(crate) struct ResponseRetention {
    pub(crate) cache: DirResponseCache,
    pub(crate) max_age: Option<Duration>,
    pub(crate) max_bytes: Option<u64>,
}

/// [`SqliteQueue`] that retires state older than the retention window at
/// open and after every [`SWEEP_EVERY`] finished calls, so a long-running
/// host's database and response cache stay bounded.
pub(crate) struct MaintainedQueue {
    queue: SqliteQueue,
    sweep: Arc<Sweep>,
    finished: AtomicU64,
}

struct Sweep {
    queue: SqliteQueue,
    retention: chrono::Duration,
    responses: ResponseRetention,
    recovery: crate::spend::SqliteSpendLedger,
}

impl Sweep {
    /// Mark calls orphaned by a crash dead, then drop finished calls, both
    /// older than the retention window; then prune the response cache.
    fn run(&self) -> Result<(), ModelError> {
        self.recovery.expire_recovery()?;
        let cutoff = Utc::now() - self.retention;
        self.queue
            .retire_stale_active(cutoff, ORPHANED)
            .and_then(|_| self.queue.prune_terminal_before(cutoff))
            .map_err(|_err| ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure))?;
        self.responses
            .cache
            .prune(self.responses.max_age, self.responses.max_bytes)?;
        Ok(())
    }
}

impl MaintainedQueue {
    pub(crate) fn new(
        queue: SqliteQueue,
        retention: Duration,
        responses: ResponseRetention,
        recovery: crate::spend::SqliteSpendLedger,
    ) -> Self {
        Self {
            sweep: Arc::new(Sweep {
                queue: queue.clone(),
                retention: chrono::Duration::from_std(retention)
                    .unwrap_or_else(|_| chrono::Duration::days(3650)),
                responses,
                recovery,
            }),
            queue,
            finished: AtomicU64::new(0),
        }
    }

    pub(crate) fn maintain(&self) -> Result<(), ModelError> {
        self.sweep.run()
    }

    async fn finished_one(&self) -> Result<(), QueueError> {
        if self.finished.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY == SWEEP_EVERY - 1 {
            let sweep = self.sweep.clone();
            match tokio::task::spawn_blocking(move || sweep.run()).await {
                Ok(result) => result.map_err(|e| QueueError::Storage(e.code()))?,
                Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
                Err(_) => {
                    return Err(QueueError::Storage(
                        symbiotic_core::DiagnosticCode::SpendLedgerUnavailable,
                    ));
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl QueueBackend for MaintainedQueue {
    async fn enqueue(&self, request: EnqueueRequest) -> Result<EnqueueOutcome, QueueError> {
        self.queue.enqueue(request).await
    }

    async fn enqueue_replacing(
        &self,
        request: EnqueueRequest,
        current: &QueueItemId,
    ) -> Result<EnqueueOutcome, QueueError> {
        self.queue.enqueue_replacing(request, current).await
    }

    async fn claim(&self, request: ClaimRequest) -> Result<Vec<QueueItem>, QueueError> {
        self.queue.claim(request).await
    }

    async fn claim_item(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
        max_in_flight: Option<usize>,
    ) -> Result<Option<QueueItem>, QueueError> {
        self.queue
            .claim_item(item_id, worker_id, lease_seconds, max_in_flight)
            .await
    }

    async fn get_item(&self, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError> {
        self.queue.get_item(item_id).await
    }

    async fn heartbeat(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<(), QueueError> {
        self.queue
            .heartbeat(item_id, worker_id, lease_seconds)
            .await
    }

    async fn complete(&self, item_id: &QueueItemId, worker_id: &str) -> Result<(), QueueError> {
        // Only successful queue updates count as finished calls. Preserve a
        // queue-write failure rather than replacing it with a sweep failure.
        self.queue.complete(item_id, worker_id).await?;
        self.finished_one().await
    }

    async fn fail(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        error: symbiotic_core::DiagnosticCode,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError> {
        let result = self
            .queue
            .fail(item_id, worker_id, error, retry_after_seconds)
            .await?;
        self.finished_one().await?;
        Ok(result)
    }

    async fn fail_with(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        failure: Failure,
    ) -> Result<FailOutcome, QueueError> {
        let result = self.queue.fail_with(item_id, worker_id, failure).await?;
        self.finished_one().await?;
        Ok(result)
    }

    async fn reclaim_expired_leases(&self, queue_id: &QueueId) -> Result<usize, QueueError> {
        self.queue.reclaim_expired_leases(queue_id).await
    }

    async fn cooldown_until(
        &self,
        queue_id: &QueueId,
    ) -> Result<Option<DateTime<Utc>>, QueueError> {
        self.queue.cooldown_until(queue_id).await
    }

    async fn note_cooldown(
        &self,
        queue_id: &QueueId,
        until: DateTime<Utc>,
    ) -> Result<(), QueueError> {
        self.queue.note_cooldown(queue_id, until).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbiotic_model::{SpendLedger, SpendReceiptRef, SpendReservation, SpendState};

    #[tokio::test]
    async fn recovery_sweep_failure_reaches_the_caller() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let queue = SqliteQueue::open(&path).unwrap();
        let ledger = crate::spend::SqliteSpendLedger::open(&path)
            .unwrap()
            .with_retention(Duration::ZERO);
        let r = SpendReservation {
            reference: SpendReceiptRef::new("paid").unwrap(),
            account: "account".into(),
            invocation: "explicit".into(),
            binding: "input".into(),
            request_limit: None,
        };
        ledger.reserve_explicit(&r, 3).unwrap();
        ledger
            .finish(
                &r.reference,
                SpendState::Unknown,
                None,
                Some(serde_json::json!({"answer":"private"})),
            )
            .unwrap();
        let maintained = MaintainedQueue::new(
            queue,
            Duration::from_secs(60),
            ResponseRetention {
                cache: DirResponseCache::new(dir.path().join("responses")),
                max_age: None,
                max_bytes: None,
            },
            ledger,
        );
        maintained
            .finished
            .store(SWEEP_EVERY - 1, Ordering::Relaxed);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TRIGGER refuse_expiry BEFORE UPDATE OF recovery ON spend_receipts BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;").unwrap();
        assert!(matches!(
            maintained.complete(&QueueItemId::new(), "worker").await,
            Err(QueueError::NotFound(_))
        ));
        assert_eq!(maintained.finished.load(Ordering::Relaxed), SWEEP_EVERY - 1);
        assert!(matches!(
            maintained.finished_one().await,
            Err(QueueError::Storage(
                symbiotic_core::DiagnosticCode::SpendLedgerUnavailable
            ))
        ));
    }
}
