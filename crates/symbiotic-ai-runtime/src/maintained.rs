//! The persistent backend with periodic retention sweeps.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use symbiotic_core::{QueueId, QueueItemId};
use symbiotic_model::ModelError;
use symbiotic_queue::{
    ClaimRequest, EnqueueOutcome, EnqueueRequest, FailOutcome, Failure, QueueBackend, QueueError,
    QueueItem,
};
use symbiotic_queue_sqlite::SqliteQueue;

/// Finished calls between two sweeps.
const SWEEP_EVERY: u64 = 10_000;

const ORPHANED: &str = "abandoned: no caller resumed this call within the runtime's retention";

/// [`SqliteQueue`] that retires state older than the retention window at
/// open and after every [`SWEEP_EVERY`] finished calls, so a long-running
/// host's database stays bounded.
pub(crate) struct MaintainedQueue {
    queue: SqliteQueue,
    retention: chrono::Duration,
    finished: AtomicU64,
}

impl MaintainedQueue {
    pub(crate) fn new(queue: SqliteQueue, retention: Duration) -> Self {
        Self {
            queue,
            retention: chrono::Duration::from_std(retention)
                .unwrap_or_else(|_| chrono::Duration::days(3650)),
            finished: AtomicU64::new(0),
        }
    }

    /// Mark calls orphaned by a crash dead, then drop finished calls, both
    /// older than the retention window.
    pub(crate) fn maintain(&self) -> Result<(), ModelError> {
        let cutoff = Utc::now() - self.retention;
        self.queue
            .retire_stale_active(cutoff, ORPHANED)
            .and_then(|_| self.queue.prune_terminal_before(cutoff))
            .map(|_| ())
            .map_err(|err| ModelError::Queue(err.to_string()))
    }

    fn finished_one(&self) {
        if self.finished.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY == SWEEP_EVERY - 1 {
            // Retention is housekeeping: a failed sweep retries at the next
            // interval and never fails the call that triggered it.
            let _ = self.maintain();
        }
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
        let result = self.queue.complete(item_id, worker_id).await;
        self.finished_one();
        result
    }

    async fn fail(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        error: &str,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError> {
        let result = self
            .queue
            .fail(item_id, worker_id, error, retry_after_seconds)
            .await;
        self.finished_one();
        result
    }

    async fn fail_with(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        failure: Failure,
    ) -> Result<FailOutcome, QueueError> {
        let result = self.queue.fail_with(item_id, worker_id, failure).await;
        self.finished_one();
        result
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
