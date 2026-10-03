//! In-process [`QueueBackend`] with no storage dependency.
//!
//! For hosts that need the queued providers' coordination (shared model cap,
//! idempotency, retry accounting, cooldowns) inside one process and no state
//! across restarts. Every clone shares the same state; separate instances are
//! independent. Terminal items (succeeded or dead) are retained up to a bound
//! so repeated requests still see their terminal duplicate; the oldest are
//! evicted first. Active items are never evicted.

use crate::{
    ClaimRequest, EnqueueDisposition, EnqueueOutcome, EnqueueRequest, FailOutcome, Failure,
    QueueBackend, QueueError, QueueEvent, QueueEventSink, QueueItem, QueueStatus,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use symbiotic_core::{QueueId, QueueItemId};

/// Terminal items kept by [`MemoryQueue::new`].
pub const DEFAULT_RETAINED_TERMINAL_ITEMS: usize = 10_000;

#[derive(Clone)]
pub struct MemoryQueue {
    state: Arc<Mutex<State>>,
    jobs: Arc<Mutex<JobMemoryState>>,
    event_sink: Option<Arc<dyn QueueEventSink>>,
}

#[derive(Default)]
struct State {
    items: HashMap<String, QueueItem>,
    /// `(queue_id, idempotency_key)` to the newest item with that key.
    idempotency: HashMap<(String, String), String>,
    /// Running item ids per queue id: the in-flight count and the lease scan.
    running: HashMap<String, HashSet<String>>,
    /// Terminal item ids, oldest first.
    terminal: VecDeque<String>,
    retain_terminal: usize,
    cooldowns: HashMap<String, DateTime<Utc>>,
}

impl Default for MemoryQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryQueue {
    pub fn new() -> Self {
        Self::with_terminal_retention(DEFAULT_RETAINED_TERMINAL_ITEMS)
    }

    /// Keep at most `retain` terminal items (at least one).
    pub fn with_terminal_retention(retain: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                retain_terminal: retain.max(1),
                ..State::default()
            })),
            jobs: Arc::new(Mutex::new(JobMemoryState::default())),
            event_sink: None,
        }
    }

    pub fn with_event_sink(mut self, sink: Arc<dyn QueueEventSink>) -> Self {
        self.event_sink = Some(sink);
        self
    }

    /// Number of items currently held, active and retained terminal.
    pub fn len(&self) -> usize {
        self.lock().map(|state| state.items.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, QueueError> {
        self.state.lock().map_err(|_| {
            QueueError::Unavailable(symbiotic_core::DiagnosticCode::MemoryQueueLockPoisoned)
        })
    }

    async fn emit(&self, events: Vec<(QueueItem, Option<symbiotic_core::DiagnosticCode>)>) {
        let Some(sink) = &self.event_sink else {
            return;
        };
        for (item, error) in events {
            sink.record_queue_event(QueueEvent {
                item_id: item.item_id,
                queue_id: item.queue_id,
                kind: item.kind,
                status: item.status,
                attempt: item.attempt,
                timestamp: Utc::now(),
                error,
            })
            .await;
        }
    }

    /// Enqueue; with `replacing`, a force enqueue happens only while that
    /// item is still the newest for the key.
    async fn enqueue_inner(
        &self,
        request: EnqueueRequest,
        replacing: Option<&QueueItemId>,
    ) -> Result<EnqueueOutcome, QueueError> {
        if request.kind.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                symbiotic_core::DiagnosticCode::QueueItemKindMustNotBeEmpty,
            ));
        }
        let now = Utc::now();
        let item = {
            let mut state = self.lock()?;
            if let Some(key) = &request.idempotency_key
                && let Some(existing_id) = state
                    .idempotency
                    .get(&(request.queue_id.0.clone(), key.clone()))
                && let Some(existing) = state.items.get(existing_id)
            {
                let active = State::is_active(existing.status);
                let superseded = replacing.is_some_and(|current| existing.item_id != *current);
                let reclaimed = replacing.is_some()
                    && existing.status == QueueStatus::Failed
                    && existing.last_error == Some(symbiotic_core::DiagnosticCode::LeaseExpired);
                if (active && !reclaimed) || !request.force || superseded {
                    return Ok(EnqueueOutcome {
                        item: existing.clone(),
                        disposition: if active {
                            EnqueueDisposition::ActiveDuplicate
                        } else {
                            EnqueueDisposition::TerminalDuplicate
                        },
                    });
                }
            }
            if let Some(current) = replacing
                && state
                    .items
                    .get(&current.0)
                    .is_some_and(|i| i.status == QueueStatus::Failed)
            {
                state.set_status(&current.0, QueueStatus::Stopped);
                if let Some(item) = state.items.get_mut(&current.0) {
                    item.last_error_class = Some(symbiotic_core::FailureClass::Queue);
                }
            }
            let item = QueueItem {
                item_id: QueueItemId::new(),
                queue_id: request.queue_id,
                kind: request.kind,
                payload: request.payload,
                status: QueueStatus::Pending,
                attempt: 0,
                max_attempts: request.max_attempts.unwrap_or(3).max(1),
                run_after: request.run_after.unwrap_or(now),
                lease_owner: None,
                lease_until: None,
                idempotency_key: request.idempotency_key,
                last_error: None,
                last_error_class: None,
                created_at: now,
                updated_at: now,
            };
            if let Some(key) = &item.idempotency_key {
                state.idempotency.insert(
                    (item.queue_id.0.clone(), key.clone()),
                    item.item_id.0.clone(),
                );
            }
            state.items.insert(item.item_id.0.clone(), item.clone());
            item
        };
        self.emit(vec![(item.clone(), None)]).await;
        Ok(EnqueueOutcome {
            item,
            disposition: EnqueueDisposition::Inserted,
        })
    }

    fn update_running(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        update: impl FnOnce(&mut State, DateTime<Utc>) -> Result<(), QueueError>,
    ) -> Result<QueueItem, QueueError> {
        let now = Utc::now();
        let mut state = self.lock()?;
        let current = state.items.get(&item_id.0).ok_or({
            QueueError::NotFound(symbiotic_core::DiagnosticCode::InvalidConfiguration)
        })?;
        if current.status != QueueStatus::Running {
            return Err(QueueError::NotRunning(
                symbiotic_core::DiagnosticCode::InvalidConfiguration,
            ));
        }
        if current.lease_owner.as_deref() != Some(worker_id) {
            return Err(QueueError::LeaseMismatch(
                symbiotic_core::DiagnosticCode::InvalidConfiguration,
            ));
        }
        if current.lease_until.is_none_or(|until| until < now) {
            return Err(QueueError::LeaseMismatch(
                symbiotic_core::DiagnosticCode::InvalidConfiguration,
            ));
        }
        update(&mut state, now)?;
        Ok(state.items[&item_id.0].clone())
    }
}

impl State {
    fn is_active(status: QueueStatus) -> bool {
        matches!(
            status,
            QueueStatus::Pending | QueueStatus::Running | QueueStatus::Failed
        )
    }

    fn running_count(&self, queue_id: &str) -> usize {
        self.running.get(queue_id).map_or(0, HashSet::len)
    }

    /// Record a status change of `item_id`, keeping the running index and the
    /// terminal window consistent.
    fn set_status(&mut self, item_id: &str, status: QueueStatus) {
        let Some(item) = self.items.get_mut(item_id) else {
            return;
        };
        let previous = item.status;
        item.status = status;
        let queue_id = item.queue_id.0.clone();
        if previous == QueueStatus::Running
            && status != QueueStatus::Running
            && let Some(running) = self.running.get_mut(&queue_id)
        {
            running.remove(item_id);
            if running.is_empty() {
                self.running.remove(&queue_id);
            }
        }
        if status == QueueStatus::Running && previous != QueueStatus::Running {
            self.running
                .entry(queue_id)
                .or_default()
                .insert(item_id.to_string());
        }
        if matches!(
            status,
            QueueStatus::Succeeded | QueueStatus::Dead | QueueStatus::Stopped
        ) {
            self.terminal.push_back(item_id.to_string());
            self.evict_terminal();
        }
    }

    fn evict_terminal(&mut self) {
        while self.terminal.len() > self.retain_terminal {
            let Some(evicted) = self.terminal.pop_front() else {
                break;
            };
            if let Some(item) = self.items.remove(&evicted)
                && let Some(key) = item.idempotency_key
            {
                let index = (item.queue_id.0, key);
                if self.idempotency.get(&index) == Some(&evicted) {
                    self.idempotency.remove(&index);
                }
            }
        }
    }

    /// Return expired running items of `queue_id` to `Failed`, or to `Dead`
    /// when the expired lease was their last allowed attempt.
    fn reclaim_expired(&mut self, queue_id: &str, now: DateTime<Utc>) -> Vec<QueueItem> {
        let expired: Vec<String> = self
            .running
            .get(queue_id)
            .map(|running| {
                running
                    .iter()
                    .filter(|id| self.items[*id].lease_until.is_some_and(|until| until < now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut reclaimed = Vec::with_capacity(expired.len());
        for id in expired {
            let item = &self.items[&id];
            let status = if item.attempt >= item.max_attempts {
                QueueStatus::Dead
            } else {
                QueueStatus::Failed
            };
            self.set_status(&id, status);
            let item = self.items.get_mut(&id).expect("running item exists");
            item.lease_owner = None;
            item.lease_until = None;
            item.updated_at = now;
            item.last_error = Some(symbiotic_core::DiagnosticCode::LeaseExpired);
            item.last_error_class = Some(symbiotic_core::FailureClass::Queue);
            reclaimed.push(item.clone());
        }
        reclaimed
    }

    /// A waiting item whose attempts are all used is dead, not claimable.
    fn retire_if_exhausted(&mut self, item_id: &str, now: DateTime<Utc>) -> Option<QueueItem> {
        let item = self.items.get_mut(item_id)?;
        if !matches!(item.status, QueueStatus::Pending | QueueStatus::Failed)
            || item.attempt < item.max_attempts
        {
            return None;
        }
        item.updated_at = now;
        item.last_error
            .get_or_insert(symbiotic_core::DiagnosticCode::AttemptBudgetExhausted);
        self.set_status(item_id, QueueStatus::Dead);
        self.items.get(item_id).cloned()
    }

    fn lease(
        &mut self,
        item_id: &str,
        worker_id: &str,
        lease_until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) {
        self.set_status(item_id, QueueStatus::Running);
        let item = self.items.get_mut(item_id).expect("claimed item exists");
        item.attempt = item.attempt.saturating_add(1);
        item.lease_owner = Some(worker_id.to_string());
        item.lease_until = Some(lease_until);
        item.updated_at = now;
    }
}

fn lease_deadline(now: DateTime<Utc>, seconds: u64) -> Result<DateTime<Utc>, QueueError> {
    i64::try_from(seconds.max(1))
        .ok()
        .and_then(ChronoDuration::try_seconds)
        .and_then(|duration| now.checked_add_signed(duration))
        .ok_or(QueueError::InvalidRequest(
            symbiotic_core::DiagnosticCode::InvalidConfiguration,
        ))
}

fn lease_events(items: Vec<QueueItem>) -> Vec<(QueueItem, Option<symbiotic_core::DiagnosticCode>)> {
    items
        .into_iter()
        .map(|item| (item, Some(symbiotic_core::DiagnosticCode::LeaseExpired)))
        .collect()
}

#[async_trait]
impl QueueBackend for MemoryQueue {
    async fn jobs(
        &self,
        scope: &crate::jobs::JobScope,
        config: &crate::jobs::JobConfig,
        now: DateTime<Utc>,
        request: crate::jobs::JobRequest,
    ) -> Result<crate::jobs::JobResponse, crate::jobs::JobError> {
        let mut state = self
            .jobs
            .lock()
            .map_err(|_| crate::jobs::JobError::Storage)?;
        let mut tx = JobMemoryTransaction::new(&mut state);
        let response = crate::jobs::apply_job_request(&mut tx, scope, config, now, request)?;
        tx.committed = true;
        Ok(response)
    }

    async fn enqueue(&self, request: EnqueueRequest) -> Result<EnqueueOutcome, QueueError> {
        self.enqueue_inner(request, None).await
    }

    async fn enqueue_replacing(
        &self,
        mut request: EnqueueRequest,
        current: &QueueItemId,
    ) -> Result<EnqueueOutcome, QueueError> {
        request.force = true;
        self.enqueue_inner(request, Some(current)).await
    }

    async fn claim(&self, request: ClaimRequest) -> Result<Vec<QueueItem>, QueueError> {
        if request.worker_id.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                symbiotic_core::DiagnosticCode::WorkerIdMustNotBeEmpty,
            ));
        }
        let now = Utc::now();
        let lease_until = lease_deadline(now, request.lease_seconds)?;
        let (reclaimed, claimed) = {
            let mut state = self.lock()?;
            let queue_id = request.queue_id.0.as_str();
            if state
                .cooldowns
                .get(queue_id)
                .is_some_and(|until| *until > Utc::now())
            {
                return Ok(Vec::new());
            }
            let reclaimed = state.reclaim_expired(queue_id, now);
            let mut limit = request.limit.max(1);
            if let Some(max_in_flight) = request.max_in_flight {
                let running = state.running_count(queue_id);
                limit = limit.min(max_in_flight.saturating_sub(running));
            }
            let mut ready: Vec<&QueueItem> = state
                .items
                .values()
                .filter(|item| {
                    item.queue_id.0 == queue_id
                        && matches!(item.status, QueueStatus::Pending | QueueStatus::Failed)
                        && item.attempt < item.max_attempts
                        && item.run_after <= now
                })
                .collect();
            ready.sort_by(|a, b| {
                (a.run_after, a.created_at, &a.item_id.0).cmp(&(
                    b.run_after,
                    b.created_at,
                    &b.item_id.0,
                ))
            });
            let ids: Vec<String> = ready
                .into_iter()
                // `limit` is zero when the queue is at its cap.
                .take(limit)
                .map(|item| item.item_id.0.clone())
                .collect();
            let claimed = ids
                .iter()
                .map(|id| {
                    state.lease(id, &request.worker_id, lease_until, now);
                    state.items[id].clone()
                })
                .collect::<Vec<_>>();
            (reclaimed, claimed)
        };
        let mut events = lease_events(reclaimed);
        events.extend(claimed.iter().cloned().map(|item| (item, None)));
        self.emit(events).await;
        Ok(claimed)
    }

    async fn claim_item(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
        max_in_flight: Option<usize>,
    ) -> Result<Option<QueueItem>, QueueError> {
        if worker_id.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                symbiotic_core::DiagnosticCode::WorkerIdMustNotBeEmpty,
            ));
        }
        let now = Utc::now();
        let lease_until = lease_deadline(now, lease_seconds)?;
        let (reclaimed, retired, claimed, missing) = {
            let mut state = self.lock()?;
            let queue_id = state
                .items
                .get(&item_id.0)
                .ok_or({
                    QueueError::NotFound(symbiotic_core::DiagnosticCode::InvalidConfiguration)
                })?
                .queue_id
                .0
                .clone();
            let reclaimed = state.reclaim_expired(&queue_id, now);
            // Reclaiming can end other items and push the requested one out
            // of the terminal window.
            if !state.items.contains_key(&item_id.0) {
                (reclaimed, None, None, true)
            } else {
                let retired = state.retire_if_exhausted(&item_id.0, now);
                let current = &state.items[&item_id.0];
                let claimable =
                    matches!(current.status, QueueStatus::Pending | QueueStatus::Failed)
                        && current.run_after <= now
                        && state
                            .cooldowns
                            .get(&queue_id)
                            .is_none_or(|until| *until <= Utc::now())
                        && max_in_flight.is_none_or(|cap| state.running_count(&queue_id) < cap);
                let claimed = claimable.then(|| {
                    state.lease(&item_id.0, worker_id, lease_until, now);
                    state.items[&item_id.0].clone()
                });
                (reclaimed, retired, claimed, false)
            }
        };
        let mut events = lease_events(reclaimed);
        events.extend(retired.map(|item| {
            let error = item.last_error;
            (item, error)
        }));
        events.extend(claimed.iter().cloned().map(|item| (item, None)));
        self.emit(events).await;
        if missing {
            return Err(QueueError::NotFound(
                symbiotic_core::DiagnosticCode::InvalidConfiguration,
            ));
        }
        Ok(claimed)
    }

    async fn get_item(&self, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError> {
        Ok(self.lock()?.items.get(&item_id.0).cloned())
    }

    async fn heartbeat(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<(), QueueError> {
        let item = self.update_running(item_id, worker_id, |state, now| {
            let item = state
                .items
                .get_mut(&item_id.0)
                .expect("running item exists");
            item.lease_until = Some(lease_deadline(now, lease_seconds)?);
            item.updated_at = now;
            Ok(())
        })?;
        self.emit(vec![(item, None)]).await;
        Ok(())
    }

    async fn complete(&self, item_id: &QueueItemId, worker_id: &str) -> Result<(), QueueError> {
        let item = self.update_running(item_id, worker_id, |state, now| {
            let item = state
                .items
                .get_mut(&item_id.0)
                .expect("running item exists");
            item.lease_owner = None;
            item.lease_until = None;
            item.last_error = None;
            item.last_error_class = None;
            item.updated_at = now;
            state.set_status(&item_id.0, QueueStatus::Succeeded);
            Ok(())
        })?;
        self.emit(vec![(item, None)]).await;
        Ok(())
    }

    async fn fail(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        error: symbiotic_core::DiagnosticCode,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError> {
        let run_after =
            Utc::now() + ChronoDuration::seconds(retry_after_seconds.unwrap_or(1) as i64);
        self.fail_with(
            item_id,
            worker_id,
            Failure {
                error,
                error_class: None,
                run_after: Some(run_after),
            },
        )
        .await
    }

    async fn fail_with(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        failure: Failure,
    ) -> Result<FailOutcome, QueueError> {
        let mut outcome = FailOutcome::RetryScheduled;
        let item = self.update_running(item_id, worker_id, |state, now| {
            let item = state
                .items
                .get_mut(&item_id.0)
                .expect("running item exists");
            let exhausted = item.attempt >= item.max_attempts;
            item.run_after = failure
                .run_after
                .unwrap_or_else(|| now + ChronoDuration::seconds(1));
            item.lease_owner = None;
            item.lease_until = None;
            item.last_error = Some(failure.error);
            item.last_error_class = failure.error_class;
            item.updated_at = now;
            let status = if failure.run_after.is_none() {
                outcome = FailOutcome::Stopped;
                QueueStatus::Stopped
            } else if exhausted {
                outcome = FailOutcome::MovedToDead;
                QueueStatus::Dead
            } else {
                QueueStatus::Failed
            };
            state.set_status(&item_id.0, status);
            Ok(())
        })?;
        self.emit(vec![(item, Some(failure.error))]).await;
        Ok(outcome)
    }

    async fn reclaim_expired_leases(&self, queue_id: &QueueId) -> Result<usize, QueueError> {
        let reclaimed = self.lock()?.reclaim_expired(&queue_id.0, Utc::now());
        let count = reclaimed.len();
        self.emit(lease_events(reclaimed)).await;
        Ok(count)
    }

    async fn cooldown_until(
        &self,
        queue_id: &QueueId,
    ) -> Result<Option<DateTime<Utc>>, QueueError> {
        Ok(self.lock()?.cooldowns.get(&queue_id.0).copied())
    }

    async fn note_cooldown(
        &self,
        queue_id: &QueueId,
        until: DateTime<Utc>,
    ) -> Result<(), QueueError> {
        let mut state = self.lock()?;
        let current = state.cooldowns.entry(queue_id.0.clone()).or_insert(until);
        if *current < until {
            *current = until;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn request(key: &str) -> EnqueueRequest {
        EnqueueRequest {
            queue_id: QueueId::new("chat:test:model"),
            kind: "chat".to_string(),
            payload: serde_json::json!({}),
            idempotency_key: Some(key.to_string()),
            run_after: None,
            max_attempts: Some(1),
            force: false,
        }
    }

    async fn run_to_success(queue: &MemoryQueue, key: &str) -> QueueItemId {
        let item = queue.enqueue(request(key)).await.unwrap().item;
        queue
            .claim_item(&item.item_id, "worker", 60, None)
            .await
            .unwrap()
            .unwrap();
        queue.complete(&item.item_id, "worker").await.unwrap();
        item.item_id
    }

    #[tokio::test]
    async fn terminal_items_are_evicted_oldest_first_and_active_items_never() {
        let queue = MemoryQueue::with_terminal_retention(2);
        let active = queue.enqueue(request("active")).await.unwrap().item;
        let first = run_to_success(&queue, "first").await;
        let second = run_to_success(&queue, "second").await;
        let third = run_to_success(&queue, "third").await;

        assert!(queue.get_item(&first).await.unwrap().is_none());
        assert!(queue.get_item(&second).await.unwrap().is_some());
        assert!(queue.get_item(&third).await.unwrap().is_some());
        assert!(queue.get_item(&active.item_id).await.unwrap().is_some());
        assert_eq!(queue.len(), 3);

        // The evicted request no longer has a terminal duplicate.
        let again = queue.enqueue(request("first")).await.unwrap();
        assert_eq!(again.disposition, EnqueueDisposition::Inserted);
    }

    #[tokio::test]
    async fn eviction_keeps_the_newest_item_for_a_reused_key() {
        let queue = MemoryQueue::with_terminal_retention(1);
        let first = run_to_success(&queue, "same").await;
        let mut forced = request("same");
        forced.force = true;
        let second = queue.enqueue(forced).await.unwrap().item;
        queue
            .claim_item(&second.item_id, "worker", 60, None)
            .await
            .unwrap()
            .unwrap();
        queue.complete(&second.item_id, "worker").await.unwrap();

        assert!(queue.get_item(&first).await.unwrap().is_none());
        let duplicate = queue.enqueue(request("same")).await.unwrap();
        assert_eq!(duplicate.disposition, EnqueueDisposition::TerminalDuplicate);
        assert_eq!(duplicate.item.item_id, second.item_id);
    }

    #[tokio::test]
    async fn claiming_an_item_evicted_by_reclamation_is_not_found_and_keeps_the_queue_usable() {
        let queue = MemoryQueue::with_terminal_retention(1);
        let finished = run_to_success(&queue, "finished").await;
        let mut crashing = request("crashing");
        crashing.max_attempts = Some(1);
        let crashing = queue.enqueue(crashing).await.unwrap().item;
        queue
            .claim_item(&crashing.item_id, "worker", 1, None)
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

        // Reclaiming the crashed final attempt ends it and evicts `finished`.
        let err = queue
            .claim_item(&finished, "worker", 60, None)
            .await
            .unwrap_err();
        assert!(matches!(err, QueueError::NotFound(_)), "{err:?}");
        assert_eq!(
            queue
                .get_item(&crashing.item_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            QueueStatus::Dead
        );
        // The lock is intact: the queue still serves requests.
        run_to_success(&queue, "after").await;
    }

    struct CountingSink(AtomicUsize);

    #[async_trait]
    impl QueueEventSink for CountingSink {
        async fn record_queue_event(&self, _event: QueueEvent) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn event_sink_receives_transitions() {
        let sink = Arc::new(CountingSink(AtomicUsize::new(0)));
        let queue = MemoryQueue::new().with_event_sink(sink.clone());
        run_to_success(&queue, "event").await;
        assert_eq!(sink.0.load(Ordering::SeqCst), 3);
    }
}

// Job tombstones are canonical; every lookup/order index is rebuilt from rows.
use crate::jobs::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum JobIndex {
    State(JobState),
    Group(String),
    UnfinishedGroup(String),
    PendingGroup(String),
    Owner(String),
    Diagnostics(String),
    Final,
    Leased,
    Expired,
}
type RowKey = (JobScope, String);
type OrderKey = (i64, String);

#[derive(Default)]
struct JobMemoryState {
    rows: BTreeMap<RowKey, JobRecord>,
    keys: BTreeMap<RowKey, String>,
    indexes: BTreeMap<(JobScope, JobIndex), BTreeSet<OrderKey>>,
    summaries: BTreeMap<RowKey, GroupSummary>,
}

fn row_indexes(row: &JobRecord) -> Vec<(JobIndex, OrderKey)> {
    let id = &row.id.id;
    let created = (row.created_at.timestamp_millis(), id.clone());
    let identity = (0, id.clone());
    let mut entries = vec![(JobIndex::State(row.state), created.clone())];
    if let Some(group) = &row.group {
        entries.push((JobIndex::Group(group.clone()), identity.clone()));
        if row.state.unfinished() {
            entries.push((JobIndex::UnfinishedGroup(group.clone()), identity.clone()));
        }
        if row.state == JobState::Pending {
            entries.push((JobIndex::PendingGroup(group.clone()), created));
        }
        if matches!(
            row.state,
            JobState::Failed | JobState::Uncertain | JobState::AwaitingAdmission
        ) {
            entries.push((JobIndex::Diagnostics(group.clone()), identity.clone()));
        }
    }
    for owner in &row.owners {
        entries.push((JobIndex::Owner(owner.clone()), identity.clone()));
    }
    if !row.state.unfinished() && !row.state.acked() {
        entries.push((
            JobIndex::Final,
            (
                row.finished_at.map_or(0, |t| t.timestamp_millis()),
                id.clone(),
            ),
        ));
        if let Some(until) = row.delivery_until {
            entries.push((JobIndex::Leased, (until.timestamp_millis(), id.clone())));
        }
        if !row.result_expired
            && let Some(until) = row.recovery_until
        {
            entries.push((JobIndex::Expired, (until.timestamp_millis(), id.clone())));
        }
    }
    entries
}

impl JobMemoryState {
    // One owner maintains all rebuildable indexes on writes and rollback.
    fn replace(&mut self, key: RowKey, new: Option<JobRecord>) -> Option<JobRecord> {
        let old = self.rows.remove(&key);
        if let Some(old) = &old {
            self.keys.remove(&(old.id.scope.clone(), old.key.clone()));
            for (index, order) in row_indexes(old) {
                let index_key = (old.id.scope.clone(), index);
                if let Some(entries) = self.indexes.get_mut(&index_key) {
                    entries.remove(&order);
                    if entries.is_empty() {
                        self.indexes.remove(&index_key);
                    }
                }
            }
        }
        if let Some(row) = new {
            self.keys
                .insert((row.id.scope.clone(), row.key.clone()), row.id.id.clone());
            for (index, order) in row_indexes(&row) {
                self.indexes
                    .entry((row.id.scope.clone(), index))
                    .or_default()
                    .insert(order);
            }
            self.rows.insert(key, row);
        }
        old
    }
    fn entries(&self, scope: &JobScope, index: JobIndex) -> impl Iterator<Item = &OrderKey> {
        self.indexes
            .get(&(scope.clone(), index))
            .into_iter()
            .flat_map(|set| set.iter())
    }
    fn oldest_pending(
        &self,
        scope: &JobScope,
        group: &str,
        summary: &GroupSummary,
    ) -> Option<DateTime<Utc>> {
        self.entries(scope, JobIndex::PendingGroup(group.into()))
            .find(|(_, id)| {
                !summary.rebuilding
                    || summary
                        .rebuild_after
                        .as_ref()
                        .is_some_and(|cursor| id <= cursor)
            })
            .and_then(|(time, _)| DateTime::from_timestamp_millis(*time))
    }
}

struct JobMemoryTransaction<'a> {
    state: &'a mut JobMemoryState,
    rows_before: BTreeMap<RowKey, Option<JobRecord>>,
    summaries_before: BTreeMap<RowKey, Option<GroupSummary>>,
    committed: bool,
    #[cfg(test)]
    examined: usize,
}
impl<'a> JobMemoryTransaction<'a> {
    fn select_with<T>(
        &mut self,
        scope: &JobScope,
        query: JobQuery,
        now: DateTime<Utc>,
        limit: usize,
        project: fn(&JobRecord) -> Result<T, JobError>,
    ) -> Result<Vec<T>, JobError> {
        let index = match &query {
            JobQuery::Group {
                group, unfinished, ..
            } => {
                if *unfinished {
                    JobIndex::UnfinishedGroup(group.clone())
                } else {
                    JobIndex::Group(group.clone())
                }
            }
            JobQuery::Owner { owner, .. } => JobIndex::Owner(owner.clone()),
            JobQuery::Pending { .. } => JobIndex::State(JobState::Pending),
            JobQuery::Final => JobIndex::Final,
            JobQuery::Notices => JobIndex::State(JobState::AwaitingAdmission),
            JobQuery::Expired => JobIndex::Expired,
            JobQuery::Diagnostics { group, .. } => JobIndex::Diagnostics(group.clone()),
        };
        let cursor = match &query {
            JobQuery::Group { after, .. }
            | JobQuery::Owner { after, .. }
            | JobQuery::Diagnostics { after, .. } => after.as_ref(),
            _ => None,
        };
        let set = self.state.indexes.get(&(scope.clone(), index));
        let start = (0, cursor.cloned().unwrap_or_default());
        let mut first = set
            .into_iter()
            .flat_map(|set| {
                use std::ops::Bound::*;
                set.range((
                    if cursor.is_some() {
                        Excluded(start.clone())
                    } else {
                        Unbounded
                    },
                    Unbounded,
                ))
            })
            .peekable();
        let mut running = self
            .state
            .entries(scope, JobIndex::State(JobState::Running))
            .peekable();
        let mut selected = Vec::new();
        while selected.len() < limit {
            let entry = if matches!(query, JobQuery::Pending { .. }) {
                match (first.peek(), running.peek()) {
                    (Some(a), Some(b)) if a > b => running.next(),
                    (None, _) => running.next(),
                    _ => first.next(),
                }
            } else {
                first.next()
            };
            let Some((time, id)) = entry else {
                break;
            };
            #[cfg(test)]
            {
                self.examined += 1;
            }
            if matches!(query, JobQuery::Expired) && *time > now.timestamp_millis() {
                break;
            }
            let row = self
                .state
                .rows
                .get(&(scope.clone(), id.clone()))
                .ok_or(JobError::Storage)?;
            let eligible = match &query {
                JobQuery::Pending { kinds, priority } => {
                    row.claimable(now)
                        && kinds.contains(&row.kind)
                        && priority.is_none_or(|p| p == row.priority)
                }
                JobQuery::Final => row.delivery_until.is_none_or(|until| until <= now),
                _ => true,
            };
            if eligible {
                selected.push(project(row)?);
            }
        }
        Ok(selected)
    }
    fn new(state: &'a mut JobMemoryState) -> Self {
        Self {
            state,
            rows_before: BTreeMap::new(),
            summaries_before: BTreeMap::new(),
            committed: false,
            #[cfg(test)]
            examined: 0,
        }
    }
    fn remember_summary(&mut self, key: &RowKey) {
        self.summaries_before
            .entry(key.clone())
            .or_insert_with(|| self.state.summaries.get(key).cloned());
    }
}
impl Drop for JobMemoryTransaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            for (key, old) in std::mem::take(&mut self.rows_before) {
                self.state.replace(key, old);
            }
            for (key, old) in std::mem::take(&mut self.summaries_before) {
                if let Some(old) = old {
                    self.state.summaries.insert(key, old);
                } else {
                    self.state.summaries.remove(&key);
                }
            }
        }
    }
}
impl JobRows for JobMemoryTransaction<'_> {
    fn get(&mut self, id: &JobId) -> Result<Option<JobRecord>, JobError> {
        Ok(self
            .state
            .rows
            .get(&(id.scope.clone(), id.id.clone()))
            .cloned())
    }
    fn by_key(&mut self, scope: &JobScope, key: &str) -> Result<Option<JobRecord>, JobError> {
        Ok(self
            .state
            .keys
            .get(&(scope.clone(), key.into()))
            .and_then(|id| self.state.rows.get(&(scope.clone(), id.clone())))
            .cloned())
    }
    fn select(
        &mut self,
        scope: &JobScope,
        query: JobQuery,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<JobRecord>, JobError> {
        self.select_with(scope, query, now, limit, |r| Ok(r.clone()))
    }
    fn inspect(
        &mut self,
        scope: &JobScope,
        query: JobQuery,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<JobInfo>, JobError> {
        self.select_with(scope, query, now, limit, |r| {
            Ok(JobInfo {
                id: r.id.clone(),
                state: r.state,
                diagnostic: r.diagnostic,
                output_bytes: r.output_bytes,
            })
        })
    }
    fn delivery_metadata(&mut self, id: &JobId) -> Result<JobRecord, JobError> {
        self.state
            .rows
            .get(&(id.scope.clone(), id.id.clone()))
            .map(JobRecord::delivery_metadata)
            .ok_or(JobError::NotFound)
    }
    fn output(&mut self, id: &JobId) -> Result<Option<serde_json::Value>, JobError> {
        self.state
            .rows
            .get(&(id.scope.clone(), id.id.clone()))
            .map(|r| r.output.clone())
            .ok_or(JobError::NotFound)
    }
    fn recovery_bytes(&mut self, id: &JobId) -> Result<usize, JobError> {
        let row = self
            .state
            .rows
            .get(&(id.scope.clone(), id.id.clone()))
            .ok_or(JobError::NotFound)?;
        [
            row.payload
                .as_ref()
                .map(encoded_bytes)
                .transpose()?
                .unwrap_or(0),
            row.checkpoint
                .as_ref()
                .map(encoded_bytes)
                .transpose()?
                .unwrap_or(0),
            row.admission
                .as_ref()
                .map(encoded_bytes)
                .transpose()?
                .unwrap_or(0),
            row.output_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total.checked_add(bytes).ok_or(JobError::Storage)
        })
    }
    fn deliver(&mut self, row: &JobRecord, expired: bool) -> Result<(), JobError> {
        if expired {
            self.expire(&row.id)?;
        }
        let mut stored = self.get(&row.id)?.ok_or(JobError::NotFound)?;
        stored.delivery_generation = row.delivery_generation;
        stored.delivery_until = row.delivery_until;
        self.save(stored)
    }
    fn expire(&mut self, id: &JobId) -> Result<(), JobError> {
        let key = (id.scope.clone(), id.id.clone());
        let mut new = self.delivery_metadata(id)?;
        new.result_expired = true;
        new.output_bytes = 0;
        let old = self.state.replace(key.clone(), Some(new));
        self.rows_before.entry(key).or_insert(old);
        Ok(())
    }
    fn save(&mut self, mut row: JobRecord) -> Result<(), JobError> {
        row.output_bytes = row
            .output
            .as_ref()
            .map(encoded_bytes)
            .transpose()?
            .unwrap_or(0);
        let key = (row.id.scope.clone(), row.id.id.clone());
        let old = self.state.rows.get(&key).cloned();
        self.rows_before
            .entry(key.clone())
            .or_insert_with(|| old.clone());
        self.state.replace(key, Some(row.clone()));
        if let Some(group) = &row.group {
            let key = (row.id.scope.clone(), group.clone());
            self.remember_summary(&key);
            let mut summary = self.state.summaries.get(&key).cloned().unwrap_or_default();
            summary_transition(&mut summary, old.as_ref(), &row)?;
            summary.oldest_pending = self.state.oldest_pending(&row.id.scope, group, &summary);
            self.state.summaries.insert(key, summary);
        }
        Ok(())
    }
    fn usage(&mut self, scope: &JobScope) -> Result<PendingUsage, JobError> {
        let mut usage = PendingUsage::default();
        for state in [
            JobState::Pending,
            JobState::AwaitingAdmission,
            JobState::Running,
            JobState::Uncertain,
        ] {
            for (_, id) in self.state.entries(scope, JobIndex::State(state)) {
                let row = self
                    .state
                    .rows
                    .get(&(scope.clone(), id.clone()))
                    .ok_or(JobError::Storage)?;
                usage.items += 1;
                usage.bytes += job_input_bytes(row)?;
            }
        }
        Ok(usage)
    }
    fn leased(&mut self, scope: &JobScope, now: DateTime<Utc>) -> Result<usize, JobError> {
        use std::ops::Bound::*;
        Ok(self
            .state
            .indexes
            .get(&(scope.clone(), JobIndex::Leased))
            .map_or(0, |set| {
                set.range((
                    Excluded((now.timestamp_millis(), String::from(char::MAX))),
                    Unbounded,
                ))
                .count()
            }))
    }
    fn load_summary(&mut self, scope: &JobScope, group: &str) -> Result<GroupSummary, JobError> {
        Ok(self
            .state
            .summaries
            .get(&(scope.clone(), group.into()))
            .cloned()
            .unwrap_or_default())
    }
    fn save_summary(
        &mut self,
        scope: &JobScope,
        group: &str,
        summary: &GroupSummary,
    ) -> Result<(), JobError> {
        let key = (scope.clone(), group.into());
        self.remember_summary(&key);
        self.state.summaries.insert(key, summary.clone());
        Ok(())
    }
    fn oldest_pending(
        &mut self,
        scope: &JobScope,
        group: &str,
        summary: &GroupSummary,
    ) -> Result<Option<DateTime<Utc>>, JobError> {
        Ok(self.state.oldest_pending(scope, group, summary))
    }
}

#[cfg(test)]
mod job_index_tests {
    use super::*;
    use serde_json::json;

    fn fixture(retained: usize) -> (JobMemoryState, JobScope, DateTime<Utc>, JobRecord) {
        let mut state = JobMemoryState::default();
        let scope = JobScope {
            tenant: "t".into(),
            incarnation: "i".into(),
            queue: "q".into(),
        };
        let now = DateTime::from_timestamp_millis(1_000_000).unwrap();
        let mut tx = JobMemoryTransaction::new(&mut state);
        apply_job_request(
            &mut tx,
            &scope,
            &JobConfig::default(),
            now,
            JobRequest::Enqueue(vec![JobSpec {
                key: "template".into(),
                group: Some("group".into()),
                owners: vec!["other".into()],
                kind: "handler".into(),
                execution: Execution::Handler,
                priority: Priority::Background,
                payload: json!("input"),
                limits: JobLimits { max_attempts: 3 },
                admission: None,
                recovery_until: None,
            }]),
        )
        .unwrap();
        let template = tx.by_key(&scope, "template").unwrap().unwrap();
        for i in 0..retained + 8 {
            let mut row = template.clone();
            row.id.id = if i < retained && i % 2 == 1 {
                format!("zz-tail-{i:08}")
            } else {
                format!("{i:08}")
            };
            row.key = row.id.id.clone();
            row.state = if i < retained {
                if i % 2 == 0 {
                    JobState::Accepted
                } else {
                    JobState::Failed
                }
            } else {
                JobState::Succeeded
            };
            row.payload = None;
            row.finished_at = Some(now);
            row.delivery_generation = 1;
            row.delivery_until = (i >= retained).then_some(now + ChronoDuration::seconds(30));
            tx.save(row).unwrap();
        }
        let mut eligible = template;
        eligible.id.id = "zz-eligible".into();
        eligible.key = "eligible".into();
        eligible.state = JobState::Failed;
        eligible.finished_at = Some(now);
        eligible.owners = vec!["target".into()];
        tx.save(eligible.clone()).unwrap();
        tx.committed = true;
        drop(tx);
        (state, scope, now, eligible)
    }

    #[test]
    fn jobs_memory_indexed_pages_have_flat_examined_rows() {
        let mut measurements = Vec::new();
        for retained in [10, 10_000] {
            let (mut state, scope, now, eligible) = fixture(retained);
            let mut tx = JobMemoryTransaction::new(&mut state);
            assert_eq!(
                tx.select(&scope, JobQuery::Final, now, 1).unwrap()[0].id,
                eligible.id
            );
            let delivery_rows = std::mem::take(&mut tx.examined);
            assert_eq!(
                tx.select(
                    &scope,
                    JobQuery::Diagnostics {
                        group: "group".into(),
                        after: None
                    },
                    now,
                    1
                )
                .unwrap()[0]
                    .id,
                eligible.id
            );
            let diagnostic_rows = std::mem::take(&mut tx.examined);
            assert_eq!(
                tx.select(
                    &scope,
                    JobQuery::Owner {
                        owner: "target".into(),
                        after: None
                    },
                    now,
                    1
                )
                .unwrap()
                .len(),
                1
            );
            assert_eq!(tx.examined, 1);
            tx.examined = 0;
            assert_eq!(
                tx.select(
                    &scope,
                    JobQuery::Group {
                        group: "group".into(),
                        after: None,
                        unfinished: true
                    },
                    now,
                    1
                )
                .unwrap()
                .len(),
                1
            );
            assert_eq!(tx.examined, 1);
            assert_eq!(tx.leased(&scope, now).unwrap(), 8);
            measurements.push((delivery_rows, diagnostic_rows));
        }
        assert_eq!(measurements, vec![(9, 1), (9, 1)]);
        eprintln!(
            "delivery/diagnostic examined rows at 10 vs 10,000 retained rows: {measurements:?}"
        );
    }

    #[test]
    fn jobs_memory_rollback_journals_only_touched_entries_and_restores_indexes() {
        let (mut state, scope, now, mut row) = fixture(10_000);
        let original = row.clone();
        let summary = state.summaries.clone();
        let indexes = state.indexes.clone();
        {
            let mut tx = JobMemoryTransaction::new(&mut state);
            row.state = JobState::Accepted;
            row.owners.clear();
            tx.save(row.clone()).unwrap();
            tx.save(row).unwrap();
            assert_eq!(tx.rows_before.len(), 1);
            assert_eq!(tx.summaries_before.len(), 1);
            // Abort after repeated writes to the same row.
        }
        assert_eq!(state.indexes, indexes);
        assert_eq!(state.summaries, summary);
        let mut tx = JobMemoryTransaction::new(&mut state);
        assert_eq!(
            tx.by_key(&scope, "eligible").unwrap().unwrap().state,
            original.state
        );
        assert_eq!(
            tx.select(
                &scope,
                JobQuery::Owner {
                    owner: "target".into(),
                    after: None
                },
                now,
                1
            )
            .unwrap()[0]
                .id,
            original.id
        );
    }
}
