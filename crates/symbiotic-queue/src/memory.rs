//! In-process [`QueueBackend`] with no storage dependency.
//!
//! For hosts that need the queued providers' coordination (shared model cap,
//! idempotency, retry accounting, cooldowns) inside one process and no state
//! across restarts. Every clone shares the same state; separate instances are
//! independent. Terminal items (succeeded or dead) are retained up to a bound
//! so repeated requests still see their terminal duplicate; the oldest are
//! evicted first. Active items are never evicted.

use crate::{
    ClaimRequest, EnqueueDisposition, EnqueueOutcome, EnqueueRequest, FailOutcome, QueueBackend,
    QueueError, QueueEvent, QueueEventSink, QueueItem, QueueStatus,
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
        self.state
            .lock()
            .map_err(|_| QueueError::Unavailable("memory queue lock poisoned".to_string()))
    }

    async fn emit(&self, events: Vec<(QueueItem, Option<String>)>) {
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

    fn update_running(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        update: impl FnOnce(&mut State, DateTime<Utc>) -> Result<(), QueueError>,
    ) -> Result<QueueItem, QueueError> {
        let now = Utc::now();
        let mut state = self.lock()?;
        let current = state
            .items
            .get(&item_id.0)
            .ok_or_else(|| QueueError::NotFound(item_id.0.clone()))?;
        if current.status != QueueStatus::Running {
            return Err(QueueError::NotRunning(item_id.0.clone()));
        }
        if current.lease_owner.as_deref() != Some(worker_id) {
            return Err(QueueError::LeaseMismatch(item_id.0.clone()));
        }
        if current.lease_until.is_none_or(|until| until < now) {
            return Err(QueueError::LeaseMismatch(format!(
                "{} lease expired",
                item_id.0
            )));
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
        if matches!(status, QueueStatus::Succeeded | QueueStatus::Dead) {
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

    /// Return expired running items of `queue_id` to `Failed`.
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
            self.set_status(&id, QueueStatus::Failed);
            let item = self.items.get_mut(&id).expect("running item exists");
            item.lease_owner = None;
            item.lease_until = None;
            item.updated_at = now;
            item.last_error
                .get_or_insert_with(|| "lease expired".to_string());
            reclaimed.push(item.clone());
        }
        reclaimed
    }

    fn lease(&mut self, item_id: &str, worker_id: &str, lease_seconds: u64, now: DateTime<Utc>) {
        self.set_status(item_id, QueueStatus::Running);
        let item = self.items.get_mut(item_id).expect("claimed item exists");
        item.attempt = item.attempt.saturating_add(1);
        item.lease_owner = Some(worker_id.to_string());
        item.lease_until = Some(now + ChronoDuration::seconds(lease_seconds.max(1) as i64));
        item.updated_at = now;
    }
}

fn lease_events(items: Vec<QueueItem>) -> Vec<(QueueItem, Option<String>)> {
    items
        .into_iter()
        .map(|item| (item, Some("lease expired".to_string())))
        .collect()
}

#[async_trait]
impl QueueBackend for MemoryQueue {
    async fn enqueue(&self, request: EnqueueRequest) -> Result<EnqueueOutcome, QueueError> {
        if request.kind.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                "queue item kind must not be empty".to_string(),
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
                if active || !request.force {
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

    async fn claim(&self, request: ClaimRequest) -> Result<Vec<QueueItem>, QueueError> {
        if request.worker_id.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                "worker_id must not be empty".to_string(),
            ));
        }
        let now = Utc::now();
        let (reclaimed, claimed) = {
            let mut state = self.lock()?;
            let queue_id = request.queue_id.0.as_str();
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
                    state.lease(id, &request.worker_id, request.lease_seconds, now);
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
                "worker_id must not be empty".to_string(),
            ));
        }
        let now = Utc::now();
        let (reclaimed, claimed) = {
            let mut state = self.lock()?;
            let queue_id = state
                .items
                .get(&item_id.0)
                .ok_or_else(|| QueueError::NotFound(item_id.0.clone()))?
                .queue_id
                .0
                .clone();
            let reclaimed = state.reclaim_expired(&queue_id, now);
            let current = &state.items[&item_id.0];
            let claimable = matches!(current.status, QueueStatus::Pending | QueueStatus::Failed)
                && current.run_after <= now
                && max_in_flight.is_none_or(|cap| state.running_count(&queue_id) < cap);
            let claimed = claimable.then(|| {
                state.lease(&item_id.0, worker_id, lease_seconds, now);
                state.items[&item_id.0].clone()
            });
            (reclaimed, claimed)
        };
        let mut events = lease_events(reclaimed);
        events.extend(claimed.iter().cloned().map(|item| (item, None)));
        self.emit(events).await;
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
            item.lease_until = Some(now + ChronoDuration::seconds(lease_seconds.max(1) as i64));
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
        error: &str,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError> {
        let mut outcome = FailOutcome::RetryScheduled;
        let item = self.update_running(item_id, worker_id, |state, now| {
            let item = state
                .items
                .get_mut(&item_id.0)
                .expect("running item exists");
            let exhausted = item.attempt >= item.max_attempts;
            item.run_after = now + ChronoDuration::seconds(retry_after_seconds.unwrap_or(1) as i64);
            item.lease_owner = None;
            item.lease_until = None;
            item.last_error = Some(error.to_string());
            item.updated_at = now;
            let status = if exhausted {
                outcome = FailOutcome::MovedToDead;
                QueueStatus::Dead
            } else {
                QueueStatus::Failed
            };
            state.set_status(&item_id.0, status);
            Ok(())
        })?;
        self.emit(vec![(item, Some(error.to_string()))]).await;
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
