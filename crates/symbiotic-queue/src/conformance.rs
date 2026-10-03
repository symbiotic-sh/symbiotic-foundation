//! Behaviour every [`QueueBackend`] must share, as reusable async checks.
//!
//! Enable the `conformance` feature in a backend crate's dev-dependencies and
//! expand [`queue_backend_conformance!`](crate::queue_backend_conformance)
//! with a constructor for a fresh, empty backend. Each check becomes one test.
//! The checks use only the trait, so a backend passes by matching the
//! documented semantics, not an implementation.

use crate::{
    ClaimRequest, EnqueueDisposition, EnqueueRequest, FailOutcome, Failure, QueueBackend,
    QueueError, QueueStatus,
};
use chrono::{Duration as ChronoDuration, Utc};
use std::collections::HashSet;
use std::sync::Arc;
use symbiotic_core::{QueueId, QueueItemId};

/// Expand one `#[tokio::test]` per conformance check.
///
/// ```ignore
/// symbiotic_queue::queue_backend_conformance!(|| std::sync::Arc::new(MyQueue::new()));
/// ```
#[macro_export]
macro_rules! queue_backend_conformance {
    ($make:expr) => {
        $crate::queue_backend_conformance!(@tests $make;
            enqueue_deduplicates_active_and_terminal_items,
            enqueue_rejects_empty_kind,
            enqueue_applies_attempt_and_schedule_defaults,
            idempotency_is_scoped_to_the_queue,
            claim_orders_ready_items_and_skips_future_items,
            claim_respects_max_in_flight,
            claim_item_claims_only_the_requested_item,
            claim_item_respects_max_in_flight,
            claim_item_of_an_unknown_item_is_not_found,
            claim_rejects_an_empty_worker,
            concurrent_claims_never_double_lease,
            lease_owner_and_running_state_are_enforced,
            heartbeat_extends_the_lease,
            fail_retries_until_dead_and_complete_clears_the_error,
            fail_schedules_the_retry_delay,
            expired_lease_cannot_complete_and_is_reclaimed,
            an_expired_final_attempt_is_dead_not_claimable,
            fail_with_records_the_class_and_the_exact_deadline,
            failure_without_retry_deadline_stops_with_attempts_remaining,
            enqueue_replacing_supersedes_only_the_current_item,
            cooldown_only_moves_forward,
            regression_claims_observe_extended_cooldowns,
            regression_unrepresentable_leases_are_refused,
            unknown_item_is_absent,
        );
    };
    (@tests $make:expr; $($check:ident),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $check() {
                let make: fn() -> ::std::sync::Arc<dyn $crate::QueueBackend> = $make;
                $crate::conformance::$check(make()).await;
            }
        )+
    };
}

const QUEUE: &str = "chat:conformance:model";

fn queue_id() -> QueueId {
    QueueId::new(QUEUE)
}

fn request(key: &str) -> EnqueueRequest {
    EnqueueRequest {
        queue_id: queue_id(),
        kind: "chat".to_string(),
        payload: serde_json::json!({ "key": key }),
        idempotency_key: Some(key.to_string()),
        run_after: None,
        max_attempts: Some(2),
        force: false,
    }
}

fn claim(worker: &str, limit: usize, max_in_flight: Option<usize>) -> ClaimRequest {
    ClaimRequest {
        queue_id: queue_id(),
        worker_id: worker.to_string(),
        limit,
        lease_seconds: 60,
        max_in_flight,
    }
}

async fn claim_one(queue: &dyn QueueBackend, item_id: &QueueItemId, lease: u64) {
    queue
        .claim_item(item_id, "worker", lease, None)
        .await
        .unwrap()
        .expect("item is claimable");
}

async fn status(queue: &dyn QueueBackend, item_id: &QueueItemId) -> QueueStatus {
    queue.get_item(item_id).await.unwrap().unwrap().status
}

pub async fn enqueue_deduplicates_active_and_terminal_items(queue: Arc<dyn QueueBackend>) {
    let first = queue.enqueue(request("same")).await.unwrap();
    assert_eq!(first.disposition, EnqueueDisposition::Inserted);
    let duplicate = queue.enqueue(request("same")).await.unwrap();
    assert_eq!(duplicate.disposition, EnqueueDisposition::ActiveDuplicate);
    assert_eq!(duplicate.item.item_id, first.item.item_id);

    claim_one(queue.as_ref(), &first.item.item_id, 60).await;
    let running = queue.enqueue(request("same")).await.unwrap();
    assert_eq!(running.disposition, EnqueueDisposition::ActiveDuplicate);
    queue.complete(&first.item.item_id, "worker").await.unwrap();

    let terminal = queue.enqueue(request("same")).await.unwrap();
    assert_eq!(terminal.disposition, EnqueueDisposition::TerminalDuplicate);
    assert_eq!(terminal.item.status, QueueStatus::Succeeded);

    let mut forced = request("same");
    forced.force = true;
    let inserted = queue.enqueue(forced).await.unwrap();
    assert_eq!(inserted.disposition, EnqueueDisposition::Inserted);
    assert_ne!(inserted.item.item_id, first.item.item_id);
    // The forced item is now the one duplicates resolve to.
    let after = queue.enqueue(request("same")).await.unwrap();
    assert_eq!(after.disposition, EnqueueDisposition::ActiveDuplicate);
    assert_eq!(after.item.item_id, inserted.item.item_id);
}

pub async fn enqueue_rejects_empty_kind(queue: Arc<dyn QueueBackend>) {
    let mut empty = request("empty-kind");
    empty.kind = "  ".to_string();
    let err = queue.enqueue(empty).await.unwrap_err();
    assert!(matches!(err, QueueError::InvalidRequest(_)), "{err:?}");
}

pub async fn enqueue_applies_attempt_and_schedule_defaults(queue: Arc<dyn QueueBackend>) {
    let before = Utc::now();
    let mut defaulted = request("defaults");
    defaulted.max_attempts = None;
    let item = queue.enqueue(defaulted).await.unwrap().item;
    assert_eq!(item.max_attempts, 3);
    assert_eq!(item.attempt, 0);
    assert_eq!(item.status, QueueStatus::Pending);
    assert!(item.run_after >= before - ChronoDuration::seconds(1));
    assert!(item.run_after <= Utc::now());

    let mut zero = request("zero-attempts");
    zero.max_attempts = Some(0);
    assert_eq!(queue.enqueue(zero).await.unwrap().item.max_attempts, 1);
}

pub async fn idempotency_is_scoped_to_the_queue(queue: Arc<dyn QueueBackend>) {
    queue.enqueue(request("shared-key")).await.unwrap();
    let mut other = request("shared-key");
    other.queue_id = QueueId::new("chat:conformance:other");
    let outcome = queue.enqueue(other).await.unwrap();
    assert_eq!(outcome.disposition, EnqueueDisposition::Inserted);
}

pub async fn claim_orders_ready_items_and_skips_future_items(queue: Arc<dyn QueueBackend>) {
    let mut later = request("later");
    later.run_after = Some(Utc::now() - ChronoDuration::seconds(5));
    let mut earlier = request("earlier");
    earlier.run_after = Some(Utc::now() - ChronoDuration::seconds(10));
    let mut future = request("future");
    future.run_after = Some(Utc::now() + ChronoDuration::hours(1));
    let later = queue.enqueue(later).await.unwrap().item;
    let earlier = queue.enqueue(earlier).await.unwrap().item;
    let future = queue.enqueue(future).await.unwrap().item;

    let claimed = queue.claim(claim("worker", 10, None)).await.unwrap();
    let ids: Vec<_> = claimed.iter().map(|item| item.item_id.clone()).collect();
    assert_eq!(ids, vec![earlier.item_id, later.item_id]);
    assert!(claimed.iter().all(|item| {
        item.status == QueueStatus::Running
            && item.attempt == 1
            && item.lease_owner.as_deref() == Some("worker")
            && item.lease_until.is_some()
    }));
    assert_eq!(
        status(queue.as_ref(), &future.item_id).await,
        QueueStatus::Pending
    );
    assert!(
        queue
            .claim_item(&future.item_id, "worker", 60, None)
            .await
            .unwrap()
            .is_none()
    );
}

pub async fn claim_respects_max_in_flight(queue: Arc<dyn QueueBackend>) {
    for idx in 0..3 {
        queue
            .enqueue(request(&format!("capped-{idx}")))
            .await
            .unwrap();
    }
    let first = queue.claim(claim("worker-a", 3, Some(2))).await.unwrap();
    assert_eq!(first.len(), 2);
    let second = queue.claim(claim("worker-b", 1, Some(2))).await.unwrap();
    assert!(second.is_empty());
    queue.complete(&first[0].item_id, "worker-a").await.unwrap();
    let third = queue.claim(claim("worker-b", 3, Some(2))).await.unwrap();
    assert_eq!(third.len(), 1);
}

pub async fn claim_item_claims_only_the_requested_item(queue: Arc<dyn QueueBackend>) {
    let first = queue.enqueue(request("target-a")).await.unwrap().item;
    let second = queue.enqueue(request("target-b")).await.unwrap().item;
    let claimed = queue
        .claim_item(&second.item_id, "worker", 60, Some(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.item_id, second.item_id);
    assert_eq!(claimed.attempt, 1);
    assert_eq!(
        status(queue.as_ref(), &first.item_id).await,
        QueueStatus::Pending
    );
    // A running item is not claimable again.
    assert!(
        queue
            .claim_item(&second.item_id, "other", 60, None)
            .await
            .unwrap()
            .is_none()
    );
}

pub async fn claim_item_respects_max_in_flight(queue: Arc<dyn QueueBackend>) {
    let first = queue.enqueue(request("cap-a")).await.unwrap().item;
    let second = queue.enqueue(request("cap-b")).await.unwrap().item;
    claim_one(queue.as_ref(), &first.item_id, 60).await;
    assert!(
        queue
            .claim_item(&second.item_id, "worker", 60, Some(1))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        queue
            .claim_item(&second.item_id, "worker", 60, Some(2))
            .await
            .unwrap()
            .is_some()
    );
}

pub async fn claim_item_of_an_unknown_item_is_not_found(queue: Arc<dyn QueueBackend>) {
    let err = queue
        .claim_item(&QueueItemId::new(), "worker", 60, None)
        .await
        .unwrap_err();
    assert!(matches!(err, QueueError::NotFound(_)), "{err:?}");
}

pub async fn claim_rejects_an_empty_worker(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("no-worker")).await.unwrap().item;
    let err = queue.claim(claim(" ", 1, None)).await.unwrap_err();
    assert!(matches!(err, QueueError::InvalidRequest(_)), "{err:?}");
    let err = queue
        .claim_item(&item.item_id, "", 60, None)
        .await
        .unwrap_err();
    assert!(matches!(err, QueueError::InvalidRequest(_)), "{err:?}");
}

pub async fn concurrent_claims_never_double_lease(queue: Arc<dyn QueueBackend>) {
    for idx in 0..25 {
        queue
            .enqueue(request(&format!("race-{idx}")))
            .await
            .unwrap();
    }
    let handles: Vec<_> = (0..10)
        .map(|idx| {
            let queue = queue.clone();
            tokio::spawn(async move {
                queue
                    .claim(claim(&format!("worker-{idx}"), 3, None))
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut ids = HashSet::new();
    let mut total = 0;
    for handle in handles {
        for item in handle.await.unwrap() {
            total += 1;
            ids.insert(item.item_id);
        }
    }
    assert_eq!(total, ids.len(), "an item was leased twice");
    assert_eq!(ids.len(), 25);
}

pub async fn lease_owner_and_running_state_are_enforced(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("lease")).await.unwrap().item;
    let err = queue.complete(&item.item_id, "worker").await.unwrap_err();
    assert!(matches!(err, QueueError::NotRunning(_)), "{err:?}");

    claim_one(queue.as_ref(), &item.item_id, 60).await;
    let err = queue.complete(&item.item_id, "other").await.unwrap_err();
    assert!(matches!(err, QueueError::LeaseMismatch(_)), "{err:?}");
    let err = queue
        .fail(
            &item.item_id,
            "other",
            symbiotic_core::DiagnosticCode::QueueFailure,
            Some(0),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, QueueError::LeaseMismatch(_)), "{err:?}");
    let err = queue
        .heartbeat(&item.item_id, "other", 60)
        .await
        .unwrap_err();
    assert!(matches!(err, QueueError::LeaseMismatch(_)), "{err:?}");

    let err = queue
        .complete(&QueueItemId::new(), "worker")
        .await
        .unwrap_err();
    assert!(matches!(err, QueueError::NotFound(_)), "{err:?}");
}

pub async fn heartbeat_extends_the_lease(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("heartbeat")).await.unwrap().item;
    claim_one(queue.as_ref(), &item.item_id, 5).await;
    let before = queue
        .get_item(&item.item_id)
        .await
        .unwrap()
        .unwrap()
        .lease_until
        .unwrap();
    queue.heartbeat(&item.item_id, "worker", 600).await.unwrap();
    let after = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert_eq!(after.status, QueueStatus::Running);
    assert_eq!(after.attempt, 1);
    assert!(after.lease_until.unwrap() > before + ChronoDuration::seconds(60));
}

pub async fn fail_retries_until_dead_and_complete_clears_the_error(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("retry")).await.unwrap().item;
    claim_one(queue.as_ref(), &item.item_id, 60).await;
    let outcome = queue
        .fail(
            &item.item_id,
            "worker",
            symbiotic_core::DiagnosticCode::QueueFailure,
            Some(0),
        )
        .await
        .unwrap();
    assert_eq!(outcome, FailOutcome::RetryScheduled);
    let failed = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert_eq!(failed.status, QueueStatus::Failed);
    assert_eq!(
        failed.last_error,
        Some(symbiotic_core::DiagnosticCode::QueueFailure)
    );
    assert!(failed.lease_owner.is_none() && failed.lease_until.is_none());
    // A failed item is still active for deduplication.
    let duplicate = queue.enqueue(request("retry")).await.unwrap();
    assert_eq!(duplicate.disposition, EnqueueDisposition::ActiveDuplicate);

    claim_one(queue.as_ref(), &item.item_id, 60).await;
    let outcome = queue
        .fail(
            &item.item_id,
            "worker",
            symbiotic_core::DiagnosticCode::QueueFailure,
            Some(0),
        )
        .await
        .unwrap();
    assert_eq!(outcome, FailOutcome::MovedToDead);
    let dead = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert_eq!(dead.status, QueueStatus::Dead);
    assert_eq!(dead.attempt, 2);
    assert_eq!(
        dead.last_error,
        Some(symbiotic_core::DiagnosticCode::QueueFailure)
    );
    let terminal = queue.enqueue(request("retry")).await.unwrap();
    assert_eq!(terminal.disposition, EnqueueDisposition::TerminalDuplicate);

    let recovered = queue.enqueue(request("recovered")).await.unwrap().item;
    claim_one(queue.as_ref(), &recovered.item_id, 60).await;
    queue
        .fail(
            &recovered.item_id,
            "worker",
            symbiotic_core::DiagnosticCode::QueueFailure,
            Some(0),
        )
        .await
        .unwrap();
    claim_one(queue.as_ref(), &recovered.item_id, 60).await;
    queue.complete(&recovered.item_id, "worker").await.unwrap();
    let done = queue.get_item(&recovered.item_id).await.unwrap().unwrap();
    assert_eq!(done.status, QueueStatus::Succeeded);
    assert_eq!(done.last_error, None);
    assert!(done.lease_owner.is_none() && done.lease_until.is_none());
}

pub async fn fail_schedules_the_retry_delay(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("delayed")).await.unwrap().item;
    claim_one(queue.as_ref(), &item.item_id, 60).await;
    queue
        .fail(
            &item.item_id,
            "worker",
            symbiotic_core::DiagnosticCode::QueueFailure,
            Some(3_600),
        )
        .await
        .unwrap();
    let failed = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert!(failed.run_after > Utc::now() + ChronoDuration::minutes(59));
    assert!(
        queue
            .claim_item(&item.item_id, "worker", 60, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        queue
            .claim(claim("worker", 5, None))
            .await
            .unwrap()
            .is_empty()
    );
}

/// Sleeps just over one second: the shortest lease a backend grants.
pub async fn expired_lease_cannot_complete_and_is_reclaimed(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("expired")).await.unwrap().item;
    claim_one(queue.as_ref(), &item.item_id, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    let err = queue.complete(&item.item_id, "worker").await.unwrap_err();
    assert!(matches!(err, QueueError::LeaseMismatch(_)), "{err:?}");
    let err = queue
        .heartbeat(&item.item_id, "worker", 60)
        .await
        .unwrap_err();
    assert!(matches!(err, QueueError::LeaseMismatch(_)), "{err:?}");

    assert_eq!(queue.reclaim_expired_leases(&queue_id()).await.unwrap(), 1);
    assert_eq!(queue.reclaim_expired_leases(&queue_id()).await.unwrap(), 0);
    let reclaimed = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert_eq!(reclaimed.status, QueueStatus::Failed);
    assert_eq!(
        reclaimed.last_error,
        Some(symbiotic_core::DiagnosticCode::LeaseExpired)
    );
    assert!(reclaimed.lease_owner.is_none() && reclaimed.lease_until.is_none());

    // Another worker can take it over; the attempt counter keeps counting.
    let retaken = queue
        .claim_item(&item.item_id, "other", 60, Some(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retaken.attempt, 2);
    assert_eq!(retaken.lease_owner.as_deref(), Some("other"));
}

pub async fn cooldown_only_moves_forward(queue: Arc<dyn QueueBackend>) {
    assert_eq!(queue.cooldown_until(&queue_id()).await.unwrap(), None);
    let later = Utc::now() + ChronoDuration::seconds(30);
    let earlier = Utc::now() + ChronoDuration::seconds(10);
    queue.note_cooldown(&queue_id(), later).await.unwrap();
    queue.note_cooldown(&queue_id(), earlier).await.unwrap();
    let until = queue.cooldown_until(&queue_id()).await.unwrap().unwrap();
    assert!(
        (until - later).num_milliseconds().abs() < 1_000,
        "{until} vs {later}"
    );
    let other = QueueId::new("chat:conformance:other");
    assert_eq!(queue.cooldown_until(&other).await.unwrap(), None);
}

pub async fn unknown_item_is_absent(queue: Arc<dyn QueueBackend>) {
    assert!(queue.get_item(&QueueItemId::new()).await.unwrap().is_none());
}

/// A crash during the last allowed attempt must not buy another attempt:
/// once that lease expires the item is dead, whether a sweep or a claim
/// finds it first. Sleeps just over one second.
pub async fn an_expired_final_attempt_is_dead_not_claimable(queue: Arc<dyn QueueBackend>) {
    let mut swept = request("final-swept");
    swept.max_attempts = Some(1);
    let mut claimed = request("final-claimed");
    claimed.max_attempts = Some(1);
    let swept = queue.enqueue(swept).await.unwrap().item;
    let claimed = queue.enqueue(claimed).await.unwrap().item;
    claim_one(queue.as_ref(), &swept.item_id, 1).await;
    claim_one(queue.as_ref(), &claimed.item_id, 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    // A claim of the expired item reclaims every expired lease of the queue.
    assert!(
        queue
            .claim_item(&claimed.item_id, "restarted", 60, None)
            .await
            .unwrap()
            .is_none()
    );
    for item_id in [&swept.item_id, &claimed.item_id] {
        let item = queue.get_item(item_id).await.unwrap().unwrap();
        assert_eq!(item.status, QueueStatus::Dead, "{item:?}");
        assert_eq!(item.attempt, 1);
        assert!(item.lease_owner.is_none());
    }
    assert!(
        queue
            .claim(claim("restarted", 5, None))
            .await
            .unwrap()
            .is_empty()
    );
    let mut again = request("final-swept");
    again.max_attempts = Some(1);
    let duplicate = queue.enqueue(again).await.unwrap();
    assert_eq!(duplicate.disposition, EnqueueDisposition::TerminalDuplicate);
}

pub async fn fail_with_records_the_class_and_the_exact_deadline(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("classified")).await.unwrap().item;
    claim_one(queue.as_ref(), &item.item_id, 60).await;
    let deadline = Utc::now() + ChronoDuration::milliseconds(400);
    let outcome = queue
        .fail_with(
            &item.item_id,
            "worker",
            Failure {
                error: symbiotic_core::DiagnosticCode::QueueFailure,
                error_class: Some(symbiotic_core::FailureClass::RateLimited),
                run_after: Some(deadline),
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome, FailOutcome::RetryScheduled);
    let failed = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert_eq!(
        failed.last_error,
        Some(symbiotic_core::DiagnosticCode::QueueFailure)
    );
    assert_eq!(
        failed.last_error_class,
        Some(symbiotic_core::FailureClass::RateLimited)
    );
    assert!(
        (failed.run_after - deadline).num_milliseconds().abs() < 5,
        "{} vs {deadline}",
        failed.run_after
    );
    assert!(
        queue
            .claim_item(&item.item_id, "worker", 60, None)
            .await
            .unwrap()
            .is_none(),
        "not before the deadline"
    );
    tokio::time::sleep(std::time::Duration::from_millis(450)).await;
    claim_one(queue.as_ref(), &item.item_id, 60).await;
    queue.complete(&item.item_id, "worker").await.unwrap();
    let done = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert_eq!(done.last_error_class, None);
}

async fn finish(queue: &dyn QueueBackend, item_id: &QueueItemId) {
    claim_one(queue, item_id, 60).await;
    queue.complete(item_id, "worker").await.unwrap();
}

pub async fn enqueue_replacing_supersedes_only_the_current_item(queue: Arc<dyn QueueBackend>) {
    let first = queue.enqueue(request("replace")).await.unwrap().item;
    finish(queue.as_ref(), &first.item_id).await;

    let second = queue
        .enqueue_replacing(request("replace"), &first.item_id)
        .await
        .unwrap();
    assert_eq!(second.disposition, EnqueueDisposition::Inserted);
    let second = second.item;
    assert_ne!(second.item_id, first.item_id);

    // A caller still holding the first item cannot replace the second.
    let stale = queue
        .enqueue_replacing(request("replace"), &first.item_id)
        .await
        .unwrap();
    assert_eq!(stale.disposition, EnqueueDisposition::ActiveDuplicate);
    assert_eq!(stale.item.item_id, second.item_id);
    finish(queue.as_ref(), &second.item_id).await;
    let stale = queue
        .enqueue_replacing(request("replace"), &first.item_id)
        .await
        .unwrap();
    assert_eq!(stale.disposition, EnqueueDisposition::TerminalDuplicate);
    assert_eq!(stale.item.item_id, second.item_id);

    // Two callers holding the current item: exactly one replaces it.
    let racers: Vec<_> = (0..2)
        .map(|_| {
            let queue = queue.clone();
            let current = second.item_id.clone();
            tokio::spawn(async move {
                queue
                    .enqueue_replacing(request("replace"), &current)
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut inserted = 0;
    let mut ids = HashSet::new();
    for racer in racers {
        let outcome = racer.await.unwrap();
        if outcome.disposition == EnqueueDisposition::Inserted {
            inserted += 1;
        }
        ids.insert(outcome.item.item_id);
    }
    assert_eq!(inserted, 1);
    assert_eq!(ids.len(), 1, "both callers end on the same replacement");
}

/// A terminal refusal must never reenter the claimable work set.
pub async fn failure_without_retry_deadline_stops_with_attempts_remaining(
    queue: Arc<dyn QueueBackend>,
) {
    let item = queue.enqueue(request("stopped")).await.unwrap().item;
    claim_one(queue.as_ref(), &item.item_id, 60).await;
    let outcome = queue
        .fail_with(
            &item.item_id,
            "worker",
            Failure {
                error: symbiotic_core::DiagnosticCode::QueueFailure,
                error_class: Some(symbiotic_core::FailureClass::Queue),
                run_after: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome, FailOutcome::Stopped);
    let stopped = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert_eq!(stopped.status, QueueStatus::Stopped);
    assert!(stopped.attempt < stopped.max_attempts);
    assert!(
        queue
            .claim_item(&item.item_id, "other", 60, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        queue
            .claim(claim("other", 1, None))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(queue.reclaim_expired_leases(&queue_id()).await.unwrap(), 0);
    let duplicate = queue.enqueue(request("stopped")).await.unwrap();
    assert_eq!(duplicate.disposition, EnqueueDisposition::TerminalDuplicate);
    assert_eq!(duplicate.item.item_id, item.item_id);
    assert_eq!(
        duplicate.item.last_error_class,
        Some(symbiotic_core::FailureClass::Queue)
    );
}

/// A cooldown extension accepted before a claim must keep both claim APIs pending.
pub async fn regression_claims_observe_extended_cooldowns(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("cooldown-claim")).await.unwrap().item;
    let now = Utc::now();
    queue
        .note_cooldown(&queue_id(), now - ChronoDuration::seconds(1))
        .await
        .unwrap();
    assert!(queue.cooldown_until(&queue_id()).await.unwrap().unwrap() < Utc::now());
    // Simulate the extension between a caller's final read and claim acceptance.
    queue
        .note_cooldown(&queue_id(), now + ChronoDuration::seconds(60))
        .await
        .unwrap();
    assert!(
        queue
            .claim_item(&item.item_id, "worker", 60, None)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        queue
            .claim(claim("worker", 1, None))
            .await
            .unwrap()
            .is_empty()
    );
    let item = queue.get_item(&item.item_id).await.unwrap().unwrap();
    assert_eq!(item.status, QueueStatus::Pending);
    assert_eq!(item.attempt, 0);
}

/// Invalid leases must fail without spending an attempt or poisoning the backend.
pub async fn regression_unrepresentable_leases_are_refused(queue: Arc<dyn QueueBackend>) {
    let item = queue.enqueue(request("invalid-lease")).await.unwrap().item;
    for seconds in [u64::MAX, i64::MAX as u64 / 1000] {
        assert!(matches!(
            queue
                .claim_item(&item.item_id, "worker", seconds, None)
                .await,
            Err(QueueError::InvalidRequest(_))
        ));
        let mut request = claim("worker", 1, None);
        request.lease_seconds = seconds;
        assert!(matches!(
            queue.claim(request).await,
            Err(QueueError::InvalidRequest(_))
        ));
    }
    assert_eq!(
        queue
            .get_item(&item.item_id)
            .await
            .unwrap()
            .unwrap()
            .attempt,
        0
    );
    claim_one(queue.as_ref(), &item.item_id, 60).await;
    assert!(matches!(
        queue.heartbeat(&item.item_id, "worker", u64::MAX).await,
        Err(QueueError::InvalidRequest(_))
    ));
    queue.heartbeat(&item.item_id, "worker", 60).await.unwrap();
}

/// Shared generic-job acceptance suite; clocks advance deterministically.
pub mod jobs {
    use crate::QueueBackend;
    use crate::jobs::*;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use symbiotic_core::BindingIdentity;

    struct Suite {
        backend: Arc<dyn QueueBackend>,
        scope: JobScope,
        config: JobConfig,
        now: DateTime<Utc>,
        background_in_flight: usize,
    }
    impl Suite {
        fn new(backend: Arc<dyn QueueBackend>) -> Self {
            Self {
                backend,
                scope: JobScope {
                    tenant: "tenant".into(),
                    incarnation: "restore-1".into(),
                    queue: "jobs".into(),
                },
                config: JobConfig::default(),
                background_in_flight: 0,
                now: DateTime::parse_from_rfc3339("2026-10-03T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }
        fn spec(&self, key: &str) -> JobSpec {
            JobSpec {
                key: key.into(),
                group: Some("group".into()),
                owners: vec!["owner-a".into(), "owner-b".into()],
                kind: "handler".into(),
                execution: Execution::Handler,
                priority: Priority::Background,
                payload: json!({ "input": key }),
                limits: JobLimits { max_attempts: 3 },
                admission: None,
                recovery_until: None,
            }
        }
        async fn op(&self, request: JobRequest) -> Result<JobResponse, JobError> {
            self.backend
                .jobs(&self.scope, &self.config, self.now, request)
                .await
        }
        async fn enqueue(&self, specs: Vec<JobSpec>) -> Vec<Enqueued> {
            match self.op(JobRequest::Enqueue(specs)).await.unwrap() {
                JobResponse::Enqueued(v) => v,
                other => panic!("{other:?}"),
            }
        }
        async fn insert(&self, spec: JobSpec) -> JobId {
            match self.enqueue(vec![spec]).await.remove(0) {
                Enqueued::Inserted(id) => id,
                other => panic!("{other:?}"),
            }
        }
        async fn get(&self, id: &JobId) -> JobRecord {
            match self.op(JobRequest::Get(id.clone())).await.unwrap() {
                JobResponse::Job(Some(row)) => *row,
                other => panic!("{other:?}"),
            }
        }
        async fn claim(&self) -> JobRecord {
            match self
                .op(JobRequest::Claim {
                    kinds: vec!["handler".into()],
                    slots_available: 4,
                    background_in_flight: self.background_in_flight,
                })
                .await
                .unwrap()
            {
                JobResponse::Job(Some(row)) => *row,
                other => panic!("{other:?}"),
            }
        }
        async fn complete(&self, row: &JobRecord, output: Value) {
            self.op(JobRequest::Complete {
                job: row.id.clone(),
                generation: row.generation,
                state: JobState::Succeeded,
                origin: ResultOrigin::Handler,
                output: Some(output),
                receipt: None,
                diagnostic: None,
            })
            .await
            .unwrap();
        }
        async fn ready(&self, key: &str) -> JobId {
            let id = self.insert(self.spec(key)).await;
            let row = self.claim().await;
            assert_eq!(id, row.id);
            self.complete(&row, json!({ "answer": key })).await;
            id
        }
        async fn deliveries(&self, limit: usize, max_bytes: usize) -> Vec<Delivery> {
            match self
                .op(JobRequest::Completions { limit, max_bytes })
                .await
                .unwrap()
            {
                JobResponse::Deliveries(v) => v,
                other => panic!("{other:?}"),
            }
        }
        async fn ack(&self, token: DeliveryToken, disposition: Disposition) -> AckResult {
            match self
                .op(JobRequest::Ack(vec![(token, disposition)]))
                .await
                .unwrap()
            {
                JobResponse::Acks(mut v) => v.remove(0),
                other => panic!("{other:?}"),
            }
        }
        async fn summary(&self, rebuild: bool) -> GroupSummary {
            let req = if rebuild {
                JobRequest::RebuildSummary("group".into())
            } else {
                JobRequest::Status("group".into())
            };
            match self.op(req).await.unwrap() {
                JobResponse::Summary(v) => v,
                other => panic!("{other:?}"),
            }
        }
        fn admission(&self, ordinal: u32, expires: DateTime<Utc>) -> SignedAdmission {
            SignedAdmission {
                ordinal,
                binding: BindingIdentity::new("tenant", "provider", "revision", "account"),
                authority_until: expires,
                signed: vec![1],
            }
        }
        fn advance(&mut self, seconds: i64) {
            self.now += Duration::seconds(seconds);
        }
        async fn changed(&self, request: JobRequest) -> usize {
            match self.op(request).await.unwrap() {
                JobResponse::Changed(n) => n,
                other => panic!("{other:?}"),
            }
        }
    }

    /// Case 4: stale issued delivery tokens remain confirmable, first disposition wins.
    pub async fn jobs_case_4_delivery_lease_expires_first_confirm_wins(
        backend: Arc<dyn QueueBackend>,
    ) {
        let mut s = Suite::new(backend);
        let id = s.ready("lease").await;
        let first = s.deliveries(1, 100_000).await.remove(0).token.unwrap();
        assert!(s.deliveries(1, 100_000).await.is_empty());
        s.advance(31);
        let second = s.deliveries(1, 100_000).await.remove(0).token.unwrap();
        assert!(second.generation > first.generation);
        assert_eq!(
            s.ack(first, Disposition::Accepted).await,
            AckResult::Acked(Disposition::Accepted)
        );
        assert_eq!(
            s.ack(second, Disposition::Discarded).await,
            AckResult::AlreadyAcked(Disposition::Accepted)
        );
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::Accepted);
        assert!(row.payload.is_none() && row.output.is_none() && row.owners.is_empty());
        assert!(matches!(
            s.enqueue(vec![s.spec("lease")]).await[0],
            Enqueued::AlreadyDone(_)
        ));
    }

    /// Case 5: accepted/discarded counts remain separate and summaries rebuild exactly.
    pub async fn jobs_case_5_accepted_discarded_status(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        s.ready("accepted").await;
        s.advance(1);
        s.ready("discarded").await;
        let deliveries = s.deliveries(2, 100_000).await;
        s.ack(deliveries[0].token.clone().unwrap(), Disposition::Accepted)
            .await;
        s.ack(deliveries[1].token.clone().unwrap(), Disposition::Discarded)
            .await;
        let status = s.summary(false).await;
        assert_eq!(status.counts.get(&JobState::Accepted), Some(&1));
        assert_eq!(status.counts.get(&JobState::Discarded), Some(&1));
        assert_eq!(status, s.summary(true).await);
        assert!(status.oldest_pending.is_none());
    }

    /// Case 6: page a backlog beyond the hard bound; joined keys do not consume capacity.
    pub async fn jobs_case_6_backlog_bounds_and_maintenance(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        s.config.max_pending_items = 2;
        s.config.max_batch = 2;
        s.config.maintenance_batch = 1;
        s.config.retention_seconds = 1;
        for base in [0, 2, 4] {
            let specs = vec![
                s.spec(&format!("job-{base}")),
                s.spec(&format!("job-{}", base + 1)),
            ];
            let inserted = s.enqueue(specs.clone()).await;
            assert!(inserted.iter().all(|e| matches!(e, Enqueued::Inserted(_))));
            assert!(
                s.enqueue(specs)
                    .await
                    .iter()
                    .all(|e| matches!(e, Enqueued::Joined(_)))
            );
            assert!(matches!(
                s.op(JobRequest::Enqueue(vec![s.spec("overflow")])).await,
                Err(JobError::QueueFull)
            ));
            for _ in 0..2 {
                let row = s.claim().await;
                s.complete(&row, json!("result")).await;
            }
            let page = s.deliveries(2, 100_000).await;
            assert_eq!(page.len(), 2);
            assert!(serde_json::to_vec(&page).unwrap().len() <= 100_000);
            for d in page {
                s.ack(d.token.unwrap(), Disposition::Accepted).await;
            }
        }
        // Separate unacked finals prove each maintenance pass deletes at most one.
        s.ready("expire-1").await;
        s.ready("expire-2").await;
        s.advance(2);
        assert_eq!(s.changed(JobRequest::Maintain).await, 1);
        assert_eq!(s.changed(JobRequest::Maintain).await, 1);
        assert_eq!(s.changed(JobRequest::Maintain).await, 0);
        let page = s.deliveries(2, 100_000).await;
        assert!(
            page.iter()
                .all(|d| d.completion.result_expired && d.completion.output.is_none())
        );
    }

    /// Case 8: recovery expiry never terminates Pending, AwaitingAdmission or Uncertain.
    pub async fn jobs_case_8_recovery_expiry_is_not_execution_expiry(
        backend: Arc<dyn QueueBackend>,
    ) {
        let mut s = Suite::new(backend);
        let mut spec = s.spec("admission");
        spec.recovery_until = Some(s.now - Duration::seconds(1));
        spec.admission = Some(s.admission(1, s.now + Duration::seconds(1)));
        let id = s.insert(spec).await;
        s.advance(2);
        assert_eq!(s.changed(JobRequest::Maintain).await, 0);
        assert_eq!(s.get(&id).await.state, JobState::Pending);
        assert!(matches!(
            s.op(JobRequest::Claim {
                kinds: vec!["handler".into()],
                slots_available: 1,
                background_in_flight: 0
            })
            .await
            .unwrap(),
            JobResponse::Job(None)
        ));
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::AwaitingAdmission);
        assert_eq!(row.attempt(), 0);
        assert!(row.payload.is_some());
        s.op(JobRequest::Admit {
            job: id.clone(),
            admission: s.admission(2, s.now + Duration::seconds(100)),
        })
        .await
        .unwrap();
        let row = s.claim().await;
        assert_eq!(row.key, "admission");
        assert_eq!(row.max_attempts, 3);
        assert_eq!(row.attempt(), 1);
        s.complete(&row, json!("late result")).await;
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::Succeeded);
        assert!(row.result_expired && row.output.is_none() && row.payload.is_none());
        let mut spec = s.spec("uncertain");
        spec.execution = Execution::Model;
        spec.recovery_until = Some(s.now - Duration::seconds(1));
        let id = s.insert(spec).await;
        let row = s.claim().await;
        s.op(JobRequest::Complete {
            job: id.clone(),
            generation: row.generation,
            state: JobState::Uncertain,
            origin: ResultOrigin::Paid,
            output: None,
            receipt: Some("receipt".into()),
            diagnostic: None,
        })
        .await
        .unwrap();
        assert_eq!(s.changed(JobRequest::Maintain).await, 0);
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::Uncertain);
        assert!(row.payload.is_some());
        assert!(matches!(
            s.op(JobRequest::Claim {
                kinds: vec!["handler".into()],
                slots_available: 1,
                background_in_flight: 0
            })
            .await
            .unwrap(),
            JobResponse::Job(None)
        ));
    }

    /// Case 9: an oversized first eligible completion errors without taking any lease.
    pub async fn jobs_case_9_oversized_completion_is_visible(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let id = s.insert(s.spec("large")).await;
        let row = s.claim().await;
        s.complete(&row, json!("a".repeat(5000))).await;
        assert!(
            matches!(s.op(JobRequest::Completions { limit: 1, max_bytes: 1000 }).await,
            Err(JobError::CompletionTooLarge { job, .. }) if job == id)
        );
        let row = s.get(&id).await;
        assert_eq!(row.delivery_generation, 0);
        assert!(row.delivery_until.is_none());
        assert_eq!(s.deliveries(1, 100_000).await.len(), 1);
    }

    /// Case 10: final results precede recurring notices; notices cannot acknowledge a job.
    pub async fn jobs_case_10_notices_never_starve_finals(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let mut notice = s.spec("notice");
        notice.admission = Some(s.admission(1, s.now - Duration::seconds(1)));
        let notice_id = s.insert(notice).await;
        for index in 0..3 {
            let id = s.ready(&format!("final-{index}")).await;
            let d = s.deliveries(1, 100_000).await.remove(0);
            assert_eq!(d.completion.id, id);
            s.ack(d.token.unwrap(), Disposition::Accepted).await;
        }
        let notice = s.deliveries(1, 100_000).await.remove(0);
        assert_eq!(notice.completion.id, notice_id);
        assert!(notice.token.is_none());
        let forged = DeliveryToken {
            job: notice_id.clone(),
            generation: 1,
        };
        assert!(matches!(
            s.op(JobRequest::Ack(vec![(forged, Disposition::Accepted)]))
                .await,
            Err(JobError::NotFinal)
        ));
        let row = s.get(&notice_id).await;
        assert_eq!(row.state, JobState::AwaitingAdmission);
        assert!(row.payload.is_some());
        assert!(s.deliveries(1, 100_000).await[0].token.is_none());
    }

    /// Case 11: a foreign tenant/incarnation cannot complete, cancel, confirm or read.
    pub async fn jobs_case_11_foreign_scope_refused_before_access(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let id = s.ready("scoped").await;
        let token = s.deliveries(1, 100_000).await.remove(0).token.unwrap();
        for tenant in [true, false] {
            let mut scope = s.scope.clone();
            if tenant {
                scope.tenant = "other".into();
            } else {
                scope.incarnation = "restore-2".into();
            }
            for req in [
                JobRequest::Complete {
                    job: id.clone(),
                    generation: 1,
                    state: JobState::Succeeded,
                    origin: ResultOrigin::Handler,
                    output: Some(json!("foreign")),
                    receipt: None,
                    diagnostic: None,
                },
                JobRequest::Cancel(Selector::Ids(vec![id.clone()])),
                JobRequest::Ack(vec![(token.clone(), Disposition::Discarded)]),
                JobRequest::Get(id.clone()),
            ] {
                assert!(matches!(
                    s.backend.jobs(&scope, &s.config, s.now, req).await,
                    Err(JobError::Scope)
                ));
            }
            // Spoofing the scope on an ID cannot find another scope's row either.
            let mut spoof = id.clone();
            spoof.scope = scope.clone();
            assert!(matches!(
                s.backend
                    .jobs(&scope, &s.config, s.now, JobRequest::Get(spoof))
                    .await,
                Err(JobError::NotFound)
            ));
        }
        assert_eq!(s.get(&id).await.state, JobState::Succeeded);
        assert_eq!(
            s.ack(token, Disposition::Accepted).await,
            AckResult::Acked(Disposition::Accepted)
        );
    }

    /// Case 12 (store part): any cache input owner erases every recovery copy, in either commit order.
    pub async fn jobs_case_12_cache_owner_purge_fences_result_commit(
        backend: Arc<dyn QueueBackend>,
    ) {
        let s = Suite::new(backend);
        for purge_first in [true, false] {
            let first = s
                .insert(s.spec(if purge_first { "before-1" } else { "after-1" }))
                .await;
            let second = s
                .insert(s.spec(if purge_first { "before-2" } else { "after-2" }))
                .await;
            if purge_first {
                s.changed(JobRequest::PurgeOwner("owner-b".into())).await;
            }
            for id in [&first, &second] {
                s.op(JobRequest::Complete {
                    job: id.clone(),
                    generation: 0,
                    state: JobState::Succeeded,
                    origin: ResultOrigin::Cache,
                    output: Some(json!("cached")),
                    receipt: None,
                    diagnostic: None,
                })
                .await
                .unwrap();
            }
            if !purge_first {
                s.changed(JobRequest::PurgeOwner("owner-a".into())).await;
            }
            for id in [&first, &second] {
                let row = s.get(id).await;
                assert!(row.purged && row.output.is_none() && row.payload.is_none());
                assert_eq!(row.state, JobState::Purged);
                assert_eq!(row.attempt(), 0); // cache hits create no execution attempt
            }
        }
        // Two host threads start erasure and cache completion together. Each
        // backend serializes them; neither ordering may leave a recovery copy.
        let id = s.insert(s.spec("concurrent-cache")).await;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for request in [
            JobRequest::PurgeOwner("owner-b".into()),
            JobRequest::Complete {
                job: id.clone(),
                generation: 0,
                state: JobState::Succeeded,
                origin: ResultOrigin::Cache,
                output: Some(json!("racing cache copy")),
                receipt: None,
                diagnostic: None,
            },
        ] {
            let backend = s.backend.clone();
            let scope = s.scope.clone();
            let config = s.config.clone();
            let now = s.now;
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap()
                    .block_on(backend.jobs(&scope, &config, now, request))
                    .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::Purged);
        assert!(row.purged && row.output.is_none() && row.payload.is_none());

        // Running completion serializes against the same sticky flag.
        let id = s.insert(s.spec("running")).await;
        let row = s.claim().await;
        s.changed(JobRequest::PurgeOwner("owner-b".into())).await;
        s.complete(&row, json!("late handler output")).await;
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::Purged);
        assert!(row.output.is_none() && row.payload.is_none());
    }

    /// Case 20: superseded claims cannot checkpoint, heartbeat or complete.
    pub async fn jobs_case_20_claim_generation_fencing(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        let id = s.insert(s.spec("fencing")).await;
        let first = s.claim().await;
        s.op(JobRequest::Checkpoint {
            job: id.clone(),
            generation: first.generation,
            bytes: b"session".to_vec(),
        })
        .await
        .unwrap();
        s.advance(31);
        let second = s.claim().await;
        assert_eq!(second.id, id);
        assert!(second.generation > first.generation);
        assert_eq!(second.checkpoint, Some(b"session".to_vec()));
        for req in [
            JobRequest::Checkpoint {
                job: id.clone(),
                generation: first.generation,
                bytes: b"old".to_vec(),
            },
            JobRequest::Heartbeat {
                job: id.clone(),
                generation: first.generation,
            },
            JobRequest::Complete {
                job: id.clone(),
                generation: first.generation,
                state: JobState::Succeeded,
                origin: ResultOrigin::Handler,
                output: Some(json!("old")),
                receipt: None,
                diagnostic: None,
            },
        ] {
            assert!(matches!(s.op(req).await, Err(JobError::StaleClaim)));
        }
        s.complete(&second, json!("new")).await;
        assert_eq!(s.get(&id).await.output, Some(json!("new")));
    }

    /// Batch conflicts and capacity errors roll back inserted jobs and summaries.
    pub async fn jobs_atomic_batch_key_conflicts_and_byte_bounds(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        let existing = s.insert(s.spec("key")).await;
        let mut conflict = s.spec("key");
        conflict.payload = json!("different");
        assert!(matches!(
            s.op(JobRequest::Enqueue(vec![s.spec("new"), conflict]))
                .await,
            Err(JobError::KeyConflict)
        ));
        assert_eq!(
            s.summary(false).await.counts.get(&JobState::Pending),
            Some(&1)
        );
        assert!(matches!(
            s.enqueue(vec![s.spec("new")]).await[0],
            Enqueued::Inserted(_)
        ));
        s.config.max_pending_bytes = 1;
        assert!(matches!(
            s.op(JobRequest::Enqueue(vec![s.spec("bytes")])).await,
            Err(JobError::QueueFull)
        ));
        assert!(matches!(
            s.enqueue(vec![s.spec("key")]).await[0],
            Enqueued::Joined(_)
        ));
        assert_eq!(s.get(&existing).await.max_attempts, 3);
        let mut duplicate = s.spec("duplicate");
        duplicate.payload = json!("same");
        let mut conflict = duplicate.clone();
        conflict.payload = json!("other");
        s.config.max_pending_bytes = 100_000;
        assert!(matches!(
            s.op(JobRequest::Enqueue(vec![duplicate.clone(), conflict]))
                .await,
            Err(JobError::KeyConflict)
        ));
        assert!(matches!(
            s.enqueue(vec![duplicate]).await[0],
            Enqueued::Inserted(_)
        ));
        assert_eq!(s.summary(false).await, s.summary(true).await);
    }

    /// Pending cancellation deletes input; running cancellation keeps the completed answer.
    pub async fn jobs_cancel_and_result_origins(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let waiting = s.insert(s.spec("waiting")).await;
        assert_eq!(
            s.changed(JobRequest::Cancel(Selector::Ids(vec![waiting.clone()])))
                .await,
            1
        );
        assert!(s.get(&waiting).await.payload.is_none());
        let running = s.insert(s.spec("running")).await;
        let row = s.claim().await;
        assert_eq!(
            s.changed(JobRequest::Cancel(Selector::Group("group".into())))
                .await,
            1
        );
        assert!(s.get(&running).await.cancel_requested);
        s.complete(&row, json!("answer retained")).await;
        let row = s.get(&running).await;
        assert_eq!(row.state, JobState::Cancelled);
        assert_eq!(row.output, Some(json!("answer retained")));
        assert_eq!(row.origin, Some(ResultOrigin::Handler));
        assert!(row.receipt.is_none());
        let mut paid = s.spec("paid");
        paid.execution = Execution::Model;
        let id = s.insert(paid).await;
        let row = s.claim().await;
        assert!(matches!(
            s.op(JobRequest::Complete {
                job: id.clone(),
                generation: row.generation,
                state: JobState::Succeeded,
                origin: ResultOrigin::Paid,
                output: Some(json!("duplicated ledger output")),
                receipt: Some("receipt".into()),
                diagnostic: None
            })
            .await,
            Err(JobError::InvalidRequest)
        ));
        s.op(JobRequest::Complete {
            job: id.clone(),
            generation: row.generation,
            state: JobState::Succeeded,
            origin: ResultOrigin::Paid,
            output: None,
            receipt: Some("receipt".into()),
            diagnostic: None,
        })
        .await
        .unwrap();
        let row = s.get(&id).await;
        assert_eq!(row.origin, Some(ResultOrigin::Paid));
        assert_eq!(row.receipt.as_deref(), Some("receipt"));
    }

    /// Expired handler claims can be cancelled/erased without stranding unfinished rows.
    pub async fn jobs_expired_handler_cancel_and_purge(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        for purge in [false, true] {
            let id = s
                .insert(s.spec(if purge {
                    "erase-expired"
                } else {
                    "cancel-expired"
                }))
                .await;
            let claimed = s.claim().await;
            s.advance(31);
            if purge {
                s.changed(JobRequest::PurgeOwner("owner-a".into())).await;
            } else {
                s.changed(JobRequest::Cancel(Selector::Ids(vec![id.clone()])))
                    .await;
            }
            let row = s.get(&id).await;
            assert_eq!(
                row.state,
                if purge {
                    JobState::Purged
                } else {
                    JobState::Cancelled
                }
            );
            assert!(row.payload.is_none());
            assert!(matches!(
                s.op(JobRequest::Checkpoint {
                    job: id,
                    generation: claimed.generation,
                    bytes: vec![1]
                })
                .await,
                Err(JobError::StaleClaim)
            ));
        }
        for purge in [false, true] {
            let id = s
                .insert(s.spec(if purge {
                    "erase-before-expiry"
                } else {
                    "cancel-before-expiry"
                }))
                .await;
            s.claim().await;
            if purge {
                s.changed(JobRequest::PurgeOwner("owner-a".into())).await;
            } else {
                s.changed(JobRequest::Cancel(Selector::Ids(vec![id.clone()])))
                    .await;
            }
            s.advance(31);
            assert!(matches!(
                s.op(JobRequest::Claim {
                    kinds: vec!["handler".into()],
                    slots_available: 1,
                    background_in_flight: 0,
                })
                .await
                .unwrap(),
                JobResponse::Job(None)
            ));
            assert_eq!(
                s.get(&id).await.state,
                if purge {
                    JobState::Purged
                } else {
                    JobState::Cancelled
                }
            );
        }
        let mut paid = s.spec("paid-expired-cancel");
        paid.execution = Execution::Model;
        let id = s.insert(paid).await;
        s.claim().await;
        s.advance(31);
        s.changed(JobRequest::Cancel(Selector::Ids(vec![id.clone()])))
            .await;
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::Running);
        assert!(row.cancel_requested && row.payload.is_some());
    }

    /// Cache hits cannot follow paid claims; unpaid origins cannot invent receipt accounting.
    pub async fn jobs_result_origin_contracts(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let id = s.insert(s.spec("origin-contract")).await;
        let row = s.claim().await;
        for (origin, generation, output, receipt) in [
            (
                ResultOrigin::Cache,
                row.generation,
                Some(json!("late cache")),
                None,
            ),
            (
                ResultOrigin::Handler,
                row.generation,
                Some(json!("handler")),
                Some("fake-receipt".into()),
            ),
            (ResultOrigin::Handler, row.generation, None, None),
        ] {
            assert!(matches!(
                s.op(JobRequest::Complete {
                    job: id.clone(),
                    generation,
                    state: JobState::Succeeded,
                    origin,
                    output,
                    receipt,
                    diagnostic: None,
                })
                .await,
                Err(JobError::InvalidRequest)
            ));
            assert_eq!(s.get(&id).await.state, JobState::Running);
        }
        s.complete(&row, Value::Null).await;
    }

    /// Diagnostics paginate without omissions and summaries track oldest pending.
    pub async fn jobs_diagnostics_and_summary_rebuild(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        for i in 0..5 {
            let mut spec = s.spec(&format!("notice-{i}"));
            spec.admission = Some(s.admission(1, s.now - Duration::seconds(1)));
            s.insert(spec).await;
        }
        let mut ids = Vec::new();
        let mut after = None;
        loop {
            let page = match s
                .op(JobRequest::Diagnostics {
                    group: "group".into(),
                    after,
                    limit: 2,
                })
                .await
                .unwrap()
            {
                JobResponse::Diagnostics(page) => page,
                other => panic!("{other:?}"),
            };
            if page.items.is_empty() {
                break;
            }
            assert!(page.items.len() <= 2);
            ids.extend(page.items.iter().map(|d| d.id.id.clone()));
            after = page.after;
        }
        assert_eq!(ids.len(), 5);
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        let id = s.insert(s.spec("oldest")).await;
        assert_eq!(s.summary(false).await.oldest_pending, Some(s.now));
        s.changed(JobRequest::Cancel(Selector::Ids(vec![id]))).await;
        assert_eq!(s.summary(false).await.oldest_pending, None);
        assert_eq!(s.summary(false).await, s.summary(true).await);
    }

    /// FIFO, strict classes and the minimum background share are per-app settings.
    pub async fn jobs_priority_policy_and_frozen_admissions(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        let mut untagged = serde_json::to_value(s.spec("untagged")).unwrap();
        untagged.as_object_mut().unwrap().remove("priority");
        assert_eq!(
            serde_json::from_value::<JobSpec>(untagged)
                .unwrap()
                .priority,
            Priority::Background
        );
        let mut interactive = s.spec("interactive");
        interactive.priority = Priority::Interactive;
        let interactive = s.insert(interactive).await;
        s.advance(1);
        let background = s.insert(s.spec("background")).await;
        s.advance(1);
        let extra_background = s.insert(s.spec("more-background")).await;
        assert_eq!(s.claim().await.id, background); // reserved background slot
        s.background_in_flight = 1; // supplied by the existing account slot owner
        assert_eq!(s.claim().await.id, interactive); // now interactive wins despite another background waiter
        assert_eq!(s.claim().await.id, extra_background);
        let mut admission = s.spec("admission");
        admission.admission = Some(s.admission(1, s.now - Duration::seconds(1)));
        let id = s.insert(admission).await;
        let mut changed = s.admission(2, s.now + Duration::seconds(100));
        changed.binding.revision.0 = "changed".into();
        assert!(matches!(
            s.op(JobRequest::Admit {
                job: id.clone(),
                admission: changed
            })
            .await,
            Err(JobError::InvalidRequest)
        ));
        s.op(JobRequest::Admit {
            job: id.clone(),
            admission: s.admission(2, s.now + Duration::seconds(100)),
        })
        .await
        .unwrap();
        assert_eq!(s.get(&id).await.max_attempts, 3);
        s.config.priority = PriorityPolicy::StrictClasses;
        let mut interactive = s.spec("strict");
        interactive.priority = Priority::Interactive;
        let interactive = s.insert(interactive).await;
        assert_eq!(s.claim().await.id, interactive);
        s.config.priority = PriorityPolicy::Fifo;
        assert_eq!(s.claim().await.id, id);
    }

    /// An oversized later item fails the whole call and rolls back earlier leases.
    pub async fn jobs_oversized_later_completion_rolls_back_page(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        let first = s.ready("small").await;
        s.advance(1);
        let second = s.insert(s.spec("large-second")).await;
        let row = s.claim().await;
        s.complete(&row, json!("x".repeat(5000))).await;
        assert!(
            matches!(s.op(JobRequest::Completions { limit: 2, max_bytes: 2500 }).await,
            Err(JobError::CompletionTooLarge { job, .. }) if job == second)
        );
        for id in [&first, &second] {
            let row = s.get(id).await;
            assert_eq!(row.delivery_generation, 0);
            assert!(row.delivery_until.is_none());
        }
    }

    /// Retained metadata, successor envelopes and checkpoints share one hard byte bound.
    pub async fn jobs_pending_metadata_and_checkpoint_share_bound(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        s.config.max_pending_bytes = 500;
        let mut spec = s.spec("metadata");
        spec.owners = vec!["owner".repeat(1000)];
        assert!(matches!(
            s.op(JobRequest::Enqueue(vec![spec])).await,
            Err(JobError::QueueFull)
        ));
        s.config.max_pending_bytes = 100_000;
        let mut checkpoint = s.spec("checkpoint\n鍵");
        checkpoint.payload = json!({"content":"é🦀\n\"", "number":1.2e20, "decimal":0.1});
        let id = s.insert(checkpoint).await;
        let row = s.claim().await;
        let usage = match s.op(JobRequest::PendingUsage).await.unwrap() {
            JobResponse::Usage(usage) => usage,
            other => panic!("{other:?}"),
        };
        assert_eq!(usage.bytes, job_input_bytes(&row).unwrap());
        s.config.max_pending_bytes = usage.bytes + 1;
        assert!(matches!(
            s.op(JobRequest::Checkpoint {
                job: id.clone(),
                generation: row.generation,
                bytes: vec![1; 100]
            })
            .await,
            Err(JobError::QueueFull)
        ));
        assert!(s.get(&id).await.checkpoint.is_none());
        // Successor admission growth uses the same bound, rather than bypassing it.
        s.config.max_pending_bytes = 100_000;
        let mut spec = s.spec("envelope");
        spec.admission = Some(s.admission(1, s.now - Duration::seconds(1)));
        let id = s.insert(spec).await;
        let mut successor = s.admission(2, s.now + Duration::seconds(100));
        successor.signed = vec![1; 1000];
        let usage = match s.op(JobRequest::PendingUsage).await.unwrap() {
            JobResponse::Usage(usage) => usage,
            other => panic!("{other:?}"),
        };
        s.config.max_pending_bytes = usage.bytes;
        assert!(matches!(
            s.op(JobRequest::Admit {
                job: id.clone(),
                admission: successor
            })
            .await,
            Err(JobError::QueueFull)
        ));
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::AwaitingAdmission);
        assert_eq!(row.admission.unwrap().ordinal, 1);
    }

    /// Invalid policy/page/lease values fail before writes, and expired claims are fenced.
    pub async fn jobs_invalid_bounds_and_leases_leave_store_usable(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        let id = s.insert(s.spec("invalid")).await;
        s.config.claim_lease_seconds = u64::MAX;
        assert!(matches!(
            s.op(JobRequest::Claim {
                kinds: vec!["handler".into()],
                slots_available: 1,
                background_in_flight: 0
            })
            .await,
            Err(JobError::InvalidRequest)
        ));
        s.config.claim_lease_seconds = 30;
        assert_eq!(s.get(&id).await.attempt(), 0);
        for (limit, max_bytes) in [(0, 1000), (65, 1000), (1, 1), (1, usize::MAX)] {
            assert!(matches!(
                s.op(JobRequest::Completions { limit, max_bytes }).await,
                Err(JobError::InvalidRequest)
            ));
        }
        let row = s.claim().await;
        assert!(matches!(
            s.op(JobRequest::Checkpoint {
                job: id.clone(),
                generation: row.generation,
                bytes: vec![0; s.config.max_checkpoint_bytes + 1]
            })
            .await,
            Err(JobError::InvalidRequest)
        ));
        s.advance(31);
        assert!(matches!(
            s.op(JobRequest::Checkpoint {
                job: id.clone(),
                generation: row.generation,
                bytes: vec![0]
            })
            .await,
            Err(JobError::StaleClaim)
        ));
        // Paid expired leases cannot be reclaimed just because the account has capacity.
        s.complete(&s.claim().await, json!("handler recovered"))
            .await;
        let mut paid = s.spec("paid-lease");
        paid.execution = Execution::Model;
        let id = s.insert(paid).await;
        let row = s.claim().await;
        s.advance(31);
        assert!(matches!(
            s.op(JobRequest::Claim {
                kinds: vec!["handler".into()],
                slots_available: 4,
                background_in_flight: 0
            })
            .await
            .unwrap(),
            JobResponse::Job(None)
        ));
        assert_eq!(s.get(&id).await.generation, row.generation);
        assert!(s.get(&id).await.payload.is_some());
    }

    /// Inspection is bounded and read-only; handoff claims the same ID and checks admission.
    pub async fn jobs_candidate_claim_and_grant_invalidation(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let mut spec = s.spec("candidate");
        spec.admission = Some(s.admission(1, s.now + Duration::seconds(100)));
        let id = s.insert(spec).await;
        match s
            .op(JobRequest::Candidates {
                kinds: vec!["handler".into()],
                background_in_flight: 0,
                limit: 1,
                max_bytes: 100_000,
            })
            .await
            .unwrap()
        {
            JobResponse::Candidates(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].id, id);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(s.get(&id).await.attempt(), 0);
        assert!(
            matches!(s.op(JobRequest::Candidates { kinds: vec!["handler".into()], background_in_flight: 0,
            limit: 1, max_bytes: 100 }).await, Err(JobError::CandidateTooLarge { job, .. }) if job == id)
        );
        // A changed grant must be handled before transport, without a paid attempt.
        s.op(JobRequest::AwaitAdmission(id.clone())).await.unwrap();
        let row = s.get(&id).await;
        assert_eq!(row.attempt(), 0);
        assert_eq!(row.state, JobState::AwaitingAdmission);
        s.op(JobRequest::Admit {
            job: id.clone(),
            admission: s.admission(2, s.now + Duration::seconds(100)),
        })
        .await
        .unwrap();
        let row = match s.op(JobRequest::ClaimJob(id.clone())).await.unwrap() {
            JobResponse::Job(Some(row)) => row,
            other => panic!("{other:?}"),
        };
        assert_eq!(row.id, id);
        assert_eq!(row.attempt(), 1);
        assert!(matches!(
            s.op(JobRequest::ClaimJob(id)).await.unwrap(),
            JobResponse::Job(None)
        ));
    }

    /// A mixed final/notice ack batch or foreign selector cannot partly commit.
    pub async fn jobs_ack_and_cancel_batches_roll_back(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let id = s.ready("final").await;
        let token = s.deliveries(1, 100_000).await.remove(0).token.unwrap();
        let mut notice = s.spec("notice");
        notice.admission = Some(s.admission(1, s.now));
        let notice = s.insert(notice).await;
        assert!(matches!(
            s.op(JobRequest::Ack(vec![
                (token.clone(), Disposition::Accepted),
                (
                    DeliveryToken {
                        job: notice.clone(),
                        generation: 1
                    },
                    Disposition::Discarded
                )
            ]))
            .await,
            Err(JobError::NotFinal)
        ));
        assert_eq!(s.get(&id).await.state, JobState::Succeeded);
        assert_eq!(
            s.summary(false).await.counts.get(&JobState::Succeeded),
            Some(&1)
        );
        let mut foreign = notice.clone();
        foreign.scope.incarnation = "foreign".into();
        assert!(matches!(
            s.op(JobRequest::Cancel(Selector::Ids(vec![
                notice.clone(),
                foreign
            ])))
            .await,
            Err(JobError::Scope)
        ));
        assert_eq!(s.get(&notice).await.state, JobState::AwaitingAdmission);
        assert_eq!(
            s.ack(token, Disposition::Accepted).await,
            AckResult::Acked(Disposition::Accepted)
        );
    }

    /// Paid recovery is explicit, fenced and cannot be converted to an automatic retry.
    pub async fn jobs_paid_reconciliation_requires_explicit_evidence(
        backend: Arc<dyn QueueBackend>,
    ) {
        let mut s = Suite::new(backend);
        let mut spec = s.spec("paid-recovery");
        spec.execution = Execution::Model;
        spec.recovery_until = Some(s.now - Duration::seconds(1));
        let id = s.insert(spec).await;
        let first = s.claim().await;
        s.advance(31);
        s.op(JobRequest::Resolve {
            job: id.clone(),
            generation: first.generation,
            resolution: JobResolution::Uncertain {
                receipt: "receipt-1".into(),
            },
        })
        .await
        .unwrap();
        assert_eq!(s.get(&id).await.state, JobState::Uncertain);
        assert!(s.get(&id).await.payload.is_some());
        assert!(matches!(
            s.op(JobRequest::ClaimJob(id.clone())).await.unwrap(),
            JobResponse::Job(None)
        ));
        s.op(JobRequest::Resolve {
            job: id.clone(),
            generation: first.generation,
            resolution: JobResolution::KnownZeroCharge {
                receipt: "receipt-1".into(),
            },
        })
        .await
        .unwrap();
        let second = s.claim().await;
        assert_eq!(second.attempt(), 2);
        assert!(matches!(
            s.op(JobRequest::Resolve {
                job: id.clone(),
                generation: first.generation,
                resolution: JobResolution::PaidResult {
                    receipt: "stale".into(),
                    recovery_until: None
                }
            })
            .await,
            Err(JobError::StaleClaim)
        ));
        s.op(JobRequest::Resolve {
            job: id.clone(),
            generation: second.generation,
            resolution: JobResolution::PaidResult {
                receipt: "receipt-2".into(),
                recovery_until: None,
            },
        })
        .await
        .unwrap();
        let row = s.get(&id).await;
        assert_eq!(row.state, JobState::Succeeded);
        assert!(row.result_expired && row.payload.is_none() && row.output.is_none());
        assert_eq!(row.receipt.as_deref(), Some("receipt-2"));
        // A committed direct-call result is recovered without a new admission or claim.
        let mut spec = s.spec("direct");
        spec.execution = Execution::Model;
        spec.admission = Some(s.admission(1, s.now));
        let id = s.insert(spec).await;
        s.op(JobRequest::Resolve {
            job: id.clone(),
            generation: 0,
            resolution: JobResolution::PaidResult {
                receipt: "direct-receipt".into(),
                recovery_until: Some(s.now + Duration::seconds(60)),
            },
        })
        .await
        .unwrap();
        let row = s.get(&id).await;
        assert_eq!(row.attempt(), 0);
        assert_eq!(row.state, JobState::Succeeded);
        assert_eq!(row.origin, Some(ResultOrigin::Paid));
    }

    /// A valid JSON null remains distinct from an erased waiting copy or missing answer.
    pub async fn jobs_null_payload_and_result_round_trip(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let mut spec = s.spec("null");
        spec.payload = Value::Null;
        let id = s.insert(spec).await;
        let row = s.get(&id).await;
        let recovered: JobRecord =
            serde_json::from_value(serde_json::to_value(&row).unwrap()).unwrap();
        assert_eq!(recovered.payload, Some(Value::Null));
        let row = s.claim().await;
        s.complete(&row, Value::Null).await;
        let delivery = s.deliveries(1, 100_000).await.remove(0);
        let recovered: Delivery =
            serde_json::from_value(serde_json::to_value(&delivery).unwrap()).unwrap();
        assert_eq!(recovered.completion.output, Some(Value::Null));
        assert!(recovered.completion.payload.is_none());
        s.ack(recovered.token.unwrap(), Disposition::Accepted).await;
        let row = s.get(&id).await;
        assert!(row.payload.is_none() && row.output.is_none());
    }

    /// Unknown operational metadata is rejected; arbitrary business payload fields are valid.
    pub async fn jobs_unknown_metadata_is_refused(backend: Arc<dyn QueueBackend>) {
        let s = Suite::new(backend);
        let mut spec = serde_json::to_value(s.spec("metadata-typo")).unwrap();
        spec.as_object_mut()
            .unwrap()
            .insert("recovery_untl".into(), serde_json::to_value(s.now).unwrap());
        assert!(serde_json::from_value::<JobSpec>(spec).is_err());
        let mut config = serde_json::to_value(&s.config).unwrap();
        config
            .as_object_mut()
            .unwrap()
            .insert("max_pendng_items".into(), json!(1));
        assert!(serde_json::from_value::<JobConfig>(config).is_err());
        let mut spec = s.spec("business-data");
        spec.payload = json!({"arbitrary_business_field":null});
        s.insert(spec).await;
    }

    /// Byte-bounded completion pages defer the next row without leasing it.
    pub async fn jobs_completion_page_byte_bound_is_exact(backend: Arc<dyn QueueBackend>) {
        let mut s = Suite::new(backend);
        let first = s.ready("first").await;
        s.advance(1);
        let second = s.ready("second").await;
        let deliveries = s.deliveries(2, 100_000).await;
        let first_size = deliveries
            .iter()
            .map(|d| serde_json::to_vec(&vec![d.clone()]).unwrap().len())
            .max()
            .unwrap();
        s.advance(31);
        let page = s.deliveries(2, first_size).await;
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].completion.id, first);
        assert!(serde_json::to_vec(&page).unwrap().len() <= first_size);
        assert_eq!(s.get(&second).await.delivery_generation, 1);
        s.ack(page[0].token.clone().unwrap(), Disposition::Accepted)
            .await;
        assert_eq!(s.deliveries(1, 100_000).await[0].completion.id, second);
    }
}

/// Instantiate exactly the same job-store acceptance suite for a backend.
#[macro_export]
macro_rules! job_backend_conformance {
    ($make:expr) => {
        $crate::job_backend_conformance!(@tests $make;
            jobs_case_4_delivery_lease_expires_first_confirm_wins,
            jobs_case_5_accepted_discarded_status,
            jobs_case_6_backlog_bounds_and_maintenance,
            jobs_case_8_recovery_expiry_is_not_execution_expiry,
            jobs_case_9_oversized_completion_is_visible,
            jobs_case_10_notices_never_starve_finals,
            jobs_case_11_foreign_scope_refused_before_access,
            jobs_case_12_cache_owner_purge_fences_result_commit,
            jobs_case_20_claim_generation_fencing,
            jobs_atomic_batch_key_conflicts_and_byte_bounds,
            jobs_cancel_and_result_origins,
            jobs_result_origin_contracts,
            jobs_expired_handler_cancel_and_purge,
            jobs_diagnostics_and_summary_rebuild,
            jobs_priority_policy_and_frozen_admissions,
            jobs_oversized_later_completion_rolls_back_page,
            jobs_pending_metadata_and_checkpoint_share_bound,
            jobs_invalid_bounds_and_leases_leave_store_usable,
            jobs_candidate_claim_and_grant_invalidation,
            jobs_ack_and_cancel_batches_roll_back,
            jobs_paid_reconciliation_requires_explicit_evidence,
            jobs_null_payload_and_result_round_trip,
            jobs_unknown_metadata_is_refused,
            jobs_completion_page_byte_bound_is_exact
        );
    };
    (@tests $make:expr; $($check:ident),+ $(,)?) => {
        $(#[tokio::test]
        async fn $check() {
            let make: fn() -> ::std::sync::Arc<dyn $crate::QueueBackend> = $make;
            $crate::conformance::jobs::$check(make()).await;
        })+
    };
}
