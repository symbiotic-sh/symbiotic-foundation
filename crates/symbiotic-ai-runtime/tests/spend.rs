//! Accounting gates against multiple handles to the real operational database.
use std::sync::{Arc, Barrier};
use symbiotic_ai_runtime::{
    ModelError, SpendLedger, SpendReceiptRef, SpendReservation, SpendState,
    spend::SqliteSpendLedger,
};
use symbiotic_core::DiagnosticCode;
use symbiotic_queue_sqlite::SqliteQueue;
use symbiotic_trace::UsageTrace;

fn reservation(id: &str, invocation: &str, account: &str) -> SpendReservation {
    SpendReservation {
        reference: SpendReceiptRef(id.into()),
        invocation: invocation.into(),
        account: account.into(),
        binding: invocation.into(),
        request_limit: Some(1),
    }
}
fn open(path: &std::path::Path) -> SqliteSpendLedger {
    SqliteQueue::open(path).unwrap();
    SqliteSpendLedger::open(path).unwrap()
}
#[test]
fn spend_crash_retains_unknown_and_refuses_a_second_attempt_until_reconciliation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.sqlite");
    let original = reservation("first", "invocation", "account");
    assert!(open(&path).reserve(&original).unwrap());
    // Drop every connection without settling: same durable state as a crashed worker.
    let ledger = open(&path);
    let receipt = ledger.receipt(&original.reference).unwrap().unwrap();
    assert_eq!(receipt.state, SpendState::Unknown);
    assert!(receipt.usage.is_none());
    assert!(!ledger.reserve(&original).unwrap());
    assert!(matches!(
        ledger.reserve(&reservation("replay", "invocation", "account")),
        Err(ModelError::Queue(
            DiagnosticCode::SpendReconciliationRequired
        ))
    ));
    assert!(matches!(
        ledger.reserve(&reservation("new", "new", "account")),
        Err(ModelError::BudgetExhausted(
            DiagnosticCode::SpendBudgetExhausted
        ))
    ));
    ledger
        .finish(&original.reference, SpendState::Released, None, None)
        .unwrap();
    let retry = reservation("retry", "invocation", "account");
    assert!(ledger.reserve(&retry).unwrap());
}
#[test]
fn spend_zero_charge_releases_and_success_settles_once_without_consumer_commit() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = open(&dir.path().join("queue.sqlite"));
    let failed = reservation("failed", "failure", "account");
    ledger.reserve(&failed).unwrap();
    ledger
        .finish(&failed.reference, SpendState::Released, None, None)
        .unwrap();
    ledger
        .finish(&failed.reference, SpendState::Released, None, None)
        .unwrap();
    let paid = reservation("paid", "success", "account");
    ledger.reserve(&paid).unwrap();
    let usage = UsageTrace {
        input_tokens: Some(7),
        reported_cost_usd: Some("0.0000123".into()),
        ..Default::default()
    };
    let output = serde_json::json!({"result": "paid output"});
    for _ in 0..2 {
        ledger
            .finish(
                &paid.reference,
                SpendState::Settled,
                Some(usage.clone()),
                Some(output.clone()),
            )
            .unwrap();
    }
    assert!(!ledger.reserve(&paid).unwrap());
    let receipt = ledger.receipt(&paid.reference).unwrap().unwrap();
    assert_eq!(receipt.usage.unwrap().input_tokens, Some(7));
    assert!(
        ledger
            .finish(&paid.reference, SpendState::Released, None, None)
            .is_err()
    );
    let over = reservation("over", "over", "account");
    assert!(ledger.reserve(&over).is_err());
    let isolated = reservation("isolated", "success", "other-account");
    assert!(ledger.reserve(&isolated).unwrap());
}
#[test]
fn spend_missing_usage_never_fabricates_zero_or_releases_successful_output() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = open(&dir.path().join("queue.sqlite"));
    let r = reservation("missing", "invocation", "account");
    ledger.reserve(&r).unwrap();
    ledger
        .finish(
            &r.reference,
            SpendState::Unknown,
            None,
            Some(serde_json::json!("output")),
        )
        .unwrap();
    assert!(
        ledger
            .finish(&r.reference, SpendState::Released, None, None)
            .is_err()
    );
    assert!(
        ledger
            .finish(&r.reference, SpendState::Settled, None, None)
            .is_err()
    );
    let another = reservation("another", "other", "account");
    assert!(ledger.reserve(&another).is_err());
    ledger
        .finish(
            &r.reference,
            SpendState::Settled,
            Some(UsageTrace {
                input_tokens: Some(0),
                ..Default::default()
            }),
            None,
        )
        .unwrap();
    assert_eq!(
        ledger.receipt(&r.reference).unwrap().unwrap().output,
        Some(serde_json::json!("output"))
    );
}
#[test]
fn spend_concurrent_reservations_across_handles_enforce_one_account_budget() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.sqlite");
    drop(open(&path));
    let barrier = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let ledger = open(&path);
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                ledger.reserve(&reservation(
                    &i.to_string(),
                    &i.to_string(),
                    "shared-account",
                ))
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| matches!(r, Ok(true))).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(
                r,
                Err(ModelError::BudgetExhausted(
                    DiagnosticCode::SpendBudgetExhausted
                ))
            ))
            .count(),
        3
    );
}

#[test]
fn spend_invocation_lookup_uses_an_index_for_retained_history_and_latest_release() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.sqlite");
    let ledger = open(&path);
    let first = reservation("first", "invocation", "account");
    ledger.reserve(&first).unwrap();
    ledger
        .finish(&first.reference, SpendState::Released, None, None)
        .unwrap();
    let latest = reservation("latest", "invocation", "account");
    ledger.reserve(&latest).unwrap();
    ledger
        .finish(&latest.reference, SpendState::Released, None, None)
        .unwrap();
    assert_eq!(
        ledger
            .invocation("account", "invocation")
            .unwrap()
            .unwrap()
            .reservation
            .reference,
        latest.reference
    );
    let conn = rusqlite::Connection::open(path).unwrap();
    let mut stmt = conn.prepare("EXPLAIN QUERY PLAN SELECT reference FROM spend_receipts WHERE account=?1 AND invocation=?2 ORDER BY rowid DESC LIMIT 1").unwrap();
    let plan = stmt
        .query_map(["account", "absent"], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" ");
    assert!(plan.contains("SEARCH spend_receipts"), "{plan}");
    assert!(
        !plan.contains("SCAN") && !plan.contains("TEMP B-TREE"),
        "{plan}"
    );
}

#[test]
fn spend_delayed_reservation_refuses_changed_inputs_after_predecessor_release() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.sqlite");
    let ledger = open(&path);
    let original = reservation("first", "invocation", "account");
    // Both callers observed no reservation before X's transaction won.
    assert!(
        ledger
            .invocation("account", "invocation")
            .unwrap()
            .is_none()
    );
    let delayed = open(&path);
    assert!(
        delayed
            .invocation("account", "invocation")
            .unwrap()
            .is_none()
    );
    ledger.reserve(&original).unwrap();
    ledger
        .finish(&original.reference, SpendState::Released, None, None)
        .unwrap();
    let mut changed = original.clone();
    changed.reference = SpendReceiptRef("delayed".into());
    changed.binding = "changed-input".into();
    assert!(matches!(
        delayed.reserve(&changed),
        Err(ModelError::Queue(
            DiagnosticCode::SpendReconciliationRequired
        ))
    ));
    assert!(delayed.receipt(&changed.reference).unwrap().is_none());
    changed.binding = original.binding;
    assert!(delayed.reserve(&changed).unwrap());
}

#[test]
fn spend_allowance_is_fixed_by_first_reservation_without_dropping_unknown_charge() {
    for first_limit in [None, Some(1)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let mut first = reservation("first", "first", "account");
        first.request_limit = first_limit;
        open(&path).reserve(&first).unwrap();
        let ledger = open(&path);
        let mut changed = reservation("changed", "changed", "account");
        changed.request_limit = if first_limit.is_none() { Some(1) } else { None };
        assert!(matches!(
            ledger.reserve(&changed),
            Err(ModelError::InvalidRequest(
                DiagnosticCode::InvalidConfiguration
            ))
        ));
        assert_eq!(
            ledger.receipt(&first.reference).unwrap().unwrap().state,
            SpendState::Unknown
        );
        assert!(ledger.receipt(&changed.reference).unwrap().is_none());
        assert_eq!(
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row("SELECT used FROM spend_accounts", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
