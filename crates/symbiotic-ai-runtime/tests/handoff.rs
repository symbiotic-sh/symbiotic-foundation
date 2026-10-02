use rusqlite::{Connection, TransactionBehavior};
use std::path::Path;
use symbiotic_ai_runtime::{
    AcceptedSpendHandoff, SpendLedger, SpendReceiptRef, SpendReservation, SpendState,
    spend::SqliteSpendLedger,
};

use std::sync::{Arc, Barrier};

fn accepted(path: &Path) -> AcceptedSpendHandoff {
    symbiotic_queue_sqlite::SqliteQueue::open(path).unwrap();
    let handoff = AcceptedSpendHandoff {
        reservation: SpendReservation {
            reference: SpendReceiptRef("accepted:attempt-1".into()),
            account: "account-a".into(),
            invocation: "invocation-1".into(),
            binding: "exact-attempt-1".into(),
            request_limit: Some(1),
        },
        input_identity: "exact-input-1".into(),
    };
    let mut conn = Connection::open(path).unwrap();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(SqliteSpendLedger::reserve_handoff_in(&tx, &handoff).unwrap());
    tx.commit().unwrap();
    handoff
}

#[test]
fn accepted_handoff_refuses_other_accounts_attempts_and_inputs_before_consuming() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let handoff = accepted(&path);
    let ledger = SqliteSpendLedger::open(&path).unwrap();
    assert!(
        ledger
            .acquire_handoff(&handoff, "account-b", "exact-input-1", "owner")
            .is_err()
    );
    assert!(
        ledger
            .acquire_handoff(&handoff, "account-a", "other-input", "owner")
            .is_err()
    );
    let mut changed = handoff.clone();
    changed.reservation.binding = "other-attempt".into();
    assert!(
        ledger
            .acquire_handoff(&changed, "account-a", "exact-input-1", "owner")
            .is_err()
    );
    changed = handoff.clone();
    changed.reservation.invocation = "other-invocation".into();
    assert!(
        ledger
            .acquire_handoff(&changed, "account-a", "exact-input-1", "owner")
            .is_err()
    );
    changed = handoff.clone();
    changed.input_identity = "forged-input".into();
    assert!(
        ledger
            .acquire_handoff(&changed, "account-a", "forged-input", "owner")
            .is_err()
    );
    ledger
        .acquire_handoff(&handoff, "account-a", "exact-input-1", "owner")
        .unwrap();
    assert!(
        ledger
            .acquire_handoff(&handoff, "account-a", "exact-input-1", "owner")
            .is_err()
    );
}

#[test]
fn accepted_handoff_has_one_atomic_dispatch_owner_across_handles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let handoff = accepted(&path);
    let barrier = Arc::new(Barrier::new(2));
    let joins: Vec<_> = (0..2)
        .map(|i| {
            let ledger = SqliteSpendLedger::open(&path).unwrap();
            let handoff = handoff.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                ledger
                    .acquire_handoff(
                        &handoff,
                        "account-a",
                        "exact-input-1",
                        &format!("owner-{i}"),
                    )
                    .is_ok()
            })
        })
        .collect();
    assert_eq!(
        joins
            .into_iter()
            .map(|join| usize::from(join.join().unwrap()))
            .sum::<usize>(),
        1
    );
    let ledger = SqliteSpendLedger::open(&path).unwrap();
    assert_eq!(
        ledger
            .receipt(&handoff.reservation.reference)
            .unwrap()
            .unwrap()
            .state,
        SpendState::Unknown
    );
    assert!(
        ledger
            .acquire_handoff(&handoff, "account-a", "exact-input-1", "after-restart")
            .is_err()
    );
}

#[test]
fn ordinary_or_released_reservations_do_not_authorize_an_accepted_handoff() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let handoff = accepted(&path);
    let ledger = SqliteSpendLedger::open(&path).unwrap();
    ledger
        .finish(
            &handoff.reservation.reference,
            SpendState::Released,
            None,
            None,
        )
        .unwrap();
    assert!(
        ledger
            .acquire_handoff(&handoff, "account-a", "exact-input-1", "owner")
            .is_err()
    );
    let mut ordinary = handoff;
    ordinary.reservation.reference = SpendReceiptRef("ordinary".into());
    ordinary.reservation.invocation = "ordinary".into();
    ledger.reserve(&ordinary.reservation).unwrap();
    assert!(
        ledger
            .acquire_handoff(&ordinary, "account-a", "exact-input-1", "owner")
            .is_err()
    );
}

#[test]
fn handoff_reservation_rejects_changed_binding_after_release_and_changed_reattachment_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let first = accepted(&path);
    let mut changed = first.clone();
    changed.input_identity = "changed-input".into();
    let mut conn = Connection::open(&path).unwrap();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(SqliteSpendLedger::reserve_handoff_in(&tx, &changed).is_err());
    drop(tx);
    let ledger = SqliteSpendLedger::open(&path).unwrap();
    ledger
        .finish(
            &first.reservation.reference,
            SpendState::Released,
            None,
            None,
        )
        .unwrap();
    changed.reservation.reference = SpendReceiptRef("next-attempt".into());
    changed.reservation.binding = "changed-binding".into();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(SqliteSpendLedger::reserve_handoff_in(&tx, &changed).is_err());
    drop(tx);
    changed = first;
    changed.reservation.reference = SpendReceiptRef("next-attempt".into());
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(SqliteSpendLedger::reserve_handoff_in(&tx, &changed).unwrap());
    tx.commit().unwrap();
}
