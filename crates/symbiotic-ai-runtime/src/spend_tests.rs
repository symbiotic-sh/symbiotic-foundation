use crate::spend::SqliteSpendLedger;
use rusqlite::params;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use symbiotic_model::{SpendLedger, SpendReceiptRef, SpendReservation, SpendState};
use symbiotic_trace::UsageTrace;

fn reservation(id: &str) -> SpendReservation {
    SpendReservation {
        reference: SpendReceiptRef::new(id).unwrap(),
        account: "account".into(),
        invocation: "invocation".into(),
        binding: "binding".into(),
        request_limit: None,
    }
}

fn steps(history: usize, explicit: bool) -> Vec<usize> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.sqlite");
    symbiotic_queue_sqlite::SqliteQueue::open(&path).unwrap();
    let ledger = SqliteSpendLedger::open(&path)
        .unwrap()
        .with_retention(std::time::Duration::ZERO);
    {
        let mut conn = ledger.0.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute(
            "INSERT INTO spend_accounts(account,used) VALUES ('account',?1)",
            [if explicit { 0 } else { history }],
        )
        .unwrap();
        for n in 0..history {
            let r = reservation(&format!("runtime:old-item-{n}:1"));
            tx.execute("INSERT INTO spend_receipts(reference, account, invocation, binding, reservation, state, output, pre_dispatch_released, attempt_limit, attempts_used) VALUES (?1,'account','invocation','binding',?2,?3,?4,?5,?6,0)",
                params![r.reference.as_str(), serde_json::to_string(&r).unwrap(), if explicit { "released" } else { "settled" },
                    (!explicit).then_some("{\"output_received\":true}"), explicit, explicit.then_some(3)]).unwrap();
        }
        tx.commit().unwrap();
    }
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    ledger.0.lock().unwrap().progress_handler(
        1,
        Some(move || {
            c.fetch_add(1, Ordering::Relaxed);
            false
        }),
    );
    let mut result = Vec::new();
    let r = reservation("runtime:current:1");
    if explicit {
        ledger.reserve_explicit(&r, 3).unwrap();
    } else {
        ledger.reserve(&r).unwrap();
    }
    result.push(count.swap(0, Ordering::Relaxed));
    ledger
        .finish(
            &r.reference,
            SpendState::Settled,
            Some(UsageTrace {
                input_tokens: Some(7),
                ..Default::default()
            }),
            Some(serde_json::json!({"answer":"private"})),
        )
        .unwrap();
    result.push(count.swap(0, Ordering::Relaxed));
    ledger.invocation("account", "invocation").unwrap();
    result.push(count.swap(0, Ordering::Relaxed));
    ledger.receipt(&r.reference).unwrap();
    result.push(count.swap(0, Ordering::Relaxed));
    // Implicit counting uses only the current item's bounded claim keys.
    for claim in 1..=3 {
        ledger
            .receipt(&SpendReceiptRef::new(format!("runtime:current:{claim}")).unwrap())
            .unwrap();
    }
    result.push(count.swap(0, Ordering::Relaxed));
    assert_eq!(ledger.expire_recovery().unwrap(), usize::from(explicit));
    result.push(count.swap(0, Ordering::Relaxed));
    ledger.discard_recovery("account", "invocation").unwrap();
    result.push(count.swap(0, Ordering::Relaxed));
    result
}

#[test]
fn request_and_expiry_work_is_independent_of_retained_history() {
    for explicit in [false, true] {
        let small = steps(10, explicit);
        let large = steps(10_000, explicit);
        eprintln!("explicit={explicit}: VM steps at 10 receipts={small:?}, at 10,000={large:?}");
        for (operation, (small, large)) in small.iter().zip(&large).enumerate() {
            assert!(
                *large <= small + 20,
                "explicit={explicit}, operation={operation}: {small} -> {large}"
            );
        }
    }
}
