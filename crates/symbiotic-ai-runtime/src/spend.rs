//! SQLite accounting in Foundation's operational database, never a Memory store.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{path::Path, sync::Mutex};
use symbiotic_core::DiagnosticCode;
use symbiotic_model::{
    AcceptedSpendHandoff, ModelError, SpendLedger, SpendReceipt, SpendReceiptRef, SpendReservation,
    SpendState,
};
use symbiotic_trace::UsageTrace;

fn storage(_: impl std::fmt::Debug) -> ModelError {
    ModelError::Queue(DiagnosticCode::SpendLedgerUnavailable)
}
fn conflict() -> ModelError {
    ModelError::Queue(DiagnosticCode::SpendReconciliationRequired)
}
fn state_name(state: SpendState) -> &'static str {
    match state {
        SpendState::Unknown => "unknown",
        SpendState::Released => "released",
        SpendState::Settled => "settled",
    }
}

/// Ledger handle for the versioned queue database. Opens only current queue state.
pub struct SqliteSpendLedger(Mutex<Connection>);
impl SqliteSpendLedger {
    /// Open an already initialized Foundation queue database.
    pub fn open(path: &Path) -> Result<Self, ModelError> {
        let conn = Connection::open(path).map_err(storage)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
        conn.pragma_update(None, "fullfsync", true)
            .map_err(storage)?;
        // Validate the atomic queue format stamp without creating or migrating tables.
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(storage)?;
        if version != symbiotic_queue_sqlite::QUEUE_SCHEMA_VERSION {
            return Err(storage(()));
        }
        Ok(Self(Mutex::new(conn)))
    }

    /// Reserve inside the caller's immediate transaction (permit/replay acceptance).
    /// Returns false for authenticated reattachment to exactly the same reservation.
    pub fn reserve_in(
        conn: &rusqlite::Transaction<'_>,
        r: &SpendReservation,
    ) -> Result<bool, ModelError> {
        if let Some(old) = receipt_in(conn, &r.reference)? {
            return if old.reservation == *r {
                Ok(false)
            } else {
                Err(conflict())
            };
        }
        let cached: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM spend_cached_invocations WHERE account=?1 AND invocation=?2)",
            params![r.account, r.invocation], |row| row.get(0),
        ).map_err(storage)?;
        if cached {
            return Err(conflict());
        }
        let limit = r
            .request_limit
            .map(i64::try_from)
            .transpose()
            .map_err(storage)?;
        conn.execute(
            "INSERT OR IGNORE INTO spend_accounts(account, request_limit) VALUES (?1, ?2)",
            params![r.account, limit],
        )
        .map_err(storage)?;
        let configured: Option<i64> = conn
            .query_row(
                "SELECT request_limit FROM spend_accounts WHERE account=?1",
                [&r.account],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if configured != limit {
            return Err(ModelError::InvalidRequest(
                DiagnosticCode::InvalidConfiguration,
            ));
        }
        let active: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM spend_receipts WHERE account=?1 AND invocation=?2 AND state!='released')", params![r.account, r.invocation], |row| row.get(0)).map_err(storage)?;
        if active {
            return Err(conflict());
        }
        let changed = conn.execute("UPDATE spend_accounts SET used=used+1 WHERE account=?1 AND used<9223372036854775807 AND (request_limit IS NULL OR used<request_limit)", [&r.account]).map_err(storage)?;
        if changed != 1 {
            return Err(ModelError::BudgetExhausted(
                DiagnosticCode::SpendBudgetExhausted,
            ));
        }
        let json = serde_json::to_string(r).map_err(storage)?;
        conn.execute("INSERT INTO spend_receipts(reference, account, invocation, binding, reservation, state) VALUES (?1, ?2, ?3, ?4, ?5, 'unknown')", params![r.reference.0, r.account, r.invocation, r.binding, json]).map_err(storage)?;
        Ok(true)
    }

    /// Reserve a trusted handoff and its exact queued input in the permit transaction.
    pub fn reserve_handoff_in(
        conn: &rusqlite::Transaction<'_>,
        handoff: &AcceptedSpendHandoff,
    ) -> Result<bool, ModelError> {
        if handoff.input_identity.is_empty() {
            return Err(conflict());
        }
        if !Self::reserve_in(conn, &handoff.reservation)? {
            return Ok(false);
        }
        conn.execute(
            "UPDATE spend_receipts SET handoff_input=?2 WHERE reference=?1",
            params![handoff.reservation.reference.0, handoff.input_identity],
        )
        .map_err(storage)?;
        Ok(true)
    }

    /// Settle or reconcile in the same transaction as execution/recovery state.
    /// Repeating an identical settlement is harmless; conflicting evidence is refused.
    pub fn finish_in(
        conn: &rusqlite::Transaction<'_>,
        reference: &SpendReceiptRef,
        state: SpendState,
        usage: Option<UsageTrace>,
        output: Option<serde_json::Value>,
    ) -> Result<(), ModelError> {
        let old = receipt_in(conn, reference)?.ok_or_else(conflict)?;
        if (state == SpendState::Settled
            && usage
                .as_ref()
                .is_none_or(|u| !symbiotic_model::has_measured_usage(u)))
            || (state == SpendState::Released && (old.output.is_some() || output.is_some()))
        {
            return Err(conflict());
        }
        let output = output.or_else(|| old.output.clone());
        let usage = usage
            .map(|u| serde_json::to_string(&u))
            .transpose()
            .map_err(storage)?;
        let output = output
            .map(|o| serde_json::to_string(&o))
            .transpose()
            .map_err(storage)?;
        if old.state != SpendState::Unknown {
            if old.state == state
                && serde_json::to_string(&old.usage).map_err(storage)?
                    == usage.clone().unwrap_or_else(|| "null".into())
                && serde_json::to_string(&old.output).map_err(storage)?
                    == output.clone().unwrap_or_else(|| "null".into())
            {
                return Ok(());
            }
            return Err(conflict());
        }
        if state == SpendState::Released {
            let changed = conn
                .execute(
                    "UPDATE spend_accounts SET used=used-1 WHERE account=?1 AND used>0",
                    [&old.reservation.account],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(storage(()));
            }
        }
        conn.execute(
            "UPDATE spend_receipts SET state=?2, usage=?3, output=?4 WHERE reference=?1",
            params![reference.0, state_name(state), usage, output],
        )
        .map_err(storage)?;
        Ok(())
    }
}

fn receipt_in(
    conn: &Connection,
    reference: &SpendReceiptRef,
) -> Result<Option<SpendReceipt>, ModelError> {
    let row = conn
        .query_row(
            "SELECT reservation, state, usage, output FROM spend_receipts WHERE reference=?1",
            [&reference.0],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    row.map(|(r, state, usage, output)| {
        Ok(SpendReceipt {
            reservation: serde_json::from_str(&r).map_err(storage)?,
            state: match state.as_str() {
                "unknown" => SpendState::Unknown,
                "released" => SpendState::Released,
                "settled" => SpendState::Settled,
                _ => return Err(storage(())),
            },
            usage: usage
                .map(|u| serde_json::from_str(&u))
                .transpose()
                .map_err(storage)?,
            output: output
                .map(|o| serde_json::from_str(&o))
                .transpose()
                .map_err(storage)?,
        })
    })
    .transpose()
}
fn invocation_in(
    conn: &Connection,
    account: &str,
    invocation: &str,
) -> Result<Option<SpendReceipt>, ModelError> {
    let cached = conn.query_row(
        "SELECT reference, binding, output FROM spend_cached_invocations WHERE account=?1 AND invocation=?2",
        params![account, invocation],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
    ).optional().map_err(storage)?;
    if let Some((reference, binding, output)) = cached {
        let mut receipt = receipt_in(conn, &SpendReceiptRef(reference))?.ok_or_else(conflict)?;
        receipt.reservation.invocation = invocation.into();
        receipt.reservation.binding = binding;
        receipt.output = Some(serde_json::from_str(&output).map_err(storage)?);
        return Ok(Some(receipt));
    }
    let reference: Option<String> = conn.query_row("SELECT reference FROM spend_receipts WHERE account=?1 AND invocation=?2 ORDER BY rowid DESC LIMIT 1", params![account, invocation], |r| r.get(0)).optional().map_err(storage)?;
    reference
        .map(|r| receipt_in(conn, &SpendReceiptRef(r)))
        .transpose()
        .map(Option::flatten)
}

impl SpendLedger for SqliteSpendLedger {
    fn reserve(&self, r: &SpendReservation) -> Result<bool, ModelError> {
        let mut conn = self.0.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let accepted = Self::reserve_in(&tx, r)?;
        tx.commit().map_err(storage)?;
        Ok(accepted)
    }
    fn acquire_handoff(
        &self,
        handoff: &AcceptedSpendHandoff,
        account: &str,
        input_identity: &str,
        owner: &str,
    ) -> Result<(), ModelError> {
        let mut conn = self.0.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let old = receipt_in(&tx, &handoff.reservation.reference)?.ok_or_else(conflict)?;
        if old.reservation != handoff.reservation
            || old.state != SpendState::Unknown
            || old.reservation.account != account
            || handoff.input_identity != input_identity
            || owner.is_empty()
        {
            return Err(conflict());
        }
        let changed = tx
            .execute(
                "UPDATE spend_receipts SET dispatch_owner=?3 WHERE reference=?1
             AND handoff_input=?2 AND dispatch_owner IS NULL AND state='unknown'",
                params![handoff.reservation.reference.0, input_identity, owner],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(conflict());
        }
        tx.commit().map_err(storage)
    }
    fn receipt(&self, reference: &SpendReceiptRef) -> Result<Option<SpendReceipt>, ModelError> {
        let conn = self.0.lock().map_err(storage)?;
        receipt_in(&conn, reference)
    }
    fn invocation(
        &self,
        account: &str,
        invocation: &str,
    ) -> Result<Option<SpendReceipt>, ModelError> {
        let conn = self.0.lock().map_err(storage)?;
        invocation_in(&conn, account, invocation)
    }
    fn bind_cached(
        &self,
        account: &str,
        invocation: &str,
        binding: &str,
        reference: &SpendReceiptRef,
        output: serde_json::Value,
    ) -> Result<SpendReceipt, ModelError> {
        let mut conn = self.0.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // Serialize selection with reservation and other cache-hit callers.
        if let Some(existing) = invocation_in(&tx, account, invocation)? {
            if existing.reservation.binding != binding || existing.output.is_none() {
                return Err(conflict());
            }
            return Ok(existing);
        }
        let mut receipt = receipt_in(&tx, reference)?.ok_or_else(conflict)?;
        if receipt.reservation.account != account
            || receipt.reservation.binding != binding
            || receipt.state == SpendState::Released
            || receipt.output.is_none()
        {
            return Err(conflict());
        }
        let encoded = serde_json::to_string(&output).map_err(storage)?;
        tx.execute(
            "INSERT INTO spend_cached_invocations(account, invocation, binding, reference, output) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![account, invocation, binding, reference.0, encoded],
        ).map_err(storage)?;
        tx.commit().map_err(storage)?;
        receipt.reservation.invocation = invocation.into();
        receipt.reservation.binding = binding.into();
        receipt.output = Some(output);
        Ok(receipt)
    }
    fn finish(
        &self,
        r: &SpendReceiptRef,
        state: SpendState,
        usage: Option<UsageTrace>,
        output: Option<serde_json::Value>,
    ) -> Result<(), ModelError> {
        let mut conn = self.0.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::finish_in(&tx, r, state, usage, output)?;
        tx.commit().map_err(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
