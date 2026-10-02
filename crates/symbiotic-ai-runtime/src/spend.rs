//! SQLite accounting in Foundation's operational database, never a Memory store.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{path::Path, sync::Mutex};
use symbiotic_core::DiagnosticCode;
use symbiotic_model::{
    ModelError, SpendLedger, SpendReceipt, SpendReceiptRef, SpendReservation, SpendState,
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
        let reference: Option<String> = conn.query_row("SELECT reference FROM spend_receipts WHERE account=?1 AND invocation=?2 AND state!='released'", params![account, invocation], |r| r.get(0)).optional().map_err(storage)?;
        reference
            .map(|r| receipt_in(&conn, &SpendReceiptRef(r)))
            .transpose()
            .map(Option::flatten)
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
