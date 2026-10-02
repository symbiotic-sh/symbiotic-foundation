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
pub struct SqliteSpendLedger {
    connection: Mutex<Connection>,
    retention: Option<chrono::Duration>,
}
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
        Ok(Self {
            connection: Mutex::new(conn),
            retention: None,
        })
    }

    /// Apply the runtime's existing recovery retention policy.
    pub(crate) fn with_retention(
        mut self,
        retention: std::time::Duration,
    ) -> Result<Self, ModelError> {
        self.retention = Some(chrono::Duration::from_std(retention).map_err(storage)?);
        Ok(self)
    }

    /// Delete expired runtime payloads while retaining completion and accounting.
    pub(crate) fn expire_outputs(&self) -> Result<usize, ModelError> {
        let Some(retention) = self.retention else {
            return Ok(0);
        };
        let cutoff = chrono::Utc::now() - retention;
        self.purge_outputs(&|output| Ok(output_timestamp(output)? <= cutoff))
    }

    fn read_current(
        &self,
        reference: &SpendReceiptRef,
    ) -> Result<Option<SpendReceipt>, ModelError> {
        let mut conn = self.connection.lock().map_err(storage)?;
        if self.retention.is_none() {
            return receipt_in(&conn, reference);
        }
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let receipt = current_receipt_in(&tx, reference, self.retention)?;
        tx.commit().map_err(storage)?;
        Ok(receipt)
    }

    /// Reserve inside the caller's immediate transaction (permit/replay acceptance).
    /// Returns false for authenticated reattachment to exactly the same reservation.
    pub fn reserve_in(
        conn: &rusqlite::Transaction<'_>,
        r: &SpendReservation,
        attempt_limit: Option<u32>,
    ) -> Result<bool, ModelError> {
        // All reservation paths fix the invocation's input binding in this same
        // immediate transaction. Released predecessors never erase the binding.
        let binding: Option<String> = conn
            .query_row(
                "SELECT binding FROM spend_receipts WHERE account=?1 AND invocation=?2 LIMIT 1",
                params![r.account, r.invocation],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if binding
            .as_ref()
            .is_some_and(|binding| binding != &r.binding)
        {
            return Err(conflict());
        }
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
            "INSERT OR IGNORE INTO spend_accounts(account) VALUES (?1)",
            [&r.account],
        )
        .map_err(storage)?;
        let active: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM spend_receipts WHERE account=?1 AND invocation=?2 AND state!='released')", params![r.account, r.invocation], |row| row.get(0)).map_err(storage)?;
        if active {
            return Err(conflict());
        }
        if let Some(limit) = attempt_limit
            && attempts_in(conn, &r.account, &r.invocation, None)? >= limit
        {
            return Err(ModelError::BudgetExhausted(
                DiagnosticCode::AttemptBudgetExhausted,
            ));
        }
        let changed = conn.execute("UPDATE spend_accounts SET used=used+1 WHERE account=?1 AND used<9223372036854775807 AND (?2 IS NULL OR used<?2)", params![r.account, limit]).map_err(storage)?;
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
        if !Self::reserve_in(conn, &handoff.reservation, None)? {
            let input: Option<String> = conn
                .query_row(
                    "SELECT handoff_input FROM spend_receipts WHERE reference=?1",
                    [&handoff.reservation.reference.0],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            return if input.as_deref() == Some(handoff.input_identity.as_str()) {
                Ok(false)
            } else {
                Err(conflict())
            };
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

/// Provider completion time recorded in the runtime's existing response trace.
pub(crate) fn output_timestamp(
    output: &serde_json::Value,
) -> Result<chrono::DateTime<chrono::Utc>, ModelError> {
    serde_json::from_value(
        output
            .pointer("/trace/timestamp")
            .cloned()
            .ok_or_else(|| storage(()))?,
    )
    .map_err(storage)
}

fn discard_in(conn: &Connection, reference: &SpendReceiptRef) -> Result<(), ModelError> {
    conn.execute(
        "UPDATE spend_receipts SET output=?2 WHERE reference=?1",
        params![reference.0, SpendReceipt::completion_evidence().to_string()],
    )
    .map_err(storage)?;
    Ok(())
}

fn current_receipt_in(
    conn: &Connection,
    reference: &SpendReceiptRef,
    retention: Option<chrono::Duration>,
) -> Result<Option<SpendReceipt>, ModelError> {
    let mut receipt = receipt_in(conn, reference)?;
    if let Some(receipt) = &mut receipt
        && let Some(output) = receipt.recovery_output()
        && let Some(retention) = retention
        && output_timestamp(output)? <= chrono::Utc::now() - retention
    {
        discard_in(conn, reference)?;
        receipt.output = Some(SpendReceipt::completion_evidence());
    }
    Ok(receipt)
}

fn receipt_in(
    conn: &Connection,
    reference: &SpendReceiptRef,
) -> Result<Option<SpendReceipt>, ModelError> {
    let row = conn
        .query_row(
            "SELECT reservation, state, usage, output, pre_dispatch_released FROM spend_receipts WHERE reference=?1",
            [&reference.0],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, bool>(4)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    row.map(|(r, state, usage, output, pre_dispatch_released)| {
        Ok(SpendReceipt {
            reservation: serde_json::from_str(&r).map_err(storage)?,
            pre_dispatch_released,
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
    let reference: Option<String> = conn.query_row("SELECT reference FROM spend_receipts WHERE account=?1 AND invocation=?2 ORDER BY rowid DESC LIMIT 1", params![account, invocation], |r| r.get(0)).optional().map_err(storage)?;
    reference
        .map(|r| receipt_in(conn, &SpendReceiptRef(r)))
        .transpose()
        .map(Option::flatten)
}

fn attempts_in(
    conn: &Connection,
    account: &str,
    invocation: &str,
    reference_prefix: Option<&str>,
) -> Result<u32, ModelError> {
    conn.query_row(
        "SELECT count(*) FROM spend_receipts WHERE account=?1 AND invocation=?2
         AND pre_dispatch_released=0
         AND (?3 IS NULL OR substr(reference, 1, length(?3))=?3)",
        params![account, invocation, reference_prefix],
        |row| row.get(0),
    )
    .map_err(storage)
}

impl SpendLedger for SqliteSpendLedger {
    fn attempts(
        &self,
        account: &str,
        invocation: &str,
        reference_prefix: Option<&str>,
    ) -> Result<u32, ModelError> {
        let conn = self.connection.lock().map_err(storage)?;
        attempts_in(&conn, account, invocation, reference_prefix)
    }
    fn release_before_dispatch(&self, reference: &SpendReceiptRef) -> Result<(), ModelError> {
        let mut conn = self.connection.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let old = receipt_in(&tx, reference)?.ok_or_else(conflict)?;
        if old.state != SpendState::Unknown && !old.pre_dispatch_released {
            return Err(conflict());
        }
        Self::finish_in(&tx, reference, SpendState::Released, None, None)?;
        tx.execute(
            "UPDATE spend_receipts SET pre_dispatch_released=1 WHERE reference=?1",
            [&reference.0],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }
    fn reserve(
        &self,
        r: &SpendReservation,
        attempt_limit: Option<u32>,
    ) -> Result<bool, ModelError> {
        let mut conn = self.connection.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let accepted = Self::reserve_in(&tx, r, attempt_limit)?;
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
        let mut conn = self.connection.lock().map_err(storage)?;
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
        self.read_current(reference)
    }
    fn invocation(
        &self,
        account: &str,
        invocation: &str,
    ) -> Result<Option<SpendReceipt>, ModelError> {
        let mut conn = self.connection.lock().map_err(storage)?;
        if self.retention.is_none() {
            return invocation_in(&conn, account, invocation);
        }
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let receipt = invocation_in(&tx, account, invocation)?;
        let receipt = receipt
            .map(|receipt| current_receipt_in(&tx, &receipt.reservation.reference, self.retention))
            .transpose()?
            .flatten();
        tx.commit().map_err(storage)?;
        Ok(receipt)
    }
    fn discard_output(&self, account: &str, invocation: &str) -> Result<bool, ModelError> {
        let mut conn = self.connection.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let receipt = invocation_in(&tx, account, invocation)?;
        let removed = if let Some(receipt) = receipt.filter(|r| r.recovery_output().is_some()) {
            discard_in(&tx, &receipt.reservation.reference)?;
            true
        } else {
            false
        };
        tx.commit().map_err(storage)?;
        Ok(removed)
    }
    fn purge_outputs(
        &self,
        matches: &dyn Fn(&serde_json::Value) -> Result<bool, ModelError>,
    ) -> Result<usize, ModelError> {
        let mut conn = self.connection.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut statement = tx
            .prepare("SELECT reference, output FROM spend_receipts WHERE output IS NOT NULL")
            .map_err(storage)?;
        let mut rows = statement.query([]).map_err(storage)?;
        let mut removed = 0;
        while let Some(row) = rows.next().map_err(storage)? {
            let output: String = row.get(1).map_err(storage)?;
            let output: serde_json::Value = serde_json::from_str(&output).map_err(storage)?;
            if output != SpendReceipt::completion_evidence() && matches(&output)? {
                let reference = SpendReceiptRef(row.get(0).map_err(storage)?);
                discard_in(&tx, &reference)?;
                removed += 1;
            }
        }
        drop(rows);
        drop(statement);
        tx.commit().map_err(storage)?;
        Ok(removed)
    }
    fn finish(
        &self,
        r: &SpendReceiptRef,
        state: SpendState,
        usage: Option<UsageTrace>,
        output: Option<serde_json::Value>,
    ) -> Result<(), ModelError> {
        let mut conn = self.connection.lock().map_err(storage)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        Self::finish_in(&tx, r, state, usage, output)?;
        tx.commit().map_err(storage)
    }
}
