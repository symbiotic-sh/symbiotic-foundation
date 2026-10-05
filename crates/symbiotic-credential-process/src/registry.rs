//! Durable permit replay protection and bounded result recovery; no provider credentials.
use rusqlite::{Connection, OptionalExtension, params};
use symbiotic_ai_runtime::{model::AcceptedSpendHandoff, spend::SqliteSpendLedger};
use symbiotic_egress::*;
use uuid::Uuid;

pub(crate) struct Registry(Connection);

// A request or idle tick must never drain an arbitrarily large expired cohort.
const EXPIRY_BATCH_SIZE: usize = 64;
const REGISTRY_SCHEMA_VERSION: u16 = 7;

// Stored receipt identity/status; accounting is projected from the ledger on reads.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredReceipt {
    attempt_digest: String,
    status: DispatchStatus,
    attempt_id: AttemptId,
    reference: SpendReceiptRef,
}

impl From<&DispatchReceipt> for StoredReceipt {
    fn from(receipt: &DispatchReceipt) -> Self {
        Self {
            attempt_digest: receipt.attempt_digest.clone(),
            status: receipt.status,
            attempt_id: receipt.attempt_id.clone(),
            reference: receipt.reference.clone(),
        }
    }
}

struct PreviousAttempt {
    binding: String,
    ordinal: u32,
    receipt: Option<String>,
    record_sequence: u64,
    consumed: bool,
    grant_revision: u64,
    expires_at: u64,
    accepted_attempts: u32,
}

fn state(_: rusqlite::Error) -> EgressError {
    EgressError::StateUnavailable
}

impl Registry {
    pub(crate) fn open(path: &std::path::Path) -> Result<Self, EgressError> {
        symbiotic_ai_runtime::model::private_fs::ensure_private_file(path)
            .map_err(|_| EgressError::StateUnavailable)?;
        let conn = Connection::open(path).map_err(state)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(state)?;
        let existing: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='egress_permits')",
                [],
                |row| row.get(0),
            )
            .map_err(state)?;
        if existing {
            let version: u16 = conn
                .query_row("SELECT version FROM egress_schema", [], |row| row.get(0))
                .map_err(|_| EgressError::Version)?;
            if version != REGISTRY_SCHEMA_VERSION {
                return Err(EgressError::Version);
            }
        }
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA secure_delete=ON;
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS egress_schema (version INTEGER NOT NULL);
            INSERT INTO egress_schema SELECT 7 WHERE NOT EXISTS(SELECT 1 FROM egress_schema);
            CREATE TABLE IF NOT EXISTS egress_permits (
                attempt_digest TEXT PRIMARY KEY,
                invocation_key TEXT NOT NULL,
                invocation_binding TEXT NOT NULL,
                grant_key TEXT NOT NULL,
                grant_revision INTEGER NOT NULL,
                accepted_attempts INTEGER NOT NULL DEFAULT 0,
                ordinal INTEGER NOT NULL,
                record_sequence INTEGER NOT NULL,
                token TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                recovery_expires_at INTEGER NOT NULL,
                finished INTEGER NOT NULL DEFAULT 0,
                result TEXT,
                consumed INTEGER NOT NULL DEFAULT 0,
                receipt TEXT,
                UNIQUE(invocation_key, ordinal)
            );
            CREATE INDEX IF NOT EXISTS egress_result_expiry
                ON egress_permits(recovery_expires_at) WHERE result IS NOT NULL;
            CREATE TABLE IF NOT EXISTS egress_grant_revisions (
                grant_key TEXT PRIMARY KEY,
                revision INTEGER NOT NULL
            ); COMMIT;",
        )
        .map_err(state)?;
        let mut registry = Self(conn);
        registry.purge_expired(now()?)?;
        Ok(registry)
    }

    pub(crate) fn issue(
        &mut self,
        a: &DurableAttempt,
        max_attempts: u32,
    ) -> Result<PermitGrant, EgressError> {
        if let Some(grant) = self.existing(a)? {
            return Ok(grant);
        }
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(state)?;
        let grant = Self::issue_in(&tx, a, max_attempts)?;
        tx.commit().map_err(state)?;
        Ok(grant)
    }

    fn issue_in(
        tx: &rusqlite::Transaction<'_>,
        a: &DurableAttempt,
        max_attempts: u32,
    ) -> Result<PermitGrant, EgressError> {
        let attempt_digest = digest(a)?;
        let invocation_key = a.attempt_id().invocation_key()?;
        let grant_key = digest(&(&a.tenant, &a.incarnation))?;
        let binding = crate::invocation_binding(a)?;
        Self::check_revision(tx, a)?;
        let previous = tx.query_row(
            "SELECT invocation_binding, ordinal, receipt, record_sequence, consumed, grant_revision, accepted_attempts, expires_at
             FROM egress_permits WHERE invocation_key=?1 ORDER BY ordinal DESC LIMIT 1", [&invocation_key],
            |row| Ok(PreviousAttempt {
                binding: row.get(0)?, ordinal: row.get(1)?, receipt: row.get(2)?,
                record_sequence: row.get(3)?, consumed: row.get(4)?,
                grant_revision: row.get(5)?, accepted_attempts: row.get(6)?,
                expires_at: row.get(7)?,
            })).optional().map_err(state)?;
        let mut accepted_attempts = 0;
        if let Some(previous) = previous {
            if previous.binding != binding {
                return Err(EgressError::InvalidRequest);
            }
            if a.attempt_ordinal <= previous.ordinal {
                return Err(EgressError::PermitRefused);
            }
            // Durable attempts can expire before issuance and leave ordinal gaps.
            if a.record_sequence <= previous.record_sequence {
                return Err(EgressError::InvalidRequest);
            }
            accepted_attempts = previous.accepted_attempts;
            // Revision publication or expiry invalidates a pending permit without a handoff.
            // It has no charge or receipt and leaves the invocation allowance intact.
            if previous.consumed
                || (previous.grant_revision == a.grant_revision && now()? < previous.expires_at)
            {
                let receipt = previous
                    .receipt
                    .ok_or(EgressError::ReconciliationRequired)?;
                let receipt: StoredReceipt =
                    serde_json::from_str(&receipt).map_err(|_| EgressError::StateUnavailable)?;
                if receipt.status == DispatchStatus::Succeeded {
                    return Err(EgressError::InvocationComplete);
                }
                // Every accepted predecessor must be a settled zero-charge failure.
                // Success is terminal and any other charge requires reconciliation,
                // so this invariant inductively covers the entire retry history.
                let ledger_state: Option<String> = tx
                    .query_row(
                        "SELECT state FROM spend_receipts WHERE reference=?1",
                        [receipt.reference.as_str()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(state)?;
                if ledger_state.as_deref() != Some("released") {
                    return Err(EgressError::ReconciliationRequired);
                }
            }
        }
        // Only the current reservation can spend: prior attempts were zero.
        if accepted_attempts >= max_attempts {
            return Err(EgressError::BudgetRefused);
        }
        if now()? >= a.expires_at {
            return Err(EgressError::AuthorityExpired);
        }
        let token = Uuid::new_v4().to_string();
        tx.execute("INSERT INTO egress_permits (attempt_digest, invocation_key, invocation_binding, ordinal, token, record_sequence, recovery_expires_at, grant_key, grant_revision, accepted_attempts, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![attempt_digest, invocation_key, binding, a.attempt_ordinal, token, a.record_sequence, a.recovery_expires_at, grant_key, a.grant_revision, accepted_attempts, a.expires_at]).map_err(state)?;
        Ok(PermitGrant {
            permit: DispatchPermit {
                token,
                attempt_digest,
            },
            status: AttemptStatus::Permitted,
        })
    }

    pub(crate) fn publish_revision(&mut self, grant: &GrantRevision) -> Result<(), EgressError> {
        let key = digest(&(&grant.tenant, &grant.incarnation))?;
        // A stale update can never roll back authorization, including after restart.
        let changed = self.0.execute("INSERT INTO egress_grant_revisions (grant_key, revision) VALUES (?1, ?2) ON CONFLICT(grant_key) DO UPDATE SET revision=excluded.revision WHERE revision<=excluded.revision", params![key, grant.revision]).map_err(state)?;
        if changed != 1 {
            return Err(EgressError::RouteRefused);
        }
        Ok(())
    }

    pub(crate) fn check_revision(
        conn: &Connection,
        attempt: &DurableAttempt,
    ) -> Result<(), EgressError> {
        let key = digest(&(&attempt.tenant, &attempt.incarnation))?;
        let current: Option<u64> = conn
            .query_row(
                "SELECT revision FROM egress_grant_revisions WHERE grant_key=?1",
                [key],
                |r| r.get(0),
            )
            .optional()
            .map_err(state)?;
        if current != Some(attempt.grant_revision) {
            return Err(EgressError::RouteRefused);
        }
        Ok(())
    }

    pub(crate) fn consume(
        &mut self,
        attempt: &DurableAttempt,
        permit: &DispatchPermit,
        handoff: &AcceptedSpendHandoff,
        max_attempts: u32,
    ) -> Result<DispatchReceipt, EgressError> {
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(state)?;
        let receipt = Self::accept_in(
            &tx,
            attempt,
            permit,
            &handoff.reservation.reference,
            max_attempts,
        )?;
        if !SqliteSpendLedger::reserve_handoff_in(&tx, handoff).map_err(ledger_error)? {
            return Err(EgressError::PermitRefused);
        }
        tx.commit().map_err(state)?;
        Ok(receipt)
    }

    pub(crate) fn accept_job_in(
        tx: &rusqlite::Transaction<'_>,
        attempt: &DurableAttempt,
        reference: &SpendReceiptRef,
        max_attempts: u32,
    ) -> Result<(), EgressError> {
        let key = attempt.attempt_id().invocation_key()?;
        let existing: Option<(String, String)> = tx.query_row(
            "SELECT attempt_digest, token FROM egress_permits WHERE invocation_key=?1 AND ordinal=?2",
            params![key, attempt.attempt_ordinal], |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional().map_err(state)?;
        let permit = if let Some((attempt_digest, token)) = existing {
            DispatchPermit {
                attempt_digest,
                token,
            }
        } else {
            Self::issue_in(tx, attempt, max_attempts)?.permit
        };
        Self::accept_in(tx, attempt, &permit, reference, max_attempts)?;
        Ok(())
    }

    // Both dispatch paths consume this canonical attempt record under the same
    // writer transaction as their reservation. A failed reservation rolls it back.
    fn accept_in(
        tx: &rusqlite::Transaction<'_>,
        attempt: &DurableAttempt,
        permit: &DispatchPermit,
        reference: &SpendReceiptRef,
        max_attempts: u32,
    ) -> Result<DispatchReceipt, EgressError> {
        let attempt_digest = digest(attempt)?;
        if attempt_digest != permit.attempt_digest {
            return Err(EgressError::PermitRefused);
        }
        let receipt = DispatchReceipt {
            attempt_digest: attempt_digest.clone(),
            status: DispatchStatus::ProviderFailed,
            usage: Default::default(),
            attempt_id: attempt.attempt_id(),
            reference: reference.clone(),
            spend_state: SpendState::Unknown,
        };
        let json = serde_json::to_string(&StoredReceipt::from(&receipt))
            .map_err(|_| EgressError::StateUnavailable)?;
        let (accepted_attempts, superseded): (u32, bool) = tx
            .query_row(
                "SELECT p.accepted_attempts, EXISTS(
                SELECT 1 FROM egress_permits successor
                WHERE successor.invocation_key=p.invocation_key AND successor.ordinal>p.ordinal)
             FROM egress_permits p WHERE p.attempt_digest=?1 AND p.token=?2 AND p.consumed=0",
                params![attempt_digest, permit.token],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(state)?
            .ok_or(EgressError::PermitRefused)?;
        // The immediate transaction orders current authority with revision publication
        // and the durable replay/reservation acceptance point.
        Self::check_revision(tx, attempt)?;
        // Issuance permanently supersedes an unconsumed predecessor, even if
        // the clock rolls back. Only the latest row can advance its handoff count.
        if superseded {
            return Err(EgressError::PermitRefused);
        }
        // Recheck the current route allowance even for a permit issued before restart.
        if accepted_attempts >= max_attempts {
            return Err(EgressError::BudgetRefused);
        }
        // Sample Foundation's clock after acquiring the writer transaction and
        // immediately before consumption/reservation. IPC or admission lock
        // delays must never turn an expired signed authority into a handoff.
        if now()? >= attempt.expires_at {
            return Err(EgressError::AuthorityExpired);
        }
        let changed = tx.execute("UPDATE egress_permits SET consumed=1, receipt=?1, accepted_attempts=accepted_attempts+1 WHERE attempt_digest=?2 AND token=?3 AND consumed=0", params![json, attempt_digest, permit.token]).map_err(state)?;
        if changed != 1 {
            return Err(EgressError::PermitRefused);
        }
        Ok(receipt)
    }

    pub(crate) fn finish(&mut self, result: &DispatchResult) -> Result<(), EgressError> {
        let mut json = serde_json::to_value(result).map_err(|_| EgressError::StateUnavailable)?;
        json["receipt"] = serde_json::to_value(StoredReceipt::from(&result.receipt))
            .map_err(|_| EgressError::StateUnavailable)?;
        let receipt = json["receipt"].to_string();
        let json = json.to_string();
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(state)?;
        let changed = tx
            .execute(
                "UPDATE egress_permits SET receipt=?1, finished=1,
             result=CASE WHEN recovery_expires_at>?4 THEN ?2 ELSE NULL END
             WHERE attempt_digest=?3 AND consumed=1 AND finished=0",
                params![receipt, json, result.receipt.attempt_digest, now()?],
            )
            .map_err(state)?;
        if changed != 1 {
            return Err(EgressError::StateUnavailable);
        }
        // Response identity is still recoverable when token usage is absent.
        // Settlement remains governed by measured usage, independently of metadata.
        let usage = (result.output.is_some()
            || symbiotic_ai_runtime::model::has_measured_usage(&result.receipt.usage))
        .then(|| result.receipt.usage.clone());
        SqliteSpendLedger::finish_in(
            &tx,
            &result.receipt.reference,
            result.receipt.spend_state,
            usage,
            // Output bytes live only in bounded egress recovery. The ledger keeps
            // completion evidence so commit refusal cannot release missing-usage spend.
            result
                .output
                .as_ref()
                .map(|_| serde_json::json!({"output_received": true})),
        )
        .map_err(ledger_error)?;
        tx.commit().map_err(state)
    }

    pub(crate) fn existing(&self, a: &DurableAttempt) -> Result<Option<PermitGrant>, EgressError> {
        let key = a.attempt_id().invocation_key()?;
        let existing: Option<(String, String)> = self.0.query_row(
            "SELECT attempt_digest, token FROM egress_permits WHERE invocation_key=?1 AND ordinal=?2",
            params![key, a.attempt_ordinal], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(state)?;
        existing
            .map(|(attempt_digest, token)| {
                if attempt_digest != digest(a)? {
                    return Err(EgressError::InvalidRequest);
                }
                Ok(PermitGrant {
                    permit: DispatchPermit {
                        token,
                        attempt_digest,
                    },
                    status: self.attempt_status(&a.attempt_id(), now()?)?,
                })
            })
            .transpose()
    }

    pub(crate) fn attempt_status(
        &self,
        id: &AttemptId,
        time: u64,
    ) -> Result<AttemptStatus, EgressError> {
        let key = id.invocation_key()?;
        let row = self
            .0
            .query_row(
                "SELECT p.consumed, p.finished, p.recovery_expires_at, p.receipt, p.result,
                        p.grant_revision = g.revision, p.expires_at, EXISTS(
                            SELECT 1 FROM egress_permits successor
                            WHERE successor.invocation_key=p.invocation_key AND successor.ordinal>p.ordinal)
                 FROM egress_permits p JOIN egress_grant_revisions g ON g.grant_key=p.grant_key
                 WHERE p.invocation_key=?1 AND p.ordinal=?2",
                params![key, id.attempt_ordinal],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, u64>(6)?,
                        row.get::<_, bool>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(state)?;
        let Some((
            consumed,
            finished,
            expires,
            receipt,
            result,
            current_revision,
            authority_expires,
            superseded,
        )) = row
        else {
            return Ok(AttemptStatus::NotIssued);
        };
        if !consumed {
            return Ok(
                if !superseded && current_revision && time < authority_expires {
                    AttemptStatus::Permitted
                } else {
                    AttemptStatus::Invalidated
                },
            );
        }
        if !finished {
            return Ok(AttemptStatus::Dispatched {
                receipt: self.project_receipt(
                    serde_json::from_str(&receipt.ok_or(EgressError::StateUnavailable)?)
                        .map_err(|_| EgressError::StateUnavailable)?,
                )?,
            });
        }
        if time >= expires {
            return Ok(AttemptStatus::Expired);
        }
        let mut result: serde_json::Value =
            serde_json::from_str(&result.ok_or(EgressError::StateUnavailable)?)
                .map_err(|_| EgressError::StateUnavailable)?;
        result["receipt"] = serde_json::to_value(
            self.project_receipt(
                serde_json::from_value(result["receipt"].take())
                    .map_err(|_| EgressError::StateUnavailable)?,
            )?,
        )
        .map_err(|_| EgressError::StateUnavailable)?;
        let result: DispatchResult =
            serde_json::from_value(result).map_err(|_| EgressError::StateUnavailable)?;
        Ok(if result.error.is_some() {
            AttemptStatus::Failed { result }
        } else {
            AttemptStatus::Completed { result }
        })
    }

    pub(crate) fn purge_expired(&mut self, time: u64) -> Result<(), EgressError> {
        // Recovery polling must not contend with the runtime's writer when no
        // result is due. Use the partial deadline index for both the probe and batch.
        let due: bool = self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM egress_permits WHERE recovery_expires_at<=?1 AND result IS NOT NULL)",
            [time], |row| row.get(0),
        ).map_err(state)?;
        if !due {
            return Ok(());
        }
        self.0
            .execute(
                "UPDATE egress_permits SET result=NULL WHERE rowid IN (
                SELECT rowid FROM egress_permits
                WHERE recovery_expires_at<=?1 AND result IS NOT NULL
                ORDER BY recovery_expires_at LIMIT ?2
            )",
                params![time, EXPIRY_BATCH_SIZE],
            )
            .map_err(state)?;
        Ok(())
    }

    fn project_receipt(&self, receipt: StoredReceipt) -> Result<DispatchReceipt, EgressError> {
        let (ledger_state, usage): (String, Option<String>) = self
            .0
            .query_row(
                "SELECT state, usage FROM spend_receipts WHERE reference=?1",
                [receipt.reference.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(state)?;
        Ok(DispatchReceipt {
            attempt_digest: receipt.attempt_digest,
            status: receipt.status,
            attempt_id: receipt.attempt_id,
            reference: receipt.reference,
            usage: usage
                .map(|usage| serde_json::from_str(&usage))
                .transpose()
                .map_err(|_| EgressError::StateUnavailable)?
                .unwrap_or_default(),
            spend_state: serde_json::from_value(serde_json::Value::String(ledger_state))
                .map_err(|_| EgressError::StateUnavailable)?,
        })
    }

    pub(crate) fn receipt(&self, id: &AttemptId) -> Result<Option<DispatchReceipt>, EgressError> {
        let json: Option<String> = self
            .0
            .query_row(
                "SELECT receipt FROM egress_permits WHERE invocation_key=?1 AND ordinal=?2 AND consumed=1",
                params![id.invocation_key()?, id.attempt_ordinal],
                |row| row.get(0),
            )
            .optional()
            .map_err(state)?;
        json.map(|json| {
            self.project_receipt(
                serde_json::from_str(&json).map_err(|_| EgressError::StateUnavailable)?,
            )
        })
        .transpose()
    }
}

pub(crate) fn now() -> Result<u64, EgressError> {
    #[cfg(test)]
    if let Some(time) = tests::CLOCK.with(std::cell::Cell::get) {
        return Ok(time);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| EgressError::StateUnavailable)
}

fn ledger_error(err: symbiotic_ai_runtime::ModelError) -> EgressError {
    match err {
        symbiotic_ai_runtime::ModelError::BudgetExhausted(_) => EgressError::BudgetRefused,
        symbiotic_ai_runtime::ModelError::Queue(
            symbiotic_ai_runtime::model::DiagnosticCode::SpendReconciliationRequired,
        ) => EgressError::ReconciliationRequired,
        _ => EgressError::StateUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbiotic_ai_runtime::SpendReservation;

    thread_local! {
        pub(super) static CLOCK: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    }

    struct TestClock;
    impl TestClock {
        fn new(time: u64) -> Self {
            let clock = Self;
            clock.set(time);
            clock
        }
        fn set(&self, time: u64) {
            CLOCK.with(|clock| clock.set(Some(time)));
        }
    }
    impl Drop for TestClock {
        fn drop(&mut self) {
            CLOCK.with(|clock| clock.set(None));
        }
    }

    fn open(path: &std::path::Path) -> Registry {
        symbiotic_queue_sqlite::SqliteQueue::open(path).unwrap();
        let mut registry = Registry::open(path).unwrap();
        let _ = registry.publish_revision(&GrantRevision {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            revision: 1,
        });
        registry
    }
    fn reservation(a: &DurableAttempt) -> AcceptedSpendHandoff {
        AcceptedSpendHandoff {
            reservation: SpendReservation {
                reference: crate::egress_reference(a).unwrap(),
                account: "test-account".into(),
                invocation: a.attempt_id().invocation_key().unwrap(),
                binding: crate::invocation_binding(a).unwrap(),
                request_limit: None,
            },
            input_identity: "test-input".into(),
        }
    }

    #[test]
    fn emitted_egress_and_runtime_refs_within_max() {
        let mut attempt = attempt();
        attempt.attempt_ordinal = u32::MAX;
        attempt.record_sequence = u64::MAX;
        attempt.invocation_id = "é".repeat(4096);
        let reference = crate::egress_reference(&attempt).unwrap();
        assert_eq!(
            reference.as_str(),
            format!("egress:{}", digest(&attempt).unwrap())
        );
        assert_eq!(reference.as_str().len(), 71);
    }

    fn finish_released(registry: &mut Registry, mut receipt: DispatchReceipt) {
        receipt.status = DispatchStatus::CredentialUnavailable;
        receipt.spend_state = SpendState::Released;
        registry
            .finish(&DispatchResult {
                receipt,
                output: None,
                error: Some(EgressError::CredentialUnavailable),
                diagnostics: Vec::new(),
                receipt_persisted: true,
            })
            .unwrap();
    }

    fn attempt() -> DurableAttempt {
        serde_json::from_value(serde_json::json!({
            "tenant": "tenant", "incarnation": "incarnation", "invocation_id": "retry",
            "attempt_ordinal": 1, "record_sequence": 1, "recorded_at": 100, "expires_at": now().unwrap() + 3600,
            "recovery_expires_at": 4000000000u64, "caller_binding": "caller", "route": "chat", "destination": "https://example.test",
            "model": "model", "method": "POST", "secret_ref": "key", "manifest_ref": "manifest",
            "input_manifest_digest": "a".repeat(64), "input_digest": "b".repeat(64),
            "grant_revision": 1
        }))
        .unwrap()
    }

    #[test]
    fn stored_receipts_leave_accounting_in_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = open(&dir.path().join("registry.sqlite"));
        let attempt = attempt();
        let permit = registry.issue(&attempt, 2).unwrap().permit;
        let receipt = registry
            .consume(&attempt, &permit, &reservation(&attempt), 2)
            .unwrap();
        let stored: String = registry
            .0
            .query_row("SELECT receipt FROM egress_permits", [], |r| r.get(0))
            .unwrap();
        let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert!(stored.get("usage").is_none());
        assert!(stored.get("spend_state").is_none());
        finish_released(&mut registry, receipt);
        let stored: String = registry
            .0
            .query_row("SELECT result FROM egress_permits", [], |r| r.get(0))
            .unwrap();
        let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert!(stored["receipt"].get("usage").is_none());
        assert!(stored["receipt"].get("spend_state").is_none());
        assert_eq!(
            registry
                .receipt(&attempt.attempt_id())
                .unwrap()
                .unwrap()
                .spend_state,
            SpendState::Released
        );
    }

    #[test]
    fn issued_successor_prevents_clock_rollback_from_reviving_pending_predecessor() {
        let clock = TestClock::new(100);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.sqlite");
        let mut registry = open(&path);
        let mut first = attempt();
        first.expires_at = 101;
        let first_grant = registry.issue(&first, 1).unwrap();
        clock.set(101);
        let mut second = first.clone();
        second.attempt_ordinal = 2;
        second.record_sequence = 2;
        second.recorded_at = 101;
        second.expires_at = 200;
        let second_grant = registry.issue(&second, 1).unwrap();
        clock.set(100);
        for restart in [false, true] {
            if restart {
                drop(registry);
                registry = open(&path);
            }
            assert!(matches!(
                registry.consume(&first, &first_grant.permit, &reservation(&first), 1),
                Err(EgressError::PermitRefused)
            ));
            assert!(matches!(
                registry.attempt_status(&first.attempt_id(), 100).unwrap(),
                AttemptStatus::Invalidated
            ));
            let reattached = registry.issue(&first, 1).unwrap();
            assert_eq!(reattached.permit.token, first_grant.permit.token);
            assert!(matches!(reattached.status, AttemptStatus::Invalidated));
            assert!(registry.receipt(&first.attempt_id()).unwrap().is_none());
            assert_eq!(
                registry
                    .0
                    .query_row("SELECT count(*) FROM spend_receipts", [], |r| r
                        .get::<_, u32>(0))
                    .unwrap(),
                0
            );
        }
        let receipt = registry
            .consume(&second, &second_grant.permit, &reservation(&second), 1)
            .unwrap();
        finish_released(&mut registry, receipt);
        second.attempt_ordinal = 3;
        second.record_sequence = 3;
        assert!(matches!(
            registry.issue(&second, 1),
            Err(EgressError::BudgetRefused)
        ));
        assert_eq!(
            registry
                .0
                .query_row(
                    "SELECT sum(consumed), sum(accepted_attempts) FROM egress_permits",
                    [],
                    |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?))
                )
                .unwrap(),
            (1, 1)
        );
    }

    #[test]
    fn expiry_before_issuance_allows_ordinal_gaps_without_losing_invariants() {
        let clock = TestClock::new(100);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.sqlite");
        let mut registry = open(&path);
        let mut first = attempt();
        first.expires_at = 101;
        clock.set(101);
        assert!(matches!(
            registry.issue(&first, 2),
            Err(EgressError::AuthorityExpired)
        ));
        assert!(matches!(
            registry.attempt_status(&first.attempt_id(), 101).unwrap(),
            AttemptStatus::NotIssued
        ));
        let mut second = first.clone();
        second.attempt_ordinal = 2;
        second.record_sequence = 2;
        second.recorded_at = 101;
        second.expires_at = 102;
        let granted = registry.issue(&second, 2).unwrap();
        let receipt = registry
            .consume(&second, &granted.permit, &reservation(&second), 2)
            .unwrap();
        finish_released(&mut registry, receipt);
        clock.set(102);
        let mut third = second.clone();
        third.attempt_ordinal = 3;
        third.record_sequence = 3;
        assert!(matches!(
            registry.issue(&third, 2),
            Err(EgressError::AuthorityExpired)
        ));
        assert!(matches!(
            registry.attempt_status(&third.attempt_id(), 102).unwrap(),
            AttemptStatus::NotIssued
        ));
        drop(registry);
        registry = open(&path);
        let mut fourth = third.clone();
        fourth.attempt_ordinal = 4;
        fourth.record_sequence = 4;
        fourth.recorded_at = 102;
        fourth.expires_at = 200;
        let mut changed = fourth.clone();
        changed.record_sequence = 2;
        assert!(matches!(
            registry.issue(&changed, 2),
            Err(EgressError::InvalidRequest)
        ));
        changed = fourth.clone();
        changed.input_digest = "c".repeat(64);
        assert!(matches!(
            registry.issue(&changed, 2),
            Err(EgressError::InvalidRequest)
        ));
        let granted = registry.issue(&fourth, 2).unwrap();
        changed = fourth.clone();
        changed.expires_at += 1;
        assert!(matches!(
            registry.issue(&changed, 2),
            Err(EgressError::InvalidRequest)
        ));
        assert!(matches!(
            registry.issue(&third, 2),
            Err(EgressError::PermitRefused)
        ));
        let receipt = registry
            .consume(&fourth, &granted.permit, &reservation(&fourth), 2)
            .unwrap();
        finish_released(&mut registry, receipt);
        assert_eq!(
            registry
                .0
                .query_row(
                    "SELECT accepted_attempts FROM egress_permits WHERE ordinal=4",
                    [],
                    |r| r.get::<_, u32>(0)
                )
                .unwrap(),
            2
        );
        // Another skipped ordinal must still carry the accepted-handoff count.
        fourth.attempt_ordinal = 6;
        fourth.record_sequence = 6;
        assert!(matches!(
            registry.issue(&fourth, 2),
            Err(EgressError::BudgetRefused)
        ));
        assert_eq!(
            registry
                .0
                .query_row("SELECT count(*) FROM egress_permits", [], |r| r
                    .get::<_, u32>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn authority_expiry_while_waiting_for_acceptance_consumes_and_reserves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.sqlite");
        let mut registry = open(&path);
        let mut first = attempt();
        first.recorded_at = now().unwrap();
        first.expires_at = first.recorded_at + 2;
        let granted = registry.issue(&first, 1).unwrap();
        assert!(matches!(
            registry
                .attempt_status(&first.attempt_id(), first.expires_at - 1)
                .unwrap(),
            AttemptStatus::Permitted
        ));
        // Hold the acceptance writer lock while valid authority expires. The
        // consumer's check and issuance have succeeded, but acceptance must use
        // Foundation's clock after acquiring its immediate transaction.
        let mut blocker = Connection::open(&path).unwrap();
        let lock = blocker
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let attempt = first.clone();
        let permit = granted.permit.clone();
        let (started, ready) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            assert!(now().unwrap() < attempt.expires_at);
            started.send(()).unwrap();
            let result = registry.consume(&attempt, &permit, &reservation(&attempt), 1);
            (registry, result)
        });
        ready.recv().unwrap();
        while now().unwrap() < first.expires_at {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        lock.commit().unwrap();
        let (mut registry, result) = worker.join().unwrap();
        assert!(
            matches!(result, Err(EgressError::AuthorityExpired)),
            "expired authority was accepted"
        );
        assert!(matches!(
            registry
                .attempt_status(&first.attempt_id(), first.expires_at)
                .unwrap(),
            AttemptStatus::Invalidated
        ));
        assert!(registry.receipt(&first.attempt_id()).unwrap().is_none());
        assert_eq!(
            registry
                .0
                .query_row(
                    "SELECT consumed, accepted_attempts FROM egress_permits",
                    [],
                    |r| { Ok((r.get::<_, bool>(0)?, r.get::<_, u32>(1)?)) }
                )
                .unwrap(),
            (false, 0)
        );
        for table in ["spend_receipts", "spend_accounts"] {
            assert_eq!(
                registry
                    .0
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, u64>(0))
                    .unwrap(),
                0
            );
        }
        drop(registry);
        registry = open(&path);
        let reattached = registry.issue(&first, 1).unwrap();
        assert_eq!(reattached.permit.token, granted.permit.token);
        assert!(matches!(reattached.status, AttemptStatus::Invalidated));
        assert!(matches!(
            registry.consume(&first, &granted.permit, &reservation(&first), 1),
            Err(EgressError::AuthorityExpired)
        ));
        // Reauthorization renews this attempt's deadline, without a revision
        // publication or spending the one accepted-attempt allowance.
        let mut second = first.clone();
        second.recorded_at = now().unwrap();
        second.expires_at = second.recorded_at + 3600;
        assert!(matches!(
            registry.issue(&second, 1),
            Err(EgressError::InvalidRequest)
        ));
        second.attempt_ordinal += 1;
        second.record_sequence += 1;
        let granted = registry.issue(&second, 1).unwrap();
        let receipt = registry
            .consume(&second, &granted.permit, &reservation(&second), 1)
            .unwrap();
        // An already accepted handoff survives authority expiry and preserves
        // accounting, completion and recovery through the separate recovery deadline.
        assert!(matches!(
            registry
                .attempt_status(&second.attempt_id(), second.expires_at)
                .unwrap(),
            AttemptStatus::Dispatched { .. }
        ));
        let mut receipt = receipt;
        receipt.status = DispatchStatus::Succeeded;
        receipt.spend_state = SpendState::Settled;
        receipt.usage.input_tokens = Some(1);
        registry
            .finish(&DispatchResult {
                receipt,
                output: Some(ProviderOutput::Chat {
                    text: "accepted answer".into(),
                    finish_reason: None,
                }),
                error: None,
                diagnostics: Vec::new(),
                receipt_persisted: true,
            })
            .unwrap();
        assert!(matches!(
            registry
                .attempt_status(&second.attempt_id(), second.expires_at)
                .unwrap(),
            AttemptStatus::Completed { .. }
        ));
        assert!(registry.receipt(&second.attempt_id()).unwrap().is_some());
    }

    #[test]
    fn revocation_does_not_withdraw_consumed_permits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.sqlite");
        let mut registry = open(&path);
        let mut attempt = attempt();
        attempt.record_sequence = 12;
        let grant = registry.issue(&attempt, 20000).unwrap();
        let receipt = registry
            .consume(&attempt, &grant.permit, &reservation(&attempt), 20000)
            .unwrap();
        registry
            .publish_revision(&GrantRevision {
                tenant: attempt.tenant.clone(),
                incarnation: attempt.incarnation.clone(),
                revision: 11,
            })
            .unwrap();
        for restart in [false, true] {
            if restart {
                drop(registry);
                registry = open(&path);
            }
            let reattached = registry.issue(&attempt, 20000).unwrap();
            assert_eq!(reattached.permit.token, grant.permit.token);
            let AttemptStatus::Dispatched { receipt: retained } = reattached.status else {
                panic!("consumed handoff was withdrawn");
            };
            assert_eq!(
                serde_json::to_value(&retained).unwrap(),
                serde_json::to_value(&receipt).unwrap()
            );
            assert!(matches!(
                registry.consume(&attempt, &grant.permit, &reservation(&attempt), 20000),
                Err(EgressError::PermitRefused)
            ));
            assert_eq!(
                serde_json::to_value(registry.receipt(&attempt.attempt_id()).unwrap().unwrap())
                    .unwrap(),
                serde_json::to_value(&receipt).unwrap()
            );
        }
    }

    #[test]
    fn recovery_expiry_cleanup_is_incremental_and_indexed() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = open(&dir.path().join("registry.sqlite"));
        let attempt = attempt();
        let grant = registry.issue(&attempt, 20000).unwrap();
        let receipt = registry
            .consume(&attempt, &grant.permit, &reservation(&attempt), 20000)
            .unwrap();
        registry
            .finish(&DispatchResult {
                diagnostics: Vec::new(),
                receipt,
                output: Some(ProviderOutput::Chat {
                    text: "retained".into(),
                    finish_reason: None,
                }),
                error: None,
                receipt_persisted: true,
            })
            .unwrap();
        // A large cohort sharing one deadline must take multiple bounded sweeps.
        registry
            .0
            .execute_batch(
                "WITH RECURSIVE ord(n) AS (
                VALUES(2) UNION ALL SELECT n+1 FROM ord WHERE n<10000
            ) INSERT INTO egress_permits
                (attempt_digest, invocation_key, invocation_binding, ordinal, record_sequence,
                 token, recovery_expires_at, consumed, finished, receipt, result,
                 grant_key, grant_revision, accepted_attempts, expires_at)
                SELECT printf('%064d', n), invocation_key, invocation_binding, n, n,
                       token, recovery_expires_at, 1, 1, receipt, result,
                       grant_key, grant_revision, n, expires_at
                FROM egress_permits, ord WHERE ordinal=1;",
            )
            .unwrap();
        // Bound VM work as well as updated rows: LIMIT alone must not hide a scan.
        registry.0.progress_handler(20000, Some(|| true));
        registry.purge_expired(attempt.recovery_expires_at).unwrap();
        registry.0.progress_handler(0, None::<fn() -> bool>);
        let remaining = || {
            registry
                .0
                .query_row(
                    "SELECT count(*) FROM egress_permits WHERE result IS NOT NULL",
                    [],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
        };
        assert_eq!(remaining(), 10000 - 64);
        // Lookup must enforce logical expiry even for rows not yet swept.
        let mut id = attempt.attempt_id();
        id.attempt_ordinal = 10000;
        assert!(matches!(
            registry
                .attempt_status(&id, attempt.recovery_expires_at)
                .unwrap(),
            AttemptStatus::Expired
        ));
        assert!(registry.receipt(&attempt.attempt_id()).unwrap().is_some());
        assert!(matches!(
            registry.consume(&attempt, &grant.permit, &reservation(&attempt), 20000),
            Err(EgressError::PermitRefused)
        ));
        registry.purge_expired(attempt.recovery_expires_at).unwrap();
        let remaining: usize = registry
            .0
            .query_row(
                "SELECT count(*) FROM egress_permits WHERE result IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 10000 - 128);
        // Before the next deadline, lookup must not scan the remaining results.
        registry.0.progress_handler(1000, Some(|| true));
        registry
            .purge_expired(attempt.recovery_expires_at - 1)
            .unwrap();
    }

    #[test]
    fn retry_admission_uses_bounded_indexed_work_with_large_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = open(&dir.path().join("registry.sqlite"));
        let mut attempt = attempt();
        let permit = registry.issue(&attempt, 20000).unwrap().permit;
        let mut receipt = registry
            .consume(&attempt, &permit, &reservation(&attempt), 20000)
            .unwrap();
        receipt.status = DispatchStatus::CredentialUnavailable;
        receipt.spend_state = SpendState::Released;
        registry
            .finish(&DispatchResult {
                diagnostics: Vec::new(),
                receipt,
                output: None,
                error: Some(EgressError::CredentialUnavailable),
                receipt_persisted: true,
            })
            .unwrap();
        // Populate settled zero-charge predecessors in one transaction. Each has
        // the same immutable binding; only sequence, ordinal and digest differ.
        registry
            .0
            .execute_batch(
                "WITH RECURSIVE ord(n) AS (
            VALUES(2) UNION ALL SELECT n+1 FROM ord WHERE n<10000
        ) INSERT INTO egress_permits
            (attempt_digest, invocation_key, invocation_binding, ordinal, record_sequence,
             token, recovery_expires_at, consumed, receipt, grant_key, grant_revision, accepted_attempts, expires_at)
            SELECT printf('%064d', n), invocation_key, invocation_binding, n, n,
                   token, recovery_expires_at, 1, receipt, grant_key, grant_revision, n, expires_at FROM egress_permits, ord WHERE ordinal=1;",
            )
            .unwrap();
        attempt.attempt_ordinal = 10001;
        attempt.record_sequence = 10001;
        // Interrupt any admission needing 1,000 VM instructions. An indexed
        // predecessor lookup fits; an aggregate over 10,000 receipts cannot.
        registry.0.progress_handler(1000, Some(|| true));
        assert!(registry.issue(&attempt, 20000).is_ok());
        registry
            .publish_revision(&GrantRevision {
                tenant: attempt.tenant.clone(),
                incarnation: attempt.incarnation.clone(),
                revision: 2,
            })
            .unwrap();
        assert!(matches!(
            registry
                .attempt_status(&attempt.attempt_id(), now().unwrap())
                .unwrap(),
            AttemptStatus::Invalidated
        ));
        attempt.attempt_ordinal += 1;
        attempt.record_sequence += 1;
        attempt.grant_revision = 2;
        // The invalidated ordinal did not increment the 10,000 accepted handoffs.
        assert!(matches!(
            registry.issue(&attempt, 10000),
            Err(EgressError::BudgetRefused)
        ));
        assert!(registry.issue(&attempt, 10001).is_ok());
    }

    #[test]
    fn retry_acceptance_preserves_invocation_binding_with_a_distinct_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = open(&dir.path().join("registry.sqlite"));
        let mut attempt = attempt();
        let first_handoff = reservation(&attempt);
        let grant = registry.issue(&attempt, 20000).unwrap();
        let mut receipt = registry
            .consume(&attempt, &grant.permit, &first_handoff, 20000)
            .unwrap();
        receipt.status = DispatchStatus::CredentialUnavailable;
        receipt.spend_state = SpendState::Released;
        registry
            .finish(&DispatchResult {
                diagnostics: Vec::new(),
                receipt,
                output: None,
                error: Some(EgressError::CredentialUnavailable),
                receipt_persisted: true,
            })
            .unwrap();
        attempt.attempt_ordinal += 1;
        attempt.record_sequence += 1;
        attempt.recorded_at += 1;
        attempt.grant_revision = 2;
        registry
            .publish_revision(&GrantRevision {
                tenant: attempt.tenant.clone(),
                incarnation: attempt.incarnation.clone(),
                revision: 2,
            })
            .unwrap();
        let second_handoff = reservation(&attempt);
        assert_eq!(
            first_handoff.reservation.binding,
            second_handoff.reservation.binding
        );
        assert_ne!(
            first_handoff.reservation.reference,
            second_handoff.reservation.reference
        );
        let grant = registry.issue(&attempt, 20000).unwrap();
        assert!(matches!(
            registry.consume(&attempt, &grant.permit, &second_handoff, 1),
            Err(EgressError::BudgetRefused)
        ));
        assert!(registry.receipt(&attempt.attempt_id()).unwrap().is_none());
        registry
            .consume(&attempt, &grant.permit, &second_handoff, 2)
            .unwrap();
    }

    #[test]
    fn reconciliation_projects_canonical_usage_into_every_receipt_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.sqlite");
        let mut registry = open(&path);
        let attempt = attempt();
        let grant = registry.issue(&attempt, 20000).unwrap();
        let receipt = registry
            .consume(&attempt, &grant.permit, &reservation(&attempt), 20000)
            .unwrap();
        let usage = symbiotic_trace::UsageTrace {
            input_tokens: Some(7),
            output_tokens: Some(3),
            ..Default::default()
        };
        let tx = registry
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        SqliteSpendLedger::finish_in(
            &tx,
            &receipt.reference,
            SpendState::Settled,
            Some(usage.clone()),
            None,
        )
        .unwrap();
        tx.commit().unwrap();
        drop(registry);
        let mut registry = open(&path);
        let retained = registry.receipt(&attempt.attempt_id()).unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&retained.usage).unwrap(),
            serde_json::to_value(&usage).unwrap()
        );
        let AttemptStatus::Dispatched { receipt: projected } =
            registry.issue(&attempt, 20000).unwrap().status
        else {
            panic!("expected accepted attempt");
        };
        assert_eq!(
            serde_json::to_value(&projected.usage).unwrap(),
            serde_json::to_value(&usage).unwrap()
        );
        let AttemptStatus::Dispatched { receipt: projected } = registry
            .attempt_status(&attempt.attempt_id(), now().unwrap())
            .unwrap()
        else {
            panic!("expected accepted attempt");
        };
        assert_eq!(
            serde_json::to_value(&projected.usage).unwrap(),
            serde_json::to_value(&usage).unwrap()
        );
    }

    #[test]
    fn retry_requires_a_released_foundation_ledger_predecessor() {
        for charge in [SpendState::Settled, SpendState::Unknown] {
            let dir = tempfile::tempdir().unwrap();
            let mut registry = open(&dir.path().join("registry.sqlite"));
            let mut attempt = attempt();
            let permit = registry.issue(&attempt, 20000).unwrap().permit;
            let mut receipt = registry
                .consume(&attempt, &permit, &reservation(&attempt), 20000)
                .unwrap();
            receipt.spend_state = charge;
            if charge == SpendState::Settled {
                receipt.usage.input_tokens = Some(1);
            }
            registry
                .finish(&DispatchResult {
                    diagnostics: Vec::new(),
                    receipt,
                    output: None,
                    error: Some(EgressError::CredentialUnavailable),
                    receipt_persisted: true,
                })
                .unwrap();
            attempt.attempt_ordinal += 1;
            attempt.record_sequence += 1;
            assert!(matches!(
                registry.issue(&attempt, 20000),
                Err(EgressError::ReconciliationRequired)
            ));
        }
    }
    #[test]
    fn recovery_expiry_is_exclusive_and_purges_only_result() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = open(&dir.path().join("registry.sqlite"));
        let attempt = attempt();
        let grant = registry.issue(&attempt, 20000).unwrap();
        assert!(matches!(
            registry
                .attempt_status(&attempt.attempt_id(), now().unwrap())
                .unwrap(),
            AttemptStatus::Permitted
        ));
        let mut receipt = registry
            .consume(&attempt, &grant.permit, &reservation(&attempt), 20000)
            .unwrap();
        assert!(matches!(
            registry
                .attempt_status(&attempt.attempt_id(), now().unwrap())
                .unwrap(),
            AttemptStatus::Dispatched {
                receipt: DispatchReceipt {
                    spend_state: SpendState::Unknown,
                    ..
                }
            }
        ));
        receipt.status = DispatchStatus::Succeeded;
        receipt.spend_state = SpendState::Settled;
        receipt.usage.input_tokens = Some(1);
        registry
            .finish(&DispatchResult {
                diagnostics: Vec::new(),
                receipt,
                output: Some(ProviderOutput::Chat {
                    text: "retained".into(),
                    finish_reason: None,
                }),
                error: None,
                receipt_persisted: true,
            })
            .unwrap();
        let id = attempt.attempt_id();
        assert!(matches!(
            registry
                .attempt_status(&id, attempt.recovery_expires_at - 1)
                .unwrap(),
            AttemptStatus::Completed { .. }
        ));
        assert!(matches!(
            registry
                .attempt_status(&id, attempt.recovery_expires_at)
                .unwrap(),
            AttemptStatus::Expired
        ));
        registry.purge_expired(attempt.recovery_expires_at).unwrap();
        assert_eq!(
            registry
                .0
                .query_row(
                    "SELECT count(*) FROM egress_permits WHERE result IS NOT NULL",
                    [],
                    |row| row.get::<_, u64>(0)
                )
                .unwrap(),
            0
        );
        assert!(registry.receipt(&attempt.attempt_id()).unwrap().is_some());
        assert!(matches!(
            registry.consume(&attempt, &grant.permit, &reservation(&attempt), 20000),
            Err(EgressError::PermitRefused)
        ));
    }

    #[test]
    fn obsolete_registry_versions_are_refused_without_migration() {
        for version in [1, 2, 3, 4, 5, 6, 8] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("registry.sqlite");
            symbiotic_ai_runtime::model::private_fs::ensure_private_file(&path).unwrap();
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE egress_permits (attempt_digest TEXT PRIMARY KEY);
                CREATE TABLE egress_schema (version INTEGER NOT NULL);",
            )
            .unwrap();
            conn.execute("INSERT INTO egress_schema VALUES (?1)", [version])
                .unwrap();
            drop(conn);
            assert!(matches!(Registry::open(&path), Err(EgressError::Version)));
            let conn = Connection::open(&path).unwrap();
            assert_eq!(
                conn.query_row("SELECT version FROM egress_schema", [], |r| r
                    .get::<_, u16>(0))
                    .unwrap(),
                version
            );
        }
    }
}
