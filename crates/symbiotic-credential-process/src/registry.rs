//! Durable permit replay protection; no prompts, results, credentials or scheduling.
use rusqlite::{Connection, OptionalExtension, params};
use symbiotic_egress::*;
use uuid::Uuid;

pub(crate) struct Registry(Connection);

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
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;
            CREATE TABLE IF NOT EXISTS egress_permits (
                attempt_digest TEXT PRIMARY KEY,
                invocation_key TEXT NOT NULL,
                invocation_binding TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                record_sequence INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                receipt TEXT,
                UNIQUE(invocation_key, ordinal)
            );
            CREATE TABLE IF NOT EXISTS egress_revocations (
                route_key TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL
            );",
        )
        .map_err(state)?;
        Ok(Self(conn))
    }

    pub(crate) fn issue(&mut self, a: &DurableAttempt) -> Result<DispatchPermit, EgressError> {
        let attempt_digest = digest(a)?;
        let invocation_key = digest(&(&a.tenant, &a.incarnation, &a.invocation_id))?;
        let route_key = digest(&(&a.tenant, &a.incarnation, &a.route))?;
        let mut immutable = a.clone();
        immutable.attempt_ordinal = 0;
        immutable.record_sequence = 0;
        immutable.recorded_at = 0;
        let binding = digest(&immutable)?;
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(state)?;
        let revoked: Option<u64> = tx
            .query_row(
                "SELECT sequence FROM egress_revocations WHERE route_key=?1",
                [&route_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(state)?;
        if revoked.is_some_and(|sequence| a.record_sequence >= sequence) {
            return Err(EgressError::RouteRefused);
        }
        let previous: Option<(String, u32, Option<String>, u64)> = tx.query_row(
            "SELECT invocation_binding, ordinal, receipt, record_sequence FROM egress_permits WHERE invocation_key=?1 ORDER BY ordinal DESC LIMIT 1", [&invocation_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).optional().map_err(state)?;
        if let Some((old_binding, ordinal, receipt, record_sequence)) = previous {
            if old_binding != binding {
                return Err(EgressError::InvalidRequest);
            }
            if a.attempt_ordinal <= ordinal {
                return Err(EgressError::PermitRefused);
            }
            if a.attempt_ordinal != ordinal + 1 || a.record_sequence <= record_sequence {
                return Err(EgressError::InvalidRequest);
            }
            let receipt = receipt.ok_or(EgressError::ReconciliationRequired)?;
            let receipt: DispatchReceipt =
                serde_json::from_str(&receipt).map_err(|_| EgressError::StateUnavailable)?;
            if receipt.status == DispatchStatus::Succeeded {
                return Err(EgressError::InvocationComplete);
            }
            if matches!(receipt.charge, ChargeReport::Unknown { .. }) {
                return Err(EgressError::ReconciliationRequired);
            }
        } else if a.attempt_ordinal != 1 {
            return Err(EgressError::InvalidRequest);
        }
        // Unsettled permits retain their full one-request reservation. Settled
        // zero-charge failures release it; attempt count and spend are independent.
        let charged: u64 = tx.query_row(
            "SELECT COALESCE(SUM(COALESCE(json_extract(receipt, '$.charge.amount'), 1)), 0) FROM egress_permits WHERE invocation_key=?1",
            [&invocation_key], |row| row.get(0),
        ).map_err(state)?;
        if charged
            .checked_add(a.reserved_budget.amount)
            .is_none_or(|total| total > a.reserved_budget.invocation_limit)
            || a.attempt_ordinal > a.max_attempts
        {
            return Err(EgressError::BudgetRefused);
        }
        let token = Uuid::new_v4().to_string();
        tx.execute("INSERT INTO egress_permits (attempt_digest, invocation_key, invocation_binding, ordinal, token_hash, record_sequence) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![attempt_digest, invocation_key, binding, a.attempt_ordinal, digest(&token)?, a.record_sequence]).map_err(state)?;
        tx.commit().map_err(state)?;
        Ok(DispatchPermit {
            token,
            attempt_digest,
        })
    }

    pub(crate) fn revoke(&mut self, revocation: &RouteRevocation) -> Result<(), EgressError> {
        let key = digest(&(
            &revocation.tenant,
            &revocation.incarnation,
            &revocation.route,
        ))?;
        self.0.execute("INSERT INTO egress_revocations (route_key, sequence) VALUES (?1, ?2) ON CONFLICT(route_key) DO UPDATE SET sequence=MIN(sequence, excluded.sequence)", params![key, revocation.record_sequence]).map_err(state)?;
        Ok(())
    }

    pub(crate) fn consume(
        &mut self,
        attempt: &DurableAttempt,
        permit: &DispatchPermit,
    ) -> Result<DispatchReceipt, EgressError> {
        let attempt_digest = digest(attempt)?;
        if attempt_digest != permit.attempt_digest {
            return Err(EgressError::PermitRefused);
        }
        let receipt = DispatchReceipt {
            attempt_digest: attempt_digest.clone(),
            status: DispatchStatus::ProviderFailed,
            usage: Default::default(),
            charge: ChargeReport::Unknown {
                reserved: attempt.reserved_budget.clone(),
            },
        };
        let json = serde_json::to_string(&receipt).map_err(|_| EgressError::StateUnavailable)?;
        let changed = self.0.execute("UPDATE egress_permits SET consumed=1, receipt=?1 WHERE attempt_digest=?2 AND token_hash=?3 AND consumed=0", params![json, attempt_digest, digest(&permit.token)?]).map_err(state)?;
        if changed != 1 {
            return Err(EgressError::PermitRefused);
        }
        Ok(receipt)
    }

    pub(crate) fn finish(&mut self, receipt: &DispatchReceipt) -> Result<(), EgressError> {
        let json = serde_json::to_string(receipt).map_err(|_| EgressError::StateUnavailable)?;
        self.0
            .execute(
                "UPDATE egress_permits SET receipt=?1 WHERE attempt_digest=?2 AND consumed=1",
                params![json, receipt.attempt_digest],
            )
            .map_err(state)?;
        Ok(())
    }

    pub(crate) fn receipt(
        &self,
        attempt: &DurableAttempt,
    ) -> Result<Option<DispatchReceipt>, EgressError> {
        let json: Option<String> = self
            .0
            .query_row(
                "SELECT receipt FROM egress_permits WHERE attempt_digest=?1 AND consumed=1",
                [digest(attempt)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(state)?;
        json.map(|json| serde_json::from_str(&json).map_err(|_| EgressError::StateUnavailable))
            .transpose()
    }
}
