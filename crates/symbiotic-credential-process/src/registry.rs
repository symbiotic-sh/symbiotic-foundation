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
            // Every admitted predecessor must be a settled zero-charge failure.
            // Success is terminal and any other charge requires reconciliation,
            // so this invariant inductively covers the entire retry history.
            if !matches!(receipt.charge, ChargeReport::Measured { ref unit, amount: 0 }
                if unit == &a.reserved_budget.unit)
            {
                return Err(EgressError::ReconciliationRequired);
            }
        } else if a.attempt_ordinal != 1 {
            return Err(EgressError::InvalidRequest);
        }
        // Only the current reservation can spend: prior attempts were zero.
        if a.reserved_budget.amount > a.reserved_budget.invocation_limit
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

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> DurableAttempt {
        serde_json::from_value(serde_json::json!({
            "tenant": "tenant", "incarnation": "incarnation", "invocation_id": "retry",
            "attempt_ordinal": 1, "record_sequence": 1, "recorded_at": 100, "expires_at": 200,
            "caller_binding": "caller", "route": "chat", "destination": "https://example.test",
            "model": "model", "method": "POST", "secret_ref": "key", "manifest_ref": "manifest",
            "input_manifest_digest": "a".repeat(64), "input_digest": "b".repeat(64),
            "markings": [], "max_attempts": 20000,
            "reserved_budget": { "unit": "provider_requests", "amount": 1, "invocation_limit": 1 }
        }))
        .unwrap()
    }

    #[test]
    fn retry_admission_uses_bounded_indexed_work_with_large_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = Registry::open(&dir.path().join("registry.sqlite")).unwrap();
        let mut attempt = attempt();
        let permit = registry.issue(&attempt).unwrap();
        let mut receipt = registry.consume(&attempt, &permit).unwrap();
        receipt.status = DispatchStatus::CredentialUnavailable;
        receipt.charge = ChargeReport::Measured {
            unit: "provider_requests".into(),
            amount: 0,
        };
        registry.finish(&receipt).unwrap();
        // Populate settled zero-charge predecessors in one transaction. Each has
        // the same immutable binding; only sequence, ordinal and digest differ.
        registry
            .0
            .execute_batch(
                "WITH RECURSIVE ord(n) AS (
            VALUES(2) UNION ALL SELECT n+1 FROM ord WHERE n<10000
        ) INSERT INTO egress_permits
            SELECT printf('%064d', n), invocation_key, invocation_binding, n, n,
                   token_hash, 1, receipt FROM egress_permits, ord WHERE ordinal=1;",
            )
            .unwrap();
        attempt.attempt_ordinal = 10001;
        attempt.record_sequence = 10001;
        // Interrupt any admission needing 1,000 VM instructions. An indexed
        // predecessor lookup fits; an aggregate over 10,000 receipts cannot.
        registry.0.progress_handler(1000, Some(|| true));
        assert!(registry.issue(&attempt).is_ok());
    }

    #[test]
    fn retry_requires_a_zero_charge_predecessor_in_the_reserved_unit() {
        for charge in [
            ChargeReport::Measured {
                unit: "provider_requests".into(),
                amount: 1,
            },
            ChargeReport::Measured {
                unit: "other".into(),
                amount: 0,
            },
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut registry = Registry::open(&dir.path().join("registry.sqlite")).unwrap();
            let mut attempt = attempt();
            attempt.reserved_budget.invocation_limit = 10;
            let permit = registry.issue(&attempt).unwrap();
            let mut receipt = registry.consume(&attempt, &permit).unwrap();
            receipt.charge = charge;
            registry.finish(&receipt).unwrap();
            attempt.attempt_ordinal += 1;
            attempt.record_sequence += 1;
            assert!(matches!(
                registry.issue(&attempt),
                Err(EgressError::ReconciliationRequired)
            ));
        }
    }
}
