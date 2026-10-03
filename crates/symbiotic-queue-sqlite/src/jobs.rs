//! Backend-owned job SQL, also usable on the ledger's caller-supplied transaction.
use super::SqliteQueue;
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use serde::{Serialize, de::DeserializeOwned};
use symbiotic_queue::jobs::*;

const COLUMNS: &str = "scope, id, key, digest, job_group, owners, kind, execution, priority, state, final_state, payload, max_attempts, admission, generation, lease_until, checkpoint, cancel_requested, purged, output, origin, receipt, recovery_until, result_expired, created_at, finished_at, delivery_generation, delivery_until, diagnostic";

fn storage(_: impl std::fmt::Display) -> JobError {
    JobError::Storage
}
fn json(value: &impl Serialize) -> Result<String, JobError> {
    serde_json::to_string(value).map_err(storage)
}
fn optional_json<T: Serialize>(value: &Option<T>) -> Result<Option<String>, JobError> {
    value.as_ref().map(json).transpose()
}
fn stamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}
fn read_json<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> rusqlite::Result<T> {
    let raw: String = row.get(index)?;
    serde_json::from_str(&raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(e))
    })
}
fn read_optional_json<T: DeserializeOwned>(
    row: &Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<T>> {
    let raw: Option<String> = row.get(index)?;
    raw.map(|s| {
        serde_json::from_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })
    })
    .transpose()
}
fn read_record(row: &Row<'_>) -> rusqlite::Result<JobRecord> {
    Ok(JobRecord {
        id: JobId {
            scope: read_json(row, 0)?,
            id: row.get(1)?,
        },
        key: row.get(2)?,
        digest: row.get(3)?,
        group: row.get(4)?,
        owners: read_json(row, 5)?,
        kind: row.get(6)?,
        execution: read_json(row, 7)?,
        priority: read_json(row, 8)?,
        state: read_json(row, 9)?,
        final_state: read_optional_json(row, 10)?,
        payload: read_optional_json(row, 11)?,
        max_attempts: row.get(12)?,
        admission: read_optional_json(row, 13)?,
        generation: row.get(14)?,
        lease_until: row.get(15)?,
        checkpoint: read_optional_json(row, 16)?,
        cancel_requested: row.get(17)?,
        purged: row.get(18)?,
        output: read_optional_json(row, 19)?,
        origin: read_optional_json(row, 20)?,
        receipt: row.get(21)?,
        recovery_until: row.get(22)?,
        result_expired: row.get(23)?,
        created_at: row.get(24)?,
        finished_at: row.get(25)?,
        delivery_generation: row.get(26)?,
        delivery_until: row.get(27)?,
        diagnostic: read_optional_json(row, 28)?,
    })
}

/// Initialize job tables as part of the queue's atomic format initialization.
pub(super) fn initialize(tx: &Transaction<'_>) -> Result<(), rusqlite::Error> {
    tx.execute_batch(
        "CREATE TABLE jobs (
        scope TEXT NOT NULL,
        id TEXT NOT NULL,
        key TEXT NOT NULL,
        digest TEXT NOT NULL,
        job_group TEXT,
        owners TEXT NOT NULL,
        kind TEXT NOT NULL,
        execution TEXT NOT NULL,
        priority TEXT NOT NULL,
        state TEXT NOT NULL,
        final_state TEXT,
        payload TEXT,
        max_attempts INTEGER NOT NULL,
        admission TEXT,
        generation INTEGER NOT NULL,
        lease_until TEXT,
        checkpoint TEXT,
        cancel_requested INTEGER NOT NULL,
        purged INTEGER NOT NULL,
        output TEXT,
        origin TEXT,
        receipt TEXT,
        recovery_until TEXT,
        result_expired INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        finished_at TEXT,
        delivery_generation INTEGER NOT NULL,
        delivery_until TEXT,
        diagnostic TEXT,
        PRIMARY KEY(scope, id), UNIQUE(scope, key)
    );
    CREATE INDEX jobs_claim ON jobs(scope, state, priority, created_at, id);
    CREATE INDEX jobs_delivery ON jobs(scope, state, finished_at, id);
    CREATE INDEX jobs_expiry ON jobs(scope, recovery_until, id)
        WHERE result_expired=0 AND state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"');
    CREATE INDEX jobs_group ON jobs(scope, job_group, state, created_at, id);
    CREATE TABLE job_groups (
        scope TEXT NOT NULL, job_group TEXT NOT NULL, summary TEXT NOT NULL,
        PRIMARY KEY(scope, job_group)
    );",
    )
}

/// All SQL stays in this backend; dropping the caller's transaction rolls it back.
/// The caller must use an IMMEDIATE transaction to serialize checks, ledger and
/// job writes, and commit only after every participant succeeds. The connection
/// must first have been initialized with [`SqliteQueue::initialize_connection`].
pub fn jobs_in_transaction(
    tx: &mut Transaction<'_>,
    scope: &JobScope,
    config: &JobConfig,
    now: DateTime<Utc>,
    request: JobRequest,
) -> Result<JobResponse, JobError> {
    let savepoint = tx.savepoint().map_err(storage)?;
    let response = apply_job_request(
        &mut SqlRows { conn: &savepoint },
        scope,
        config,
        now,
        request,
    )?;
    savepoint.commit().map_err(storage)?;
    Ok(response)
}

struct SqlRows<'a> {
    conn: &'a Connection,
}
impl JobRows for SqlRows<'_> {
    fn get(&mut self, id: &JobId) -> Result<Option<JobRecord>, JobError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM jobs WHERE scope=?1 AND id=?2"),
                params![json(&id.scope)?, id.id],
                read_record,
            )
            .optional()
            .map_err(storage)
    }
    fn by_key(&mut self, scope: &JobScope, key: &str) -> Result<Option<JobRecord>, JobError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM jobs WHERE scope=?1 AND key=?2"),
                params![json(scope)?, key],
                read_record,
            )
            .optional()
            .map_err(storage)
    }
    fn select(
        &mut self,
        scope: &JobScope,
        query: JobQuery,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<JobRecord>, JobError> {
        let mut args = vec![rusqlite::types::Value::Text(json(scope)?)];
        let (filter, order) = match query {
            JobQuery::Group(group) => {
                args.push(group.into());
                ("job_group=?2".to_string(), "created_at, id")
            }
            JobQuery::Owner(owner) => {
                args.push(owner.into());
                (
                    "EXISTS (SELECT 1 FROM json_each(jobs.owners) WHERE value=?2)".to_string(),
                    "created_at, id",
                )
            }
            JobQuery::Pending { kinds, priority } => {
                args.push(json(&kinds)?.into());
                args.push(stamp(now).into());
                let mut filter = "(state='\"Pending\"' OR (state='\"Running\"' AND execution='\"Handler\"' AND lease_until<=?3)) AND kind IN (SELECT value FROM json_each(?2))".to_string();
                if let Some(priority) = priority {
                    args.push(json(&priority)?.into());
                    filter.push_str(" AND priority=?4");
                }
                (filter, "created_at, id")
            }
            JobQuery::Final => {
                args.push(stamp(now).into());
                ("state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"') AND (delivery_until IS NULL OR delivery_until<=?2)".to_string(), "finished_at, id")
            }
            JobQuery::Notices => (
                "state='\"AwaitingAdmission\"'".to_string(),
                "created_at, id",
            ),
            JobQuery::Expired => {
                args.push(stamp(now).into());
                ("state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"') AND result_expired=0 AND recovery_until<=?2".to_string(), "recovery_until, id")
            }
            JobQuery::Diagnostics { group, after } => {
                args.push(group.into());
                args.push(after.unwrap_or_default().into());
                ("job_group=?2 AND state IN ('\"Failed\"','\"Uncertain\"','\"AwaitingAdmission\"') AND id>?3".to_string(), "id")
            }
        };
        // Unlimited selections are only atomic group/owner operations; no read
        // API or maintenance pass exposes an unbounded selection.
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        args.push(limit.into());
        let sql = format!(
            "SELECT {COLUMNS} FROM jobs WHERE scope=?1 AND {filter} ORDER BY {order} LIMIT ?{}",
            args.len()
        );
        let mut stmt = self.conn.prepare(&sql).map_err(storage)?;
        stmt.query_map(rusqlite::params_from_iter(args), read_record)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)
    }
    fn save(&mut self, row: JobRecord) -> Result<(), JobError> {
        let old = self.get(&row.id)?;
        self.conn.execute("INSERT INTO jobs (scope, id, key, digest, job_group, owners, kind, execution, priority, state, final_state, payload, max_attempts, admission, generation, lease_until, checkpoint, cancel_requested, purged, output, origin, receipt, recovery_until, result_expired, created_at, finished_at, delivery_generation, delivery_until, diagnostic) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29) ON CONFLICT(scope,id) DO UPDATE SET key=excluded.key, digest=excluded.digest, job_group=excluded.job_group, owners=excluded.owners, kind=excluded.kind, execution=excluded.execution, priority=excluded.priority, state=excluded.state, final_state=excluded.final_state, payload=excluded.payload, max_attempts=excluded.max_attempts, admission=excluded.admission, generation=excluded.generation, lease_until=excluded.lease_until, checkpoint=excluded.checkpoint, cancel_requested=excluded.cancel_requested, purged=excluded.purged, output=excluded.output, origin=excluded.origin, receipt=excluded.receipt, recovery_until=excluded.recovery_until, result_expired=excluded.result_expired, created_at=excluded.created_at, finished_at=excluded.finished_at, delivery_generation=excluded.delivery_generation, delivery_until=excluded.delivery_until, diagnostic=excluded.diagnostic",
            params![
                json(&row.id.scope)?,
                &row.id.id,
                &row.key,
                &row.digest,
                &row.group,
                json(&row.owners)?,
                &row.kind,
                json(&row.execution)?,
                json(&row.priority)?,
                json(&row.state)?,
                optional_json(&row.final_state)?,
                optional_json(&row.payload)?,
                i64::from(row.max_attempts),
                optional_json(&row.admission)?,
                i64::try_from(row.generation).map_err(storage)?,
                row.lease_until.map(stamp),
                optional_json(&row.checkpoint)?,
                &row.cancel_requested,
                &row.purged,
                optional_json(&row.output)?,
                optional_json(&row.origin)?,
                &row.receipt,
                row.recovery_until.map(stamp),
                &row.result_expired,
                stamp(row.created_at),
                row.finished_at.map(stamp),
                i64::try_from(row.delivery_generation).map_err(storage)?,
                row.delivery_until.map(stamp),
                optional_json(&row.diagnostic)?,
            ]).map_err(storage)?;
        if let Some(group) = &row.group {
            let mut summary = self.summary(&row.id.scope, group, false)?;
            summary_transition(&mut summary, old.as_ref(), &row)?;
            summary.oldest_pending = self.conn.query_row(
                "SELECT min(created_at) FROM jobs WHERE scope=?1 AND job_group=?2 AND state='\"Pending\"'",
                params![json(&row.id.scope)?, group], |r| r.get(0)).map_err(storage)?;
            self.write_summary(&row.id.scope, group, &summary)?;
        }
        Ok(())
    }
    fn usage(&mut self, scope: &JobScope) -> Result<PendingUsage, JobError> {
        // The JSON tuple has exactly the same canonical fields as job_input_bytes.
        // CAST to BLOB counts UTF-8 bytes, rather than SQLite's character count.
        self.conn.query_row("SELECT count(*), coalesce(sum(length(CAST(json_array(json(scope),key,job_group,json(owners),kind,json(execution),json(priority),json(payload),json(admission),json(checkpoint),max_attempts) AS BLOB))),0) FROM jobs WHERE scope=?1 AND state IN ('\"Pending\"','\"AwaitingAdmission\"','\"Running\"','\"Uncertain\"')",
            [json(scope)?], |r| Ok(PendingUsage { items: r.get(0)?, bytes: r.get(1)? })).map_err(storage)
    }
    fn summary(
        &mut self,
        scope: &JobScope,
        group: &str,
        rebuild: bool,
    ) -> Result<GroupSummary, JobError> {
        if rebuild {
            let mut summary = GroupSummary::default();
            let mut stmt = self.conn.prepare("SELECT state, count(*) FROM jobs WHERE scope=?1 AND job_group=?2 GROUP BY state").map_err(storage)?;
            let counts = stmt
                .query_map(params![json(scope)?, group], |r| {
                    Ok((read_json(r, 0)?, r.get(1)?))
                })
                .map_err(storage)?;
            for count in counts {
                let (state, count) = count.map_err(storage)?;
                summary.counts.insert(state, count);
            }
            summary.oldest_pending = self.conn.query_row("SELECT min(created_at) FROM jobs WHERE scope=?1 AND job_group=?2 AND state='\"Pending\"'",
                params![json(scope)?, group], |r| r.get(0)).map_err(storage)?;
            self.write_summary(scope, group, &summary)?;
            return Ok(summary);
        }
        Ok(self
            .conn
            .query_row(
                "SELECT summary FROM job_groups WHERE scope=?1 AND job_group=?2",
                params![json(scope)?, group],
                |r| read_json(r, 0),
            )
            .optional()
            .map_err(storage)?
            .unwrap_or_default())
    }
}
impl SqlRows<'_> {
    fn write_summary(
        &self,
        scope: &JobScope,
        group: &str,
        summary: &GroupSummary,
    ) -> Result<(), JobError> {
        self.conn.execute("INSERT INTO job_groups(scope,job_group,summary) VALUES (?1,?2,?3) ON CONFLICT(scope,job_group) DO UPDATE SET summary=excluded.summary",
            params![json(scope)?, group, json(summary)?]).map_err(storage)?;
        Ok(())
    }
}

impl SqliteQueue {
    pub(super) fn job_operation(
        &self,
        scope: &JobScope,
        config: &JobConfig,
        now: DateTime<Utc>,
        request: JobRequest,
    ) -> Result<JobResponse, JobError> {
        let mut conn = self.conn.lock().map_err(storage)?;
        let mut tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage)?;
        let response = jobs_in_transaction(&mut tx, scope, config, now, request)?;
        tx.commit().map_err(storage)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use symbiotic_queue::QueueBackend;

    fn scope() -> JobScope {
        JobScope {
            tenant: "tenant".into(),
            incarnation: "restore".into(),
            queue: "queue".into(),
        }
    }
    fn spec(key: &str) -> JobSpec {
        JobSpec {
            key: key.into(),
            group: Some("group".into()),
            owners: vec!["owner".into()],
            kind: "handler".into(),
            execution: Execution::Handler,
            priority: Priority::Background,
            payload: json!({ "input": key }),
            limits: JobLimits { max_attempts: 3 },
            admission: None,
            recovery_until: None,
        }
    }
    fn count(conn: &Connection, table: &str) -> usize {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn jobs_caller_transaction_commit_and_rollback() {
        let mut conn = Connection::open_in_memory().unwrap();
        SqliteQueue::initialize_connection(&mut conn).unwrap();
        conn.execute_batch("CREATE TABLE caller_records (id INTEGER PRIMARY KEY)")
            .unwrap();
        let config = JobConfig::default();
        let now = Utc::now();
        {
            let mut tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            tx.execute("INSERT INTO caller_records VALUES (1)", [])
                .unwrap();
            jobs_in_transaction(
                &mut tx,
                &scope(),
                &config,
                now,
                JobRequest::Enqueue(vec![spec("rollback")]),
            )
            .unwrap();
            assert_eq!(count(&tx, "jobs"), 1);
            // Simulated crash/abort: caller record, job, and group roll back together.
        }
        assert_eq!(count(&conn, "caller_records"), 0);
        assert_eq!(count(&conn, "jobs"), 0);
        assert_eq!(count(&conn, "job_groups"), 0);
        {
            let mut tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            tx.execute("INSERT INTO caller_records VALUES (1)", [])
                .unwrap();
            jobs_in_transaction(
                &mut tx,
                &scope(),
                &config,
                now,
                JobRequest::Enqueue(vec![spec("commit")]),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(count(&conn, "caller_records"), 1);
        assert_eq!(count(&conn, "jobs"), 1);
        assert_eq!(count(&conn, "job_groups"), 1);
        {
            let mut tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            let mut conflict = spec("commit");
            conflict.payload = json!("conflict");
            assert!(matches!(
                jobs_in_transaction(
                    &mut tx,
                    &scope(),
                    &config,
                    now,
                    JobRequest::Enqueue(vec![spec("new"), conflict])
                ),
                Err(JobError::KeyConflict)
            ));
            // Even a caller that commits after handling the error cannot retain half a batch.
            tx.commit().unwrap();
        }
        assert_eq!(count(&conn, "jobs"), 1);
        assert_eq!(count(&conn, "job_groups"), 1);
    }

    #[tokio::test]
    async fn jobs_reopen_preserves_results_and_content_free_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let scope = scope();
        let config = JobConfig::default();
        let now = Utc::now();
        let queue = SqliteQueue::open(&path).unwrap();
        let id = match queue
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Enqueue(vec![spec("durable")]),
            )
            .await
            .unwrap()
        {
            JobResponse::Enqueued(mut v) => match v.remove(0) {
                Enqueued::Inserted(id) => id,
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        };
        let row = match queue
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Claim {
                    kinds: vec!["handler".into()],
                    slots_available: 1,
                    background_in_flight: 0,
                },
            )
            .await
            .unwrap()
        {
            JobResponse::Job(Some(r)) => r,
            other => panic!("{other:?}"),
        };
        queue
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Complete {
                    job: id.clone(),
                    generation: row.generation,
                    state: JobState::Succeeded,
                    origin: ResultOrigin::Handler,
                    output: Some(json!("durable answer")),
                    receipt: None,
                    diagnostic: None,
                },
            )
            .await
            .unwrap();
        drop(queue);
        let queue = SqliteQueue::open(&path).unwrap();
        let delivery = match queue
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Completions {
                    limit: 1,
                    max_bytes: 100_000,
                },
            )
            .await
            .unwrap()
        {
            JobResponse::Deliveries(mut v) => v.remove(0),
            other => panic!("{other:?}"),
        };
        assert_eq!(delivery.completion.output, Some(json!("durable answer")));
        queue
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Ack(vec![(delivery.token.unwrap(), Disposition::Accepted)]),
            )
            .await
            .unwrap();
        drop(queue);
        let queue = SqliteQueue::open(&path).unwrap();
        let result = queue
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Enqueue(vec![spec("durable")]),
            )
            .await
            .unwrap();
        match result {
            JobResponse::Enqueued(mut v) => match v.remove(0) {
                Enqueued::AlreadyDone(row) => {
                    assert_eq!(row.id, id);
                    assert_eq!(row.final_state, Some(JobState::Succeeded));
                    assert!(row.output.is_none() && row.payload.is_none());
                }
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn jobs_independent_connections_serialize_bounds_and_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let a = SqliteQueue::open(&path).unwrap();
        let b = SqliteQueue::open(&path).unwrap();
        let config = JobConfig {
            max_pending_items: 1,
            ..JobConfig::default()
        };
        let scope = scope();
        let now = Utc::now();
        // Both connections can read the initial state; capacity is checked only
        // after acquiring the writer lock, so the second operation cannot exceed it.
        a.jobs(&scope, &config, now, JobRequest::Enqueue(vec![spec("one")]))
            .await
            .unwrap();
        assert!(matches!(
            b.jobs(&scope, &config, now, JobRequest::Enqueue(vec![spec("two")]))
                .await,
            Err(JobError::QueueFull)
        ));
        let row = match b
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Claim {
                    kinds: vec!["handler".into()],
                    slots_available: 1,
                    background_in_flight: 0,
                },
            )
            .await
            .unwrap()
        {
            JobResponse::Job(Some(r)) => r,
            other => panic!("{other:?}"),
        };
        a.jobs(
            &scope,
            &config,
            now,
            JobRequest::Complete {
                job: row.id.clone(),
                generation: row.generation,
                state: JobState::Succeeded,
                origin: ResultOrigin::Handler,
                output: Some(json!("answer")),
                receipt: None,
                diagnostic: None,
            },
        )
        .await
        .unwrap();
        let token = match a
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Completions {
                    limit: 1,
                    max_bytes: 100_000,
                },
            )
            .await
            .unwrap()
        {
            JobResponse::Deliveries(mut v) => v.remove(0).token.unwrap(),
            other => panic!("{other:?}"),
        };
        a.jobs(
            &scope,
            &config,
            now,
            JobRequest::Ack(vec![(token.clone(), Disposition::Accepted)]),
        )
        .await
        .unwrap();
        match b
            .jobs(
                &scope,
                &config,
                now,
                JobRequest::Ack(vec![(token, Disposition::Discarded)]),
            )
            .await
            .unwrap()
        {
            JobResponse::Acks(v) => {
                assert_eq!(v, vec![AckResult::AlreadyAcked(Disposition::Accepted)])
            }
            other => panic!("{other:?}"),
        }
    }
}
