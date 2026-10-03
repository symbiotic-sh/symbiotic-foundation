//! Backend-owned job SQL, also usable on the ledger's caller-supplied transaction.
use super::SqliteQueue;
use chrono::{DateTime, Utc};
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
fn stamp(time: DateTime<Utc>) -> i64 {
    time.timestamp_millis()
}
fn read_time(row: &Row<'_>, index: usize) -> rusqlite::Result<DateTime<Utc>> {
    let raw: i64 = row.get(index)?;
    DateTime::from_timestamp_millis(raw).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(JobError::InvalidRequest),
        )
    })
}
fn read_optional_time(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<DateTime<Utc>>> {
    let raw: Option<i64> = row.get(index)?;
    raw.map(|_| read_time(row, index)).transpose()
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
        lease_until: read_optional_time(row, 15)?,
        checkpoint: read_optional_json(row, 16)?,
        cancel_requested: row.get(17)?,
        purged: row.get(18)?,
        output: read_optional_json(row, 19)?,
        origin: read_optional_json(row, 20)?,
        receipt: row.get(21)?,
        recovery_until: read_optional_time(row, 22)?,
        result_expired: row.get(23)?,
        created_at: read_time(row, 24)?,
        finished_at: read_optional_time(row, 25)?,
        delivery_generation: row.get(26)?,
        delivery_until: read_optional_time(row, 27)?,
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
        lease_until INTEGER,
        checkpoint TEXT,
        cancel_requested INTEGER NOT NULL,
        purged INTEGER NOT NULL,
        output TEXT,
        origin TEXT,
        receipt TEXT,
        recovery_until INTEGER,
        result_expired INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        finished_at INTEGER,
        delivery_generation INTEGER NOT NULL,
        delivery_until INTEGER,
        diagnostic TEXT,
        PRIMARY KEY(scope, id), UNIQUE(scope, key)
    );
    CREATE INDEX jobs_claim ON jobs(scope, created_at, id)
        WHERE state IN ('\"Pending\"','\"AwaitingAdmission\"','\"Running\"','\"Uncertain\"');
    CREATE INDEX jobs_delivery ON jobs(scope, finished_at, id)
        WHERE state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"');
    CREATE INDEX jobs_leased ON jobs(scope, delivery_until)
        WHERE delivery_until IS NOT NULL AND state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"');
    CREATE INDEX jobs_expiry ON jobs(scope, recovery_until, id)
        WHERE result_expired=0 AND state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"');
    CREATE INDEX jobs_group ON jobs(scope, job_group, id);
    CREATE INDEX jobs_unfinished_group ON jobs(scope, job_group, id)
        WHERE state IN ('\"Pending\"','\"AwaitingAdmission\"','\"Running\"','\"Uncertain\"');
    CREATE INDEX jobs_pending_group ON jobs(scope, job_group, created_at, id) WHERE state='\"Pending\"';
    CREATE INDEX jobs_diagnostics ON jobs(scope, job_group, id) WHERE state IN ('\"Failed\"','\"Uncertain\"');
    CREATE INDEX jobs_notices ON jobs(scope, created_at, id) WHERE state='\"AwaitingAdmission\"';
    CREATE INDEX jobs_notice_diagnostics ON jobs(scope, job_group, id) WHERE state='\"AwaitingAdmission\"';
    CREATE TABLE job_owners (
        scope TEXT NOT NULL, owner TEXT NOT NULL, job_id TEXT NOT NULL,
        PRIMARY KEY(scope, owner, job_id)
    );
    CREATE INDEX job_owners_job ON job_owners(scope, job_id);
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
    let response = apply_job_request(&mut SqlRows::new(&savepoint), scope, config, now, request)?;
    savepoint.commit().map_err(storage)?;
    Ok(response)
}

struct SqlRows<'a> {
    conn: &'a Connection,
    #[cfg(test)]
    metrics: Option<&'a QueryMetrics>,
}
#[cfg(test)]
#[derive(Default)]
struct QueryMetrics {
    steps: std::cell::Cell<i32>,
    plans: std::cell::RefCell<Vec<String>>,
}
impl<'a> SqlRows<'a> {
    fn new(conn: &'a Connection) -> Self {
        Self {
            conn,
            #[cfg(test)]
            metrics: None,
        }
    }
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
        let bound = i64::try_from(limit).map_err(|_| JobError::InvalidRequest)?;
        if let JobQuery::Diagnostics { group, after } = &query {
            // Each state class gets an ordered LIMIT before merging at most 2 * page.
            // Failed/Uncertain history stays in jobs_diagnostics; notices are separate.
            let mut selected = Vec::new();
            for (index, predicate) in [
                (
                    "jobs_diagnostics",
                    "state IN ('\"Failed\"','\"Uncertain\"')",
                ),
                ("jobs_notice_diagnostics", "state='\"AwaitingAdmission\"'"),
            ] {
                let sql = format!(
                    "SELECT {COLUMNS} FROM jobs INDEXED BY {index} WHERE scope=?1 AND job_group=?2 AND {predicate} AND id>?3 ORDER BY id LIMIT ?4"
                );
                selected.extend(self.read(
                    &sql,
                    vec![
                        json(scope)?.into(),
                        group.clone().into(),
                        after.clone().unwrap_or_default().into(),
                        bound.into(),
                    ],
                )?);
            }
            selected.sort_by(|a, b| a.id.id.cmp(&b.id.id));
            selected.truncate(limit);
            return Ok(selected);
        }
        if let JobQuery::Owner { owner, after } = query {
            let columns = COLUMNS
                .split(", ")
                .map(|c| format!("jobs.{c}"))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT {columns} FROM job_owners JOIN jobs ON jobs.scope=job_owners.scope AND jobs.id=job_owners.job_id WHERE job_owners.scope=?1 AND job_owners.owner=?2 AND job_owners.job_id>?3 ORDER BY job_owners.job_id LIMIT ?4"
            );
            return self.read(
                &sql,
                vec![
                    json(scope)?.into(),
                    owner.into(),
                    after.unwrap_or_default().into(),
                    bound.into(),
                ],
            );
        }
        let mut args = vec![rusqlite::types::Value::Text(json(scope)?)];
        let (filter, order, index) = match query {
            JobQuery::Group {
                group,
                after,
                unfinished,
            } => {
                args.push(group.into());
                args.push(after.unwrap_or_default().into());
                (
                    format!(
                        "job_group=?2 AND id>?3{}",
                        if unfinished {
                            " AND state IN ('\"Pending\"','\"AwaitingAdmission\"','\"Running\"','\"Uncertain\"')"
                        } else {
                            ""
                        }
                    ),
                    "id",
                    if unfinished {
                        "jobs_unfinished_group"
                    } else {
                        "jobs_group"
                    },
                )
            }
            JobQuery::Pending { kinds, priority } => {
                args.push(json(&kinds)?.into());
                args.push(stamp(now).into());
                let mut filter = "state IN ('\"Pending\"','\"AwaitingAdmission\"','\"Running\"','\"Uncertain\"') AND (state='\"Pending\"' OR (state='\"Running\"' AND execution='\"Handler\"' AND lease_until<=?3)) AND kind IN (SELECT value FROM json_each(?2))".to_string();
                if let Some(priority) = priority {
                    args.push(json(&priority)?.into());
                    filter.push_str(" AND priority=?4");
                }
                (filter, "created_at, id", "jobs_claim")
            }
            JobQuery::Final => {
                args.push(stamp(now).into());
                ("state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"') AND (delivery_until IS NULL OR delivery_until<=?2)".to_string(), "finished_at, id", "jobs_delivery")
            }
            JobQuery::Notices => (
                "state='\"AwaitingAdmission\"'".to_string(),
                "created_at, id",
                "jobs_notices",
            ),
            JobQuery::Expired => {
                args.push(stamp(now).into());
                ("state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"') AND result_expired=0 AND recovery_until<=?2".to_string(), "recovery_until, id", "jobs_expiry")
            }
            JobQuery::Diagnostics { .. } | JobQuery::Owner { .. } => {
                return Err(JobError::InvalidRequest);
            }
        };
        args.push(bound.into());
        let sql = format!(
            "SELECT {COLUMNS} FROM jobs INDEXED BY {index} WHERE scope=?1 AND {filter} ORDER BY {order} LIMIT ?{}",
            args.len()
        );
        self.read(&sql, args)
    }
    fn save(&mut self, row: JobRecord) -> Result<(), JobError> {
        // Validate before touching SQL, also when used directly by backend tests.
        millisecond_time(row.created_at)?;
        for time in [
            row.lease_until,
            row.recovery_until,
            row.finished_at,
            row.delivery_until,
        ]
        .into_iter()
        .flatten()
        {
            millisecond_time(time)?;
        }
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
        if old.as_ref().is_none_or(|old| old.owners != row.owners) {
            self.conn
                .execute(
                    "DELETE FROM job_owners WHERE scope=?1 AND job_id=?2",
                    params![json(&row.id.scope)?, row.id.id],
                )
                .map_err(storage)?;
            for owner in &row.owners {
                self.conn
                    .execute(
                        "INSERT INTO job_owners(scope,owner,job_id) VALUES (?1,?2,?3) ON CONFLICT(scope,owner,job_id) DO NOTHING",
                        params![json(&row.id.scope)?, owner, row.id.id],
                    )
                    .map_err(storage)?;
            }
        }
        if let Some(group) = &row.group {
            let mut summary = self.summary(&row.id.scope, group, None)?;
            summary_transition(&mut summary, old.as_ref(), &row)?;
            summary.oldest_pending = self.oldest_pending(&row.id.scope, group, &summary)?;
            self.write_summary(&row.id.scope, group, &summary)?;
        }
        Ok(())
    }
    fn usage(&mut self, scope: &JobScope) -> Result<PendingUsage, JobError> {
        // The JSON tuple has exactly the same canonical fields as job_input_bytes.
        // CAST to BLOB counts UTF-8 bytes, rather than SQLite's character count.
        self.conn.query_row("SELECT count(*), coalesce(sum(length(CAST(json_array(json(scope),key,job_group,json(owners),kind,json(execution),json(priority),json(payload),json(admission),json(checkpoint),max_attempts) AS BLOB))),0) FROM jobs INDEXED BY jobs_claim WHERE scope=?1 AND state IN ('\"Pending\"','\"AwaitingAdmission\"','\"Running\"','\"Uncertain\"')",
            [json(scope)?], |r| Ok(PendingUsage { items: r.get(0)?, bytes: r.get(1)? })).map_err(storage)
    }
    fn leased(&mut self, scope: &JobScope, now: DateTime<Utc>) -> Result<usize, JobError> {
        self.conn.query_row("SELECT count(*) FROM jobs INDEXED BY jobs_leased WHERE scope=?1 AND delivery_until IS NOT NULL AND delivery_until>?2 AND state IN ('\"Succeeded\"','\"Failed\"','\"Cancelled\"','\"Refused\"','\"Purged\"')", params![json(scope)?, stamp(now)], |r| r.get(0)).map_err(storage)
    }
    fn load_summary(&mut self, scope: &JobScope, group: &str) -> Result<GroupSummary, JobError> {
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
    fn save_summary(
        &mut self,
        scope: &JobScope,
        group: &str,
        summary: &GroupSummary,
    ) -> Result<(), JobError> {
        self.write_summary(scope, group, summary)
    }
    fn oldest_pending(
        &mut self,
        scope: &JobScope,
        group: &str,
        summary: &GroupSummary,
    ) -> Result<Option<DateTime<Utc>>, JobError> {
        self.pending_time(scope, group, summary)
    }
}
impl SqlRows<'_> {
    fn read(
        &self,
        sql: &str,
        args: Vec<rusqlite::types::Value>,
    ) -> Result<Vec<JobRecord>, JobError> {
        let mut stmt = self.conn.prepare(sql).map_err(storage)?;
        let records = stmt
            .query_map(rusqlite::params_from_iter(&args), read_record)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        #[cfg(test)]
        if let Some(metrics) = self.metrics {
            metrics
                .steps
                .set(metrics.steps.get() + stmt.get_status(rusqlite::StatementStatus::VmStep));
            let mut plan = self
                .conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .map_err(storage)?;
            let details = plan
                .query_map(rusqlite::params_from_iter(&args), |r| r.get::<_, String>(3))
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?;
            metrics.plans.borrow_mut().extend(details);
        }
        Ok(records)
    }
    fn pending_time(
        &self,
        scope: &JobScope,
        group: &str,
        summary: &GroupSummary,
    ) -> Result<Option<DateTime<Utc>>, JobError> {
        self.conn.query_row("SELECT created_at FROM jobs INDEXED BY jobs_pending_group WHERE scope=?1 AND job_group=?2 AND state='\"Pending\"' AND (?3=0 OR id<=?4) ORDER BY created_at,id LIMIT 1", params![json(scope)?, group, summary.rebuilding, summary.rebuild_after.as_deref().unwrap_or("")], |r| read_time(r, 0)).optional().map_err(storage)
    }
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
            JobResponse::Deliveries(mut v) => v.items.remove(0),
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
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [a.clone(), b.clone()]
            .into_iter()
            .enumerate()
            .map(|(i, queue)| {
                let barrier = barrier.clone();
                let scope = scope.clone();
                let config = config.clone();
                tokio::task::spawn_blocking(move || {
                    barrier.wait();
                    queue.job_operation(
                        &scope,
                        &config,
                        now,
                        JobRequest::Enqueue(vec![spec(&format!("concurrent-{i}"))]),
                    )
                })
            })
            .collect();
        let mut inserted = 0;
        let mut full = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(JobResponse::Enqueued(_)) => inserted += 1,
                Err(JobError::QueueFull) => full += 1,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!((inserted, full), (1, 1));
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
            JobResponse::Deliveries(mut v) => v.items.remove(0).token.unwrap(),
            other => panic!("{other:?}"),
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [
            (a.clone(), Disposition::Accepted),
            (b.clone(), Disposition::Discarded),
        ]
        .into_iter()
        .map(|(queue, disposition)| {
            let barrier = barrier.clone();
            let scope = scope.clone();
            let config = config.clone();
            let token = token.clone();
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                queue.job_operation(
                    &scope,
                    &config,
                    now,
                    JobRequest::Ack(vec![(token, disposition)]),
                )
            })
        })
        .collect();
        let mut results = Vec::new();
        for handle in handles {
            match handle.await.unwrap().unwrap() {
                JobResponse::Acks(mut v) => results.push(v.remove(0)),
                other => panic!("{other:?}"),
            }
        }
        let winner = results
            .iter()
            .find_map(|r| {
                if let AckResult::Acked(d) = r {
                    Some(*d)
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == AckResult::Acked(winner))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == AckResult::AlreadyAcked(winner))
                .count(),
            1
        );
        // A confirmation and a new admission must also overlap safely: neither
        // may lose the other's summary transition or retained-input bound check.
        let cross_id = match a
            .job_operation(
                &scope,
                &config,
                now,
                JobRequest::Enqueue(vec![spec("cross-final")]),
            )
            .unwrap()
        {
            JobResponse::Enqueued(mut v) => match v.remove(0) {
                Enqueued::Inserted(id) => id,
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        };
        a.job_operation(
            &scope,
            &config,
            now,
            JobRequest::Cancel(Selector::Ids(vec![cross_id.clone()])),
        )
        .unwrap();
        let cross_token = match a
            .job_operation(
                &scope,
                &config,
                now,
                JobRequest::Completions {
                    limit: 1,
                    max_bytes: 100_000,
                },
            )
            .unwrap()
        {
            JobResponse::Deliveries(mut page) => page.items.remove(0).token.unwrap(),
            other => panic!("{other:?}"),
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [
            (
                a.clone(),
                JobRequest::Ack(vec![(cross_token, Disposition::Accepted)]),
            ),
            (b.clone(), JobRequest::Enqueue(vec![spec("cross-admitted")])),
        ]
        .into_iter()
        .map(|(queue, request)| {
            let barrier = barrier.clone();
            let scope = scope.clone();
            let config = config.clone();
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                queue.job_operation(&scope, &config, now, request)
            })
        })
        .collect();
        for handle in handles {
            handle.await.unwrap().unwrap();
        }
        match a
            .job_operation(&scope, &config, now, JobRequest::Status("group".into()))
            .unwrap()
        {
            JobResponse::Summary(summary) => {
                assert_eq!(summary.counts.values().sum::<usize>(), 3);
                assert_eq!(summary.counts.get(&JobState::Pending), Some(&1));
                match b
                    .job_operation(
                        &scope,
                        &config,
                        now,
                        JobRequest::RebuildSummary("group".into()),
                    )
                    .unwrap()
                {
                    JobResponse::Summary(rebuilt) => assert_eq!(summary, rebuilt),
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    }
    #[test]
    fn jobs_indexed_pages_have_flat_work_and_cursor_plans() {
        let mut measurements = Vec::new();
        for retained in [10, 10_000] {
            let mut conn = Connection::open_in_memory().unwrap();
            SqliteQueue::initialize_connection(&mut conn).unwrap();
            let mut tx = conn.transaction().unwrap();
            let now = DateTime::from_timestamp_millis(1_000_000).unwrap();
            jobs_in_transaction(
                &mut tx,
                &scope(),
                &JobConfig::default(),
                now,
                JobRequest::Enqueue(vec![spec("template")]),
            )
            .unwrap();
            let mut store = SqlRows::new(&tx);
            let template = store.by_key(&scope(), "template").unwrap().unwrap();
            for i in 0..retained + 8 {
                let mut row = template.clone();
                row.id.id = if i < retained && i % 2 == 1 {
                    format!("zz-tail-{i:08}")
                } else {
                    format!("{i:08}")
                };
                row.key = row.id.id.clone();
                row.state = if i < retained {
                    if i % 2 == 0 {
                        JobState::Accepted
                    } else {
                        JobState::Failed
                    }
                } else {
                    JobState::Succeeded
                };
                row.payload = None;
                row.finished_at = Some(now);
                row.delivery_generation = 1;
                row.delivery_until = (i >= retained).then_some(now + chrono::Duration::seconds(30));
                store.save(row).unwrap();
            }
            let mut eligible = template.clone();
            eligible.id.id = "zz-eligible".into();
            eligible.key = "eligible".into();
            eligible.state = JobState::Failed;
            eligible.finished_at = Some(now);
            eligible.owners = vec!["target".into()];
            store.save(eligible.clone()).unwrap();
            let metrics = QueryMetrics::default();
            store.metrics = Some(&metrics);
            let finals = store.select(&scope(), JobQuery::Final, now, 1).unwrap();
            assert_eq!(finals[0].id, eligible.id);
            let delivery_steps = metrics.steps.replace(0);
            let diagnostics = store
                .select(
                    &scope(),
                    JobQuery::Diagnostics {
                        group: "group".into(),
                        after: None,
                    },
                    now,
                    1,
                )
                .unwrap();
            assert_eq!(diagnostics[0].id, eligible.id);
            let diagnostic_steps = metrics.steps.replace(0);
            let owner = store
                .select(
                    &scope(),
                    JobQuery::Owner {
                        owner: "target".into(),
                        after: None,
                    },
                    now,
                    1,
                )
                .unwrap();
            assert_eq!(owner[0].id, eligible.id);
            let owner_steps = metrics.steps.replace(0);
            let unfinished = store
                .select(
                    &scope(),
                    JobQuery::Group {
                        group: "group".into(),
                        after: None,
                        unfinished: true,
                    },
                    now,
                    1,
                )
                .unwrap();
            assert_eq!(unfinished[0].id, template.id);
            let group_steps = metrics.steps.get();
            // Actual EXPLAIN QUERY PLAN for the executed selectors:
            // SEARCH jobs USING INDEX jobs_delivery (scope=?)
            // SEARCH jobs USING INDEX jobs_diagnostics (scope=? AND job_group=? AND id>?)
            // SEARCH jobs USING INDEX jobs_notice_diagnostics (scope=? AND job_group=? AND id>?)
            let plans = metrics.plans.borrow();
            for index in [
                "jobs_delivery",
                "jobs_diagnostics",
                "jobs_notice_diagnostics",
                "sqlite_autoindex_job_owners_1",
                "jobs_unfinished_group",
            ] {
                assert!(plans.iter().any(|p| p.contains(index)), "{plans:?}");
            }
            assert!(
                plans
                    .iter()
                    .all(|p| !p.contains("SCAN") && !p.contains("TEMP B-TREE")),
                "{plans:?}"
            );
            assert!(
                delivery_steps < 300 && diagnostic_steps < 150,
                "{delivery_steps}, {diagnostic_steps}"
            );
            measurements.push((delivery_steps, diagnostic_steps, owner_steps, group_steps));
        }
        assert_eq!(
            measurements[0], measurements[1],
            "retained history must not affect selector work"
        );
        eprintln!(
            "delivery/diagnostic/owner/group VM steps at 10 vs 10,000 retained rows: {measurements:?}"
        );
    }

    #[test]
    fn jobs_numeric_timestamp_readers_reject_unsupported_integers() {
        let mut conn = Connection::open_in_memory().unwrap();
        SqliteQueue::initialize_connection(&mut conn).unwrap();
        let mut tx = conn.transaction().unwrap();
        jobs_in_transaction(
            &mut tx,
            &scope(),
            &JobConfig::default(),
            Utc::now(),
            JobRequest::Enqueue(vec![spec("time")]),
        )
        .unwrap();
        assert_eq!(
            tx.query_row("SELECT typeof(created_at) FROM jobs", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "integer"
        );
        tx.execute("UPDATE jobs SET created_at=?1", [i64::MAX])
            .unwrap();
        assert!(matches!(
            SqlRows::new(&tx).by_key(&scope(), "time"),
            Err(JobError::Storage)
        ));
    }
}
