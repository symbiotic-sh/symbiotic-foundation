//! Provider-neutral durable queue contracts and a local SQLite backend.
//!
//! The queue is intentionally model-agnostic. Model/provider code chooses the
//! `queue_id`; this crate enforces durable work semantics for that id.

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use symbiotic_core::{QueueId, QueueItemId};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Dead,
}

impl QueueStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Dead => "dead",
        }
    }

    fn from_str(value: &str) -> Result<Self, QueueError> {
        match value {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "dead" => Ok(Self::Dead),
            other => Err(QueueError::Storage(format!("unknown queue status {other}"))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuePolicy {
    pub queue_id: QueueId,
    pub max_in_flight: usize,
    pub lease_seconds: u64,
    pub max_attempts: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnqueueRequest {
    pub queue_id: QueueId,
    pub kind: String,
    pub payload: Value,
    pub idempotency_key: Option<String>,
    pub run_after: Option<DateTime<Utc>>,
    pub max_attempts: Option<u32>,
    #[serde(default)]
    pub force: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnqueueDisposition {
    Inserted,
    ActiveDuplicate,
    TerminalDuplicate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnqueueOutcome {
    pub item: QueueItem,
    pub disposition: EnqueueDisposition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueueItem {
    pub item_id: QueueItemId,
    pub queue_id: QueueId,
    pub kind: String,
    pub payload: Value,
    pub status: QueueStatus,
    pub attempt: u32,
    pub max_attempts: u32,
    pub run_after: DateTime<Utc>,
    pub lease_owner: Option<String>,
    pub lease_until: Option<DateTime<Utc>>,
    pub idempotency_key: Option<String>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub queue_id: QueueId,
    pub worker_id: String,
    pub limit: usize,
    pub lease_seconds: u64,
    #[serde(default)]
    pub max_in_flight: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueueEvent {
    pub item_id: QueueItemId,
    pub queue_id: QueueId,
    pub kind: String,
    pub status: QueueStatus,
    pub attempt: u32,
    pub timestamp: DateTime<Utc>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailOutcome {
    RetryScheduled,
    MovedToDead,
}

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("queue item not found: {0}")]
    NotFound(String),
    #[error("queue item is not leased by worker: {0}")]
    LeaseMismatch(String),
    #[error("queue item is not running: {0}")]
    NotRunning(String),
    #[error("queue backend unavailable: {0}")]
    Unavailable(String),
    #[error("queue backend rejected request: {0}")]
    InvalidRequest(String),
    #[error("queue storage failed: {0}")]
    Storage(String),
}

#[async_trait]
pub trait QueueBackend: Send + Sync {
    async fn enqueue(&self, request: EnqueueRequest) -> Result<EnqueueOutcome, QueueError>;
    async fn claim(&self, request: ClaimRequest) -> Result<Vec<QueueItem>, QueueError>;
    async fn claim_item(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
        max_in_flight: Option<usize>,
    ) -> Result<Option<QueueItem>, QueueError>;
    async fn get_item(&self, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError>;
    async fn heartbeat(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<(), QueueError>;
    async fn complete(&self, item_id: &QueueItemId, worker_id: &str) -> Result<(), QueueError>;
    async fn fail(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        error: &str,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError>;
    async fn reclaim_expired_leases(&self, queue_id: &QueueId) -> Result<usize, QueueError>;
    async fn cooldown_until(
        &self,
        _queue_id: &QueueId,
    ) -> Result<Option<DateTime<Utc>>, QueueError> {
        Ok(None)
    }
    async fn note_cooldown(
        &self,
        _queue_id: &QueueId,
        _until: DateTime<Utc>,
    ) -> Result<(), QueueError> {
        Ok(())
    }
}

#[async_trait]
pub trait QueueEventSink: Send + Sync {
    async fn record_queue_event(&self, event: QueueEvent);
}

#[derive(Clone)]
pub struct SqliteQueue {
    conn: Arc<Mutex<Connection>>,
    event_sink: Option<Arc<dyn QueueEventSink>>,
}

impl SqliteQueue {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QueueError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(storage_error)?;
        }
        let conn = Connection::open(path).map_err(storage_error)?;
        configure(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            event_sink: None,
        })
    }

    pub fn in_memory() -> Result<Self, QueueError> {
        let conn = Connection::open_in_memory().map_err(storage_error)?;
        configure(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            event_sink: None,
        })
    }

    pub fn with_event_sink(mut self, sink: Arc<dyn QueueEventSink>) -> Self {
        self.event_sink = Some(sink);
        self
    }

    pub fn get(&self, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let mut stmt = conn
            .prepare(
                "select item_id, queue_id, kind, payload_json, status, attempt, max_attempts,
                        run_after, lease_owner, lease_until, idempotency_key, last_error,
                        created_at, updated_at
                 from queue_items where item_id = ?1",
            )
            .map_err(storage_error)?;
        stmt.query_row(params![item_id.0], row_to_item)
            .optional()
            .map_err(storage_error)
    }

    pub fn events(&self) -> Result<Vec<QueueEvent>, QueueError> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let mut stmt = conn
            .prepare(
                "select item_id, queue_id, kind, status, attempt, timestamp, error
                 from queue_events
                 order by event_id asc",
            )
            .map_err(storage_error)?;
        stmt.query_map([], row_to_event)
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)
    }

    pub async fn mark_stale_active_dead(
        &self,
        queue_id: &QueueId,
        stale_before: DateTime<Utc>,
        reason: &str,
    ) -> Result<usize, QueueError> {
        self.mark_stale_active_dead_inner(Some(queue_id), stale_before, reason)
            .await
    }

    pub async fn mark_all_stale_active_dead(
        &self,
        stale_before: DateTime<Utc>,
        reason: &str,
    ) -> Result<usize, QueueError> {
        self.mark_stale_active_dead_inner(None, stale_before, reason)
            .await
    }

    async fn mark_stale_active_dead_inner(
        &self,
        queue_id: Option<&QueueId>,
        stale_before: DateTime<Utc>,
        reason: &str,
    ) -> Result<usize, QueueError> {
        if reason.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                "stale queue cleanup reason must not be empty".to_string(),
            ));
        }
        let now = Utc::now();
        let (updated, items) = {
            let mut conn = self.conn.lock().map_err(lock_error)?;
            let tx = conn.transaction().map_err(storage_error)?;
            let items = stale_active_items_in_tx(&tx, queue_id, stale_before, now)?;
            let updated = match queue_id {
                Some(queue_id) => tx
                    .execute(
                        "update queue_items
                         set status = 'dead',
                             lease_owner = null,
                             lease_until = null,
                             last_error = ?3,
                             updated_at = ?4
                         where queue_id = ?1
                           and status in ('pending', 'failed', 'running')
                           and updated_at < ?2
                           and (status != 'running' or lease_until is null or lease_until < ?4)",
                        params![queue_id.0, ts(stale_before), reason, ts(now)],
                    )
                    .map_err(storage_error)?,
                None => tx
                    .execute(
                        "update queue_items
                         set status = 'dead',
                             lease_owner = null,
                             lease_until = null,
                             last_error = ?2,
                             updated_at = ?3
                         where status in ('pending', 'failed', 'running')
                           and updated_at < ?1
                           and (status != 'running' or lease_until is null or lease_until < ?3)",
                        params![ts(stale_before), reason, ts(now)],
                    )
                    .map_err(storage_error)?,
            };
            for mut item in items.clone() {
                item.status = QueueStatus::Dead;
                item.lease_owner = None;
                item.lease_until = None;
                item.last_error = Some(reason.to_string());
                item.updated_at = now;
                insert_event(&tx, &item, Some(reason.to_string()))?;
            }
            tx.commit().map_err(storage_error)?;
            (updated, items)
        };
        if let Some(sink) = &self.event_sink {
            for mut item in items {
                item.status = QueueStatus::Dead;
                item.lease_owner = None;
                item.lease_until = None;
                item.last_error = Some(reason.to_string());
                item.updated_at = now;
                sink.record_queue_event(QueueEvent {
                    item_id: item.item_id,
                    queue_id: item.queue_id,
                    kind: item.kind,
                    status: item.status,
                    attempt: item.attempt,
                    timestamp: Utc::now(),
                    error: Some(reason.to_string()),
                })
                .await;
            }
        }
        Ok(updated)
    }

    fn record_event_sync(&self, item: &QueueItem, error: Option<String>) -> Result<(), QueueError> {
        let conn = self.conn.lock().map_err(lock_error)?;
        insert_event(&conn, item, error)?;
        Ok(())
    }

    async fn emit(&self, item: QueueItem, error: Option<String>) {
        let _ = self.record_event_sync(&item, error.clone());
        if let Some(sink) = &self.event_sink {
            sink.record_queue_event(QueueEvent {
                item_id: item.item_id,
                queue_id: item.queue_id,
                kind: item.kind,
                status: item.status,
                attempt: item.attempt,
                timestamp: Utc::now(),
                error,
            })
            .await;
        }
    }
}

#[async_trait]
impl QueueBackend for SqliteQueue {
    async fn enqueue(&self, request: EnqueueRequest) -> Result<EnqueueOutcome, QueueError> {
        if request.kind.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                "queue item kind must not be empty".to_string(),
            ));
        }
        let now = Utc::now();
        let run_after = request.run_after.unwrap_or(now);
        let max_attempts = request.max_attempts.unwrap_or(3).max(1);
        let payload = serde_json::to_string(&request.payload).map_err(storage_error)?;

        let (item, disposition) = {
            let mut conn = self.conn.lock().map_err(lock_error)?;
            let tx = conn.transaction().map_err(storage_error)?;
            if let Some(key) = &request.idempotency_key {
                let existing = find_by_idempotency(&tx, &request.queue_id, key)?;
                if let Some(existing) = existing {
                    let active = matches!(
                        existing.status,
                        QueueStatus::Pending | QueueStatus::Running | QueueStatus::Failed
                    );
                    let terminal =
                        matches!(existing.status, QueueStatus::Succeeded | QueueStatus::Dead);
                    if active || (terminal && !request.force) {
                        tx.commit().map_err(storage_error)?;
                        let disposition = if active {
                            EnqueueDisposition::ActiveDuplicate
                        } else {
                            EnqueueDisposition::TerminalDuplicate
                        };
                        return Ok(EnqueueOutcome {
                            item: existing,
                            disposition,
                        });
                    }
                }
            }

            let item = QueueItem {
                item_id: QueueItemId::new(),
                queue_id: request.queue_id,
                kind: request.kind,
                payload: request.payload,
                status: QueueStatus::Pending,
                attempt: 0,
                max_attempts,
                run_after,
                lease_owner: None,
                lease_until: None,
                idempotency_key: request.idempotency_key,
                last_error: None,
                created_at: now,
                updated_at: now,
            };
            if let Err(err) = tx.execute(
                "insert into queue_items
                 (item_id, queue_id, kind, payload_json, status, attempt, max_attempts,
                  run_after, lease_owner, lease_until, idempotency_key, last_error, created_at, updated_at)
                 values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, null, null, ?9, null, ?10, ?11)",
                params![
                    item.item_id.0,
                    item.queue_id.0,
                    item.kind,
                    payload,
                    item.status.as_str(),
                    item.attempt,
                    item.max_attempts,
                    ts(item.run_after),
                    item.idempotency_key,
                    ts(item.created_at),
                    ts(item.updated_at),
                ],
            ) {
                if let Some(key) = &item.idempotency_key {
                    if is_unique_constraint(&err) {
                        if let Some(existing) = find_by_idempotency(&tx, &item.queue_id, key)? {
                            tx.commit().map_err(storage_error)?;
                            return Ok(EnqueueOutcome {
                                item: existing,
                                disposition: EnqueueDisposition::ActiveDuplicate,
                            });
                        }
                    }
                }
                return Err(storage_error(err));
            }
            tx.commit().map_err(storage_error)?;
            (item, EnqueueDisposition::Inserted)
        };

        self.emit(item.clone(), None).await;
        Ok(EnqueueOutcome { item, disposition })
    }

    async fn claim(&self, request: ClaimRequest) -> Result<Vec<QueueItem>, QueueError> {
        if request.worker_id.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                "worker_id must not be empty".to_string(),
            ));
        }
        let now = Utc::now();
        let lease_until = now + ChronoDuration::seconds(request.lease_seconds.max(1) as i64);
        let mut limit = request.limit.max(1);
        let claimed = {
            let mut conn = self.conn.lock().map_err(lock_error)?;
            let tx = conn.transaction().map_err(storage_error)?;
            reclaim_expired_in_tx(&tx, &request.queue_id, now)?;
            if let Some(max_in_flight) = request.max_in_flight {
                let running: i64 = tx
                    .query_row(
                        "select count(*) from queue_items
                         where queue_id = ?1 and status = 'running'",
                        params![request.queue_id.0],
                        |row| row.get(0),
                    )
                    .map_err(storage_error)?;
                if running >= max_in_flight as i64 {
                    tx.commit().map_err(storage_error)?;
                    return Ok(Vec::new());
                }
                limit = limit.min(max_in_flight.saturating_sub(running as usize));
            }
            let ids = {
                let mut stmt = tx
                    .prepare(
                        "select item_id from queue_items
                         where queue_id = ?1
                           and status in ('pending', 'failed')
                           and run_after <= ?2
                         order by run_after asc, created_at asc
                         limit ?3",
                    )
                    .map_err(storage_error)?;
                stmt.query_map(params![request.queue_id.0, ts(now), limit as i64], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(storage_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage_error)?
            };
            let mut out = Vec::new();
            for id in ids {
                let updated = tx
                    .execute(
                        "update queue_items
                     set status = 'running',
                         attempt = attempt + 1,
                         lease_owner = ?2,
                         lease_until = ?3,
                         updated_at = ?4
                    where item_id = ?1
                       and status in ('pending', 'failed')",
                        params![id, request.worker_id, ts(lease_until), ts(now)],
                    )
                    .map_err(storage_error)?;
                if updated == 1
                    && let Some(item) = get_in_tx(&tx, &QueueItemId(id))?
                {
                    out.push(item);
                }
            }
            tx.commit().map_err(storage_error)?;
            out
        };
        for item in claimed.clone() {
            self.emit(item, None).await;
        }
        Ok(claimed)
    }

    async fn claim_item(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
        max_in_flight: Option<usize>,
    ) -> Result<Option<QueueItem>, QueueError> {
        if worker_id.trim().is_empty() {
            return Err(QueueError::InvalidRequest(
                "worker_id must not be empty".to_string(),
            ));
        }
        let now = Utc::now();
        let lease_until = now + ChronoDuration::seconds(lease_seconds.max(1) as i64);
        let claimed = {
            let mut conn = self.conn.lock().map_err(lock_error)?;
            let tx = conn.transaction().map_err(storage_error)?;
            let item = get_required(&tx, item_id)?;
            reclaim_expired_in_tx(&tx, &item.queue_id, now)?;
            if let Some(max_in_flight) = max_in_flight {
                let running: i64 = tx
                    .query_row(
                        "select count(*) from queue_items
                         where queue_id = ?1 and status = 'running'",
                        params![item.queue_id.0],
                        |row| row.get(0),
                    )
                    .map_err(storage_error)?;
                if running >= max_in_flight as i64 {
                    tx.commit().map_err(storage_error)?;
                    return Ok(None);
                }
            }
            let refreshed = get_required(&tx, item_id)?;
            if !matches!(refreshed.status, QueueStatus::Pending | QueueStatus::Failed)
                || refreshed.run_after > now
            {
                tx.commit().map_err(storage_error)?;
                return Ok(None);
            }
            let updated = tx
                .execute(
                    "update queue_items
                 set status = 'running',
                     attempt = attempt + 1,
                     lease_owner = ?2,
                     lease_until = ?3,
                     updated_at = ?4
                where item_id = ?1
                   and status in ('pending', 'failed')",
                    params![item_id.0, worker_id, ts(lease_until), ts(now)],
                )
                .map_err(storage_error)?;
            if updated != 1 {
                tx.commit().map_err(storage_error)?;
                return Ok(None);
            }
            let claimed = get_required(&tx, item_id)?;
            tx.commit().map_err(storage_error)?;
            Some(claimed)
        };
        if let Some(item) = claimed.clone() {
            self.emit(item, None).await;
        }
        Ok(claimed)
    }

    async fn get_item(&self, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError> {
        self.get(item_id)
    }

    async fn heartbeat(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<(), QueueError> {
        let now = Utc::now();
        let lease_until = now + ChronoDuration::seconds(lease_seconds.max(1) as i64);
        let item = update_running_item(&self.conn, item_id, worker_id, |conn| {
            conn.execute(
                "update queue_items set lease_until = ?2, updated_at = ?3 where item_id = ?1",
                params![item_id.0, ts(lease_until), ts(now)],
            )
            .map_err(storage_error)?;
            get_required(conn, item_id)
        })?;
        self.emit(item, None).await;
        Ok(())
    }

    async fn complete(&self, item_id: &QueueItemId, worker_id: &str) -> Result<(), QueueError> {
        let now = Utc::now();
        let item = update_running_item(&self.conn, item_id, worker_id, |conn| {
            conn.execute(
                "update queue_items
                 set status = 'succeeded',
                     lease_owner = null,
                     lease_until = null,
                     last_error = null,
                     updated_at = ?2
                 where item_id = ?1",
                params![item_id.0, ts(now)],
            )
            .map_err(storage_error)?;
            get_required(conn, item_id)
        })?;
        self.emit(item, None).await;
        Ok(())
    }

    async fn fail(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        error: &str,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError> {
        let now = Utc::now();
        let (item, outcome) = update_running_item(&self.conn, item_id, worker_id, |conn| {
            let item = get_required(conn, item_id)?;
            let exhausted = item.attempt >= item.max_attempts;
            let status = if exhausted {
                QueueStatus::Dead
            } else {
                QueueStatus::Failed
            };
            let run_after = now + ChronoDuration::seconds(retry_after_seconds.unwrap_or(1) as i64);
            conn.execute(
                "update queue_items
                 set status = ?2,
                     run_after = ?3,
                     lease_owner = null,
                     lease_until = null,
                     last_error = ?4,
                     updated_at = ?5
                 where item_id = ?1",
                params![item_id.0, status.as_str(), ts(run_after), error, ts(now)],
            )
            .map_err(storage_error)?;
            let updated = get_required(conn, item_id)?;
            let outcome = if exhausted {
                FailOutcome::MovedToDead
            } else {
                FailOutcome::RetryScheduled
            };
            Ok((updated, outcome))
        })?;
        self.emit(item, Some(error.to_string())).await;
        Ok(outcome)
    }

    async fn reclaim_expired_leases(&self, queue_id: &QueueId) -> Result<usize, QueueError> {
        let now = Utc::now();
        let (reclaimed, events) = {
            let mut conn = self.conn.lock().map_err(lock_error)?;
            let tx = conn.transaction().map_err(storage_error)?;
            let expired = expired_running_items_in_tx(&tx, queue_id, now)?;
            let reclaimed = reclaim_expired_in_tx(&tx, queue_id, now)?;
            let events = expired
                .into_iter()
                .map(|mut item| {
                    item.status = QueueStatus::Failed;
                    item.lease_owner = None;
                    item.lease_until = None;
                    item.last_error
                        .get_or_insert_with(|| "lease expired".to_string());
                    item.updated_at = now;
                    insert_event(&tx, &item, Some("lease expired".to_string()))?;
                    Ok(item)
                })
                .collect::<Result<Vec<_>, QueueError>>()?;
            tx.commit().map_err(storage_error)?;
            (reclaimed, events)
        };
        if let Some(sink) = &self.event_sink {
            for item in events {
                sink.record_queue_event(QueueEvent {
                    item_id: item.item_id,
                    queue_id: item.queue_id,
                    kind: item.kind,
                    status: item.status,
                    attempt: item.attempt,
                    timestamp: Utc::now(),
                    error: Some("lease expired".to_string()),
                })
                .await;
            }
        }
        Ok(reclaimed)
    }

    async fn cooldown_until(
        &self,
        queue_id: &QueueId,
    ) -> Result<Option<DateTime<Utc>>, QueueError> {
        let conn = self.conn.lock().map_err(lock_error)?;
        let raw: Option<String> = conn
            .query_row(
                "select cooldown_until from queue_cooldowns where queue_id = ?1",
                params![queue_id.0],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?;
        raw.map(|value| parse_ts(value).map_err(|err| QueueError::Storage(err.to_string())))
            .transpose()
    }

    async fn note_cooldown(
        &self,
        queue_id: &QueueId,
        until: DateTime<Utc>,
    ) -> Result<(), QueueError> {
        let now = Utc::now();
        let conn = self.conn.lock().map_err(lock_error)?;
        conn.execute(
            "insert into queue_cooldowns(queue_id, cooldown_until, updated_at)
             values (?1, ?2, ?3)
             on conflict(queue_id) do update set
               cooldown_until = case
                 when queue_cooldowns.cooldown_until < excluded.cooldown_until
                 then excluded.cooldown_until
                 else queue_cooldowns.cooldown_until
               end,
               updated_at = excluded.updated_at",
            params![queue_id.0, ts(until), ts(now)],
        )
        .map_err(storage_error)?;
        Ok(())
    }
}

fn configure(conn: &Connection) -> Result<(), QueueError> {
    conn.busy_timeout(std::time::Duration::from_millis(sqlite_busy_timeout_ms()))
        .map_err(storage_error)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(storage_error)?;
    conn.execute_batch(
        "
        create table if not exists queue_items (
            item_id text primary key,
            queue_id text not null,
            kind text not null,
            payload_json text not null,
            status text not null,
            attempt integer not null,
            max_attempts integer not null,
            run_after text not null,
            lease_owner text,
            lease_until text,
            idempotency_key text,
            last_error text,
            created_at text not null,
            updated_at text not null
        );
        create index if not exists idx_queue_claim
            on queue_items(queue_id, status, run_after, created_at);
        create index if not exists idx_queue_idempotency
            on queue_items(queue_id, idempotency_key);
        create unique index if not exists idx_queue_active_idempotency
            on queue_items(queue_id, idempotency_key)
            where idempotency_key is not null
              and status in ('pending', 'running', 'failed');
        create table if not exists queue_events (
            event_id integer primary key autoincrement,
            item_id text not null,
            queue_id text not null,
            kind text not null,
            status text not null,
            attempt integer not null,
            timestamp text not null,
            error text
        );
        create table if not exists queue_cooldowns (
            queue_id text primary key,
            cooldown_until text not null,
            updated_at text not null
        );
        ",
    )
    .map_err(storage_error)?;
    Ok(())
}

fn sqlite_busy_timeout_ms() -> u64 {
    std::env::var("SYMBIOTIC_QUEUE_SQLITE_BUSY_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(60_000)
}

fn find_by_idempotency(
    conn: &Connection,
    queue_id: &QueueId,
    key: &str,
) -> Result<Option<QueueItem>, QueueError> {
    let mut stmt = conn
        .prepare(
            "select item_id, queue_id, kind, payload_json, status, attempt, max_attempts,
                    run_after, lease_owner, lease_until, idempotency_key, last_error,
                    created_at, updated_at
             from queue_items
             where queue_id = ?1 and idempotency_key = ?2
             order by created_at desc
             limit 1",
        )
        .map_err(storage_error)?;
    stmt.query_row(params![queue_id.0, key], row_to_item)
        .optional()
        .map_err(storage_error)
}

fn get_in_tx(conn: &Connection, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError> {
    let mut stmt = conn
        .prepare(
            "select item_id, queue_id, kind, payload_json, status, attempt, max_attempts,
                    run_after, lease_owner, lease_until, idempotency_key, last_error,
                    created_at, updated_at
             from queue_items where item_id = ?1",
        )
        .map_err(storage_error)?;
    stmt.query_row(params![item_id.0], row_to_item)
        .optional()
        .map_err(storage_error)
}

fn get_required(conn: &Connection, item_id: &QueueItemId) -> Result<QueueItem, QueueError> {
    get_in_tx(conn, item_id)?.ok_or_else(|| QueueError::NotFound(item_id.0.clone()))
}

fn update_running_item<T>(
    conn: &Arc<Mutex<Connection>>,
    item_id: &QueueItemId,
    worker_id: &str,
    update: impl FnOnce(&Connection) -> Result<T, QueueError>,
) -> Result<T, QueueError> {
    let mut conn = conn.lock().map_err(lock_error)?;
    let tx = conn.transaction().map_err(storage_error)?;
    let current = get_required(&tx, item_id)?;
    if current.status != QueueStatus::Running {
        return Err(QueueError::NotRunning(item_id.0.clone()));
    }
    if current.lease_owner.as_deref() != Some(worker_id) {
        return Err(QueueError::LeaseMismatch(item_id.0.clone()));
    }
    if current
        .lease_until
        .is_none_or(|lease_until| lease_until < Utc::now())
    {
        return Err(QueueError::LeaseMismatch(format!(
            "{} lease expired",
            item_id.0
        )));
    }
    let value = update(&tx)?;
    tx.commit().map_err(storage_error)?;
    Ok(value)
}

fn expired_running_items_in_tx(
    conn: &Connection,
    queue_id: &QueueId,
    now: DateTime<Utc>,
) -> Result<Vec<QueueItem>, QueueError> {
    let mut stmt = conn
        .prepare(
            "select item_id, queue_id, kind, payload_json, status, attempt, max_attempts,
                    run_after, lease_owner, lease_until, idempotency_key, last_error,
                    created_at, updated_at
             from queue_items
             where queue_id = ?1
               and status = 'running'
               and lease_until is not null
               and lease_until < ?2
             order by updated_at asc",
        )
        .map_err(storage_error)?;
    stmt.query_map(params![queue_id.0, ts(now)], row_to_item)
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)
}

fn stale_active_items_in_tx(
    conn: &Connection,
    queue_id: Option<&QueueId>,
    stale_before: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Vec<QueueItem>, QueueError> {
    match queue_id {
        Some(queue_id) => {
            let mut stmt = conn
                .prepare(
                    "select item_id, queue_id, kind, payload_json, status, attempt, max_attempts,
                            run_after, lease_owner, lease_until, idempotency_key, last_error,
                            created_at, updated_at
                     from queue_items
                     where queue_id = ?1
                       and status in ('pending', 'failed', 'running')
                       and updated_at < ?2
                       and (status != 'running' or lease_until is null or lease_until < ?3)
                     order by updated_at asc",
                )
                .map_err(storage_error)?;
            stmt.query_map(params![queue_id.0, ts(stale_before), ts(now)], row_to_item)
                .map_err(storage_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage_error)
        }
        None => {
            let mut stmt = conn
                .prepare(
                    "select item_id, queue_id, kind, payload_json, status, attempt, max_attempts,
                            run_after, lease_owner, lease_until, idempotency_key, last_error,
                            created_at, updated_at
                     from queue_items
                     where status in ('pending', 'failed', 'running')
                       and updated_at < ?1
                       and (status != 'running' or lease_until is null or lease_until < ?2)
                     order by updated_at asc",
                )
                .map_err(storage_error)?;
            stmt.query_map(params![ts(stale_before), ts(now)], row_to_item)
                .map_err(storage_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage_error)
        }
    }
}

fn reclaim_expired_in_tx(
    conn: &Connection,
    queue_id: &QueueId,
    now: DateTime<Utc>,
) -> Result<usize, QueueError> {
    conn.execute(
        "update queue_items
         set status = 'failed',
             lease_owner = null,
             lease_until = null,
             updated_at = ?2,
             last_error = coalesce(last_error, 'lease expired')
         where queue_id = ?1
           and status = 'running'
           and lease_until is not null
           and lease_until < ?2",
        params![queue_id.0, ts(now)],
    )
    .map_err(storage_error)
}

fn insert_event(
    conn: &Connection,
    item: &QueueItem,
    error: Option<String>,
) -> Result<(), QueueError> {
    conn.execute(
        "insert into queue_events
         (item_id, queue_id, kind, status, attempt, timestamp, error)
         values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            item.item_id.0,
            item.queue_id.0,
            item.kind,
            item.status.as_str(),
            item.attempt,
            ts(Utc::now()),
            error
        ],
    )
    .map_err(storage_error)?;
    Ok(())
}

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueItem> {
    let payload_json: String = row.get(3)?;
    let status: String = row.get(4)?;
    Ok(QueueItem {
        item_id: QueueItemId(row.get(0)?),
        queue_id: QueueId(row.get(1)?),
        kind: row.get(2)?,
        payload: serde_json::from_str(&payload_json).map_err(json_to_sql)?,
        status: QueueStatus::from_str(&status).map_err(queue_to_sql)?,
        attempt: row.get(5)?,
        max_attempts: row.get(6)?,
        run_after: parse_ts(row.get::<_, String>(7)?).map_err(queue_to_sql)?,
        lease_owner: row.get(8)?,
        lease_until: row
            .get::<_, Option<String>>(9)?
            .map(parse_ts)
            .transpose()
            .map_err(queue_to_sql)?,
        idempotency_key: row.get(10)?,
        last_error: row.get(11)?,
        created_at: parse_ts(row.get::<_, String>(12)?).map_err(queue_to_sql)?,
        updated_at: parse_ts(row.get::<_, String>(13)?).map_err(queue_to_sql)?,
    })
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueEvent> {
    let status: String = row.get(3)?;
    Ok(QueueEvent {
        item_id: QueueItemId(row.get(0)?),
        queue_id: QueueId(row.get(1)?),
        kind: row.get(2)?,
        status: QueueStatus::from_str(&status).map_err(queue_to_sql)?,
        attempt: row.get(4)?,
        timestamp: parse_ts(row.get::<_, String>(5)?).map_err(queue_to_sql)?,
        error: row.get(6)?,
    })
}

fn ts(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

fn parse_ts(value: String) -> Result<DateTime<Utc>, QueueError> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| QueueError::Storage(err.to_string()))
}

fn storage_error(error: impl std::fmt::Display) -> QueueError {
    QueueError::Storage(error.to_string())
}

fn lock_error(_: std::sync::PoisonError<std::sync::MutexGuard<'_, Connection>>) -> QueueError {
    QueueError::Unavailable("sqlite queue lock poisoned".to_string())
}

fn json_to_sql(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
}

fn queue_to_sql(error: QueueError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(error))
}

fn is_unique_constraint(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

/// Latency distribution over millisecond samples (nearest-rank percentiles).
///
/// Additive-only: `serde(default)` so persisted summaries keep loading as
/// fields are added.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LatencyStats {
    pub count: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub max_ms: u64,
}

impl LatencyStats {
    pub fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Self {
            count: sorted.len() as u64,
            p50_ms: nearest_rank(&sorted, 50),
            p95_ms: nearest_rank(&sorted, 95),
            max_ms: *sorted.last().expect("non-empty samples"),
        }
    }
}

/// Nearest-rank percentile over an ascending-sorted, non-empty sample set.
fn nearest_rank(sorted: &[u64], percentile: u64) -> u64 {
    let rank = (percentile * sorted.len() as u64).div_ceil(100).max(1);
    sorted[(rank - 1) as usize]
}

/// Per-queue latency summary separating the three phases of a queued provider
/// call: semaphore wait (`queue_wait`), rate-bucket wait (`throttle_wait`), and
/// the provider HTTP call itself (`provider`). Throttle-wait vs http-time is
/// the split that matters when diagnosing slow/serial queues — measure it here
/// instead of reasoning from configured rates.
///
/// Additive-only: `serde(default)` so persisted summaries keep loading as
/// fields are added.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueTelemetrySummary {
    pub queue_id: String,
    pub queue_wait: LatencyStats,
    pub throttle_wait: LatencyStats,
    pub provider: LatencyStats,
}

#[derive(Clone, Debug, Default)]
struct QueueTelemetrySamples {
    queue_wait_ms: Vec<u64>,
    throttle_wait_ms: Vec<u64>,
    provider_ms: Vec<u64>,
}

/// Accumulates per-queue latency samples and folds them into
/// [`QueueTelemetrySummary`] rows. Pure in-memory math, deliberately decoupled
/// from any recorded trace type so hosts can feed it from whatever telemetry
/// they already persist (JSONL queue events, timing traces, ...). Keyed by the
/// plain queue-id string so both `QueueId` newtypes and raw strings fit.
#[derive(Clone, Debug, Default)]
pub struct QueueTelemetryAccumulator {
    queues: BTreeMap<String, QueueTelemetrySamples>,
}

impl QueueTelemetryAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_queue_wait(&mut self, queue_id: &str, ms: u64) {
        self.samples(queue_id).queue_wait_ms.push(ms);
    }

    pub fn observe_throttle_wait(&mut self, queue_id: &str, ms: u64) {
        self.samples(queue_id).throttle_wait_ms.push(ms);
    }

    pub fn observe_provider(&mut self, queue_id: &str, ms: u64) {
        self.samples(queue_id).provider_ms.push(ms);
    }

    /// Summaries for every observed queue, ordered by queue id.
    pub fn summaries(&self) -> Vec<QueueTelemetrySummary> {
        self.queues
            .iter()
            .map(|(queue_id, samples)| QueueTelemetrySummary {
                queue_id: queue_id.clone(),
                queue_wait: LatencyStats::from_samples(&samples.queue_wait_ms),
                throttle_wait: LatencyStats::from_samples(&samples.throttle_wait_ms),
                provider: LatencyStats::from_samples(&samples.provider_ms),
            })
            .collect()
    }

    fn samples(&mut self, queue_id: &str) -> &mut QueueTelemetrySamples {
        self.queues.entry(queue_id.to_string()).or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn request(key: &str) -> EnqueueRequest {
        EnqueueRequest {
            queue_id: QueueId::new("chat:deepseek:pro"),
            kind: "chat".to_string(),
            payload: serde_json::json!({"hello": "world"}),
            idempotency_key: Some(key.to_string()),
            run_after: None,
            max_attempts: Some(2),
            force: false,
        }
    }

    #[test]
    fn queue_telemetry_summaries_report_nearest_rank_percentiles() {
        let mut accumulator = QueueTelemetryAccumulator::new();
        for ms in 1..=100 {
            accumulator.observe_throttle_wait("chat:deepseek:pro", ms);
        }
        accumulator.observe_provider("chat:deepseek:pro", 40);
        accumulator.observe_provider("chat:deepseek:pro", 10);
        accumulator.observe_provider("chat:deepseek:pro", 20);
        accumulator.observe_queue_wait("chat:acme:other", 7);

        let summaries = accumulator.summaries();
        assert_eq!(summaries.len(), 2);
        // Ordered by queue id.
        assert_eq!(summaries[0].queue_id, "chat:acme:other");
        assert_eq!(summaries[1].queue_id, "chat:deepseek:pro");

        let deepseek = &summaries[1];
        assert_eq!(deepseek.throttle_wait.count, 100);
        assert_eq!(deepseek.throttle_wait.p50_ms, 50);
        assert_eq!(deepseek.throttle_wait.p95_ms, 95);
        assert_eq!(deepseek.throttle_wait.max_ms, 100);
        assert_eq!(deepseek.provider.count, 3);
        assert_eq!(deepseek.provider.p50_ms, 20);
        assert_eq!(deepseek.provider.p95_ms, 40);
        assert_eq!(deepseek.provider.max_ms, 40);
        // No queue-wait samples observed for this queue: empty stats, not a panic.
        assert_eq!(deepseek.queue_wait, LatencyStats::default());

        let other = &summaries[0];
        assert_eq!(other.queue_wait.count, 1);
        assert_eq!(other.queue_wait.p50_ms, 7);
        assert_eq!(other.queue_wait.p95_ms, 7);
    }

    #[test]
    fn sqlite_busy_timeout_defaults_to_longer_lock_wait() {
        unsafe {
            std::env::remove_var("SYMBIOTIC_QUEUE_SQLITE_BUSY_TIMEOUT_MS");
        }
        assert_eq!(sqlite_busy_timeout_ms(), 60_000);

        unsafe {
            std::env::set_var("SYMBIOTIC_QUEUE_SQLITE_BUSY_TIMEOUT_MS", "1500");
        }
        assert_eq!(sqlite_busy_timeout_ms(), 1500);

        unsafe {
            std::env::set_var("SYMBIOTIC_QUEUE_SQLITE_BUSY_TIMEOUT_MS", "0");
        }
        assert_eq!(sqlite_busy_timeout_ms(), 60_000);

        unsafe {
            std::env::remove_var("SYMBIOTIC_QUEUE_SQLITE_BUSY_TIMEOUT_MS");
        }
    }

    #[tokio::test]
    async fn enqueue_deduplicates_active_and_terminal_items() {
        let queue = SqliteQueue::in_memory().unwrap();
        let first = queue.enqueue(request("same")).await.unwrap();
        assert_eq!(first.disposition, EnqueueDisposition::Inserted);
        let duplicate = queue.enqueue(request("same")).await.unwrap();
        assert_eq!(duplicate.disposition, EnqueueDisposition::ActiveDuplicate);
        let claimed = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "w1".to_string(),
                limit: 1,
                lease_seconds: 60,
                max_in_flight: None,
            })
            .await
            .unwrap();
        queue.complete(&claimed[0].item_id, "w1").await.unwrap();

        let terminal = queue.enqueue(request("same")).await.unwrap();
        assert_eq!(terminal.disposition, EnqueueDisposition::TerminalDuplicate);
        let mut forced = request("same");
        forced.force = true;
        let inserted = queue.enqueue(forced).await.unwrap();
        assert_eq!(inserted.disposition, EnqueueDisposition::Inserted);
        assert_ne!(inserted.item.item_id.0, first.item.item_id.0);
    }

    #[tokio::test]
    async fn concurrent_claim_does_not_double_lease() {
        let queue = SqliteQueue::in_memory().unwrap();
        for idx in 0..25 {
            queue
                .enqueue(request(&format!("item-{idx}")))
                .await
                .unwrap();
        }
        let claimed = join_all((0..10).map(|idx| {
            let queue = queue.clone();
            async move {
                queue
                    .claim(ClaimRequest {
                        queue_id: QueueId::new("chat:deepseek:pro"),
                        worker_id: format!("worker-{idx}"),
                        limit: 3,
                        lease_seconds: 60,
                        max_in_flight: None,
                    })
                    .await
                    .unwrap()
            }
        }))
        .await;
        let mut ids = claimed
            .into_iter()
            .flatten()
            .map(|item| item.item_id.0)
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 25);
    }

    #[tokio::test]
    async fn multi_connection_enqueue_deduplicates_active_idempotency_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let first = SqliteQueue::open(&path).unwrap();
        let second = SqliteQueue::open(&path).unwrap();

        let outcomes = join_all(vec![
            first.enqueue(request("cross-process")),
            second.enqueue(request("cross-process")),
        ])
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

        let inserted = outcomes
            .iter()
            .filter(|outcome| outcome.disposition == EnqueueDisposition::Inserted)
            .count();
        let duplicates = outcomes
            .iter()
            .filter(|outcome| outcome.disposition == EnqueueDisposition::ActiveDuplicate)
            .count();
        assert_eq!(inserted, 1);
        assert_eq!(duplicates, 1);
        assert_eq!(outcomes[0].item.item_id.0, outcomes[1].item.item_id.0);
    }

    #[tokio::test]
    async fn multi_connection_claim_does_not_return_stale_loser() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let writer = SqliteQueue::open(&path).unwrap();
        for idx in 0..20 {
            writer
                .enqueue(request(&format!("multi-claim-{idx}")))
                .await
                .unwrap();
        }
        let first = SqliteQueue::open(&path).unwrap();
        let second = SqliteQueue::open(&path).unwrap();

        let claimed = join_all(vec![
            first.claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker-a".to_string(),
                limit: 20,
                lease_seconds: 60,
                max_in_flight: None,
            }),
            second.claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker-b".to_string(),
                limit: 20,
                lease_seconds: 60,
                max_in_flight: None,
            }),
        ])
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

        let mut ids = claimed
            .iter()
            .flat_map(|items| items.iter().map(|item| item.item_id.0.clone()))
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        let claimed_count = claimed.iter().map(Vec::len).sum::<usize>();
        assert_eq!(ids.len(), claimed_count);
        assert_eq!(claimed_count, 20);
    }

    #[tokio::test]
    async fn mark_stale_active_dead_preserves_fresh_and_live_running_items() {
        let queue = SqliteQueue::in_memory().unwrap();
        let queue_id = QueueId::new("chat:deepseek:pro");
        let stale_pending = queue.enqueue(request("stale-pending")).await.unwrap().item;
        let fresh_pending = queue.enqueue(request("fresh-pending")).await.unwrap().item;
        let stale_failed = queue.enqueue(request("stale-failed")).await.unwrap().item;
        let stale_running = queue.enqueue(request("stale-running")).await.unwrap().item;
        let live_running = queue.enqueue(request("live-running")).await.unwrap().item;

        {
            let conn = queue.conn.lock().unwrap();
            let old = ts(Utc::now() - ChronoDuration::hours(2));
            conn.execute(
                "update queue_items set updated_at = ?2 where item_id = ?1",
                params![stale_pending.item_id.0, old],
            )
            .unwrap();
            conn.execute(
                "update queue_items
                 set status = 'failed', attempt = 1, updated_at = ?2
                 where item_id = ?1",
                params![stale_failed.item_id.0, old],
            )
            .unwrap();
            conn.execute(
                "update queue_items
                 set status = 'running',
                     attempt = 1,
                     lease_owner = 'old-worker',
                     lease_until = ?2,
                     updated_at = ?3
                 where item_id = ?1",
                params![
                    stale_running.item_id.0,
                    ts(Utc::now() - ChronoDuration::hours(1)),
                    old
                ],
            )
            .unwrap();
            conn.execute(
                "update queue_items
                 set status = 'running',
                     attempt = 1,
                     lease_owner = 'live-worker',
                     lease_until = ?2,
                     updated_at = ?3
                 where item_id = ?1",
                params![
                    live_running.item_id.0,
                    ts(Utc::now() + ChronoDuration::hours(1)),
                    old
                ],
            )
            .unwrap();
        }

        let updated = queue
            .mark_stale_active_dead(
                &queue_id,
                Utc::now() - ChronoDuration::hours(1),
                "orphaned queue item",
            )
            .await
            .unwrap();
        assert_eq!(updated, 3);

        assert_eq!(
            queue.get(&stale_pending.item_id).unwrap().unwrap().status,
            QueueStatus::Dead
        );
        assert_eq!(
            queue.get(&stale_failed.item_id).unwrap().unwrap().status,
            QueueStatus::Dead
        );
        assert_eq!(
            queue.get(&stale_running.item_id).unwrap().unwrap().status,
            QueueStatus::Dead
        );
        assert_eq!(
            queue.get(&fresh_pending.item_id).unwrap().unwrap().status,
            QueueStatus::Pending
        );
        assert_eq!(
            queue.get(&live_running.item_id).unwrap().unwrap().status,
            QueueStatus::Running
        );
        let cleanup_events = queue
            .events()
            .unwrap()
            .into_iter()
            .filter(|event| event.error.as_deref() == Some("orphaned queue item"))
            .count();
        assert_eq!(cleanup_events, 3);
    }

    #[tokio::test]
    async fn fail_retries_until_dead_and_reopens_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let queue = SqliteQueue::open(&path).unwrap();
        queue.enqueue(request("retry")).await.unwrap();
        let claimed = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker".to_string(),
                limit: 1,
                lease_seconds: 60,
                max_in_flight: None,
            })
            .await
            .unwrap();
        assert_eq!(
            queue
                .fail(&claimed[0].item_id, "worker", "timeout", Some(0))
                .await
                .unwrap(),
            FailOutcome::RetryScheduled
        );
        let reopened = SqliteQueue::open(&path).unwrap();
        let claimed_again = reopened
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker".to_string(),
                limit: 1,
                lease_seconds: 60,
                max_in_flight: None,
            })
            .await
            .unwrap();
        assert_eq!(
            reopened
                .fail(&claimed_again[0].item_id, "worker", "timeout", Some(0))
                .await
                .unwrap(),
            FailOutcome::MovedToDead
        );
        assert_eq!(
            reopened.get(&claimed[0].item_id).unwrap().unwrap().status,
            QueueStatus::Dead
        );
    }

    #[tokio::test]
    async fn lease_owner_is_enforced() {
        let queue = SqliteQueue::in_memory().unwrap();
        queue.enqueue(request("lease")).await.unwrap();
        let claimed = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker".to_string(),
                limit: 1,
                lease_seconds: 60,
                max_in_flight: None,
            })
            .await
            .unwrap();
        let err = queue
            .complete(&claimed[0].item_id, "other")
            .await
            .unwrap_err();
        assert!(matches!(err, QueueError::LeaseMismatch(_)));
    }

    #[tokio::test]
    async fn expired_lease_cannot_complete_and_can_be_reclaimed() {
        let queue = SqliteQueue::in_memory().unwrap();
        queue.enqueue(request("expired")).await.unwrap();
        let claimed = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker".to_string(),
                limit: 1,
                lease_seconds: 1,
                max_in_flight: None,
            })
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let err = queue
            .complete(&claimed[0].item_id, "worker")
            .await
            .unwrap_err();
        assert!(matches!(err, QueueError::LeaseMismatch(_)));

        let reclaimed = queue
            .reclaim_expired_leases(&QueueId::new("chat:deepseek:pro"))
            .await
            .unwrap();
        assert_eq!(reclaimed, 1);
        let item = queue.get(&claimed[0].item_id).unwrap().unwrap();
        assert_eq!(item.status, QueueStatus::Failed);
        assert_eq!(item.last_error.as_deref(), Some("lease expired"));
        assert!(queue.events().unwrap().iter().any(|event| {
            event.item_id.0 == item.item_id.0
                && event.status == QueueStatus::Failed
                && event.error.as_deref() == Some("lease expired")
        }));
    }

    #[tokio::test]
    async fn complete_clears_previous_retry_error() {
        let queue = SqliteQueue::in_memory().unwrap();
        queue.enqueue(request("retry-clears-error")).await.unwrap();
        let claimed = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker".to_string(),
                limit: 1,
                lease_seconds: 60,
                max_in_flight: None,
            })
            .await
            .unwrap();
        assert_eq!(
            queue
                .fail(
                    &claimed[0].item_id,
                    "worker",
                    "temporary provider error",
                    Some(0)
                )
                .await
                .unwrap(),
            FailOutcome::RetryScheduled
        );
        let retried = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker".to_string(),
                limit: 1,
                lease_seconds: 60,
                max_in_flight: None,
            })
            .await
            .unwrap();
        queue.complete(&retried[0].item_id, "worker").await.unwrap();

        let item = queue.get(&retried[0].item_id).unwrap().unwrap();
        assert_eq!(item.status, QueueStatus::Succeeded);
        assert_eq!(item.last_error, None);
    }

    struct CountingSink(AtomicUsize);

    #[async_trait]
    impl QueueEventSink for CountingSink {
        async fn record_queue_event(&self, _event: QueueEvent) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn event_sink_receives_transitions() {
        let sink = Arc::new(CountingSink(AtomicUsize::new(0)));
        let queue = SqliteQueue::in_memory()
            .unwrap()
            .with_event_sink(sink.clone());
        queue.enqueue(request("event")).await.unwrap();
        let claimed = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker".to_string(),
                limit: 1,
                lease_seconds: 60,
                max_in_flight: None,
            })
            .await
            .unwrap();
        queue.complete(&claimed[0].item_id, "worker").await.unwrap();
        assert_eq!(sink.0.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn claim_respects_queue_max_in_flight() {
        let queue = SqliteQueue::in_memory().unwrap();
        for idx in 0..3 {
            queue
                .enqueue(request(&format!("capped-{idx}")))
                .await
                .unwrap();
        }
        let first = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker-a".to_string(),
                limit: 3,
                lease_seconds: 60,
                max_in_flight: Some(2),
            })
            .await
            .unwrap();
        assert_eq!(first.len(), 2);
        let second = queue
            .claim(ClaimRequest {
                queue_id: QueueId::new("chat:deepseek:pro"),
                worker_id: "worker-b".to_string(),
                limit: 1,
                lease_seconds: 60,
                max_in_flight: Some(2),
            })
            .await
            .unwrap();
        assert!(second.is_empty());
    }

    #[tokio::test]
    async fn claim_item_claims_only_requested_item() {
        let queue = SqliteQueue::in_memory().unwrap();
        let first = queue.enqueue(request("target-a")).await.unwrap().item;
        let second = queue.enqueue(request("target-b")).await.unwrap().item;
        let claimed = queue
            .claim_item(&second.item_id, "worker", 60, Some(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.item_id.0, second.item_id.0);
        assert_eq!(
            queue.get(&first.item_id).unwrap().unwrap().status,
            QueueStatus::Pending
        );
    }
}
