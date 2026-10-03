//! Runtime-owned timer for persistent retention sweeps.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;
use symbiotic_core::DiagnosticCode;
use symbiotic_model::{DirResponseCache, ModelError};
use symbiotic_queue_sqlite::SqliteQueue;
use tokio::sync::watch;

const ORPHANED: DiagnosticCode = DiagnosticCode::StaleQueueItem;

/// How long and how much of the response cache the sweep keeps.
pub(crate) struct ResponseRetention {
    pub(crate) cache: DirResponseCache,
    pub(crate) max_age: Option<Duration>,
    pub(crate) max_bytes: Option<u64>,
}

/// The shared retention operation used at open and on each timer tick.
pub(crate) struct Sweep {
    queue: SqliteQueue,
    retention: chrono::Duration,
    responses: ResponseRetention,
    recovery: crate::spend::SqliteSpendLedger,
}

impl Sweep {
    /// Use the runtime retention settings and its existing operational stores.
    pub(crate) fn new(
        queue: SqliteQueue,
        retention: Duration,
        responses: ResponseRetention,
        recovery: crate::spend::SqliteSpendLedger,
    ) -> Self {
        Self {
            queue,
            retention: chrono::Duration::from_std(retention)
                .unwrap_or_else(|_| chrono::Duration::days(3650)),
            responses,
            recovery,
        }
    }

    /// Validate the cache tree before any deletion, then drain expired recovery,
    /// retire old queue state and prune cached responses.
    pub(crate) fn maintain(&self) -> Result<(), ModelError> {
        self.responses.cache.validate_tree()?;
        self.recovery.expire_recovery()?;
        let cutoff = chrono::Utc::now() - self.retention;
        self.queue
            .retire_stale_active(cutoff, ORPHANED)
            .and_then(|_| self.queue.prune_terminal_before(cutoff))
            .map_err(|_err| ModelError::Queue(DiagnosticCode::QueueFailure))?;
        self.responses
            .cache
            .prune(self.responses.max_age, self.responses.max_bytes)?;
        Ok(())
    }
}

/// Lives on the shared runtime handle, never on providers or the worker itself.
/// A dedicated thread also supports opening a runtime outside a Tokio executor.
pub(crate) struct Maintenance {
    stop: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
    last_error: watch::Receiver<Option<ModelError>>,
}

impl Maintenance {
    /// Start the cancellable timer after the open-time sweep has succeeded.
    pub(crate) fn start(sweep: Sweep, interval: Duration) -> Result<Self, ModelError> {
        let (stop, stopped) = mpsc::channel();
        let (errors, last_error) = watch::channel(None);
        let worker = std::thread::Builder::new()
            .name("ai-runtime-maintenance".into())
            .spawn(move || loop {
                match stopped.recv_timeout(interval) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        if let Err(error) = sweep.maintain() {
                            tracing::warn!(code = %error.code(), "AI runtime maintenance failed");
                            errors.send_replace(Some(error));
                        }
                    }
                }
            })
            .map_err(|_| ModelError::Queue(DiagnosticCode::SpendLedgerUnavailable))?;
        Ok(Self {
            stop,
            worker: Some(worker),
            last_error,
        })
    }

    /// Retain the latest static failure diagnostic for the runtime handle.
    pub(crate) fn last_error(&self) -> Option<ModelError> {
        *self.last_error.borrow()
    }
}

impl Drop for Maintenance {
    fn drop(&mut self) {
        // A disconnected channel means the worker has already stopped.
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take()
            && let Err(panic) = worker.join()
        {
            if std::thread::panicking() {
                tracing::warn!("AI runtime maintenance worker panicked during shutdown");
            } else {
                std::panic::resume_unwind(panic);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbiotic_model::{SpendLedger, SpendReceiptRef, SpendReservation, SpendState};

    #[test]
    fn idle_runtime_maintenance_deletes_the_entire_expired_answer_backlog() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.path().join(crate::QUEUE_DATABASE);
        let _runtime = crate::Runtime::open(crate::RuntimeConfig {
            state_dir: Some(dir.path().to_path_buf()),
            maintenance_interval: Duration::from_millis(10),
            ..crate::RuntimeConfig::default()
        })
        .unwrap();
        let ledger = crate::spend::SqliteSpendLedger::open(&path)
            .unwrap()
            .with_retention(Duration::from_secs(60));
        for n in 0..129 {
            let r = SpendReservation {
                reference: SpendReceiptRef::new(format!("paid-{n}")).unwrap(),
                account: "account".into(),
                invocation: format!("explicit-{n}"),
                binding: "input".into(),
                request_limit: None,
            };
            ledger.reserve_explicit(&r, 3).unwrap();
            ledger
                .finish(
                    &r.reference,
                    SpendState::Unknown,
                    None,
                    Some(serde_json::json!({"answer":"private"})),
                )
                .unwrap();
        }
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute(
            "UPDATE spend_receipts SET recovery_expires_at='2000-01-01T00:00:00+00:00'",
            [],
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while conn
            .query_row(
                "SELECT count(*) FROM spend_receipts WHERE recovery IS NOT NULL",
                [],
                |r| r.get::<_, usize>(0),
            )
            .unwrap()
            != 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(conn.query_row(
            "SELECT count(*) FROM spend_receipts WHERE recovery IS NOT NULL OR recovery_expires_at IS NOT NULL",
            [], |r| r.get::<_, usize>(0)).unwrap(), 0);
        assert_eq!(
            conn.query_row("SELECT count(*) FROM spend_receipts", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            129
        );
    }

    #[cfg(unix)]
    #[test]
    fn refused_maintenance_preserves_expired_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.sqlite");
        let queue = SqliteQueue::open(&path).unwrap();
        let ledger = crate::spend::SqliteSpendLedger::open(&path)
            .unwrap()
            .with_retention(Duration::ZERO);
        let r = SpendReservation {
            reference: SpendReceiptRef::new("paid").unwrap(),
            account: "account".into(),
            invocation: "explicit".into(),
            binding: "input".into(),
            request_limit: None,
        };
        ledger.reserve_explicit(&r, 3).unwrap();
        ledger
            .finish(
                &r.reference,
                SpendState::Unknown,
                None,
                Some(serde_json::json!({"answer":"private"})),
            )
            .unwrap();
        let cache_root = dir.path().join("responses");
        std::os::unix::fs::symlink(dir.path().join("bystander"), &cache_root).unwrap();
        let maintained = Sweep::new(
            queue,
            Duration::from_secs(60),
            ResponseRetention {
                cache: DirResponseCache::new(cache_root),
                max_age: None,
                max_bytes: None,
            },
            ledger,
        );
        assert!(matches!(
            maintained.maintain(),
            Err(ModelError::Cache(
                symbiotic_core::DiagnosticCode::CachePathRefused
            ))
        ));
        assert_eq!(
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM spend_receipts WHERE recovery IS NOT NULL",
                    [],
                    |r| r.get::<_, usize>(0)
                )
                .unwrap(),
            1
        );
    }
}
