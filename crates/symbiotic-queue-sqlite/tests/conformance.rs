//! The SQLite backend passes the shared `QueueBackend` conformance checks.

use std::sync::Arc;
use symbiotic_queue::QueueBackend;
use symbiotic_queue_sqlite::SqliteQueue;

symbiotic_queue::queue_backend_conformance!(|| Arc::new(
    SqliteQueue::in_memory().expect("open in-memory SQLite queue")
) as Arc<dyn QueueBackend>);
