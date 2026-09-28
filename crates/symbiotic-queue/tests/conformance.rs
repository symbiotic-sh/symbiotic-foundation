//! The in-process backend passes the shared `QueueBackend` conformance checks.
#![cfg(feature = "conformance")]

use std::sync::Arc;
use symbiotic_queue::{MemoryQueue, QueueBackend};

symbiotic_queue::queue_backend_conformance!(
    || Arc::new(MemoryQueue::new()) as Arc<dyn QueueBackend>
);
