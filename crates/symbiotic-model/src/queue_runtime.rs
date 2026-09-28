//! Shared state and seams of the queued providers: in-process admission,
//! usage receipts and the response cache.
//!
//! Hosts reach these through `symbiotic-ai-runtime`, which owns one set of
//! them per runtime. They are public because that crate composes them.

use crate::ModelError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use symbiotic_core::{QueueId, QueueItemId};
use symbiotic_queue::QueueBackend;
use symbiotic_trace::{CacheTrace, TraceSink, UsageTrace};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// In-process admission: one FIFO semaphore per `queue_id`, shared by every
/// queued provider built with the same `ModelAdmission`.
///
/// Callers wait here, in arrival order, for one of the model's
/// `max_in_flight` slots before they claim their queue item. That keeps the
/// model cap shared across providers and roles without polling the backend.
/// The backend still enforces the same cap, which also covers other
/// processes on a shared persistent backend.
///
/// The first provider admitted for a `queue_id` fixes its cap. A later one
/// asking for a different cap is a configuration error, not a silent
/// override.
#[derive(Clone, Default)]
pub struct ModelAdmission {
    gates: Arc<Mutex<AdmissionGates>>,
}

/// Per `queue_id`: the fixed cap and its semaphore.
type AdmissionGates = HashMap<String, (usize, Arc<Semaphore>)>;

impl ModelAdmission {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cap fixed for `queue_id`, if a provider was admitted for it.
    pub fn cap(&self, queue_id: &QueueId) -> Option<usize> {
        self.gates
            .lock()
            .ok()
            .and_then(|gates| gates.get(&queue_id.0).map(|(cap, _)| *cap))
    }

    /// Fix the cap for `queue_id`, or check it matches the fixed one.
    pub fn register(&self, queue_id: &QueueId, max_in_flight: usize) -> Result<(), ModelError> {
        self.gate(queue_id, max_in_flight).map(|_| ())
    }

    pub(crate) async fn acquire(
        &self,
        queue_id: &QueueId,
        max_in_flight: usize,
    ) -> Result<OwnedSemaphorePermit, ModelError> {
        self.gate(queue_id, max_in_flight)?
            .acquire_owned()
            .await
            .map_err(|err| ModelError::Queue(err.to_string()))
    }

    fn gate(&self, queue_id: &QueueId, max_in_flight: usize) -> Result<Arc<Semaphore>, ModelError> {
        let max_in_flight = max_in_flight.max(1);
        let mut gates = self
            .gates
            .lock()
            .map_err(|_| ModelError::Queue("model admission lock poisoned".to_string()))?;
        let (cap, gate) = gates
            .entry(queue_id.0.clone())
            .or_insert_with(|| (max_in_flight, Arc::new(Semaphore::new(max_in_flight))));
        if *cap != max_in_flight {
            return Err(ModelError::InvalidRequest(format!(
                "{} is admitted with max_in_flight {cap}; a provider asked for {max_in_flight}",
                queue_id.0
            )));
        }
        Ok(gate.clone())
    }
}

/// Key in a response trace's `metadata` listing side effects that failed
/// while the call's outcome stood, as `[{"kind": ..., "error": ...}]`.
///
/// Once the provider has answered, the answer is returned and its usage
/// receipt recorded even when writing the response cache
/// (`response_cache_write_failed`), the trace (`trace_write_failed`) or the
/// queue completion (`queue_complete_failed`) fails. The usage receipt's
/// `metadata` carries the same list. Each failure is also logged as a
/// `tracing` warning, as are failed cooldown and failure-trace writes of a
/// failed call, which keeps its own error.
pub const RUNTIME_DIAGNOSTICS: &str = "runtime_diagnostics";

/// What happened to one queued call at one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    /// The call joined the queue (attempt 0).
    Queued,
    /// An attempt claimed its slot and is calling the provider.
    Running,
    Succeeded,
    /// An attempt failed; `error` says why. A retry may follow.
    Failed,
    /// Answered from the response cache without a provider call.
    CacheHit,
}

/// One usage receipt of a queued call: per attempt, with the provider's usage
/// and receipt metadata, the input charged against the rate buckets and the
/// wait split. A cache hit repeats the original usage and costs nothing new.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueueReceipt {
    pub queue_id: QueueId,
    /// `chat`, `embedding`, `rerank` or `classify`.
    pub kind: String,
    pub item_id: Option<QueueItemId>,
    pub request_hash: String,
    pub status: ReceiptStatus,
    pub attempt: u32,
    /// Charge against the requests-per-minute bucket: one per call or batch.
    pub request_units: u64,
    /// Charge against the input-units bucket (text length / 4).
    pub input_units: u64,
    /// Provider usage for `Succeeded` and `CacheHit`.
    pub usage: Option<UsageTrace>,
    pub cache: Option<CacheTrace>,
    /// The provider's receipt metadata (response id, served model, reported
    /// cost, ...) as the provider put it on its trace.
    pub metadata: Value,
    pub error: Option<String>,
    /// Wait for an in-process admission slot and a claimable item.
    pub queue_wait_ms: Option<u64>,
    /// Wait on cooldowns and rate buckets.
    pub throttle_wait_ms: Option<u64>,
    pub provider_ms: Option<u64>,
    pub timestamp: DateTime<Utc>,
}

impl QueueReceipt {
    /// The receipt with provider error text replaced by a fixed note, for
    /// logs that must not carry response bodies.
    pub fn redacted(mut self) -> Self {
        if self.error.is_some() {
            self.error = Some("provider call failed; response details omitted".to_string());
        }
        self
    }
}

/// Receives usage receipts. Best-effort: a sink cannot fail a call.
#[async_trait]
pub trait QueueReceiptSink: Send + Sync {
    async fn record_receipt(&self, receipt: QueueReceipt);
}

/// Keeps every receipt in memory, for tests and short-lived tools.
#[derive(Default)]
pub struct InMemoryReceiptSink {
    receipts: Mutex<Vec<QueueReceipt>>,
}

impl InMemoryReceiptSink {
    pub fn receipts(&self) -> Vec<QueueReceipt> {
        self.receipts
            .lock()
            .map(|receipts| receipts.clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl QueueReceiptSink for InMemoryReceiptSink {
    async fn record_receipt(&self, receipt: QueueReceipt) {
        if let Ok(mut receipts) = self.receipts.lock() {
            receipts.push(receipt);
        }
    }
}

/// The request a cached response belongs to.
pub struct CacheEntry<'a> {
    /// `chat`, `embedding`, `rerank` or `classify`.
    pub kind: &'a str,
    /// Provider scope within `kind` (classifiers scope by descriptor).
    pub scope: Option<&'a str>,
    /// SHA-256 of the serialized request.
    pub request_hash: &'a str,
    /// The serialized request, for caches keyed by something else.
    pub request: &'a Value,
}

/// Exact response cache consulted before a queued call and filled after a
/// successful one. Values are serialized responses of the provider kind.
///
/// Implement it to keep reading a cache whose layout or keys predate the
/// runtime: return `Ok(None)` for requests it cannot answer and skip stores
/// it does not keep.
pub trait ResponseCache: Send + Sync {
    fn load(&self, entry: &CacheEntry<'_>) -> Result<Option<Value>, ModelError>;
    fn store(&self, entry: &CacheEntry<'_>, response: &Value) -> Result<(), ModelError>;
}

/// The runtime's own cache: `{root}/{kind}[/{scope}]/{request_hash}.json`,
/// written through a temporary file and a rename.
#[derive(Clone, Debug)]
pub struct DirResponseCache {
    root: PathBuf,
}

impl DirResponseCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, entry: &CacheEntry<'_>) -> Result<PathBuf, ModelError> {
        let mut path = self.root.join(safe_component(entry.kind)?);
        if let Some(scope) = entry.scope {
            path = path.join(safe_component(scope)?);
        }
        Ok(path.join(format!("{}.json", safe_component(entry.request_hash)?)))
    }
}

fn safe_component(value: &str) -> Result<&str, ModelError> {
    let safe = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte));
    if safe {
        Ok(value)
    } else {
        Err(ModelError::Cache(format!(
            "response cache path component is not a safe file name: {value:?}"
        )))
    }
}

impl ResponseCache for DirResponseCache {
    fn load(&self, entry: &CacheEntry<'_>) -> Result<Option<Value>, ModelError> {
        let path = self.path(entry)?;
        if !path.is_file() {
            return Ok(None);
        }
        let raw = std::fs::read(&path).map_err(|err| ModelError::Cache(err.to_string()))?;
        serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|err| ModelError::Cache(err.to_string()))
    }

    fn store(&self, entry: &CacheEntry<'_>, response: &Value) -> Result<(), ModelError> {
        let path = self.path(entry)?;
        write_json_atomically(&path, response)
    }
}

pub(crate) fn write_json_atomically(path: &Path, value: &Value) -> Result<(), ModelError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| ModelError::Cache(err.to_string()))?;
    }
    let tmp = path.with_extension(format!("json.{}.tmp", uuid_like()));
    let bytes = serde_json::to_vec(value).map_err(|err| ModelError::Cache(err.to_string()))?;
    std::fs::write(&tmp, bytes).map_err(|err| ModelError::Cache(err.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        ModelError::Cache(err.to_string())
    })
}

/// Unique enough for a temporary file name: concurrent writers of one entry
/// must not share a temporary path.
fn uuid_like() -> String {
    QueueItemId::new().0
}

/// Everything a queued provider carries besides its inner provider.
#[derive(Clone)]
pub(crate) struct QueueRuntime {
    pub(crate) queue: Arc<dyn QueueBackend>,
    pub(crate) trace_sink: Option<Arc<dyn TraceSink>>,
    pub(crate) receipt_sink: Option<Arc<dyn QueueReceiptSink>>,
    pub(crate) admission: Option<ModelAdmission>,
    pub(crate) response_cache: Option<Arc<dyn ResponseCache>>,
    /// Queue identity override; `None` uses the descriptor's `queue_id`.
    pub(crate) queue_id: Option<QueueId>,
    pub(crate) worker_id: String,
    pub(crate) config: crate::ModelQueueConfig,
}

impl QueueRuntime {
    pub(crate) fn new(
        queue: Arc<dyn QueueBackend>,
        worker_id: String,
        config: crate::ModelQueueConfig,
    ) -> Self {
        Self {
            queue,
            trace_sink: None,
            receipt_sink: None,
            admission: None,
            response_cache: None,
            queue_id: None,
            worker_id,
            config,
        }
    }

    /// The explicit cache, else a [`DirResponseCache`] at the configured
    /// directory, else none.
    pub(crate) fn cache(&self) -> Option<Arc<dyn ResponseCache>> {
        self.response_cache.clone().or_else(|| {
            self.config
                .response_cache_dir
                .as_ref()
                .map(|dir| Arc::new(DirResponseCache::new(dir.clone())) as Arc<dyn ResponseCache>)
        })
    }
}

/// Builder methods shared by the `Queued*` providers.
macro_rules! queue_runtime_builders {
    () => {
        pub fn with_trace_sink(mut self, sink: Arc<dyn TraceSink>) -> Self {
            self.runtime.trace_sink = Some(sink);
            self
        }

        /// Deliver per-attempt usage receipts to `sink`.
        pub fn with_receipt_sink(mut self, sink: Arc<dyn $crate::QueueReceiptSink>) -> Self {
            self.runtime.receipt_sink = Some(sink);
            self
        }

        /// Share in-process admission (the model cap) with every provider
        /// built from the same [`ModelAdmission`](crate::ModelAdmission).
        pub fn with_admission(mut self, admission: $crate::ModelAdmission) -> Self {
            self.runtime.admission = Some(admission);
            self
        }

        /// Run on `queue_id` instead of the model's own queue, so its limits
        /// and cooldown are shared with (or isolated from) other providers by
        /// that id.
        pub fn with_queue_id(mut self, queue_id: symbiotic_core::QueueId) -> Self {
            self.runtime.queue_id = Some(queue_id);
            self
        }

        /// Use `cache` instead of the configured `response_cache_dir`.
        pub fn with_response_cache(mut self, cache: Arc<dyn $crate::ResponseCache>) -> Self {
            self.runtime.response_cache = Some(cache);
            self
        }
    };
}
pub(crate) use queue_runtime_builders;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_fixes_the_first_cap_and_rejects_a_different_one() {
        let admission = ModelAdmission::new();
        let queue_id = QueueId::new("chat:test:model");
        admission.register(&queue_id, 4).unwrap();
        admission.register(&queue_id, 4).unwrap();
        assert_eq!(admission.cap(&queue_id), Some(4));
        let err = admission.register(&queue_id, 2).unwrap_err();
        assert!(matches!(err, ModelError::InvalidRequest(_)), "{err:?}");
        // Other models are independent.
        admission
            .register(&QueueId::new("chat:test:other"), 2)
            .unwrap();
    }

    #[tokio::test]
    async fn admission_is_fifo_and_bounded() {
        let admission = ModelAdmission::new();
        let queue_id = QueueId::new("chat:test:fifo");
        let first = admission.acquire(&queue_id, 1).await.unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut waiters = Vec::new();
        for idx in 0..3 {
            let admission = admission.clone();
            let queue_id = queue_id.clone();
            let order = order.clone();
            waiters.push(tokio::spawn(async move {
                let _permit = admission.acquire(&queue_id, 1).await.unwrap();
                order.lock().unwrap().push(idx);
            }));
            tokio::task::yield_now().await;
        }
        drop(first);
        for waiter in waiters {
            waiter.await.unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn dir_cache_round_trips_and_refuses_unsafe_components() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DirResponseCache::new(dir.path());
        let request = serde_json::json!({});
        let entry = CacheEntry {
            kind: "chat",
            scope: Some("scope"),
            request_hash: "abc123",
            request: &request,
        };
        assert_eq!(cache.load(&entry).unwrap(), None);
        cache
            .store(&entry, &serde_json::json!({"text": "hi"}))
            .unwrap();
        assert_eq!(
            cache.load(&entry).unwrap(),
            Some(serde_json::json!({"text": "hi"}))
        );
        assert!(dir.path().join("chat/scope/abc123.json").is_file());

        let traversal = CacheEntry {
            kind: "chat",
            scope: Some(".."),
            request_hash: "abc123",
            request: &request,
        };
        assert!(cache.load(&traversal).is_err());
    }

    #[test]
    fn redacted_receipt_drops_error_text() {
        let receipt = QueueReceipt {
            queue_id: QueueId::new("chat:test:model"),
            kind: "chat".into(),
            item_id: None,
            request_hash: "hash".into(),
            status: ReceiptStatus::Failed,
            attempt: 1,
            request_units: 1,
            input_units: 1,
            usage: None,
            cache: None,
            metadata: Value::Null,
            error: Some("401 body with details".into()),
            queue_wait_ms: None,
            throttle_wait_ms: None,
            provider_ms: None,
            timestamp: Utc::now(),
        }
        .redacted();
        assert_eq!(
            receipt.error.as_deref(),
            Some("provider call failed; response details omitted")
        );
    }
}
