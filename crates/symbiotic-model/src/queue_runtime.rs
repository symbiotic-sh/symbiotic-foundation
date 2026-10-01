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
    pub fn cap(&self, queue_id: &QueueId) -> Result<Option<usize>, ModelError> {
        self.gates
            .lock()
            .map(|gates| gates.get(&queue_id.0).map(|(cap, _)| *cap))
            .map_err(|_| ModelError::Queue("model admission lock poisoned".into()))
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
    pub binding: Option<symbiotic_core::BindingIdentity>,
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

/// The runtime's own cache: `{root}/{kind}[/{scope}]/{request_hash}.json`.
///
/// Private: the root and its subdirectories are `0700` and entries `0600`,
/// written through a temporary file and a rename. A missing root is created
/// `0700`. A component that is a symlink or belongs to another user is
/// refused; one with wider permissions, as earlier versions wrote, is
/// tightened on the next store.
///
/// With a maximum age, older entries miss. [`prune`](Self::prune) removes
/// them, and the oldest entries beyond a size limit;
/// [`purge`](Self::purge) removes entries by what their trace records.
#[derive(Clone, Debug)]
pub struct DirResponseCache {
    root: PathBuf,
    max_age: Option<std::time::Duration>,
}

/// A cached response as [`DirResponseCache::purge`] sees it: whom it was
/// for, as recorded on its trace.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub binding: Option<symbiotic_core::BindingIdentity>,
    /// The request's `source`.
    pub source: Option<String>,
    /// The request's `role_binding`.
    pub role_binding: Option<String>,
    /// The model that answered.
    pub model: Option<symbiotic_core::ModelIdentity>,
    pub modified: std::time::SystemTime,
    pub bytes: u64,
}

impl DirResponseCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_age: None,
        }
    }

    /// Entries older than `max_age` miss, as if absent.
    pub fn with_max_age(mut self, max_age: Option<std::time::Duration>) -> Self {
        self.max_age = max_age;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The entry's directories below the root, and its file.
    fn path(&self, entry: &CacheEntry<'_>) -> Result<(Vec<PathBuf>, PathBuf), ModelError> {
        let mut dirs = vec![self.root.join(safe_component(entry.kind)?)];
        if let Some(scope) = entry.scope {
            let scoped = dirs[0].join(safe_component(scope)?);
            dirs.push(scoped);
        }
        let file =
            dirs[dirs.len() - 1].join(format!("{}.json", safe_component(entry.request_hash)?));
        Ok((dirs, file))
    }

    /// Remove entries older than `max_age`, then the oldest entries until
    /// the rest fit in `max_bytes`. Returns how many were removed.
    pub fn prune(
        &self,
        max_age: Option<std::time::Duration>,
        max_bytes: Option<u64>,
    ) -> Result<usize, ModelError> {
        let now = std::time::SystemTime::now();
        let mut entries = self.entries()?;
        entries.sort_by_key(|(_, meta)| meta.modified().unwrap_or(now));
        let mut total: u64 = entries.iter().map(|(_, meta)| meta.len()).sum();
        let mut removed = 0;
        for (path, meta) in entries {
            let expired = max_age.is_some_and(|max_age| is_older(&meta, max_age, now));
            let over = max_bytes.is_some_and(|max_bytes| total > max_bytes);
            if !expired && !over {
                continue;
            }
            remove_entry(&path)?;
            total = total.saturating_sub(meta.len());
            removed += 1;
        }
        Ok(removed)
    }

    /// Remove every entry whose recorded owner `matches`, for example all
    /// responses to requests from one source. Returns how many were
    /// removed. An entry that cannot be read is kept and reported.
    pub fn purge(&self, matches: impl Fn(&CachedResponse) -> bool) -> Result<usize, ModelError> {
        let mut removed = 0;
        for (path, meta) in self.entries()? {
            let raw = std::fs::read(&path).map_err(|err| cache_io(&path, err))?;
            let value: Value = serde_json::from_slice(&raw)
                .map_err(|err| ModelError::Cache(format!("{}: {err}", path.display())))?;
            let trace = value.get("trace");
            let text = |key: &str| {
                trace
                    .and_then(|trace| trace.get(key))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            let response = CachedResponse {
                binding: trace
                    .and_then(|trace| trace.pointer("/metadata/binding"))
                    .and_then(|v| serde_json::from_value(v.clone()).ok()),
                source: text("source"),
                role_binding: text("role_binding"),
                model: trace
                    .and_then(|trace| trace.get("model"))
                    .and_then(|model| serde_json::from_value(model.clone()).ok()),
                modified: meta.modified().unwrap_or(std::time::UNIX_EPOCH),
                bytes: meta.len(),
            };
            if matches(&response) {
                remove_entry(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Every entry file under the root. The whole tree is checked before
    /// anyone deletes from it: the root and every component in it must be
    /// the current user's own and not a symlink, or the walk is refused, so
    /// a prune or purge can never reach outside the cache.
    fn entries(&self) -> Result<Vec<(PathBuf, std::fs::Metadata)>, ModelError> {
        let mut found = Vec::new();
        if owned_or_missing(&self.root)?.is_none() {
            return Ok(found);
        }
        let mut pending = vec![self.root.clone()];
        while let Some(dir) = pending.pop() {
            let listing = std::fs::read_dir(&dir).map_err(|err| cache_io(&dir, err))?;
            for entry in listing {
                let path = entry.map_err(|err| cache_io(&dir, err))?.path();
                let Some(meta) = owned_or_missing(&path)? else {
                    continue;
                };
                if meta.is_dir() {
                    pending.push(path);
                } else if meta.is_file() && path.extension().is_some_and(|ext| ext == "json") {
                    found.push((path, meta));
                }
            }
        }
        Ok(found)
    }
}

fn is_older(
    meta: &std::fs::Metadata,
    max_age: std::time::Duration,
    now: std::time::SystemTime,
) -> bool {
    meta.modified()
        .ok()
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age > max_age)
}

fn remove_entry(path: &Path) -> Result<(), ModelError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(cache_io(path, err)),
    }
}

fn cache_io(path: &Path, err: std::io::Error) -> ModelError {
    ModelError::Cache(format!("{}: {err}", path.display()))
}

/// Whether a path the cache reads exists, refusing one that is a symlink or
/// belongs to another user.
fn owned_or_missing(path: &Path) -> Result<Option<std::fs::Metadata>, ModelError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(ModelError::Cache(format!(
                    "{} is a symlink; the response cache does not follow them",
                    path.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                // SAFETY: `geteuid` has no preconditions and cannot fail.
                if meta.uid() != unsafe { libc::geteuid() } {
                    return Err(ModelError::Cache(format!(
                        "{} is owned by another user",
                        path.display()
                    )));
                }
            }
            Ok(Some(meta))
        }
        // Below a regular file nothing can exist: a miss, like a missing file.
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(cache_io(path, err)),
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
        let (dirs, file) = self.path(entry)?;
        for path in std::iter::once(&self.root).chain(&dirs) {
            if owned_or_missing(path)?.is_none() {
                return Ok(None);
            }
        }
        let Some(meta) = owned_or_missing(&file)? else {
            return Ok(None);
        };
        if self
            .max_age
            .is_some_and(|max_age| is_older(&meta, max_age, std::time::SystemTime::now()))
        {
            return Ok(None);
        }
        let raw = std::fs::read(&file).map_err(|err| cache_io(&file, err))?;
        serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|err| ModelError::Cache(err.to_string()))
    }

    fn store(&self, entry: &CacheEntry<'_>, response: &Value) -> Result<(), ModelError> {
        let (dirs, file) = self.path(entry)?;
        crate::private_fs::ensure_owned_dir(&self.root).map_err(|err| cache_io(&self.root, err))?;
        for dir in &dirs {
            crate::private_fs::ensure_owned_dir(dir).map_err(|err| cache_io(dir, err))?;
        }
        if owned_or_missing(&file)?.is_some() {
            crate::private_fs::ensure_owned_file(&file).map_err(|err| cache_io(&file, err))?;
        }
        let bytes =
            serde_json::to_vec(response).map_err(|err| ModelError::Cache(err.to_string()))?;
        crate::private_fs::write_private_file(&file, &bytes).map_err(|err| cache_io(&file, err))
    }
}

/// Everything a queued provider carries besides its inner provider.
#[derive(Clone)]
pub(crate) struct QueueRuntime {
    pub(crate) queue: Arc<dyn QueueBackend>,
    pub(crate) trace_sink: Option<Arc<dyn TraceSink>>,
    pub(crate) receipt_sink: Option<Arc<dyn QueueReceiptSink>>,
    pub(crate) admission: Option<ModelAdmission>,
    pub(crate) rate_state: crate::ModelRateState,
    pub(crate) response_cache: Option<Arc<dyn ResponseCache>>,
    /// Queue identity override; `None` uses the descriptor's `queue_id`.
    pub(crate) queue_id: Option<QueueId>,
    pub(crate) binding_identity: Option<symbiotic_core::BindingIdentity>,
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
            rate_state: crate::ModelRateState::default(),
            response_cache: None,
            queue_id: None,
            binding_identity: None,
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
        /// Runtime-owned rate state, pooled by explicit account identity.
        pub fn with_rate_state(mut self, state: $crate::ModelRateState) -> Self {
            self.runtime.rate_state = state;
            self
        }
        pub fn with_admission(mut self, admission: $crate::ModelAdmission) -> Self {
            self.runtime.admission = Some(admission);
            self
        }

        /// Run on `queue_id` instead of the model's own queue, so its limits
        /// and cooldown are shared with (or isolated from) other providers by
        /// that id.
        pub fn with_binding_identity(mut self, identity: symbiotic_core::BindingIdentity) -> Self {
            self.runtime.binding_identity = Some(identity);
            self
        }

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
    #[tokio::test]
    async fn failed_admission_state_refuses_visibly() {
        let admission = super::ModelAdmission::new();
        let id = symbiotic_core::QueueId::new("account");
        let gate = admission.gate(&id, 1).unwrap();
        gate.close();
        assert!(admission.acquire(&id, 1).await.is_err());
        let gates = admission.gates.clone();
        let _ = std::thread::spawn(move || {
            let _held = gates.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(admission.cap(&id).is_err());
        assert!(admission.register(&id, 1).is_err());
    }

    use super::*;

    #[test]
    fn admission_fixes_the_first_cap_and_rejects_a_different_one() {
        let admission = ModelAdmission::new();
        let queue_id = QueueId::new("chat:test:model");
        admission.register(&queue_id, 4).unwrap();
        admission.register(&queue_id, 4).unwrap();
        assert_eq!(admission.cap(&queue_id).unwrap(), Some(4));
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

    fn chat_entry<'a>(hash: &'a str, request: &'a Value) -> CacheEntry<'a> {
        CacheEntry {
            kind: "chat",
            scope: None,
            request_hash: hash,
            request,
        }
    }

    #[test]
    fn dir_cache_prunes_by_age_then_size_and_purges_by_source() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DirResponseCache::new(dir.path().join("cache"));
        let request = serde_json::json!({});
        for (hash, source) in [("a1", "a"), ("a2", "a"), ("b1", "b")] {
            cache
                .store(
                    &chat_entry(hash, &request),
                    &serde_json::json!({"trace": {"source": source}, "text": "x"}),
                )
                .unwrap();
        }
        let path = |hash: &str| dir.path().join(format!("cache/chat/{hash}.json"));
        let set_age = |hash: &str, seconds: u64| {
            std::fs::File::options()
                .write(true)
                .open(path(hash))
                .unwrap()
                .set_modified(
                    std::time::SystemTime::now() - std::time::Duration::from_secs(seconds),
                )
                .unwrap();
        };
        set_age("a1", 300);
        set_age("a2", 200);
        set_age("b1", 100);

        // An expired entry misses before any prune.
        let aging = cache
            .clone()
            .with_max_age(Some(std::time::Duration::from_secs(250)));
        assert!(aging.load(&chat_entry("a1", &request)).unwrap().is_none());
        assert!(aging.load(&chat_entry("a2", &request)).unwrap().is_some());

        assert_eq!(
            cache
                .prune(Some(std::time::Duration::from_secs(250)), None)
                .unwrap(),
            1
        );
        assert!(!path("a1").exists());
        let one_entry = std::fs::metadata(path("b1")).unwrap().len();
        assert_eq!(cache.prune(None, Some(one_entry)).unwrap(), 1);
        assert!(!path("a2").exists() && path("b1").exists());

        cache
            .store(
                &chat_entry("a3", &request),
                &serde_json::json!({"trace": {"source": "a"}}),
            )
            .unwrap();
        let purged = cache
            .purge(|cached| cached.source.as_deref() == Some("a"))
            .unwrap();
        assert_eq!(purged, 1);
        assert!(!path("a3").exists() && path("b1").exists());
    }

    #[cfg(unix)]
    #[test]
    fn dir_cache_is_owner_only_and_refuses_symlinked_directories() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = DirResponseCache::new(dir.path().join("cache"));
        let request = serde_json::json!({});
        cache
            .store(&chat_entry("h", &request), &serde_json::json!({}))
            .unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("cache")), 0o700);
        assert_eq!(mode(&dir.path().join("cache/chat")), 0o700);
        assert_eq!(mode(&dir.path().join("cache/chat/h.json")), 0o600);

        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::remove_dir_all(dir.path().join("cache/chat")).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("cache/chat")).unwrap();
        let load = cache.load(&chat_entry("h", &request)).unwrap_err();
        assert!(load.to_string().contains("symlink"), "{load}");
        let store = cache
            .store(&chat_entry("h", &request), &serde_json::json!({}))
            .unwrap_err();
        assert!(store.to_string().contains("symlink"), "{store}");
    }

    #[test]
    fn redacted_receipt_drops_error_text() {
        let receipt = QueueReceipt {
            binding: None,
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
