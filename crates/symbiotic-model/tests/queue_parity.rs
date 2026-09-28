//! Queued-provider behaviour hosts depend on: shared admission, usage
//! receipts, retry timing and classification, eviction recovery, request
//! capture, the response-cache seam, and attempts that outlive a caller who
//! stopped waiting. Loopback providers only.
#![cfg(feature = "queue")]

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use symbiotic_core::{ModelIdentity, QueueId, QueueItemId, Sensitivity, TraceId};
use symbiotic_model::{
    CacheEntry, ChatMessage, ChatProvider, ChatRequest, ChatResponse, InMemoryReceiptSink,
    ModelAdmission, ModelCapability, ModelError, ModelProvider, ModelQueueConfig, ProviderAuthMode,
    ProviderClass, ProviderDescriptor, QueuedChatProvider, ReceiptStatus, ResponseCache,
};
use symbiotic_queue::{
    ClaimRequest, EnqueueOutcome, EnqueueRequest, FailOutcome, Failure, MemoryQueue, QueueBackend,
    QueueError, QueueItem, QueueStatus,
};
use symbiotic_queue_sqlite::SqliteQueue;
use symbiotic_trace::{
    CacheTrace, InvocationOutcome, ModelInvocationTrace, TimingTrace, UsageTrace,
};

static MODEL_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh model name per test: rate buckets and cooldowns are per model.
fn unique_identity() -> ModelIdentity {
    ModelIdentity::new(
        "chat",
        "loopback",
        format!("parity-{}", MODEL_COUNTER.fetch_add(1, Ordering::SeqCst)),
    )
}

fn config() -> ModelQueueConfig {
    ModelQueueConfig {
        max_in_flight: 1,
        lease_seconds: 60,
        logical_retry_attempts: 3,
        retry_attempts: 3,
        retry_jitter_seconds: 0,
        request_timeout_seconds: Some(10),
        retry_base_delay_ms: 20,
        ..ModelQueueConfig::default()
    }
}

fn request(text: &str) -> ChatRequest {
    ChatRequest {
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: text.to_string(),
        }],
        max_output_tokens: None,
        temperature: Some(0.0),
        response_format: None,
        sensitivity: Sensitivity::Shareable,
        role_binding: None,
        source: None,
        metadata: json!({}),
    }
}

/// Loopback chat: echoes the last message, reports usage and a provider
/// receipt, optionally fails first with scripted errors, and records the
/// peak number of concurrent calls.
#[derive(Clone)]
struct Loopback {
    descriptor: ProviderDescriptor,
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    failures: Arc<Mutex<Vec<ModelError>>>,
    starts: Arc<Mutex<Vec<Instant>>>,
    delay: Duration,
}

impl Loopback {
    fn new(identity: ModelIdentity) -> Self {
        Self {
            descriptor: ProviderDescriptor {
                identity,
                provider_class: ProviderClass::Cloud,
                capabilities: vec![ModelCapability::Chat],
                auth_mode: ProviderAuthMode::None,
                metadata: json!({}),
            },
            calls: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            failures: Arc::new(Mutex::new(Vec::new())),
            starts: Arc::new(Mutex::new(Vec::new())),
            delay: Duration::ZERO,
        }
    }

    fn failing_first(self, failures: Vec<ModelError>) -> Self {
        *self.failures.lock().unwrap() = failures;
        self
    }

    fn slow(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

impl ModelProvider for Loopback {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }
}

#[async_trait]
impl ChatProvider for Loopback {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.starts.lock().unwrap().push(Instant::now());
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        // Count the call out even when it is cancelled mid-flight.
        let _active = Leaves(&self.active);
        tokio::time::sleep(self.delay).await;
        drop(_active);
        let failure = {
            let mut failures = self.failures.lock().unwrap();
            (!failures.is_empty()).then(|| failures.remove(0))
        };
        if let Some(err) = failure {
            return Err(err);
        }
        Ok(ChatResponse {
            text: request.messages.last().unwrap().content.clone(),
            finish_reason: Some("stop".to_string()),
            trace: ModelInvocationTrace {
                trace_id: TraceId::new(),
                queue_item_id: None,
                model: self.descriptor.identity.clone(),
                role_binding: None,
                source: None,
                sensitivity: Sensitivity::Shareable,
                request_hash: String::new(),
                response_hash: None,
                cache: CacheTrace {
                    cached_input_tokens: Some(4),
                    ..CacheTrace::default()
                },
                usage: UsageTrace {
                    input_tokens: Some(10),
                    output_tokens: Some(2),
                    ..UsageTrace::default()
                },
                timing: TimingTrace::default(),
                outcome: InvocationOutcome::Succeeded,
                error_class: None,
                audit_refs: Vec::new(),
                metadata: json!({"provider": {"response_id": "loopback-1"}}),
                timestamp: Utc::now(),
            },
            raw_provider_response: None,
        })
    }
}

/// Decrements a gauge when dropped.
struct Leaves<'a>(&'a AtomicUsize);

impl Drop for Leaves<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn queued(
    provider: Loopback,
    queue: Arc<dyn QueueBackend>,
    config: ModelQueueConfig,
) -> QueuedChatProvider<Loopback> {
    QueuedChatProvider::new(provider, queue, "worker", config)
}

#[tokio::test]
async fn providers_sharing_admission_share_one_model_cap() {
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let admission = ModelAdmission::new();
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(20));
    let policy = ModelQueueConfig {
        max_in_flight: 2,
        ..config()
    };
    // Two roles bound to the same model.
    let first =
        queued(raw.clone(), queue.clone(), policy.clone()).with_admission(admission.clone());
    let second = queued(raw.clone(), queue.clone(), policy).with_admission(admission.clone());
    let calls = (0..12).map(|idx| {
        let provider = if idx % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        tokio::spawn(async move { provider.chat(request(&format!("call-{idx}"))).await })
    });
    for call in calls.collect::<Vec<_>>() {
        call.await.unwrap().unwrap();
    }
    assert_eq!(raw.calls.load(Ordering::SeqCst), 12);
    assert_eq!(raw.peak.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_second_cap_for_an_admitted_model_is_a_configuration_error() {
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let admission = ModelAdmission::new();
    let raw = Loopback::new(unique_identity());
    let two = queued(
        raw.clone(),
        queue.clone(),
        ModelQueueConfig {
            max_in_flight: 2,
            ..config()
        },
    )
    .with_admission(admission.clone());
    let three = queued(
        raw,
        queue,
        ModelQueueConfig {
            max_in_flight: 3,
            ..config()
        },
    )
    .with_admission(admission);
    two.chat(request("first")).await.unwrap();
    let err = three.chat(request("second")).await.unwrap_err();
    assert!(matches!(err, ModelError::InvalidRequest(_)), "{err:?}");
}

#[tokio::test]
async fn receipts_cover_each_step_and_a_cache_hit_keeps_the_original_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let sink = Arc::new(InMemoryReceiptSink::default());
    let raw = Loopback::new(unique_identity());
    let provider = queued(
        raw.clone(),
        queue,
        ModelQueueConfig {
            response_cache_dir: Some(dir.path().to_path_buf()),
            ..config()
        },
    )
    .with_receipt_sink(sink.clone());

    provider.chat(request("hello")).await.unwrap();
    let replay = provider.chat(request("hello")).await.unwrap();
    assert_eq!(replay.text, "hello");
    assert_eq!(raw.calls.load(Ordering::SeqCst), 1);

    let receipts = sink.receipts();
    let statuses: Vec<_> = receipts.iter().map(|receipt| receipt.status).collect();
    assert_eq!(
        statuses,
        vec![
            ReceiptStatus::Queued,
            ReceiptStatus::Running,
            ReceiptStatus::Succeeded,
            ReceiptStatus::CacheHit,
        ]
    );
    let running = &receipts[1];
    assert_eq!(running.attempt, 1);
    assert!(running.queue_wait_ms.is_some() && running.throttle_wait_ms.is_some());
    let succeeded = &receipts[2];
    assert_eq!(succeeded.request_units, 1);
    assert!(succeeded.input_units >= 1);
    assert_eq!(succeeded.usage.as_ref().unwrap().input_tokens, Some(10));
    assert_eq!(
        succeeded.cache.as_ref().unwrap().cached_input_tokens,
        Some(4)
    );
    assert_eq!(succeeded.metadata["provider"]["response_id"], "loopback-1");
    assert!(succeeded.provider_ms.is_some());
    // The cache hit carries the original usage and receipt; it adds no call.
    let hit = &receipts[3];
    assert_eq!(hit.usage.as_ref().unwrap().output_tokens, Some(2));
    assert_eq!(hit.metadata["provider"]["response_id"], "loopback-1");
    assert!(hit.provider_ms.is_none());
}

#[tokio::test]
async fn retry_base_delay_allows_sub_second_backoff_and_receipts_record_the_failure() {
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let sink = Arc::new(InMemoryReceiptSink::default());
    let raw = Loopback::new(unique_identity())
        .failing_first(vec![ModelError::Unavailable("blip".to_string())]);
    let provider = queued(raw.clone(), queue, config()).with_receipt_sink(sink.clone());

    let started = Instant::now();
    provider.chat(request("retry me")).await.unwrap();
    assert_eq!(raw.calls.load(Ordering::SeqCst), 2);
    // 20 ms backoff (plus the 20 ms x 2 cooldown) instead of the 1 s default.
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
    let failed: Vec<_> = sink
        .receipts()
        .into_iter()
        .filter(|receipt| receipt.status == ReceiptStatus::Failed)
        .collect();
    assert_eq!(failed.len(), 1);
    assert!(failed[0].error.as_deref().unwrap().contains("blip"));
    assert_eq!(failed[0].attempt, 1);
}

#[tokio::test]
async fn provider_errors_retry_only_when_the_policy_opts_in() {
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let strict = Loopback::new(unique_identity())
        .failing_first(vec![ModelError::Provider("bad json".to_string())]);
    let err = queued(strict.clone(), queue.clone(), config())
        .chat(request("strict"))
        .await
        .unwrap_err();
    assert!(matches!(err, ModelError::Provider(_)), "{err:?}");
    assert_eq!(strict.calls.load(Ordering::SeqCst), 1);

    let lenient = Loopback::new(unique_identity())
        .failing_first(vec![ModelError::Provider("bad json".to_string())]);
    let response = queued(
        lenient.clone(),
        queue,
        ModelQueueConfig {
            retry_provider_errors: true,
            ..config()
        },
    )
    .chat(request("lenient"))
    .await
    .unwrap();
    assert_eq!(response.text, "lenient");
    assert_eq!(lenient.calls.load(Ordering::SeqCst), 2);
}

/// A retention-bounded backend that evicts the caller's item just before
/// its first claim: another request finishes and pushes it out of a
/// one-item terminal window.
struct EvictsOnce {
    inner: MemoryQueue,
    evicted: Mutex<Option<QueueItemId>>,
}

impl EvictsOnce {
    fn new() -> Self {
        Self {
            inner: MemoryQueue::with_terminal_retention(1),
            evicted: Mutex::new(None),
        }
    }

    /// Finish `item_id` as another worker, then finish a filler item so the
    /// one-item terminal window drops it.
    async fn evict(&self, item_id: &QueueItemId) {
        self.inner
            .claim_item(item_id, "other-worker", 60, None)
            .await
            .unwrap()
            .expect("the target is claimable");
        self.inner.complete(item_id, "other-worker").await.unwrap();
        let filler = self
            .inner
            .enqueue(EnqueueRequest {
                queue_id: QueueId::new("chat:filler:filler"),
                kind: "chat".to_string(),
                payload: json!({}),
                idempotency_key: None,
                run_after: None,
                max_attempts: None,
                force: false,
            })
            .await
            .unwrap()
            .item;
        self.inner
            .claim_item(&filler.item_id, "other-worker", 60, None)
            .await
            .unwrap()
            .unwrap();
        self.inner
            .complete(&filler.item_id, "other-worker")
            .await
            .unwrap();
        assert!(self.inner.get_item(item_id).await.unwrap().is_none());
    }
}

#[async_trait]
impl QueueBackend for EvictsOnce {
    async fn enqueue(&self, request: EnqueueRequest) -> Result<EnqueueOutcome, QueueError> {
        self.inner.enqueue(request).await
    }
    async fn claim(&self, request: ClaimRequest) -> Result<Vec<QueueItem>, QueueError> {
        self.inner.claim(request).await
    }
    async fn claim_item(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
        max_in_flight: Option<usize>,
    ) -> Result<Option<QueueItem>, QueueError> {
        let first = {
            let mut evicted = self.evicted.lock().unwrap();
            let first = evicted.is_none();
            if first {
                *evicted = Some(item_id.clone());
            }
            first
        };
        if first {
            self.evict(item_id).await;
        }
        self.inner
            .claim_item(item_id, worker_id, lease_seconds, max_in_flight)
            .await
    }
    async fn get_item(&self, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError> {
        self.inner.get_item(item_id).await
    }
    async fn heartbeat(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<(), QueueError> {
        self.inner
            .heartbeat(item_id, worker_id, lease_seconds)
            .await
    }
    async fn complete(&self, item_id: &QueueItemId, worker_id: &str) -> Result<(), QueueError> {
        self.inner.complete(item_id, worker_id).await
    }
    async fn fail(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        error: &str,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError> {
        self.inner
            .fail(item_id, worker_id, error, retry_after_seconds)
            .await
    }
    async fn reclaim_expired_leases(&self, queue_id: &QueueId) -> Result<usize, QueueError> {
        self.inner.reclaim_expired_leases(queue_id).await
    }
}

#[tokio::test]
async fn an_evicted_queue_item_is_queued_again_instead_of_failing() {
    let backend = Arc::new(EvictsOnce::new());
    let raw = Loopback::new(unique_identity());
    let response = queued(raw.clone(), backend.clone(), config())
        .chat(request("still here"))
        .await
        .unwrap();
    assert_eq!(response.text, "still here");
    assert_eq!(raw.calls.load(Ordering::SeqCst), 1);
    let evicted = backend.evicted.lock().unwrap().clone().unwrap();
    let replacement = response
        .trace
        .queue_item_id
        .expect("the call ran on a queue item");
    assert_ne!(replacement, evicted, "a replacement item was created");
    assert!(
        backend
            .inner
            .get_item(&replacement)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn request_debug_capture_writes_the_serialized_request() {
    let dir = tempfile::tempdir().unwrap();
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let raw = Loopback::new(unique_identity());
    queued(
        raw,
        queue,
        ModelQueueConfig {
            request_debug_dir: Some(dir.path().to_path_buf()),
            ..config()
        },
    )
    .chat(request("capture me"))
    .await
    .unwrap();
    let captured: Vec<_> = std::fs::read_dir(dir.path().join("chat"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(captured.len(), 1);
    let body: Value = serde_json::from_slice(&std::fs::read(&captured[0]).unwrap()).unwrap();
    assert_eq!(body["messages"][0]["content"], "capture me");
}

/// A host cache keyed by the raw message text, standing in for a cache
/// layout that predates the runtime.
#[derive(Default)]
struct TextKeyedCache {
    entries: Mutex<std::collections::HashMap<String, Value>>,
    stores: AtomicUsize,
}

impl TextKeyedCache {
    fn key(entry: &CacheEntry<'_>) -> Option<String> {
        entry.request["messages"][0]["content"]
            .as_str()
            .map(str::to_string)
    }
}

impl ResponseCache for TextKeyedCache {
    fn load(&self, entry: &CacheEntry<'_>) -> Result<Option<Value>, ModelError> {
        Ok(Self::key(entry).and_then(|key| self.entries.lock().unwrap().get(&key).cloned()))
    }

    fn store(&self, entry: &CacheEntry<'_>, response: &Value) -> Result<(), ModelError> {
        self.stores.fetch_add(1, Ordering::SeqCst);
        if let Some(key) = Self::key(entry) {
            self.entries.lock().unwrap().insert(key, response.clone());
        }
        Ok(())
    }
}

#[tokio::test]
async fn a_host_response_cache_answers_before_the_queue() {
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let raw = Loopback::new(unique_identity());
    let cache = Arc::new(TextKeyedCache::default());
    // A response already present under the host's own key.
    let seeded = raw.chat(request("seeded")).await.unwrap();
    cache
        .entries
        .lock()
        .unwrap()
        .insert("seeded".to_string(), serde_json::to_value(&seeded).unwrap());
    let provider = queued(raw.clone(), queue, config()).with_response_cache(cache.clone());

    let hit = provider.chat(request("seeded")).await.unwrap();
    assert_eq!(hit.text, "seeded");
    assert_eq!(
        hit.trace.cache.response_cache,
        symbiotic_trace::CacheStatus::Hit
    );
    assert_eq!(raw.calls.load(Ordering::SeqCst), 1, "the seed call only");

    provider.chat(request("fresh")).await.unwrap();
    assert_eq!(raw.calls.load(Ordering::SeqCst), 2);
    assert_eq!(cache.stores.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exhausted_retries_keep_the_class_of_the_last_failure() {
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let raw = Loopback::new(unique_identity()).failing_first(vec![
        ModelError::RateLimited("slow down".to_string()),
        ModelError::RateLimited("slow down".to_string()),
        ModelError::Timeout("still slow".to_string()),
    ]);
    let err = queued(raw.clone(), queue, config())
        .chat(request("give up"))
        .await
        .unwrap_err();
    assert!(matches!(err, ModelError::Timeout(_)), "{err:?}");
    assert!(err.to_string().contains("exhausted after 3/3"), "{err}");
    assert_eq!(raw.calls.load(Ordering::SeqCst), 3);
}

#[derive(Clone)]
struct CountingClassifier {
    inner: symbiotic_model::StaticClassifierProvider,
    calls: Arc<AtomicUsize>,
}

impl ModelProvider for CountingClassifier {
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }
}

#[async_trait]
impl symbiotic_model::ClassifierProvider for CountingClassifier {
    async fn classify(
        &self,
        request: symbiotic_model::ClassifyRequest,
    ) -> Result<symbiotic_model::ClassifyResponse, ModelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.classify(request).await
    }
}

#[tokio::test]
async fn an_invalid_classify_request_takes_no_queue_slot() {
    use symbiotic_model::ClassifierProvider as _;
    let queue = Arc::new(MemoryQueue::new());
    let raw = CountingClassifier {
        inner: symbiotic_model::StaticClassifierProvider::new([
            symbiotic_model::ClassifierAnswer::noul("goal", 0.7),
        ]),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let classifier = symbiotic_model::QueuedClassifierProvider::new(
        raw.clone(),
        queue.clone(),
        "worker",
        config(),
    );
    let mut state = serde_json::Map::new();
    state.insert("message".into(), json!("synthetic"));
    let err = classifier
        .classify(symbiotic_model::ClassifyRequest::new(state, Vec::new()))
        .await
        .unwrap_err();
    assert!(matches!(err, ModelError::InvalidRequest(_)), "{err:?}");
    assert_eq!(raw.calls.load(Ordering::SeqCst), 0);
    assert!(queue.is_empty());
}

#[tokio::test]
async fn an_exhausted_budget_blocks_repeats_unless_the_policy_renews_it() {
    let down = || {
        Loopback::new(unique_identity()).failing_first(
            (0..4)
                .map(|_| ModelError::Unavailable("down".to_string()))
                .collect(),
        )
    };
    let once = ModelQueueConfig {
        logical_retry_attempts: 1,
        retry_attempts: 1,
        ..config()
    };

    let kept = down();
    let provider = queued(kept.clone(), Arc::new(MemoryQueue::new()), once.clone());
    provider.chat(request("same")).await.unwrap_err();
    let err = provider.chat(request("same")).await.unwrap_err();
    assert!(err.to_string().contains("exhausted"), "{err}");
    assert_eq!(kept.calls.load(Ordering::SeqCst), 1, "no second paid call");

    let renewed = down();
    let provider = queued(
        renewed.clone(),
        Arc::new(MemoryQueue::new()),
        ModelQueueConfig {
            budget_renewal_seconds: Some(0),
            ..once
        },
    );
    provider.chat(request("same")).await.unwrap_err();
    provider.chat(request("same")).await.unwrap_err();
    assert_eq!(
        renewed.calls.load(Ordering::SeqCst),
        2,
        "each call has its own budget"
    );
}

#[tokio::test]
async fn a_retry_waits_the_whole_delay_for_every_caller_of_the_request() {
    let queue: Arc<dyn QueueBackend> = Arc::new(MemoryQueue::new());
    let raw = Loopback::new(unique_identity())
        .failing_first(vec![ModelError::Provider("bad json".to_string())]);
    let provider = queued(
        raw.clone(),
        queue,
        ModelQueueConfig {
            retry_base_delay_ms: 1_500,
            retry_provider_errors: true,
            max_in_flight: 2,
            ..config()
        },
    );
    // Two callers of the same request: one runs the failing attempt, the
    // other waits on the same queue item.
    let (first, second) = tokio::join!(
        provider.chat(request("fractional")),
        provider.chat(request("fractional"))
    );
    first.unwrap();
    second.unwrap();
    let starts = raw.starts.lock().unwrap().clone();
    assert!(starts.len() >= 2, "{starts:?}");
    let waited = starts[1].duration_since(starts[0]);
    assert!(
        waited >= Duration::from_millis(1_490),
        "no attempt may start before the 1.5 s retry deadline: {waited:?}"
    );
    assert!(waited < Duration::from_millis(2_400), "{waited:?}");
}

/// Pauses the first enqueue after it is armed, after the backend answered
/// and before the caller sees the answer: a caller delayed while holding a
/// stale item.
struct PausesOneEnqueue {
    inner: MemoryQueue,
    armed: std::sync::atomic::AtomicBool,
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

#[async_trait]
impl QueueBackend for PausesOneEnqueue {
    async fn enqueue(&self, request: EnqueueRequest) -> Result<EnqueueOutcome, QueueError> {
        let outcome = self.inner.enqueue(request).await;
        if self.armed.swap(false, Ordering::SeqCst) {
            self.reached.notify_one();
            self.resume.notified().await;
        }
        outcome
    }
    async fn enqueue_replacing(
        &self,
        request: EnqueueRequest,
        current: &QueueItemId,
    ) -> Result<EnqueueOutcome, QueueError> {
        self.inner.enqueue_replacing(request, current).await
    }
    async fn claim(&self, request: ClaimRequest) -> Result<Vec<QueueItem>, QueueError> {
        self.inner.claim(request).await
    }
    async fn claim_item(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
        max_in_flight: Option<usize>,
    ) -> Result<Option<QueueItem>, QueueError> {
        self.inner
            .claim_item(item_id, worker_id, lease_seconds, max_in_flight)
            .await
    }
    async fn get_item(&self, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError> {
        self.inner.get_item(item_id).await
    }
    async fn heartbeat(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<(), QueueError> {
        self.inner
            .heartbeat(item_id, worker_id, lease_seconds)
            .await
    }
    async fn complete(&self, item_id: &QueueItemId, worker_id: &str) -> Result<(), QueueError> {
        self.inner.complete(item_id, worker_id).await
    }
    async fn fail(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        error: &str,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError> {
        self.inner
            .fail(item_id, worker_id, error, retry_after_seconds)
            .await
    }
    async fn fail_with(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        failure: symbiotic_queue::Failure,
    ) -> Result<FailOutcome, QueueError> {
        self.inner.fail_with(item_id, worker_id, failure).await
    }
    async fn reclaim_expired_leases(&self, queue_id: &QueueId) -> Result<usize, QueueError> {
        self.inner.reclaim_expired_leases(queue_id).await
    }
}

#[tokio::test]
async fn a_delayed_caller_cannot_renew_over_a_budget_renewed_meanwhile() {
    let backend = Arc::new(PausesOneEnqueue {
        inner: MemoryQueue::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        reached: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
    });
    let raw = Loopback::new(unique_identity()).failing_first(
        (0..8)
            .map(|_| ModelError::Unavailable("down".to_string()))
            .collect(),
    );
    let provider = queued(
        raw.clone(),
        backend.clone(),
        ModelQueueConfig {
            logical_retry_attempts: 1,
            retry_attempts: 1,
            budget_renewal_seconds: Some(1),
            ..config()
        },
    );
    provider.chat(request("renewal race")).await.unwrap_err();
    assert_eq!(raw.calls.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    // The delayed caller sees the first, renewable, dead item and stalls.
    backend.armed.store(true, Ordering::SeqCst);
    let delayed = tokio::spawn({
        let provider = provider.clone();
        async move { provider.chat(request("renewal race")).await }
    });
    backend.reached.notified().await;
    // Meanwhile another caller renews the budget and exhausts it.
    provider.chat(request("renewal race")).await.unwrap_err();
    assert_eq!(raw.calls.load(Ordering::SeqCst), 2);

    backend.resume.notify_one();
    let err = delayed.await.unwrap().unwrap_err();
    assert!(err.to_string().contains("exhausted"), "{err}");
    assert_eq!(
        raw.calls.load(Ordering::SeqCst),
        2,
        "the fresh budget is still inside its renewal interval"
    );
}

// ---------------------------------------------------------------------------
// Once an attempt holds its lease, the runtime owns it, not the caller
// ---------------------------------------------------------------------------

/// A 3 s lease, renewed every second, and a single attempt per request.
fn leased() -> ModelQueueConfig {
    ModelQueueConfig {
        lease_seconds: 3,
        logical_retry_attempts: 1,
        retry_attempts: 1,
        ..config()
    }
}

/// Forwards to a backend and counts lease renewals. Cooldown writes fail
/// while `fail_cooldown_writes` is set.
struct CountsRenewals {
    inner: Arc<dyn QueueBackend>,
    renewals: AtomicUsize,
    fail_cooldown_writes: std::sync::atomic::AtomicBool,
}

impl CountsRenewals {
    fn renewals(&self) -> usize {
        self.renewals.load(Ordering::SeqCst)
    }
}

fn counted(inner: Arc<dyn QueueBackend>) -> Arc<CountsRenewals> {
    Arc::new(CountsRenewals {
        inner,
        renewals: AtomicUsize::new(0),
        fail_cooldown_writes: std::sync::atomic::AtomicBool::new(false),
    })
}

/// One test per backend for each scenario below.
macro_rules! on_both_backends {
    ($($scenario:ident),* $(,)?) => {
        mod memory {
            use super::*;
            $(
                #[tokio::test]
                async fn $scenario() {
                    super::$scenario("memory", counted(Arc::new(MemoryQueue::new()))).await;
                }
            )*
        }
        mod sqlite {
            use super::*;
            $(
                #[tokio::test]
                async fn $scenario() {
                    let queue = SqliteQueue::in_memory().unwrap();
                    super::$scenario("sqlite", counted(Arc::new(queue))).await;
                }
            )*
        }
    };
}

on_both_backends!(
    an_abandoned_call_completes_and_answers_the_next_identical_request,
    an_abandoned_call_that_fails_records_its_class_and_releases_its_lease,
    lease_renewal_ends_with_its_call_when_the_caller_left,
    a_failed_cache_write_still_releases_the_lease,
    an_abandoned_call_keeps_its_model_slot_until_it_finishes,
    a_provider_panic_reaches_its_caller_and_ends_lease_renewal,
    a_slow_trace_write_keeps_the_lease_until_the_item_completes,
    a_slow_failure_receipt_keeps_the_lease_until_the_failure_is_recorded,
    a_failed_trace_write_still_completes_the_item,
    a_failed_cooldown_write_still_records_the_failure,
);

#[async_trait]
impl QueueBackend for CountsRenewals {
    async fn enqueue(&self, request: EnqueueRequest) -> Result<EnqueueOutcome, QueueError> {
        self.inner.enqueue(request).await
    }
    async fn enqueue_replacing(
        &self,
        request: EnqueueRequest,
        current: &QueueItemId,
    ) -> Result<EnqueueOutcome, QueueError> {
        self.inner.enqueue_replacing(request, current).await
    }
    async fn claim(&self, request: ClaimRequest) -> Result<Vec<QueueItem>, QueueError> {
        self.inner.claim(request).await
    }
    async fn claim_item(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
        max_in_flight: Option<usize>,
    ) -> Result<Option<QueueItem>, QueueError> {
        self.inner
            .claim_item(item_id, worker_id, lease_seconds, max_in_flight)
            .await
    }
    async fn get_item(&self, item_id: &QueueItemId) -> Result<Option<QueueItem>, QueueError> {
        self.inner.get_item(item_id).await
    }
    async fn heartbeat(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<(), QueueError> {
        self.renewals.fetch_add(1, Ordering::SeqCst);
        self.inner
            .heartbeat(item_id, worker_id, lease_seconds)
            .await
    }
    async fn complete(&self, item_id: &QueueItemId, worker_id: &str) -> Result<(), QueueError> {
        self.inner.complete(item_id, worker_id).await
    }
    async fn fail(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        error: &str,
        retry_after_seconds: Option<u64>,
    ) -> Result<FailOutcome, QueueError> {
        self.inner
            .fail(item_id, worker_id, error, retry_after_seconds)
            .await
    }
    async fn fail_with(
        &self,
        item_id: &QueueItemId,
        worker_id: &str,
        failure: Failure,
    ) -> Result<FailOutcome, QueueError> {
        self.inner.fail_with(item_id, worker_id, failure).await
    }
    async fn reclaim_expired_leases(&self, queue_id: &QueueId) -> Result<usize, QueueError> {
        self.inner.reclaim_expired_leases(queue_id).await
    }
    async fn cooldown_until(
        &self,
        queue_id: &QueueId,
    ) -> Result<Option<chrono::DateTime<Utc>>, QueueError> {
        self.inner.cooldown_until(queue_id).await
    }
    async fn note_cooldown(
        &self,
        queue_id: &QueueId,
        until: chrono::DateTime<Utc>,
    ) -> Result<(), QueueError> {
        if self.fail_cooldown_writes.load(Ordering::SeqCst) {
            return Err(QueueError::Unavailable("cooldown store down".to_string()));
        }
        self.inner.note_cooldown(queue_id, until).await
    }
}

/// Start `text` and stop waiting after `after`, as a job timeout would,
/// while the provider is still working.
async fn abandon(provider: &QueuedChatProvider<Loopback>, text: &str, after: Duration) {
    let waited = tokio::time::timeout(after, provider.chat(request(text))).await;
    assert!(
        waited.is_err(),
        "the caller must stop waiting while the provider works"
    );
}

/// The item of the first call `receipts` saw queued.
fn queued_item(receipts: &InMemoryReceiptSink) -> QueueItemId {
    receipts
        .receipts()
        .iter()
        .find(|receipt| receipt.status == ReceiptStatus::Queued)
        .and_then(|receipt| receipt.item_id.clone())
        .expect("the call was queued")
}

/// `item_id` once it has left `Running`.
async fn settled(queue: &CountsRenewals, item_id: &QueueItemId, within: Duration) -> QueueItem {
    let deadline = Instant::now() + within;
    loop {
        let item = queue.get_item(item_id).await.unwrap().expect("item exists");
        if item.status != QueueStatus::Running {
            return item;
        }
        assert!(
            Instant::now() < deadline,
            "the item is still Running after {within:?}: its lease was renewed {} times, \
             now until {:?}",
            queue.renewals(),
            item.lease_until
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// No lease is renewed from now on: waits over two renewal intervals.
async fn assert_no_more_renewals(queue: &CountsRenewals, backend: &str) {
    let before = queue.renewals();
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(
        queue.renewals(),
        before,
        "{backend}: a lease was renewed after its call ended"
    );
}

async fn an_abandoned_call_completes_and_answers_the_next_identical_request(
    backend: &str,
    queue: Arc<CountsRenewals>,
) {
    let cache = tempfile::tempdir().unwrap();
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(1_500));
    let receipts = Arc::new(InMemoryReceiptSink::default());
    let provider = queued(
        raw.clone(),
        queue.clone(),
        ModelQueueConfig {
            response_cache_dir: Some(cache.path().to_path_buf()),
            ..leased()
        },
    )
    .with_receipt_sink(receipts.clone());

    abandon(&provider, "abandoned", Duration::from_millis(300)).await;
    let item = settled(&queue, &queued_item(&receipts), Duration::from_secs(5)).await;
    assert_eq!(item.status, QueueStatus::Succeeded, "{backend}");
    assert!(item.lease_owner.is_none(), "{backend}: {item:?}");

    let answer = tokio::time::timeout(Duration::from_secs(5), provider.chat(request("abandoned")))
        .await
        .unwrap_or_else(|_| panic!("{backend}: the identical request finishes"))
        .unwrap();
    assert_eq!(answer.text, "abandoned", "{backend}");
    assert_eq!(
        raw.calls.load(Ordering::SeqCst),
        1,
        "{backend}: answered from the cache without a second provider call"
    );
}

async fn an_abandoned_call_that_fails_records_its_class_and_releases_its_lease(
    backend: &str,
    queue: Arc<CountsRenewals>,
) {
    let raw = Loopback::new(unique_identity())
        .slow(Duration::from_millis(1_500))
        .failing_first(vec![ModelError::Unavailable("provider down".to_string())]);
    let receipts = Arc::new(InMemoryReceiptSink::default());
    let provider = queued(raw.clone(), queue.clone(), leased()).with_receipt_sink(receipts.clone());

    abandon(&provider, "doomed", Duration::from_millis(300)).await;
    let item = settled(&queue, &queued_item(&receipts), Duration::from_secs(5)).await;
    assert_eq!(
        item.status,
        QueueStatus::Dead,
        "{backend}: its only attempt failed"
    );
    assert_eq!(
        item.last_error_class.as_deref(),
        Some("unavailable"),
        "{backend}"
    );
    assert!(
        item.lease_owner.is_none() && item.lease_until.is_none(),
        "{backend}: {item:?}"
    );

    // The next identical request reports the recorded failure and does
    // not pay for another provider call.
    let err = tokio::time::timeout(Duration::from_secs(5), provider.chat(request("doomed")))
        .await
        .unwrap_or_else(|_| panic!("{backend}: the identical request finishes"))
        .unwrap_err();
    assert!(
        matches!(err, ModelError::Unavailable(_)),
        "{backend}: {err:?}"
    );
    assert!(err.to_string().contains("exhausted"), "{backend}: {err}");
    assert_eq!(raw.calls.load(Ordering::SeqCst), 1, "{backend}");
}

async fn lease_renewal_ends_with_its_call_when_the_caller_left(
    backend: &str,
    queue: Arc<CountsRenewals>,
) {
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(2_200));
    let receipts = Arc::new(InMemoryReceiptSink::default());
    let provider = queued(raw.clone(), queue.clone(), leased()).with_receipt_sink(receipts.clone());

    abandon(&provider, "renewed", Duration::from_millis(300)).await;
    let item = settled(&queue, &queued_item(&receipts), Duration::from_secs(5)).await;
    assert_eq!(item.status, QueueStatus::Succeeded, "{backend}");
    assert!(
        queue.renewals() >= 1,
        "{backend}: the lease is renewed while the provider works"
    );
    assert_no_more_renewals(&queue, backend).await;
}

/// A response cache that cannot store.
struct FullCache;

impl ResponseCache for FullCache {
    fn load(&self, _entry: &CacheEntry<'_>) -> Result<Option<Value>, ModelError> {
        Ok(None)
    }

    fn store(&self, _entry: &CacheEntry<'_>, _response: &Value) -> Result<(), ModelError> {
        Err(ModelError::Cache("disk full".to_string()))
    }
}

async fn a_failed_cache_write_still_releases_the_lease(backend: &str, queue: Arc<CountsRenewals>) {
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(1_200));
    let receipts = Arc::new(InMemoryReceiptSink::default());
    let provider = queued(raw.clone(), queue.clone(), leased())
        .with_receipt_sink(receipts.clone())
        .with_response_cache(Arc::new(FullCache));

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        provider.chat(request("uncacheable")),
    )
    .await
    .unwrap_or_else(|_| panic!("{backend}: the call finishes"))
    .unwrap_err();
    assert!(matches!(err, ModelError::Cache(_)), "{backend}: {err:?}");
    let item = settled(&queue, &queued_item(&receipts), Duration::from_secs(1)).await;
    assert_eq!(
        item.status,
        QueueStatus::Succeeded,
        "{backend}: the provider answered"
    );
    assert!(item.lease_owner.is_none(), "{backend}: {item:?}");
    assert_no_more_renewals(&queue, backend).await;
}

async fn an_abandoned_call_keeps_its_model_slot_until_it_finishes(
    backend: &str,
    queue: Arc<CountsRenewals>,
) {
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(1_000));
    let provider =
        queued(raw.clone(), queue.clone(), leased()).with_admission(ModelAdmission::new());

    abandon(&provider, "first", Duration::from_millis(300)).await;
    tokio::time::timeout(Duration::from_secs(5), provider.chat(request("second")))
        .await
        .unwrap_or_else(|_| panic!("{backend}: the next call gets the model's slot"))
        .unwrap();
    assert_eq!(raw.calls.load(Ordering::SeqCst), 2, "{backend}");
    assert_eq!(
        raw.peak.load(Ordering::SeqCst),
        1,
        "{backend}: the next call waited for the abandoned one"
    );
}

/// A chat provider with a bug: it panics mid-call.
#[derive(Clone)]
struct PanicsMidCall {
    descriptor: ProviderDescriptor,
    delay: Duration,
}

impl ModelProvider for PanicsMidCall {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }
}

#[async_trait]
impl ChatProvider for PanicsMidCall {
    async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse, ModelError> {
        tokio::time::sleep(self.delay).await;
        panic!("provider bug");
    }
}

async fn a_provider_panic_reaches_its_caller_and_ends_lease_renewal(
    backend: &str,
    queue: Arc<CountsRenewals>,
) {
    let provider = QueuedChatProvider::new(
        PanicsMidCall {
            descriptor: Loopback::new(unique_identity()).descriptor,
            delay: Duration::from_millis(1_600),
        },
        queue.clone(),
        "worker",
        leased(),
    );
    let call = tokio::spawn(async move { provider.chat(request("boom")).await });
    let err = call.await.expect_err("the call panics");
    assert!(err.is_panic(), "{backend}: {err:?}");
    assert!(
        queue.renewals() >= 1,
        "{backend}: the lease is renewed while the provider works"
    );
    assert_no_more_renewals(&queue, backend).await;
}

/// A trace sink whose first write takes `delay`.
struct SlowFirstTrace {
    delay: Duration,
    slowed: std::sync::atomic::AtomicBool,
}

impl SlowFirstTrace {
    fn new(delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            delay,
            slowed: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl symbiotic_trace::TraceSink for SlowFirstTrace {
    async fn record_model_invocation(
        &self,
        _trace: ModelInvocationTrace,
    ) -> Result<(), symbiotic_trace::TraceError> {
        if !self.slowed.swap(true, Ordering::SeqCst) {
            tokio::time::sleep(self.delay).await;
        }
        Ok(())
    }
}

/// A trace sink that cannot write.
struct BrokenTrace;

#[async_trait]
impl symbiotic_trace::TraceSink for BrokenTrace {
    async fn record_model_invocation(
        &self,
        _trace: ModelInvocationTrace,
    ) -> Result<(), symbiotic_trace::TraceError> {
        Err(symbiotic_trace::TraceError::Sink(
            "trace store down".to_string(),
        ))
    }
}

/// Keeps receipts; recording the first `Failed` one takes `delay`.
struct SlowFirstFailureReceipt {
    receipts: InMemoryReceiptSink,
    delay: Duration,
    slowed: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl symbiotic_model::QueueReceiptSink for SlowFirstFailureReceipt {
    async fn record_receipt(&self, receipt: symbiotic_model::QueueReceipt) {
        if receipt.status == ReceiptStatus::Failed && !self.slowed.swap(true, Ordering::SeqCst) {
            tokio::time::sleep(self.delay).await;
        }
        self.receipts.record_receipt(receipt).await;
    }
}

/// Past the 3 s lease of `leased()`, while the attempt is still recording:
/// how many expired leases a claim on `queue_id` would reclaim now.
async fn reclaimable_after_the_lease(queue: &CountsRenewals, queue_id: &QueueId) -> usize {
    tokio::time::sleep(Duration::from_millis(3_500)).await;
    queue.reclaim_expired_leases(queue_id).await.unwrap()
}

async fn a_slow_trace_write_keeps_the_lease_until_the_item_completes(
    backend: &str,
    queue: Arc<CountsRenewals>,
) {
    let cache = tempfile::tempdir().unwrap();
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(100));
    let queue_id = raw.descriptor.queue_id();
    let receipts = Arc::new(InMemoryReceiptSink::default());
    // Two attempts per item: a reclaimed item would be claimed and paid for
    // again.
    let provider = queued(
        raw.clone(),
        queue.clone(),
        ModelQueueConfig {
            response_cache_dir: Some(cache.path().to_path_buf()),
            logical_retry_attempts: 2,
            retry_attempts: 2,
            ..leased()
        },
    )
    .with_receipt_sink(receipts.clone())
    .with_trace_sink(SlowFirstTrace::new(Duration::from_millis(4_000)));

    let call = tokio::spawn({
        let provider = provider.clone();
        async move { provider.chat(request("traced")).await }
    });
    assert_eq!(
        reclaimable_after_the_lease(&queue, &queue_id).await,
        0,
        "{backend}: the lease expired while the trace was written"
    );
    let answer = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .unwrap_or_else(|_| panic!("{backend}: the call finishes"))
        .unwrap()
        .unwrap();
    assert_eq!(answer.text, "traced", "{backend}");
    let item = queue
        .get_item(&queued_item(&receipts))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(item.status, QueueStatus::Succeeded, "{backend}: {item:?}");
    assert_eq!(item.attempt, 1, "{backend}: {item:?}");

    let again = tokio::time::timeout(Duration::from_secs(5), provider.chat(request("traced")))
        .await
        .unwrap_or_else(|_| panic!("{backend}: the identical request finishes"))
        .unwrap();
    assert_eq!(again.text, "traced", "{backend}");
    assert_eq!(
        raw.calls.load(Ordering::SeqCst),
        1,
        "{backend}: no second provider call"
    );
}

async fn a_slow_failure_receipt_keeps_the_lease_until_the_failure_is_recorded(
    backend: &str,
    queue: Arc<CountsRenewals>,
) {
    let raw = Loopback::new(unique_identity())
        .slow(Duration::from_millis(100))
        .failing_first(vec![ModelError::Unavailable("provider down".to_string())]);
    let queue_id = raw.descriptor.queue_id();
    let receipts = Arc::new(SlowFirstFailureReceipt {
        receipts: InMemoryReceiptSink::default(),
        delay: Duration::from_millis(4_000),
        slowed: std::sync::atomic::AtomicBool::new(false),
    });
    let provider = queued(raw.clone(), queue.clone(), leased()).with_receipt_sink(receipts.clone());

    let call = tokio::spawn({
        let provider = provider.clone();
        async move { provider.chat(request("refused")).await }
    });
    assert_eq!(
        reclaimable_after_the_lease(&queue, &queue_id).await,
        0,
        "{backend}: the lease expired while the failure receipt was written"
    );
    let err = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .unwrap_or_else(|_| panic!("{backend}: the call finishes"))
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(err, ModelError::Unavailable(_)),
        "{backend}: {err:?}"
    );
    let item = queue
        .get_item(&queued_item(&receipts.receipts))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(item.status, QueueStatus::Dead, "{backend}: {item:?}");
    assert_eq!(
        item.last_error_class.as_deref(),
        Some("unavailable"),
        "{backend}: {item:?}"
    );
    assert_eq!(
        item.last_error.as_deref(),
        Some("provider unavailable: provider down"),
        "{backend}: the provider's failure, not an expired lease"
    );
    assert_eq!(raw.calls.load(Ordering::SeqCst), 1, "{backend}");
}

async fn a_failed_trace_write_still_completes_the_item(backend: &str, queue: Arc<CountsRenewals>) {
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(1_200));
    let receipts = Arc::new(InMemoryReceiptSink::default());
    let provider = queued(raw.clone(), queue.clone(), leased())
        .with_receipt_sink(receipts.clone())
        .with_trace_sink(Arc::new(BrokenTrace));

    let err = tokio::time::timeout(Duration::from_secs(5), provider.chat(request("untraced")))
        .await
        .unwrap_or_else(|_| panic!("{backend}: the call finishes"))
        .unwrap_err();
    assert!(
        err.to_string().contains("trace store down"),
        "{backend}: {err}"
    );
    let item = settled(&queue, &queued_item(&receipts), Duration::from_secs(1)).await;
    assert_eq!(
        item.status,
        QueueStatus::Succeeded,
        "{backend}: the provider answered"
    );
    assert!(item.lease_owner.is_none(), "{backend}: {item:?}");
    assert_no_more_renewals(&queue, backend).await;
}

async fn a_failed_cooldown_write_still_records_the_failure(
    backend: &str,
    queue: Arc<CountsRenewals>,
) {
    queue.fail_cooldown_writes.store(true, Ordering::SeqCst);
    let raw = Loopback::new(unique_identity())
        .slow(Duration::from_millis(1_200))
        .failing_first(vec![ModelError::Unavailable("provider down".to_string())]);
    let receipts = Arc::new(InMemoryReceiptSink::default());
    let provider = queued(raw.clone(), queue.clone(), leased()).with_receipt_sink(receipts.clone());

    let err = tokio::time::timeout(Duration::from_secs(5), provider.chat(request("cooling")))
        .await
        .unwrap_or_else(|_| panic!("{backend}: the call finishes"))
        .unwrap_err();
    assert!(
        err.to_string().contains("cooldown store down"),
        "{backend}: {err}"
    );
    let item = settled(&queue, &queued_item(&receipts), Duration::from_secs(1)).await;
    assert_eq!(item.status, QueueStatus::Dead, "{backend}: {item:?}");
    assert_eq!(
        item.last_error_class.as_deref(),
        Some("unavailable"),
        "{backend}: {item:?}"
    );
    assert!(item.lease_owner.is_none(), "{backend}: {item:?}");
    assert_no_more_renewals(&queue, backend).await;
}
