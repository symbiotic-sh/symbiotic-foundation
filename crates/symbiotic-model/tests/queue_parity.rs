//! Queued-provider behaviour hosts depend on: shared admission, usage
//! receipts, retry timing and classification, eviction recovery, request
//! capture and the response-cache seam. Loopback providers only.
#![cfg(feature = "queue")]

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use symbiotic_core::{ModelIdentity, QueueId, QueueItemId, Sensitivity, TraceId};
use symbiotic_model::{
    CacheEntry, ChatMessage, ChatProvider, ChatRequest, ChatResponse, InMemoryReceiptSink,
    ModelAdmission, ModelCapability, ModelError, ModelProvider, ModelQueueConfig, ProviderAuthMode,
    ProviderClass, ProviderDescriptor, QueuedChatProvider, ReceiptStatus, ResponseCache,
};
use symbiotic_queue::{
    ClaimRequest, EnqueueOutcome, EnqueueRequest, FailOutcome, MemoryQueue, QueueBackend,
    QueueError, QueueItem,
};
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
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
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

/// Reports the first claimed item as missing, as a retention-bounded
/// backend does after evicting it.
struct EvictsOnce {
    inner: MemoryQueue,
    evicted: AtomicBool,
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
        if !self.evicted.swap(true, Ordering::SeqCst) {
            return Err(QueueError::NotFound(item_id.0.clone()));
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
    let queue: Arc<dyn QueueBackend> = Arc::new(EvictsOnce {
        inner: MemoryQueue::new(),
        evicted: AtomicBool::new(false),
    });
    let raw = Loopback::new(unique_identity());
    let response = queued(raw.clone(), queue, config())
        .chat(request("still here"))
        .await
        .unwrap();
    assert_eq!(response.text, "still here");
    assert_eq!(raw.calls.load(Ordering::SeqCst), 1);
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
