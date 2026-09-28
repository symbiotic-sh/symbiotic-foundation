//! The runtime facade: shared limits across bindings, persistence with a
//! state directory, and cache scoping. Loopback providers only.

use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use symbiotic_ai_runtime::model::{ChatMessage, ModelCapability, ProviderAuthMode, ProviderClass};
use symbiotic_ai_runtime::{
    ChatProvider, ChatRequest, ChatResponse, DirResponseCache, InMemoryReceiptSink, ModelBinding,
    ModelError, ModelProvider, ModelQueueConfig, ProviderDescriptor, ReceiptStatus,
    ResponseCacheMode, Runtime, RuntimeConfig,
};
use symbiotic_core::{ModelIdentity, Sensitivity, TraceId};
use symbiotic_trace::{InvocationOutcome, ModelInvocationTrace};

static MODEL_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn unique_identity() -> ModelIdentity {
    ModelIdentity::new(
        "chat",
        "loopback",
        format!("runtime-{}", MODEL_COUNTER.fetch_add(1, Ordering::SeqCst)),
    )
}

fn policy() -> ModelQueueConfig {
    ModelQueueConfig {
        max_in_flight: 2,
        lease_seconds: 60,
        logical_retry_attempts: 1,
        retry_attempts: 1,
        retry_jitter_seconds: 0,
        request_timeout_seconds: Some(10),
        retry_base_delay_ms: 10,
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

#[derive(Clone)]
struct Loopback {
    descriptor: ProviderDescriptor,
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    fail: Option<Arc<ModelError>>,
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
            fail: None,
            delay: Duration::from_millis(15),
        }
    }

    fn slow(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    fn unavailable(self) -> Self {
        self.failing(ModelError::Unavailable("loopback is down".to_string()))
    }

    fn failing(mut self, err: ModelError) -> Self {
        self.fail = Some(Arc::new(err));
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
        if let Some(err) = &self.fail {
            return Err(match err.as_ref() {
                ModelError::Unavailable(message) => ModelError::Unavailable(message.clone()),
                ModelError::Provider(message) => ModelError::Provider(message.clone()),
                other => ModelError::Provider(other.to_string()),
            });
        }
        Ok(ChatResponse {
            text: format!(
                "{}:{}",
                self.descriptor.identity.model.0, request.messages[0].content
            ),
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
                cache: Default::default(),
                usage: Default::default(),
                timing: Default::default(),
                outcome: InvocationOutcome::Succeeded,
                error_class: None,
                audit_refs: Vec::new(),
                metadata: json!({}),
                timestamp: chrono::Utc::now(),
            },
            raw_provider_response: None,
        })
    }
}

fn persistent(dir: &std::path::Path) -> Runtime {
    Runtime::open(RuntimeConfig {
        state_dir: Some(dir.to_path_buf()),
        ..RuntimeConfig::default()
    })
    .unwrap()
}

#[tokio::test]
async fn bindings_of_one_model_share_its_cap() {
    let runtime = Runtime::in_memory();
    let raw = Loopback::new(unique_identity());
    let answer = runtime
        .chat(ModelBinding::new(raw.clone()).with_policy(policy()))
        .unwrap();
    let judge = runtime
        .chat(ModelBinding::new(raw.clone()).with_policy(policy()))
        .unwrap();
    let calls: Vec<_> = (0..10)
        .map(|idx| {
            let provider = if idx % 2 == 0 {
                answer.clone()
            } else {
                judge.clone()
            };
            tokio::spawn(async move { provider.chat(request(&format!("q{idx}"))).await })
        })
        .collect();
    for call in calls {
        call.await.unwrap().unwrap();
    }
    assert_eq!(raw.calls.load(Ordering::SeqCst), 10);
    assert_eq!(raw.peak.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn conflicting_limits_for_one_model_are_rejected_and_other_models_are_independent() {
    let runtime = Runtime::in_memory();
    let identity = unique_identity();
    runtime
        .chat(ModelBinding::new(Loopback::new(identity.clone())).with_policy(policy()))
        .unwrap();
    let conflicting = ModelQueueConfig {
        requests_per_minute: Some(60),
        ..policy()
    };
    let err = runtime
        .chat(ModelBinding::new(Loopback::new(identity)).with_policy(conflicting.clone()))
        .err()
        .expect("a second policy for one model is rejected");
    assert!(matches!(err, ModelError::InvalidRequest(_)), "{err:?}");
    // Retry settings may differ per binding; only shared limits must agree.
    runtime
        .chat(ModelBinding::new(Loopback::new(unique_identity())).with_policy(conflicting))
        .unwrap();
}

#[tokio::test]
async fn host_provider_objects_can_be_bound() {
    let runtime = Runtime::in_memory();
    let raw: Arc<dyn ChatProvider> = Arc::new(Loopback::new(unique_identity()));
    let chat = runtime
        .chat(ModelBinding::new(raw).with_policy(policy()))
        .unwrap();
    assert!(
        chat.chat(request("hi"))
            .await
            .unwrap()
            .text
            .ends_with(":hi")
    );
}

#[tokio::test]
async fn a_persistent_runtime_keeps_state_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("ai-runtime");
    let runtime = persistent(&state);
    assert!(runtime.is_persistent());
    assert!(state.join(symbiotic_ai_runtime::QUEUE_DATABASE).is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = std::fs::metadata(&state).unwrap().permissions().mode();
        let db_mode = std::fs::metadata(state.join(symbiotic_ai_runtime::QUEUE_DATABASE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        assert_eq!(db_mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn cached_responses_survive_a_restart_and_stay_scoped_to_their_model() {
    let dir = tempfile::tempdir().unwrap();
    let first_model = Loopback::new(unique_identity());
    let second_model = Loopback::new(unique_identity());

    let runtime = persistent(dir.path());
    let chat = runtime
        .chat(ModelBinding::new(first_model.clone()).with_policy(policy()))
        .unwrap();
    let original = chat.chat(request("same question")).await.unwrap();
    drop((chat, runtime));

    let reopened = persistent(dir.path());
    let chat = reopened
        .chat(ModelBinding::new(first_model.clone()).with_policy(policy()))
        .unwrap();
    let replay = chat.chat(request("same question")).await.unwrap();
    assert_eq!(replay.text, original.text);
    assert_eq!(first_model.calls.load(Ordering::SeqCst), 1);

    // Another model asked the same question gets its own answer.
    let other = reopened
        .chat(ModelBinding::new(second_model.clone()).with_policy(policy()))
        .unwrap();
    let answer = other.chat(request("same question")).await.unwrap();
    assert_ne!(answer.text, original.text);
    assert_eq!(second_model.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn attempt_budgets_survive_a_restart_only_when_persistent() {
    let dir = tempfile::tempdir().unwrap();
    let down = Loopback::new(unique_identity()).unavailable();
    let binding = || {
        ModelBinding::new(down.clone())
            .with_policy(policy())
            .with_response_cache(ResponseCacheMode::Off)
    };

    let runtime = persistent(dir.path());
    runtime
        .chat(binding())
        .unwrap()
        .chat(request("doomed"))
        .await
        .unwrap_err();
    assert_eq!(down.calls.load(Ordering::SeqCst), 1);

    // The exhausted budget is on disk: a restarted host does not pay again.
    let reopened = persistent(dir.path());
    let err = reopened
        .chat(binding())
        .unwrap()
        .chat(request("doomed"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exhausted"), "{err}");
    assert_eq!(down.calls.load(Ordering::SeqCst), 1);

    // An in-memory runtime starts with a fresh budget.
    Runtime::in_memory()
        .chat(binding())
        .unwrap()
        .chat(request("doomed"))
        .await
        .unwrap_err();
    assert_eq!(down.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_in_memory_runtime_caches_nothing_by_default_and_binding_sinks_apply() {
    let runtime = Runtime::in_memory();
    let raw = Loopback::new(unique_identity());
    let receipts = Arc::new(InMemoryReceiptSink::default());
    let chat = runtime
        .chat(
            ModelBinding::new(raw.clone())
                .with_policy(policy())
                .with_receipt_sink(receipts.clone()),
        )
        .unwrap();
    chat.chat(request("again")).await.unwrap();
    chat.chat(request("again")).await.unwrap();
    assert_eq!(raw.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        receipts
            .receipts()
            .iter()
            .filter(|receipt| receipt.status == ReceiptStatus::Succeeded)
            .count(),
        2
    );
}

#[tokio::test]
async fn a_queue_id_isolates_a_role_or_pools_models() {
    let runtime = Runtime::in_memory();
    let raw = Loopback::new(unique_identity());
    let one_slot = ModelQueueConfig {
        max_in_flight: 1,
        ..policy()
    };
    // The same model on its own queue and on an isolated role queue: the two
    // queues do not share the one slot.
    let shared = runtime
        .chat(ModelBinding::new(raw.clone()).with_policy(one_slot.clone()))
        .unwrap();
    let isolated = runtime
        .chat(
            ModelBinding::new(raw.clone())
                .with_policy(one_slot.clone())
                .with_queue_id(symbiotic_core::QueueId::new("answer:isolated")),
        )
        .unwrap();
    let (a, b) = tokio::join!(shared.chat(request("a")), isolated.chat(request("b")));
    a.unwrap();
    b.unwrap();
    assert_eq!(raw.peak.load(Ordering::SeqCst), 2);

    // Two models pooled on one queue share its slot: count their calls on
    // one gauge.
    let first = Loopback::new(unique_identity());
    let mut second = Loopback::new(unique_identity());
    second.active = first.active.clone();
    second.peak = first.peak.clone();
    let pool = symbiotic_core::QueueId::new("chat:pool:shared");
    let first_chat = runtime
        .chat(
            ModelBinding::new(first.clone())
                .with_policy(one_slot.clone())
                .with_queue_id(pool.clone()),
        )
        .unwrap();
    let second_chat = runtime
        .chat(
            ModelBinding::new(second.clone())
                .with_policy(one_slot)
                .with_queue_id(pool),
        )
        .unwrap();
    let (a, b) = tokio::join!(
        first_chat.chat(request("x")),
        second_chat.chat(request("y"))
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        first.peak.load(Ordering::SeqCst),
        1,
        "pooled models share one slot"
    );
}

#[tokio::test]
async fn pooled_models_keep_separate_budgets_for_the_same_request() {
    let runtime = Runtime::in_memory();
    let pool = symbiotic_core::QueueId::new("chat:pool:budgets");
    let down = Loopback::new(unique_identity()).unavailable();
    let up = Loopback::new(unique_identity());
    let bind = |raw: Loopback| {
        runtime
            .chat(
                ModelBinding::new(raw)
                    .with_policy(policy())
                    .with_queue_id(pool.clone()),
            )
            .unwrap()
    };
    bind(down.clone())
        .chat(request("identical"))
        .await
        .unwrap_err();
    // The other model's identical request is its own call, not the first
    // model's exhausted one.
    let answer = bind(up.clone()).chat(request("identical")).await.unwrap();
    assert!(answer.text.ends_with(":identical"));
    assert_eq!(up.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_exhausted_error_keeps_its_class_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let broken =
        Loopback::new(unique_identity()).failing(ModelError::Provider("bad json".to_string()));
    let binding = || {
        ModelBinding::new(broken.clone())
            .with_policy(ModelQueueConfig {
                retry_provider_errors: true,
                ..policy()
            })
            .with_response_cache(ResponseCacheMode::Off)
    };
    let first = persistent(dir.path())
        .chat(binding())
        .unwrap()
        .chat(request("unparsable"))
        .await
        .unwrap_err();
    assert!(matches!(first, ModelError::Provider(_)), "{first:?}");

    let again = persistent(dir.path())
        .chat(binding())
        .unwrap()
        .chat(request("unparsable"))
        .await
        .unwrap_err();
    assert!(matches!(again, ModelError::Provider(_)), "{again:?}");
    assert!(again.to_string().contains("exhausted"), "{again}");
    assert_eq!(broken.calls.load(Ordering::SeqCst), 1);
}

/// A 3 s lease, renewed every second.
fn leased() -> ModelQueueConfig {
    ModelQueueConfig {
        lease_seconds: 3,
        ..policy()
    }
}

/// The reported defect: a job timeout gives up on the first call while the
/// provider works, and the identical call behind it must still finish.
async fn an_abandoned_call_does_not_block_the_identical_request_behind_it(runtime: Runtime) {
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(1_500));
    let chat = runtime
        .chat(ModelBinding::new(raw.clone()).with_policy(leased()))
        .unwrap();

    let first = tokio::time::timeout(Duration::from_millis(500), chat.chat(request("same"))).await;
    assert!(first.is_err(), "the first caller stops waiting");

    let second = tokio::time::timeout(Duration::from_secs(20), chat.chat(request("same")))
        .await
        .expect("the identical request finishes")
        .unwrap();
    assert!(second.text.ends_with(":same"), "{}", second.text);
}

/// An identical caller already waiting, and one arriving later, both get the
/// abandoned call's answer from one provider call.
async fn a_waiter_and_a_later_caller_share_the_answer_of_an_abandoned_call(
    runtime: Runtime,
    cache: ResponseCacheMode,
) {
    let raw = Loopback::new(unique_identity()).slow(Duration::from_millis(1_000));
    let chat = runtime
        .chat(
            ModelBinding::new(raw.clone())
                .with_policy(leased())
                .with_response_cache(cache),
        )
        .unwrap();

    let waiter = tokio::spawn({
        let chat = chat.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            chat.chat(request("shared")).await
        }
    });
    let first =
        tokio::time::timeout(Duration::from_millis(300), chat.chat(request("shared"))).await;
    assert!(first.is_err(), "the first caller stops waiting");

    let waited = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the identical waiter finishes")
        .unwrap()
        .unwrap();
    let later = tokio::time::timeout(Duration::from_secs(5), chat.chat(request("shared")))
        .await
        .expect("the later identical request finishes")
        .unwrap();
    assert_eq!(waited.text, later.text);
    assert_eq!(
        raw.calls.load(Ordering::SeqCst),
        1,
        "one provider call answered all three callers"
    );
}

/// `MemoryQueue`.
mod in_memory {
    use super::*;

    #[tokio::test]
    async fn an_abandoned_call_does_not_block_the_identical_request_behind_it() {
        super::an_abandoned_call_does_not_block_the_identical_request_behind_it(
            Runtime::in_memory(),
        )
        .await;
    }

    #[tokio::test]
    async fn a_waiter_and_a_later_caller_share_the_answer_of_an_abandoned_call() {
        // An in-memory runtime caches nothing by default; a host cache
        // answers the later callers.
        let cache = tempfile::tempdir().unwrap();
        super::a_waiter_and_a_later_caller_share_the_answer_of_an_abandoned_call(
            Runtime::in_memory(),
            ResponseCacheMode::Custom(Arc::new(DirResponseCache::new(cache.path()))),
        )
        .await;
    }
}

/// `SqliteQueue` in a state directory.
mod persistent {
    use super::*;

    #[tokio::test]
    async fn an_abandoned_call_does_not_block_the_identical_request_behind_it() {
        let dir = tempfile::tempdir().unwrap();
        super::an_abandoned_call_does_not_block_the_identical_request_behind_it(persistent(
            dir.path(),
        ))
        .await;
    }

    #[tokio::test]
    async fn a_waiter_and_a_later_caller_share_the_answer_of_an_abandoned_call() {
        let dir = tempfile::tempdir().unwrap();
        super::a_waiter_and_a_later_caller_share_the_answer_of_an_abandoned_call(
            persistent(dir.path()),
            ResponseCacheMode::Default,
        )
        .await;
    }
}
