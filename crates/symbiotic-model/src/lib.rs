//! Provider-neutral model runtime contracts.
//!
//! Implementations may wrap HTTP SDKs, local CLIs, subscription-backed tools,
//! or host-owned adapters. Policy and scheduling are supplied by the host.

use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use symbiotic_core::{
    InvocationSource, ModelIdentity, ModelName, ModelTier, Operation, Operator, QueueId,
    QueueItemId, RoleBinding, Sensitivity, TraceId,
};
use symbiotic_queue::{
    EnqueueDisposition, EnqueueOutcome, EnqueueRequest, FailOutcome, QueueBackend, QueueItem,
    QueueStatus,
};
use symbiotic_trace::{
    CacheStatus, CacheTrace, InvocationOutcome, ModelInvocationTrace, TimingTrace, TraceSink,
    UsageTrace,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderClass {
    Local,
    Cloud,
    Aggregator,
    CliSession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    Chat,
    Embedding,
    Rerank,
    Vision,
    ImageGeneration,
    VideoGeneration,
    AgentTask,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ProviderAuthMode {
    None,
    ApiKey {
        secret_ref: String,
    },
    OAuthAccessToken {
        token_ref: String,
    },
    GoogleAdc {
        account_ref: Option<String>,
    },
    OAuthMintsApiKey {
        provider: String,
        account_ref: String,
    },
    CliSession {
        tool: String,
        account_ref: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub identity: ModelIdentity,
    pub provider_class: ProviderClass,
    pub capabilities: Vec<ModelCapability>,
    pub auth_mode: ProviderAuthMode,
    pub metadata: Value,
}

impl ProviderDescriptor {
    pub fn queue_id(&self) -> QueueId {
        self.identity.queue_id()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default)]
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub response_format: Option<String>,
    pub sensitivity: Sensitivity,
    pub role_binding: Option<String>,
    pub source: Option<String>,
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatResponse {
    pub text: String,
    pub finish_reason: Option<String>,
    pub trace: ModelInvocationTrace,
    pub raw_provider_response: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    pub inputs: Vec<String>,
    pub dimensions: Option<usize>,
    pub task: Option<String>,
    pub sensitivity: Sensitivity,
    pub role_binding: Option<String>,
    pub source: Option<String>,
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    pub vectors: Vec<Vec<f32>>,
    pub dimensions: usize,
    pub trace: ModelInvocationTrace,
    pub raw_provider_response: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RerankRequest {
    pub query: String,
    pub documents: Vec<String>,
    pub top_k: Option<usize>,
    pub sensitivity: Sensitivity,
    pub role_binding: Option<String>,
    pub source: Option<String>,
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RerankHit {
    pub index: usize,
    pub score: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RerankResponse {
    pub hits: Vec<RerankHit>,
    pub trace: ModelInvocationTrace,
    pub raw_provider_response: Option<Value>,
}

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("provider auth failed: {0}")]
    Auth(String),
    #[error("provider rate limited: {0}")]
    RateLimited(String),
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),
    #[error("provider timed out: {0}")]
    Timeout(String),
    #[error("capability unsupported: {0:?}")]
    Unsupported(ModelCapability),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("provider failed: {0}")]
    Provider(String),
    #[error("model queue failed: {0}")]
    Queue(String),
    #[error("model cache failed: {0}")]
    Cache(String),
}

#[async_trait]
pub trait ModelProvider: Send + Sync {
    fn descriptor(&self) -> &ProviderDescriptor;
}

#[async_trait]
pub trait ChatProvider: ModelProvider {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError>;
}

#[async_trait]
pub trait EmbeddingProvider: ModelProvider {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError>;
}

#[async_trait]
pub trait RerankProvider: ModelProvider {
    async fn rerank(&self, request: RerankRequest) -> Result<RerankResponse, ModelError>;
}

#[async_trait]
pub trait CredentialResolver: Send + Sync {
    async fn resolve_auth(&self, mode: &ProviderAuthMode) -> Result<ResolvedAuth, ModelError>;
}

#[derive(Clone, Debug)]
pub enum ResolvedAuth {
    None,
    Bearer(String),
    ApiKey(String),
    Headers(Vec<(String, String)>),
    LocalSession { tool: String, account: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectionRequest {
    pub capability: ModelCapability,
    pub tier: Option<ModelTier>,
    pub sensitivity: Sensitivity,
    pub role_binding: Option<RoleBinding>,
    pub source: Option<InvocationSource>,
    pub preferred: Option<ModelIdentity>,
    pub allowed_classes: Vec<ProviderClass>,
}

#[async_trait]
pub trait ModelSelector: Send + Sync {
    async fn select(&self, request: SelectionRequest) -> Result<Vec<ModelIdentity>, ModelError>;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProviderCatalog {
    providers: Vec<ProviderDescriptor>,
}

impl ProviderCatalog {
    pub fn new(providers: Vec<ProviderDescriptor>) -> Self {
        Self { providers }
    }

    pub fn register(&mut self, descriptor: ProviderDescriptor) {
        self.providers.push(descriptor);
    }

    pub fn providers(&self) -> &[ProviderDescriptor] {
        &self.providers
    }

    pub fn select(&self, request: &SelectionRequest) -> Vec<ModelIdentity> {
        let allowed = if request.allowed_classes.is_empty() {
            vec![
                ProviderClass::Local,
                ProviderClass::Cloud,
                ProviderClass::Aggregator,
                ProviderClass::CliSession,
            ]
        } else {
            request.allowed_classes.clone()
        };
        let mut candidates = self
            .providers
            .iter()
            .filter(|provider| provider.capabilities.contains(&request.capability))
            .filter(|provider| allowed.contains(&provider.provider_class))
            .filter(|provider| {
                !matches!(
                    request.sensitivity,
                    Sensitivity::Private | Sensitivity::Restricted
                ) || matches!(
                    provider.provider_class,
                    ProviderClass::Local | ProviderClass::CliSession
                )
            })
            .map(|provider| provider.identity.clone())
            .collect::<Vec<_>>();
        if let Some(preferred) = &request.preferred {
            candidates.sort_by_key(|candidate| if candidate == preferred { 0 } else { 1 });
        }
        candidates
    }
}

#[async_trait]
impl ModelSelector for ProviderCatalog {
    async fn select(&self, request: SelectionRequest) -> Result<Vec<ModelIdentity>, ModelError> {
        Ok(self.select(&request))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelQueueConfig {
    pub max_in_flight: usize,
    pub lease_seconds: u64,
    pub logical_retry_attempts: u32,
    pub retry_attempts: u32,
    pub retry_jitter_seconds: u64,
    pub request_timeout_seconds: Option<u64>,
    pub requests_per_minute: Option<u32>,
    pub input_units_per_minute: Option<u64>,
    pub response_cache_dir: Option<PathBuf>,
}

impl Default for ModelQueueConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 1,
            lease_seconds: 600,
            logical_retry_attempts: 3,
            retry_attempts: 3,
            retry_jitter_seconds: 20,
            request_timeout_seconds: Some(600),
            requests_per_minute: None,
            input_units_per_minute: None,
            response_cache_dir: None,
        }
    }
}

/// Production-oriented queue defaults for known model identities.
///
/// Unknown models deliberately return `None` so the host/product layer can apply
/// its operation defaults. Direct use of `ModelQueueConfig::default()` remains a
/// conservative local fallback; local Ollama-style models also get an explicit
/// one-at-a-time catalog entry.
pub fn default_model_queue_config(identity: &ModelIdentity) -> Option<ModelQueueConfig> {
    match identity.queue_id().0.as_str() {
        "chat:deepseek:deepseek-v4-flash" => Some(ModelQueueConfig {
            max_in_flight: 2_000,
            lease_seconds: 600,
            logical_retry_attempts: 4,
            retry_attempts: 4,
            retry_jitter_seconds: 20,
            request_timeout_seconds: Some(600),
            requests_per_minute: None,
            input_units_per_minute: None,
            response_cache_dir: None,
        }),
        "chat:deepseek:deepseek-v4-pro" => Some(ModelQueueConfig {
            max_in_flight: 400,
            lease_seconds: 600,
            logical_retry_attempts: 4,
            retry_attempts: 4,
            retry_jitter_seconds: 20,
            request_timeout_seconds: Some(600),
            requests_per_minute: Some(600),
            input_units_per_minute: None,
            response_cache_dir: None,
        }),
        "chat:gemini:gemini-3.5-flash" => Some(ModelQueueConfig {
            max_in_flight: 100,
            lease_seconds: 600,
            logical_retry_attempts: 3,
            retry_attempts: 3,
            retry_jitter_seconds: 20,
            request_timeout_seconds: Some(600),
            requests_per_minute: Some(1_000),
            input_units_per_minute: None,
            response_cache_dir: None,
        }),
        "chat:gemini:gemini-3.1-pro-preview" => Some(ModelQueueConfig {
            max_in_flight: 500,
            lease_seconds: 600,
            logical_retry_attempts: 3,
            retry_attempts: 3,
            retry_jitter_seconds: 20,
            request_timeout_seconds: Some(600),
            requests_per_minute: Some(100),
            input_units_per_minute: None,
            response_cache_dir: None,
        }),
        "embedding:gemini:gemini-embedding-2" => Some(ModelQueueConfig {
            max_in_flight: 1_000,
            lease_seconds: 300,
            logical_retry_attempts: 6,
            retry_attempts: 6,
            retry_jitter_seconds: 10,
            request_timeout_seconds: Some(300),
            requests_per_minute: Some(4_500),
            input_units_per_minute: Some(5_000_000),
            response_cache_dir: None,
        }),
        "embedding:openrouter:qwen/qwen3-embedding-8b"
        | "embedding:openrouter:qwen/qwen3-embedding-4b" => Some(ModelQueueConfig {
            max_in_flight: 2_000,
            lease_seconds: 300,
            logical_retry_attempts: 6,
            retry_attempts: 6,
            retry_jitter_seconds: 10,
            request_timeout_seconds: Some(300),
            requests_per_minute: None,
            input_units_per_minute: None,
            response_cache_dir: None,
        }),
        // Nemotron free reranker: keep the elevated openrouter concurrency but cap the per-request
        // timeout at 60s (the free tier stalls rather than erroring) and let requests_per_minute fall
        // through to the host's default rate bucket (None here).
        "rerank:openrouter:nvidia/llama-nemotron-rerank-vl-1b-v2:free" => Some(ModelQueueConfig {
            max_in_flight: 200,
            lease_seconds: 600,
            logical_retry_attempts: 4,
            retry_attempts: 4,
            retry_jitter_seconds: 20,
            request_timeout_seconds: Some(60),
            requests_per_minute: None,
            input_units_per_minute: None,
            response_cache_dir: None,
        }),
        // (openrouter qwen chat: removed the conservative 200/600rpm entry — falls through to the
        // generic operator=openrouter fallback at 1000; throttle reactively only if it starts 429ing.)
        _ if identity.operator.0 == "ollama" || identity.operator.0 == "local" => {
            Some(ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 600,
                logical_retry_attempts: 2,
                retry_attempts: 2,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(600),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: None,
            })
        }
        // Sane default for any not-individually-catalogued OpenRouter model (chat or embedding):
        // OpenRouter fronts many providers and handles high concurrency, so without this an
        // uncatalogued model would fall to max_in_flight=8 and serialize. Matches the catalogued
        // OpenRouter embedding rate (1000); the queue's retry/backoff absorbs any 429 bursts.
        _ if identity.operator.0 == "openrouter" => Some(ModelQueueConfig {
            max_in_flight: 1_000,
            lease_seconds: 600,
            logical_retry_attempts: 4,
            retry_attempts: 4,
            retry_jitter_seconds: 20,
            request_timeout_seconds: Some(600),
            requests_per_minute: None,
            input_units_per_minute: None,
            response_cache_dir: None,
        }),
        _ => None,
    }
}

#[derive(Clone)]
pub struct QueuedChatProvider<C> {
    inner: C,
    queue: Arc<dyn QueueBackend>,
    trace_sink: Option<Arc<dyn TraceSink>>,
    worker_id: String,
    config: ModelQueueConfig,
}

impl<C> QueuedChatProvider<C> {
    pub fn new(
        inner: C,
        queue: Arc<dyn QueueBackend>,
        worker_id: impl Into<String>,
        config: ModelQueueConfig,
    ) -> Self {
        Self {
            inner,
            queue,
            trace_sink: None,
            worker_id: worker_id.into(),
            config,
        }
    }

    pub fn with_trace_sink(mut self, sink: Arc<dyn TraceSink>) -> Self {
        self.trace_sink = Some(sink);
        self
    }
}

#[async_trait]
impl<C> ModelProvider for QueuedChatProvider<C>
where
    C: ChatProvider + Clone + Send + Sync,
{
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }
}

#[async_trait]
impl<C> ChatProvider for QueuedChatProvider<C>
where
    C: ChatProvider + Clone + Send + Sync + 'static,
{
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        run_queued(
            self.inner.descriptor().clone(),
            self.queue.clone(),
            self.trace_sink.clone(),
            self.worker_id.clone(),
            self.config.clone(),
            ModelCapability::Chat,
            "chat",
            &request,
            |inner: C, request| async move { inner.chat(request).await },
            self.inner.clone(),
        )
        .await
    }
}

#[derive(Clone)]
pub struct QueuedEmbeddingProvider<E> {
    inner: E,
    queue: Arc<dyn QueueBackend>,
    trace_sink: Option<Arc<dyn TraceSink>>,
    worker_id: String,
    config: ModelQueueConfig,
}

impl<E> QueuedEmbeddingProvider<E> {
    pub fn new(
        inner: E,
        queue: Arc<dyn QueueBackend>,
        worker_id: impl Into<String>,
        config: ModelQueueConfig,
    ) -> Self {
        Self {
            inner,
            queue,
            trace_sink: None,
            worker_id: worker_id.into(),
            config,
        }
    }

    pub fn with_trace_sink(mut self, sink: Arc<dyn TraceSink>) -> Self {
        self.trace_sink = Some(sink);
        self
    }
}

#[async_trait]
impl<E> ModelProvider for QueuedEmbeddingProvider<E>
where
    E: EmbeddingProvider + Clone + Send + Sync,
{
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }
}

#[async_trait]
impl<E> EmbeddingProvider for QueuedEmbeddingProvider<E>
where
    E: EmbeddingProvider + Clone + Send + Sync + 'static,
{
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        run_queued(
            self.inner.descriptor().clone(),
            self.queue.clone(),
            self.trace_sink.clone(),
            self.worker_id.clone(),
            self.config.clone(),
            ModelCapability::Embedding,
            "embedding",
            &request,
            |inner: E, request| async move { inner.embed(request).await },
            self.inner.clone(),
        )
        .await
    }
}

async fn run_queued<P, Req, Res, Fut>(
    descriptor: ProviderDescriptor,
    queue: Arc<dyn QueueBackend>,
    trace_sink: Option<Arc<dyn TraceSink>>,
    worker_id: String,
    config: ModelQueueConfig,
    capability: ModelCapability,
    kind: &str,
    request: &Req,
    call: impl Fn(P, Req) -> Fut + Send + Sync,
    provider: P,
) -> Result<Res, ModelError>
where
    P: Clone + Send + Sync + 'static,
    Req: Clone + Serialize + Send + Sync + 'static,
    Req: BudgetedModelRequest,
    Res: Clone + Serialize + for<'de> Deserialize<'de> + TraceCarrier + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Res, ModelError>> + Send,
{
    let request_hash = hash_json(request)?;
    if let Some(cache_dir) = &config.response_cache_dir {
        if let Some(cached) = load_cache::<Res>(cache_dir, kind, &request_hash)? {
            return return_cached_response(
                cached,
                &descriptor,
                &trace_sink,
                request_hash.clone(),
                None,
            )
            .await;
        }
    }

    let queued_at = std::time::Instant::now();
    let logical_state = LogicalRetryState {
        attempts_used: 0,
        max_attempts: config
            .logical_retry_attempts
            .max(config.retry_attempts)
            .max(1),
    };
    let payload = model_queue_payload(&capability, &request_hash, &descriptor, logical_state);
    let idempotency_key = Some(format!("{}:{request_hash}", descriptor.queue_id().0));
    let mut enqueue = queue
        .enqueue(EnqueueRequest {
            queue_id: descriptor.queue_id(),
            kind: kind.to_string(),
            payload: payload.clone(),
            idempotency_key: idempotency_key.clone(),
            run_after: None,
            max_attempts: Some(config.retry_attempts),
            force: false,
        })
        .await
        .map_err(|err| ModelError::Queue(err.to_string()))?;
    if enqueue.disposition == EnqueueDisposition::TerminalDuplicate {
        match enqueue.item.status {
            QueueStatus::Dead => {
                let dead_err = dead_item_retry_error(&enqueue.item);
                if let Some(next) = reenqueue_dead_item(
                    queue.as_ref(),
                    &descriptor,
                    capability,
                    kind,
                    &request_hash,
                    &idempotency_key,
                    &enqueue.item,
                    &config,
                    &dead_err,
                )
                .await?
                {
                    enqueue = next;
                } else {
                    return Err(exhausted_request_error(&descriptor, &enqueue.item, &config));
                }
            }
            QueueStatus::Succeeded if config.response_cache_dir.is_none() => {
                return Err(ModelError::Cache(format!(
                    "{} request already completed but no cached response was available",
                    descriptor.queue_id().0
                )));
            }
            QueueStatus::Succeeded => {
                enqueue = reenqueue_succeeded_without_cache(
                    queue.as_ref(),
                    &descriptor,
                    capability,
                    kind,
                    &request_hash,
                    &idempotency_key,
                    &config,
                )
                .await?;
            }
            QueueStatus::Pending | QueueStatus::Running | QueueStatus::Failed => {}
        }
    }

    loop {
        if let Some(cache_dir) = &config.response_cache_dir {
            if let Some(cached) = load_cache::<Res>(cache_dir, kind, &request_hash)? {
                return return_cached_response(
                    cached,
                    &descriptor,
                    &trace_sink,
                    request_hash.clone(),
                    Some(enqueue.item.item_id.clone()),
                )
                .await;
            }
        }
        wait_for_model_cooldown(queue.as_ref(), &descriptor.queue_id()).await?;
        wait_for_model_budget(&descriptor.queue_id(), &config, request).await?;
        let Some(item) = queue
            .claim_item(
                &enqueue.item.item_id,
                &worker_id,
                config.lease_seconds,
                Some(config.max_in_flight.max(1)),
            )
            .await
            .map_err(|err| ModelError::Queue(err.to_string()))?
        else {
            if let Some(current) = queue
                .get_item(&enqueue.item.item_id)
                .await
                .map_err(|err| ModelError::Queue(err.to_string()))?
            {
                match current.status {
                    QueueStatus::Dead => {
                        let dead_err = dead_item_retry_error(&current);
                        if let Some(next) = reenqueue_dead_item(
                            queue.as_ref(),
                            &descriptor,
                            capability,
                            kind,
                            &request_hash,
                            &idempotency_key,
                            &current,
                            &config,
                            &dead_err,
                        )
                        .await?
                        {
                            enqueue = next;
                        } else {
                            return Err(exhausted_request_error(&descriptor, &current, &config));
                        }
                    }
                    QueueStatus::Succeeded => {
                        if let Some(cache_dir) = &config.response_cache_dir {
                            if let Some(cached) = load_cache::<Res>(cache_dir, kind, &request_hash)?
                            {
                                return return_cached_response(
                                    cached,
                                    &descriptor,
                                    &trace_sink,
                                    request_hash.clone(),
                                    Some(current.item_id),
                                )
                                .await;
                            }
                        }
                        enqueue = reenqueue_succeeded_without_cache(
                            queue.as_ref(),
                            &descriptor,
                            capability,
                            kind,
                            &request_hash,
                            &idempotency_key,
                            &config,
                        )
                        .await?;
                        continue;
                    }
                    QueueStatus::Pending | QueueStatus::Running | QueueStatus::Failed => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            continue;
        };

        let heartbeat = spawn_queue_heartbeat(
            queue.clone(),
            item.item_id.clone(),
            worker_id.clone(),
            config.lease_seconds,
        );
        let provider_started = std::time::Instant::now();
        let result = if let Some(timeout) = config.request_timeout_seconds {
            match tokio::time::timeout(
                Duration::from_secs(timeout),
                call(provider.clone(), request.clone()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(ModelError::Timeout(format!(
                    "{} timed out after {}s",
                    descriptor.queue_id().0,
                    timeout
                ))),
            }
        } else {
            call(provider.clone(), request.clone()).await
        };

        match result {
            Ok(mut response) => {
                let mut trace = response.trace().clone();
                trace.queue_item_id = Some(item.item_id.clone());
                trace.request_hash = request_hash.clone();
                trace.timing.queued_ms =
                    Some(provider_started.duration_since(queued_at).as_millis() as u64);
                trace.timing.provider_ms = Some(provider_started.elapsed().as_millis() as u64);
                trace.timing.total_ms = Some(queued_at.elapsed().as_millis() as u64);
                if let Some(trace_sink) = &trace_sink {
                    trace_sink
                        .record_model_invocation(trace.clone())
                        .await
                        .map_err(|err| ModelError::Provider(err.to_string()))?;
                }
                response.set_trace(trace);
                if let Some(cache_dir) = &config.response_cache_dir {
                    store_cache(cache_dir, kind, &request_hash, &response)?;
                }
                queue
                    .complete(&item.item_id, &worker_id)
                    .await
                    .map_err(|err| {
                        heartbeat.abort();
                        ModelError::Queue(err.to_string())
                    })?;
                heartbeat.abort();
                return Ok(response);
            }
            Err(err) if is_retryable(&err) => {
                let retry_after = retry_after_seconds(
                    item.attempt,
                    config.retry_jitter_seconds,
                    &item.item_id,
                    &request_hash,
                    &err,
                );
                note_model_cooldown(queue.as_ref(), &descriptor.queue_id(), &err, retry_after)
                    .await?;
                let outcome = queue
                    .fail(
                        &item.item_id,
                        &worker_id,
                        &err.to_string(),
                        Some(retry_after),
                    )
                    .await
                    .map_err(|err| {
                        heartbeat.abort();
                        ModelError::Queue(err.to_string())
                    })?;
                heartbeat.abort();
                if outcome == FailOutcome::MovedToDead {
                    let dead_item = queue
                        .get_item(&item.item_id)
                        .await
                        .map_err(|err| ModelError::Queue(err.to_string()))?
                        .unwrap_or(item);
                    if let Some(next) = reenqueue_dead_item(
                        queue.as_ref(),
                        &descriptor,
                        capability,
                        kind,
                        &request_hash,
                        &idempotency_key,
                        &dead_item,
                        &config,
                        &err,
                    )
                    .await?
                    {
                        enqueue = next;
                        continue;
                    }
                    emit_failure_trace(
                        &descriptor,
                        &trace_sink,
                        Some(dead_item.item_id.clone()),
                        request_hash.clone(),
                        request_sensitivity(request),
                        err.to_string(),
                    )
                    .await?;
                    return Err(exhausted_request_error(&descriptor, &dead_item, &config));
                }
            }
            Err(err) => {
                queue
                    .fail(&item.item_id, &worker_id, &err.to_string(), None)
                    .await
                    .map_err(|err| {
                        heartbeat.abort();
                        ModelError::Queue(err.to_string())
                    })?;
                heartbeat.abort();
                emit_failure_trace(
                    &descriptor,
                    &trace_sink,
                    Some(item.item_id),
                    request_hash.clone(),
                    request_sensitivity(request),
                    err.to_string(),
                )
                .await?;
                return Err(err);
            }
        }
    }
}

fn spawn_queue_heartbeat(
    queue: Arc<dyn QueueBackend>,
    item_id: QueueItemId,
    worker_id: String,
    lease_seconds: u64,
) -> tokio::task::JoinHandle<()> {
    let interval_seconds = (lease_seconds / 3).clamp(1, 60);
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_seconds);
        loop {
            tokio::time::sleep(interval).await;
            if queue
                .heartbeat(&item_id, &worker_id, lease_seconds)
                .await
                .is_err()
            {
                break;
            }
        }
    })
}

#[async_trait]
pub trait TraceCarrier {
    fn trace(&self) -> &ModelInvocationTrace;
    fn set_trace(&mut self, trace: ModelInvocationTrace);
}

impl TraceCarrier for ChatResponse {
    fn trace(&self) -> &ModelInvocationTrace {
        &self.trace
    }

    fn set_trace(&mut self, trace: ModelInvocationTrace) {
        self.trace = trace;
    }
}

impl TraceCarrier for EmbeddingResponse {
    fn trace(&self) -> &ModelInvocationTrace {
        &self.trace
    }

    fn set_trace(&mut self, trace: ModelInvocationTrace) {
        self.trace = trace;
    }
}

impl TraceCarrier for RerankResponse {
    fn trace(&self) -> &ModelInvocationTrace {
        &self.trace
    }

    fn set_trace(&mut self, trace: ModelInvocationTrace) {
        self.trace = trace;
    }
}

fn is_retryable(err: &ModelError) -> bool {
    matches!(
        err,
        ModelError::Unavailable(_) | ModelError::RateLimited(_) | ModelError::Timeout(_)
    )
}

fn retry_backoff_seconds(attempt: u32) -> u64 {
    2u64.saturating_pow(attempt.saturating_sub(1).min(5))
        .min(30)
}

fn retry_after_seconds(
    attempt: u32,
    max_jitter_seconds: u64,
    item_id: &QueueItemId,
    request_hash: &str,
    err: &ModelError,
) -> u64 {
    retry_backoff_seconds(attempt)
        .saturating_add(retry_jitter_seconds(
            max_jitter_seconds,
            item_id,
            request_hash,
            attempt,
            err,
        ))
        .clamp(1, 120)
}

fn retry_jitter_seconds(
    max_jitter_seconds: u64,
    item_id: &QueueItemId,
    request_hash: &str,
    attempt: u32,
    err: &ModelError,
) -> u64 {
    if max_jitter_seconds == 0 {
        return 0;
    }
    let err_kind = match err {
        ModelError::RateLimited(_) => "rate_limited",
        ModelError::Unavailable(_) => "unavailable",
        ModelError::Timeout(_) => "timeout",
        _ => "other",
    };
    let mut hasher = Sha256::new();
    hasher.update(item_id.0.as_bytes());
    hasher.update(request_hash.as_bytes());
    hasher.update(attempt.to_le_bytes());
    hasher.update(err_kind.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes) % (max_jitter_seconds + 1)
}

fn dead_item_retry_error(item: &QueueItem) -> ModelError {
    let error = item
        .last_error
        .clone()
        .unwrap_or_else(|| "dead queue item".to_string());
    let lower = error.to_ascii_lowercase();
    if lower.contains("rate") || lower.contains("429") {
        ModelError::RateLimited(error)
    } else if lower.contains("timeout") || lower.contains("timed out") {
        ModelError::Timeout(error)
    } else {
        ModelError::Unavailable(error)
    }
}

#[derive(Clone, Copy, Debug)]
struct LogicalRetryState {
    attempts_used: u32,
    max_attempts: u32,
}

fn model_queue_payload(
    capability: &ModelCapability,
    request_hash: &str,
    descriptor: &ProviderDescriptor,
    retry_state: LogicalRetryState,
) -> Value {
    serde_json::json!({
        "capability": capability,
        "request_hash": request_hash,
        "model": descriptor.identity,
        "logical_retry": {
            "attempts_used": retry_state.attempts_used,
            "max_attempts": retry_state.max_attempts,
        },
    })
}

fn logical_retry_state(payload: &Value, default_max_attempts: u32) -> LogicalRetryState {
    let retry = payload.get("logical_retry");
    let attempts_used = retry
        .and_then(|value| value.get("attempts_used"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let max_attempts = retry
        .and_then(|value| value.get("max_attempts"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(default_max_attempts)
        .max(1);
    LogicalRetryState {
        attempts_used,
        max_attempts,
    }
}

async fn reenqueue_dead_item(
    queue: &dyn QueueBackend,
    descriptor: &ProviderDescriptor,
    capability: ModelCapability,
    kind: &str,
    request_hash: &str,
    idempotency_key: &Option<String>,
    item: &QueueItem,
    config: &ModelQueueConfig,
    err: &ModelError,
) -> Result<Option<EnqueueOutcome>, ModelError> {
    let state = logical_retry_state(
        &item.payload,
        config
            .logical_retry_attempts
            .max(config.retry_attempts)
            .max(1),
    );
    let attempts_used = state.attempts_used.saturating_add(item.attempt);
    if attempts_used >= state.max_attempts {
        return Ok(None);
    }
    let remaining_attempts = state.max_attempts - attempts_used;
    let next_state = LogicalRetryState {
        attempts_used,
        max_attempts: state.max_attempts,
    };
    let payload = model_queue_payload(&capability, request_hash, descriptor, next_state);
    let retry_after = retry_after_seconds(
        item.attempt,
        config.retry_jitter_seconds,
        &item.item_id,
        request_hash,
        err,
    );
    let outcome = queue
        .enqueue(EnqueueRequest {
            queue_id: descriptor.queue_id(),
            kind: kind.to_string(),
            payload,
            idempotency_key: idempotency_key.clone(),
            run_after: Some(Utc::now() + ChronoDuration::seconds(retry_after as i64)),
            max_attempts: Some(remaining_attempts.min(config.retry_attempts.max(1)).max(1)),
            force: true,
        })
        .await
        .map_err(|err| ModelError::Queue(err.to_string()))?;
    Ok(Some(outcome))
}

async fn reenqueue_succeeded_without_cache(
    queue: &dyn QueueBackend,
    descriptor: &ProviderDescriptor,
    capability: ModelCapability,
    kind: &str,
    request_hash: &str,
    idempotency_key: &Option<String>,
    config: &ModelQueueConfig,
) -> Result<EnqueueOutcome, ModelError> {
    let payload = model_queue_payload(
        &capability,
        request_hash,
        descriptor,
        LogicalRetryState {
            attempts_used: 0,
            max_attempts: config
                .logical_retry_attempts
                .max(config.retry_attempts)
                .max(1),
        },
    );
    queue
        .enqueue(EnqueueRequest {
            queue_id: descriptor.queue_id(),
            kind: kind.to_string(),
            payload,
            idempotency_key: idempotency_key.clone(),
            run_after: None,
            max_attempts: Some(config.retry_attempts.max(1)),
            force: true,
        })
        .await
        .map_err(|err| ModelError::Queue(err.to_string()))
}

fn exhausted_request_error(
    descriptor: &ProviderDescriptor,
    item: &QueueItem,
    config: &ModelQueueConfig,
) -> ModelError {
    let state = logical_retry_state(
        &item.payload,
        config
            .logical_retry_attempts
            .max(config.retry_attempts)
            .max(1),
    );
    let attempts_used = state.attempts_used.saturating_add(item.attempt);
    ModelError::Provider(format!(
        "{} request exhausted after {}/{} logical attempt(s): {}",
        descriptor.queue_id().0,
        attempts_used,
        state.max_attempts,
        item.last_error
            .clone()
            .unwrap_or_else(|| "unknown provider error".to_string())
    ))
}

static MODEL_COOLDOWNS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
static MODEL_RATE_BUCKETS: OnceLock<Mutex<HashMap<String, RateBucket>>> = OnceLock::new();

trait BudgetedModelRequest {
    fn input_budget_units(&self) -> u64;
}

impl BudgetedModelRequest for ChatRequest {
    fn input_budget_units(&self) -> u64 {
        estimate_token_budget_units(self.messages.iter().map(|message| message.content.as_str()))
    }
}

impl BudgetedModelRequest for EmbeddingRequest {
    fn input_budget_units(&self) -> u64 {
        estimate_token_budget_units(self.inputs.iter().map(String::as_str))
    }
}

impl BudgetedModelRequest for RerankRequest {
    fn input_budget_units(&self) -> u64 {
        estimate_token_budget_units(
            std::iter::once(self.query.as_str()).chain(self.documents.iter().map(String::as_str)),
        )
    }
}

fn estimate_token_budget_units<'a>(parts: impl IntoIterator<Item = &'a str>) -> u64 {
    parts
        .into_iter()
        .map(|part| (part.chars().count() as u64).div_ceil(4))
        .sum::<u64>()
        .max(1)
}

#[derive(Clone, Debug)]
struct RateBucket {
    tokens: f64,
    capacity: f64,
    rate_per_second: f64,
    updated_at: Instant,
}

impl RateBucket {
    fn new(per_minute: f64) -> Self {
        let rate_per_second = (per_minute / 60.0).max(0.000_001);
        let capacity = 1.0;
        Self {
            tokens: capacity,
            capacity,
            rate_per_second,
            updated_at: Instant::now(),
        }
    }

    fn reserve(&mut self, amount: f64) -> Option<Duration> {
        let amount = amount.max(1.0);
        if self.capacity < amount {
            self.capacity = amount;
        }
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.updated_at);
        self.updated_at = now;
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() * self.rate_per_second).min(self.capacity);
        self.tokens -= amount;
        if self.tokens >= 0.0 {
            None
        } else {
            Some(Duration::from_secs_f64(
                (-self.tokens) / self.rate_per_second,
            ))
        }
    }
}

async fn wait_for_model_budget<R>(
    queue_id: &QueueId,
    config: &ModelQueueConfig,
    request: &R,
) -> Result<(), ModelError>
where
    R: BudgetedModelRequest,
{
    if config.requests_per_minute.is_none() && config.input_units_per_minute.is_none() {
        return Ok(());
    }
    let sleep_for = {
        let map = MODEL_RATE_BUCKETS.get_or_init(|| Mutex::new(HashMap::new()));
        let Ok(mut guard) = map.lock() else {
            return Ok(());
        };
        let mut wait: Option<Duration> = None;
        if let Some(requests_per_minute) = config.requests_per_minute {
            let key = format!("{}:requests", queue_id.0);
            let bucket = guard
                .entry(key)
                .or_insert_with(|| RateBucket::new(requests_per_minute as f64));
            wait = wait.max(bucket.reserve(1.0));
        }
        if let Some(input_units_per_minute) = config.input_units_per_minute {
            let key = format!("{}:input-units", queue_id.0);
            let bucket = guard
                .entry(key)
                .or_insert_with(|| RateBucket::new(input_units_per_minute as f64));
            wait = wait.max(bucket.reserve(request.input_budget_units() as f64));
        }
        wait
    };
    if let Some(sleep_for) = sleep_for {
        tokio::time::sleep(sleep_for).await;
    }
    Ok(())
}

async fn wait_for_model_cooldown(
    queue: &dyn QueueBackend,
    queue_id: &QueueId,
) -> Result<(), ModelError> {
    let durable_until = queue
        .cooldown_until(queue_id)
        .await
        .map_err(|err| ModelError::Queue(err.to_string()))?;
    let local_sleep_for = {
        let map = MODEL_COOLDOWNS.get_or_init(|| Mutex::new(HashMap::new()));
        let Ok(mut guard) = map.lock() else {
            return Ok(());
        };
        if let Some(until) = guard.get(&queue_id.0).copied() {
            let now = Instant::now();
            if until <= now {
                guard.remove(&queue_id.0);
                None
            } else {
                Some(until.saturating_duration_since(now))
            }
        } else {
            None
        }
    };
    let durable_sleep_for = durable_until.and_then(|until| {
        let now = Utc::now();
        if until <= now {
            None
        } else {
            (until - now).to_std().ok()
        }
    });
    let sleep_for = match (local_sleep_for, durable_sleep_for) {
        (Some(local), Some(durable)) => Some(local.max(durable)),
        (Some(local), None) => Some(local),
        (None, Some(durable)) => Some(durable),
        (None, None) => None,
    };
    if let Some(sleep_for) = sleep_for {
        tokio::time::sleep(sleep_for).await;
    }
    Ok(())
}

async fn note_model_cooldown(
    queue: &dyn QueueBackend,
    queue_id: &QueueId,
    err: &ModelError,
    retry_after_seconds: u64,
) -> Result<(), ModelError> {
    let multiplier = match err {
        ModelError::RateLimited(_) => 4,
        ModelError::Unavailable(_) => 2,
        ModelError::Timeout(_) => 1,
        _ => 1,
    };
    let seconds = retry_after_seconds.saturating_mul(multiplier).clamp(1, 60);
    let until_instant = Instant::now() + Duration::from_secs(seconds);
    let until_utc = Utc::now() + ChronoDuration::seconds(seconds as i64);
    {
        let map = MODEL_COOLDOWNS.get_or_init(|| Mutex::new(HashMap::new()));
        let Ok(mut guard) = map.lock() else {
            queue
                .note_cooldown(queue_id, until_utc)
                .await
                .map_err(|err| ModelError::Queue(err.to_string()))?;
            return Ok(());
        };
        guard
            .entry(queue_id.0.clone())
            .and_modify(|current| {
                if *current < until_instant {
                    *current = until_instant;
                }
            })
            .or_insert(until_instant);
    }
    queue
        .note_cooldown(queue_id, until_utc)
        .await
        .map_err(|err| ModelError::Queue(err.to_string()))?;
    Ok(())
}

async fn emit_failure_trace(
    descriptor: &ProviderDescriptor,
    trace_sink: &Option<Arc<dyn TraceSink>>,
    queue_item_id: Option<symbiotic_core::QueueItemId>,
    request_hash: String,
    sensitivity: Sensitivity,
    error: String,
) -> Result<(), ModelError> {
    if let Some(trace_sink) = trace_sink {
        trace_sink
            .record_model_invocation(ModelInvocationTrace {
                trace_id: TraceId::new(),
                queue_item_id,
                model: descriptor.identity.clone(),
                role_binding: None,
                source: None,
                sensitivity,
                request_hash,
                response_hash: None,
                cache: CacheTrace::default(),
                usage: UsageTrace::default(),
                timing: TimingTrace::default(),
                outcome: InvocationOutcome::Failed,
                error_class: Some(error),
                audit_refs: Vec::new(),
                metadata: serde_json::json!({}),
                timestamp: Utc::now(),
            })
            .await
            .map_err(|err| ModelError::Provider(err.to_string()))?;
    }
    Ok(())
}

async fn return_cached_response<Res: TraceCarrier>(
    mut response: Res,
    descriptor: &ProviderDescriptor,
    trace_sink: &Option<Arc<dyn TraceSink>>,
    request_hash: String,
    queue_item_id: Option<symbiotic_core::QueueItemId>,
) -> Result<Res, ModelError> {
    let mut trace = response.trace().clone();
    trace.trace_id = TraceId::new();
    trace.queue_item_id = queue_item_id;
    trace.model = descriptor.identity.clone();
    trace.request_hash = request_hash;
    trace.cache.response_cache = CacheStatus::Hit;
    trace.outcome = InvocationOutcome::Succeeded;
    trace.error_class = None;
    trace.timestamp = Utc::now();
    if let Some(trace_sink) = trace_sink {
        trace_sink
            .record_model_invocation(trace.clone())
            .await
            .map_err(|err| ModelError::Provider(err.to_string()))?;
    }
    response.set_trace(trace);
    Ok(response)
}

fn request_sensitivity<T: Serialize>(request: &T) -> Sensitivity {
    serde_json::to_value(request)
        .ok()
        .and_then(|value| value.get("sensitivity").cloned())
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or(Sensitivity::Shareable)
}

fn hash_json<T: Serialize>(value: &T) -> Result<String, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|err| ModelError::Provider(err.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn cache_path(root: &Path, kind: &str, hash: &str) -> PathBuf {
    root.join(kind).join(format!("{hash}.json"))
}

fn load_cache<T: for<'de> Deserialize<'de>>(
    root: &Path,
    kind: &str,
    hash: &str,
) -> Result<Option<T>, ModelError> {
    let path = cache_path(root, kind, hash);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|err| ModelError::Cache(err.to_string()))?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|err| ModelError::Cache(err.to_string()))
}

fn store_cache<T: Serialize>(
    root: &Path,
    kind: &str,
    hash: &str,
    value: &T,
) -> Result<(), ModelError> {
    let path = cache_path(root, kind, hash);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| ModelError::Cache(err.to_string()))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec(value).map_err(|err| ModelError::Cache(err.to_string()))?,
    )
    .map_err(|err| ModelError::Cache(err.to_string()))?;
    std::fs::rename(tmp, path).map_err(|err| ModelError::Cache(err.to_string()))
}

#[derive(Clone)]
pub struct HashEmbeddingProvider {
    descriptor: ProviderDescriptor,
    dimensions: usize,
}

impl HashEmbeddingProvider {
    pub fn new(dimensions: usize) -> Self {
        Self {
            descriptor: ProviderDescriptor {
                identity: ModelIdentity::new("embedding", "hash", "hash-embedding-v1"),
                provider_class: ProviderClass::Local,
                capabilities: vec![ModelCapability::Embedding],
                auth_mode: ProviderAuthMode::None,
                metadata: serde_json::json!({ "dimensions": dimensions }),
            },
            dimensions,
        }
    }
}

impl Default for HashEmbeddingProvider {
    fn default() -> Self {
        Self::new(64)
    }
}

#[async_trait]
impl ModelProvider for HashEmbeddingProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }
}

#[async_trait]
impl EmbeddingProvider for HashEmbeddingProvider {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        let mut vectors = Vec::new();
        for input in &request.inputs {
            let mut vector = vec![0.0f32; self.dimensions];
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            let bytes = hasher.finalize();
            for (idx, byte) in bytes.iter().enumerate() {
                vector[idx % self.dimensions] += (*byte as f32 / 255.0) - 0.5;
            }
            vectors.push(vector);
        }
        let trace = success_trace(
            &self.descriptor,
            request.sensitivity,
            request.role_binding.clone(),
            request.source.clone(),
            hash_json(&request)?,
            None,
        );
        Ok(EmbeddingResponse {
            dimensions: self.dimensions,
            vectors,
            trace,
            raw_provider_response: None,
        })
    }
}

#[derive(Clone)]
pub struct StaticChatProvider {
    descriptor: ProviderDescriptor,
    response: String,
}

impl StaticChatProvider {
    pub fn new(response: impl Into<String>) -> Self {
        Self {
            descriptor: ProviderDescriptor {
                identity: ModelIdentity::new("chat", "static", "static-chat-v1"),
                provider_class: ProviderClass::Local,
                capabilities: vec![ModelCapability::Chat],
                auth_mode: ProviderAuthMode::None,
                metadata: serde_json::json!({}),
            },
            response: response.into(),
        }
    }
}

#[async_trait]
impl ModelProvider for StaticChatProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }
}

#[async_trait]
impl ChatProvider for StaticChatProvider {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        let trace = success_trace(
            &self.descriptor,
            request.sensitivity,
            request.role_binding.clone(),
            request.source.clone(),
            hash_json(&request)?,
            Some(&self.response),
        );
        Ok(ChatResponse {
            text: self.response.clone(),
            finish_reason: Some("stop".to_string()),
            trace,
            raw_provider_response: None,
        })
    }
}

#[derive(Clone)]
pub struct OpenAiCompatibleChatProvider {
    descriptor: ProviderDescriptor,
    client: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl OpenAiCompatibleChatProvider {
    pub fn new(
        operator: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        let operator = operator.into();
        let model = model.into();
        Self {
            descriptor: ProviderDescriptor {
                identity: ModelIdentity {
                    operation: Operation::new("chat"),
                    operator: Operator::new(operator),
                    model: ModelName::new(model.clone()),
                },
                provider_class: ProviderClass::Cloud,
                capabilities: vec![ModelCapability::Chat],
                auth_mode: ProviderAuthMode::ApiKey {
                    secret_ref: "runtime".to_string(),
                },
                metadata: serde_json::json!({ "wire": "openai-compatible" }),
            },
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            api_key: api_key.into(),
        }
    }
}

#[async_trait]
impl ModelProvider for OpenAiCompatibleChatProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }
}

#[derive(Serialize)]
struct OpenAiChatWireRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<Value>,
    stream: bool,
}

#[derive(Deserialize)]
struct OpenAiChatWireResponse {
    choices: Vec<OpenAiChoice>,
    usage: Option<OpenAiUsage>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    message: Option<ChatMessage>,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct OpenAiUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    prompt_cache_hit_tokens: Option<u64>,
    prompt_cache_miss_tokens: Option<u64>,
}

#[async_trait]
impl ChatProvider for OpenAiCompatibleChatProvider {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        let wire = OpenAiChatWireRequest {
            model: &self.descriptor.identity.model.0,
            messages: &request.messages,
            max_tokens: request.max_output_tokens,
            temperature: request.temperature,
            response_format: request
                .response_format
                .as_deref()
                .map(|format| serde_json::json!({ "type": format })),
            stream: false,
        };
        let resp = self
            .client
            .post(format!(
                "{}/chat/completions",
                self.base_url.trim_end_matches('/')
            ))
            .bearer_auth(&self.api_key)
            .json(&wire)
            .send()
            .await
            .map_err(|err| ModelError::Unavailable(err.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(status_error(status.as_u16(), body));
        }
        let raw: Value = resp
            .json()
            .await
            .map_err(|err| ModelError::Unavailable(err.to_string()))?;
        let parsed: OpenAiChatWireResponse = serde_json::from_value(raw.clone())
            .map_err(|err| ModelError::Provider(err.to_string()))?;
        let choice = parsed.choices.into_iter().next().ok_or_else(|| {
            ModelError::Provider("OpenAI-compatible response had no choices".to_string())
        })?;
        let usage = parsed.usage.unwrap_or(OpenAiUsage {
            prompt_tokens: None,
            completion_tokens: None,
            prompt_cache_hit_tokens: None,
            prompt_cache_miss_tokens: None,
        });
        let content = choice
            .message
            .as_ref()
            .map(|message| message.content.as_str())
            .unwrap_or_default();
        let mut trace = success_trace(
            &self.descriptor,
            request.sensitivity,
            request.role_binding.clone(),
            request.source.clone(),
            hash_json(&request)?,
            Some(content),
        );
        trace.usage = UsageTrace {
            input_tokens: usage.prompt_tokens,
            output_tokens: usage.completion_tokens,
            reasoning_tokens: None,
            media_units: None,
            cost_micro_usd: None,
        };
        trace.cache = CacheTrace {
            response_cache: CacheStatus::Miss,
            prompt_cache: match (
                usage.prompt_cache_hit_tokens.unwrap_or(0),
                usage.prompt_cache_miss_tokens.unwrap_or(0),
            ) {
                (0, _) => CacheStatus::Miss,
                (_, 0) => CacheStatus::Hit,
                _ => CacheStatus::PartialHit,
            },
            cached_input_tokens: usage.prompt_cache_hit_tokens,
        };
        Ok(ChatResponse {
            text: content.to_string(),
            finish_reason: choice.finish_reason,
            trace,
            raw_provider_response: Some(raw),
        })
    }
}

#[derive(Clone)]
pub struct GeminiEmbeddingProvider {
    descriptor: ProviderDescriptor,
    client: reqwest::Client,
    api_key: String,
    dimensions: usize,
}

impl GeminiEmbeddingProvider {
    pub fn new(model: impl Into<String>, api_key: impl Into<String>, dimensions: usize) -> Self {
        let model = model.into();
        Self {
            descriptor: ProviderDescriptor {
                identity: ModelIdentity::new("embedding", "gemini", model),
                provider_class: ProviderClass::Cloud,
                capabilities: vec![ModelCapability::Embedding],
                auth_mode: ProviderAuthMode::ApiKey {
                    secret_ref: "runtime".to_string(),
                },
                metadata: serde_json::json!({ "dimensions": dimensions }),
            },
            client: reqwest::Client::new(),
            api_key: api_key.into(),
            dimensions,
        }
    }
}

#[async_trait]
impl ModelProvider for GeminiEmbeddingProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }
}

#[derive(Serialize)]
struct GeminiEmbedWireRequest<'a> {
    model: String,
    content: GeminiContent<'a>,
    output_dimensionality: usize,
}

#[derive(Serialize)]
struct GeminiBatchEmbedWireRequest<'a> {
    requests: Vec<GeminiEmbedWireRequest<'a>>,
}

#[derive(Serialize)]
struct GeminiContent<'a> {
    parts: Vec<GeminiPart<'a>>,
}

#[derive(Serialize)]
struct GeminiPart<'a> {
    text: &'a str,
}

#[derive(Deserialize)]
struct GeminiEmbedWireResponse {
    embedding: Option<GeminiEmbedding>,
}

#[derive(Deserialize)]
struct GeminiBatchEmbedWireResponse {
    embeddings: Option<Vec<GeminiEmbedding>>,
}

#[derive(Deserialize)]
struct GeminiEmbedding {
    values: Vec<f32>,
}

#[async_trait]
impl EmbeddingProvider for GeminiEmbeddingProvider {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        if request.inputs.is_empty() {
            return Ok(EmbeddingResponse {
                dimensions: self.dimensions,
                vectors: Vec::new(),
                trace: success_trace(
                    &self.descriptor,
                    request.sensitivity,
                    request.role_binding.clone(),
                    request.source.clone(),
                    hash_json(&request)?,
                    None,
                ),
                raw_provider_response: None,
            });
        }
        let model = self
            .descriptor
            .identity
            .model
            .0
            .trim_start_matches("models/");
        let vectors = if request.inputs.len() == 1 {
            let wire = GeminiEmbedWireRequest {
                model: format!("models/{model}"),
                content: GeminiContent {
                    parts: vec![GeminiPart {
                        text: &request.inputs[0],
                    }],
                },
                output_dimensionality: self.dimensions,
            };
            let resp = self
                .client
                .post(format!(
                    "https://generativelanguage.googleapis.com/v1beta/models/{model}:embedContent"
                ))
                .header("x-goog-api-key", &self.api_key)
                .json(&wire)
                .send()
                .await
                .map_err(|err| ModelError::Unavailable(err.to_string()))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(status_error(status.as_u16(), body));
            }
            let raw: GeminiEmbedWireResponse = resp
                .json()
                .await
                .map_err(|err| ModelError::Unavailable(err.to_string()))?;
            vec![
                raw.embedding
                    .ok_or_else(|| {
                        ModelError::Provider("Gemini response missing embedding".to_string())
                    })?
                    .values,
            ]
        } else {
            let model_name = format!("models/{model}");
            let wire = GeminiBatchEmbedWireRequest {
                requests: request
                    .inputs
                    .iter()
                    .map(|input| GeminiEmbedWireRequest {
                        model: model_name.clone(),
                        content: GeminiContent {
                            parts: vec![GeminiPart { text: input }],
                        },
                        output_dimensionality: self.dimensions,
                    })
                    .collect(),
            };
            let resp = self
                .client
                .post(format!(
                    "https://generativelanguage.googleapis.com/v1beta/models/{model}:batchEmbedContents"
                ))
                .header("x-goog-api-key", &self.api_key)
                .json(&wire)
                .send()
                .await
                .map_err(|err| ModelError::Unavailable(err.to_string()))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(status_error(status.as_u16(), body));
            }
            let raw: GeminiBatchEmbedWireResponse = resp
                .json()
                .await
                .map_err(|err| ModelError::Unavailable(err.to_string()))?;
            let embeddings = raw.embeddings.ok_or_else(|| {
                ModelError::Provider("Gemini batch response missing embeddings".to_string())
            })?;
            if embeddings.len() != request.inputs.len() {
                return Err(ModelError::Provider(format!(
                    "Gemini batch returned {} embeddings for {} inputs",
                    embeddings.len(),
                    request.inputs.len()
                )));
            }
            embeddings
                .into_iter()
                .map(|embedding| embedding.values)
                .collect()
        };
        Ok(EmbeddingResponse {
            dimensions: self.dimensions,
            vectors,
            trace: success_trace(
                &self.descriptor,
                request.sensitivity,
                request.role_binding.clone(),
                request.source.clone(),
                hash_json(&request)?,
                None,
            ),
            raw_provider_response: None,
        })
    }
}

fn status_error(status: u16, body: String) -> ModelError {
    match status {
        401 | 403 => ModelError::Auth(body),
        402 => ModelError::BudgetExhausted(body),
        408 | 504 => ModelError::Timeout(body),
        429 => ModelError::RateLimited(body),
        500..=599 => ModelError::Unavailable(body),
        _ => ModelError::Provider(format!("status={status}: {body}")),
    }
}

fn success_trace(
    descriptor: &ProviderDescriptor,
    sensitivity: Sensitivity,
    role_binding: Option<String>,
    source: Option<String>,
    request_hash: String,
    response: Option<&str>,
) -> ModelInvocationTrace {
    ModelInvocationTrace {
        trace_id: TraceId::new(),
        queue_item_id: None,
        model: descriptor.identity.clone(),
        role_binding,
        source,
        sensitivity,
        request_hash,
        response_hash: response.map(hash_text),
        cache: CacheTrace {
            response_cache: CacheStatus::Miss,
            prompt_cache: CacheStatus::NotApplicable,
            cached_input_tokens: None,
        },
        usage: UsageTrace::default(),
        timing: TimingTrace::default(),
        outcome: InvocationOutcome::Succeeded,
        error_class: None,
        audit_refs: Vec::new(),
        metadata: serde_json::json!({}),
        timestamp: Utc::now(),
    }
}

fn hash_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use symbiotic_queue::SqliteQueue;

    static TEST_QUEUE_COUNTER: AtomicUsize = AtomicUsize::new(0);
    use symbiotic_trace::InMemoryTraceSink;

    #[test]
    fn known_model_queue_defaults_live_in_catalog() {
        let flash = default_model_queue_config(&ModelIdentity::new(
            "chat",
            "deepseek",
            "deepseek-v4-flash",
        ))
        .unwrap();
        let gemini = default_model_queue_config(&ModelIdentity::new(
            "embedding",
            "gemini",
            "gemini-embedding-2",
        ))
        .unwrap();
        let gemini_flash =
            default_model_queue_config(&ModelIdentity::new("chat", "gemini", "gemini-3.5-flash"))
                .unwrap();
        let gemini_pro = default_model_queue_config(&ModelIdentity::new(
            "chat",
            "gemini",
            "gemini-3.1-pro-preview",
        ))
        .unwrap();

        assert_eq!(flash.max_in_flight, 2_000);
        assert_eq!(flash.request_timeout_seconds, Some(600));
        assert_eq!(gemini.max_in_flight, 1_000);
        assert_eq!(gemini.requests_per_minute, Some(4_500));
        assert_eq!(gemini.input_units_per_minute, Some(5_000_000));
        let qwen_embedding = default_model_queue_config(&ModelIdentity::new(
            "embedding",
            "openrouter",
            "qwen/qwen3-embedding-8b",
        ))
        .unwrap();
        assert_eq!(qwen_embedding.max_in_flight, 1_000);
        assert_eq!(qwen_embedding.requests_per_minute, None);
        assert_eq!(gemini_flash.max_in_flight, 100);
        assert_eq!(gemini_flash.requests_per_minute, Some(1_000));
        assert_eq!(gemini_pro.max_in_flight, 500);
        assert_eq!(gemini_pro.requests_per_minute, Some(100));
    }

    #[test]
    fn model_budget_units_are_token_estimates() {
        let request = EmbeddingRequest {
            inputs: vec!["abcd".to_string(), "abcde".to_string()],
            dimensions: None,
            task: None,
            sensitivity: Sensitivity::Private,
            role_binding: None,
            source: None,
            metadata: Value::Null,
        };

        assert_eq!(request.input_budget_units(), 3);
        assert_eq!(estimate_token_budget_units([""]), 1);
    }

    #[test]
    fn local_ollama_queue_defaults_are_conservative() {
        let config =
            default_model_queue_config(&ModelIdentity::new("chat", "ollama", "qwen-local"))
                .unwrap();

        assert_eq!(config.max_in_flight, 1);
        assert_eq!(config.retry_attempts, 2);
    }

    #[derive(Clone)]
    struct SlowCountingChat {
        descriptor: ProviderDescriptor,
        active: Arc<AtomicUsize>,
        max_seen: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }

    impl SlowCountingChat {
        fn new(
            active: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
            calls: Arc<AtomicUsize>,
        ) -> Self {
            Self::new_with_identity(
                active,
                max_seen,
                calls,
                ModelIdentity::new("chat", "deepseek", "deepseek-v4-pro"),
            )
        }

        fn new_with_identity(
            active: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
            calls: Arc<AtomicUsize>,
            identity: ModelIdentity,
        ) -> Self {
            Self {
                descriptor: ProviderDescriptor {
                    identity,
                    provider_class: ProviderClass::Cloud,
                    capabilities: vec![ModelCapability::Chat],
                    auth_mode: ProviderAuthMode::None,
                    metadata: serde_json::json!({}),
                },
                active,
                max_seen,
                calls,
            }
        }
    }

    #[async_trait]
    impl ModelProvider for SlowCountingChat {
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[async_trait]
    impl ChatProvider for SlowCountingChat {
        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_seen.fetch_max(active, Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(ChatResponse {
                text: request
                    .messages
                    .last()
                    .map(|msg| msg.content.clone())
                    .unwrap_or_default(),
                finish_reason: Some("stop".to_string()),
                trace: success_trace(
                    &self.descriptor,
                    request.sensitivity,
                    request.role_binding.clone(),
                    request.source.clone(),
                    hash_json(&request)?,
                    Some("ok"),
                ),
                raw_provider_response: None,
            })
        }
    }

    #[derive(Clone)]
    struct DeadThenSuccessChat {
        descriptor: ProviderDescriptor,
        calls: Arc<AtomicUsize>,
    }

    impl DeadThenSuccessChat {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                descriptor: ProviderDescriptor {
                    identity: ModelIdentity::new("chat", "deepseek", "deepseek-v4-flash"),
                    provider_class: ProviderClass::Cloud,
                    capabilities: vec![ModelCapability::Chat],
                    auth_mode: ProviderAuthMode::None,
                    metadata: serde_json::json!({}),
                },
                calls,
            }
        }
    }

    #[async_trait]
    impl ModelProvider for DeadThenSuccessChat {
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[async_trait]
    impl ChatProvider for DeadThenSuccessChat {
        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return Err(ModelError::Unavailable("temporary outage".to_string()));
            }
            Ok(ChatResponse {
                text: request
                    .messages
                    .last()
                    .map(|msg| msg.content.clone())
                    .unwrap_or_default(),
                finish_reason: Some("stop".to_string()),
                trace: success_trace(
                    &self.descriptor,
                    request.sensitivity,
                    request.role_binding.clone(),
                    request.source.clone(),
                    hash_json(&request)?,
                    Some("ok"),
                ),
                raw_provider_response: None,
            })
        }
    }

    #[derive(Clone)]
    struct SlowUnavailableChat {
        descriptor: ProviderDescriptor,
        calls: Arc<AtomicUsize>,
    }

    impl SlowUnavailableChat {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                descriptor: ProviderDescriptor {
                    identity: ModelIdentity::new("chat", "deepseek", "deepseek-v4-flash"),
                    provider_class: ProviderClass::Cloud,
                    capabilities: vec![ModelCapability::Chat],
                    auth_mode: ProviderAuthMode::None,
                    metadata: serde_json::json!({}),
                },
                calls,
            }
        }
    }

    #[async_trait]
    impl ModelProvider for SlowUnavailableChat {
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[async_trait]
    impl ChatProvider for SlowUnavailableChat {
        async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse, ModelError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            Err(ModelError::Unavailable("temporary outage".to_string()))
        }
    }

    #[derive(Clone)]
    struct LeaseCrossingChat {
        descriptor: ProviderDescriptor,
    }

    impl LeaseCrossingChat {
        fn new() -> Self {
            Self {
                descriptor: ProviderDescriptor {
                    identity: ModelIdentity::new("chat", "deepseek", "deepseek-v4-pro"),
                    provider_class: ProviderClass::Cloud,
                    capabilities: vec![ModelCapability::Chat],
                    auth_mode: ProviderAuthMode::None,
                    metadata: serde_json::json!({}),
                },
            }
        }
    }

    #[async_trait]
    impl ModelProvider for LeaseCrossingChat {
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[async_trait]
    impl ChatProvider for LeaseCrossingChat {
        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
            tokio::time::sleep(Duration::from_secs(3)).await;
            Ok(ChatResponse {
                text: request
                    .messages
                    .last()
                    .map(|msg| msg.content.clone())
                    .unwrap_or_default(),
                finish_reason: Some("stop".to_string()),
                trace: success_trace(
                    &self.descriptor,
                    request.sensitivity,
                    request.role_binding.clone(),
                    request.source.clone(),
                    hash_json(&request)?,
                    Some("ok"),
                ),
                raw_provider_response: None,
            })
        }
    }

    fn chat_request(text: &str) -> ChatRequest {
        ChatRequest {
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: text.to_string(),
            }],
            max_output_tokens: Some(32),
            temperature: Some(0.0),
            response_format: None,
            sensitivity: Sensitivity::Shareable,
            role_binding: Some("memory.answer".to_string()),
            source: Some("test".to_string()),
            metadata: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn queued_chat_provider_enforces_model_cap() {
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = QueuedChatProvider::new(
            SlowCountingChat::new(active, max_seen.clone(), calls.clone()),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 2,
                lease_seconds: 60,
                logical_retry_attempts: 2,
                retry_attempts: 2,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(10),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: None,
            },
        );
        let results = futures::future::join_all((0..8).map(|idx| {
            let provider = provider.clone();
            async move { provider.chat(chat_request(&format!("request-{idx}"))).await }
        }))
        .await;

        assert!(results.iter().all(Result::is_ok));
        assert_eq!(max_seen.load(Ordering::SeqCst), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 8);
    }

    #[tokio::test]
    async fn queued_chat_provider_uses_exact_response_cache() {
        let dir = tempfile::tempdir().unwrap();
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let trace_sink = Arc::new(InMemoryTraceSink::default());
        let provider = QueuedChatProvider::new(
            SlowCountingChat::new(active, max_seen, calls.clone()),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 60,
                logical_retry_attempts: 2,
                retry_attempts: 2,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(10),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: Some(dir.path().join("cache")),
            },
        )
        .with_trace_sink(trace_sink.clone());

        let first = provider.chat(chat_request("hello")).await.unwrap();
        let second = provider.chat(chat_request("hello")).await.unwrap();

        assert_eq!(first.text, "hello");
        assert_eq!(second.text, "hello");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let records = trace_sink.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].cache.response_cache, CacheStatus::Miss);
        assert_eq!(records[1].cache.response_cache, CacheStatus::Hit);
    }

    #[tokio::test]
    async fn queued_chat_trace_separates_queue_wait_from_provider_time() {
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let trace_sink = Arc::new(InMemoryTraceSink::default());
        let unique_model = format!(
            "timing-{}",
            TEST_QUEUE_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let provider = QueuedChatProvider::new(
            SlowCountingChat::new_with_identity(
                active,
                max_seen,
                calls,
                ModelIdentity::new("chat", "test", unique_model),
            ),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 60,
                logical_retry_attempts: 1,
                retry_attempts: 1,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(1),
                requests_per_minute: Some(60),
                input_units_per_minute: None,
                response_cache_dir: None,
            },
        )
        .with_trace_sink(trace_sink.clone());

        provider.chat(chat_request("first")).await.unwrap();
        provider.chat(chat_request("second")).await.unwrap();

        let records = trace_sink.records();
        assert_eq!(records.len(), 2);
        assert!(
            records[1].timing.queued_ms.unwrap_or_default() >= 900,
            "second request should account for budget wait as queued time: {:?}",
            records[1].timing
        );
        assert!(
            records[1].timing.provider_ms.unwrap_or(u64::MAX) < 500,
            "provider timeout window should only cover the inner provider call: {:?}",
            records[1].timing
        );
        assert!(
            records[1].timing.total_ms.unwrap_or_default()
                >= records[1].timing.queued_ms.unwrap_or_default()
                    + records[1].timing.provider_ms.unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn queued_chat_rate_budget_wait_does_not_hold_running_slot() {
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let unique_model = format!(
            "budget-slot-{}",
            TEST_QUEUE_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let provider = QueuedChatProvider::new(
            SlowCountingChat::new_with_identity(
                active,
                max_seen,
                calls,
                ModelIdentity::new("chat", "test", unique_model),
            ),
            queue.clone(),
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 60,
                logical_retry_attempts: 1,
                retry_attempts: 1,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(1),
                requests_per_minute: Some(60),
                input_units_per_minute: None,
                response_cache_dir: None,
            },
        );

        provider.chat(chat_request("first")).await.unwrap();
        let second = tokio::spawn({
            let provider = provider.clone();
            async move { provider.chat(chat_request("second")).await }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut statuses = Vec::new();
        for event in queue.events().unwrap() {
            if statuses
                .iter()
                .any(|(item_id, _): &(QueueItemId, QueueStatus)| *item_id == event.item_id)
            {
                continue;
            }
            if let Some(item) = queue.get(&event.item_id).unwrap() {
                statuses.push((item.item_id, item.status));
            }
        }

        assert!(
            statuses
                .iter()
                .any(|(_, status)| *status == QueueStatus::Pending),
            "rate-paced request should remain pending before it can claim a slot: {statuses:?}"
        );
        assert!(
            statuses
                .iter()
                .all(|(_, status)| *status != QueueStatus::Running),
            "rate-budget sleeps must not occupy running queue slots: {statuses:?}"
        );

        second.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn queued_chat_provider_shares_cached_response_with_concurrent_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = QueuedChatProvider::new(
            SlowCountingChat::new(active, max_seen, calls.clone()),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 60,
                logical_retry_attempts: 2,
                retry_attempts: 2,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(10),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: Some(dir.path().join("cache")),
            },
        );

        let results = futures::future::join_all((0..2).map(|_| {
            let provider = provider.clone();
            async move { provider.chat(chat_request("same request")).await }
        }))
        .await;

        assert!(results.iter().all(Result::is_ok));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn queued_chat_provider_replays_succeeded_item_when_cache_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let request = chat_request("same request");
        let request_hash = hash_json(&request).unwrap();
        let queue_id = QueueId::new("chat:deepseek:deepseek-v4-pro");
        let descriptor = ProviderDescriptor {
            identity: ModelIdentity::new("chat", "deepseek", "deepseek-v4-pro"),
            provider_class: ProviderClass::Cloud,
            capabilities: vec![ModelCapability::Chat],
            auth_mode: ProviderAuthMode::None,
            metadata: serde_json::json!({}),
        };
        let preexisting = queue
            .enqueue(EnqueueRequest {
                queue_id: queue_id.clone(),
                kind: "chat".to_string(),
                payload: model_queue_payload(
                    &ModelCapability::Chat,
                    &request_hash,
                    &descriptor,
                    LogicalRetryState {
                        attempts_used: 0,
                        max_attempts: 2,
                    },
                ),
                idempotency_key: Some(format!("{}:{request_hash}", queue_id.0)),
                run_after: None,
                max_attempts: Some(2),
                force: false,
            })
            .await
            .unwrap();
        let claimed = queue
            .claim_item(&preexisting.item.item_id, "preexisting-worker", 60, Some(1))
            .await
            .unwrap()
            .unwrap();
        queue
            .complete(&claimed.item_id, "preexisting-worker")
            .await
            .unwrap();

        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = QueuedChatProvider::new(
            SlowCountingChat::new(active, max_seen, calls.clone()),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 60,
                logical_retry_attempts: 2,
                retry_attempts: 2,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(10),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: Some(dir.path().join("cache")),
            },
        );

        let response = provider.chat(request).await.unwrap();

        assert_eq!(response.text, "same request");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cache_path(dir.path().join("cache").as_path(), "chat", &request_hash).is_file());
    }

    #[tokio::test]
    async fn queued_chat_provider_reenqueues_dead_item_until_logical_retry_limit() {
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = QueuedChatProvider::new(
            DeadThenSuccessChat::new(calls.clone()),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 60,
                logical_retry_attempts: 2,
                retry_attempts: 1,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(10),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: None,
            },
        );

        let response = provider.chat(chat_request("hello")).await.unwrap();

        assert_eq!(response.text, "hello");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn queued_chat_provider_stops_at_logical_retry_limit() {
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = QueuedChatProvider::new(
            SlowUnavailableChat::new(calls.clone()),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 60,
                logical_retry_attempts: 2,
                retry_attempts: 1,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(10),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: None,
            },
        );

        let err = provider.chat(chat_request("hello")).await.unwrap_err();

        assert!(err.to_string().contains("exhausted after 2/2"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn queued_chat_provider_waiter_shares_logical_retry_envelope() {
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = QueuedChatProvider::new(
            SlowUnavailableChat::new(calls.clone()),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 60,
                logical_retry_attempts: 2,
                retry_attempts: 1,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(10),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: None,
            },
        );

        let run = futures::future::join_all((0..2).map(|_| {
            let provider = provider.clone();
            async move { provider.chat(chat_request("same request")).await }
        }));
        let results = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("duplicate waiter should observe the dead item instead of spinning");

        assert!(results.iter().all(Result::is_err));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn queued_chat_provider_heartbeats_long_provider_call() {
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let provider = QueuedChatProvider::new(
            LeaseCrossingChat::new(),
            queue,
            "worker",
            ModelQueueConfig {
                max_in_flight: 1,
                lease_seconds: 2,
                logical_retry_attempts: 1,
                retry_attempts: 1,
                retry_jitter_seconds: 0,
                request_timeout_seconds: Some(10),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: None,
            },
        );

        let response = provider.chat(chat_request("hello")).await.unwrap();

        assert_eq!(response.text, "hello");
    }

    #[test]
    fn rate_bucket_waits_after_burst_without_consuming_request_timeout() {
        let mut bucket = RateBucket::new(60.0);
        assert!(bucket.reserve(1.0).is_none());
        assert!(bucket.reserve(1.0).is_some());
    }

    #[test]
    fn rate_bucket_smooths_high_rpm_instead_of_cold_start_bursting() {
        let mut bucket = RateBucket::new(20_000.0);
        assert!(bucket.reserve(1.0).is_none());
        let wait = bucket
            .reserve(1.0)
            .expect("second request should be paced even for high-rpm queues");
        assert!(
            wait < Duration::from_millis(10),
            "20k rpm should pace in milliseconds, not seconds: {wait:?}"
        );
    }

    #[test]
    fn retry_jitter_spreads_same_attempt_failures_deterministically() {
        let err = ModelError::Unavailable("connect timeout".to_string());
        let first = QueueItemId("item-a".to_string());
        let second = QueueItemId("item-b".to_string());
        let request_hash = "same-request-shape";

        let first_delay = retry_after_seconds(1, 20, &first, request_hash, &err);
        let second_delay = retry_after_seconds(1, 20, &second, request_hash, &err);

        assert_eq!(
            first_delay,
            retry_after_seconds(1, 20, &first, request_hash, &err)
        );
        assert_ne!(first_delay, second_delay);
        assert!((1..=21).contains(&first_delay));
        assert!((1..=21).contains(&second_delay));
    }

    #[tokio::test]
    async fn model_budget_wait_reserves_once_then_proceeds() {
        let config = ModelQueueConfig {
            max_in_flight: 1,
            lease_seconds: 60,
            logical_retry_attempts: 1,
            retry_attempts: 1,
            retry_jitter_seconds: 0,
            request_timeout_seconds: Some(1),
            requests_per_minute: Some(60),
            input_units_per_minute: None,
            response_cache_dir: None,
        };
        let queue_id = QueueId(format!(
            "test-budget-{}",
            TEST_QUEUE_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));

        wait_for_model_budget(&queue_id, &config, &chat_request("first"))
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_millis(1500),
            wait_for_model_budget(&queue_id, &config, &chat_request("second")),
        )
        .await
        .expect("second reservation should sleep for the already-reserved slot and proceed")
        .unwrap();
    }

    #[tokio::test]
    async fn provider_catalog_filters_private_cloud_candidates() {
        let catalog = ProviderCatalog::new(vec![
            ProviderDescriptor {
                identity: ModelIdentity::new("chat", "deepseek", "deepseek-v4-pro"),
                provider_class: ProviderClass::Cloud,
                capabilities: vec![ModelCapability::Chat],
                auth_mode: ProviderAuthMode::None,
                metadata: serde_json::json!({}),
            },
            ProviderDescriptor {
                identity: ModelIdentity::new("chat", "ollama", "local-model"),
                provider_class: ProviderClass::Local,
                capabilities: vec![ModelCapability::Chat],
                auth_mode: ProviderAuthMode::None,
                metadata: serde_json::json!({}),
            },
        ]);
        let selected = ModelSelector::select(
            &catalog,
            SelectionRequest {
                capability: ModelCapability::Chat,
                tier: Some(ModelTier::Deep),
                sensitivity: Sensitivity::Private,
                role_binding: Some(RoleBinding::new("agent.answer")),
                source: Some(InvocationSource::new("unit-test")),
                preferred: None,
                allowed_classes: Vec::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].operator.0, "ollama");
    }
}
