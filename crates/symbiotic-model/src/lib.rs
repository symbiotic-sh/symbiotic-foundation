//! Provider-neutral model runtime contracts.
//!
//! Implementations may wrap HTTP SDKs, local CLIs, subscription-backed tools,
//! or host-owned adapters. Foundation owns execution policy and scheduling through
//! `symbiotic-ai-runtime`; Memory owns stored-input authorization and output commits.
//! The authoritative contract is `docs/architecture/boundary.md`.
//!
//! The default `queue` feature adds the `Queued*` providers, which run calls
//! through a `symbiotic-queue` backend. Without it, the crate is the provider
//! contracts and HTTP providers alone: no queue runtime and no SQLite.
//!
//! Hosts do not assemble the queued providers themselves: `symbiotic-ai-runtime`
//! opens one stateful runtime and hands out ready providers. The `Queued*`
//! types, [`ModelQueueConfig`] wiring and the queue backends are public because
//! that crate composes them; using them directly from a consumer is
//! unsupported.

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
pub use symbiotic_core::{
    DiagnosticCode, FailureClass, ModelIdentity, ProviderPrincipalId, TenantId,
};
use symbiotic_core::{ModelName, Operation, Operator, QueueId, Sensitivity, TraceId};
use symbiotic_trace::{
    CacheStatus, CacheTrace, InvocationOutcome, ModelInvocationTrace, TimingTrace, UsageTrace,
};
use thiserror::Error;

// The queue runtime behind the `Queued*` providers.
#[cfg(feature = "queue")]
use chrono::Duration as ChronoDuration;
#[cfg(feature = "queue")]
use std::sync::Mutex;
#[cfg(feature = "queue")]
use std::time::Duration;
#[cfg(feature = "queue")]
use symbiotic_core::QueueItemId;
#[cfg(feature = "queue")]
use symbiotic_queue::{
    EnqueueDisposition, EnqueueOutcome, EnqueueRequest, FailOutcome, Failure, QueueBackend,
    QueueItem, QueueStatus,
};
#[cfg(feature = "queue")]
use symbiotic_trace::TraceSink;

#[cfg(feature = "queue")]
pub mod private_fs;
#[cfg(feature = "queue")]
mod queue_runtime;
#[cfg(feature = "queue")]
pub use queue_runtime::{
    CacheEntry, CachedResponse, DirResponseCache, InMemoryReceiptSink, ModelAdmission,
    QueueReceipt, QueueReceiptSink, RUNTIME_DIAGNOSTICS, ReceiptStatus, ResponseCache,
};
#[cfg(feature = "queue")]
use queue_runtime::{QueueRuntime, queue_runtime_builders};

#[cfg(feature = "queue")]
mod spend;
#[cfg(feature = "queue")]
pub use spend::*;

mod secrets;
pub use secrets::{CredentialBoundary, SecretValue};
mod registry;
pub use registry::*;
mod classify;
pub mod wire;
#[cfg(feature = "queue")]
pub use classify::QueuedClassifierProvider;
pub use classify::{
    AnswerValue, ChatClassifierProvider, ChoiceDecision, ChoiceOption, ClassifierAnswer,
    ClassifierProvider, ClassifierQuestion, ClassifyRequest, ClassifyResponse, JEV_DEFAULT_MODEL,
    JEV_MAX_CHOICE_OPTIONS, JEV_MAX_REQUEST_TOKENS, JEV_MAX_SCORE_LEVELS,
    JEV_MAX_STATE_AND_LONGEST_QUESTION_TOKENS, JevClassifierProvider, OptionProbability,
    QuestionKind, StaticClassifierProvider, TYPESAFE_BASE_URL,
};

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
    /// Typed questions about a JSON state answered with probabilities
    /// ([`ClassifierProvider`]).
    Classify,
    Vision,
    ImageGeneration,
    VideoGeneration,
    AgentTask,
}

/// Relative price band for advisory model selection. It does not establish an
/// enforceable monetary reservation; Foundation owns spend accounting and budgets
/// under `docs/architecture/boundary.md`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostClass {
    Free,
    Budget,
    #[default]
    Standard,
    Premium,
}

/// Reasoning capability of a model — distinct from `symbiotic_core::ModelTier`,
/// which is selection routing, not what the model can do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningTier {
    #[default]
    None,
    Standard,
    Extended,
}

/// Capability flags for a model behind the engine seam: what the host can rely
/// on when planning a call. Distinct from [`ModelCapability`], which names the
/// operation kinds a provider serves (chat/embedding/rerank/...).
///
/// Advisory metadata supplied by the validated deployment registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelCapabilities {
    /// Maximum context window in tokens, when known.
    pub context_window: Option<u32>,
    pub tool_use: bool,
    pub structured_output: bool,
    pub reasoning_tier: ReasoningTier,
    pub cost_class: CostClass,
    /// Published token tariff, when catalogued.
    pub pricing: Option<ModelPricing>,
}

/// A model's published per-token tariff in micro-USD per million tokens
/// (USD 1 per million tokens = 1_000_000). Advisory, like [`CostClass`]:
/// hosts use it for estimates; the provider's bill is authoritative.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelPricing {
    pub input_micro_usd_per_million_tokens: u64,
    pub output_micro_usd_per_million_tokens: u64,
}

impl ModelPricing {
    /// Estimated cost of one call in micro-USD, rounded up.
    pub fn cost_micro_usd(&self, input_tokens: u64, output_tokens: u64) -> u64 {
        let total = u128::from(input_tokens) * u128::from(self.input_micro_usd_per_million_tokens)
            + u128::from(output_tokens) * u128::from(self.output_micro_usd_per_million_tokens);
        u64::try_from(total.div_ceil(1_000_000)).unwrap_or(u64::MAX)
    }
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

/// Provider/runtime failures contain only a closed diagnostic code or capability.
/// Adapter output and validation text cannot become an error payload.
/// ```compile_fail
/// use symbiotic_model::ModelError;
/// let key = "synthetic-validation-key";
/// let error = ModelError::Auth(format!("invalid key {key}"));
/// ```
#[derive(Clone, Copy, Debug, Error)]
pub enum ModelError {
    #[error("provider unavailable: {0}")]
    Unavailable(symbiotic_core::DiagnosticCode),
    #[error("provider auth failed: {0}")]
    Auth(symbiotic_core::DiagnosticCode),
    #[error("provider rate limited: {0}")]
    RateLimited(symbiotic_core::DiagnosticCode),
    #[error("budget exhausted: {0}")]
    BudgetExhausted(symbiotic_core::DiagnosticCode),
    #[error("provider timed out: {0}")]
    Timeout(symbiotic_core::DiagnosticCode),
    #[error("capability unsupported: {0:?}")]
    Unsupported(ModelCapability),
    #[error("invalid request: {0}")]
    InvalidRequest(symbiotic_core::DiagnosticCode),
    #[error("provider failed: {0}")]
    Provider(symbiotic_core::DiagnosticCode),
    #[error("model queue failed: {0}")]
    Queue(symbiotic_core::DiagnosticCode),
    #[error("model cache failed: {0}")]
    Cache(symbiotic_core::DiagnosticCode),
}

impl ModelError {
    /// Static diagnostic used by logs and durable queue failure records.
    pub const fn code(&self) -> DiagnosticCode {
        match self {
            Self::Unavailable(code) => *code,
            Self::Auth(code) => *code,
            Self::RateLimited(code) => *code,
            Self::BudgetExhausted(code) => *code,
            Self::Timeout(code) => *code,
            Self::InvalidRequest(code) => *code,
            Self::Provider(code) => *code,
            Self::Queue(code) => *code,
            Self::Cache(code) => *code,
            Self::Unsupported(_) => DiagnosticCode::InvalidConfiguration,
        }
    }
}

/// Adapter evidence about a failed provider call; error class alone supplies none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureCharge {
    Unknown,
    KnownZero,
}

#[async_trait]
pub trait ModelProvider: Send + Sync {
    fn descriptor(&self) -> &ProviderDescriptor;
    /// Override only with evidence that the failed attempt incurred no charge.
    fn failure_charge(&self, _error: &ModelError) -> FailureCharge {
        FailureCharge::Unknown
    }
    /// Refuse unsupported or unbounded transport configuration before execution.
    fn validate_configuration(&self) -> Result<(), ModelError> {
        Ok(())
    }

    /// A stable, non-secret fingerprint of the credential this provider
    /// calls with, or `None` when it has none. The queue runtime keys
    /// attempt budgets by it, so a rotated credential starts with a fresh
    /// budget instead of inheriting the exhausted budget of the old one. It
    /// must never be the credential or a reversible form of it; see
    /// [`api_key_fingerprint`]. The runtime does not store or trace it.
    fn credential_fingerprint(&self) -> Option<String> {
        None
    }

    /// Forward the opaque credential owner for composed adapter results.
    /// Foundation creates this guard; adapters cannot replace its result policy
    /// or read its secret. Credential-bearing adapters without a guard are refused.
    #[doc(hidden)]
    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        None
    }
}

impl<T> ModelProvider for Arc<T>
where
    T: ModelProvider + ?Sized,
{
    fn failure_charge(&self, error: &ModelError) -> FailureCharge {
        self.as_ref().failure_charge(error)
    }
    fn descriptor(&self) -> &ProviderDescriptor {
        (**self).descriptor()
    }

    fn validate_configuration(&self) -> Result<(), ModelError> {
        (**self).validate_configuration()
    }

    fn credential_fingerprint(&self) -> Option<String> {
        (**self).credential_fingerprint()
    }

    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        (**self).credential_boundary()
    }
}

/// The fingerprint of an API key for
/// [`ModelProvider::credential_fingerprint`]: SHA-256 over a fixed
/// domain-separation prefix and the key, in hex; `None` for an empty key.
/// One-way, so it identifies a key generation without revealing the key.
pub fn api_key_fingerprint(api_key: &str) -> Option<String> {
    if api_key.trim().is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"symbiotic-model/credential-fingerprint/v1\0");
    hasher.update(api_key.as_bytes());
    Some(hex::encode(hasher.finalize()))
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
impl<T> ChatProvider for Arc<T>
where
    T: ChatProvider + ?Sized,
{
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        (**self).chat(request).await
    }
}

#[async_trait]
impl<T> EmbeddingProvider for Arc<T>
where
    T: EmbeddingProvider + ?Sized,
{
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        (**self).embed(request).await
    }
}

#[async_trait]
impl<T> RerankProvider for Arc<T>
where
    T: RerankProvider + ?Sized,
{
    async fn rerank(&self, request: RerankRequest) -> Result<RerankResponse, ModelError> {
        (**self).rerank(request).await
    }
}

#[async_trait]
pub trait CredentialResolver: Send + Sync {
    async fn resolve_auth(&self, mode: &ProviderAuthMode) -> Result<ResolvedAuth, ModelError>;
}

/// Resolved provider authentication; secret material has no diagnostic representation.
/// ```compile_fail
/// use symbiotic_model::{ResolvedAuth, SecretValue};
/// let auth = ResolvedAuth::Bearer(SecretValue::from("synthetic"));
/// println!("{auth:?}");
/// ```
#[derive(Clone)]
pub enum ResolvedAuth {
    None,
    Bearer(SecretValue<String>),
    ApiKey(SecretValue<String>),
    Headers(Vec<(String, SecretValue<String>)>),
    LocalSession { tool: String, account: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelQueueConfig {
    /// Absolute durable account request allowance, separate from pacing and money.
    #[serde(default)]
    pub provider_request_limit: Option<u64>,
    pub max_in_flight: usize,
    pub lease_seconds: u64,
    pub logical_retry_attempts: u32,
    pub retry_attempts: u32,
    pub retry_jitter_seconds: u64,
    /// Longest provider call; execution requires a finite nonzero value. A caller that stops
    /// waiting does not cancel a call in flight (the runtime owns it), so
    /// this is also what bounds a call nobody waits for.
    pub request_timeout_seconds: Option<u64>,
    pub requests_per_minute: Option<u32>,
    pub input_units_per_minute: Option<u64>,
    pub response_cache_dir: Option<PathBuf>,
    /// Seconds of rate budget available as an initial burst. `0` (the
    /// default) paces from the first request; `60` lets one minute's budget
    /// through at once, as providers that meter per minute allow.
    #[serde(default)]
    pub rate_burst_seconds: u64,
    /// First retry delay; it doubles per attempt up to 32x, capped at 30 s,
    /// before jitter. The default is one second.
    #[serde(default = "default_retry_base_delay_ms")]
    pub retry_base_delay_ms: u64,
    /// Also retry `ModelError::Provider` failures (non-transient provider
    /// answers such as a 4xx or an unparsable body). Off by default: only
    /// unavailable, rate-limited and timed-out calls retry. Provider errors
    /// never start a cooldown.
    #[serde(default)]
    pub retry_provider_errors: bool,
    /// Write each request, serialized, to
    /// `{dir}/{kind}[/{scope}]/{request_hash}.json` before it is queued.
    /// Debugging only: requests may contain sensitive text.
    #[serde(default)]
    pub request_debug_dir: Option<PathBuf>,
    /// When a request's attempt budget ran out in an earlier call, a new call
    /// for the same request gets a fresh budget once this many seconds have
    /// passed. `None` (the default) keeps the exhausted budget while the queue
    /// remembers the request, so a persistent runtime does not pay for it
    /// again after a restart. `Some(0)` gives every call its own budget.
    #[serde(default)]
    pub budget_renewal_seconds: Option<u64>,
}

fn default_retry_base_delay_ms() -> u64 {
    1_000
}

impl Default for ModelQueueConfig {
    fn default() -> Self {
        Self {
            provider_request_limit: None,
            max_in_flight: 1,
            lease_seconds: 600,
            logical_retry_attempts: 3,
            retry_attempts: 3,
            retry_jitter_seconds: 20,
            request_timeout_seconds: Some(600),
            requests_per_minute: None,
            input_units_per_minute: None,
            response_cache_dir: None,
            rate_burst_seconds: 0,
            retry_base_delay_ms: default_retry_base_delay_ms(),
            retry_provider_errors: false,
            request_debug_dir: None,
            budget_renewal_seconds: None,
        }
    }
}

#[cfg(feature = "queue")]
/// Queue-bound wrapper for a [`ChatProvider`].
///
/// Hosts get queued providers from `symbiotic-ai-runtime`'s `Runtime`, which
/// owns the backend, admission, caches and sinks. Constructing this type
/// directly is supported only inside Foundation.
#[derive(Clone)]
pub struct QueuedChatProvider<C> {
    inner: C,
    runtime: QueueRuntime,
}

#[cfg(feature = "queue")]
impl<C> QueuedChatProvider<C> {
    pub fn new(
        inner: C,
        queue: Arc<dyn QueueBackend>,
        worker_id: impl Into<String>,
        config: ModelQueueConfig,
    ) -> Self {
        Self {
            inner,
            runtime: QueueRuntime::new(queue, worker_id.into(), config),
        }
    }

    queue_runtime_builders!();
}

#[cfg(feature = "queue")]
#[async_trait]
impl<C> ModelProvider for QueuedChatProvider<C>
where
    C: ChatProvider + Clone + Send + Sync,
{
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }

    fn validate_configuration(&self) -> Result<(), ModelError> {
        self.inner.validate_configuration()
    }

    fn credential_fingerprint(&self) -> Option<String> {
        self.inner.credential_fingerprint()
    }

    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        self.inner.credential_boundary()
    }
}

#[cfg(feature = "queue")]
#[async_trait]
impl<C> ChatProvider for QueuedChatProvider<C>
where
    C: ChatProvider + Clone + Send + Sync + 'static,
{
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        run_queued(
            &self.runtime,
            self.inner.descriptor().clone(),
            ModelCapability::Chat,
            "chat",
            request,
            |inner: C, request| async move { inner.chat(request).await },
            self.inner.clone(),
        )
        .await
    }
}

#[cfg(feature = "queue")]
/// Queue-bound wrapper for an [`EmbeddingProvider`]; see
/// [`QueuedChatProvider`] for who constructs it.
#[derive(Clone)]
pub struct QueuedEmbeddingProvider<E> {
    inner: E,
    runtime: QueueRuntime,
}

#[cfg(feature = "queue")]
impl<E> QueuedEmbeddingProvider<E> {
    pub fn new(
        inner: E,
        queue: Arc<dyn QueueBackend>,
        worker_id: impl Into<String>,
        config: ModelQueueConfig,
    ) -> Self {
        Self {
            inner,
            runtime: QueueRuntime::new(queue, worker_id.into(), config),
        }
    }

    queue_runtime_builders!();
}

#[cfg(feature = "queue")]
#[async_trait]
impl<E> ModelProvider for QueuedEmbeddingProvider<E>
where
    E: EmbeddingProvider + Clone + Send + Sync,
{
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }

    fn validate_configuration(&self) -> Result<(), ModelError> {
        self.inner.validate_configuration()
    }

    fn credential_fingerprint(&self) -> Option<String> {
        self.inner.credential_fingerprint()
    }

    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        self.inner.credential_boundary()
    }
}

#[cfg(feature = "queue")]
#[async_trait]
impl<E> EmbeddingProvider for QueuedEmbeddingProvider<E>
where
    E: EmbeddingProvider + Clone + Send + Sync + 'static,
{
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        run_queued(
            &self.runtime,
            self.inner.descriptor().clone(),
            ModelCapability::Embedding,
            "embedding",
            request,
            |inner: E, request| async move { inner.embed(request).await },
            self.inner.clone(),
        )
        .await
    }
}

#[cfg(feature = "queue")]
/// Queue-bound wrapper for a [`RerankProvider`], mirroring [`QueuedChatProvider`]
/// and [`QueuedEmbeddingProvider`]. Reranking is a first-class model seam (the
/// recall cascade's relevance stage), so it earns the same idempotency,
/// response-cache, cooldown, and trace machinery as chat and embedding rather
/// than a bespoke rate limiter.
#[derive(Clone)]
pub struct QueuedRerankProvider<R> {
    inner: R,
    runtime: QueueRuntime,
}

#[cfg(feature = "queue")]
impl<R> QueuedRerankProvider<R> {
    pub fn new(
        inner: R,
        queue: Arc<dyn QueueBackend>,
        worker_id: impl Into<String>,
        config: ModelQueueConfig,
    ) -> Self {
        Self {
            inner,
            runtime: QueueRuntime::new(queue, worker_id.into(), config),
        }
    }

    queue_runtime_builders!();
}

#[cfg(feature = "queue")]
#[async_trait]
impl<R> ModelProvider for QueuedRerankProvider<R>
where
    R: RerankProvider + Clone + Send + Sync,
{
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }

    fn validate_configuration(&self) -> Result<(), ModelError> {
        self.inner.validate_configuration()
    }

    fn credential_fingerprint(&self) -> Option<String> {
        self.inner.credential_fingerprint()
    }

    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        self.inner.credential_boundary()
    }
}

#[cfg(feature = "queue")]
#[async_trait]
impl<R> RerankProvider for QueuedRerankProvider<R>
where
    R: RerankProvider + Clone + Send + Sync + 'static,
{
    async fn rerank(&self, request: RerankRequest) -> Result<RerankResponse, ModelError> {
        run_queued(
            &self.runtime,
            self.inner.descriptor().clone(),
            ModelCapability::Rerank,
            "rerank",
            request,
            |inner: R, request| async move { inner.rerank(request).await },
            self.inner.clone(),
        )
        .await
    }
}

/// Usage receipts of one queued call.
#[cfg(feature = "queue")]
struct CallReceipts {
    accepted_spend: Option<AcceptedSpendHandoff>,
    sink: Option<Arc<dyn QueueReceiptSink>>,
    binding: Option<symbiotic_core::BindingIdentity>,
    queue_id: QueueId,
    kind: String,
    request_hash: String,
    input_units: u64,
}

#[cfg(feature = "queue")]
struct AttemptTiming {
    queue_wait_ms: Option<u64>,
    throttle_wait_ms: Option<u64>,
    provider_ms: Option<u64>,
}

#[cfg(feature = "queue")]
impl AttemptTiming {
    const NONE: Self = Self {
        queue_wait_ms: None,
        throttle_wait_ms: None,
        provider_ms: None,
    };
}

#[cfg(feature = "queue")]
impl CallReceipts {
    async fn record(
        &self,
        status: ReceiptStatus,
        item: Option<&QueueItem>,
        trace: Option<&ModelInvocationTrace>,
        error: Option<DiagnosticCode>,
        timing: AttemptTiming,
    ) {
        let Some(sink) = &self.sink else {
            return;
        };
        sink.record_receipt(QueueReceipt {
            spend_receipt: item.filter(|i| i.attempt > 0).map(|i| {
                self.accepted_spend
                    .as_ref()
                    .map(|h| h.reservation.reference.clone())
                    .unwrap_or_else(|| {
                        SpendReceiptRef(format!("runtime:{}:{}", i.item_id.0, i.attempt))
                    })
            }),
            binding: self.binding.clone(),
            queue_id: self.queue_id.clone(),
            kind: self.kind.clone(),
            item_id: item.map(|item| item.item_id.clone()),
            request_hash: self.request_hash.clone(),
            status,
            attempt: item.map_or(0, |item| item.attempt),
            request_units: 1,
            input_units: self.input_units,
            usage: trace.map(|trace| trace.usage.clone()),
            cache: trace.map(|trace| trace.cache.clone()),
            metadata: trace.map_or(Value::Null, |trace| trace.metadata.clone()),
            error,
            queue_wait_ms: timing.queue_wait_ms,
            throttle_wait_ms: timing.throttle_wait_ms,
            provider_ms: timing.provider_ms,
            timestamp: Utc::now(),
        })
        .await;
    }
}

#[cfg(feature = "queue")]
fn load_cached<Res: for<'de> Deserialize<'de>>(
    cache: &dyn ResponseCache,
    entry: &CacheEntry<'_>,
) -> Result<Option<Res>, ModelError> {
    let Some(value) = cache.load(entry)? else {
        return Ok(None);
    };
    if value
        .pointer("/trace/metadata/result_scope")
        .and_then(Value::as_str)
        != entry.scope
        || value.pointer("/trace/request_hash").and_then(Value::as_str) != Some(entry.request_hash)
    {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(|_err| ModelError::Cache(symbiotic_core::DiagnosticCode::CacheFailure))
}

/// Run `work` on tokio's blocking pool and wait for it. A `ResponseCache`
/// is synchronous and may do file I/O, and (de)serializing a whole response
/// is CPU work. On an async worker thread either would stall every task
/// there, including the renewal of an attempt's lease.
#[cfg(feature = "queue")]
async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ModelError> + Send + 'static,
) -> Result<T, ModelError> {
    match tokio::task::spawn_blocking(work).await {
        Ok(output) => output,
        Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
        Err(_err) => Err(ModelError::Cache(
            symbiotic_core::DiagnosticCode::CacheFailure,
        )),
    }
}

#[cfg(feature = "queue")]
fn queue_error(_err: symbiotic_queue::QueueError) -> ModelError {
    ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure)
}

#[cfg(feature = "queue")]
fn elapsed_ms(since: std::time::Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// What every attempt of one queued call shares: the backend and policy,
/// the request with its identity and cache entry, and the call's sinks.
#[cfg(feature = "queue")]
struct QueuedCall<Req> {
    queue: Arc<dyn QueueBackend>,
    spend: Arc<dyn SpendLedger>,
    accepted_spend: Option<AcceptedSpendHandoff>,
    invocation: String,
    attempt_binding: String,
    attempt_context: Option<ExecutionAttemptContext>,
    worker_id: String,
    config: ModelQueueConfig,
    queue_id: QueueId,
    descriptor: ProviderDescriptor,
    result_owner: Arc<dyn ModelProvider>,
    capability: ModelCapability,
    kind: String,
    binding_identity: Option<symbiotic_core::BindingIdentity>,
    // Response-cache subdirectory under `kind`; see `run_queued`.
    cache_scope: Option<String>,
    cache: Option<Arc<dyn ResponseCache>>,
    trace_sink: Option<Arc<dyn TraceSink>>,
    receipts: CallReceipts,
    request: Req,
    request_hash: String,
    request_value: Value,
    sensitivity: Sensitivity,
    idempotency_key: Option<String>,
}

#[cfg(feature = "queue")]
impl<Req> QueuedCall<Req> {
    async fn recovered<Res: Serialize + for<'de> Deserialize<'de>>(
        &self,
    ) -> Result<Option<Res>, ModelError> {
        if self.accepted_spend.is_some() {
            return Ok(None);
        }
        let spend = self.spend.clone();
        let account = self.queue_id.0.clone();
        let invocation = self.invocation.clone();
        let binding = self.attempt_binding.clone();
        let context = self.attempt_context.clone();
        run_blocking(move || {
            let receipt = spend.invocation(&account, &invocation)?;
            if receipt
                .as_ref()
                .is_some_and(|r| r.reservation.binding != binding)
            {
                return Err(spend::reconciliation());
            }
            if let Some(receipt) = &receipt
                && let Some(context) = context
            {
                context.capture(&receipt.reservation.reference)?;
            }
            Ok(receipt)
        })
        .await?
        .and_then(|receipt| receipt.output)
        .map(|output| {
            secrets::composed_result(
                self.result_owner.as_ref(),
                serde_json::from_value(output).map_err(|_| spend::storage()),
            )
        })
        .transpose()
    }

    fn cache_entry(&self) -> CacheEntry<'_> {
        CacheEntry {
            kind: &self.kind,
            scope: self.cache_scope.as_deref(),
            request_hash: &self.request_hash,
            request: &self.request_value,
        }
    }

    /// Queue the request with a fresh attempt budget, or join the item an
    /// identical request already has.
    async fn enqueue(&self) -> Result<EnqueueOutcome, ModelError> {
        self.queue
            .enqueue(EnqueueRequest {
                queue_id: self.queue_id.clone(),
                kind: self.kind.clone(),
                payload: model_queue_payload(
                    &self.capability,
                    &self.request_hash,
                    &self.descriptor,
                    LogicalRetryState {
                        attempts_used: 0,
                        max_attempts: logical_max_attempts(&self.config),
                    },
                ),
                idempotency_key: self.idempotency_key.clone(),
                run_after: None,
                max_attempts: Some(item_max_attempts(&self.config)),
                force: false,
            })
            .await
            .map_err(queue_error)
    }

    async fn renew_budget(&self, current: &QueueItemId) -> Result<EnqueueOutcome, ModelError> {
        reenqueue_with_fresh_budget(
            self.queue.as_ref(),
            &self.queue_id,
            &self.descriptor,
            self.capability,
            &self.kind,
            &self.request_hash,
            &self.idempotency_key,
            &self.config,
            current,
        )
        .await
    }

    async fn release_before_dispatch(&self, reference: &SpendReceiptRef) -> Result<(), ModelError> {
        if self.accepted_spend.is_none() {
            let spend = self.spend.clone();
            let reference = reference.clone();
            run_blocking(move || spend.finish(&reference, SpendState::Released, None, None))
                .await?;
        }
        Ok(())
    }

    // A later handoff may reconsider accounting refusals after reconciliation
    // or restored account allowance. Other stopped failures remain terminal.
    async fn reconsider_stopped(
        &self,
        item: &QueueItem,
    ) -> Result<Option<EnqueueOutcome>, ModelError> {
        let mut denied = item.last_error == Some(DiagnosticCode::SpendBudgetExhausted);
        if !denied {
            if item.last_error != Some(DiagnosticCode::SpendReconciliationRequired) {
                return Ok(None);
            }
            let spend = self.spend.clone();
            let account = self.queue_id.0.clone();
            let invocation = self.invocation.clone();
            let receipt = run_blocking(move || spend.invocation(&account, &invocation)).await?;
            let Some(receipt) = receipt.filter(|r| r.state == SpendState::Released) else {
                return Ok(None);
            };
            // A reclaimed queue claim may itself have been denied while an
            // earlier accepted attempt was still unknown. That claim never
            // consumed a provider attempt either.
            denied = receipt.reservation.reference
                != SpendReceiptRef(format!("runtime:{}:{}", item.item_id.0, item.attempt));
        }
        let state = logical_retry_state(&item.payload, logical_max_attempts(&self.config));
        // Reservation denial is a queue claim, never a provider attempt.
        let attempts_used = state
            .attempts_used
            .saturating_add(item.attempt)
            .saturating_sub(u32::from(denied));
        if attempts_used >= state.max_attempts {
            return if budget_renewed(item, &self.config)? {
                self.renew_budget(&item.item_id).await.map(Some)
            } else {
                Ok(None)
            };
        }
        let remaining = state.max_attempts - attempts_used;
        let payload = model_queue_payload(
            &self.capability,
            &self.request_hash,
            &self.descriptor,
            LogicalRetryState {
                attempts_used,
                max_attempts: state.max_attempts,
            },
        );
        self.queue
            .enqueue_replacing(
                EnqueueRequest {
                    queue_id: self.queue_id.clone(),
                    kind: self.kind.clone(),
                    payload,
                    idempotency_key: self.idempotency_key.clone(),
                    run_after: None,
                    max_attempts: Some(remaining.min(item_max_attempts(&self.config))),
                    force: true,
                },
                &item.item_id,
            )
            .await
            .map(Some)
            .map_err(queue_error)
    }

    /// The next item of the request's retry chain after `dead`, or `None`
    /// once the request's attempts are used up.
    async fn continue_chain(
        &self,
        dead: &QueueItem,
        err: &ModelError,
    ) -> Result<Option<EnqueueOutcome>, ModelError> {
        reenqueue_dead_item(
            self.queue.as_ref(),
            &self.queue_id,
            &self.descriptor,
            self.capability,
            &self.kind,
            &self.request_hash,
            &self.idempotency_key,
            dead,
            &self.config,
            err,
        )
        .await
    }
}

/// Response-cache work, which runs on the blocking pool with a handle to
/// the call.
#[cfg(feature = "queue")]
impl<Req: Send + Sync + 'static> QueuedCall<Req> {
    /// The cached response, traced and receipted as a cache hit on `item`.
    async fn cached<Res>(
        self: &Arc<Self>,
        item: Option<&QueueItem>,
    ) -> Result<Option<Res>, ModelError>
    where
        Res: Serialize + TraceCarrier + for<'de> Deserialize<'de> + Send + 'static,
    {
        let Some(cache) = self.cache.clone() else {
            return Ok(None);
        };
        let call = self.clone();
        let loaded =
            run_blocking(move || load_cached::<Res>(cache.as_ref(), &call.cache_entry())).await;
        let loaded = secrets::composed_result(self.result_owner.as_ref(), loaded)?;
        let Some(cached) = loaded else {
            return Ok(None);
        };
        // Trace first, so the receipt carries any diagnostic the trace write
        // added. The receipt repeats the original usage; its metadata is the
        // returned response's.
        let mut receipted = cached.trace().clone();
        let response = self
            .traced_cache_hit(cached, item.map(|item| item.item_id.clone()))
            .await;
        receipted.metadata = response.trace().metadata.clone();
        self.receipts
            .record(
                ReceiptStatus::CacheHit,
                item,
                Some(&receipted),
                None,
                AttemptTiming::NONE,
            )
            .await;
        Ok(Some(response))
    }

    /// Cache a successful attempt's response, then trace it. The provider
    /// has answered and been paid, so neither write can fail the call: a
    /// failure is noted on the response ([`note_side_effect`]).
    async fn record_success<Res>(self: &Arc<Self>, response: Res) -> Res
    where
        Res: Serialize + TraceCarrier + Clone + Send + Sync + 'static,
    {
        let mut response = response;
        let mut trace = response.trace().clone();
        if !trace.metadata.is_object() {
            trace.metadata = serde_json::json!({ "value": trace.metadata });
        }
        trace.metadata["result_scope"] = serde_json::json!(self.cache_scope);
        trace.metadata["binding"] =
            serde_json::to_value(&self.binding_identity).expect("binding identity serializes");
        response.set_trace(trace);
        if let Some(cache) = self.cache.clone() {
            let call = self.clone();
            let shared = Arc::new(response);
            let stored = run_blocking({
                let shared = shared.clone();
                move || {
                    let value = serde_json::to_value(&*shared).map_err(|_err| {
                        ModelError::Cache(symbiotic_core::DiagnosticCode::CacheFailure)
                    })?;
                    cache.store(&call.cache_entry(), &value)
                }
            })
            .await;
            // The blocking task has dropped its handle by the time it is joined.
            response = Arc::try_unwrap(shared).unwrap_or_else(|shared| (*shared).clone());
            if let Err(err) = stored {
                note_side_effect(
                    &mut response,
                    &self.queue_id,
                    "response_cache_write_failed",
                    err.code(),
                );
            }
        }
        if let Some(trace_sink) = &self.trace_sink
            && let Err(err) = trace_sink
                .record_model_invocation(response.trace().clone())
                .await
        {
            note_side_effect(
                &mut response,
                &self.queue_id,
                "trace_write_failed",
                err.code(),
            );
        }
        response
    }
}

#[cfg(feature = "queue")]
impl<Req> QueuedCall<Req> {
    /// A cached response, traced as a cache hit. A failed trace write is
    /// noted on the response; it does not fail the call.
    async fn traced_cache_hit<Res: TraceCarrier>(
        &self,
        mut response: Res,
        queue_item_id: Option<QueueItemId>,
    ) -> Res {
        let mut trace = response.trace().clone();
        trace.trace_id = TraceId::new();
        trace.queue_item_id = queue_item_id;
        trace.model = self.descriptor.identity.clone();
        trace.cache.response_cache = CacheStatus::Hit;
        trace.outcome = InvocationOutcome::Succeeded;
        trace.error_class = None;
        trace.timestamp = Utc::now();
        response.set_trace(trace.clone());
        if let Some(trace_sink) = &self.trace_sink
            && let Err(err) = trace_sink.record_model_invocation(trace).await
        {
            note_side_effect(
                &mut response,
                &self.queue_id,
                "trace_write_failed",
                err.code(),
            );
        }
        response
    }

    /// Trace a failed call. A failed trace write is logged; the call still
    /// fails with its own error.
    async fn trace_failure(&self, queue_item_id: Option<QueueItemId>, err: &ModelError) {
        let Some(trace_sink) = &self.trace_sink else {
            return;
        };
        let written = trace_sink
            .record_model_invocation(ModelInvocationTrace {
                trace_id: TraceId::new(),
                queue_item_id,
                model: self.descriptor.identity.clone(),
                role_binding: None,
                source: None,
                sensitivity: self.sensitivity,
                request_hash: self.request_hash.clone(),
                response_hash: None,
                cache: CacheTrace::default(),
                usage: UsageTrace::default(),
                timing: TimingTrace::default(),
                outcome: InvocationOutcome::Failed,
                error_class: Some(error_class(err)),
                audit_refs: Vec::new(),
                metadata: serde_json::json!({"binding": self.binding_identity}),
                timestamp: Utc::now(),
            })
            .await;
        if let Err(trace_err) = written {
            warn_side_effect(
                &self.queue_id,
                "failure_trace_write_failed",
                trace_err.code(),
            );
        }
    }
}

/// A side effect of a call (a cache, trace, cooldown or queue write)
/// failed. The call's outcome stands; the failure is logged as a warning.
#[cfg(feature = "queue")]
fn warn_side_effect(queue_id: &QueueId, kind: &str, error: DiagnosticCode) {
    tracing::warn!(
        queue_id = %queue_id.0,
        kind,
        error = error.code(),
        "model call side effect failed; the call's outcome stands"
    );
}

/// As [`warn_side_effect`], and also listed under [`RUNTIME_DIAGNOSTICS`] in
/// the response's trace metadata, which its usage receipt carries.
#[cfg(feature = "queue")]
fn note_side_effect<Res: TraceCarrier>(
    response: &mut Res,
    queue_id: &QueueId,
    kind: &str,
    error: DiagnosticCode,
) {
    warn_side_effect(queue_id, kind, error);
    let mut trace = response.trace().clone();
    if !trace.metadata.is_object() {
        let original = std::mem::take(&mut trace.metadata);
        trace.metadata = if original.is_null() {
            serde_json::json!({})
        } else {
            serde_json::json!({ "value": original })
        };
    }
    let entry = serde_json::json!({ "kind": kind, "error": error.code() });
    match trace.metadata.get_mut(RUNTIME_DIAGNOSTICS) {
        Some(Value::Array(list)) => list.push(entry),
        _ => trace.metadata[RUNTIME_DIAGNOSTICS] = serde_json::json!([entry]),
    }
    response.set_trace(trace);
}

// The arguments are the queue execution boundary: one queued call.
#[cfg(feature = "queue")]
#[allow(clippy::too_many_arguments)]
async fn run_queued<P, Req, Res, F, Fut>(
    runtime: &QueueRuntime,
    mut descriptor: ProviderDescriptor,
    capability: ModelCapability,
    kind: &str,
    request: Req,
    call: F,
    provider: P,
) -> Result<Res, ModelError>
where
    P: ModelProvider + Clone + Send + Sync + 'static,
    Req: Clone + Serialize + Send + Sync + 'static,
    Req: BudgetedModelRequest,
    Res: Clone + Serialize + for<'de> Deserialize<'de> + TraceCarrier + Send + Sync + 'static,
    F: FnOnce(P, Req) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Result<Res, ModelError>> + Send + 'static,
{
    runtime.config.validate()?;
    provider.validate_configuration()?;
    let queue_id = runtime
        .queue_id
        .clone()
        .unwrap_or_else(|| descriptor.queue_id());
    let request_hash = hash_json(&request)?;
    let request_value = serde_json::to_value(&request).map_err(|_err| {
        ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::InvalidConfiguration)
    })?;
    // The provider is part of the key: models pooled on one queue share its
    // limits, never each other's attempt budgets or results. So is its
    // credential's fingerprint, when it has one: a rotated credential gets
    // a fresh budget. Only a hash of the fingerprint is stored.
    descriptor.metadata = serde_json::json!({"configuration": descriptor.metadata, "binding": runtime.binding_identity});
    let provider_identity = hash_json(&(
        &descriptor,
        &runtime.binding_identity,
        provider.credential_fingerprint(),
    ))?;
    let attempt_binding = hash_json(&(&provider_identity, &request_hash))?;
    let invocation = match &runtime.invocation {
        Some(invocation) => execution_invocation_identity(
            runtime
                .binding_identity
                .as_ref()
                .ok_or(ModelError::InvalidRequest(
                    DiagnosticCode::BindingIdentityIsRequired,
                ))?,
            invocation,
        )?,
        None => attempt_binding.clone(),
    };
    let idempotency_key = Some(format!(
        "{}:{provider_identity}:{request_hash}:{}",
        queue_id.0,
        hash_json(&invocation)?
    ));
    let call_state = Arc::new(QueuedCall {
        queue: runtime.queue.clone(),
        spend: runtime.spend.clone(),
        accepted_spend: runtime.accepted_spend.clone(),
        invocation,
        attempt_binding,
        attempt_context: runtime.attempt_context.clone(),
        worker_id: runtime.worker_id.clone(),
        config: runtime.config.clone(),
        receipts: CallReceipts {
            accepted_spend: runtime.accepted_spend.clone(),
            sink: runtime.receipt_sink.clone(),
            binding: runtime.binding_identity.clone(),
            queue_id: queue_id.clone(),
            kind: kind.to_string(),
            request_hash: request_hash.clone(),
            input_units: request.input_budget_units()?,
        },
        queue_id,
        descriptor,
        result_owner: Arc::new(provider.clone()),
        capability,
        kind: kind.to_string(),
        binding_identity: runtime.binding_identity.clone(),
        cache_scope: Some(provider_identity),
        cache: runtime.cache(),
        trace_sink: runtime.trace_sink.clone(),
        sensitivity: request.sensitivity(),
        request,
        request_hash,
        request_value,
        idempotency_key,
    });
    let this = call_state.as_ref();
    let queue = &this.queue;
    let config = &this.config;
    let queue_id = &this.queue_id;
    if let Some(dir) = config.request_debug_dir.clone() {
        let call = call_state.clone();
        run_blocking(move || {
            DirResponseCache::new(dir).store(&call.cache_entry(), &call.request_value)
        })
        .await?;
    }
    // Ordinary cache hits retain their cache provenance and need no dispatch
    // store. Explicit invocation replay must validate its exact binding first.
    if runtime.invocation.is_none()
        && let Some(cached) = call_state.cached::<Res>(None).await?
    {
        return Ok(cached);
    }
    if let Some(output) = this.recovered::<Res>().await? {
        return Ok(output);
    }
    if runtime.invocation.is_some()
        && let Some(cached) = call_state.cached::<Res>(None).await?
    {
        return Ok(cached);
    }
    let queued_at = std::time::Instant::now();
    // Cooldown + rate-bucket wait accumulated across loop iterations, so the
    // trace can report the throttle-wait vs http-time split (the measured
    // lesson) without changing `queued_ms` semantics.
    let mut throttle_wait = Duration::ZERO;
    let mut enqueue = this.enqueue().await?;
    this.receipts
        .record(
            ReceiptStatus::Queued,
            Some(&enqueue.item),
            None,
            None,
            AttemptTiming::NONE,
        )
        .await;
    if enqueue.disposition == EnqueueDisposition::TerminalDuplicate {
        match enqueue.item.status {
            QueueStatus::Stopped => {
                if let Some(next) = this.reconsider_stopped(&enqueue.item).await? {
                    enqueue = next;
                } else {
                    return Err(dead_item_retry_error(&enqueue.item));
                }
            }
            QueueStatus::Dead if budget_renewed(&enqueue.item, config)? => {
                enqueue = this.renew_budget(&enqueue.item.item_id).await?;
            }
            QueueStatus::Dead => {
                let dead_err = dead_item_retry_error(&enqueue.item);
                if let Some(next) = this.continue_chain(&enqueue.item, &dead_err).await? {
                    enqueue = next;
                } else {
                    return Err(exhausted_request_error(
                        queue_id,
                        &enqueue.item,
                        config,
                        &dead_err,
                    ));
                }
            }
            // A finished identical request whose response is not cached (or
            // no cache is configured) runs again: queue records coordinate
            // calls, they do not hold answers.
            QueueStatus::Succeeded => {
                enqueue = this.renew_budget(&enqueue.item.item_id).await?;
            }
            QueueStatus::Pending | QueueStatus::Running | QueueStatus::Failed => {}
        }
    }

    // An attempt that waits for rate budget in slices keeps its start and
    // its throttle time across them, for its receipts.
    let mut waiting_attempt: Option<(std::time::Instant, Duration)> = None;
    loop {
        if let Some(output) = this.recovered::<Res>().await? {
            return Ok(output);
        }
        if let Some(cached) = call_state.cached::<Res>(Some(&enqueue.item)).await? {
            return Ok(cached);
        }
        let (attempt_started, mut attempt_throttle) = waiting_attempt
            .take()
            .unwrap_or_else(|| (std::time::Instant::now(), Duration::ZERO));
        let permit = match &runtime.admission {
            Some(admission) => Some(
                admission
                    .acquire(queue_id, config.max_in_flight.max(1))
                    .await?,
            ),
            None => None,
        };
        let throttle_started = std::time::Instant::now();
        wait_for_model_cooldown(queue.as_ref(), queue_id).await?;
        let rate =
            match check_model_budget(&runtime.rate_state, queue_id, config, &this.request).await? {
                RateCheck::Cleared(rate) => rate,
                RateCheck::Wait(wait) => {
                    // Wait for budget in short slices without holding a model
                    // slot, and look at the item and the cache in between: a
                    // duplicate whose answer arrives returns without spending.
                    drop(permit);
                    tokio::time::sleep(wait.min(RATE_WAIT_SLICE)).await;
                    let slice = throttle_started.elapsed();
                    throttle_wait += slice;
                    waiting_attempt = Some((attempt_started, attempt_throttle + slice));
                    if let Followed::Answer(answer) = this
                        .waiting_on_item(&call_state, &mut enqueue, config)
                        .await?
                    {
                        return Ok(answer);
                    }
                    continue;
                }
            };
        let throttled = throttle_started.elapsed();
        attempt_throttle += throttled;
        throttle_wait += throttled;

        // From its claim on, the attempt runs as a task of its own, holding
        // the model slot. A caller that stops waiting for it does not cancel
        // the provider call or strand the item's lease.
        let attempt = tokio::spawn(run_attempt(
            call_state.clone(),
            enqueue.item.item_id.clone(),
            permit,
            rate,
            provider.clone(),
            call.clone(),
            AttemptClock {
                queued_at,
                attempt_started,
                attempt_throttle,
                throttle_wait,
            },
        ));
        let ended = match attempt.await {
            Ok(ended) => ended?,
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(_err) => {
                return Err(ModelError::Queue(
                    symbiotic_core::DiagnosticCode::QueueFailure,
                ));
            }
        };
        match ended {
            AttemptEnd::Succeeded(response) => return Ok(response),
            AttemptEnd::Retry(Some(next)) => enqueue = *next,
            AttemptEnd::Retry(None) => {}
            // A retention-bounded backend evicted the item after it turned
            // terminal: queue the request again.
            AttemptEnd::Missing => enqueue = this.enqueue().await?,
            AttemptEnd::NotClaimed => match this
                .waiting_on_item(&call_state, &mut enqueue, config)
                .await?
            {
                Followed::Answer(answer) => return Ok(answer),
                Followed::Moved => {}
                Followed::Waiting => tokio::time::sleep(Duration::from_millis(25)).await,
            },
        }
    }
}

/// What a caller that cannot run its item found when it looked again.
#[cfg(feature = "queue")]
enum Followed<Res> {
    /// A finished identical call's cached answer.
    Answer(Res),
    /// `enqueue` now points at a fresh or renewed item: try it at once.
    Moved,
    /// Nothing to do yet (the item may have moved to the next item of its
    /// retry chain): look again shortly.
    Waiting,
}

#[cfg(feature = "queue")]
impl<Req: Send + Sync + 'static> QueuedCall<Req> {
    /// Follow the request's item while this caller cannot run it, and fail
    /// once the request's attempts are used up.
    async fn waiting_on_item<Res>(
        &self,
        call_state: &Arc<Self>,
        enqueue: &mut EnqueueOutcome,
        config: &ModelQueueConfig,
    ) -> Result<Followed<Res>, ModelError>
    where
        Res: Serialize + TraceCarrier + for<'de> Deserialize<'de> + Send + 'static,
    {
        if let Some(output) = self.recovered::<Res>().await? {
            return Ok(Followed::Answer(output));
        }
        let current = self
            .queue
            .get_item(&enqueue.item.item_id)
            .await
            .map_err(queue_error)?;
        let Some(current) = current else {
            *enqueue = self.enqueue().await?;
            return Ok(Followed::Moved);
        };
        if let Some(output) = self.recovered::<Res>().await? {
            return Ok(Followed::Answer(output));
        }
        match current.status {
            QueueStatus::Stopped => Err(dead_item_retry_error(&current)),
            QueueStatus::Dead if budget_renewed(&current, config)? => {
                *enqueue = self.renew_budget(&current.item_id).await?;
                Ok(Followed::Moved)
            }
            QueueStatus::Dead => {
                let dead_err = dead_item_retry_error(&current);
                match self.continue_chain(&current, &dead_err).await? {
                    Some(next) => {
                        *enqueue = next;
                        Ok(Followed::Waiting)
                    }
                    None => Err(exhausted_request_error(
                        &self.queue_id,
                        &current,
                        config,
                        &dead_err,
                    )),
                }
            }
            QueueStatus::Succeeded => {
                if let Some(cached) = call_state.cached::<Res>(Some(&current)).await? {
                    return Ok(Followed::Answer(cached));
                }
                *enqueue = self.renew_budget(&current.item_id).await?;
                Ok(Followed::Moved)
            }
            // Still waiting: the top of the caller's loop checks the cache.
            QueueStatus::Pending | QueueStatus::Running | QueueStatus::Failed => {
                Ok(Followed::Waiting)
            }
        }
    }
}

/// When an attempt started and what it waited for, for its receipts and trace.
#[cfg(feature = "queue")]
struct AttemptClock {
    /// When the call joined the queue.
    queued_at: std::time::Instant,
    /// When this attempt started waiting for a model slot.
    attempt_started: std::time::Instant,
    /// This attempt's cooldown and rate-bucket wait.
    attempt_throttle: Duration,
    /// The call's cooldown and rate-bucket wait over all its attempts.
    throttle_wait: Duration,
}

/// How an attempt ended, as far as its caller's loop is concerned.
#[cfg(feature = "queue")]
enum AttemptEnd<Res> {
    Succeeded(Res),
    /// A retryable failure is recorded. The request's next attempt runs on
    /// this item once its retry time comes (`None`), or on the next item of
    /// its retry chain.
    Retry(Option<Box<EnqueueOutcome>>),
    /// Not claimable now: an identical call holds it, its retry time has not
    /// come, or it has finished.
    NotClaimed,
    /// The backend no longer holds the item.
    Missing,
}

/// One attempt of a queued call, from claiming its item to recording the
/// outcome.
///
/// `run_queued` runs it as a task of its own and awaits it, so the runtime,
/// not the caller, owns the attempt once it holds a lease. A caller that
/// stops waiting (a dropped future, a timeout around the call) does not
/// cancel the provider call: the attempt still records its result or error
/// class, fills the response cache, completes or fails its item and frees
/// the model slot, and identical requests find the outcome through
/// deduplication and the cache. The call is bounded by the policy's
/// `request_timeout_seconds`, not by any caller.
///
/// The lease is renewed from the claim until the item is completed or
/// failed ([`settle`]), so slow receipt, trace, cache or cooldown writes
/// cannot let it expire, and every path after the claim releases it.
#[cfg(feature = "queue")]
async fn run_attempt<P, Req, Res, F, Fut>(
    call_state: Arc<QueuedCall<Req>>,
    item_id: QueueItemId,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    rate: Option<RateGrant>,
    provider: P,
    call: F,
    clock: AttemptClock,
) -> Result<AttemptEnd<Res>, ModelError>
where
    P: ModelProvider + Clone,
    Req: Clone + Send + Sync + 'static,
    Res: Serialize + for<'de> Deserialize<'de> + Clone + TraceCarrier + Send + Sync + 'static,
    F: FnOnce(P, Req) -> Fut,
    Fut: std::future::Future<Output = Result<Res, ModelError>>,
{
    let this = call_state.as_ref();
    let queue = this.queue.as_ref();
    let config = &this.config;
    let worker_id = this.worker_id.as_str();
    let item = match queue
        .claim_item(
            &item_id,
            worker_id,
            config.lease_seconds,
            Some(config.max_in_flight.max(1)),
        )
        .await
    {
        Ok(Some(item)) => item,
        Ok(None) => return Ok(AttemptEnd::NotClaimed),
        Err(symbiotic_queue::QueueError::NotFound(_)) => return Ok(AttemptEnd::Missing),
        Err(err) => return Err(queue_error(err)),
    };
    let reference = this
        .accepted_spend
        .as_ref()
        .map(|h| h.reservation.reference.clone())
        .unwrap_or_else(|| SpendReceiptRef(format!("runtime:{}:{}", item.item_id.0, item.attempt)));
    let ownership_lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let settled = holding_lease(
        queue,
        &item.item_id,
        worker_id,
        config.lease_seconds,
        ownership_lost.clone(),
        async {
            // Another worker may have saved an answer since our last follow.
            if let Some(response) = this.recovered::<Res>().await? {
                let completed = queue.complete(&item.item_id, worker_id).await;
                return Ok(Settled::Succeeded {
                    response,
                    provider_ms: 0,
                    completed,
                });
            }
            let state = call_state.clone();
            let reference_for_reserve = reference.clone();
            let owner = format!("{}:{}", item.item_id.0, item.attempt);
            let reserve = run_blocking(move || {
                if let Some(handoff) = &state.accepted_spend {
                    let identity = handoff_input_identity(
                        &state.kind,
                        state.binding_identity.as_ref(),
                        &state.request_hash,
                    )?;
                    state
                        .spend
                        .acquire_handoff(handoff, &state.queue_id.0, &identity, &owner)?;
                    Ok(true)
                } else {
                    state.spend.reserve(&SpendReservation {
                        reference: reference_for_reserve,
                        account: state.queue_id.0.clone(),
                        invocation: state.invocation.clone(),
                        binding: state.attempt_binding.clone(),
                        request_limit: state.config.provider_request_limit,
                    })
                }
            })
            .await;
            if matches!(reserve, Ok(true))
                && let Some(context) = &this.attempt_context
            {
                context.capture(&reference)?;
            }
            // A blocking reservation can finish after ownership was lost. It
            // must never authorize a provider call under that stale claim.
            let ownership = if ownership_lost.load(std::sync::atomic::Ordering::SeqCst) {
                Err(ModelError::Queue(DiagnosticCode::QueueFailure))
            } else {
                queue
                    .heartbeat(&item.item_id, worker_id, config.lease_seconds)
                    .await
                    .map_err(queue_error)
            };
            if let Err(err) = ownership {
                if matches!(reserve, Ok(true)) {
                    this.release_before_dispatch(&reference).await?;
                }
                return Err(err);
            }
            if !matches!(reserve, Ok(true)) {
                let err = reserve.err().unwrap_or_else(spend::reconciliation);
                queue
                    .fail_with(
                        &item.item_id,
                        worker_id,
                        Failure {
                            error: err.code(),
                            error_class: Some(error_class(&err)),
                            run_after: None,
                        },
                    )
                    .await
                    .map_err(queue_error)?;
                return Err(err);
            }
            // Only an attempt that reaches the provider spends rate budget.
            if let Some(rate) = rate
                && let Err(err) = rate.charge()
            {
                if this.accepted_spend.is_none() {
                    let spend = this.spend.clone();
                    let reference = reference.clone();
                    run_blocking(move || {
                        spend.finish(&reference, SpendState::Released, None, None)
                    })
                    .await?;
                }
                queue
                    .fail(&item.item_id, worker_id, err.code(), None)
                    .await
                    .map_err(queue_error)?;
                return Err(err);
            }
            Ok(settle(
                &call_state,
                &item,
                provider,
                call,
                &clock,
                &reference,
                &ownership_lost,
            )
            .await)
        },
    )
    .await?;
    drop(permit);

    // The item is completed or failed: report what the writes returned, then
    // continue the request's retry chain if the item is dead.
    match settled {
        Settled::Succeeded {
            mut response,
            provider_ms,
            completed,
        } => {
            // The answer is paid for: a failed completion is noted, not
            // returned in its place.
            if let Err(err) = completed {
                note_side_effect(
                    &mut response,
                    &this.queue_id,
                    "queue_complete_failed",
                    err.code(),
                );
            }
            this.receipts
                .record(
                    ReceiptStatus::Succeeded,
                    Some(&item),
                    Some(response.trace()),
                    None,
                    AttemptTiming {
                        queue_wait_ms: None,
                        throttle_wait_ms: None,
                        provider_ms: Some(provider_ms),
                    },
                )
                .await;
            Ok(AttemptEnd::Succeeded(response))
        }
        Settled::Retryable { err, failed } => {
            if failed.map_err(queue_error)? == FailOutcome::RetryScheduled {
                return Ok(AttemptEnd::Retry(None));
            }
            let dead_item = queue
                .get_item(&item.item_id)
                .await
                .map_err(queue_error)?
                .unwrap_or(item);
            if let Some(next) = this.continue_chain(&dead_item, &err).await? {
                return Ok(AttemptEnd::Retry(Some(Box::new(next))));
            }
            this.trace_failure(Some(dead_item.item_id.clone()), &err)
                .await;
            Err(exhausted_request_error(
                &this.queue_id,
                &dead_item,
                config,
                &err,
            ))
        }
        Settled::Failed { err, failed } => {
            failed.map_err(queue_error)?;
            this.trace_failure(Some(item.item_id), &err).await;
            Err(err)
        }
    }
}

/// How the leased part of an attempt ended: the item is completed or failed,
/// with the result of that queue write.
#[cfg(feature = "queue")]
enum Settled<Res> {
    Succeeded {
        response: Res,
        provider_ms: u64,
        completed: Result<(), symbiotic_queue::QueueError>,
    },

    Retryable {
        err: ModelError,
        failed: Result<FailOutcome, symbiotic_queue::QueueError>,
    },
    Failed {
        err: ModelError,
        failed: Result<FailOutcome, symbiotic_queue::QueueError>,
    },
}

/// The leased part of an attempt: the running receipt, the provider call,
/// and recording its outcome up to completing or failing the item. Every
/// path ends with `complete` or `fail_with`, whatever the writes before it
/// returned. It shares its task with the lease renewal, so it never blocks
/// the thread: response-cache work runs on the blocking pool.
#[cfg(feature = "queue")]
async fn settle<P, Req, Res, F, Fut>(
    this: &Arc<QueuedCall<Req>>,
    item: &QueueItem,
    provider: P,
    call: F,
    clock: &AttemptClock,
    reference: &SpendReceiptRef,
    ownership_lost: &std::sync::atomic::AtomicBool,
) -> Settled<Res>
where
    P: ModelProvider + Clone,
    Req: Clone + Send + Sync + 'static,
    Res: Serialize + for<'de> Deserialize<'de> + Clone + TraceCarrier + Send + Sync + 'static,
    F: FnOnce(P, Req) -> Fut,
    Fut: std::future::Future<Output = Result<Res, ModelError>>,
{
    let queue = this.queue.as_ref();
    let config = &this.config;
    let worker_id = this.worker_id.as_str();
    // Queue wait of this attempt: admission plus claim, without throttle.
    let attempt_throttle_ms = u64::try_from(clock.attempt_throttle.as_millis()).unwrap_or(u64::MAX);
    let attempt_queue_wait_ms =
        elapsed_ms(clock.attempt_started).saturating_sub(attempt_throttle_ms);
    this.receipts
        .record(
            ReceiptStatus::Running,
            Some(item),
            None,
            None,
            AttemptTiming {
                queue_wait_ms: Some(attempt_queue_wait_ms),
                throttle_wait_ms: Some(attempt_throttle_ms),
                provider_ms: None,
            },
        )
        .await;
    // Running telemetry may itself await. Validate ownership once more at
    // the actual transport boundary; after dispatch retain its outcome.
    if ownership_lost.load(std::sync::atomic::Ordering::SeqCst) {
        let err = this
            .release_before_dispatch(reference)
            .await
            .err()
            .unwrap_or(ModelError::Queue(DiagnosticCode::QueueFailure));
        return Settled::Failed {
            err,
            failed: Ok(FailOutcome::Stopped),
        };
    }
    if let Err(err) = queue
        .heartbeat(&item.item_id, worker_id, config.lease_seconds)
        .await
    {
        let err = this
            .release_before_dispatch(reference)
            .await
            .err()
            .unwrap_or_else(|| queue_error(err));
        return Settled::Failed {
            err,
            failed: Ok(FailOutcome::Stopped),
        };
    }
    let provider_started = std::time::Instant::now();
    let result = within_timeout(
        &this.queue_id,
        config.request_timeout_seconds,
        call(provider.clone(), this.request.clone()),
    )
    .await;
    let result = secrets::composed_result(&provider, result);
    let provider_ms = elapsed_ms(provider_started);
    let failed_timing = || AttemptTiming {
        queue_wait_ms: None,
        throttle_wait_ms: None,
        provider_ms: Some(provider_ms),
    };

    let known_zero = result.as_ref().err().is_some_and(|err| {
        !matches!(err, ModelError::Timeout(_))
            && provider.failure_charge(err) == FailureCharge::KnownZero
    });
    let released = if known_zero && this.accepted_spend.is_none() {
        let spend = this.spend.clone();
        let reference = reference.clone();
        run_blocking(move || spend.finish(&reference, SpendState::Released, None, None)).await
    } else {
        Ok(())
    };
    if let Err(err) = released {
        let failed = queue
            .fail_with(
                &item.item_id,
                worker_id,
                Failure {
                    error: err.code(),
                    error_class: Some(error_class(&err)),
                    run_after: None,
                },
            )
            .await;
        return Settled::Failed { err, failed };
    }
    match result {
        Ok(mut response) => {
            let mut trace = response.trace().clone();
            trace.queue_item_id = Some(item.item_id.clone());
            trace.request_hash = this.request_hash.clone();
            let queued_ms = provider_started.duration_since(clock.queued_at).as_millis() as u64;
            let throttle_wait_ms = clock.throttle_wait.as_millis() as u64;
            trace.timing.queued_ms = Some(queued_ms);
            trace.timing.queue_wait_ms = Some(queued_ms.saturating_sub(throttle_wait_ms));
            trace.timing.throttle_wait_ms = Some(throttle_wait_ms);
            trace.timing.provider_ms = Some(provider_ms);
            trace.timing.total_ms = Some(clock.queued_at.elapsed().as_millis() as u64);
            if !trace.metadata.is_object() {
                trace.metadata = serde_json::json!({"value": trace.metadata});
            }
            trace.metadata["spend_receipt"] = serde_json::json!(reference);
            response.set_trace(trace);
            if this.accepted_spend.is_none() {
                let usage = response.trace().usage.clone();
                let state = if has_measured_usage(&usage) {
                    SpendState::Settled
                } else {
                    SpendState::Unknown
                };
                let response_to_save = response.clone();
                let spend = this.spend.clone();
                let reference = reference.clone();
                let saved = run_blocking(move || {
                    let output =
                        serde_json::to_value(&response_to_save).map_err(|_| spend::storage())?;
                    spend.finish(
                        &reference,
                        state,
                        if has_measured_usage(&usage) {
                            Some(usage)
                        } else {
                            None
                        },
                        Some(output),
                    )
                })
                .await;
                if let Err(err) = saved {
                    note_side_effect(
                        &mut response,
                        &this.queue_id,
                        "spend_settlement_failed",
                        err.code(),
                    );
                }
            }
            let response = this.record_success(response).await;
            let completed = queue.complete(&item.item_id, worker_id).await;
            Settled::Succeeded {
                response,
                provider_ms,
                completed,
            }
        }
        Err(err) if known_zero && is_retryable(&err, config) => {
            this.receipts
                .record(
                    ReceiptStatus::Failed,
                    Some(item),
                    None,
                    Some(err.code()),
                    failed_timing(),
                )
                .await;
            let delay_ms = match retry_delay_ms(
                item.attempt,
                config,
                &item.item_id,
                &this.request_hash,
                &err,
            ) {
                Ok(delay) => delay,
                Err(err) => {
                    let failed = queue
                        .fail_with(
                            &item.item_id,
                            worker_id,
                            Failure {
                                error: err.code(),
                                error_class: Some(error_class(&err)),
                                run_after: None,
                            },
                        )
                        .await;
                    return Settled::Failed { err, failed };
                }
            };
            // Failed limiter state refuses visibly and cannot admit a retry.
            if is_transient(&err)
                && let Err(cooldown_err) =
                    note_model_cooldown(queue, &this.queue_id, &err, delay_ms).await
            {
                let failed = queue
                    .fail_with(
                        &item.item_id,
                        worker_id,
                        Failure {
                            error: cooldown_err.code(),
                            error_class: Some(symbiotic_core::FailureClass::Queue),
                            run_after: None,
                        },
                    )
                    .await;
                return Settled::Failed {
                    err: cooldown_err,
                    failed,
                };
            }
            // One exact deadline, kept by the backend: this caller and any
            // duplicate waiting on the item retry no earlier than it.
            let failed = queue
                .fail_with(
                    &item.item_id,
                    worker_id,
                    Failure {
                        error: err.code(),
                        error_class: Some(error_class(&err)),
                        run_after: Some(Utc::now() + ChronoDuration::milliseconds(delay_ms as i64)),
                    },
                )
                .await;
            Settled::Retryable { err, failed }
        }
        Err(err) => {
            if is_transient(&err)
                && let Err(failure) =
                    note_model_cooldown(queue, &this.queue_id, &err, config.retry_base_delay_ms)
                        .await
            {
                let failed = queue
                    .fail_with(
                        &item.item_id,
                        worker_id,
                        Failure {
                            error: failure.code(),
                            error_class: Some(FailureClass::Queue),
                            run_after: None,
                        },
                    )
                    .await;
                return Settled::Failed {
                    err: failure,
                    failed,
                };
            }
            this.receipts
                .record(
                    ReceiptStatus::Failed,
                    Some(item),
                    None,
                    Some(err.code()),
                    failed_timing(),
                )
                .await;
            let failed = queue
                .fail_with(
                    &item.item_id,
                    worker_id,
                    Failure {
                        error: if known_zero {
                            err.code()
                        } else {
                            DiagnosticCode::SpendReconciliationRequired
                        },
                        error_class: Some(if known_zero {
                            error_class(&err)
                        } else {
                            FailureClass::Queue
                        }),
                        run_after: None,
                    },
                )
                .await;
            Settled::Failed { err, failed }
        }
    }
}

/// `call`, failed as a timeout once `timeout_seconds` have passed.
#[cfg(feature = "queue")]
async fn within_timeout<T>(
    _queue_id: &QueueId,
    timeout_seconds: Option<u64>,
    call: impl std::future::Future<Output = Result<T, ModelError>>,
) -> Result<T, ModelError> {
    let Some(timeout) = timeout_seconds else {
        return call.await;
    };
    tokio::time::timeout(Duration::from_secs(timeout), call)
        .await
        .unwrap_or_else(|_| {
            Err(ModelError::Timeout(
                symbiotic_core::DiagnosticCode::HttpTimeout,
            ))
        })
}

/// Run `work` while renewing its item's lease every third of the lease.
///
/// The renewal is part of this future, not a task of its own, so it cannot
/// outlive `work`: it ends when `work` does, or earlier once a renewal fails
/// because the lease was lost.
#[cfg(feature = "queue")]
async fn holding_lease<T>(
    queue: &dyn QueueBackend,
    item_id: &QueueItemId,
    worker_id: &str,
    lease_seconds: u64,
    ownership_lost: Arc<std::sync::atomic::AtomicBool>,
    work: impl std::future::Future<Output = T>,
) -> T {
    let renew = async {
        let interval =
            Duration::from_millis((lease_seconds.saturating_mul(1000) / 3).clamp(1, 60_000));
        loop {
            tokio::time::sleep(interval).await;
            if queue
                .heartbeat(item_id, worker_id, lease_seconds)
                .await
                .is_err()
            {
                ownership_lost.store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            }
        }
    };
    let mut work = std::pin::pin!(work);
    tokio::select! {
        biased;
        output = &mut work => output,
        () = renew => work.await,
    }
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

#[cfg(feature = "queue")]
fn is_transient(err: &ModelError) -> bool {
    matches!(
        err,
        ModelError::Unavailable(_) | ModelError::RateLimited(_) | ModelError::Timeout(_)
    )
}

#[cfg(feature = "queue")]
fn is_retryable(err: &ModelError, config: &ModelQueueConfig) -> bool {
    is_transient(err) || (config.retry_provider_errors && matches!(err, ModelError::Provider(_)))
}

/// Backoff before jitter: the base delay doubling per attempt up to 32x,
/// capped at 30 s (or at the base, if that is longer).
#[cfg(feature = "queue")]
fn retry_backoff_ms(attempt: u32, base_ms: u64) -> u64 {
    let base_ms = base_ms.max(1);
    base_ms
        .saturating_mul(2u64.saturating_pow(attempt.saturating_sub(1).min(5)))
        .min(30_000.max(base_ms))
}

/// Delay before the next attempt: backoff plus deterministic jitter, at most
/// two minutes.
#[cfg(feature = "queue")]
fn retry_delay_ms(
    attempt: u32,
    config: &ModelQueueConfig,
    item_id: &QueueItemId,
    request_hash: &str,
    err: &ModelError,
) -> Result<u64, ModelError> {
    Ok(retry_backoff_ms(attempt, config.retry_base_delay_ms)
        .saturating_add(
            retry_jitter_seconds(
                config.retry_jitter_seconds,
                item_id,
                request_hash,
                attempt,
                err,
            )?
            .saturating_mul(1_000),
        )
        .clamp(1, 120_000))
}

#[cfg(test)]
#[cfg(feature = "queue")]
fn retry_after_seconds(
    attempt: u32,
    max_jitter_seconds: u64,
    item_id: &QueueItemId,
    request_hash: &str,
    err: &ModelError,
) -> u64 {
    let config = ModelQueueConfig {
        retry_jitter_seconds: max_jitter_seconds,
        ..ModelQueueConfig::default()
    };
    retry_delay_ms(attempt, &config, item_id, request_hash, err)
        .unwrap()
        .div_ceil(1_000)
}

#[cfg(feature = "queue")]
fn retry_jitter_seconds(
    max_jitter_seconds: u64,
    item_id: &QueueItemId,
    request_hash: &str,
    attempt: u32,
    err: &ModelError,
) -> Result<u64, ModelError> {
    if max_jitter_seconds == 0 {
        return Ok(0);
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
    let range = max_jitter_seconds
        .checked_add(1)
        .ok_or(ModelError::InvalidRequest(
            symbiotic_core::DiagnosticCode::InvalidConfiguration,
        ))?;
    Ok(u64::from_le_bytes(bytes) % range)
}

/// Whether a request another call exhausted (or that was exhausted before a
/// restart) gets a fresh attempt budget: only when the policy renews budgets
/// and the renewal time has passed since the request went dead.
#[cfg(feature = "queue")]
fn budget_renewed(item: &QueueItem, config: &ModelQueueConfig) -> Result<bool, ModelError> {
    let Some(seconds) = config.budget_renewal_seconds else {
        return Ok(false);
    };
    let deadline = i64::try_from(seconds)
        .ok()
        .and_then(ChronoDuration::try_seconds)
        .and_then(|duration| item.updated_at.checked_add_signed(duration))
        .ok_or(ModelError::InvalidRequest(
            symbiotic_core::DiagnosticCode::InvalidConfiguration,
        ))?;
    Ok(Utc::now() >= deadline)
}

#[cfg(feature = "queue")]
/// The request's total provider attempts, across every queue item of its
/// retry chain.
fn logical_max_attempts(config: &ModelQueueConfig) -> u32 {
    config.logical_retry_attempts.max(1)
}

/// Provider attempts of one queue item: `retry_attempts`, never more than
/// the request's total.
#[cfg(feature = "queue")]
fn item_max_attempts(config: &ModelQueueConfig) -> u32 {
    config
        .retry_attempts
        .min(logical_max_attempts(config))
        .max(1)
}

/// Stable class name of an error, kept on failed queue items so a later
/// call reports the same class.
#[cfg(feature = "queue")]
fn error_class(err: &ModelError) -> FailureClass {
    match err {
        ModelError::Unavailable(_) => FailureClass::Unavailable,
        ModelError::Auth(_) => FailureClass::Auth,
        ModelError::RateLimited(_) => FailureClass::RateLimited,
        ModelError::BudgetExhausted(_) => FailureClass::BudgetExhausted,
        ModelError::Timeout(_) => FailureClass::Timeout,
        ModelError::InvalidRequest(_) => FailureClass::InvalidRequest,
        ModelError::Provider(_) => FailureClass::Provider,
        ModelError::Queue(_) => FailureClass::Queue,
        ModelError::Cache(_) => FailureClass::Cache,
        ModelError::Unsupported(ModelCapability::Chat) => FailureClass::UnsupportedChat,
        ModelError::Unsupported(ModelCapability::Embedding) => FailureClass::UnsupportedEmbedding,
        ModelError::Unsupported(ModelCapability::Rerank) => FailureClass::UnsupportedRerank,
        ModelError::Unsupported(ModelCapability::Classify) => FailureClass::UnsupportedClassify,
        ModelError::Unsupported(ModelCapability::Vision) => FailureClass::UnsupportedVision,
        ModelError::Unsupported(ModelCapability::ImageGeneration) => {
            FailureClass::UnsupportedImageGeneration
        }
        ModelError::Unsupported(ModelCapability::VideoGeneration) => {
            FailureClass::UnsupportedVideoGeneration
        }
        ModelError::Unsupported(ModelCapability::AgentTask) => FailureClass::UnsupportedAgentTask,
    }
}

/// Restore only typed persisted class/code, never provider or stored text.
#[cfg(feature = "queue")]
fn dead_item_retry_error(item: &QueueItem) -> ModelError {
    let code = item.last_error.unwrap_or(DiagnosticCode::QueueFailure);
    match item.last_error_class {
        Some(FailureClass::Unavailable) => ModelError::Unavailable(code),
        Some(FailureClass::Auth) => ModelError::Auth(code),
        Some(FailureClass::RateLimited) => ModelError::RateLimited(code),
        Some(FailureClass::BudgetExhausted) => ModelError::BudgetExhausted(code),
        Some(FailureClass::Timeout) => ModelError::Timeout(code),
        Some(FailureClass::InvalidRequest) => ModelError::InvalidRequest(code),
        Some(FailureClass::Provider) => ModelError::Provider(code),
        Some(FailureClass::Queue) => ModelError::Queue(code),
        Some(FailureClass::Cache) => ModelError::Cache(code),
        Some(FailureClass::UnsupportedChat) => ModelError::Unsupported(ModelCapability::Chat),
        Some(FailureClass::UnsupportedEmbedding) => {
            ModelError::Unsupported(ModelCapability::Embedding)
        }
        Some(FailureClass::UnsupportedRerank) => ModelError::Unsupported(ModelCapability::Rerank),
        Some(FailureClass::UnsupportedClassify) => {
            ModelError::Unsupported(ModelCapability::Classify)
        }
        Some(FailureClass::UnsupportedVision) => ModelError::Unsupported(ModelCapability::Vision),
        Some(FailureClass::UnsupportedImageGeneration) => {
            ModelError::Unsupported(ModelCapability::ImageGeneration)
        }
        Some(FailureClass::UnsupportedVideoGeneration) => {
            ModelError::Unsupported(ModelCapability::VideoGeneration)
        }
        Some(FailureClass::UnsupportedAgentTask) => {
            ModelError::Unsupported(ModelCapability::AgentTask)
        }
        None => ModelError::Queue(DiagnosticCode::TerminalQueueItemIsMissingItsErrorClass),
    }
}

#[cfg(feature = "queue")]
#[derive(Clone, Copy, Debug)]
struct LogicalRetryState {
    attempts_used: u32,
    max_attempts: u32,
}

#[cfg(feature = "queue")]
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
        "binding": descriptor.metadata.get("binding"),
        "logical_retry": {
            "attempts_used": retry_state.attempts_used,
            "max_attempts": retry_state.max_attempts,
        },
    })
}

#[cfg(feature = "queue")]
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

// Retry bookkeeping follows the same execution boundary rather than another state type.
#[cfg(feature = "queue")]
#[allow(clippy::too_many_arguments)]
async fn reenqueue_dead_item(
    queue: &dyn QueueBackend,
    queue_id: &QueueId,
    descriptor: &ProviderDescriptor,
    capability: ModelCapability,
    kind: &str,
    request_hash: &str,
    idempotency_key: &Option<String>,
    item: &QueueItem,
    config: &ModelQueueConfig,
    err: &ModelError,
) -> Result<Option<EnqueueOutcome>, ModelError> {
    let state = logical_retry_state(&item.payload, logical_max_attempts(config));
    let attempts_used = state.attempts_used.saturating_add(item.attempt);
    if item.status == QueueStatus::Stopped || attempts_used >= state.max_attempts {
        return Ok(None);
    }
    let remaining_attempts = state.max_attempts - attempts_used;
    let next_state = LogicalRetryState {
        attempts_used,
        max_attempts: state.max_attempts,
    };
    let payload = model_queue_payload(&capability, request_hash, descriptor, next_state);
    let retry_after_ms = retry_delay_ms(item.attempt, config, &item.item_id, request_hash, err)?;
    // Replace the dead item only while it is still the newest for the
    // request: a caller holding a stale item must not start a second chain.
    let outcome = queue
        .enqueue_replacing(
            EnqueueRequest {
                queue_id: queue_id.clone(),
                kind: kind.to_string(),
                payload,
                idempotency_key: idempotency_key.clone(),
                run_after: Some(Utc::now() + ChronoDuration::milliseconds(retry_after_ms as i64)),
                max_attempts: Some(remaining_attempts.min(config.retry_attempts.max(1)).max(1)),
                force: true,
            },
            &item.item_id,
        )
        .await
        .map_err(|_err| ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure))?;
    Ok(Some(outcome))
}

// Same execution boundary as `reenqueue_dead_item`.
#[cfg(feature = "queue")]
#[allow(clippy::too_many_arguments)]
async fn reenqueue_with_fresh_budget(
    queue: &dyn QueueBackend,
    queue_id: &QueueId,
    descriptor: &ProviderDescriptor,
    capability: ModelCapability,
    kind: &str,
    request_hash: &str,
    idempotency_key: &Option<String>,
    config: &ModelQueueConfig,
    current: &QueueItemId,
) -> Result<EnqueueOutcome, ModelError> {
    let payload = model_queue_payload(
        &capability,
        request_hash,
        descriptor,
        LogicalRetryState {
            attempts_used: 0,
            max_attempts: logical_max_attempts(config),
        },
    );
    // Conditional on `current` still being the newest item, so a delayed
    // caller cannot renew over a budget another caller renewed meanwhile.
    queue
        .enqueue_replacing(
            EnqueueRequest {
                queue_id: queue_id.clone(),
                kind: kind.to_string(),
                payload,
                idempotency_key: idempotency_key.clone(),
                run_after: None,
                max_attempts: Some(item_max_attempts(config)),
                force: true,
            },
            current,
        )
        .await
        .map_err(|_err| ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure))
}

#[cfg(feature = "queue")]
fn exhausted_request_error(
    _queue_id: &QueueId,
    _item: &QueueItem,
    _config: &ModelQueueConfig,
    last_error: &ModelError,
) -> ModelError {
    match last_error {
        ModelError::RateLimited(_) => {
            ModelError::RateLimited(DiagnosticCode::AttemptBudgetExhausted)
        }
        ModelError::Timeout(_) => ModelError::Timeout(DiagnosticCode::AttemptBudgetExhausted),
        ModelError::Unavailable(_) => {
            ModelError::Unavailable(DiagnosticCode::AttemptBudgetExhausted)
        }
        ModelError::Auth(_) => ModelError::Auth(DiagnosticCode::AttemptBudgetExhausted),
        ModelError::BudgetExhausted(_) => {
            ModelError::BudgetExhausted(DiagnosticCode::AttemptBudgetExhausted)
        }
        ModelError::InvalidRequest(_) => {
            ModelError::InvalidRequest(DiagnosticCode::AttemptBudgetExhausted)
        }
        ModelError::Queue(_) => ModelError::Queue(DiagnosticCode::AttemptBudgetExhausted),
        ModelError::Cache(_) => ModelError::Cache(DiagnosticCode::AttemptBudgetExhausted),
        ModelError::Provider(_) => ModelError::Provider(DiagnosticCode::AttemptBudgetExhausted),
        ModelError::Unsupported(capability) => ModelError::Unsupported(*capability),
    }
}

#[cfg(feature = "queue")]
type RateGates = HashMap<String, Arc<tokio::sync::Mutex<()>>>;

/// Rate state owned by a runtime and shared only through its account keys.
#[cfg(feature = "queue")]
#[derive(Clone, Default)]
pub struct ModelRateState {
    buckets: Arc<Mutex<HashMap<String, RateBucket>>>,
    gates: Arc<Mutex<RateGates>>,
}

#[cfg(feature = "queue")]
trait BudgetedModelRequest {
    fn input_budget_units(&self) -> Result<u64, ModelError>;
    fn sensitivity(&self) -> Sensitivity;
}

#[cfg(feature = "queue")]
impl BudgetedModelRequest for ChatRequest {
    fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
    fn input_budget_units(&self) -> Result<u64, ModelError> {
        Ok(estimate_token_budget_units(
            self.messages.iter().map(|message| message.content.as_str()),
        ))
    }
}

#[cfg(feature = "queue")]
impl BudgetedModelRequest for EmbeddingRequest {
    fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
    fn input_budget_units(&self) -> Result<u64, ModelError> {
        Ok(estimate_token_budget_units(
            self.inputs.iter().map(String::as_str),
        ))
    }
}

#[cfg(feature = "queue")]
impl BudgetedModelRequest for RerankRequest {
    fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
    fn input_budget_units(&self) -> Result<u64, ModelError> {
        Ok(estimate_token_budget_units(
            std::iter::once(self.query.as_str()).chain(self.documents.iter().map(String::as_str)),
        ))
    }
}

#[cfg(feature = "queue")]
fn estimate_token_budget_units<'a>(parts: impl IntoIterator<Item = &'a str>) -> u64 {
    parts
        .into_iter()
        .map(|part| (part.chars().count() as u64).div_ceil(4))
        .sum::<u64>()
        .max(1)
}

#[cfg(feature = "queue")]
#[derive(Clone, Debug)]
struct RateBucket {
    tokens: f64,
    capacity: f64,
    rate_per_second: f64,
    updated_at: Instant,
}

#[cfg(feature = "queue")]
impl RateBucket {
    #[cfg(test)]
    fn new(per_minute: f64) -> Self {
        Self::with_burst(per_minute, 0)
    }

    /// A bucket that starts full with `burst_seconds` of budget (at least
    /// one unit), so an idle queue may spend that much at once.
    fn with_burst(per_minute: f64, burst_seconds: u64) -> Self {
        let rate_per_second = (per_minute / 60.0).max(0.000_001);
        let capacity = (rate_per_second * burst_seconds as f64).max(1.0);
        Self {
            tokens: capacity,
            capacity,
            rate_per_second,
            updated_at: Instant::now(),
        }
    }

    /// Add the budget earned since the last update. A request larger than
    /// the bucket raises its capacity, so it can still run once full.
    fn refill(&mut self, amount: f64) {
        if self.capacity < amount {
            self.capacity = amount;
        }
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.updated_at);
        self.updated_at = now;
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() * self.rate_per_second).min(self.capacity);
    }

    /// How long until `amount` is available. Spends nothing.
    fn wait_for(&mut self, amount: f64) -> Option<Duration> {
        let amount = amount.max(1.0);
        self.refill(amount);
        (self.tokens < amount)
            .then(|| Duration::from_secs_f64((amount - self.tokens) / self.rate_per_second))
    }

    fn charge(&mut self, amount: f64) {
        let amount = amount.max(1.0);
        self.refill(amount);
        self.tokens -= amount;
    }
}

/// One rate bucket an attempt draws on.
#[cfg(feature = "queue")]
struct RateCharge {
    /// Keyed by policy too: providers of one model with the same limits
    /// share a bucket; a different policy gets its own.
    key: String,
    per_minute: f64,
    amount: f64,
}

/// Rate budget cleared for one attempt that is about to claim its item.
///
/// It holds the queue's rate gate from the budget check through the claim,
/// so no other caller is cleared for the same budget meanwhile.
/// [`RateGrant::charge`] spends it once the claim succeeded, just before
/// the provider call. Dropping it, because the item was not claimable (a
/// duplicate holds it, or its retry time has not come), spends nothing.
#[cfg(feature = "queue")]
struct RateGrant {
    state: ModelRateState,
    _gate: tokio::sync::OwnedMutexGuard<()>,
    charges: Vec<RateCharge>,
}

#[cfg(feature = "queue")]
impl RateGrant {
    fn charge(self) -> Result<(), ModelError> {
        let mut buckets = self.state.buckets.lock().map_err(|_| {
            ModelError::Queue(symbiotic_core::DiagnosticCode::RateBucketLockPoisoned)
        })?;
        for charge in &self.charges {
            buckets
                .get_mut(&charge.key)
                .ok_or({
                    ModelError::Queue(symbiotic_core::DiagnosticCode::RateBucketDisappeared)
                })?
                .charge(charge.amount);
        }
        Ok(())
    }
}

/// Whether the queue's rate limits allow one more attempt of `request` now.
#[cfg(feature = "queue")]
enum RateCheck {
    /// Go ahead. The grant (`None` when the policy sets no rate limit) is
    /// spent on a successful claim.
    Cleared(Option<RateGrant>),
    /// Not enough budget for this long. Nothing was spent.
    Wait(Duration),
}

/// Check the queue's rate limits for one more attempt of `request`, without
/// spending anything; a cleared attempt spends its grant on a successful
/// claim.
#[cfg(feature = "queue")]
async fn check_model_budget<R>(
    state: &ModelRateState,
    queue_id: &QueueId,
    config: &ModelQueueConfig,
    request: &R,
) -> Result<RateCheck, ModelError>
where
    R: BudgetedModelRequest,
{
    let mut charges = Vec::new();
    if let Some(requests_per_minute) = config.requests_per_minute {
        charges.push(RateCharge {
            key: format!(
                "{}:requests:{requests_per_minute}:{}",
                queue_id.0, config.rate_burst_seconds
            ),
            per_minute: requests_per_minute as f64,
            amount: 1.0,
        });
    }
    if let Some(input_units_per_minute) = config.input_units_per_minute {
        charges.push(RateCharge {
            key: format!(
                "{}:input-units:{input_units_per_minute}:{}",
                queue_id.0, config.rate_burst_seconds
            ),
            per_minute: input_units_per_minute as f64,
            amount: request.input_budget_units()? as f64,
        });
    }
    if charges.is_empty() {
        return Ok(RateCheck::Cleared(None));
    }
    let gate = {
        let mut gates = state
            .gates
            .lock()
            .map_err(|_| ModelError::Queue(symbiotic_core::DiagnosticCode::RateGateLockPoisoned))?;
        gates.entry(queue_id.0.clone()).or_default().clone()
    };
    let held = gate.lock_owned().await;
    let wait = {
        let mut buckets = state
            .buckets
            .lock()
            .map_err(|_| ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure))?;
        charges
            .iter()
            .filter_map(|charge| {
                buckets
                    .entry(charge.key.clone())
                    .or_insert_with(|| {
                        RateBucket::with_burst(charge.per_minute, config.rate_burst_seconds)
                    })
                    .wait_for(charge.amount)
            })
            .max()
    };
    Ok(match wait {
        None => RateCheck::Cleared(Some(RateGrant {
            state: state.clone(),
            _gate: held,
            charges,
        })),
        Some(wait) => RateCheck::Wait(wait),
    })
}

/// Longest sleep of a caller waiting for rate budget before it looks again
/// at its item and the cache: a duplicate's answer may have arrived.
#[cfg(feature = "queue")]
const RATE_WAIT_SLICE: Duration = Duration::from_millis(250);

#[cfg(feature = "queue")]
async fn wait_for_model_cooldown(
    queue: &dyn QueueBackend,
    queue_id: &QueueId,
) -> Result<(), ModelError> {
    loop {
        let durable_until = queue.cooldown_until(queue_id).await.map_err(queue_error)?;
        let sleep_for = durable_until.and_then(|until| (until - Utc::now()).to_std().ok());
        match sleep_for {
            Some(duration) if !duration.is_zero() => tokio::time::sleep(duration).await,
            _ => return Ok(()),
        }
    }
}

#[cfg(feature = "queue")]
async fn note_model_cooldown(
    queue: &dyn QueueBackend,
    queue_id: &QueueId,
    err: &ModelError,
    retry_delay_ms: u64,
) -> Result<(), ModelError> {
    let multiplier = match err {
        ModelError::RateLimited(_) => 4,
        ModelError::Unavailable(_) => 2,
        ModelError::Timeout(_) => 1,
        _ => 1,
    };
    let millis = retry_delay_ms.saturating_mul(multiplier).clamp(1, 60_000);
    let until_utc = Utc::now() + ChronoDuration::milliseconds(millis as i64);
    queue
        .note_cooldown(queue_id, until_utc)
        .await
        .map_err(|_err| ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure))?;
    Ok(())
}

/// Opaque revision of a serializable configuration. Never pass secret values.
pub fn configuration_revision(
    settings: &impl Serialize,
) -> Result<symbiotic_core::ConfigurationRevision, ModelError> {
    hash_json(settings).map(symbiotic_core::ConfigurationRevision)
}

fn hash_json<T: Serialize>(value: &T) -> Result<String, ModelError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_err| ModelError::Provider(symbiotic_core::DiagnosticCode::ProviderFailure))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
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
    client: HttpClient,
    base_url: String,
    api_key: CredentialBoundary,
    max_response_bytes: Option<usize>,
    max_request_bytes: Option<usize>,
    thinking: Option<ThinkingMode>,
    reasoning_effort: Option<String>,
    max_output_tokens: Option<u32>,
}

/// Provider extension supported by compatible APIs such as DeepSeek.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThinkingMode {
    /// Enable provider thinking.
    Enabled,
    /// Disable provider thinking; reasoning effort is refused.
    Disabled,
}

/// Refuse settings that would otherwise be silently omitted from the wire.
fn validate_chat_settings(
    thinking: Option<ThinkingMode>,
    effort: Option<&str>,
) -> Result<(), ModelError> {
    if effort.is_some_and(|s| s.trim().is_empty())
        || (thinking == Some(ThinkingMode::Disabled) && effort.is_some())
    {
        return Err(ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::UnsupportedChatSettingsReasoningEffortRequiresThinkingAndMustBeNonempty));
    }
    Ok(())
}

impl OpenAiCompatibleChatProvider {
    /// Construct a compatible chat transport; finite byte and output limits are required to execute.
    pub fn new(
        operator: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        api_key: impl Into<SecretValue<String>>,
    ) -> Self {
        let operator = operator.into();
        let model = model.into();
        let base_url = base_url.into();
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
                metadata: serde_json::json!({ "wire": "openai-compatible", "endpoint": registry::validate_endpoint(&base_url).ok().map(|()| base_url.as_str()) }),
            },
            client: HttpClient::default(),
            base_url,
            api_key: CredentialBoundary::new(api_key.into()),
            max_response_bytes: None,
            max_request_bytes: None,
            thinking: None,
            reasoning_effort: None,
            max_output_tokens: None,
        }
    }

    /// Clients cannot be injected through the public API.
    /// ```compile_fail
    /// use symbiotic_model::OpenAiCompatibleChatProvider;
    /// OpenAiCompatibleChatProvider::new("op", "model", "http://localhost", "key")
    ///     .with_client(reqwest::Client::new());
    /// ```
    /// Set a finite timeout on a Foundation-owned redirect-free, direct client.
    pub fn with_timeout(mut self, timeout_seconds: u64) -> Result<Self, ModelError> {
        self.client = HttpClient(Ok(http_client(Some(timeout_seconds))?));
        Ok(self)
    }

    /// Bound the complete encoded HTTP request body before transmission.
    pub fn with_request_limit(mut self, max_bytes: usize) -> Self {
        self.descriptor.metadata["max_request_bytes"] = serde_json::json!(max_bytes);
        self.max_request_bytes = Some(max_bytes);
        self
    }

    /// Bound response bodies before buffering, including provider error bodies.
    pub fn with_response_limit(mut self, max_bytes: usize) -> Self {
        self.descriptor.metadata["max_response_bytes"] = serde_json::json!(max_bytes);
        self.max_response_bytes = Some(max_bytes);
        self
    }

    /// Configured output-token ceiling; requests above it are refused.
    pub fn with_output_limit(mut self, max_tokens: u32) -> Self {
        self.descriptor.metadata["max_output_tokens"] = serde_json::json!(max_tokens);
        self.max_output_tokens = Some(max_tokens);
        self
    }

    /// Configure thinking; combining disabled thinking with effort is refused.
    pub fn with_thinking(mut self, thinking: Option<ThinkingMode>) -> Self {
        self.descriptor.metadata["thinking"] =
            serde_json::to_value(thinking).expect("thinking serializes");
        self.thinking = thinking;
        self
    }

    /// Configure a nonempty reasoning effort; invalid settings are refused on binding or execution.
    pub fn with_reasoning_effort(mut self, effort: impl Into<String>) -> Self {
        let effort = effort.into();
        self.descriptor.metadata["reasoning_effort"] = Value::String(effort.clone());
        self.reasoning_effort = Some(effort);
        self
    }
}

#[async_trait]
impl ModelProvider for OpenAiCompatibleChatProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }

    fn validate_configuration(&self) -> Result<(), ModelError> {
        registry::validate_endpoint(&self.base_url)?;
        self.client.get()?;
        required_byte_limit(self.max_request_bytes)?;
        required_byte_limit(self.max_response_bytes)?;
        if self.max_output_tokens == Some(0) {
            return Err(ModelError::InvalidRequest(
                symbiotic_core::DiagnosticCode::OutputTokenLimitMustBeNonzero,
            ));
        }
        validate_chat_settings(self.thinking, self.reasoning_effort.as_deref())
    }

    fn credential_fingerprint(&self) -> Option<String> {
        api_key_fingerprint(self.api_key.secret())
    }

    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        Some(&self.api_key)
    }
}

#[derive(Deserialize)]
struct OpenAiChatWireResponse {
    choices: Vec<OpenAiChoice>,
    usage: Option<OpenAiUsage>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    message: Option<OpenAiResponseMessage>,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct OpenAiResponseMessage {
    content: Option<String>,
}

#[derive(Default, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    prompt_cache_hit_tokens: Option<u64>,
    prompt_cache_miss_tokens: Option<u64>,
    prompt_tokens_details: Option<OpenAiPromptDetails>,
    completion_tokens_details: Option<OpenAiCompletionDetails>,
}

#[derive(Deserialize)]
struct OpenAiPromptDetails {
    cached_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct OpenAiCompletionDetails {
    reasoning_tokens: Option<u64>,
}

/// A cache label is meaningful only when numeric counters describe a consistent split.
pub fn prompt_cache_status(total: Option<u64>, hit: Option<u64>, miss: Option<u64>) -> CacheStatus {
    match (total, hit, miss) {
        (Some(total), Some(hit), Some(miss)) if hit.checked_add(miss) == Some(total) => {
            match (hit, miss) {
                (0, _) => CacheStatus::Miss,
                (_, 0) => CacheStatus::Hit,
                _ => CacheStatus::PartialHit,
            }
        }
        _ => CacheStatus::NotApplicable,
    }
}

/// Normalize supported cache counters, rejecting contradictory observations.
pub fn prompt_cache_counts(
    total: Option<u64>,
    hit: Option<u64>,
    miss: Option<u64>,
    nested_hit: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    if hit.zip(nested_hit).is_some_and(|(a, b)| a != b) {
        return (None, None);
    }
    let hit = hit.or(nested_hit).or_else(|| {
        total
            .zip(miss)
            .and_then(|(total, miss)| total.checked_sub(miss))
    });
    let miss = miss.or_else(|| {
        total
            .zip(hit)
            .and_then(|(total, hit)| total.checked_sub(hit))
    });
    if total.zip(hit).is_some_and(|(total, hit)| hit > total)
        || total.zip(miss).is_some_and(|(total, miss)| miss > total)
        || total
            .zip(hit.zip(miss))
            .is_some_and(|(total, (hit, miss))| hit.checked_add(miss) != Some(total))
    {
        return (None, None);
    }
    (hit, miss)
}

fn reported_cost_usd(raw: &Value) -> Option<String> {
    // Only explicit provider billing fields; never substitute token/rate estimates.
    let value = raw
        .pointer("/usage/cost")
        .or_else(|| raw.pointer("/usage/cost_usd"))?;
    let text = match value {
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        _ => return None,
    };
    let number = text.parse::<f64>().ok()?;
    (number.is_finite() && number >= 0.0).then_some(text)
}

#[async_trait]
impl ChatProvider for OpenAiCompatibleChatProvider {
    async fn chat(&self, mut request: ChatRequest) -> Result<ChatResponse, ModelError> {
        secrets::credential_boundary(
            (async {
                self.validate_configuration()?;
                let output = request
                    .max_output_tokens
                    .or(self.max_output_tokens)
                    .filter(|n| *n > 0)
                    .ok_or({
                        ModelError::InvalidRequest(
                            symbiotic_core::DiagnosticCode::FiniteOutputTokensAreRequired,
                        )
                    })?;
                if self.max_output_tokens.is_some_and(|limit| output > limit) {
                    return Err(ModelError::InvalidRequest(
                        symbiotic_core::DiagnosticCode::OutputTokenLimitExceeded,
                    ));
                }
                request.max_output_tokens = Some(output);
                let body = wire::openai_chat_body(
                    &self.descriptor.identity.model.0,
                    &request,
                    self.thinking,
                    self.reasoning_effort.as_deref(),
                    self.max_request_bytes,
                )?;
                let builder = self
                    .client
                    .get()?
                    .post(format!(
                        "{}/chat/completions",
                        self.base_url.trim_end_matches('/')
                    ))
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body);
                let builder = if self.api_key.secret().is_empty() {
                    builder
                } else {
                    builder.bearer_auth(self.api_key.secret())
                };
                let (raw, _) = provider_response_json(
                    builder,
                    self.max_response_bytes,
                    ModelError::Unavailable,
                )
                .await?;
                let parsed: OpenAiChatWireResponse =
                    serde_json::from_value(raw.clone()).map_err(|_err| {
                        ModelError::Provider(symbiotic_core::DiagnosticCode::ProviderFailure)
                    })?;
                let choice = parsed.choices.into_iter().next().ok_or({
                    ModelError::Provider(
                        symbiotic_core::DiagnosticCode::OpenaiCompatibleResponseHadNoChoices,
                    )
                })?;
                let usage = parsed.usage.unwrap_or_default();
                let content = choice
                    .message
                    .as_ref()
                    .and_then(|message| message.content.as_deref())
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
                    reasoning_tokens: usage
                        .completion_tokens_details
                        .and_then(|details| details.reasoning_tokens),
                    media_units: None,
                    cost_micro_usd: None,
                    reported_cost_usd: reported_cost_usd(&raw),
                };
                let nested_hit = usage
                    .prompt_tokens_details
                    .and_then(|details| details.cached_tokens);
                let (hit, miss) = prompt_cache_counts(
                    usage.prompt_tokens,
                    usage.prompt_cache_hit_tokens,
                    usage.prompt_cache_miss_tokens,
                    nested_hit,
                );
                trace.metadata = serde_json::json!({
                    "provider": {
                        "response_id": raw.get("id").and_then(Value::as_str),
                        "served_model": raw.get("model").and_then(Value::as_str),
                        "created": raw.get("created").and_then(Value::as_i64),
                        "reasoning_tokens": trace.usage.reasoning_tokens,
                        "reported_cost_usd": trace.usage.reported_cost_usd,
                    },
                    "cache_miss_tokens": miss,
                    "observed_cache_tokens": {
                        "hit": usage.prompt_cache_hit_tokens,
                        "miss": usage.prompt_cache_miss_tokens,
                        "nested_hit": nested_hit,
                    },
                });
                trace.cache = CacheTrace {
                    response_cache: CacheStatus::Miss,
                    prompt_cache: prompt_cache_status(usage.prompt_tokens, hit, miss),
                    cached_input_tokens: hit,
                };
                Ok(ChatResponse {
                    text: content.to_string(),
                    finish_reason: choice.finish_reason,
                    trace,
                    raw_provider_response: Some(raw),
                })
            })
            .await,
            &self.api_key,
        )
    }
}

#[derive(Clone)]
pub struct GeminiEmbeddingProvider {
    descriptor: ProviderDescriptor,
    client: HttpClient,
    api_key: CredentialBoundary,
    max_response_bytes: Option<usize>,
    max_request_bytes: Option<usize>,
    dimensions: usize,
    #[cfg(test)]
    test_endpoint: Option<String>,
}

impl GeminiEmbeddingProvider {
    #[cfg(test)]
    fn at_test_endpoint(mut self, endpoint: String) -> Self {
        self.test_endpoint = Some(endpoint);
        self
    }

    fn endpoint(&self) -> &str {
        #[cfg(test)]
        if let Some(endpoint) = &self.test_endpoint {
            return endpoint;
        }
        "https://generativelanguage.googleapis.com/v1beta"
    }
    /// Construct a Gemini transport with an owned key and explicit dimensions.
    pub fn new(
        operator: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<SecretValue<String>>,
        dimensions: usize,
    ) -> Self {
        let model = model.into();
        Self {
            descriptor: ProviderDescriptor {
                identity: ModelIdentity::new("embedding", operator, model),
                provider_class: ProviderClass::Cloud,
                capabilities: vec![ModelCapability::Embedding],
                auth_mode: ProviderAuthMode::ApiKey {
                    secret_ref: "runtime".to_string(),
                },
                metadata: serde_json::json!({ "dimensions": dimensions, "endpoint": "https://generativelanguage.googleapis.com/v1beta" }),
            },
            client: HttpClient::default(),
            api_key: CredentialBoundary::new(api_key.into()),
            max_response_bytes: None,
            max_request_bytes: None,
            dimensions,
            #[cfg(test)]
            test_endpoint: None,
        }
    }

    /// Clients cannot be injected through the public API.
    /// ```compile_fail
    /// use symbiotic_model::GeminiEmbeddingProvider;
    /// GeminiEmbeddingProvider::new("op", "model", "key", 2)
    ///     .with_client(reqwest::Client::new());
    /// ```
    /// Set a finite timeout on a Foundation-owned redirect-free, direct client.
    pub fn with_timeout(mut self, timeout_seconds: u64) -> Result<Self, ModelError> {
        self.client = HttpClient(Ok(http_client(Some(timeout_seconds))?));
        Ok(self)
    }

    /// Bound the complete encoded HTTP request body before transmission.
    pub fn with_request_limit(mut self, max_bytes: usize) -> Self {
        self.descriptor.metadata["max_request_bytes"] = serde_json::json!(max_bytes);
        self.max_request_bytes = Some(max_bytes);
        self
    }

    /// Bound response bodies before buffering, including provider error bodies.
    pub fn with_response_limit(mut self, max_bytes: usize) -> Self {
        self.descriptor.metadata["max_response_bytes"] = serde_json::json!(max_bytes);
        self.max_response_bytes = Some(max_bytes);
        self
    }
}

#[async_trait]
impl ModelProvider for GeminiEmbeddingProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }

    fn validate_configuration(&self) -> Result<(), ModelError> {
        self.client.get()?;
        required_byte_limit(self.max_request_bytes)?;
        required_byte_limit(self.max_response_bytes)?;
        if self.dimensions == 0 {
            return Err(ModelError::InvalidRequest(
                symbiotic_core::DiagnosticCode::EmbeddingDimensionsMustBeNonzero,
            ));
        }
        Ok(())
    }

    fn credential_fingerprint(&self) -> Option<String> {
        api_key_fingerprint(self.api_key.secret())
    }

    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        Some(&self.api_key)
    }
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

impl GeminiEmbedding {
    fn into_values(self, dimensions: usize) -> Result<Vec<f32>, ModelError> {
        if self.values.len() != dimensions {
            return Err(ModelError::Provider(
                symbiotic_core::DiagnosticCode::GeminiEmbeddingDimensionMismatch,
            ));
        }
        if self.values.iter().any(|value| !value.is_finite()) {
            return Err(ModelError::Provider(
                symbiotic_core::DiagnosticCode::GeminiEmbeddingContainsNonFiniteComponents,
            ));
        }
        Ok(self.values)
    }
}

#[async_trait]
impl EmbeddingProvider for GeminiEmbeddingProvider {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        secrets::credential_boundary(
            (async {
                self.validate_configuration()?;
                wire::validate_gemini_options(self.dimensions, &request)?;
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
                let body = wire::gemini_embedding_body(
                    model,
                    self.dimensions,
                    &request,
                    self.max_request_bytes,
                )?;
                let raw_provider_response;
                let vectors = if request.inputs.len() == 1 {
                    let builder = self
                        .client
                        .get()?
                        .post(format!("{}/models/{model}:embedContent", self.endpoint()))
                        .header("x-goog-api-key", self.api_key.secret())
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(body);
                    let (raw, _) = provider_response_json(
                        builder,
                        self.max_response_bytes,
                        ModelError::Unavailable,
                    )
                    .await?;
                    raw_provider_response = Some(raw.clone());
                    let raw: GeminiEmbedWireResponse =
                        serde_json::from_value(raw).map_err(|_err| {
                            ModelError::Unavailable(symbiotic_core::DiagnosticCode::HttpUnavailable)
                        })?;
                    vec![
                        raw.embedding
                            .ok_or({
                                ModelError::Provider(
                                    symbiotic_core::DiagnosticCode::GeminiResponseMissingEmbedding,
                                )
                            })?
                            .into_values(self.dimensions)?,
                    ]
                } else {
                    let builder = self
                        .client
                        .get()?
                        .post(format!(
                            "{}/models/{model}:batchEmbedContents",
                            self.endpoint()
                        ))
                        .header("x-goog-api-key", self.api_key.secret())
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(body);
                    let (raw, _) = provider_response_json(
                        builder,
                        self.max_response_bytes,
                        ModelError::Unavailable,
                    )
                    .await?;
                    raw_provider_response = Some(raw.clone());
                    let raw: GeminiBatchEmbedWireResponse =
                        serde_json::from_value(raw).map_err(|_err| {
                            ModelError::Unavailable(symbiotic_core::DiagnosticCode::HttpUnavailable)
                        })?;
                    let embeddings = raw.embeddings.ok_or({
                        ModelError::Provider(
                            symbiotic_core::DiagnosticCode::GeminiBatchResponseMissingEmbeddings,
                        )
                    })?;
                    if embeddings.len() != request.inputs.len() {
                        return Err(ModelError::Provider(
                            symbiotic_core::DiagnosticCode::ProviderFailure,
                        ));
                    }
                    embeddings
                        .into_iter()
                        .map(|embedding| embedding.into_values(self.dimensions))
                        .collect::<Result<Vec<_>, _>>()?
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
                    raw_provider_response,
                })
            })
            .await,
            &self.api_key,
        )
    }
}

// Keep infallible adapter constructors while surfacing client construction errors
// during configuration validation, before a binding can dispatch.
#[derive(Clone)]
struct HttpClient(Result<reqwest::Client, ()>);

impl Default for HttpClient {
    fn default() -> Self {
        Self(http_client_builder().build().map_err(|_| ()))
    }
}

impl HttpClient {
    fn get(&self) -> Result<&reqwest::Client, ModelError> {
        self.0.as_ref().map_err(|_| invalid_http_client())
    }
}

fn invalid_http_client() -> ModelError {
    ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::InvalidHttpClientConfiguration)
}

fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .retry(reqwest::retry::never())
}

/// Boundary-owned HTTP client construction; no public client injection.
fn http_client(timeout_seconds: Option<u64>) -> Result<reqwest::Client, ModelError> {
    let timeout = timeout_seconds.filter(|n| *n > 0).ok_or({
        ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::FiniteTimeoutIsRequired)
    })?;
    http_client_builder()
        .timeout(std::time::Duration::from_secs(timeout))
        .build()
        .map_err(|_| invalid_http_client())
}

fn required_byte_limit(limit: Option<usize>) -> Result<usize, ModelError> {
    limit.filter(|n| *n > 0).ok_or({
        ModelError::InvalidRequest(
            symbiotic_core::DiagnosticCode::FiniteNonzeroRequestResponseByteLimitsAreRequired,
        )
    })
}

async fn bounded_response_bytes(
    mut response: reqwest::Response,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>, ModelError> {
    let limit = required_byte_limit(max_bytes)?;
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(ModelError::Provider(
            symbiotic_core::DiagnosticCode::ProviderResponseLimitExceeded,
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        ModelError::Unavailable(symbiotic_core::DiagnosticCode::ProviderResponseReadFailed)
    })? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(ModelError::Provider(
                symbiotic_core::DiagnosticCode::ProviderResponseLimitExceeded,
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Bounded HTTP decoding. Credential policy belongs exclusively to the final
/// adapter-result boundary, including errors raised after this helper returns.
async fn provider_response_json(
    builder: reqwest::RequestBuilder,
    max_bytes: Option<usize>,
    invalid_json: fn(DiagnosticCode) -> ModelError,
) -> Result<(Value, String), ModelError> {
    let response = builder
        .send()
        .await
        .map_err(|_err| ModelError::Unavailable(symbiotic_core::DiagnosticCode::HttpUnavailable))?;
    let status = response.status();
    if status.is_redirection() {
        return Err(ModelError::Provider(
            symbiotic_core::DiagnosticCode::ProviderRedirectRefused,
        ));
    }
    if !status.is_success() {
        return Err(status_error(status.as_u16()));
    }
    let bytes = bounded_response_bytes(response, max_bytes).await?;
    let text = String::from_utf8(bytes).map_err(|_| {
        ModelError::Provider(symbiotic_core::DiagnosticCode::ProviderResponseIsNotValidUtf8)
    })?;
    let raw: Value = serde_json::from_str(&text)
        .map_err(|_err| invalid_json(DiagnosticCode::InvalidResponse))?;
    Ok((raw, text))
}

fn status_error(status: u16) -> ModelError {
    match status {
        401 | 403 => ModelError::Auth(DiagnosticCode::AuthenticationRejected),
        402 => ModelError::BudgetExhausted(DiagnosticCode::HttpBudgetExhausted),
        408 | 504 => ModelError::Timeout(DiagnosticCode::HttpTimeout),
        429 => ModelError::RateLimited(DiagnosticCode::HttpRateLimited),
        500..=599 => ModelError::Unavailable(DiagnosticCode::HttpUnavailable),
        _ => ModelError::Provider(DiagnosticCode::HttpFailure),
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

#[cfg(all(test, feature = "queue"))]
extern crate self as symbiotic_model;
#[cfg(all(test, feature = "queue"))]
#[path = "../tests/support/spend.rs"]
mod test_spend;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "queue")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "queue")]
    use std::time::Duration;
    #[cfg(feature = "queue")]
    use symbiotic_queue_sqlite::SqliteQueue;

    #[cfg(feature = "queue")]
    #[tokio::test]
    async fn regression_cooldown_wait_rereads_after_waking() {
        let queue = std::sync::Arc::new(symbiotic_queue::MemoryQueue::new());
        let queue_id = QueueId::new("extended-cooldown");
        queue
            .note_cooldown(&queue_id, Utc::now() + ChronoDuration::milliseconds(100))
            .await
            .unwrap();
        let waiter = wait_for_model_cooldown(queue.as_ref(), &queue_id);
        tokio::pin!(waiter);
        // Poll through the initial read so the extension occurs while sleeping.
        assert!(futures::poll!(waiter.as_mut()).is_pending());
        let extended = Utc::now() + ChronoDuration::milliseconds(250);
        queue.note_cooldown(&queue_id, extended).await.unwrap();
        waiter.await.unwrap();
        assert!(Utc::now() >= extended);
    }

    #[test]
    fn failed_http_client_construction_refuses_chat_and_embedding_configuration() {
        let mut chat = OpenAiCompatibleChatProvider::new("op", "model", "http://localhost", "")
            .with_request_limit(1024)
            .with_response_limit(1024);
        let mut embedding = GeminiEmbeddingProvider::new("op", "model", "", 2)
            .with_request_limit(1024)
            .with_response_limit(1024);
        chat.client = HttpClient(Err(()));
        embedding.client = HttpClient(Err(()));
        for provider in [&chat as &dyn ModelProvider, &embedding] {
            assert!(matches!(
                provider.validate_configuration(),
                Err(ModelError::InvalidRequest(
                    symbiotic_core::DiagnosticCode::InvalidHttpClientConfiguration
                ))
            ));
        }
    }

    #[test]
    fn gemini_single_vectors_require_exact_configured_dimensions() {
        for length in [0, 1, 2, 4] {
            let raw: GeminiEmbedWireResponse = serde_json::from_value(
                serde_json::json!({"embedding": {"values": vec![0.5; length]}}),
            )
            .unwrap();
            assert!(matches!(
                raw.embedding.unwrap().into_values(3),
                Err(ModelError::Provider(_))
            ));
        }
        assert_eq!(
            GeminiEmbedding {
                values: vec![0.5; 3]
            }
            .into_values(3)
            .unwrap()
            .len(),
            3
        );
    }
    #[test]
    fn gemini_batch_checks_each_vectors_exact_length() {
        for length in [0, 1, 2, 4] {
            let raw: GeminiBatchEmbedWireResponse = serde_json::from_value(serde_json::json!({"embeddings": [{"values": [0.1, 0.2, 0.3]}, {"values": vec![0.5; length]}]})).unwrap();
            let result: Result<Vec<_>, _> = raw
                .embeddings
                .unwrap()
                .into_iter()
                .map(|embedding| embedding.into_values(3))
                .collect();
            assert!(matches!(result, Err(ModelError::Provider(_))));
        }
    }
    #[tokio::test]
    async fn gemini_request_options_are_refused_even_for_empty_batches() {
        let provider = GeminiEmbeddingProvider::new("gemini", "synthetic", "", 3)
            .with_request_limit(1024)
            .with_response_limit(1024);
        let base = EmbeddingRequest {
            inputs: vec![],
            dimensions: None,
            task: None,
            sensitivity: Sensitivity::Shareable,
            role_binding: None,
            source: None,
            metadata: Value::Null,
        };
        for dimensions in [Some(0), Some(2), Some(4)] {
            let mut request = base.clone();
            request.dimensions = dimensions;
            assert!(matches!(
                provider.embed(request).await,
                Err(ModelError::InvalidRequest(_))
            ));
        }
        let mut request = base.clone();
        request.task = Some("retrieval_document".into());
        assert!(matches!(
            provider.embed(request).await,
            Err(ModelError::InvalidRequest(_))
        ));
        let mut request = base;
        request.dimensions = Some(3);
        let result = provider.embed(request).await.unwrap();
        assert_eq!(result.dimensions, 3);
        assert!(result.vectors.is_empty());
    }

    #[test]
    fn gemini_single_embedding_rejects_non_finite_components() {
        for number in ["1e39", "-1e39"] {
            let raw: GeminiEmbedWireResponse =
                serde_json::from_str(&format!(r#"{{"embedding":{{"values":[0.25,{number}]}}}}"#))
                    .unwrap();
            assert!(matches!(
                raw.embedding.unwrap().into_values(2),
                Err(ModelError::Provider(
                    symbiotic_core::DiagnosticCode::GeminiEmbeddingContainsNonFiniteComponents
                ))
            ));
        }
        let raw: GeminiEmbedWireResponse =
            serde_json::from_str(r#"{"embedding":{"values":[0.25,-0.5,3e38]}}"#).unwrap();
        let values = raw.embedding.unwrap().into_values(3).unwrap();
        assert_eq!(values.len(), 3);
        assert!(values.iter().all(|value| value.is_finite()));
    }

    #[test]
    fn gemini_batch_embedding_rejects_non_finite_components() {
        for number in ["1e39", "-1e39"] {
            let raw: GeminiBatchEmbedWireResponse = serde_json::from_str(&format!(
                r#"{{"embeddings":[{{"values":[0.25,0.5]}},{{"values":[-0.5,{number}]}}]}}"#
            ))
            .unwrap();
            let result: Result<Vec<_>, _> = raw
                .embeddings
                .unwrap()
                .into_iter()
                .map(|embedding| embedding.into_values(2))
                .collect();
            assert!(matches!(
                result,
                Err(ModelError::Provider(
                    symbiotic_core::DiagnosticCode::GeminiEmbeddingContainsNonFiniteComponents
                ))
            ));
        }
        let raw: GeminiBatchEmbedWireResponse = serde_json::from_str(
            r#"{"embeddings":[{"values":[0.25,0.5]},{"values":[-0.5,3e38]}]}"#,
        )
        .unwrap();
        let vectors: Vec<_> = raw
            .embeddings
            .unwrap()
            .into_iter()
            .map(|embedding| embedding.into_values(2))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(vectors.len(), 2);
        assert!(vectors.iter().flatten().all(|value| value.is_finite()));
    }

    #[cfg(feature = "queue")]
    static TEST_QUEUE_COUNTER: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "queue")]
    use symbiotic_trace::InMemoryTraceSink;

    #[cfg(feature = "queue")]
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

        assert_eq!(request.input_budget_units().unwrap(), 3);
        assert_eq!(estimate_token_budget_units([""]), 1);
    }

    #[cfg(feature = "queue")]
    #[derive(Clone)]
    struct SlowCountingChat {
        descriptor: ProviderDescriptor,
        active: Arc<AtomicUsize>,
        max_seen: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }

    #[cfg(feature = "queue")]
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

    #[cfg(feature = "queue")]
    #[async_trait]
    impl ModelProvider for SlowCountingChat {
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[cfg(feature = "queue")]
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

    #[cfg(feature = "queue")]
    #[derive(Clone)]
    struct DeadThenSuccessChat {
        descriptor: ProviderDescriptor,
        calls: Arc<AtomicUsize>,
    }

    #[cfg(feature = "queue")]
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

    #[cfg(feature = "queue")]
    #[async_trait]
    impl ModelProvider for DeadThenSuccessChat {
        fn failure_charge(&self, _: &ModelError) -> crate::FailureCharge {
            crate::FailureCharge::KnownZero
        }
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[cfg(feature = "queue")]
    #[async_trait]
    impl ChatProvider for DeadThenSuccessChat {
        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return Err(ModelError::Unavailable(
                    symbiotic_core::DiagnosticCode::HttpUnavailable,
                ));
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

    #[cfg(feature = "queue")]
    #[derive(Clone)]
    struct SlowUnavailableChat {
        descriptor: ProviderDescriptor,
        calls: Arc<AtomicUsize>,
    }

    #[cfg(feature = "queue")]
    impl SlowUnavailableChat {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            // Independent fixtures must not inherit another test's model cooldown.
            let model = format!(
                "unavailable-fixture-{}",
                TEST_QUEUE_COUNTER.fetch_add(1, Ordering::SeqCst)
            );
            Self {
                descriptor: ProviderDescriptor {
                    identity: ModelIdentity::new("chat", "fixture", model),
                    provider_class: ProviderClass::Cloud,
                    capabilities: vec![ModelCapability::Chat],
                    auth_mode: ProviderAuthMode::None,
                    metadata: serde_json::json!({}),
                },
                calls,
            }
        }
    }

    #[cfg(feature = "queue")]
    #[async_trait]
    impl ModelProvider for SlowUnavailableChat {
        fn failure_charge(&self, _: &ModelError) -> crate::FailureCharge {
            crate::FailureCharge::KnownZero
        }
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[cfg(feature = "queue")]
    #[async_trait]
    impl ChatProvider for SlowUnavailableChat {
        async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse, ModelError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            Err(ModelError::Unavailable(
                symbiotic_core::DiagnosticCode::HttpUnavailable,
            ))
        }
    }

    #[cfg(feature = "queue")]
    #[derive(Clone)]
    struct LeaseCrossingChat {
        descriptor: ProviderDescriptor,
    }

    #[cfg(feature = "queue")]
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

    #[cfg(feature = "queue")]
    #[async_trait]
    impl ModelProvider for LeaseCrossingChat {
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[cfg(feature = "queue")]
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

    #[cfg(feature = "queue")]
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

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None);
        let results = futures::future::join_all((0..8).map(|idx| {
            let provider = provider.clone();
            async move { provider.chat(chat_request(&format!("request-{idx}"))).await }
        }))
        .await;

        assert!(results.iter().all(Result::is_ok));
        assert_eq!(max_seen.load(Ordering::SeqCst), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 8);
    }

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None)
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

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None)
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
        assert!(
            records[1].timing.throttle_wait_ms.unwrap_or_default() >= 900,
            "budget wait should be attributed to throttle_wait: {:?}",
            records[1].timing
        );
        assert_eq!(
            records[1].timing.queued_ms.unwrap_or_default(),
            records[1].timing.queue_wait_ms.unwrap_or_default()
                + records[1].timing.throttle_wait_ms.unwrap_or_default(),
            "queue_wait + throttle_wait should partition queued time: {:?}",
            records[1].timing
        );
    }

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None);

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

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None);

        let results = futures::future::join_all((0..2).map(|_| {
            let provider = provider.clone();
            async move { provider.chat(chat_request("same request")).await }
        }))
        .await;

        assert!(results.iter().all(Result::is_ok));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None);

        let response = provider.chat(request).await.unwrap();

        assert_eq!(response.text, "same request");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let scope = std::fs::read_dir(dir.path().join("cache/chat"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(scope.join(format!("{request_hash}.json")).is_file());
    }

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None);

        let response = provider.chat(chat_request("hello")).await.unwrap();

        assert_eq!(response.text, "hello");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None);

        let err = provider.chat(chat_request("hello")).await.unwrap_err();

        assert!(matches!(
            err,
            ModelError::Unavailable(symbiotic_core::DiagnosticCode::AttemptBudgetExhausted)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None);

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

    #[cfg(feature = "queue")]
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None);

        let response = provider.chat(chat_request("hello")).await.unwrap();

        assert_eq!(response.text, "hello");
    }

    #[test]
    fn credential_fingerprints_identify_a_key_without_revealing_it() {
        let key = "sk-live-0123456789abcdef";
        let fingerprint = api_key_fingerprint(key).unwrap();
        assert_eq!(api_key_fingerprint(key), Some(fingerprint.clone()));
        assert_ne!(
            api_key_fingerprint("sk-live-other"),
            Some(fingerprint.clone())
        );
        assert!(!fingerprint.contains(key) && !fingerprint.contains("0123456789"));
        assert_eq!(api_key_fingerprint(""), None);
        assert_eq!(api_key_fingerprint("  "), None);

        let provider = OpenAiCompatibleChatProvider::new("op", "m", "http://127.0.0.1:9", key);
        assert_eq!(provider.credential_fingerprint(), Some(fingerprint.clone()));
        let rotated = OpenAiCompatibleChatProvider::new("op", "m", "http://127.0.0.1:9", "sk-2");
        assert_eq!(
            provider.descriptor().identity,
            rotated.descriptor().identity
        );
        assert_ne!(
            provider.credential_fingerprint(),
            rotated.credential_fingerprint()
        );
        let shared: Arc<dyn ChatProvider> = Arc::new(provider);
        assert_eq!(shared.credential_fingerprint(), Some(fingerprint));
    }

    #[cfg(feature = "queue")]
    #[test]
    fn rate_bucket_waits_after_burst_without_consuming_request_timeout() {
        let mut bucket = RateBucket::new(60.0);
        assert!(bucket.wait_for(1.0).is_none());
        bucket.charge(1.0);
        assert!(bucket.wait_for(1.0).is_some());
    }

    #[cfg(feature = "queue")]
    #[test]
    fn rate_bucket_smooths_high_rpm_instead_of_cold_start_bursting() {
        let mut bucket = RateBucket::new(20_000.0);
        assert!(bucket.wait_for(1.0).is_none());
        bucket.charge(1.0);
        let wait = bucket
            .wait_for(1.0)
            .expect("second request should be paced even for high-rpm queues");
        assert!(
            wait < Duration::from_millis(10),
            "20k rpm should pace in milliseconds, not seconds: {wait:?}"
        );
    }

    #[cfg(feature = "queue")]
    #[test]
    fn every_error_class_survives_a_dead_item_and_exhaustion() {
        let errors = [
            ModelError::Unavailable(symbiotic_core::DiagnosticCode::HttpUnavailable),
            ModelError::Auth(symbiotic_core::DiagnosticCode::AuthenticationRejected),
            ModelError::RateLimited(symbiotic_core::DiagnosticCode::HttpRateLimited),
            ModelError::BudgetExhausted(symbiotic_core::DiagnosticCode::HttpBudgetExhausted),
            ModelError::Timeout(symbiotic_core::DiagnosticCode::HttpTimeout),
            ModelError::Unsupported(ModelCapability::Rerank),
            ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::InvalidConfiguration),
            ModelError::Provider(symbiotic_core::DiagnosticCode::ProviderFailure),
            ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure),
            ModelError::Cache(symbiotic_core::DiagnosticCode::CacheFailure),
            ModelError::Cache(symbiotic_core::DiagnosticCode::CachePathRefused),
        ];
        let now = Utc::now();
        for err in errors {
            let item = QueueItem {
                item_id: QueueItemId::new(),
                queue_id: QueueId::new("chat:test:classes"),
                kind: "chat".to_string(),
                payload: serde_json::json!({}),
                status: QueueStatus::Dead,
                attempt: 1,
                max_attempts: 1,
                run_after: now,
                lease_owner: None,
                lease_until: None,
                idempotency_key: None,
                last_error: Some(err.code()),
                last_error_class: Some(error_class(&err)),
                created_at: now,
                updated_at: now,
            };
            let replayed = dead_item_retry_error(&item);
            assert_eq!(replayed.code(), err.code());
            assert_eq!(
                std::mem::discriminant(&replayed),
                std::mem::discriminant(&err),
                "{err:?} came back as {replayed:?}"
            );
            let exhausted = exhausted_request_error(
                &item.queue_id,
                &item,
                &ModelQueueConfig::default(),
                &replayed,
            );
            assert_eq!(
                std::mem::discriminant(&exhausted),
                std::mem::discriminant(&err),
                "{err:?} exhausted as {exhausted:?}"
            );
            if let (ModelError::Unsupported(expected), ModelError::Unsupported(actual)) =
                (&err, &exhausted)
            {
                assert_eq!(expected, actual);
            }
            let mut missing_class = item;
            missing_class.last_error_class = None;
            missing_class.last_error = Some(DiagnosticCode::ProviderFailure);
            assert!(matches!(
                dead_item_retry_error(&missing_class),
                ModelError::Queue(
                    symbiotic_core::DiagnosticCode::TerminalQueueItemIsMissingItsErrorClass
                )
            ));
        }
    }

    #[cfg(feature = "queue")]
    #[test]
    fn rate_bucket_burst_admits_one_window_then_paces() {
        let mut bucket = RateBucket::with_burst(60.0, 60);
        for _ in 0..60 {
            assert!(bucket.wait_for(1.0).is_none());
            bucket.charge(1.0);
        }
        let wait = bucket.wait_for(1.0).expect("the 61st request waits");
        assert!(wait <= Duration::from_millis(1_050), "{wait:?}");
    }

    #[cfg(feature = "queue")]
    #[test]
    fn retry_backoff_doubles_from_the_base_and_caps() {
        assert_eq!(retry_backoff_ms(1, 1_000), 1_000);
        assert_eq!(retry_backoff_ms(2, 1_000), 2_000);
        assert_eq!(retry_backoff_ms(6, 1_000), 30_000);
        assert_eq!(retry_backoff_ms(1, 250), 250);
        assert_eq!(retry_backoff_ms(3, 250), 1_000);
        assert_eq!(retry_backoff_ms(9, 250), 8_000);
    }

    #[cfg(feature = "queue")]
    #[test]
    fn retry_jitter_spreads_same_attempt_failures_deterministically() {
        let err = ModelError::Unavailable(symbiotic_core::DiagnosticCode::HttpUnavailable);
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

    #[cfg(feature = "queue")]
    #[tokio::test]
    async fn model_budget_is_spent_only_by_a_charged_grant() {
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
            ..ModelQueueConfig::default()
        };
        let queue_id = QueueId(format!(
            "test-budget-{}",
            TEST_QUEUE_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));

        let state = ModelRateState::default();
        let cleared = |check: RateCheck| match check {
            RateCheck::Cleared(grant) => grant.expect("a rate-limited policy returns a grant"),
            RateCheck::Wait(wait) => panic!("budget is available, but asked to wait {wait:?}"),
        };
        // Cleared without a claim: nothing is spent, and the next caller is
        // cleared at once.
        drop(cleared(
            check_model_budget(&state, &queue_id, &config, &chat_request("first"))
                .await
                .unwrap(),
        ));
        cleared(
            check_model_budget(&state, &queue_id, &config, &chat_request("first"))
                .await
                .unwrap(),
        )
        .charge()
        .unwrap();
        // Spent: the next caller waits about a second for the refill.
        match check_model_budget(&state, &queue_id, &config, &chat_request("second"))
            .await
            .unwrap()
        {
            RateCheck::Wait(wait) => assert!(wait >= Duration::from_millis(900), "{wait:?}"),
            RateCheck::Cleared(_) => panic!("the budget was spent"),
        }
    }

    #[cfg(feature = "queue")]
    #[tokio::test]
    async fn poisoned_rate_state_refuses_checks_and_charging() {
        let policy = ModelQueueConfig {
            requests_per_minute: Some(60),
            ..ModelQueueConfig::default()
        };
        let request = chat_request("x");
        let queue = QueueId::new("account");
        let state = ModelRateState::default();
        let RateCheck::Cleared(Some(grant)) = check_model_budget(&state, &queue, &policy, &request)
            .await
            .unwrap()
        else {
            panic!("fresh budget");
        };
        let buckets = state.buckets.clone();
        let _ = std::thread::spawn(move || {
            let _held = buckets.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(matches!(grant.charge(), Err(ModelError::Queue(_))));
        assert!(matches!(
            check_model_budget(&state, &queue, &policy, &request).await,
            Err(ModelError::Queue(_))
        ));
        let state = ModelRateState::default();
        let gates = state.gates.clone();
        let _ = std::thread::spawn(move || {
            let _held = gates.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(matches!(
            check_model_budget(&state, &queue, &policy, &request).await,
            Err(ModelError::Queue(_))
        ));
    }

    #[cfg(feature = "queue")]
    #[derive(Clone)]
    struct CountingRerank {
        descriptor: ProviderDescriptor,
        calls: Arc<AtomicUsize>,
    }

    #[cfg(feature = "queue")]
    impl CountingRerank {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                descriptor: ProviderDescriptor {
                    identity: ModelIdentity::new("rerank", "nemotron", "nemotron-rerank-1b"),
                    provider_class: ProviderClass::Cloud,
                    capabilities: vec![ModelCapability::Rerank],
                    auth_mode: ProviderAuthMode::None,
                    metadata: serde_json::json!({}),
                },
                calls,
            }
        }
    }

    #[cfg(feature = "queue")]
    #[async_trait]
    impl ModelProvider for CountingRerank {
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
    }

    #[cfg(feature = "queue")]
    #[async_trait]
    impl RerankProvider for CountingRerank {
        async fn rerank(&self, request: RerankRequest) -> Result<RerankResponse, ModelError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Rank documents by descending length as a deterministic stand-in
            // for a real relevance model.
            let mut hits: Vec<RerankHit> = request
                .documents
                .iter()
                .enumerate()
                .map(|(index, doc)| RerankHit {
                    index,
                    score: doc.len() as f32,
                })
                .collect();
            hits.sort_by(|a, b| b.score.total_cmp(&a.score));
            if let Some(top_k) = request.top_k {
                hits.truncate(top_k);
            }
            Ok(RerankResponse {
                hits,
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

    #[cfg(feature = "queue")]
    fn rerank_request(query: &str) -> RerankRequest {
        RerankRequest {
            query: query.to_string(),
            documents: vec![
                "short".to_string(),
                "a much longer candidate document".to_string(),
                "medium length".to_string(),
            ],
            top_k: Some(2),
            sensitivity: Sensitivity::Shareable,
            role_binding: Some("memory.rerank".to_string()),
            source: Some("test".to_string()),
            metadata: serde_json::json!({}),
        }
    }

    #[cfg(feature = "queue")]
    #[tokio::test]
    async fn queued_rerank_provider_reuses_exact_response_cache_and_traces() {
        let dir = tempfile::tempdir().unwrap();
        let queue = Arc::new(SqliteQueue::in_memory().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let trace_sink = Arc::new(InMemoryTraceSink::default());
        let provider = QueuedRerankProvider::new(
            CountingRerank::new(calls.clone()),
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
                ..ModelQueueConfig::default()
            },
        )
        .with_spend_ledger(test_spend::ledger(), None)
        .with_trace_sink(trace_sink.clone());

        let first = provider.rerank(rerank_request("query")).await.unwrap();
        // Longest document ("a much longer candidate document") ranks first.
        assert_eq!(first.hits.len(), 2);
        assert_eq!(first.hits[0].index, 1);

        let second = provider.rerank(rerank_request("query")).await.unwrap();
        assert_eq!(second.hits[0].index, 1);

        // Second identical call is served from the response cache — the
        // underlying model runs exactly once.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let records = trace_sink.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].cache.response_cache, CacheStatus::Miss);
        assert_eq!(records[1].cache.response_cache, CacheStatus::Hit);
    }
}

#[cfg(test)]
mod credential_transport_tests;
