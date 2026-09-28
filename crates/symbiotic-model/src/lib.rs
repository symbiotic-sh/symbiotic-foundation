//! Provider-neutral model runtime contracts.
//!
//! Implementations may wrap HTTP SDKs, local CLIs, subscription-backed tools,
//! or host-owned adapters. Policy and scheduling are supplied by the host.
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
use symbiotic_core::{
    InvocationSource, ModelIdentity, ModelName, ModelTier, Operation, Operator, QueueId,
    RoleBinding, Sensitivity, TraceId,
};
use symbiotic_trace::{
    CacheStatus, CacheTrace, InvocationOutcome, ModelInvocationTrace, TimingTrace, UsageTrace,
};
use thiserror::Error;

// The queue runtime behind the `Queued*` providers.
#[cfg(feature = "queue")]
use chrono::Duration as ChronoDuration;
#[cfg(feature = "queue")]
use std::sync::{Mutex, OnceLock};
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
mod queue_runtime;
#[cfg(feature = "queue")]
pub use queue_runtime::{
    CacheEntry, DirResponseCache, InMemoryReceiptSink, ModelAdmission, QueueReceipt,
    QueueReceiptSink, ReceiptStatus, ResponseCache,
};
#[cfg(feature = "queue")]
use queue_runtime::{QueueRuntime, queue_runtime_builders};

mod classify;
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

/// Relative price band for a model. Advisory: hosts use it for routing/budget
/// decisions, not billing.
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
/// Additive-only: every field has a serde default so archived artifacts keep
/// loading as fields are added.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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

    /// Capability flags for this model, resolved from the catalog by identity.
    /// Unknown models get the conservative [`ModelCapabilities::default`] —
    /// deliberately budget-pessimistic (`cost_class: Standard`, never `Free`,
    /// even for uncatalogued `:free` models), so budget routing stays safe.
    pub fn model_capabilities(&self) -> ModelCapabilities {
        default_model_capabilities(&self.identity).unwrap_or_default()
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

impl<T> ModelProvider for Arc<T>
where
    T: ModelProvider + ?Sized,
{
    fn descriptor(&self) -> &ProviderDescriptor {
        (**self).descriptor()
    }
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

/// Production-oriented queue defaults for known model identities.
///
/// Unknown models deliberately return `None` so the host/product layer can apply
/// its operation defaults. Direct use of `ModelQueueConfig::default()` remains a
/// conservative local fallback; local Ollama-style models also get an explicit
/// one-at-a-time catalog entry.
pub fn default_model_queue_config(identity: &ModelIdentity) -> Option<ModelQueueConfig> {
    match identity.queue_id().0.as_str() {
        "chat:deepseek:deepseek-flash" | "chat:deepseek:deepseek-v4-flash" => {
            Some(ModelQueueConfig {
                max_in_flight: 2_000,
                lease_seconds: 600,
                logical_retry_attempts: 4,
                retry_attempts: 4,
                retry_jitter_seconds: 20,
                request_timeout_seconds: Some(600),
                requests_per_minute: None,
                input_units_per_minute: None,
                response_cache_dir: None,
                ..ModelQueueConfig::default()
            })
        }
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
            ..ModelQueueConfig::default()
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
            ..ModelQueueConfig::default()
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
            ..ModelQueueConfig::default()
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
            ..ModelQueueConfig::default()
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
            ..ModelQueueConfig::default()
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
            ..ModelQueueConfig::default()
        }),
        // TypeSafe System One (Jev 1.13). Account limits checked 2026-09-28:
        // 1,200 requests/min and 250,000 tokens/s (15M/min), adjusted
        // dynamically by TypeSafe. One call answers every question in about
        // 0.4 s, so 32 in flight stays under the request limit; short
        // timeout and jitter because callers usually wait on the answer.
        "classify:typesafe:jev-1.13.0" => Some(ModelQueueConfig {
            max_in_flight: 32,
            lease_seconds: 60,
            logical_retry_attempts: 3,
            retry_attempts: 3,
            retry_jitter_seconds: 2,
            request_timeout_seconds: Some(30),
            requests_per_minute: Some(1_200),
            input_units_per_minute: Some(15_000_000),
            response_cache_dir: None,
            ..ModelQueueConfig::default()
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
                ..ModelQueueConfig::default()
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
            ..ModelQueueConfig::default()
        }),
        _ => None,
    }
}

/// Capability flags for known model identities, mirroring the
/// [`default_model_queue_config`] catalog convention: unknown models return
/// `None` so the host can apply its own defaults (or fall back to
/// `ModelCapabilities::default()` via [`ProviderDescriptor::model_capabilities`]).
///
/// Values are advisory seam metadata (context budgets, routing hints), not
/// provider-enforced limits.
pub fn default_model_capabilities(identity: &ModelIdentity) -> Option<ModelCapabilities> {
    match identity.queue_id().0.as_str() {
        "chat:deepseek:deepseek-v4-flash" => Some(ModelCapabilities {
            context_window: Some(128_000),
            tool_use: true,
            structured_output: true,
            reasoning_tier: ReasoningTier::Standard,
            cost_class: CostClass::Budget,
            pricing: None,
        }),
        "chat:deepseek:deepseek-v4-pro" => Some(ModelCapabilities {
            context_window: Some(128_000),
            tool_use: true,
            structured_output: true,
            reasoning_tier: ReasoningTier::Extended,
            cost_class: CostClass::Standard,
            pricing: None,
        }),
        "chat:gemini:gemini-3.5-flash" => Some(ModelCapabilities {
            context_window: Some(1_000_000),
            tool_use: true,
            structured_output: true,
            reasoning_tier: ReasoningTier::Standard,
            cost_class: CostClass::Budget,
            pricing: None,
        }),
        "chat:gemini:gemini-3.1-pro-preview" => Some(ModelCapabilities {
            context_window: Some(1_000_000),
            tool_use: true,
            structured_output: true,
            reasoning_tier: ReasoningTier::Extended,
            cost_class: CostClass::Premium,
            pricing: None,
        }),
        "embedding:gemini:gemini-embedding-2" => Some(ModelCapabilities {
            context_window: Some(2_048),
            tool_use: false,
            structured_output: false,
            reasoning_tier: ReasoningTier::None,
            cost_class: CostClass::Budget,
            pricing: None,
        }),
        "embedding:openrouter:qwen/qwen3-embedding-8b"
        | "embedding:openrouter:qwen/qwen3-embedding-4b" => Some(ModelCapabilities {
            context_window: Some(32_768),
            tool_use: false,
            structured_output: false,
            reasoning_tier: ReasoningTier::None,
            cost_class: CostClass::Budget,
            pricing: None,
        }),
        // TypeSafe System One: typed answers, 64k tokens per request (32k for
        // the state plus the longest question), $0.042 per million input
        // tokens, output free. OpenRouter serves the same version through
        // its `/systemone` route at the same listed token price; its credit
        // purchase fee makes the direct key cheaper when you have one.
        "classify:typesafe:jev-1.13.0" | "classify:openrouter:typesafe/jev-1.13" => {
            Some(ModelCapabilities {
                context_window: Some(64_000),
                tool_use: false,
                structured_output: true,
                reasoning_tier: ReasoningTier::None,
                cost_class: CostClass::Budget,
                pricing: Some(ModelPricing {
                    input_micro_usd_per_million_tokens: 42_000,
                    output_micro_usd_per_million_tokens: 0,
                }),
            })
        }
        "rerank:openrouter:nvidia/llama-nemotron-rerank-vl-1b-v2:free" => Some(ModelCapabilities {
            context_window: None,
            tool_use: false,
            structured_output: false,
            reasoning_tier: ReasoningTier::None,
            cost_class: CostClass::Free,
            pricing: None,
        }),
        // Deliberately pessimistic floor for local models: local qwen-class chat
        // models DO support tool use, but until per-model local entries exist we
        // only guarantee cost (free). Catalogue a model explicitly if routing
        // needs to rely on more.
        _ if identity.operator.0 == "ollama" || identity.operator.0 == "local" => {
            Some(ModelCapabilities {
                context_window: None,
                tool_use: false,
                structured_output: false,
                reasoning_tier: ReasoningTier::None,
                cost_class: CostClass::Free,
                pricing: None,
            })
        }
        _ => None,
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
            None,
            &request,
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
            None,
            &request,
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
            None,
            &request,
            |inner: R, request| async move { inner.rerank(request).await },
            self.inner.clone(),
        )
        .await
    }
}

/// Usage receipts of one queued call.
#[cfg(feature = "queue")]
struct CallReceipts {
    sink: Option<Arc<dyn QueueReceiptSink>>,
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
        error: Option<String>,
        timing: AttemptTiming,
    ) {
        let Some(sink) = &self.sink else {
            return;
        };
        sink.record_receipt(QueueReceipt {
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
    cache: &Option<Arc<dyn ResponseCache>>,
    entry: &CacheEntry<'_>,
) -> Result<Option<Res>, ModelError> {
    let Some(cache) = cache else {
        return Ok(None);
    };
    cache
        .load(entry)?
        .map(|value| {
            serde_json::from_value(value).map_err(|err| ModelError::Cache(err.to_string()))
        })
        .transpose()
}

#[cfg(feature = "queue")]
fn queue_error(err: symbiotic_queue::QueueError) -> ModelError {
    ModelError::Queue(err.to_string())
}

#[cfg(feature = "queue")]
fn elapsed_ms(since: std::time::Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// The arguments are the queue execution boundary: one queued call.
#[cfg(feature = "queue")]
#[allow(clippy::too_many_arguments)]
async fn run_queued<P, Req, Res, Fut>(
    runtime: &QueueRuntime,
    descriptor: ProviderDescriptor,
    capability: ModelCapability,
    kind: &str,
    // Response-cache subdirectory under `kind`. `None` keeps the historical
    // `{cache}/{kind}/{request hash}` path, which is shared by every provider
    // of that kind: two chat models sharing a cache directory can read each
    // other's cached answers. Classification passes a descriptor hash.
    cache_scope: Option<String>,
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
    let queue = &runtime.queue;
    let trace_sink = &runtime.trace_sink;
    let config = &runtime.config;
    let worker_id = &runtime.worker_id;
    let queue_id = runtime
        .queue_id
        .clone()
        .unwrap_or_else(|| descriptor.queue_id());
    let request_hash = hash_json(request)?;
    let request_value =
        serde_json::to_value(request).map_err(|err| ModelError::InvalidRequest(err.to_string()))?;
    let cache = runtime.cache();
    let entry = CacheEntry {
        kind,
        scope: cache_scope.as_deref(),
        request_hash: &request_hash,
        request: &request_value,
    };
    let receipts = CallReceipts {
        sink: runtime.receipt_sink.clone(),
        queue_id: queue_id.clone(),
        kind: kind.to_string(),
        request_hash: request_hash.clone(),
        input_units: request.input_budget_units(),
    };
    if let Some(dir) = &config.request_debug_dir {
        DirResponseCache::new(dir.clone()).store(&entry, &request_value)?;
    }
    if let Some(cached) = load_cached::<Res>(&cache, &entry)? {
        receipts
            .record(
                ReceiptStatus::CacheHit,
                None,
                Some(cached.trace()),
                None,
                AttemptTiming::NONE,
            )
            .await;
        return return_cached_response(cached, &descriptor, trace_sink, request_hash.clone(), None)
            .await;
    }

    let queued_at = std::time::Instant::now();
    // Cooldown + rate-bucket wait accumulated across loop iterations, so the
    // trace can report the throttle-wait vs http-time split (the measured
    // lesson) without changing `queued_ms` semantics.
    let mut throttle_wait = Duration::ZERO;
    // The provider is part of the key: models pooled on one queue share its
    // limits, never each other's attempt budgets or results.
    let idempotency_key = Some(format!(
        "{}:{}:{request_hash}",
        queue_id.0,
        hash_json(&descriptor)?
    ));
    let fresh_enqueue = || {
        queue.enqueue(EnqueueRequest {
            queue_id: queue_id.clone(),
            kind: kind.to_string(),
            payload: model_queue_payload(
                &capability,
                &request_hash,
                &descriptor,
                LogicalRetryState {
                    attempts_used: 0,
                    max_attempts: logical_max_attempts(config),
                },
            ),
            idempotency_key: idempotency_key.clone(),
            run_after: None,
            max_attempts: Some(config.retry_attempts),
            force: false,
        })
    };
    let mut enqueue = fresh_enqueue().await.map_err(queue_error)?;
    receipts
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
            QueueStatus::Dead if budget_renewed(&enqueue.item, config) => {
                enqueue = reenqueue_with_fresh_budget(
                    queue.as_ref(),
                    &queue_id,
                    &descriptor,
                    capability,
                    kind,
                    &request_hash,
                    &idempotency_key,
                    config,
                    &enqueue.item.item_id,
                )
                .await?;
            }
            QueueStatus::Dead => {
                let dead_err = dead_item_retry_error(&enqueue.item);
                if let Some(next) = reenqueue_dead_item(
                    queue.as_ref(),
                    &queue_id,
                    &descriptor,
                    capability,
                    kind,
                    &request_hash,
                    &idempotency_key,
                    &enqueue.item,
                    config,
                    &dead_err,
                )
                .await?
                {
                    enqueue = next;
                } else {
                    return Err(exhausted_request_error(
                        &queue_id,
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
                enqueue = reenqueue_with_fresh_budget(
                    queue.as_ref(),
                    &queue_id,
                    &descriptor,
                    capability,
                    kind,
                    &request_hash,
                    &idempotency_key,
                    config,
                    &enqueue.item.item_id,
                )
                .await?;
            }
            QueueStatus::Pending | QueueStatus::Running | QueueStatus::Failed => {}
        }
    }

    loop {
        if let Some(cached) = load_cached::<Res>(&cache, &entry)? {
            receipts
                .record(
                    ReceiptStatus::CacheHit,
                    Some(&enqueue.item),
                    Some(cached.trace()),
                    None,
                    AttemptTiming::NONE,
                )
                .await;
            return return_cached_response(
                cached,
                &descriptor,
                trace_sink,
                request_hash.clone(),
                Some(enqueue.item.item_id.clone()),
            )
            .await;
        }
        let attempt_started = std::time::Instant::now();
        let permit = match &runtime.admission {
            Some(admission) => Some(
                admission
                    .acquire(&queue_id, config.max_in_flight.max(1))
                    .await?,
            ),
            None => None,
        };
        let throttle_started = std::time::Instant::now();
        wait_for_model_cooldown(queue.as_ref(), &queue_id).await?;
        wait_for_model_budget(&queue_id, config, request).await?;
        let attempt_throttle = throttle_started.elapsed();
        throttle_wait += attempt_throttle;
        let claimed = match queue
            .claim_item(
                &enqueue.item.item_id,
                worker_id,
                config.lease_seconds,
                Some(config.max_in_flight.max(1)),
            )
            .await
        {
            Ok(claimed) => claimed,
            // A retention-bounded backend evicted the item after it turned
            // terminal: queue the request again.
            Err(symbiotic_queue::QueueError::NotFound(_)) => {
                drop(permit);
                enqueue = fresh_enqueue().await.map_err(queue_error)?;
                continue;
            }
            Err(err) => return Err(queue_error(err)),
        };
        let Some(item) = claimed else {
            drop(permit);
            match queue
                .get_item(&enqueue.item.item_id)
                .await
                .map_err(queue_error)?
            {
                None => {
                    enqueue = fresh_enqueue().await.map_err(queue_error)?;
                    continue;
                }
                Some(current) => match current.status {
                    QueueStatus::Dead if budget_renewed(&current, config) => {
                        enqueue = reenqueue_with_fresh_budget(
                            queue.as_ref(),
                            &queue_id,
                            &descriptor,
                            capability,
                            kind,
                            &request_hash,
                            &idempotency_key,
                            config,
                            &current.item_id,
                        )
                        .await?;
                        continue;
                    }
                    QueueStatus::Dead => {
                        let dead_err = dead_item_retry_error(&current);
                        if let Some(next) = reenqueue_dead_item(
                            queue.as_ref(),
                            &queue_id,
                            &descriptor,
                            capability,
                            kind,
                            &request_hash,
                            &idempotency_key,
                            &current,
                            config,
                            &dead_err,
                        )
                        .await?
                        {
                            enqueue = next;
                        } else {
                            return Err(exhausted_request_error(
                                &queue_id, &current, config, &dead_err,
                            ));
                        }
                    }
                    QueueStatus::Succeeded => {
                        if let Some(cached) = load_cached::<Res>(&cache, &entry)? {
                            receipts
                                .record(
                                    ReceiptStatus::CacheHit,
                                    Some(&current),
                                    Some(cached.trace()),
                                    None,
                                    AttemptTiming::NONE,
                                )
                                .await;
                            return return_cached_response(
                                cached,
                                &descriptor,
                                trace_sink,
                                request_hash.clone(),
                                Some(current.item_id),
                            )
                            .await;
                        }
                        enqueue = reenqueue_with_fresh_budget(
                            queue.as_ref(),
                            &queue_id,
                            &descriptor,
                            capability,
                            kind,
                            &request_hash,
                            &idempotency_key,
                            config,
                            &current.item_id,
                        )
                        .await?;
                        continue;
                    }
                    QueueStatus::Pending | QueueStatus::Running | QueueStatus::Failed => {}
                },
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            continue;
        };

        // Queue wait of this attempt: admission plus claim, without throttle.
        let attempt_throttle_ms = u64::try_from(attempt_throttle.as_millis()).unwrap_or(u64::MAX);
        let attempt_queue_wait_ms = elapsed_ms(attempt_started).saturating_sub(attempt_throttle_ms);
        receipts
            .record(
                ReceiptStatus::Running,
                Some(&item),
                None,
                None,
                AttemptTiming {
                    queue_wait_ms: Some(attempt_queue_wait_ms),
                    throttle_wait_ms: Some(attempt_throttle_ms),
                    provider_ms: None,
                },
            )
            .await;
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
                    queue_id.0, timeout
                ))),
            }
        } else {
            call(provider.clone(), request.clone()).await
        };
        let provider_ms = elapsed_ms(provider_started);
        let failed_timing = || AttemptTiming {
            queue_wait_ms: None,
            throttle_wait_ms: None,
            provider_ms: Some(provider_ms),
        };

        match result {
            Ok(mut response) => {
                let mut trace = response.trace().clone();
                trace.queue_item_id = Some(item.item_id.clone());
                trace.request_hash = request_hash.clone();
                let queued_ms = provider_started.duration_since(queued_at).as_millis() as u64;
                let throttle_wait_ms = throttle_wait.as_millis() as u64;
                trace.timing.queued_ms = Some(queued_ms);
                trace.timing.queue_wait_ms = Some(queued_ms.saturating_sub(throttle_wait_ms));
                trace.timing.throttle_wait_ms = Some(throttle_wait_ms);
                trace.timing.provider_ms = Some(provider_ms);
                trace.timing.total_ms = Some(queued_at.elapsed().as_millis() as u64);
                if let Some(trace_sink) = trace_sink {
                    trace_sink
                        .record_model_invocation(trace.clone())
                        .await
                        .map_err(|err| ModelError::Provider(err.to_string()))?;
                }
                response.set_trace(trace.clone());
                if let Some(cache) = &cache {
                    let value = serde_json::to_value(&response)
                        .map_err(|err| ModelError::Cache(err.to_string()))?;
                    cache.store(&entry, &value)?;
                }
                let completed = queue.complete(&item.item_id, worker_id).await;
                heartbeat.abort();
                drop(permit);
                completed.map_err(queue_error)?;
                receipts
                    .record(
                        ReceiptStatus::Succeeded,
                        Some(&item),
                        Some(&trace),
                        None,
                        AttemptTiming {
                            queue_wait_ms: None,
                            throttle_wait_ms: None,
                            provider_ms: Some(provider_ms),
                        },
                    )
                    .await;
                return Ok(response);
            }
            Err(err) if is_retryable(&err, config) => {
                receipts
                    .record(
                        ReceiptStatus::Failed,
                        Some(&item),
                        None,
                        Some(err.to_string()),
                        failed_timing(),
                    )
                    .await;
                let delay_ms =
                    retry_delay_ms(item.attempt, config, &item.item_id, &request_hash, &err);
                if is_transient(&err) {
                    note_model_cooldown(queue.as_ref(), &queue_id, &err, delay_ms).await?;
                }
                // One exact deadline, kept by the backend: this caller and any
                // duplicate waiting on the item retry no earlier than it.
                let outcome = queue
                    .fail_with(
                        &item.item_id,
                        worker_id,
                        Failure {
                            error: err.to_string(),
                            error_class: Some(error_class(&err)),
                            run_after: Some(
                                Utc::now() + ChronoDuration::milliseconds(delay_ms as i64),
                            ),
                        },
                    )
                    .await;
                heartbeat.abort();
                drop(permit);
                let outcome = outcome.map_err(queue_error)?;
                if outcome == FailOutcome::MovedToDead {
                    let dead_item = queue
                        .get_item(&item.item_id)
                        .await
                        .map_err(queue_error)?
                        .unwrap_or(item);
                    if let Some(next) = reenqueue_dead_item(
                        queue.as_ref(),
                        &queue_id,
                        &descriptor,
                        capability,
                        kind,
                        &request_hash,
                        &idempotency_key,
                        &dead_item,
                        config,
                        &err,
                    )
                    .await?
                    {
                        enqueue = next;
                        continue;
                    }
                    emit_failure_trace(
                        &descriptor,
                        trace_sink,
                        Some(dead_item.item_id.clone()),
                        request_hash.clone(),
                        request_sensitivity(request),
                        err.to_string(),
                    )
                    .await?;
                    return Err(exhausted_request_error(&queue_id, &dead_item, config, &err));
                }
            }
            Err(err) => {
                receipts
                    .record(
                        ReceiptStatus::Failed,
                        Some(&item),
                        None,
                        Some(err.to_string()),
                        failed_timing(),
                    )
                    .await;
                let failed = queue
                    .fail_with(
                        &item.item_id,
                        worker_id,
                        Failure {
                            error: err.to_string(),
                            error_class: Some(error_class(&err)),
                            run_after: None,
                        },
                    )
                    .await;
                heartbeat.abort();
                drop(permit);
                failed.map_err(queue_error)?;
                emit_failure_trace(
                    &descriptor,
                    trace_sink,
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

#[cfg(feature = "queue")]
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
) -> u64 {
    retry_backoff_ms(attempt, config.retry_base_delay_ms)
        .saturating_add(
            retry_jitter_seconds(
                config.retry_jitter_seconds,
                item_id,
                request_hash,
                attempt,
                err,
            )
            .saturating_mul(1_000),
        )
        .clamp(1, 120_000)
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
    retry_delay_ms(attempt, &config, item_id, request_hash, err).div_ceil(1_000)
}

#[cfg(feature = "queue")]
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

/// Whether a request another call exhausted (or that was exhausted before a
/// restart) gets a fresh attempt budget: only when the policy renews budgets
/// and the renewal time has passed since the request went dead.
#[cfg(feature = "queue")]
fn budget_renewed(item: &QueueItem, config: &ModelQueueConfig) -> bool {
    config.budget_renewal_seconds.is_some_and(|seconds| {
        Utc::now() - item.updated_at >= ChronoDuration::seconds(seconds as i64)
    })
}

#[cfg(feature = "queue")]
fn logical_max_attempts(config: &ModelQueueConfig) -> u32 {
    config
        .logical_retry_attempts
        .max(config.retry_attempts)
        .max(1)
}

/// Stable class name of an error, kept on failed queue items so a later
/// call reports the same class.
#[cfg(feature = "queue")]
fn error_class(err: &ModelError) -> String {
    match err {
        ModelError::Unavailable(_) => "unavailable".to_string(),
        ModelError::Auth(_) => "auth".to_string(),
        ModelError::RateLimited(_) => "rate_limited".to_string(),
        ModelError::BudgetExhausted(_) => "budget_exhausted".to_string(),
        ModelError::Timeout(_) => "timeout".to_string(),
        ModelError::Unsupported(capability) => format!(
            "unsupported:{}",
            serde_json::to_value(capability)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default()
        ),
        ModelError::InvalidRequest(_) => "invalid_request".to_string(),
        ModelError::Provider(_) => "provider".to_string(),
        ModelError::Queue(_) => "queue".to_string(),
        ModelError::Cache(_) => "cache".to_string(),
    }
}

/// The error a dead item stands for, from its recorded class. Items failed
/// before classes were recorded fall back to reading the message.
#[cfg(feature = "queue")]
fn dead_item_retry_error(item: &QueueItem) -> ModelError {
    let error = item
        .last_error
        .clone()
        .unwrap_or_else(|| "dead queue item".to_string());
    match item.last_error_class.as_deref() {
        Some("unavailable") => ModelError::Unavailable(error),
        Some("auth") => ModelError::Auth(error),
        Some("rate_limited") => ModelError::RateLimited(error),
        Some("budget_exhausted") => ModelError::BudgetExhausted(error),
        Some("timeout") => ModelError::Timeout(error),
        Some("invalid_request") => ModelError::InvalidRequest(error),
        Some("queue") => ModelError::Queue(error),
        Some("cache") => ModelError::Cache(error),
        Some(class) => class
            .strip_prefix("unsupported:")
            .and_then(|capability| {
                serde_json::from_value(Value::String(capability.to_string())).ok()
            })
            .map_or(ModelError::Provider(error), ModelError::Unsupported),
        None => {
            let lower = error.to_ascii_lowercase();
            if lower.contains("rate") || lower.contains("429") {
                ModelError::RateLimited(error)
            } else if lower.contains("timeout") || lower.contains("timed out") {
                ModelError::Timeout(error)
            } else {
                ModelError::Unavailable(error)
            }
        }
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
    if attempts_used >= state.max_attempts {
        return Ok(None);
    }
    let remaining_attempts = state.max_attempts - attempts_used;
    let next_state = LogicalRetryState {
        attempts_used,
        max_attempts: state.max_attempts,
    };
    let payload = model_queue_payload(&capability, request_hash, descriptor, next_state);
    let retry_after_ms = retry_delay_ms(item.attempt, config, &item.item_id, request_hash, err);
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
        .map_err(|err| ModelError::Queue(err.to_string()))?;
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
            max_attempts: config
                .logical_retry_attempts
                .max(config.retry_attempts)
                .max(1),
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
                max_attempts: Some(config.retry_attempts.max(1)),
                force: true,
            },
            current,
        )
        .await
        .map_err(|err| ModelError::Queue(err.to_string()))
}

#[cfg(feature = "queue")]
fn exhausted_request_error(
    queue_id: &QueueId,
    item: &QueueItem,
    config: &ModelQueueConfig,
    last_error: &ModelError,
) -> ModelError {
    let state = logical_retry_state(&item.payload, logical_max_attempts(config));
    let attempts_used = state.attempts_used.saturating_add(item.attempt);
    let message = format!(
        "{} request exhausted after {}/{} logical attempt(s): {}",
        queue_id.0,
        attempts_used,
        state.max_attempts,
        item.last_error
            .clone()
            .unwrap_or_else(|| "unknown provider error".to_string())
    );
    // Keep the class of the last failure, so callers can still tell a rate
    // limit or timeout from a provider fault once retries run out.
    match last_error {
        ModelError::RateLimited(_) => ModelError::RateLimited(message),
        ModelError::Timeout(_) => ModelError::Timeout(message),
        ModelError::Unavailable(_) => ModelError::Unavailable(message),
        ModelError::Auth(_) => ModelError::Auth(message),
        ModelError::BudgetExhausted(_) => ModelError::BudgetExhausted(message),
        ModelError::InvalidRequest(_) => ModelError::InvalidRequest(message),
        ModelError::Queue(_) => ModelError::Queue(message),
        ModelError::Cache(_) => ModelError::Cache(message),
        ModelError::Unsupported(capability) => ModelError::Unsupported(*capability),
        ModelError::Provider(_) => ModelError::Provider(message),
    }
}

#[cfg(feature = "queue")]
static MODEL_COOLDOWNS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
#[cfg(feature = "queue")]
static MODEL_RATE_BUCKETS: OnceLock<Mutex<HashMap<String, RateBucket>>> = OnceLock::new();

#[cfg(feature = "queue")]
trait BudgetedModelRequest {
    fn input_budget_units(&self) -> u64;
}

#[cfg(feature = "queue")]
impl BudgetedModelRequest for ChatRequest {
    fn input_budget_units(&self) -> u64 {
        estimate_token_budget_units(self.messages.iter().map(|message| message.content.as_str()))
    }
}

#[cfg(feature = "queue")]
impl BudgetedModelRequest for EmbeddingRequest {
    fn input_budget_units(&self) -> u64 {
        estimate_token_budget_units(self.inputs.iter().map(String::as_str))
    }
}

#[cfg(feature = "queue")]
impl BudgetedModelRequest for RerankRequest {
    fn input_budget_units(&self) -> u64 {
        estimate_token_budget_units(
            std::iter::once(self.query.as_str()).chain(self.documents.iter().map(String::as_str)),
        )
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

#[cfg(feature = "queue")]
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
            // Keyed by policy too: providers of one model with the same
            // limits share a bucket; a different policy gets its own.
            let key = format!(
                "{}:requests:{requests_per_minute}:{}",
                queue_id.0, config.rate_burst_seconds
            );
            let bucket = guard.entry(key).or_insert_with(|| {
                RateBucket::with_burst(requests_per_minute as f64, config.rate_burst_seconds)
            });
            wait = wait.max(bucket.reserve(1.0));
        }
        if let Some(input_units_per_minute) = config.input_units_per_minute {
            let key = format!(
                "{}:input-units:{input_units_per_minute}:{}",
                queue_id.0, config.rate_burst_seconds
            );
            let bucket = guard.entry(key).or_insert_with(|| {
                RateBucket::with_burst(input_units_per_minute as f64, config.rate_burst_seconds)
            });
            wait = wait.max(bucket.reserve(request.input_budget_units() as f64));
        }
        wait
    };
    if let Some(sleep_for) = sleep_for {
        tokio::time::sleep(sleep_for).await;
    }
    Ok(())
}

#[cfg(feature = "queue")]
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
    let until_instant = Instant::now() + Duration::from_millis(millis);
    let until_utc = Utc::now() + ChronoDuration::milliseconds(millis as i64);
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

#[cfg(feature = "queue")]
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

#[cfg(feature = "queue")]
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

#[cfg(feature = "queue")]
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
    thinking: Option<ThinkingMode>,
    reasoning_effort: Option<String>,
}

/// Provider extension supported by compatible APIs such as DeepSeek.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThinkingMode {
    Enabled,
    Disabled,
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
            thinking: None,
            reasoning_effort: None,
        }
    }

    /// Reuse the consumer's connection pool and timeout policy.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    pub fn with_thinking(mut self, thinking: Option<ThinkingMode>) -> Self {
        self.thinking = thinking;
        self
    }

    pub fn with_reasoning_effort(mut self, effort: impl Into<String>) -> Self {
        let effort = effort.into();
        if !effort.trim().is_empty() {
            self.reasoning_effort = Some(effort);
        }
        self
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
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<&'a str>,
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
            thinking: self
                .thinking
                .map(|mode| serde_json::json!({ "type": mode })),
            reasoning_effort: if self.thinking == Some(ThinkingMode::Disabled) {
                None
            } else {
                self.reasoning_effort.as_deref()
            },
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
                "reported_cost_usd": reported_cost_usd(&raw),
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
    #[cfg(feature = "queue")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "queue")]
    use std::time::Duration;
    #[cfg(feature = "queue")]
    use symbiotic_queue_sqlite::SqliteQueue;

    #[cfg(feature = "queue")]
    static TEST_QUEUE_COUNTER: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "queue")]
    use symbiotic_trace::InMemoryTraceSink;

    #[test]
    fn current_deepseek_flash_name_preserves_shared_parallel_defaults() {
        let current =
            default_model_queue_config(&ModelIdentity::new("chat", "deepseek", "deepseek-flash"))
                .expect("current Flash name must resolve shared queue settings");
        let legacy = default_model_queue_config(&ModelIdentity::new(
            "chat",
            "deepseek",
            "deepseek-v4-flash",
        ))
        .unwrap();
        assert_eq!(current.max_in_flight, 2_000);
        assert_eq!(
            serde_json::to_value(current).unwrap(),
            serde_json::to_value(legacy).unwrap()
        );
    }

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
        assert_eq!(qwen_embedding.max_in_flight, 2_000);
        assert_eq!(qwen_embedding.requests_per_minute, None);
        assert_eq!(gemini_flash.max_in_flight, 100);
        assert_eq!(gemini_flash.requests_per_minute, Some(1_000));
        assert_eq!(gemini_pro.max_in_flight, 500);
        assert_eq!(gemini_pro.requests_per_minute, Some(100));
    }

    #[test]
    fn known_model_capabilities_live_in_catalog() {
        let flash = default_model_capabilities(&ModelIdentity::new(
            "chat",
            "deepseek",
            "deepseek-v4-flash",
        ))
        .unwrap();
        assert_eq!(flash.context_window, Some(128_000));
        assert!(flash.tool_use);
        assert!(flash.structured_output);
        assert_eq!(flash.reasoning_tier, ReasoningTier::Standard);
        assert_eq!(flash.cost_class, CostClass::Budget);

        // Unknown models return None from the catalog; the descriptor method
        // falls back to the conservative default profile.
        let unknown = ModelIdentity::new("chat", "acme", "unknown-model");
        assert!(default_model_capabilities(&unknown).is_none());
        let descriptor = ProviderDescriptor {
            identity: unknown,
            provider_class: ProviderClass::Cloud,
            capabilities: vec![ModelCapability::Chat],
            auth_mode: ProviderAuthMode::None,
            metadata: serde_json::json!({}),
        };
        assert_eq!(
            descriptor.model_capabilities(),
            ModelCapabilities::default()
        );
        assert_eq!(
            ModelCapabilities::default().reasoning_tier,
            ReasoningTier::None
        );
        assert_eq!(ModelCapabilities::default().cost_class, CostClass::Standard);

        // Additive serde: a profile persisted before new fields existed still loads.
        let sparse: ModelCapabilities = serde_json::from_str("{}").unwrap();
        assert_eq!(sparse, ModelCapabilities::default());
    }

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
            Err(ModelError::Unavailable("temporary outage".to_string()))
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
        );

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
        );

        let response = provider.chat(request).await.unwrap();

        assert_eq!(response.text, "same request");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            dir.path()
                .join("cache")
                .join("chat")
                .join(format!("{request_hash}.json"))
                .is_file()
        );
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
        );

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
        );

        let err = provider.chat(chat_request("hello")).await.unwrap_err();

        assert!(err.to_string().contains("exhausted after 2/2"));
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
        );

        let response = provider.chat(chat_request("hello")).await.unwrap();

        assert_eq!(response.text, "hello");
    }

    #[cfg(feature = "queue")]
    #[test]
    fn rate_bucket_waits_after_burst_without_consuming_request_timeout() {
        let mut bucket = RateBucket::new(60.0);
        assert!(bucket.reserve(1.0).is_none());
        assert!(bucket.reserve(1.0).is_some());
    }

    #[cfg(feature = "queue")]
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

    #[cfg(feature = "queue")]
    #[test]
    fn every_error_class_survives_a_dead_item_and_exhaustion() {
        let errors = [
            ModelError::Unavailable("x".into()),
            ModelError::Auth("x".into()),
            ModelError::RateLimited("x".into()),
            ModelError::BudgetExhausted("x".into()),
            ModelError::Timeout("x".into()),
            ModelError::Unsupported(ModelCapability::Rerank),
            ModelError::InvalidRequest("x".into()),
            ModelError::Provider("x".into()),
            ModelError::Queue("x".into()),
            ModelError::Cache("x".into()),
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
                last_error: Some(err.to_string()),
                last_error_class: Some(error_class(&err)),
                created_at: now,
                updated_at: now,
            };
            let replayed = dead_item_retry_error(&item);
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
        }
    }

    #[cfg(feature = "queue")]
    #[test]
    fn rate_bucket_burst_admits_one_window_then_paces() {
        let mut bucket = RateBucket::with_burst(60.0, 60);
        for _ in 0..60 {
            assert!(bucket.reserve(1.0).is_none());
        }
        let wait = bucket.reserve(1.0).expect("the 61st request waits");
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

    #[cfg(feature = "queue")]
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
            ..ModelQueueConfig::default()
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
