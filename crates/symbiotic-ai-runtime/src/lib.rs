//! Stateful AI provider runtime.
//!
//! A host opens one [`Runtime`] and asks it for ready providers. It never
//! builds queues, backends or queued wrappers itself:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use symbiotic_ai_runtime::{ModelBinding, Runtime, RuntimeConfig};
//! # fn demo(raw_chat: Arc<dyn symbiotic_ai_runtime::ChatProvider>) -> Result<(), symbiotic_ai_runtime::ModelError> {
//! let runtime = Runtime::open(RuntimeConfig {
//!     state_dir: Some("/var/lib/host/ai-runtime".into()),
//!     ..RuntimeConfig::default()
//! })?;
//! let chat = runtime.chat(ModelBinding::new(raw_chat).with_identity(symbiotic_ai_runtime::BindingIdentity::new("tenant", "provider", "1", "account")).with_policy(symbiotic_ai_runtime::ModelQueueConfig::default()))?;
//! # Ok(()) }
//! ```
//!
//! The runtime owns retries and backoff, rate and concurrency limits,
//! cooldowns, attempt budgets, the response cache, traces, usage receipts
//! and persistence:
//!
//! - With a `state_dir`, state lives in a private SQLite database there, so
//!   cooldowns, attempt budgets and cached responses survive restarts. The
//!   directory and everything the runtime keeps in it are owner-only; the
//!   runtime refuses a state directory open to others, owned by someone
//!   else or reached through a symlink.
//! - Without one, dispatch is refused with `SpendLedgerUnavailable`; no
//!   default state directory is chosen.
//!
//! Once a provider call starts, it belongs to the runtime. A caller that
//! stops waiting (a dropped future, a timeout around the call) does not
//! cancel it: the call finishes, records its outcome, fills the cache and
//! releases its queue item, and identical requests get its result.
//!
//! Every provider bound to one configured account shares one
//! concurrency cap, one pair of rate buckets and one cooldown, whichever role
//! or caller uses it. Account bindings must agree on those limits.
//!
//! SQLite stays behind runtime/credential-process implementations; provider
//! and egress contracts do not link it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
pub use symbiotic_core::{AccountSharingKey, BindingIdentity};
use symbiotic_core::{QueueId, QueueItemId};
use symbiotic_model::private_fs;
use symbiotic_model::{
    ModelAdmission, QueuedChatProvider, QueuedClassifierProvider, QueuedEmbeddingProvider,
    QueuedRerankProvider,
};
use symbiotic_queue::{MemoryQueue, QueueBackend};
use symbiotic_queue_sqlite::SqliteQueue;
use symbiotic_trace::TraceSink;

mod execution;
mod maintained;
pub use execution::{ExecutionAttemptStatus, ExecutionError, ExecutionResult};
pub mod spend;
pub use model::{
    AcceptedSpendHandoff, SpendLedger, SpendReceipt, SpendReceiptRef, SpendReservation, SpendState,
};

use maintained::{MaintainedQueue, ResponseRetention};

/// The provider contracts and HTTP providers, for implementing or
/// constructing the raw transports a [`ModelBinding`] wraps. Its `Queued*`
/// types and queue wiring are the runtime's internals; consumer use of them is
/// unsupported.
pub use symbiotic_model as model;
pub use symbiotic_model::{
    CacheEntry, CachedResponse, ChatProvider, ChatRequest, ChatResponse, ClassifierProvider,
    ClassifyRequest, ClassifyResponse, DirResponseCache, EmbeddingProvider, EmbeddingRequest,
    EmbeddingResponse, InMemoryReceiptSink, ModelError, ModelProvider, ModelQueueConfig,
    ProviderDescriptor, QueueReceipt, QueueReceiptSink, RUNTIME_DIAGNOSTICS, ReceiptStatus,
    RerankProvider, RerankRequest, RerankResponse, ResponseCache,
};

/// File name of the persistent queue database inside `state_dir`.
pub const QUEUE_DATABASE: &str = "queue.sqlite";
/// Directory of the runtime's response cache inside `state_dir`.
pub const RESPONSES_DIR: &str = "responses";

/// How the runtime is opened.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Validated deployment registry; no provider is inferred when absent.
    pub registry: Option<Arc<model::ModelRegistry>>,
    /// Private directory required for dispatch. `None` refuses dispatch with
    /// `SpendLedgerUnavailable`. A missing directory is created owner-only.
    pub state_dir: Option<PathBuf>,
    /// Lease-owner prefix for this process. Defaults to the crate name and
    /// process id; a random suffix keeps restarts distinct.
    pub worker_id: Option<String>,
    /// Receives a trace for every provider call and cache hit, unless a
    /// binding supplies its own.
    pub trace_sink: Option<Arc<dyn TraceSink>>,
    /// Receives per-attempt usage receipts, unless a binding supplies its
    /// own.
    pub receipt_sink: Option<Arc<dyn QueueReceiptSink>>,
    /// Persistent state older than this is retired: queue records of
    /// finished calls, and calls orphaned by a crash. Seven days by default.
    /// Retiring a finished call only drops its deduplication record; cached
    /// responses follow `response_max_age` and `response_max_bytes`.
    pub retention: Duration,
    /// Cached responses older than this miss, and the retention sweep
    /// removes them. 30 days by default; `None` keeps them indefinitely.
    pub response_max_age: Option<Duration>,
    /// Past this total size, the retention sweep removes the oldest cached
    /// responses. 1 GiB by default; `None` sets no limit.
    pub response_max_bytes: Option<u64>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            registry: None,
            state_dir: None,
            worker_id: None,
            trace_sink: None,
            receipt_sink: None,
            retention: Duration::from_secs(7 * 24 * 60 * 60),
            response_max_age: Some(Duration::from_secs(30 * 24 * 60 * 60)),
            response_max_bytes: Some(1 << 30),
        }
    }
}

/// Where a bound provider's responses are cached.
#[derive(Clone, Default)]
pub enum ResponseCacheMode {
    /// The runtime's own cache when it is persistent, scoped to the
    /// binding identity and effective transport; no cache when it is in memory.
    #[default]
    Default,
    /// No response cache: every call reaches the provider.
    Off,
    /// A host cache. Its hits must carry the runtime's matching result scope.
    /// See [`ResponseCache`].
    Custom(Arc<dyn ResponseCache>),
}

/// A raw provider (the transport) plus how the runtime should run it.
#[derive(Clone)]
pub struct ModelBinding<P> {
    /// Raw transport whose effective configuration is checked at binding.
    pub provider: P,
    /// Foundation-internal handoff already reserved atomically with its permit.
    #[doc(hidden)]
    pub accepted_spend: Option<AcceptedSpendHandoff>,
    /// Caller-selected logical invocation, for durable status lookup and recovery.
    /// Reusing it with different inputs is refused. `None` derives identity from the request.
    pub invocation: Option<String>,
    /// Foundation-internal capture of the exact attempt selected for this call.
    #[doc(hidden)]
    pub attempt_context: Option<model::ExecutionAttemptContext>,
    /// Required tenant, provider, revision and concrete account.
    pub identity: Option<BindingIdentity>,
    /// Explicit quota pool. `None` isolates by tenant and concrete account.
    /// The same key pools limits across bindings, models and tenants.
    pub account_sharing_key: Option<AccountSharingKey>,
    /// Explicit execution policy, or the configured registry account policy.
    /// Without either, binding is refused.
    /// Its `response_cache_dir` is ignored: use [`ResponseCacheMode`].
    pub policy: Option<ModelQueueConfig>,
    /// Select the runtime cache, disable caching or supply a custom cache.
    pub response_cache: ResponseCacheMode,
    /// Overrides the runtime's receipt sink for this binding.
    pub receipt_sink: Option<Arc<dyn QueueReceiptSink>>,
    /// Overrides the runtime's trace sink for this binding.
    pub trace_sink: Option<Arc<dyn TraceSink>>,
}

impl<P> ModelBinding<P> {
    /// Create an unconfigured binding; supply identity and policy before installation.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            accepted_spend: None,
            invocation: None,
            attempt_context: None,
            identity: None,
            account_sharing_key: None,
            policy: None,
            response_cache: ResponseCacheMode::Default,
            receipt_sink: None,
            trace_sink: None,
        }
    }

    /// Set the tenant, provider principal, configuration revision and account.
    pub fn with_identity(mut self, identity: BindingIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set a caller-selected logical invocation for durable recovery.
    /// Scope it to this binding account and reuse it only for the same inputs.
    pub fn with_invocation(mut self, invocation: impl Into<String>) -> Self {
        self.invocation = Some(invocation.into());
        self
    }

    pub(crate) fn with_attempt_context(mut self, context: model::ExecutionAttemptContext) -> Self {
        self.attempt_context = Some(context);
        self
    }

    /// Explicitly pool account limits with bindings using this same key.
    pub fn with_account_sharing(mut self, key: AccountSharingKey) -> Self {
        self.account_sharing_key = Some(key);
        self
    }

    /// Set the account execution policy; registry bindings must match their configured policy.
    pub fn with_policy(mut self, policy: ModelQueueConfig) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Choose this binding's response cache behavior.
    pub fn with_response_cache(mut self, mode: ResponseCacheMode) -> Self {
        self.response_cache = mode;
        self
    }

    /// Override the runtime receipt sink for this binding.
    pub fn with_receipt_sink(mut self, sink: Arc<dyn QueueReceiptSink>) -> Self {
        self.receipt_sink = Some(sink);
        self
    }

    /// Override the runtime trace sink for this binding.
    pub fn with_trace_sink(mut self, sink: Arc<dyn TraceSink>) -> Self {
        self.trace_sink = Some(sink);
        self
    }
}

/// The limits every binding of one concrete account shares.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedLimits {
    provider_request_limit: Option<u64>,
    max_in_flight: usize,
    requests_per_minute: Option<u32>,
    input_units_per_minute: Option<u64>,
    rate_burst_seconds: u64,
}

impl SharedLimits {
    fn of(policy: &ModelQueueConfig) -> Self {
        Self {
            provider_request_limit: policy.provider_request_limit,
            max_in_flight: policy.max_in_flight.max(1),
            requests_per_minute: policy.requests_per_minute,
            input_units_per_minute: policy.input_units_per_minute,
            rate_burst_seconds: policy.rate_burst_seconds,
        }
    }
}

struct Inner {
    queue: Arc<dyn QueueBackend>,
    admission: ModelAdmission,
    rate_state: model::ModelRateState,
    spend: Arc<dyn SpendLedger>,
    registry: Option<Arc<model::ModelRegistry>>,
    limits: Mutex<HashMap<String, SharedLimits>>,
    state_dir: Option<PathBuf>,
    response_max_age: Option<Duration>,
    worker_id: String,
    trace_sink: Option<Arc<dyn TraceSink>>,
    receipt_sink: Option<Arc<dyn QueueReceiptSink>>,
}

/// Implemented configured operation. Unsupported operations are refused at registry validation.
pub enum ConfiguredProvider {
    /// A configured queued chat adapter.
    Chat(Arc<dyn ChatProvider>),
    /// A configured queued embedding adapter.
    Embedding(Arc<dyn EmbeddingProvider>),
    /// A configured queued probability classifier.
    Classifier(Arc<dyn ClassifierProvider>),
}

/// One stateful AI runtime. Clones share all state.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<Inner>,
}

impl Runtime {
    /// Open the runtime. With a `state_dir`, this creates the directory if
    /// needed, opens (or creates) its queue database and retires state older
    /// than the retention window.
    pub fn open(config: RuntimeConfig) -> Result<Self, ModelError> {
        let worker_id = config
            .worker_id
            .clone()
            .unwrap_or_else(|| format!("symbiotic-ai-runtime:{}", std::process::id()));
        let worker_id = format!("{worker_id}:{}", QueueItemId::new().0);
        let queue: Arc<dyn QueueBackend> = match &config.state_dir {
            Some(dir) => Arc::new(open_persistent_queue(dir, &config)?),
            None => Arc::new(MemoryQueue::new()),
        };
        let spend: Arc<dyn SpendLedger> = match &config.state_dir {
            Some(dir) => Arc::new(spend::SqliteSpendLedger::open(&dir.join(QUEUE_DATABASE))?),
            None => Arc::new(model::UnavailableSpendLedger),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                spend,
                queue,
                admission: ModelAdmission::new(),
                rate_state: model::ModelRateState::default(),
                registry: config.registry,
                limits: Mutex::new(HashMap::new()),
                state_dir: config.state_dir,
                response_max_age: config.response_max_age,
                worker_id,
                trace_sink: config.trace_sink,
                receipt_sink: config.receipt_sink,
            }),
        })
    }

    /// Canonical receipt lookup. Consumer commit refusal never alters this receipt.
    pub fn spend_receipt(
        &self,
        reference: &SpendReceiptRef,
    ) -> Result<Option<SpendReceipt>, ModelError> {
        self.inner.spend.receipt(reference)
    }

    /// Foundation-owned reconciliation; callers must establish external charge evidence.
    pub fn reconcile_spend(
        &self,
        reference: &SpendReceiptRef,
        state: SpendState,
        usage: Option<symbiotic_trace::UsageTrace>,
    ) -> Result<(), ModelError> {
        self.inner.spend.finish(reference, state, usage, None)
    }

    /// An in-memory runtime for configuration inspection; dispatch is refused.
    pub fn in_memory() -> Self {
        Self::open(RuntimeConfig::default()).expect("an in-memory runtime needs no I/O")
    }

    pub fn state_dir(&self) -> Option<&Path> {
        self.inner.state_dir.as_deref()
    }

    pub fn is_persistent(&self) -> bool {
        self.inner.state_dir.is_some()
    }

    /// Remove every cached response whose recorded owner `matches`, for
    /// example all responses to requests from one source when that source
    /// is erased. It sees what the response's trace records: the request's
    /// `source` and `role_binding`, and the model. Returns how many
    /// responses were removed; an in-memory runtime keeps none.
    pub fn purge_responses(
        &self,
        matches: impl Fn(&CachedResponse) -> bool,
    ) -> Result<usize, ModelError> {
        match &self.inner.state_dir {
            Some(dir) => DirResponseCache::new(dir.join(RESPONSES_DIR)).purge(matches),
            None => Ok(0),
        }
    }

    /// Build a configured adapter after resolving its optional credential inside Foundation.
    pub async fn configured_provider(
        &self,
        tenant: &symbiotic_core::TenantId,
        principal: &symbiotic_core::ProviderPrincipalId,
        resolver: &dyn model::CredentialResolver,
    ) -> Result<ConfiguredProvider, ModelError> {
        let registry = self.inner.registry.as_ref().ok_or({
            ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::ModelRegistryIsNotConfigured)
        })?;
        let resolved = registry.binding(tenant, principal)?;
        let config = resolved.binding;
        let auth_mode =
            config
                .secret_ref
                .as_ref()
                .map_or(model::ProviderAuthMode::None, |secret_ref| {
                    model::ProviderAuthMode::ApiKey {
                        secret_ref: secret_ref.clone(),
                    }
                });
        let auth = if config.secret_ref.is_some() {
            resolver.resolve_auth(&auth_mode).await?
        } else {
            model::ResolvedAuth::None
        };
        let key = match auth {
            model::ResolvedAuth::None if config.secret_ref.is_none() => {
                model::SecretValue::new(String::new())
            }
            model::ResolvedAuth::Bearer(key) | model::ResolvedAuth::ApiKey(key)
                if !key.is_empty() =>
            {
                key
            }
            _ => {
                return Err(ModelError::Auth(
                    symbiotic_core::DiagnosticCode::ConfiguredCredentialModeIsUnsupportedOrEmpty,
                ));
            }
        };
        let timeout_seconds = resolved.account.policy.request_timeout_seconds.ok_or({
            ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::FiniteTimeoutIsRequired)
        })?;
        let limits = &config.limits;
        let settings = &config.settings;
        match resolved.model.adapter {
            model::ModelAdapter::OpenAiChat => {
                let mut raw = model::OpenAiCompatibleChatProvider::new(
                    &resolved.model.identity.operator.0,
                    &resolved.model.identity.model.0,
                    &config.endpoint,
                    key,
                )
                .with_timeout(timeout_seconds)?
                .with_request_limit(limits.max_request_bytes)
                .with_response_limit(limits.max_response_bytes)
                .with_output_limit(limits.max_output_tokens.ok_or({
                    ModelError::InvalidRequest(
                        symbiotic_core::DiagnosticCode::ChatOutputLimitRequired,
                    )
                })?)
                .with_thinking(settings.thinking);
                if let Some(effort) = &settings.reasoning_effort {
                    raw = raw.with_reasoning_effort(effort);
                }
                Ok(ConfiguredProvider::Chat(
                    self.chat(self.registry_binding(tenant, principal, raw)?)?,
                ))
            }
            model::ModelAdapter::GeminiEmbedding => {
                let raw = model::GeminiEmbeddingProvider::new(
                    &resolved.model.identity.operator.0,
                    &resolved.model.identity.model.0,
                    key,
                    settings.dimensions.ok_or({
                        ModelError::InvalidRequest(
                            symbiotic_core::DiagnosticCode::EmbeddingDimensionsRequired,
                        )
                    })?,
                )
                .with_timeout(timeout_seconds)?
                .with_request_limit(limits.max_request_bytes)
                .with_response_limit(limits.max_response_bytes);
                Ok(ConfiguredProvider::Embedding(self.embedding(
                    self.registry_binding(tenant, principal, raw)?,
                )?))
            }
            model::ModelAdapter::JevClassifier => {
                let mut raw = model::JevClassifierProvider::new(
                    &resolved.model.identity.operator.0,
                    &resolved.model.identity.model.0,
                    &config.endpoint,
                    key,
                )
                .with_timeout(timeout_seconds)?
                .with_request_limit(limits.max_request_bytes)
                .with_response_limit(limits.max_response_bytes);
                if let Some(served) = &settings.served_model {
                    raw = raw.with_served_model(served);
                }
                Ok(ConfiguredProvider::Classifier(self.classifier(
                    self.registry_binding(tenant, principal, raw)?,
                )?))
            }
        }
    }

    /// Resolve identity and account policy for a raw Foundation adapter. `bind` verifies its effective settings.
    pub fn registry_binding<P>(
        &self,
        tenant: &symbiotic_core::TenantId,
        principal: &symbiotic_core::ProviderPrincipalId,
        provider: P,
    ) -> Result<ModelBinding<P>, ModelError> {
        let registry = self.inner.registry.as_ref().ok_or({
            ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::ModelRegistryIsNotConfigured)
        })?;
        let resolved = registry.binding(tenant, principal)?;
        let mut binding =
            ModelBinding::new(provider).with_identity(resolved.binding.identity.clone());
        binding.account_sharing_key = resolved.binding.account_sharing_key.clone();
        Ok(binding)
    }

    /// A queued chat provider for `binding`.
    pub fn chat<C>(&self, binding: ModelBinding<C>) -> Result<Arc<dyn ChatProvider>, ModelError>
    where
        C: ChatProvider + Clone + 'static,
    {
        binding.provider.validate_configuration()?;
        let bound = self.bind(binding.provider.descriptor(), &binding)?;
        let provider =
            QueuedChatProvider::new(binding.provider, bound.queue, bound.worker_id, bound.policy)
                .with_admission(self.inner.admission.clone())
                .with_rate_state(self.inner.rate_state.clone())
                .with_spend_ledger(self.inner.spend.clone(), binding.accepted_spend.clone());
        Ok(Arc::new(bound.sinks.apply_chat(provider)))
    }

    /// A queued embedding provider for `binding`.
    pub fn embedding<E>(
        &self,
        binding: ModelBinding<E>,
    ) -> Result<Arc<dyn EmbeddingProvider>, ModelError>
    where
        E: EmbeddingProvider + Clone + 'static,
    {
        binding.provider.validate_configuration()?;
        let bound = self.bind(binding.provider.descriptor(), &binding)?;
        let provider = QueuedEmbeddingProvider::new(
            binding.provider,
            bound.queue,
            bound.worker_id,
            bound.policy,
        )
        .with_admission(self.inner.admission.clone())
        .with_rate_state(self.inner.rate_state.clone())
        .with_spend_ledger(self.inner.spend.clone(), binding.accepted_spend.clone());
        Ok(Arc::new(bound.sinks.apply_embedding(provider)))
    }

    /// A queued rerank provider for `binding`.
    pub fn rerank<R>(&self, binding: ModelBinding<R>) -> Result<Arc<dyn RerankProvider>, ModelError>
    where
        R: RerankProvider + Clone + 'static,
    {
        binding.provider.validate_configuration()?;
        let bound = self.bind(binding.provider.descriptor(), &binding)?;
        let provider =
            QueuedRerankProvider::new(binding.provider, bound.queue, bound.worker_id, bound.policy)
                .with_admission(self.inner.admission.clone())
                .with_rate_state(self.inner.rate_state.clone())
                .with_spend_ledger(self.inner.spend.clone(), binding.accepted_spend.clone());
        Ok(Arc::new(bound.sinks.apply_rerank(provider)))
    }

    /// A queued classifier for `binding`.
    pub fn classifier<P>(
        &self,
        binding: ModelBinding<P>,
    ) -> Result<Arc<dyn ClassifierProvider>, ModelError>
    where
        P: ClassifierProvider + Clone + 'static,
    {
        binding.provider.validate_configuration()?;
        let bound = self.bind(binding.provider.descriptor(), &binding)?;
        let provider = QueuedClassifierProvider::new(
            binding.provider,
            bound.queue,
            bound.worker_id,
            bound.policy,
        )
        .with_admission(self.inner.admission.clone())
        .with_rate_state(self.inner.rate_state.clone())
        .with_spend_ledger(self.inner.spend.clone(), binding.accepted_spend.clone());
        Ok(Arc::new(bound.sinks.apply_classifier(provider)))
    }

    /// Resolve a binding's policy, check it against the model's shared
    /// limits, and pick its cache and sinks.
    fn bind<P>(
        &self,
        descriptor: &ProviderDescriptor,
        binding: &ModelBinding<P>,
    ) -> Result<Bound, ModelError> {
        let identity = binding
            .identity
            .clone()
            .filter(BindingIdentity::is_valid)
            .ok_or({
                ModelError::InvalidRequest(
                    symbiotic_core::DiagnosticCode::BindingIdentityIsRequired,
                )
            })?;
        if binding
            .invocation
            .as_ref()
            .is_some_and(|id| id.trim().is_empty())
        {
            return Err(ModelError::InvalidRequest(
                symbiotic_core::DiagnosticCode::InvalidConfiguration,
            ));
        }
        let queue_id = QueueId::new(account_scope(
            &identity,
            binding.account_sharing_key.as_ref(),
        )?);
        let mut policy = if let Some(registry) = &self.inner.registry {
            let resolved = registry.binding(&identity.tenant, &identity.provider)?;
            if resolved.binding.identity != identity
                || resolved.model.identity != descriptor.identity
            {
                return Err(ModelError::InvalidRequest(
                    symbiotic_core::DiagnosticCode::BindingDiffersFromConfiguredIdentityModel,
                ));
            }
            if descriptor.capabilities != resolved.model.operations {
                return Err(ModelError::InvalidRequest(
                    symbiotic_core::DiagnosticCode::AdapterCapabilitiesDifferFromConfiguredModel,
                ));
            }
            if descriptor
                .metadata
                .get("max_request_bytes")
                .and_then(serde_json::Value::as_u64)
                != Some(resolved.binding.limits.max_request_bytes as u64)
                || descriptor
                    .metadata
                    .get("max_response_bytes")
                    .and_then(serde_json::Value::as_u64)
                    != Some(resolved.binding.limits.max_response_bytes as u64)
                || (resolved.model.adapter == model::ModelAdapter::OpenAiChat
                    && descriptor
                        .metadata
                        .get("max_output_tokens")
                        .and_then(serde_json::Value::as_u64)
                        != resolved.binding.limits.max_output_tokens.map(u64::from))
            {
                return Err(ModelError::InvalidRequest(
                    symbiotic_core::DiagnosticCode::AdapterBoundsDifferFromConfiguredBinding,
                ));
            }
            let settings = &resolved.binding.settings;
            if descriptor
                .metadata
                .get("endpoint")
                .and_then(serde_json::Value::as_str)
                != Some(resolved.binding.endpoint.as_str())
                || descriptor
                    .metadata
                    .get("thinking")
                    .and_then(serde_json::Value::as_str)
                    != settings.thinking.map(|mode| match mode {
                        model::ThinkingMode::Enabled => "enabled",
                        model::ThinkingMode::Disabled => "disabled",
                    })
                || descriptor
                    .metadata
                    .get("reasoning_effort")
                    .and_then(serde_json::Value::as_str)
                    != settings.reasoning_effort.as_deref()
                || descriptor
                    .metadata
                    .get("dimensions")
                    .and_then(serde_json::Value::as_u64)
                    != settings.dimensions.map(|n| n as u64)
                || (resolved.model.adapter == model::ModelAdapter::JevClassifier
                    && descriptor
                        .metadata
                        .get("served_model")
                        .and_then(serde_json::Value::as_str)
                        != Some(
                            settings
                                .served_model
                                .as_deref()
                                .unwrap_or(&resolved.model.identity.model.0),
                        ))
                || binding.account_sharing_key != resolved.binding.account_sharing_key
            {
                return Err(ModelError::InvalidRequest(
                    symbiotic_core::DiagnosticCode::EffectiveTransportDiffersFromConfiguredBinding,
                ));
            }
            if let Some(policy) = &binding.policy
                && serde_json::to_value(policy).map_err(|_e| {
                    ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::InvalidConfiguration)
                })? != serde_json::to_value(&resolved.account.policy).map_err(|_e| {
                    ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::InvalidConfiguration)
                })?
            {
                return Err(ModelError::InvalidRequest(
                    symbiotic_core::DiagnosticCode::BindingOverridesConfiguredAccountPolicy,
                ));
            }
            resolved.account.policy.clone()
        } else {
            binding.policy.clone().ok_or({
                ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::BindingRequiresAnExplicitExecutionPolicyOrConfiguredRegistry)
            })?
        };
        policy.validate()?;
        policy.response_cache_dir = None;
        self.register_limits(&queue_id, &policy)?;
        let cache = match &binding.response_cache {
            ResponseCacheMode::Off => None,
            ResponseCacheMode::Custom(cache) => Some(cache.clone()),
            ResponseCacheMode::Default => self.inner.state_dir.as_ref().map(|dir| {
                Arc::new(
                    DirResponseCache::new(dir.join(RESPONSES_DIR))
                        .with_max_age(self.inner.response_max_age),
                ) as Arc<dyn ResponseCache>
            }),
        };
        Ok(Bound {
            queue: self.inner.queue.clone(),
            worker_id: self.inner.worker_id.clone(),
            policy,
            sinks: Sinks {
                invocation: binding.invocation.clone(),
                attempt_context: binding.attempt_context.clone(),
                queue_id,
                identity,
                trace: binding
                    .trace_sink
                    .clone()
                    .or_else(|| self.inner.trace_sink.clone()),
                receipt: binding
                    .receipt_sink
                    .clone()
                    .or_else(|| self.inner.receipt_sink.clone()),
                cache,
            },
        })
    }

    fn register_limits(
        &self,
        queue_id: &QueueId,
        policy: &ModelQueueConfig,
    ) -> Result<(), ModelError> {
        let limits = SharedLimits::of(policy);
        let mut registered = self.inner.limits.lock().map_err(|_| {
            ModelError::Queue(symbiotic_core::DiagnosticCode::RuntimePolicyLockPoisoned)
        })?;
        match registered.get(&queue_id.0) {
            Some(existing) if *existing != limits => Err(ModelError::InvalidRequest(
                symbiotic_core::DiagnosticCode::InvalidConfiguration,
            )),
            Some(_) => Ok(()),
            None => {
                self.inner
                    .admission
                    .register(queue_id, limits.max_in_flight)?;
                registered.insert(queue_id.0.clone(), limits);
                Ok(())
            }
        }
    }
}

struct Bound {
    queue: Arc<dyn QueueBackend>,
    worker_id: String,
    policy: ModelQueueConfig,
    sinks: Sinks,
}

struct Sinks {
    invocation: Option<String>,
    attempt_context: Option<model::ExecutionAttemptContext>,
    queue_id: QueueId,
    identity: BindingIdentity,
    trace: Option<Arc<dyn TraceSink>>,
    receipt: Option<Arc<dyn QueueReceiptSink>>,
    cache: Option<Arc<dyn ResponseCache>>,
}

macro_rules! apply_sinks {
    ($name:ident, $ty:ident) => {
        fn $name<P>(self, mut provider: $ty<P>) -> $ty<P> {
            provider = provider
                .with_queue_id(self.queue_id)
                .with_binding_identity(self.identity);
            if let Some(invocation) = self.invocation {
                provider = provider.with_invocation(invocation);
            }
            if let Some(context) = self.attempt_context {
                provider = provider.with_attempt_context(context);
            }
            if let Some(sink) = self.trace {
                provider = provider.with_trace_sink(sink);
            }
            if let Some(sink) = self.receipt {
                provider = provider.with_receipt_sink(sink);
            }
            if let Some(cache) = self.cache {
                provider = provider.with_response_cache(cache);
            }
            provider
        }
    };
}

impl Sinks {
    apply_sinks!(apply_chat, QueuedChatProvider);
    apply_sinks!(apply_embedding, QueuedEmbeddingProvider);
    apply_sinks!(apply_rerank, QueuedRerankProvider);
    apply_sinks!(apply_classifier, QueuedClassifierProvider);
}

fn open_persistent_queue(
    dir: &Path,
    config: &RuntimeConfig,
) -> Result<MaintainedQueue, ModelError> {
    // The state directory is the host's: it must already be private, or be
    // created so. Inside it, everything is the runtime's own: owner-only,
    // with wider permissions from earlier versions tightened, and no
    // symlinks.
    private_fs::ensure_private_dir(dir).map_err(|err| io_error(dir, err))?;
    let responses = dir.join(RESPONSES_DIR);
    match std::fs::symlink_metadata(&responses) {
        Ok(_) => {
            private_fs::ensure_owned_tree(&responses).map_err(|err| io_error(&responses, err))?
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_error(&responses, err)),
    }
    let path = dir.join(QUEUE_DATABASE);
    private_fs::ensure_private_file(&path).map_err(|err| io_error(&path, err))?;
    // SQLite gives its journal files the database's mode; adopt any that
    // an earlier version left.
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = dir.join(format!("{QUEUE_DATABASE}{suffix}"));
        if std::fs::symlink_metadata(&sidecar).is_ok() {
            private_fs::ensure_owned_file(&sidecar).map_err(|err| io_error(&sidecar, err))?;
        }
    }
    let queue = SqliteQueue::open(&path)
        .map_err(|_err| ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure))?;
    let queue = MaintainedQueue::new(
        queue,
        config.retention,
        ResponseRetention {
            cache: DirResponseCache::new(responses),
            max_age: config.response_max_age,
            max_bytes: config.response_max_bytes,
        },
    );
    queue.maintain()?;
    Ok(queue)
}

fn io_error(_path: &Path, _err: std::io::Error) -> ModelError {
    ModelError::Queue(symbiotic_core::DiagnosticCode::QueueFailure)
}

/// Canonical account key shared by pacing, reservation and credential acceptance.
#[doc(hidden)]
pub fn account_scope(
    identity: &BindingIdentity,
    sharing: Option<&AccountSharingKey>,
) -> Result<String, ModelError> {
    let scope = match sharing {
        Some(key) if !key.0.trim().is_empty() => serde_json::json!({"shared": key}),
        Some(_) => {
            return Err(ModelError::InvalidRequest(
                symbiotic_core::DiagnosticCode::AccountSharingKeyIsEmpty,
            ));
        }
        None => serde_json::json!({"tenant": identity.tenant, "account": identity.account}),
    };
    Ok(format!(
        "account:{}",
        model::configuration_revision(&scope)?.0
    ))
}
