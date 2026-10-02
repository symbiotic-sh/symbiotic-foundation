//! Validated deployment configuration. Model metadata grants no data authority.
use crate::{ModelCapabilities, ModelCapability, ModelError, ModelQueueConfig, ThinkingMode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use symbiotic_core::{
    AccountSharingKey, BindingIdentity, ModelIdentity, ProviderPrincipalId, TenantId,
};

/// Installed HTTP adapter, rather than a provider-class routing policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAdapter {
    /// Compatible chat completions over HTTP.
    OpenAiChat,
    /// Gemini single and batch embedding requests.
    GeminiEmbedding,
    /// OpenAI/OpenRouter compatible batch embeddings, including Qwen.
    OpenAiEmbedding,
    /// Ollama's single-input `/api/embeddings` protocol.
    OllamaEmbedding,
    /// Cohere/OpenRouter compatible reranking.
    CohereRerank,
    /// System One probability classification requests.
    JevClassifier,
}
impl ModelAdapter {
    /// Operation implemented by this adapter.
    pub fn capability(self) -> ModelCapability {
        match self {
            Self::OpenAiChat => ModelCapability::Chat,
            Self::GeminiEmbedding | Self::OpenAiEmbedding | Self::OllamaEmbedding => {
                ModelCapability::Embedding
            }
            Self::CohereRerank => ModelCapability::Rerank,
            Self::JevClassifier => ModelCapability::Classify,
        }
    }
    fn operation(self) -> &'static str {
        match self {
            Self::OpenAiChat => "chat",
            Self::GeminiEmbedding | Self::OpenAiEmbedding | Self::OllamaEmbedding => "embedding",
            Self::CohereRerank => "rerank",
            Self::JevClassifier => "classify",
        }
    }
}

/// A canonical model entry; aliases resolve to this same entry and metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEntry {
    /// Canonical lookup name for this model.
    pub id: String,
    /// Additional lookup names resolving to this exact entry.
    pub aliases: Vec<String>,
    /// Effective operation, operator and model name.
    pub identity: ModelIdentity,
    /// Installed transport implementation.
    pub adapter: ModelAdapter,
    /// Supported operations; must match the installed adapter.
    pub operations: Vec<ModelCapability>,
    /// Declared features and advisory pricing; grants no execution authority.
    pub capabilities: ModelCapabilities,
    /// Required when advisory prices are supplied, e.g. source URL and date.
    pub pricing_provenance: Option<PricingProvenance>,
}
/// Source and date of an advisory tariff, independent of execution authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PricingProvenance {
    /// Reference identifying the tariff source.
    pub source: String,
    /// Date of the tariff observation in YYYY-MM-DD format.
    pub date: String,
}
/// Hard encoded request and HTTP response limits, in bytes, per binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLimits {
    /// Maximum encoded HTTP request body bytes; required and nonzero.
    pub max_request_bytes: usize,
    /// Maximum buffered HTTP response body bytes, including errors.
    pub max_response_bytes: usize,
    /// Required nonzero output ceiling for chat; unsupported for other adapters.
    pub max_output_tokens: Option<u32>,
}
/// Effective request settings; unsupported settings are refused at startup.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportSettings {
    /// Optional compatible chat thinking mode.
    pub thinking: Option<ThinkingMode>,
    /// Optional nonempty chat effort; refused when thinking is disabled.
    pub reasoning_effort: Option<String>,
    /// Required nonzero default output dimension count for embeddings.
    pub dimensions: Option<usize>,
    /// Required full-vector ceiling for compatible embeddings; reduced output
    /// dimensions must not exceed it. No model-name defaults are inferred.
    pub embedding_full_dimensions: Option<usize>,
    /// Required usable input token capacity of the deployed compatible embedder,
    /// after reserving special/template/task tokens. One token per UTF-8 byte is
    /// used for conservative admission with supported byte-level tokenizers.
    pub embedding_input_tokens: Option<usize>,
    /// Required hard sum of query and candidate UTF-8 bytes for reranking.
    pub rerank_input_bytes: Option<usize>,
    /// Required hard candidate count for reranking, checked before encoding.
    pub rerank_candidates: Option<usize>,
    /// Required usable query/document token capacity of the deployed reranker,
    /// after reserving provider/model special and template tokens. Admission uses
    /// one token per UTF-8 byte as a conservative bound, not an average estimate.
    /// Also sent as `max_tokens_per_doc` to disable the provider's default cutoff.
    pub rerank_context_tokens: Option<usize>,
    /// Required provider/model query token capacity; must fit the usable context.
    pub rerank_query_tokens: Option<usize>,
    /// Optional expected System One served model name.
    pub served_model: Option<String>,
}
/// A tenant's provider principal with a concrete account and config revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantProviderBinding {
    /// Tenant, provider principal, revision and concrete account.
    pub identity: BindingIdentity,
    /// Canonical model lookup name or alias.
    pub model: String,
    /// Effective HTTP(S) API base without credentials, query or fragment.
    pub endpoint: String,
    /// Opaque credential reference; None selects keyless execution.
    pub secret_ref: Option<String>,
    /// Lookup name of the account execution policy.
    pub account_policy: String,
    /// Explicit quota pool; None isolates by tenant and concrete account.
    pub account_sharing_key: Option<AccountSharingKey>,
    /// Hard transport limits enforced by the adapter.
    pub limits: ProviderLimits,
    /// Effective adapter-specific request settings.
    pub settings: TransportSettings,
}
/// Explicit account execution policy. No operator/model defaults are inferred.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountExecutionPolicy {
    /// Unique account policy lookup name.
    pub id: String,
    /// Explicit concurrency, pacing, timeout and retry policy.
    pub policy: ModelQueueConfig,
}
/// Current format only; examples configure no implicit provider.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    /// Current configuration format version; must be 1.
    pub version: u16,
    /// Model catalogue entries; duplicates and ambiguous aliases are refused.
    pub models: Vec<ModelEntry>,
    /// Explicit tenant/provider bindings; no implicit bindings are inferred.
    pub bindings: Vec<TenantProviderBinding>,
    /// Named account execution policies used by bindings.
    pub accounts: Vec<AccountExecutionPolicy>,
}
/// Immutable validated configuration with keyed model and tenant lookups.
#[derive(Clone, Debug)]
pub struct ModelRegistry {
    config: RegistryConfig,
    models: HashMap<String, usize>,
    bindings: HashMap<(TenantId, ProviderPrincipalId), usize>,
    accounts: HashMap<String, usize>,
}
/// References to one fully resolved configuration, never credentials.
pub struct RegistryBinding<'a> {
    /// Resolved tenant/provider configuration.
    pub binding: &'a TenantProviderBinding,
    /// Canonical model entry, including alias resolution.
    pub model: &'a ModelEntry,
    /// Resolved account execution policy.
    pub account: &'a AccountExecutionPolicy,
}
fn invalid() -> ModelError {
    ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::InvalidConfiguration)
}
fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

impl TransportSettings {
    pub(crate) fn validate_retrieval(&self, adapter: ModelAdapter) -> Result<(), ModelError> {
        let embedding = matches!(
            adapter,
            ModelAdapter::OpenAiEmbedding | ModelAdapter::OllamaEmbedding
        );
        let rerank = adapter == ModelAdapter::CohereRerank;
        if (!embedding
            && (self.embedding_full_dimensions.is_some() || self.embedding_input_tokens.is_some()))
            || (!rerank
                && (self.rerank_input_bytes.is_some()
                    || self.rerank_candidates.is_some()
                    || self.rerank_context_tokens.is_some()
                    || self.rerank_query_tokens.is_some()))
            || (embedding
                && (self.dimensions.is_none_or(|n| n == 0)
                    || self.embedding_full_dimensions.is_none_or(|n| n == 0)
                    || self.embedding_input_tokens.is_none_or(|n| n == 0)
                    || self.dimensions > self.embedding_full_dimensions))
            || (rerank
                && (self.dimensions.is_some()
                    || self.rerank_input_bytes.is_none_or(|n| n == 0)
                    || self.rerank_candidates.is_none_or(|n| n == 0)
                    || self.rerank_context_tokens.is_none_or(|n| n == 0)
                    || self.rerank_query_tokens.is_none_or(|n| n == 0)
                    || self.rerank_query_tokens > self.rerank_context_tokens))
            || ((embedding || rerank)
                && (self.thinking.is_some()
                    || self.reasoning_effort.is_some()
                    || self.served_model.is_some()))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Validate endpoints before they can enter public provider descriptors.
pub(crate) fn validate_endpoint(endpoint: &str) -> Result<(), ModelError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

impl ModelQueueConfig {
    /// Refuse unusable execution policy rather than normalizing it silently.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self
            .provider_request_limit
            .is_some_and(|n| n > i64::MAX as u64)
            || self.max_in_flight == 0
            || self.max_in_flight > tokio::sync::Semaphore::MAX_PERMITS
            || self.lease_seconds == 0
            || i64::try_from(self.lease_seconds)
                .ok()
                .and_then(chrono::Duration::try_seconds)
                .and_then(|duration| chrono::Utc::now().checked_add_signed(duration))
                .is_none()
            || self.retry_jitter_seconds.checked_add(1).is_none()
            || self.budget_renewal_seconds.is_some_and(|seconds| {
                i64::try_from(seconds)
                    .ok()
                    .and_then(chrono::Duration::try_seconds)
                    .and_then(|duration| chrono::Utc::now().checked_add_signed(duration))
                    .is_none()
            })
            || self.logical_retry_attempts == 0
            || self.retry_attempts == 0
            || self
                .request_timeout_seconds
                .is_none_or(|n| n == 0 || n > i64::MAX as u64 / 1000)
            || self.requests_per_minute == Some(0)
            || self.input_units_per_minute == Some(0)
        {
            return Err(invalid());
        }
        if !cfg!(debug_assertions) && self.request_debug_dir.is_some() {
            return Err(invalid());
        }
        Ok(())
    }
}
impl ModelRegistry {
    /// Load and validate the entire JSON configuration before serving any binding.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ModelError> {
        Self::new(serde_json::from_slice(bytes).map_err(|_| invalid())?)
    }
    /// Validate all entries, bindings and account policies atomically.
    pub fn new(config: RegistryConfig) -> Result<Self, ModelError> {
        if config.version != 1 {
            return Err(invalid());
        }
        let mut registry = Self {
            config,
            models: HashMap::new(),
            bindings: HashMap::new(),
            accounts: HashMap::new(),
        };
        let mut identities = HashSet::new();
        for (index, model) in registry.config.models.iter().enumerate() {
            if !identities.insert(model.identity.clone())
                || !nonempty(&model.id)
                || !nonempty(&model.identity.operator.0)
                || !nonempty(&model.identity.model.0)
                || model.identity.operation.0 != model.adapter.operation()
                || model.operations != [model.adapter.capability()]
                || model.capabilities.context_window == Some(0)
                || (model.capabilities.pricing.is_some()
                    && !model.pricing_provenance.as_ref().is_some_and(|p| {
                        nonempty(&p.source)
                            && chrono::NaiveDate::parse_from_str(&p.date, "%Y-%m-%d").is_ok()
                    }))
            {
                return Err(invalid());
            }
            for id in std::iter::once(&model.id).chain(&model.aliases) {
                if !nonempty(id) || registry.models.insert(id.clone(), index).is_some() {
                    return Err(invalid());
                }
            }
        }
        for (index, account) in registry.config.accounts.iter().enumerate() {
            account.policy.validate()?;
            if !nonempty(&account.id)
                || registry
                    .accounts
                    .insert(account.id.clone(), index)
                    .is_some()
                || account.policy.response_cache_dir.is_some()
            {
                return Err(invalid());
            }
        }
        let mut shared = HashMap::new();
        for (index, binding) in registry.config.bindings.iter().enumerate() {
            if !binding.identity.is_valid()
                || binding.limits.max_request_bytes == 0
                || binding.limits.max_response_bytes == 0
                || binding.limits.max_output_tokens == Some(0)
                || binding.secret_ref.as_deref().is_some_and(|s| !nonempty(s))
            {
                return Err(invalid());
            }
            validate_endpoint(&binding.endpoint)?;
            let model = registry.model(&binding.model)?;
            if (model.adapter == ModelAdapter::OpenAiChat
                && binding.limits.max_output_tokens.is_none())
                || (model.adapter != ModelAdapter::OpenAiChat
                    && binding.limits.max_output_tokens.is_some())
            {
                return Err(invalid());
            }
            let settings = &binding.settings;
            settings.validate_retrieval(model.adapter)?;
            if settings
                .served_model
                .as_deref()
                .is_some_and(|s| !nonempty(s))
            {
                return Err(invalid());
            }
            if model.adapter == ModelAdapter::OpenAiChat {
                crate::validate_chat_settings(
                    settings.thinking,
                    settings.reasoning_effort.as_deref(),
                )?;
            }
            match model.adapter {
                ModelAdapter::OpenAiChat
                    if settings.dimensions.is_some() || settings.served_model.is_some() =>
                {
                    return Err(invalid());
                }
                ModelAdapter::GeminiEmbedding
                    if settings.dimensions.is_none_or(|n| n == 0)
                        || settings.thinking.is_some()
                        || settings.reasoning_effort.is_some()
                        || settings.served_model.is_some()
                        || binding.endpoint
                            != "https://generativelanguage.googleapis.com/v1beta" =>
                {
                    return Err(invalid());
                }
                ModelAdapter::JevClassifier
                    if settings.dimensions.is_some()
                        || settings.thinking.is_some()
                        || settings.reasoning_effort.is_some() =>
                {
                    return Err(invalid());
                }
                _ => {}
            }
            let account = registry
                .accounts
                .get(&binding.account_policy)
                .map(|i| &registry.config.accounts[*i])
                .ok_or_else(invalid)?;
            let key = match &binding.account_sharing_key {
                Some(key) if nonempty(&key.0) => serde_json::json!(["shared", key]),
                Some(_) => return Err(invalid()),
                None => serde_json::json!([
                    "tenant-account",
                    binding.identity.tenant,
                    binding.identity.account
                ]),
            }
            .to_string();
            let policy = serde_json::to_value(&account.policy).map_err(|_| invalid())?;
            if shared
                .insert(key, policy.clone())
                .is_some_and(|previous| previous != policy)
            {
                return Err(invalid());
            }
            if registry
                .bindings
                .insert(
                    (
                        binding.identity.tenant.clone(),
                        binding.identity.provider.clone(),
                    ),
                    index,
                )
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(registry)
    }
    /// Resolve a canonical model name or alias; unknown names are refused.
    pub fn model(&self, id: &str) -> Result<&ModelEntry, ModelError> {
        self.models
            .get(id)
            .map(|i| &self.config.models[*i])
            .ok_or_else(invalid)
    }
    /// Resolve a configured tenant/provider pair without accessing credentials.
    pub fn binding(
        &self,
        tenant: &TenantId,
        provider: &ProviderPrincipalId,
    ) -> Result<RegistryBinding<'_>, ModelError> {
        let binding = self
            .bindings
            .get(&(tenant.clone(), provider.clone()))
            .map(|i| &self.config.bindings[*i])
            .ok_or_else(invalid)?;
        Ok(RegistryBinding {
            model: self.model(&binding.model)?,
            account: &self.config.accounts[self.accounts[&binding.account_policy]],
            binding,
        })
    }
    /// Inspect the immutable validated configuration.
    pub fn config(&self) -> &RegistryConfig {
        &self.config
    }
}
