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
    /// System One probability classification requests.
    JevClassifier,
}
impl ModelAdapter {
    /// Operation implemented by this adapter.
    pub fn capability(self) -> ModelCapability {
        match self {
            Self::OpenAiChat => ModelCapability::Chat,
            Self::GeminiEmbedding => ModelCapability::Embedding,
            Self::JevClassifier => ModelCapability::Classify,
        }
    }
    fn operation(self) -> &'static str {
        match self {
            Self::OpenAiChat => "chat",
            Self::GeminiEmbedding => "embedding",
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
    /// Required nonzero Gemini embedding dimension count.
    pub dimensions: Option<usize>,
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
fn invalid(_message: &str) -> ModelError {
    ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::InvalidConfiguration)
}
fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

impl ModelQueueConfig {
    /// Refuse unusable execution policy rather than normalizing it silently.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.max_in_flight == 0
            || self.max_in_flight > tokio::sync::Semaphore::MAX_PERMITS
            || self.lease_seconds == 0
            || self.lease_seconds > i64::MAX as u64 / 1000
            || self.logical_retry_attempts == 0
            || self.retry_attempts == 0
            || self
                .request_timeout_seconds
                .is_none_or(|n| n == 0 || n > i64::MAX as u64 / 1000)
            || self.requests_per_minute == Some(0)
            || self.input_units_per_minute == Some(0)
        {
            return Err(invalid(
                "finite nonzero timeout, concurrency, attempts and pacing are required",
            ));
        }
        if !cfg!(debug_assertions) && self.request_debug_dir.is_some() {
            return Err(invalid("request_debug_dir requires a development build"));
        }
        Ok(())
    }
}
impl ModelRegistry {
    /// Load and validate the entire JSON configuration before serving any binding.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ModelError> {
        Self::new(serde_json::from_slice(bytes).map_err(|_| invalid("invalid configuration JSON"))?)
    }
    /// Validate all entries, bindings and account policies atomically.
    pub fn new(config: RegistryConfig) -> Result<Self, ModelError> {
        if config.version != 1 {
            return Err(invalid("unsupported configuration version"));
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
                return Err(invalid("invalid model or unsupported operation/adapter"));
            }
            for id in std::iter::once(&model.id).chain(&model.aliases) {
                if !nonempty(id) || registry.models.insert(id.clone(), index).is_some() {
                    return Err(invalid("duplicate or empty model/alias"));
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
                return Err(invalid("invalid account policy; runtime owns cache paths"));
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
                return Err(invalid(
                    "binding identity and finite nonzero limits are required",
                ));
            }
            let url =
                reqwest::Url::parse(&binding.endpoint).map_err(|_| invalid("invalid endpoint"))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid(
                    "endpoint must be HTTP(S) without credentials, query or fragment",
                ));
            }
            let model = registry.model(&binding.model)?;
            if (model.adapter == ModelAdapter::OpenAiChat
                && binding.limits.max_output_tokens.is_none())
                || (model.adapter != ModelAdapter::OpenAiChat
                    && binding.limits.max_output_tokens.is_some())
            {
                return Err(invalid(
                    "output tokens are required for chat and unsupported for this adapter",
                ));
            }
            let settings = &binding.settings;
            if settings
                .served_model
                .as_deref()
                .is_some_and(|s| !nonempty(s))
            {
                return Err(invalid("empty transport setting"));
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
                    return Err(invalid("unsupported chat settings"));
                }
                ModelAdapter::GeminiEmbedding
                    if settings.dimensions.is_none_or(|n| n == 0)
                        || settings.thinking.is_some()
                        || settings.reasoning_effort.is_some()
                        || settings.served_model.is_some()
                        || binding.endpoint
                            != "https://generativelanguage.googleapis.com/v1beta" =>
                {
                    return Err(invalid("unsupported Gemini endpoint or settings"));
                }
                ModelAdapter::JevClassifier
                    if settings.dimensions.is_some()
                        || settings.thinking.is_some()
                        || settings.reasoning_effort.is_some() =>
                {
                    return Err(invalid("unsupported classifier settings"));
                }
                _ => {}
            }
            let account = registry
                .accounts
                .get(&binding.account_policy)
                .map(|i| &registry.config.accounts[*i])
                .ok_or_else(|| invalid("unknown account policy"))?;
            let key = match &binding.account_sharing_key {
                Some(key) if nonempty(&key.0) => serde_json::json!(["shared", key]),
                Some(_) => return Err(invalid("empty account sharing key")),
                None => serde_json::json!([
                    "tenant-account",
                    binding.identity.tenant,
                    binding.identity.account
                ]),
            }
            .to_string();
            let policy =
                serde_json::to_value(&account.policy).map_err(|_| invalid("invalid policy"))?;
            if shared
                .insert(key, policy.clone())
                .is_some_and(|previous| previous != policy)
            {
                return Err(invalid("shared account policies disagree"));
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
                return Err(invalid("duplicate tenant/provider binding"));
            }
        }
        Ok(registry)
    }
    /// Resolve a canonical model name or alias; unknown names are refused.
    pub fn model(&self, id: &str) -> Result<&ModelEntry, ModelError> {
        self.models
            .get(id)
            .map(|i| &self.config.models[*i])
            .ok_or_else(|| invalid("unknown model or alias"))
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
            .ok_or_else(|| invalid("tenant provider is not configured"))?;
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
