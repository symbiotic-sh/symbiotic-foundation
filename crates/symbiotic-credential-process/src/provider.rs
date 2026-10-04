//! Track dispatch and project sanitized model output into credential-process replies.
use crate::{
    RouteConfig, RouteProvider,
    secrets::{Secret, SecretSource},
};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use symbiotic_ai_runtime::{
    model::{
        AnthropicChatProvider, CredentialBoundary, GeminiEmbeddingProvider,
        OpenAiCompatibleChatProvider,
    },
    *,
};
use symbiotic_egress::{DispatchDiagnostic, EgressError, ProviderOutput, ProviderPayload};
use symbiotic_trace::{ModelInvocationTrace, UsageTrace};

#[derive(Clone)]
struct Dispatched<P> {
    inner: P,
    started: Arc<AtomicBool>,
}
impl<P: ModelProvider> Dispatched<P> {
    fn outcome<T>(&self, result: Result<T, ModelError>) -> Result<T, ModelError> {
        if result.as_ref().err().is_some_and(|error| {
            !matches!(error, ModelError::Timeout(_))
                && self.inner.failure_charge(error) == model::FailureCharge::KnownZero
        }) {
            self.started.store(false, Ordering::SeqCst);
        }
        result
    }
}
impl<P: ModelProvider> ModelProvider for Dispatched<P> {
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }
    fn validate_configuration(&self) -> Result<(), ModelError> {
        self.inner.validate_configuration()
    }
    fn credential_fingerprint(&self) -> Option<String> {
        self.inner.credential_fingerprint()
    }
    fn failure_charge(&self, error: &ModelError) -> model::FailureCharge {
        self.inner.failure_charge(error)
    }
    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        self.inner.credential_boundary()
    }
}
#[async_trait]
impl<P: ChatProvider> ChatProvider for Dispatched<P> {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        self.started.store(true, Ordering::SeqCst);
        let mut response = self.outcome(self.inner.chat(request).await)?;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}
#[async_trait]
impl<P: EmbeddingProvider> EmbeddingProvider for Dispatched<P> {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        self.started.store(true, Ordering::SeqCst);
        let mut response = self.outcome(self.inner.embed(request).await)?;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}
#[async_trait]
impl<P: RerankProvider> RerankProvider for Dispatched<P> {
    async fn rerank(&self, request: RerankRequest) -> Result<RerankResponse, ModelError> {
        self.started.store(true, Ordering::SeqCst);
        let mut response = self.outcome(self.inner.rerank(request).await)?;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}

// Once the raw adapter starts, retain the reservation unless it establishes
// trusted KnownZero evidence. Queue/setup failures before that boundary are
// known not to have reached HTTP.
pub(crate) struct ExecuteError {
    pub(crate) code: EgressError,
    pub(crate) may_have_dispatched: bool,
}

impl From<EgressError> for ExecuteError {
    fn from(code: EgressError) -> Self {
        Self {
            code,
            may_have_dispatched: false,
        }
    }
}

pub(crate) fn route_binding<P>(
    runtime: &Runtime,
    route: &RouteConfig,
    provider: P,
) -> Result<ModelBinding<P>, EgressError> {
    runtime
        .registry_binding(
            &model::TenantId(route.tenant.clone()),
            &model::ProviderPrincipalId(route.route.clone()),
            provider,
        )
        .map_err(|_| EgressError::InvalidRequest)
}

fn accepted_route_binding<P>(
    runtime: &Runtime,
    route: &RouteConfig,
    provider: P,
    handoff: model::AcceptedSpendHandoff,
) -> Result<ModelBinding<P>, EgressError> {
    let mut binding = route_binding(runtime, route, provider)?;
    binding.accepted_spend = Some(handoff);
    Ok(binding.with_response_cache(ResponseCacheMode::Off))
}

pub(crate) fn resolved_route<'a>(
    runtime: &'a Runtime,
    route: &RouteConfig,
) -> Result<model::RegistryBinding<'a>, EgressError> {
    runtime
        .registry()
        .ok_or(EgressError::InvalidRequest)?
        .binding(
            &model::TenantId(route.tenant.clone()),
            &model::ProviderPrincipalId(route.route.clone()),
        )
        .map_err(|_| EgressError::InvalidRequest)
}

pub(crate) fn route_settings(
    route: &RouteConfig,
) -> (model::ModelAdapter, &str, model::TransportSettings) {
    let mut settings = model::TransportSettings::default();
    let (adapter, operator) = match &route.provider {
        RouteProvider::OpenAiChat { operator } => {
            (model::ModelAdapter::OpenAiChat, operator.as_str())
        }
        RouteProvider::AnthropicChat { operator, thinking } => {
            settings.thinking = *thinking;
            (model::ModelAdapter::AnthropicChat, operator.as_str())
        }
        RouteProvider::GeminiEmbedding { dimensions } => {
            settings.dimensions = Some(*dimensions);
            (model::ModelAdapter::GeminiEmbedding, "gemini")
        }
        RouteProvider::CompatibleEmbedding {
            adapter,
            operator,
            dimensions,
            embedding_full_dimensions,
            embedding_input_tokens,
        } => {
            settings.dimensions = Some(*dimensions);
            settings.embedding_full_dimensions = Some(*embedding_full_dimensions);
            settings.embedding_input_tokens = Some(*embedding_input_tokens);
            (*adapter, operator.as_str())
        }
        RouteProvider::CohereRerank {
            operator,
            rerank_input_bytes,
            rerank_candidates,
            rerank_context_tokens,
            rerank_query_tokens,
        } => {
            settings.rerank_input_bytes = Some(*rerank_input_bytes);
            settings.rerank_candidates = Some(*rerank_candidates);
            settings.rerank_context_tokens = Some(*rerank_context_tokens);
            settings.rerank_query_tokens = Some(*rerank_query_tokens);
            (model::ModelAdapter::CohereRerank, operator.as_str())
        }
    };
    (adapter, operator, settings)
}

fn execute_error(error: ModelError, started: &AtomicBool) -> ExecuteError {
    ExecuteError {
        code: match error {
            ModelError::Queue(_) => EgressError::StateUnavailable,
            ModelError::InvalidRequest(_) => EgressError::InvalidRequest,
            _ => EgressError::Transport,
        },
        may_have_dispatched: started.load(Ordering::SeqCst),
    }
}

// Resolver revisions encode (route with a keyless placeholder, backend tag,
// key name), in that order. Callback code and values have no stable serialization,
// just as file contents are excluded. Other sources retain their route encoding.
// Registration and accepted handoffs must use this same revision mechanism.
fn route_revision(route: &RouteConfig) -> Result<String, EgressError> {
    let revision = if let SecretSource::Resolver { name, .. } = &route.secret {
        let mut metadata = route.clone();
        metadata.secret = SecretSource::None;
        model::configuration_revision(&(metadata, "resolver", name))
    } else {
        model::configuration_revision(route)
    };
    revision
        .map(|revision| revision.0)
        .map_err(|_| EgressError::InvalidRequest)
}

/// Compile deployment routes into the same validated registry used by embedded runtimes.
pub(crate) fn configured_registry(
    routes: &[RouteConfig],
) -> Result<model::ModelRegistry, EgressError> {
    let mut models = std::collections::HashMap::new();
    let mut accounts = std::collections::HashMap::new();
    let mut bindings = Vec::new();
    for route in routes {
        let (adapter, operator, settings) = route_settings(route);
        let operation = match adapter.capability() {
            model::ModelCapability::Chat => "chat",
            model::ModelCapability::Rerank => "rerank",
            _ => "embedding",
        };
        let identity = model::ModelIdentity::new(operation, operator, &route.model);
        let model_id = model::configuration_revision(&identity)
            .map_err(|_| EgressError::InvalidRequest)?
            .0;
        let entry = models.entry(model_id.clone()).or_insert(model::ModelEntry {
            id: model_id.clone(),
            aliases: vec![],
            identity,
            adapter,
            operations: vec![adapter.capability()],
            capabilities: model::ModelCapabilities::default(),
            pricing_provenance: None,
        });
        if entry.adapter != adapter {
            return Err(EgressError::InvalidRequest);
        }
        let policy = queue_policy(route);
        let policy_id = model::configuration_revision(&policy)
            .map_err(|_| EgressError::InvalidRequest)?
            .0;
        accounts
            .entry(policy_id.clone())
            .or_insert(model::AccountExecutionPolicy {
                id: policy_id.clone(),
                policy,
            });
        bindings.push(model::TenantProviderBinding {
            identity: BindingIdentity::new(
                &route.tenant,
                &route.route,
                route_revision(route)?,
                &route.account,
            ),
            model: model_id,
            endpoint: route.destination.clone(),
            secret_ref: (!route.secret_ref.is_empty()).then(|| route.secret_ref.clone()),
            account_policy: policy_id,
            account_sharing_key: route.account_sharing_key.clone(),
            limits: model::ProviderLimits {
                max_request_bytes: route.max_input_bytes,
                max_response_bytes: route.max_response_bytes,
                max_output_tokens: if adapter.capability() == model::ModelCapability::Chat {
                    Some(route.max_output_tokens)
                } else {
                    None
                },
            },
            settings,
        });
    }
    model::ModelRegistry::new(model::RegistryConfig {
        version: 1,
        models: models.into_values().collect(),
        bindings,
        accounts: accounts.into_values().collect(),
    })
    .map_err(|_| EgressError::InvalidRequest)
}

fn queue_policy(route: &RouteConfig) -> ModelQueueConfig {
    // No hidden retry layer may spend a permit twice. Every retry must come back
    // through Memory's admission/barrier with its next ordinal.
    ModelQueueConfig {
        provider_request_limit: route.provider_request_limit,
        max_in_flight: route.max_in_flight,
        requests_per_minute: route.requests_per_minute,
        input_units_per_minute: route.input_units_per_minute,
        logical_retry_attempts: 1,
        retry_attempts: 1,
        request_timeout_seconds: Some(route.timeout_seconds),
        budget_renewal_seconds: None,
        ..ModelQueueConfig::default()
    }
}

/// Register all routes against the runtime's actual shared-limit rules without
/// resolving a provider credential or submitting a request.
pub(crate) fn validate_binding(runtime: &Runtime, route: &RouteConfig) -> Result<(), EgressError> {
    match &route.provider {
        RouteProvider::CompatibleEmbedding { .. } => {
            let resolved = resolved_route(runtime, route)?;
            let raw = model::CompatibleEmbeddingProvider::from_binding(&resolved, "")
                .map_err(|_| EgressError::InvalidRequest)?;
            runtime
                .embedding(
                    route_binding(runtime, route, raw)?.with_response_cache(ResponseCacheMode::Off),
                )
                .map(|_| ())
        }
        RouteProvider::CohereRerank { .. } => {
            let resolved = resolved_route(runtime, route)?;
            let raw = model::CohereRerankProvider::from_binding(&resolved, "")
                .map_err(|_| EgressError::InvalidRequest)?;
            runtime
                .rerank(
                    route_binding(runtime, route, raw)?.with_response_cache(ResponseCacheMode::Off),
                )
                .map(|_| ())
        }
        RouteProvider::AnthropicChat { operator, thinking } => runtime
            .chat(
                route_binding(
                    runtime,
                    route,
                    AnthropicChatProvider::new(operator, &route.model, &route.destination, "")
                        .with_request_limit(route.max_input_bytes)
                        .with_response_limit(route.max_response_bytes)
                        .with_output_limit(route.max_output_tokens)
                        .with_thinking(*thinking),
                )?
                .with_response_cache(ResponseCacheMode::Off),
            )
            .map(|_| ()),
        RouteProvider::OpenAiChat { operator } => runtime
            .chat(
                route_binding(
                    runtime,
                    route,
                    OpenAiCompatibleChatProvider::new(
                        operator,
                        &route.model,
                        &route.destination,
                        "",
                    )
                    .with_request_limit(route.max_input_bytes)
                    .with_response_limit(route.max_response_bytes)
                    .with_output_limit(route.max_output_tokens),
                )?
                .with_response_cache(ResponseCacheMode::Off),
            )
            .map(|_| ()),
        RouteProvider::GeminiEmbedding { dimensions } => runtime
            .embedding(
                route_binding(
                    runtime,
                    route,
                    GeminiEmbeddingProvider::new("gemini", &route.model, "", *dimensions)
                        .with_request_limit(route.max_input_bytes)
                        .with_response_limit(route.max_response_bytes),
                )?
                .with_response_cache(ResponseCacheMode::Off),
            )
            .map(|_| ()),
    }
    .map_err(|_| EgressError::InvalidRequest)
}

fn completed(
    output: ProviderOutput,
    trace: ModelInvocationTrace,
) -> (ProviderOutput, UsageTrace, Vec<DispatchDiagnostic>) {
    let mut diagnostics = Vec::new();
    if let Some(entries) = trace.metadata[RUNTIME_DIAGNOSTICS].as_array() {
        for entry in entries {
            let diagnostic = match entry["kind"].as_str() {
                Some("queue_complete_failed") => DispatchDiagnostic::QueueCompleteFailed,
                Some("trace_write_failed") => DispatchDiagnostic::TraceWriteFailed,
                Some("response_cache_write_failed") => DispatchDiagnostic::ResponseCacheWriteFailed,
                _ => continue,
            };
            if !diagnostics.contains(&diagnostic) {
                diagnostics.push(diagnostic);
            }
        }
    }
    (output, trace.usage, diagnostics)
}

/// Give each admitted attempt a queue identity while preserving provider-visible input.
pub(crate) fn prepare_payload(payload: &mut ProviderPayload, attempt_digest: &str) {
    match payload {
        ProviderPayload::Chat(request) => {
            request.source = Some(attempt_digest.to_owned());
            request.role_binding = None;
            request.metadata = serde_json::Value::Null;
        }
        ProviderPayload::Embedding(request) => {
            request.source = Some(attempt_digest.to_owned());
            request.role_binding = None;
            request.metadata = serde_json::Value::Null;
        }
        ProviderPayload::Rerank(request) => {
            request.source = Some(attempt_digest.to_owned());
            request.role_binding = None;
            request.metadata = serde_json::Value::Null;
        }
    }
}

pub(crate) fn accepted_handoff(
    attempt: &symbiotic_egress::DurableAttempt,
    route: &RouteConfig,
    payload: &ProviderPayload,
) -> Result<model::AcceptedSpendHandoff, EgressError> {
    let (kind, request_hash) = match payload {
        ProviderPayload::Chat(request) => ("chat", model::configuration_revision(request)),
        ProviderPayload::Embedding(request) => {
            ("embedding", model::configuration_revision(request))
        }
        ProviderPayload::Rerank(request) => ("rerank", model::configuration_revision(request)),
    };
    let binding = BindingIdentity::new(
        &route.tenant,
        &route.route,
        route_revision(route)?,
        &route.account,
    );
    Ok(model::AcceptedSpendHandoff {
        reservation: crate::spend_reservation(attempt, route)?,
        input_identity: model::handoff_input_identity(
            kind,
            Some(&binding),
            &request_hash.map_err(|_| EgressError::InvalidRequest)?.0,
        )
        .map_err(|_| EgressError::InvalidRequest)?,
    })
}

pub(crate) fn chat_adapter(
    route: &RouteConfig,
    secret: &str,
) -> Result<Arc<dyn ChatProvider>, EgressError> {
    let (RouteProvider::OpenAiChat { operator } | RouteProvider::AnthropicChat { operator, .. }) =
        &route.provider
    else {
        return Err(EgressError::InvalidRequest);
    };
    let inner: Arc<dyn ChatProvider> = match &route.provider {
        RouteProvider::AnthropicChat { thinking, .. } => Arc::new(
            AnthropicChatProvider::new(operator, &route.model, &route.destination, secret)
                .with_timeout(route.timeout_seconds)
                .map_err(|_| EgressError::InvalidRequest)?
                .with_request_limit(route.max_input_bytes)
                .with_response_limit(route.max_response_bytes)
                .with_output_limit(route.max_output_tokens)
                .with_thinking(*thinking),
        ),
        _ => Arc::new(
            OpenAiCompatibleChatProvider::new(operator, &route.model, &route.destination, secret)
                .with_timeout(route.timeout_seconds)
                .map_err(|_| EgressError::InvalidRequest)?
                .with_request_limit(route.max_input_bytes)
                .with_response_limit(route.max_response_bytes)
                .with_output_limit(route.max_output_tokens),
        ),
    };

    Ok(inner)
}

pub(crate) fn embedding_adapter(
    runtime: &Runtime,
    route: &RouteConfig,
    secret: &str,
) -> Result<Arc<dyn EmbeddingProvider>, EgressError> {
    match route.provider {
        RouteProvider::GeminiEmbedding { dimensions } => Ok(Arc::new(
            GeminiEmbeddingProvider::new("gemini", &route.model, secret, dimensions)
                .with_timeout(route.timeout_seconds)
                .map_err(|_| EgressError::InvalidRequest)?
                .with_request_limit(route.max_input_bytes)
                .with_response_limit(route.max_response_bytes),
        )),
        RouteProvider::CompatibleEmbedding { .. } => Ok(Arc::new(
            model::CompatibleEmbeddingProvider::from_binding(
                &resolved_route(runtime, route)?,
                secret,
            )
            .map_err(|_| EgressError::InvalidRequest)?,
        )),
        _ => Err(EgressError::InvalidRequest),
    }
}
pub(crate) fn rerank_adapter(
    runtime: &Runtime,
    route: &RouteConfig,
    secret: &str,
) -> Result<Arc<dyn RerankProvider>, EgressError> {
    Ok(Arc::new(
        model::CohereRerankProvider::from_binding(&resolved_route(runtime, route)?, secret)
            .map_err(|_| EgressError::InvalidRequest)?,
    ))
}

pub(crate) async fn execute(
    runtime: &Runtime,
    route: &RouteConfig,
    secret: Arc<Secret>,
    payload: ProviderPayload,
    handoff: model::AcceptedSpendHandoff,
) -> Result<(ProviderOutput, UsageTrace, Vec<DispatchDiagnostic>), ExecuteError> {
    let started = Arc::new(AtomicBool::new(false));
    match (&route.provider, payload) {
        (
            RouteProvider::OpenAiChat { .. } | RouteProvider::AnthropicChat { .. },
            ProviderPayload::Chat(request),
        ) => {
            let inner = chat_adapter(route, secret.value())?;
            let provider = Dispatched {
                inner,
                started: started.clone(),
            };
            let provider = runtime
                .chat(accepted_route_binding(runtime, route, provider, handoff)?)
                .map_err(|_| EgressError::StateUnavailable)?;
            let response = provider
                .chat(request)
                .await
                .map_err(|error| execute_error(error, &started))?;
            Ok(completed(
                ProviderOutput::Chat {
                    text: response.text,
                },
                response.trace,
            ))
        }
        (
            RouteProvider::GeminiEmbedding { .. } | RouteProvider::CompatibleEmbedding { .. },
            ProviderPayload::Embedding(request),
        ) => {
            let provider = Dispatched {
                inner: embedding_adapter(runtime, route, secret.value())?,
                started: started.clone(),
            };
            let provider = runtime
                .embedding(accepted_route_binding(runtime, route, provider, handoff)?)
                .map_err(|_| EgressError::StateUnavailable)?;
            let response = provider
                .embed(request)
                .await
                .map_err(|error| execute_error(error, &started))?;
            Ok(completed(
                ProviderOutput::Embedding {
                    vectors: response.vectors,
                    dimensions: response.dimensions,
                },
                response.trace,
            ))
        }
        (RouteProvider::CohereRerank { .. }, ProviderPayload::Rerank(request)) => {
            let provider = Dispatched {
                inner: rerank_adapter(runtime, route, secret.value())?,
                started: started.clone(),
            };
            let provider = runtime
                .rerank(accepted_route_binding(runtime, route, provider, handoff)?)
                .map_err(|_| EgressError::StateUnavailable)?;
            let response = provider
                .rerank(request)
                .await
                .map_err(|error| execute_error(error, &started))?;
            Ok(completed(
                ProviderOutput::Rerank {
                    hits: response.hits,
                },
                response.trace,
            ))
        }
        _ => Err(EgressError::InvalidRequest.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct RejectBeforeTransport {
        descriptor: ProviderDescriptor,
        error: ModelError,
    }
    impl ModelProvider for RejectBeforeTransport {
        fn descriptor(&self) -> &ProviderDescriptor {
            &self.descriptor
        }
        fn failure_charge(&self, _: &ModelError) -> model::FailureCharge {
            model::FailureCharge::KnownZero
        }
    }
    #[async_trait]
    impl ChatProvider for RejectBeforeTransport {
        async fn chat(&self, _: ChatRequest) -> Result<ChatResponse, ModelError> {
            Err(self.error.clone())
        }
    }
    #[tokio::test]
    async fn dispatched_wrapper_preserves_trusted_zero_charge_without_releasing_timeouts() {
        for (error, started_after) in [
            (
                ModelError::Auth(model::DiagnosticCode::InvalidConfiguration),
                false,
            ),
            (
                ModelError::Timeout(model::DiagnosticCode::HttpTimeout),
                true,
            ),
        ] {
            let provider = Dispatched {
                inner: RejectBeforeTransport {
                    descriptor: ProviderDescriptor {
                        identity: model::ModelIdentity::new("test", "synthetic", "1"),
                        provider_class: model::ProviderClass::Local,
                        capabilities: vec![model::ModelCapability::Chat],
                        auth_mode: model::ProviderAuthMode::None,
                        metadata: serde_json::Value::Null,
                    },
                    error,
                },
                started: Arc::new(AtomicBool::new(false)),
            };
            let request = ChatRequest {
                messages: vec![],
                response_format: None,
                max_output_tokens: None,
                temperature: None,
                role_binding: None,
                source: None,
                metadata: serde_json::Value::Null,
            };
            let error = provider.chat(request).await.unwrap_err();
            assert_eq!(
                provider.failure_charge(&error),
                model::FailureCharge::KnownZero
            );
            assert_eq!(provider.started.load(Ordering::SeqCst), started_after);
        }
    }

    struct FailingTrace;
    #[async_trait]
    impl symbiotic_trace::TraceSink for FailingTrace {
        async fn record_model_invocation(
            &self,
            _: ModelInvocationTrace,
        ) -> Result<(), symbiotic_trace::TraceError> {
            Err(symbiotic_trace::TraceError::Sink(
                model::DiagnosticCode::StorageFailure,
            ))
        }
    }

    #[tokio::test]
    async fn embedding_runtime_failure_projects_only_static_diagnostics() {
        let state = tempfile::tempdir().unwrap();
        let runtime = Runtime::open(RuntimeConfig {
            state_dir: Some(state.path().join("state")),
            trace_sink: Some(Arc::new(FailingTrace)),
            ..RuntimeConfig::default()
        })
        .unwrap();
        let provider = runtime
            .embedding(
                ModelBinding::new(model::HashEmbeddingProvider::new(2))
                    .with_identity(BindingIdentity::new("test", "provider", "1", "account"))
                    .with_policy(ModelQueueConfig::default()),
            )
            .unwrap();
        let mut response = provider
            .embed(EmbeddingRequest {
                inputs: vec!["synthetic input".into()],
                dimensions: None,
                task: None,
                role_binding: None,
                source: None,
                metadata: serde_json::Value::Null,
            })
            .await
            .unwrap();
        assert!(
            response
                .trace
                .metadata
                .to_string()
                .contains("storage_failure")
        );
        // Extra metadata and unknown diagnostic kinds must not cross this boundary.
        response.trace.metadata[RUNTIME_DIAGNOSTICS]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"kind": "private unknown kind", "error": "private detail"}));
        response.trace.usage.input_tokens = Some(7);
        let expected_vectors = response.vectors.clone();
        let (output, usage, diagnostics) = completed(
            ProviderOutput::Embedding {
                vectors: response.vectors,
                dimensions: response.dimensions,
            },
            response.trace,
        );
        assert!(
            matches!(output, ProviderOutput::Embedding { vectors, dimensions: 2 }
            if vectors == expected_vectors)
        );
        assert_eq!(usage.input_tokens, Some(7));
        assert_eq!(diagnostics, vec![DispatchDiagnostic::TraceWriteFailed]);
        assert_eq!(
            serde_json::to_string(&diagnostics).unwrap(),
            r#"["trace_write_failed"]"#
        );
        assert!(serde_json::from_str::<DispatchDiagnostic>(r#""private unknown kind""#).is_err());
    }
}
