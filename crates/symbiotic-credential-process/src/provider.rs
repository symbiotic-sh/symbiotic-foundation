//! Track dispatch and project sanitized model output into credential-process replies.
use crate::{RouteConfig, RouteProvider, secrets::Secret};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use symbiotic_ai_runtime::{
    model::{CredentialBoundary, GeminiEmbeddingProvider, OpenAiCompatibleChatProvider},
    *,
};
use symbiotic_egress::{DispatchDiagnostic, EgressError, ProviderOutput, ProviderPayload};
use symbiotic_trace::{ModelInvocationTrace, UsageTrace};

#[derive(Clone)]
struct DispatchedChat {
    inner: OpenAiCompatibleChatProvider,
    started: Arc<AtomicBool>,
}
#[derive(Clone)]
struct DispatchedEmbedding {
    inner: GeminiEmbeddingProvider,
    started: Arc<AtomicBool>,
}

impl ModelProvider for DispatchedChat {
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
impl ModelProvider for DispatchedEmbedding {
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
#[async_trait]
impl ChatProvider for DispatchedChat {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        self.started.store(true, Ordering::SeqCst);
        let mut response = self.inner.chat(request).await?;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}
#[async_trait]
impl EmbeddingProvider for DispatchedEmbedding {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        self.started.store(true, Ordering::SeqCst);
        let mut response = self.inner.embed(request).await?;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}

// Once the raw adapter starts, conservatively retain the reservation even if
// it fails while building/sending the request. Queue/setup failures before that
// boundary are known not to have reached HTTP.
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

fn route_binding<P>(
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

/// Compile deployment routes into the same validated registry used by embedded runtimes.
pub(crate) fn configured_registry(
    routes: &[RouteConfig],
) -> Result<model::ModelRegistry, EgressError> {
    let mut models = std::collections::HashMap::new();
    let mut accounts = std::collections::HashMap::new();
    let mut bindings = Vec::new();
    for route in routes {
        let (adapter, operator, dimensions) = match &route.provider {
            RouteProvider::OpenAiChat { operator } => {
                (model::ModelAdapter::OpenAiChat, operator.as_str(), None)
            }
            RouteProvider::GeminiEmbedding { dimensions } => (
                model::ModelAdapter::GeminiEmbedding,
                "gemini",
                Some(*dimensions),
            ),
        };
        let operation = match adapter {
            model::ModelAdapter::OpenAiChat => "chat",
            _ => "embedding",
        };
        let identity = model::ModelIdentity::new(operation, operator, &route.model);
        let model_id = model::configuration_revision(&identity)
            .map_err(|_| EgressError::InvalidRequest)?
            .0;
        models.entry(model_id.clone()).or_insert(model::ModelEntry {
            id: model_id.clone(),
            aliases: vec![],
            identity,
            adapter,
            operations: vec![adapter.capability()],
            capabilities: model::ModelCapabilities::default(),
            pricing_provenance: None,
        });
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
                model::configuration_revision(route)
                    .map_err(|_| EgressError::InvalidRequest)?
                    .0,
                &route.account,
            ),
            model: model_id,
            endpoint: route.destination.clone(),
            secret_ref: Some(route.secret_ref.clone()),
            account_policy: policy_id,
            account_sharing_key: route.account_sharing_key.clone(),
            limits: model::ProviderLimits {
                max_request_bytes: route.max_input_bytes,
                max_response_bytes: route.max_response_bytes,
                max_output_tokens: if adapter == model::ModelAdapter::OpenAiChat {
                    Some(route.max_output_tokens)
                } else {
                    None
                },
            },
            settings: model::TransportSettings {
                dimensions,
                ..model::TransportSettings::default()
            },
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

pub(crate) async fn execute(
    runtime: &Runtime,
    route: &RouteConfig,
    secret: Arc<Secret>,
    payload: ProviderPayload,
    attempt_digest: &str,
) -> Result<(ProviderOutput, UsageTrace, Vec<DispatchDiagnostic>), ExecuteError> {
    let started = Arc::new(AtomicBool::new(false));
    match (&route.provider, payload) {
        (RouteProvider::OpenAiChat { operator }, ProviderPayload::Chat(mut request)) => {
            // Per-attempt queue identity without changing provider-visible inputs.
            request.source = Some(attempt_digest.to_owned());
            request.role_binding = None;
            request.metadata = serde_json::Value::Null;
            let provider = DispatchedChat {
                inner: OpenAiCompatibleChatProvider::new(
                    operator,
                    &route.model,
                    &route.destination,
                    secret.value(),
                )
                .with_timeout(route.timeout_seconds)
                .map_err(|_| EgressError::InvalidRequest)?
                .with_request_limit(route.max_input_bytes)
                .with_response_limit(route.max_response_bytes)
                .with_output_limit(route.max_output_tokens),
                started: started.clone(),
            };
            let provider = runtime
                .chat(
                    route_binding(runtime, route, provider)?
                        .with_response_cache(ResponseCacheMode::Off),
                )
                .map_err(|_| EgressError::StateUnavailable)?;
            let response = provider.chat(request).await.map_err(|error| ExecuteError {
                code: match error {
                    ModelError::Queue(_) => EgressError::StateUnavailable,
                    ModelError::InvalidRequest(_) => EgressError::InvalidRequest,
                    _ => EgressError::Transport,
                },
                may_have_dispatched: started.load(Ordering::SeqCst),
            })?;
            Ok(completed(
                ProviderOutput::Chat {
                    text: response.text,
                },
                response.trace,
            ))
        }
        (
            RouteProvider::GeminiEmbedding { dimensions },
            ProviderPayload::Embedding(mut request),
        ) => {
            request.source = Some(attempt_digest.to_owned());
            request.role_binding = None;
            request.metadata = serde_json::Value::Null;
            let provider = DispatchedEmbedding {
                inner: GeminiEmbeddingProvider::new(
                    "gemini",
                    &route.model,
                    secret.value(),
                    *dimensions,
                )
                .with_timeout(route.timeout_seconds)
                .map_err(|_| EgressError::InvalidRequest)?
                .with_request_limit(route.max_input_bytes)
                .with_response_limit(route.max_response_bytes),
                started: started.clone(),
            };
            let provider = runtime
                .embedding(
                    route_binding(runtime, route, provider)?
                        .with_response_cache(ResponseCacheMode::Off),
                )
                .map_err(|_| EgressError::StateUnavailable)?;
            let response = provider
                .embed(request)
                .await
                .map_err(|error| ExecuteError {
                    code: match error {
                        ModelError::Queue(_) => EgressError::StateUnavailable,
                        ModelError::InvalidRequest(_) => EgressError::InvalidRequest,
                        _ => EgressError::Transport,
                    },
                    may_have_dispatched: started.load(Ordering::SeqCst),
                })?;
            Ok(completed(
                ProviderOutput::Embedding {
                    vectors: response.vectors,
                    dimensions: response.dimensions,
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

    struct FailingTrace;
    #[async_trait]
    impl symbiotic_trace::TraceSink for FailingTrace {
        async fn record_model_invocation(
            &self,
            _: ModelInvocationTrace,
        ) -> Result<(), symbiotic_trace::TraceError> {
            Err(symbiotic_trace::TraceError::Sink(
                "private sink detail".into(),
            ))
        }
    }

    #[tokio::test]
    async fn embedding_runtime_failure_projects_only_static_diagnostics() {
        let runtime = Runtime::open(RuntimeConfig {
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
                sensitivity: symbiotic_egress::Sensitivity::Private,
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
                .contains("private sink detail")
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
