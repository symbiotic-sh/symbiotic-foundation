//! Sanitize inside the raw provider, before runtime receipts/logging see any result.
use crate::{RouteConfig, RouteProvider, secrets::Secret};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use symbiotic_ai_runtime::{
    model::{GeminiEmbeddingProvider, OpenAiCompatibleChatProvider},
    *,
};
use symbiotic_egress::{DispatchDiagnostic, EgressError, ProviderOutput, ProviderPayload};
use symbiotic_trace::{ModelInvocationTrace, UsageTrace};

#[derive(Clone)]
struct SafeChat {
    inner: OpenAiCompatibleChatProvider,
    secret: Arc<Secret>,
    started: Arc<AtomicBool>,
}
#[derive(Clone)]
struct SafeEmbedding {
    inner: GeminiEmbeddingProvider,
    secret: Arc<Secret>,
    started: Arc<AtomicBool>,
}

fn safe_error(error: ModelError) -> ModelError {
    // Preserve useful error classes without retaining any provider-controlled bytes.
    let safe = "credential-process provider failure".to_owned();
    match error {
        ModelError::Auth(_) => ModelError::Auth(safe),
        ModelError::RateLimited(_) => ModelError::RateLimited(safe),
        ModelError::BudgetExhausted(_) => ModelError::BudgetExhausted(safe),
        ModelError::Timeout(_) => ModelError::Timeout(safe),
        ModelError::Unavailable(_) => ModelError::Unavailable(safe),
        _ => ModelError::Provider(safe),
    }
}

fn check_response(value: &impl serde::Serialize, secret: &Secret) -> Result<(), ModelError> {
    fn contains(value: &serde_json::Value, secret: &Secret) -> bool {
        match value {
            serde_json::Value::String(text) => secret.contains(text.as_bytes()),
            serde_json::Value::Array(values) => values.iter().any(|value| contains(value, secret)),
            serde_json::Value::Object(values) => values
                .iter()
                .any(|(key, value)| secret.contains(key.as_bytes()) || contains(value, secret)),
            _ => false,
        }
    }
    let value = serde_json::to_value(value)
        .map_err(|_| ModelError::Provider("invalid provider response".into()))?;
    let wire = serde_json::to_vec(&value)
        .map_err(|_| ModelError::Provider("invalid provider response".into()))?;
    if contains(&value, secret) || secret.contains(&wire) {
        return Err(ModelError::Provider(
            "credential-bearing provider response refused".into(),
        ));
    }
    Ok(())
}

impl ModelProvider for SafeChat {
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }
    fn credential_fingerprint(&self) -> Option<String> {
        self.inner.credential_fingerprint()
    }
}
impl ModelProvider for SafeEmbedding {
    fn descriptor(&self) -> &ProviderDescriptor {
        self.inner.descriptor()
    }
    fn credential_fingerprint(&self) -> Option<String> {
        self.inner.credential_fingerprint()
    }
}
#[async_trait]
impl ChatProvider for SafeChat {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        self.started.store(true, Ordering::SeqCst);
        let mut response = self.inner.chat(request).await.map_err(safe_error)?;
        check_response(&response, &self.secret)?;
        response.raw_provider_response = None;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}
#[async_trait]
impl EmbeddingProvider for SafeEmbedding {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        self.started.store(true, Ordering::SeqCst);
        let mut response = self.inner.embed(request).await.map_err(safe_error)?;
        check_response(&response, &self.secret)?;
        response.raw_provider_response = None;
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
    let policy = queue_policy(route);
    match &route.provider {
        RouteProvider::OpenAiChat { operator } => runtime
            .chat(
                ModelBinding::new(OpenAiCompatibleChatProvider::new(
                    operator,
                    &route.model,
                    &route.destination,
                    "",
                ))
                .with_policy(policy)
                .with_response_cache(ResponseCacheMode::Off),
            )
            .map(|_| ()),
        RouteProvider::GeminiEmbedding { dimensions } => runtime
            .embedding(
                ModelBinding::new(GeminiEmbeddingProvider::new(&route.model, "", *dimensions))
                    .with_policy(policy)
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
    // Ambient proxies must not reroute an admitted destination or receive its secret.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(route.timeout_seconds))
        .build()
        .map_err(|_| EgressError::InvalidRequest)?;
    let policy = queue_policy(route);
    let started = Arc::new(AtomicBool::new(false));
    match (&route.provider, payload) {
        (RouteProvider::OpenAiChat { operator }, ProviderPayload::Chat(mut request)) => {
            // Per-attempt queue identity without changing provider-visible inputs.
            request.source = Some(attempt_digest.to_owned());
            request.role_binding = None;
            request.metadata = serde_json::Value::Null;
            let provider = SafeChat {
                inner: OpenAiCompatibleChatProvider::new(
                    operator,
                    &route.model,
                    &route.destination,
                    secret.value(),
                )
                .with_client(client)
                .with_request_limit(route.max_input_bytes)
                .with_response_limit(route.max_response_bytes),
                secret,
                started: started.clone(),
            };
            let provider = runtime
                .chat(
                    ModelBinding::new(provider)
                        .with_policy(policy)
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
            let provider = SafeEmbedding {
                inner: GeminiEmbeddingProvider::new(&route.model, secret.value(), *dimensions)
                    .with_client(client)
                    .with_request_limit(route.max_input_bytes)
                    .with_response_limit(route.max_response_bytes),
                secret,
                started: started.clone(),
            };
            let provider = runtime
                .embedding(
                    ModelBinding::new(provider)
                        .with_policy(policy)
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
            .embedding(ModelBinding::new(model::HashEmbeddingProvider::new(2)))
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

    #[test]
    fn invalid_embedding_error_is_sanitized_as_provider_failure() {
        let error = safe_error(ModelError::Provider(
            "Gemini embedding contains non-finite components".into(),
        ));
        assert!(matches!(error, ModelError::Provider(message)
            if message == "credential-process provider failure"));
    }

    #[test]
    fn numeric_provider_values_cannot_echo_credential_bytes() {
        let secret = Secret::from_bytes(zeroize::Zeroizing::new(b"123456789".to_vec())).unwrap();
        assert!(check_response(&serde_json::json!({"vectors": [[123456789]]}), &secret).is_err());
    }
}
