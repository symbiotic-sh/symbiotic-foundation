//! Sanitize inside the raw provider, before runtime receipts/logging see any result.
use crate::{RouteConfig, RouteProvider, secrets::Secret};
use async_trait::async_trait;
use std::sync::Arc;
use symbiotic_ai_runtime::{
    model::{GeminiEmbeddingProvider, OpenAiCompatibleChatProvider},
    *,
};
use symbiotic_egress::{EgressError, ProviderOutput, ProviderPayload};
use symbiotic_trace::UsageTrace;

#[derive(Clone)]
struct SafeChat {
    inner: OpenAiCompatibleChatProvider,
    secret: Arc<Secret>,
}
#[derive(Clone)]
struct SafeEmbedding {
    inner: GeminiEmbeddingProvider,
    secret: Arc<Secret>,
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
        let mut response = self.inner.embed(request).await.map_err(safe_error)?;
        check_response(&response, &self.secret)?;
        response.raw_provider_response = None;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}

pub(crate) async fn execute(
    runtime: &Runtime,
    route: &RouteConfig,
    secret: Arc<Secret>,
    payload: ProviderPayload,
    attempt_digest: &str,
) -> Result<(ProviderOutput, UsageTrace), EgressError> {
    // Ambient proxies must not reroute an admitted destination or receive its secret.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(route.timeout_seconds))
        .build()
        .map_err(|_| EgressError::InvalidRequest)?;
    // No hidden retry layer may spend a permit twice. Every retry must come back
    // through Memory's admission/barrier with its next ordinal.
    let policy = ModelQueueConfig {
        max_in_flight: route.max_in_flight,
        requests_per_minute: route.requests_per_minute,
        input_units_per_minute: route.input_units_per_minute,
        logical_retry_attempts: 1,
        retry_attempts: 1,
        request_timeout_seconds: Some(route.timeout_seconds),
        budget_renewal_seconds: None,
        ..ModelQueueConfig::default()
    };
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
            };
            let provider = runtime
                .chat(
                    ModelBinding::new(provider)
                        .with_policy(policy)
                        .with_response_cache(ResponseCacheMode::Off),
                )
                .map_err(|_| EgressError::StateUnavailable)?;
            let response = provider
                .chat(request)
                .await
                .map_err(|_| EgressError::Transport)?;
            Ok((
                ProviderOutput::Chat {
                    text: response.text,
                },
                response.trace.usage,
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
                .map_err(|_| EgressError::Transport)?;
            Ok((
                ProviderOutput::Embedding {
                    vectors: response.vectors,
                    dimensions: response.dimensions,
                },
                response.trace.usage,
            ))
        }
        _ => Err(EgressError::InvalidRequest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_provider_values_cannot_echo_credential_bytes() {
        let secret = Secret::from_bytes(zeroize::Zeroizing::new(b"123456789".to_vec())).unwrap();
        assert!(check_response(&serde_json::json!({"vectors": [[123456789]]}), &secret).is_err());
    }
}
