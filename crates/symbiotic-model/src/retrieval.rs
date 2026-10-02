//! Consumer-proven embedding and rerank protocols through the shared HTTP boundary.
use crate::*;
use std::collections::HashSet;

fn invalid() -> ModelError {
    ModelError::InvalidRequest(DiagnosticCode::InvalidConfiguration)
}
fn malformed() -> ModelError {
    ModelError::Provider(DiagnosticCode::InvalidResponse)
}

#[derive(Clone)]
struct RetrievalTransport {
    descriptor: ProviderDescriptor,
    client: HttpClient,
    key: CredentialBoundary,
    adapter: ModelAdapter,
    endpoint: String,
    limits: ProviderLimits,
    settings: TransportSettings,
}
impl RetrievalTransport {
    fn new(binding: &RegistryBinding<'_>, key: SecretValue<String>) -> Result<Self, ModelError> {
        let config = binding.binding;
        registry::validate_endpoint(&config.endpoint)?;
        config.settings.validate_retrieval(binding.model.adapter)?;
        required_byte_limit(Some(config.limits.max_request_bytes))?;
        required_byte_limit(Some(config.limits.max_response_bytes))?;
        if config.limits.max_output_tokens.is_some() {
            return Err(invalid());
        }
        let auth_mode = if key.is_empty() {
            ProviderAuthMode::None
        } else {
            ProviderAuthMode::ApiKey {
                secret_ref: "runtime".into(),
            }
        };
        Ok(Self {
            descriptor: ProviderDescriptor {
                identity: binding.model.identity.clone(),
                provider_class: ProviderClass::Cloud,
                capabilities: vec![binding.model.adapter.capability()],
                auth_mode,
                metadata: serde_json::json!({
                    "endpoint": config.endpoint, "dimensions": config.settings.dimensions,
                    "retrieval_settings": config.settings, "adapter": binding.model.adapter,
                    "max_request_bytes": config.limits.max_request_bytes,
                    "max_response_bytes": config.limits.max_response_bytes,
                }),
            },
            client: HttpClient(Ok(http_client(
                binding.account.policy.request_timeout_seconds,
            )?)),
            key: CredentialBoundary::new(key),
            adapter: binding.model.adapter,
            endpoint: config.endpoint.clone(),
            limits: config.limits.clone(),
            settings: config.settings.clone(),
        })
    }
    async fn send(&self, path: &str, body: Vec<u8>) -> Result<(Value, String), ModelError> {
        let mut builder = self
            .client
            .get()?
            .post(format!("{}{path}", self.endpoint.trim_end_matches('/')))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if !self.key.secret().is_empty() {
            builder = builder.bearer_auth(self.key.secret());
        }
        provider_response_json(
            builder,
            Some(self.limits.max_response_bytes),
            ModelError::Provider,
        )
        .await
    }
}

/// OpenAI/OpenRouter batch embeddings or Ollama single-input embeddings.
/// Construct only from explicit registry configuration; no provider/model defaults.
#[derive(Clone)]
pub struct CompatibleEmbeddingProvider(RetrievalTransport);
/// Cohere/OpenRouter `/rerank` with configured candidate and input byte bounds.
#[derive(Clone)]
pub struct CohereRerankProvider(RetrievalTransport);

macro_rules! retrieval_provider {
    ($provider:ident, $matches:pat) => {
        impl $provider {
            /// Resolve effective transport settings from a validated registry binding.
            /// An empty key selects keyless HTTP without an Authorization header.
            pub fn from_binding(
                binding: &RegistryBinding<'_>,
                key: impl Into<SecretValue<String>>,
            ) -> Result<Self, ModelError> {
                if !matches!(binding.model.adapter, $matches) {
                    return Err(invalid());
                }
                Ok(Self(RetrievalTransport::new(binding, key.into())?))
            }
        }
        impl ModelProvider for $provider {
            fn descriptor(&self) -> &ProviderDescriptor {
                &self.0.descriptor
            }
            fn validate_configuration(&self) -> Result<(), ModelError> {
                self.0.client.get().map(|_| ())
            }
            fn credential_fingerprint(&self) -> Option<String> {
                api_key_fingerprint(self.0.key.secret())
            }
            fn credential_boundary(&self) -> Option<&CredentialBoundary> {
                Some(&self.0.key)
            }
        }
    };
}
retrieval_provider!(
    CompatibleEmbeddingProvider,
    ModelAdapter::OpenAiEmbedding | ModelAdapter::OllamaEmbedding
);
retrieval_provider!(CohereRerankProvider, ModelAdapter::CohereRerank);

/// Validate and encode the exact consumer-compatible embedding request.
/// Ollama has no batch/dimension/task options: refuse them rather than issuing
/// multiple requests under one invocation or silently ignoring an option.
pub fn compatible_embedding_body(
    adapter: ModelAdapter,
    model: &str,
    settings: &TransportSettings,
    request: &EmbeddingRequest,
    max_bytes: usize,
) -> Result<(Vec<u8>, usize), ModelError> {
    settings.validate_retrieval(adapter)?;
    let dimensions = request
        .dimensions
        .or(settings.dimensions)
        .ok_or_else(invalid)?;
    if dimensions == 0
        || settings
            .embedding_full_dimensions
            .is_none_or(|full| dimensions > full)
        || request.inputs.is_empty()
        || request
            .task
            .as_deref()
            .is_some_and(|task| task.trim().is_empty())
    {
        return Err(invalid());
    }
    if request.inputs.iter().any(|input| {
        settings
            .embedding_input_tokens
            .is_none_or(|limit| input.len() > limit)
    }) {
        return Err(ModelError::InvalidRequest(
            DiagnosticCode::ProviderRequestLimitExceeded,
        ));
    }
    #[derive(Serialize)]
    struct OpenAiBody<'a> {
        model: &'a str,
        input: &'a [String],
        dimensions: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_type: Option<&'a str>,
    }
    #[derive(Serialize)]
    struct OllamaBody<'a> {
        model: &'a str,
        prompt: &'a str,
    }
    let body = match adapter {
        ModelAdapter::OpenAiEmbedding => wire::encode(
            &OpenAiBody {
                model,
                input: &request.inputs,
                dimensions,
                input_type: request.task.as_deref(),
            },
            Some(max_bytes),
        )?,
        ModelAdapter::OllamaEmbedding
            if request.inputs.len() == 1
                && request.task.is_none()
                && Some(dimensions) == settings.dimensions =>
        {
            wire::encode(
                &OllamaBody {
                    model,
                    prompt: &request.inputs[0],
                },
                Some(max_bytes),
            )?
        }
        _ => return Err(invalid()),
    };
    Ok((body, dimensions))
}

/// Validate and encode the Cohere-compatible payload, preserving every candidate.
pub fn cohere_rerank_body(
    model: &str,
    settings: &TransportSettings,
    request: &RerankRequest,
    max_bytes: usize,
) -> Result<(Vec<u8>, usize), ModelError> {
    settings.validate_retrieval(ModelAdapter::CohereRerank)?;
    let count = request.documents.len();
    if count == 0 || request.top_k == Some(0) {
        return Err(invalid());
    }
    if settings.rerank_candidates.is_none_or(|limit| count > limit) {
        return Err(ModelError::InvalidRequest(
            DiagnosticCode::ProviderRequestLimitExceeded,
        ));
    }
    let context_tokens = settings.rerank_context_tokens.ok_or_else(invalid)?;
    // Byte-level text tokenization needs at most one token per UTF-8 byte.
    // Include the query in every pair; deployment reserves template/special tokens
    // in the configured usable capacity. Never rely on a bytes/4 estimate.
    if settings
        .rerank_query_tokens
        .is_none_or(|limit| request.query.len() > limit)
        || request.documents.iter().any(|doc| {
            request
                .query
                .len()
                .checked_add(doc.len())
                .is_none_or(|n| n > context_tokens)
        })
    {
        return Err(ModelError::InvalidRequest(
            DiagnosticCode::ProviderRequestLimitExceeded,
        ));
    }
    let bytes = request
        .documents
        .iter()
        .try_fold(request.query.len(), |sum, doc| sum.checked_add(doc.len()));
    if bytes.is_none_or(|bytes| {
        settings
            .rerank_input_bytes
            .is_none_or(|limit| bytes > limit)
    }) {
        return Err(ModelError::InvalidRequest(
            DiagnosticCode::ProviderRequestLimitExceeded,
        ));
    }
    let top_n = request.top_k.unwrap_or(count).min(count);
    #[derive(Serialize)]
    struct Body<'a> {
        model: &'a str,
        query: &'a str,
        documents: &'a [String],
        top_n: usize,
        max_tokens_per_doc: usize,
    }
    Ok((
        wire::encode(
            &Body {
                model,
                query: &request.query,
                documents: &request.documents,
                top_n,
                max_tokens_per_doc: context_tokens,
            },
            Some(max_bytes),
        )?,
        top_n,
    ))
}

#[derive(Deserialize)]
struct EmbeddingItem {
    index: usize,
    embedding: Vec<f32>,
}
#[derive(Deserialize)]
struct CompatibleEmbeddingResponse {
    data: Vec<EmbeddingItem>,
    usage: Option<OpenAiUsage>,
}
#[derive(Deserialize)]
struct OllamaResponse {
    embedding: Vec<f32>,
}
fn validate_vector(vector: &[f32], dimensions: usize) -> Result<(), ModelError> {
    if vector.len() != dimensions || vector.iter().any(|n| !n.is_finite()) {
        return Err(malformed());
    }
    Ok(())
}
#[async_trait]
impl EmbeddingProvider for CompatibleEmbeddingProvider {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        let mut response = secrets::credential_boundary(
            (async {
                let transport = &self.0;
                let (body, dimensions) = compatible_embedding_body(
                    transport.adapter,
                    &transport.descriptor.identity.model.0,
                    &transport.settings,
                    &request,
                    transport.limits.max_request_bytes,
                )?;
                let path = if transport.adapter == ModelAdapter::OllamaEmbedding {
                    "/api/embeddings"
                } else {
                    "/embeddings"
                };
                let (raw, text) = transport.send(path, body).await?;
                let mut trace = success_trace(
                    &transport.descriptor,
                    request.role_binding.clone(),
                    request.source.clone(),
                    hash_json(&request)?,
                    Some(&text),
                );
                trace.usage.reported_cost_usd = reported_cost_usd(&raw);
                let vectors = if transport.adapter == ModelAdapter::OllamaEmbedding {
                    let parsed: OllamaResponse =
                        serde_json::from_value(raw.clone()).map_err(|_| malformed())?;
                    validate_vector(&parsed.embedding, dimensions)?;
                    vec![parsed.embedding]
                } else {
                    let parsed: CompatibleEmbeddingResponse =
                        serde_json::from_value(raw.clone()).map_err(|_| malformed())?;
                    if parsed.data.len() != request.inputs.len() {
                        return Err(malformed());
                    }
                    let mut vectors = vec![Vec::new(); request.inputs.len()];
                    for item in parsed.data {
                        validate_vector(&item.embedding, dimensions)?;
                        if item.index >= vectors.len() || !vectors[item.index].is_empty() {
                            return Err(malformed());
                        }
                        vectors[item.index] = item.embedding;
                    }
                    if let Some(usage) = parsed.usage {
                        trace.usage.input_tokens = usage.prompt_tokens;
                    }
                    vectors
                };
                Ok(EmbeddingResponse {
                    vectors,
                    dimensions,
                    trace,
                    raw_provider_response: Some(raw),
                })
            })
            .await,
            &self.0.key,
        )?;
        response.raw_provider_response = None;
        Ok(response)
    }
}

#[derive(Deserialize)]
struct RerankResults {
    results: Vec<RerankResult>,
}
#[derive(Deserialize)]
struct RerankResult {
    index: usize,
    relevance_score: f32,
}
#[async_trait]
impl RerankProvider for CohereRerankProvider {
    async fn rerank(&self, request: RerankRequest) -> Result<RerankResponse, ModelError> {
        let mut response = secrets::credential_boundary(
            (async {
                let transport = &self.0;
                let (body, top_n) = cohere_rerank_body(
                    &transport.descriptor.identity.model.0,
                    &transport.settings,
                    &request,
                    transport.limits.max_request_bytes,
                )?;
                let (raw, text) = transport.send("/rerank", body).await?;
                let parsed: RerankResults =
                    serde_json::from_value(raw.clone()).map_err(|_| malformed())?;
                if parsed.results.len() != top_n {
                    return Err(malformed());
                }
                let mut indices = HashSet::new();
                let mut hits = Vec::with_capacity(parsed.results.len());
                for result in parsed.results {
                    if result.index >= request.documents.len()
                        || !result.relevance_score.is_finite()
                        || !indices.insert(result.index)
                    {
                        return Err(malformed());
                    }
                    hits.push(RerankHit {
                        index: result.index,
                        score: result.relevance_score,
                    });
                }
                hits.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.index.cmp(&b.index)));
                let mut trace = success_trace(
                    &transport.descriptor,
                    request.role_binding.clone(),
                    request.source.clone(),
                    hash_json(&request)?,
                    Some(&text),
                );
                trace.usage.reported_cost_usd = reported_cost_usd(&raw);
                Ok(RerankResponse {
                    hits,
                    trace,
                    raw_provider_response: Some(raw),
                })
            })
            .await,
            &self.0.key,
        )?;
        response.raw_provider_response = None;
        Ok(response)
    }
}
