//! Anthropic Messages transport using the shared HTTP and credential owners.
use crate::*;

/// Non-streaming Anthropic Messages adapter. The base URL includes `/v1`.
/// Requests without a token bound default to 16,000; shared byte defaults apply.
#[derive(Clone)]
pub struct AnthropicChatProvider {
    transport: OpenAiCompatibleChatProvider,
}

impl AnthropicChatProvider {
    /// Construct a Foundation-owned transport without an optional thinking setting.
    pub fn new(
        operator: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        api_key: impl Into<SecretValue<String>>,
    ) -> Self {
        let mut transport = OpenAiCompatibleChatProvider::new(operator, model, base_url, api_key)
            .with_output_limit(16000);
        transport.descriptor.metadata["wire"] = serde_json::json!("anthropic-messages");
        Self { transport }
    }

    /// Set a finite timeout on the shared redirect-free, direct HTTP client.
    pub fn with_timeout(mut self, timeout_seconds: u64) -> Result<Self, ModelError> {
        self.transport = self.transport.with_timeout(timeout_seconds)?;
        Ok(self)
    }

    /// Bound the complete encoded request before transmission.
    pub fn with_request_limit(mut self, max_bytes: usize) -> Self {
        self.transport = self.transport.with_request_limit(max_bytes);
        self
    }

    /// Bound successful responses, including chunked bodies.
    pub fn with_response_limit(mut self, max_bytes: usize) -> Self {
        self.transport = self.transport.with_response_limit(max_bytes);
        self
    }

    /// Set the output-token ceiling and default; requests above it are refused.
    pub fn with_output_limit(mut self, max_tokens: u32) -> Self {
        self.transport = self.transport.with_output_limit(max_tokens);
        self
    }

    /// Enable adaptive thinking, explicitly disable it, or omit it with `None`.
    pub fn with_thinking(mut self, thinking: Option<ThinkingMode>) -> Self {
        self.transport = self.transport.with_thinking(thinking);
        self
    }
}

#[async_trait]
impl ModelProvider for AnthropicChatProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        self.transport.descriptor()
    }
    fn validate_configuration(&self) -> Result<(), ModelError> {
        self.transport.validate_configuration()
    }
    fn credential_fingerprint(&self) -> Option<String> {
        self.transport.credential_fingerprint()
    }
    fn credential_boundary(&self) -> Option<&CredentialBoundary> {
        self.transport.credential_boundary()
    }
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
    stop_reason: String,
    usage: Option<MessagesUsage>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ContentBlock {
    Text { text: String },
    Thinking { thinking: String, signature: String },
    RedactedThinking { data: String },
}

#[derive(Default, Deserialize)]
struct MessagesUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    output_tokens_details: Option<OutputTokensDetails>,
    cache_read_input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct OutputTokensDetails {
    thinking_tokens: Option<u64>,
}

#[async_trait]
impl ChatProvider for AnthropicChatProvider {
    async fn chat(&self, mut request: ChatRequest) -> Result<ChatResponse, ModelError> {
        let transport = &self.transport;
        secrets::credential_boundary(
            async {
                self.validate_configuration()?;
                request.max_output_tokens = Some(chat_output_tokens(
                    request.max_output_tokens,
                    transport.max_output_tokens,
                )?);
                let body = wire::anthropic_chat_body(
                    &transport.descriptor.identity.model.0,
                    &request,
                    transport.thinking,
                    transport.max_request_bytes,
                )?;
                let mut builder = transport
                    .client
                    .get()?
                    .post(format!(
                        "{}/messages",
                        transport.base_url.trim_end_matches('/')
                    ))
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .header("anthropic-version", "2023-06-01")
                    .body(body);
                if !transport.api_key.secret().is_empty() {
                    let mut header =
                        reqwest::header::HeaderValue::from_str(transport.api_key.secret())
                            .map_err(|_| {
                                ModelError::Auth(DiagnosticCode::AuthenticationRejected)
                            })?;
                    header.set_sensitive(true);
                    builder = builder.header("x-api-key", header);
                }
                let (raw, _) = provider_response_json(
                    builder,
                    transport.max_response_bytes,
                    ModelError::Unavailable,
                )
                .await?;
                let parsed: MessagesResponse = serde_json::from_value(raw.clone())
                    .map_err(|_| ModelError::Unavailable(DiagnosticCode::InvalidResponse))?;
                // Unsupported tool/pause/refusal outcomes cannot become a partial answer.
                if !matches!(
                    parsed.stop_reason.as_str(),
                    "end_turn" | "max_tokens" | "stop_sequence" | "model_context_window_exceeded"
                ) {
                    return Err(ModelError::Provider(DiagnosticCode::ProviderFailure));
                }
                let mut text = String::new();
                for block in parsed.content {
                    match block {
                        ContentBlock::Text { text: part } => text.push_str(&part),
                        // Reasoning is validated on the raw response by the credential owner,
                        // then discarded rather than copied into output or bookkeeping.
                        ContentBlock::Thinking {
                            thinking,
                            signature,
                        } => {
                            drop((thinking, signature));
                        }
                        ContentBlock::RedactedThinking { data } => {
                            drop(data);
                        }
                    }
                }
                let usage = parsed.usage.unwrap_or_default();
                // Anthropic input_tokens excludes both cache-read and cache-write tokens.
                let input = usage
                    .input_tokens
                    .map(|n| {
                        n.checked_add(usage.cache_read_input_tokens.unwrap_or(0))
                            .and_then(|n| {
                                n.checked_add(usage.cache_creation_input_tokens.unwrap_or(0))
                            })
                            .ok_or(ModelError::Provider(DiagnosticCode::InvalidResponse))
                    })
                    .transpose()?;
                let mut trace = success_trace(
                    &transport.descriptor,
                    request.role_binding.clone(),
                    request.source.clone(),
                    hash_json(&request)?,
                    Some(&text),
                );
                trace.usage = UsageTrace {
                    input_tokens: input,
                    output_tokens: usage.output_tokens,
                    reasoning_tokens: usage.output_tokens_details.and_then(|d| d.thinking_tokens),
                    reported_cost_usd: reported_cost_usd(&raw),
                    ..UsageTrace::default()
                };
                let miss = usage
                    .input_tokens
                    .map(|uncached| {
                        uncached
                            .checked_add(usage.cache_creation_input_tokens.unwrap_or(0))
                            .ok_or(ModelError::Provider(DiagnosticCode::InvalidResponse))
                    })
                    .transpose()?;
                // Keep omitted cache reads absent while projecting the known miss count.
                let (hit, _) =
                    observed_prompt_cache_counts(input, usage.cache_read_input_tokens, None, None)?;
                trace.usage.cache_hit_tokens = hit;
                trace.usage.cache_miss_tokens = miss;
                trace.cache = CacheTrace {
                    response_cache: CacheStatus::Miss,
                    prompt_cache: prompt_cache_status(input, hit, miss),
                    cached_input_tokens: hit,
                };
                trace.metadata = serde_json::json!({
                    "provider": {"response_id": raw.get("id").and_then(Value::as_str),
                        "served_model": raw.get("model").and_then(Value::as_str)},
                    "cache_miss_tokens": miss,
                    "cache_creation_input_tokens": usage.cache_creation_input_tokens,
                });
                provider_usage_identity(&mut trace, &raw, |identity| {
                    request
                        .messages
                        .iter()
                        .any(|message| message.content.contains(identity))
                });
                Ok(ChatResponse {
                    text,
                    finish_reason: Some(parsed.stop_reason),
                    trace,
                    raw_provider_response: Some(raw),
                })
            }
            .await,
            &transport.api_key,
        )
    }
}
