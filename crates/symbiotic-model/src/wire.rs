//! Provider request encoding shared by admission checks and HTTP transmission.
pub use crate::classify::jev_classify_body;
pub use crate::retrieval::{cohere_rerank_body, compatible_embedding_body};
use crate::{ChatMessage, ChatRequest, EmbeddingRequest, ModelError, ThinkingMode};
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};

#[cfg(test)]
thread_local! {
    static SERIALIZED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct CappedWriter<W> {
    output: W,
    written: usize,
    max_bytes: usize,
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max_bytes - self.written {
            return Err(io::Error::other("provider request limit exceeded"));
        }
        self.output.write_all(bytes)?;
        #[cfg(test)]
        SERIALIZED_BYTES.with(|count| count.set(count.get() + bytes.len()));
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

pub(crate) fn encode(
    value: &impl Serialize,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>, ModelError> {
    let mut body = CappedWriter {
        output: Vec::new(),
        written: 0,
        max_bytes: max_bytes.unwrap_or(usize::MAX),
    };
    serde_json::to_writer(&mut body, value).map_err(|_| {
        ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::ProviderRequestLimitExceeded)
    })?;
    Ok(body.output)
}

/// Count encoded JSON bytes without buffering, refusing to exceed `max_bytes`.
pub(crate) fn encoded_len(value: &impl Serialize, max_bytes: usize) -> Result<usize, ModelError> {
    let mut counter = CappedWriter {
        output: io::sink(),
        written: 0,
        max_bytes,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| {
        ModelError::InvalidRequest(symbiotic_core::DiagnosticCode::ProviderRequestLimitExceeded)
    })?;
    Ok(counter.written)
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
    response_format: Option<ResponseFormat<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<&'a str>,
    stream: bool,
}

#[derive(Serialize)]
struct ResponseFormat<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
}

/// Encode the complete OpenAI-compatible HTTP body, refusing to buffer more than
/// `max_bytes` when set. Local metadata is excluded, exactly as in the adapter.
pub fn openai_chat_body(
    model: &str,
    request: &ChatRequest,
    thinking: Option<ThinkingMode>,
    reasoning_effort: Option<&str>,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>, ModelError> {
    super::validate_chat_settings(thinking, reasoning_effort)?;
    encode(
        &OpenAiChatWireRequest {
            model,
            messages: &request.messages,
            max_tokens: request.max_output_tokens,
            temperature: request.temperature,
            response_format: request
                .response_format
                .as_deref()
                .map(|kind| ResponseFormat { kind }),
            thinking: thinking.map(|mode| serde_json::json!({ "type": mode })),
            reasoning_effort,
            stream: false,
        },
        max_bytes,
    )
}

#[derive(Serialize)]
struct GeminiEmbedWireRequest<'a> {
    model: &'a str,
    content: GeminiContent<'a>,
    output_dimensionality: usize,
}

#[derive(Serialize)]
struct GeminiBatchEmbedWireRequest<'a> {
    requests: GeminiRequests<'a>,
}

#[derive(Serialize)]
struct GeminiContent<'a> {
    parts: [GeminiPart<'a>; 1],
}

#[derive(Serialize)]
struct GeminiPart<'a> {
    text: &'a str,
}

struct GeminiRequests<'a> {
    model: &'a str,
    dimensions: usize,
    inputs: &'a [String],
}

impl Serialize for GeminiRequests<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.inputs.len()))?;
        for input in self.inputs {
            seq.serialize_element(&GeminiEmbedWireRequest {
                model: self.model,
                content: GeminiContent {
                    parts: [GeminiPart { text: input }],
                },
                output_dimensionality: self.dimensions,
            })?;
        }
        seq.end()
    }
}

/// Refuse request options the installed Gemini adapter does not implement.
pub fn validate_gemini_options(
    dimensions: usize,
    request: &EmbeddingRequest,
) -> Result<(), ModelError> {
    if dimensions == 0
        || request
            .dimensions
            .is_some_and(|requested| requested != dimensions)
    {
        return Err(ModelError::InvalidRequest(
            symbiotic_core::DiagnosticCode::GeminiRequestDimensionsDifferFromConfiguredBinding,
        ));
    }
    if request.task.is_some() {
        return Err(ModelError::InvalidRequest(
            symbiotic_core::DiagnosticCode::GeminiTaskOptionIsUnsupported,
        ));
    }
    Ok(())
}

/// Encode the complete Gemini single/batch HTTP body, refusing to buffer more
/// than `max_bytes` when set, including repeated model names and JSON escaping.
pub fn gemini_embedding_body(
    model: &str,
    dimensions: usize,
    request: &EmbeddingRequest,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>, ModelError> {
    validate_gemini_options(dimensions, request)?;
    let model = format!("models/{}", model.trim_start_matches("models/"));
    let wire_request = |input| GeminiEmbedWireRequest {
        model: &model,
        content: GeminiContent {
            parts: [GeminiPart { text: input }],
        },
        output_dimensionality: dimensions,
    };
    if request.inputs.len() == 1 {
        encode(&wire_request(request.inputs[0].as_str()), max_bytes)
    } else {
        encode(
            &GeminiBatchEmbedWireRequest {
                requests: GeminiRequests {
                    model: &model,
                    dimensions,
                    inputs: &request.inputs,
                },
            },
            max_bytes,
        )
    }
}

/// Encode a Messages request with an optional leading system prompt, followed
/// by user/assistant messages in their original order, ending with a user turn.
/// Other roles, response formats, and non-default temperature with enabled
/// thinking are refused rather than omitted.
pub fn anthropic_chat_body(
    model: &str,
    request: &ChatRequest,
    thinking: Option<ThinkingMode>,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>, ModelError> {
    #[derive(Serialize)]
    struct Body<'a> {
        model: &'a str,
        max_tokens: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        system: Option<&'a str>,
        messages: &'a [ChatMessage],
        #[serde(skip_serializing_if = "Option::is_none")]
        temperature: Option<f32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        thinking: Option<Value>,
        stream: bool,
    }
    let (system, messages) = match request.messages.split_first() {
        Some((first, rest)) if first.role == "system" => (Some(first.content.as_str()), rest),
        _ => (None, request.messages.as_slice()),
    };
    if request.response_format.is_some()
        || request.temperature.is_some_and(|temperature| {
            !temperature.is_finite() || !(0.0..=1.0).contains(&temperature)
        })
        || messages.last().is_none_or(|message| message.role != "user")
        || (thinking == Some(ThinkingMode::Enabled)
            && request
                .temperature
                .is_some_and(|temperature| temperature != 1.0))
        || messages
            .iter()
            .any(|m| !matches!(m.role.as_str(), "user" | "assistant"))
    {
        return Err(ModelError::InvalidRequest(
            symbiotic_core::DiagnosticCode::InvalidConfiguration,
        ));
    }
    encode(
        &Body {
            model,
            max_tokens: request.max_output_tokens,
            system,
            messages,
            temperature: request.temperature,
            thinking: thinking.map(|mode| match mode {
                ThinkingMode::Enabled => serde_json::json!({"type":"adaptive"}),
                ThinkingMode::Disabled => serde_json::json!({"type":"disabled"}),
            }),
            stream: false,
        },
        max_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encoding_jev_byte_limit_precedes_whole_input_counting() {
        let state_request = crate::ClassifyRequest::new(
            serde_json::from_value(serde_json::json!({"text": "x".repeat(16_384)})).unwrap(),
            vec![crate::ClassifierQuestion::noul("q", "", None, None)],
        );
        let questions_request = crate::ClassifyRequest::new(
            serde_json::Map::new(),
            (0..1000)
                .map(|id| crate::ClassifierQuestion::noul(id.to_string(), "", None, None))
                .collect(),
        );
        for (trigger, request) in [("state", state_request), ("questions", questions_request)] {
            assert!(jev_classify_body("jev", &request, None).is_ok());
            SERIALIZED_BYTES.with(|count| count.set(0));
            let error = jev_classify_body("jev", &request, Some(1024)).unwrap_err();
            let serialized = SERIALIZED_BYTES.with(|count| count.get());
            assert_eq!(
                error.code(),
                symbiotic_core::DiagnosticCode::ProviderRequestLimitExceeded
            );
            eprintln!("Jev {trigger} rejected: {serialized} serialized bytes, cap 1024");
            // Count successful writes across both counting and encoding. Internal
            // string escape scans are outside the capped-writer contract.
            assert!(serialized <= 1024, "serialized {serialized} bytes");
        }
    }

    #[test]
    fn gemini_wire_refuses_unsupported_task_and_conflicting_dimensions() {
        let mut request = EmbeddingRequest {
            inputs: vec!["synthetic".into()],
            dimensions: Some(3),
            task: None,
            role_binding: None,
            source: None,
            metadata: Value::Null,
        };
        assert!(gemini_embedding_body("model", 3, &request, Some(1024)).is_ok());
        request.task = Some("retrieval_query".into());
        assert!(gemini_embedding_body("model", 3, &request, Some(1024)).is_err());
        request.task = None;
        request.dimensions = Some(4);
        assert!(gemini_embedding_body("model", 3, &request, Some(1024)).is_err());
    }
    #[test]
    fn gemini_wire_limit_covers_single_and_batch_expansion_at_exact_boundary() {
        for count in [1, 128] {
            let request = EmbeddingRequest {
                inputs: vec!["\\\"\n\té".into(); count],
                dimensions: Some(8),
                task: None,
                role_binding: None,
                source: None,
                metadata: Value::Null,
            };
            let body = gemini_embedding_body("test-model", 8, &request, None).unwrap();
            let wire: Value = serde_json::from_slice(&body).unwrap();
            let first = if count == 1 {
                &wire
            } else {
                &wire["requests"][0]
            };
            assert_eq!(first["content"]["parts"][0]["text"], request.inputs[0]);
            assert_eq!(first["model"], "models/test-model");
            assert_eq!(first["output_dimensionality"], 8);
            assert_eq!(
                gemini_embedding_body("test-model", 8, &request, Some(body.len())).unwrap(),
                body
            );
            assert!(
                gemini_embedding_body("test-model", 8, &request, Some(body.len() - 1)).is_err()
            );
            assert!(gemini_embedding_body("test-model", 8, &request, Some(0)).is_err());
        }
    }

    #[test]
    fn request_encoding_counter_stops_serializing_at_the_cap() {
        use serde::ser::SerializeSeq;
        use std::cell::Cell;

        struct Items(Cell<usize>);
        impl Serialize for Items {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut seq = serializer.serialize_seq(Some(4096))?;
                for _ in 0..4096 {
                    self.0.set(self.0.get() + 1);
                    seq.serialize_element("x")?;
                }
                seq.end()
            }
        }
        let items = Items(Cell::new(0));
        assert!(encoded_len(&items, 32).is_err());
        assert_eq!(items.0.get(), 9);
        assert_eq!(encoded_len(&["x", "y"], 9).unwrap(), 9);
        assert!(encoded_len(&["x", "y"], 8).is_err());
    }

    #[test]
    fn capped_writer_never_buffers_beyond_limit() {
        let mut writer = CappedWriter {
            output: Vec::new(),
            written: 0,
            max_bytes: 4,
        };
        writer.write_all(b"1234").unwrap();
        assert!(writer.write_all(b"5").is_err());
        assert_eq!(writer.output, b"1234");
        let mut writer = CappedWriter {
            output: Vec::new(),
            written: 0,
            max_bytes: 4,
        };
        assert!(writer.write_all(b"12345").is_err());
        assert!(writer.output.is_empty());
    }
}
