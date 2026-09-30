//! Provider request encoding shared by admission checks and HTTP transmission.
use crate::{ChatMessage, ChatRequest, EmbeddingRequest, ModelError, ThinkingMode};
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};

struct CappedBody {
    bytes: Vec<u8>,
    max_bytes: usize,
}

impl Write for CappedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max_bytes - self.bytes.len() {
            return Err(io::Error::other("provider request limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode(value: &impl Serialize, max_bytes: Option<usize>) -> Result<Vec<u8>, ModelError> {
    let mut body = CappedBody {
        bytes: Vec::new(),
        max_bytes: max_bytes.unwrap_or(usize::MAX),
    };
    serde_json::to_writer(&mut body, value)
        .map_err(|_| ModelError::InvalidRequest("provider request limit exceeded".into()))?;
    Ok(body.bytes)
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
    response_format: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<&'a str>,
    stream: bool,
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
    encode(
        &OpenAiChatWireRequest {
            model,
            messages: &request.messages,
            max_tokens: request.max_output_tokens,
            temperature: request.temperature,
            response_format: request
                .response_format
                .as_deref()
                .map(|format| serde_json::json!({ "type": format })),
            thinking: thinking.map(|mode| serde_json::json!({ "type": mode })),
            reasoning_effort: if thinking == Some(ThinkingMode::Disabled) {
                None
            } else {
                reasoning_effort
            },
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
    requests: Vec<GeminiEmbedWireRequest<'a>>,
}

#[derive(Serialize)]
struct GeminiContent<'a> {
    parts: Vec<GeminiPart<'a>>,
}

#[derive(Serialize)]
struct GeminiPart<'a> {
    text: &'a str,
}

/// Encode the complete Gemini single/batch HTTP body, refusing to buffer more
/// than `max_bytes` when set, including repeated model names and JSON escaping.
pub fn gemini_embedding_body(
    model: &str,
    dimensions: usize,
    request: &EmbeddingRequest,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>, ModelError> {
    let model = format!("models/{}", model.trim_start_matches("models/"));
    let wire_request = |input| GeminiEmbedWireRequest {
        model: &model,
        content: GeminiContent {
            parts: vec![GeminiPart { text: input }],
        },
        output_dimensionality: dimensions,
    };
    if request.inputs.len() == 1 {
        encode(&wire_request(request.inputs[0].as_str()), max_bytes)
    } else {
        encode(
            &GeminiBatchEmbedWireRequest {
                requests: request
                    .inputs
                    .iter()
                    .map(|input| wire_request(input.as_str()))
                    .collect(),
            },
            max_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use symbiotic_core::Sensitivity;

    #[test]
    fn gemini_wire_limit_covers_single_and_batch_expansion_at_exact_boundary() {
        for count in [1, 128] {
            let request = EmbeddingRequest {
                inputs: vec!["\\\"\n\té".into(); count],
                dimensions: Some(8),
                task: None,
                sensitivity: Sensitivity::Private,
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
    fn capped_writer_never_buffers_beyond_limit() {
        let mut writer = CappedBody {
            bytes: Vec::new(),
            max_bytes: 4,
        };
        writer.write_all(b"1234").unwrap();
        assert!(writer.write_all(b"5").is_err());
        assert_eq!(writer.bytes, b"1234");
        let mut writer = CappedBody {
            bytes: Vec::new(),
            max_bytes: 4,
        };
        assert!(writer.write_all(b"12345").is_err());
        assert!(writer.bytes.is_empty());
    }
}
