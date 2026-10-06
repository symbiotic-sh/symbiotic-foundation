//! Rejected request encoding must allocate near the byte cap, not the caller's input size.
#[path = "../../test-support/request_allocations.rs"]
mod allocations;

use serde_json::Value;
use symbiotic_model::{
    ChatMessage, ChatRequest, ClassifierQuestion, ClassifyRequest, DiagnosticCode,
    EmbeddingRequest, ModelError, wire,
};

const LIMIT: usize = 1024;
const LARGE: usize = 128 * 1024;

fn chat() -> ChatRequest {
    ChatRequest {
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "hello\n\"é".into(),
        }],
        max_output_tokens: Some(10),
        temperature: None,
        response_format: Some("json_object".into()),
        role_binding: None,
        source: None,
        metadata: Value::Null,
    }
}

fn refused(operation: impl FnOnce() -> Result<Vec<u8>, ModelError>, expected: DiagnosticCode) {
    let (result, allocated) = allocations::allocated(operation);
    assert_eq!(result.unwrap_err().code(), expected);
    eprintln!("request rejected with {expected:?}: {allocated} allocated bytes, cap {LIMIT}");
    // Count every allocation/reallocation request, rather than only the final live buffer.
    assert!(
        allocated <= 8 * LIMIT,
        "allocated {allocated} bytes for a {LIMIT}-byte cap"
    );
}

#[test]
fn request_encoding_openai_response_format_is_borrowed_and_byte_identical() {
    let mut request = chat();
    let expected = "{\"model\":\"model\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\\n\\\"é\"}],\"max_tokens\":10,\"response_format\":{\"type\":\"json_object\"},\"stream\":false}".as_bytes();
    assert_eq!(
        wire::openai_chat_body("model", &request, None, None, Some(expected.len())).unwrap(),
        expected
    );
    assert_eq!(
        wire::openai_chat_body("model", &request, None, None, None).unwrap(),
        expected
    );
    request.response_format = Some("x".repeat(LARGE));
    refused(
        || wire::openai_chat_body("model", &request, None, None, Some(LIMIT)),
        DiagnosticCode::ProviderRequestLimitExceeded,
    );
}

#[test]
fn request_encoding_gemini_batch_is_incremental_and_byte_identical() {
    let mut request = EmbeddingRequest {
        inputs: vec!["a\n\"é".into(), "b".into()],
        dimensions: Some(8),
        task: None,
        role_binding: None,
        source: None,
        metadata: Value::Null,
    };
    let first = "{\"model\":\"models/model\",\"content\":{\"parts\":[{\"text\":\"a\\n\\\"é\"}]},\"output_dimensionality\":8}";
    let second =
        r#"{"model":"models/model","content":{"parts":[{"text":"b"}]},"output_dimensionality":8}"#;
    let batch = format!("{{\"requests\":[{first},{second}]}}");
    assert_eq!(
        wire::gemini_embedding_body("models/model", 8, &request, Some(batch.len())).unwrap(),
        batch.as_bytes()
    );
    request.inputs.pop();
    assert_eq!(
        wire::gemini_embedding_body("model", 8, &request, Some(first.len())).unwrap(),
        first.as_bytes()
    );
    request.inputs = vec![String::new(); 4096];
    refused(
        || wire::gemini_embedding_body("model", 8, &request, Some(LIMIT)),
        DiagnosticCode::ProviderRequestLimitExceeded,
    );
}

fn classify() -> ClassifyRequest {
    ClassifyRequest::new(
        serde_json::from_value(serde_json::json!({"text": "hello\n\"é"})).unwrap(),
        vec![ClassifierQuestion::noul("q", "Check.", None, None)],
    )
}

fn jev_bytes_are_identical(request: &ClassifyRequest) {
    let expected = "{\"model\":\"jev\",\"state\":{\"text\":\"hello\\n\\\"é\"},\"questions\":{\"q\":{\"type\":\"noul\",\"instructions\":\"Check.\"}}}".as_bytes();
    assert_eq!(
        wire::jev_classify_body("jev", request, Some(expected.len())).unwrap(),
        expected
    );
    assert_eq!(
        wire::jev_classify_body("jev", request, None).unwrap(),
        expected
    );
}

#[test]
fn request_encoding_jev_state_is_counted_without_copies() {
    let mut request = classify();
    jev_bytes_are_identical(&request);
    for (size, expected_error) in [
        (16 * LIMIT, DiagnosticCode::ProviderRequestLimitExceeded),
        (LARGE, DiagnosticCode::InvalidConfiguration),
    ] {
        request
            .state
            .insert("text".into(), Value::String("x".repeat(size)));
        refused(
            || wire::jev_classify_body("jev", &request, Some(LIMIT)),
            expected_error,
        );
    }
}

#[test]
fn request_encoding_jev_questions_are_counted_without_copies() {
    let mut request = classify();
    jev_bytes_are_identical(&request);
    for (size, expected_error) in [
        (16 * LIMIT, DiagnosticCode::ProviderRequestLimitExceeded),
        (LARGE, DiagnosticCode::InvalidConfiguration),
    ] {
        request.questions[0].instructions = "x".repeat(size);
        refused(
            || wire::jev_classify_body("jev", &request, Some(LIMIT)),
            expected_error,
        );
    }
}

#[test]
fn request_encoding_jev_many_questions_are_refused_before_uniqueness_allocation() {
    let mut request = classify();
    request.questions = (0..4096)
        .map(|id| ClassifierQuestion::noul(id.to_string(), "Check.", None, None))
        .collect();
    refused(
        || wire::jev_classify_body("jev", &request, Some(LIMIT)),
        DiagnosticCode::InvalidConfiguration,
    );
}

#[test]
fn request_encoding_jev_many_options_are_refused_before_uniqueness_allocation() {
    let mut request = classify();
    request.questions = vec![ClassifierQuestion::choice(
        "q",
        "Choose.",
        (0..4096).map(|id| (id.to_string(), "Option.")),
    )];
    refused(
        || wire::jev_classify_body("jev", &request, Some(LIMIT)),
        DiagnosticCode::InvalidConfiguration,
    );
}

#[test]
fn request_encoding_jev_empty_questions_keep_their_diagnostic_before_token_limits() {
    let mut request = classify();
    request.questions.clear();
    request
        .state
        .insert("text".into(), Value::String("x".repeat(LARGE)));
    refused(
        || wire::jev_classify_body("jev", &request, Some(LIMIT)),
        DiagnosticCode::AClassifyRequestNeedsAtLeastOneQuestion,
    );
}
