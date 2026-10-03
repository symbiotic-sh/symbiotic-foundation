use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use symbiotic_core::DiagnosticCode;
use symbiotic_model::{
    AnthropicChatProvider, ChatMessage, ChatProvider, ChatRequest, ModelError, ModelProvider,
    ThinkingMode, wire,
};
use symbiotic_trace::CacheStatus;
const KEY: &str = "synthetic-anthropic-test-secret";
fn fixture(
    status: u16,
    body: &str,
    chunked: bool,
) -> (String, std::thread::JoinHandle<(String, serde_json::Value)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let payload = body.to_owned();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        let (offset, length) = loop {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..offset]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (offset + 4, length);
            }
        };
        while bytes.len() < offset + length {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
        }
        let headers = String::from_utf8(bytes[..offset].to_vec()).unwrap();
        if chunked {
            let _ = write!(
                stream,
                "HTTP/1.1 {status} test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{payload}\r\n0\r\n\r\n",
                payload.len()
            );
        } else {
            let _ = write!(
                stream,
                "HTTP/1.1 {status} test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
        }
        (
            headers,
            serde_json::from_slice(&bytes[offset..offset + length]).unwrap(),
        )
    });
    (url, handle)
}

fn request() -> ChatRequest {
    ChatRequest {
        messages: vec![
            ChatMessage {
                role: "system".into(),
                content: "system\n\"é".into(),
            },
            ChatMessage {
                role: "user".into(),
                content: "evidence".into(),
            },
        ],
        max_output_tokens: None,
        temperature: None,
        response_format: None,
        role_binding: Some("local-role".into()),
        source: Some("local-source".into()),
        metadata: json!({"private":"metadata"}),
    }
}
fn provider(url: &str) -> AnthropicChatProvider {
    AnthropicChatProvider::new("fixture", "fixture-model", url, KEY)
        .with_request_limit(65536)
        .with_response_limit(65536)
}
fn answer() -> Value {
    json!({"id":"fixture-id", "model":"served-model", "stop_reason":"end_turn",
        "content":[{"type":"thinking","thinking":"private reasoning","signature":"sig"},
        {"type":"text","text":"first"},{"type":"redacted_thinking","data":"private redacted"},{"type":"text","text":"second"}],
        "usage":{"input_tokens":7,"output_tokens":3,"cache_read_input_tokens":5,"cache_creation_input_tokens":2}})
}
#[tokio::test]
async fn messages_headers_default_tokens_thinking_and_usage() {
    let (url, server) = fixture(200, &answer().to_string(), false);
    let response = provider(&format!("{url}/v1/"))
        .chat(request())
        .await
        .unwrap();
    let (headers, body) = server.join().unwrap();
    assert!(headers.starts_with("POST /v1/messages HTTP/1.1"));
    assert!(headers.contains(&format!("x-api-key: {KEY}")));
    assert!(headers.contains("anthropic-version: 2023-06-01"));
    assert!(headers.contains("content-type: application/json"));
    assert!(!headers.contains("authorization:"));
    assert_eq!(
        body,
        json!({"model":"fixture-model","max_tokens":16000,"system":"system\n\"é",
        "messages":[{"role":"user","content":"evidence"}],"thinking":{"type":"adaptive"},"stream":false})
    );
    assert_eq!(response.text, "firstsecond");
    assert_eq!(response.finish_reason.as_deref(), Some("end_turn"));
    assert_eq!(response.trace.usage.input_tokens, Some(14));
    assert_eq!(response.trace.usage.output_tokens, Some(3));
    assert_eq!(response.trace.cache.cached_input_tokens, Some(5));
    assert_eq!(response.trace.cache.prompt_cache, CacheStatus::PartialHit);
    assert_eq!(response.trace.metadata["cache_miss_tokens"], 9);
    assert_eq!(
        response.trace.metadata["provider"]["served_model"],
        "served-model"
    );
    assert_eq!(response.trace.role_binding.as_deref(), Some("local-role"));
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("private reasoning")
    );
    assert!(response.raw_provider_response.is_none());
}
#[tokio::test]
async fn disabled_thinking_and_explicit_output_limit_preserve_conversation_order() {
    for thinking in [None, Some(ThinkingMode::Disabled)] {
        let (url, server) = fixture(200, &answer().to_string(), false);
        let mut req = request();
        req.messages.extend([
            ChatMessage {
                role: "assistant".into(),
                content: "previous".into(),
            },
            ChatMessage {
                role: "user".into(),
                content: "next".into(),
            },
        ]);
        req.max_output_tokens = Some(128);
        req.temperature = Some(0.0);
        provider(&url)
            .with_output_limit(256)
            .with_thinking(thinking)
            .chat(req.clone())
            .await
            .unwrap();
        let (_, body) = server.join().unwrap();
        assert!(body.get("thinking").is_none());
        assert_eq!(body["max_tokens"], 128);
        assert_eq!(body["temperature"], 0.0);
        assert_eq!(
            body["messages"],
            serde_json::to_value(&req.messages[1..]).unwrap()
        );
    }
}
#[tokio::test]
async fn request_limits_and_unsupported_options_refuse_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    for case in 0..8 {
        let mut req = request();
        let mut p = provider(&url);
        match case {
            0 => p = p.with_request_limit(1),
            1 => req.max_output_tokens = Some(16001),
            2 => req.max_output_tokens = Some(0),
            3 => p = p.with_output_limit(0),
            4 => req.response_format = Some("json_object".into()),
            5 => req.messages[1].role = "tool".into(),
            6 => req.messages.push(ChatMessage {
                role: "system".into(),
                content: "late".into(),
            }),
            _ => req.messages.truncate(1),
        }
        assert!(
            matches!(p.chat(req).await, Err(ModelError::InvalidRequest(_))),
            "case {case}"
        );
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[tokio::test]
async fn byte_limits_are_required_and_endpoint_credentials_refused() {
    for p in [
        AnthropicChatProvider::new("f", "m", "http://127.0.0.1:9", KEY),
        provider("http://127.0.0.1:9").with_request_limit(0),
        provider("http://127.0.0.1:9").with_response_limit(0),
        provider("http://user:password@127.0.0.1:9"),
    ] {
        assert!(p.validate_configuration().is_err());
        assert!(p.chat(request()).await.is_err());
    }
}
#[tokio::test]
async fn exact_encoded_request_boundary_includes_system_escaping_and_thinking() {
    let mut req = request();
    req.max_output_tokens = Some(16000);
    let bytes = wire::anthropic_chat_body("fixture-model", &req, Some(ThinkingMode::Enabled), None)
        .unwrap();
    let (url, server) = fixture(200, &answer().to_string(), false);
    provider(&url)
        .with_request_limit(bytes.len())
        .chat(req.clone())
        .await
        .unwrap();
    assert_eq!(
        server.join().unwrap().1,
        serde_json::from_slice::<Value>(&bytes).unwrap()
    );
    assert!(
        wire::anthropic_chat_body(
            "fixture-model",
            &req,
            Some(ThinkingMode::Enabled),
            Some(bytes.len() - 1)
        )
        .is_err()
    );
}
#[tokio::test]
async fn success_response_limit_covers_content_length_and_chunked_bodies() {
    for chunked in [false, true] {
        let (url, server) = fixture(200, &"x".repeat(4096), chunked);
        assert!(matches!(
            provider(&url)
                .with_response_limit(1024)
                .chat(request())
                .await,
            Err(ModelError::Provider(
                DiagnosticCode::ProviderResponseLimitExceeded
            ))
        ));
        server.join().unwrap();
    }
}
#[tokio::test]
async fn status_mapping_discards_error_bodies_and_refuses_redirects() {
    for (status, expected) in [
        (401, DiagnosticCode::AuthenticationRejected),
        (403, DiagnosticCode::AuthenticationRejected),
        (402, DiagnosticCode::HttpBudgetExhausted),
        (408, DiagnosticCode::HttpTimeout),
        (504, DiagnosticCode::HttpTimeout),
        (429, DiagnosticCode::HttpRateLimited),
        (500, DiagnosticCode::HttpUnavailable),
        (529, DiagnosticCode::HttpUnavailable),
        (400, DiagnosticCode::HttpFailure),
        (302, DiagnosticCode::ProviderRedirectRefused),
    ] {
        let (url, server) = fixture(status, &format!("invalid JSON echo {KEY}"), false);
        let error = provider(&url).chat(request()).await.unwrap_err();
        server.join().unwrap();
        assert_eq!(error.code(), expected);
        assert!(!format!("{error:?} {error}").contains(KEY));
    }
}
#[tokio::test]
async fn malformed_refusal_and_unsupported_blocks_fail_visibly() {
    let mut cases = vec![
        json!({}),
        json!({"content":[],"stop_reason":"refusal"}),
        json!({"content":[{"type":"text"}],"stop_reason":"end_turn"}),
        json!({"content":[{"type":"tool_use","id":"x"}],"stop_reason":"tool_use"}),
    ];
    let mut overflow = answer();
    overflow["usage"]["input_tokens"] = json!(u64::MAX);
    cases.push(overflow);
    for body in cases {
        let (url, server) = fixture(200, &body.to_string(), false);
        assert!(matches!(
            provider(&url).chat(request()).await,
            Err(ModelError::Provider(_))
        ));
        server.join().unwrap();
    }
    let (url, server) = fixture(200, "invalid JSON", false);
    assert!(matches!(
        provider(&url).chat(request()).await,
        Err(ModelError::Unavailable(DiagnosticCode::InvalidResponse))
    ));
    server.join().unwrap();
}
#[tokio::test]
async fn credential_echo_in_text_reasoning_or_metadata_never_returns() {
    for path in ["/content/1/text", "/content/0/thinking", "/id"] {
        let mut body = answer();
        *body.pointer_mut(path).unwrap() = json!(KEY);
        let (url, server) = fixture(200, &body.to_string(), false);
        let error = provider(&url).chat(request()).await.unwrap_err();
        server.join().unwrap();
        assert!(!format!("{error:?} {error}").contains(KEY));
    }
}
#[tokio::test]
async fn max_tokens_finish_reason_and_missing_usage_remain_visible() {
    let (url, server) = fixture(
        200,
        &json!({"content":[],"stop_reason":"max_tokens"}).to_string(),
        false,
    );
    let response = provider(&url).chat(request()).await.unwrap();
    server.join().unwrap();
    assert_eq!(response.text, "");
    assert_eq!(response.finish_reason.as_deref(), Some("max_tokens"));
    assert_eq!(response.trace.usage.input_tokens, None);
}
