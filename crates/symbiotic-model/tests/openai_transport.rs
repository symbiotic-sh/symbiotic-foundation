use std::io::{Read, Write};
use std::net::TcpListener;
use symbiotic_core::Sensitivity;
use symbiotic_model::{
    ChatMessage, ChatProvider, ChatRequest, OpenAiCompatibleChatProvider, ThinkingMode,
    prompt_cache_counts,
};
use symbiotic_trace::CacheStatus;

fn fixture(body: serde_json::Value) -> (String, std::thread::JoinHandle<serde_json::Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
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
        let payload = body.to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload).unwrap();
        serde_json::from_slice(&bytes[offset..offset + length]).unwrap()
    });
    (url, handle)
}

fn request() -> ChatRequest {
    ChatRequest {
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "synthetic evidence".into(),
        }],
        max_output_tokens: Some(128),
        temperature: Some(0.0),
        response_format: None,
        sensitivity: Sensitivity::Shareable,
        role_binding: None,
        source: None,
        metadata: serde_json::json!({}),
    }
}

#[tokio::test]
async fn missing_cache_counters_remain_unknown() {
    let (url, server) = fixture(serde_json::json!({
        "choices":[{"message":{"content":"OK"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":10,"completion_tokens":2}
    }));
    let response = OpenAiCompatibleChatProvider::new("fixture", "fixture", url, "synthetic-key")
        .chat(request())
        .await
        .unwrap();
    server.join().unwrap();
    assert_eq!(
        response.trace.cache.prompt_cache,
        CacheStatus::NotApplicable
    );
    assert_eq!(response.trace.cache.cached_input_tokens, None);
}

#[tokio::test]
async fn low_thinking_and_metadata_without_reasoning_text() {
    let (url, server) = fixture(serde_json::json!({
        "id":"fixture-id", "model":"served-model", "created":123,
        "choices":[{"message":{"content":"OK","reasoning_content":"private hidden reasoning"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":10,"completion_tokens":5,
            "prompt_tokens_details":{"cached_tokens":4},
            "completion_tokens_details":{"reasoning_tokens":3}, "cost":"0.00001234"}
    }));
    let response =
        OpenAiCompatibleChatProvider::new("fixture", "requested-model", url, "synthetic-key")
            .with_thinking(Some(ThinkingMode::Enabled))
            .with_reasoning_effort("low")
            .chat(request())
            .await
            .unwrap();
    let wire = server.join().unwrap();
    assert_eq!(wire["thinking"]["type"], "enabled");
    assert_eq!(wire["reasoning_effort"], "low");
    assert_eq!(wire["max_tokens"], 128);
    assert_eq!(response.trace.model.model.0, "requested-model");
    assert_eq!(
        response.trace.metadata["provider"]["served_model"],
        "served-model"
    );
    assert_eq!(
        response.trace.metadata["provider"]["response_id"],
        "fixture-id"
    );
    assert_eq!(response.trace.metadata["provider"]["created"], 123);
    assert_eq!(
        response.trace.metadata["provider"]["reported_cost_usd"],
        "0.00001234"
    );
    assert_eq!(response.trace.usage.reasoning_tokens, Some(3));
    assert_eq!(response.trace.usage.cost_micro_usd, None);
    assert_eq!(response.trace.cache.prompt_cache, CacheStatus::PartialHit);
    assert_eq!(response.trace.metadata["cache_miss_tokens"], 6);
    assert!(
        !serde_json::to_string(&response.trace)
            .unwrap()
            .contains("private hidden reasoning")
    );
}

#[tokio::test]
async fn disabled_thinking_omits_effort_and_nullable_content_keeps_identity() {
    let (url, server) = fixture(serde_json::json!({
        "id":"no-usage", "model":"served-model",
        "choices":[{"message":{"content":null},"finish_reason":"length"}]
    }));
    let response = OpenAiCompatibleChatProvider::new("fixture", "fixture", url, "synthetic-key")
        .with_thinking(Some(ThinkingMode::Disabled))
        .with_reasoning_effort("low")
        .chat(request())
        .await
        .unwrap();
    let wire = server.join().unwrap();
    assert_eq!(wire["thinking"]["type"], "disabled");
    assert!(wire.get("reasoning_effort").is_none());
    assert_eq!(response.text, "");
    assert_eq!(response.finish_reason.as_deref(), Some("length"));
    assert_eq!(
        response.trace.metadata["provider"]["response_id"],
        "no-usage"
    );
    assert_eq!(response.trace.usage.input_tokens, None);
}

#[test]
fn cache_counts_reject_conflicts_and_derive_only_numeric_evidence() {
    assert_eq!(
        prompt_cache_counts(Some(10), Some(4), Some(6), Some(5)),
        (None, None)
    );
    assert_eq!(
        prompt_cache_counts(Some(10), Some(4), Some(7), None),
        (None, None)
    );
    assert_eq!(
        prompt_cache_counts(Some(10), None, Some(11), None),
        (None, None)
    );
    assert_eq!(
        prompt_cache_counts(Some(10), None, Some(6), None),
        (Some(4), Some(6))
    );
    assert_eq!(
        prompt_cache_counts(Some(10), None, None, None),
        (None, None)
    );
    assert_eq!(
        prompt_cache_counts(Some(10), Some(0), None, None),
        (Some(0), Some(10))
    );
}

#[tokio::test]
async fn invalid_reported_costs_remain_unknown() {
    for cost in [
        serde_json::json!(-0.1),
        serde_json::json!("NaN"),
        serde_json::json!("inf"),
        serde_json::json!("invalid"),
    ] {
        let (url, server) = fixture(serde_json::json!({
            "choices":[{"message":{"content":"OK"}}],
            "usage":{"cost":cost}
        }));
        let response =
            OpenAiCompatibleChatProvider::new("fixture", "fixture", url, "synthetic-key")
                .chat(request())
                .await
                .unwrap();
        server.join().unwrap();
        assert!(response.trace.metadata["provider"]["reported_cost_usd"].is_null());
    }
}
