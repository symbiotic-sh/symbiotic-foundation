use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
};
use symbiotic_core::{ProviderPrincipalId, Sensitivity, TenantId};
use symbiotic_model::*;

const KEY: &str = "synthetic-retrieval-key";
const ADAPTERS: [ModelAdapter; 3] = [
    ModelAdapter::OpenAiEmbedding,
    ModelAdapter::OllamaEmbedding,
    ModelAdapter::CohereRerank,
];
fn registry(adapter: ModelAdapter, endpoint: &str, response_limit: usize) -> ModelRegistry {
    let rerank = adapter == ModelAdapter::CohereRerank;
    let mut config: Value =
        serde_json::from_slice(include_bytes!("../../../examples/model-registry.json")).unwrap();
    config["models"][0]["adapter"] = json!(adapter);
    config["models"][0]["operations"] = json!([adapter.capability()]);
    config["models"][0]["identity"]["operation"] =
        json!(if rerank { "rerank" } else { "embedding" });
    config["models"][0]["identity"]["model"] = json!("Qwen3-Embedding-8B");
    config["accounts"] = json!([{"id":"account", "policy": ModelQueueConfig {
        request_timeout_seconds: Some(2), retry_attempts: 1, logical_retry_attempts: 1, ..ModelQueueConfig::default()
    }}]);
    config["bindings"] = json!([{
        "identity":{"tenant":"tenant","provider":"provider","revision":"1","account":"account"},
        "model":"example-chat","endpoint":endpoint,"secret_ref":null,"account_policy":"account","account_sharing_key":null,
        "limits":{"max_request_bytes":4096,"max_response_bytes":response_limit,"max_output_tokens":null},
        "settings": if rerank {json!({"rerank_input_bytes":64,"rerank_candidates":2})}
                    else {json!({"dimensions":2,"embedding_full_dimensions":1024})}
    }]);
    ModelRegistry::from_json(&serde_json::to_vec(&config).unwrap()).unwrap()
}
fn embed_request() -> EmbeddingRequest {
    EmbeddingRequest {
        inputs: vec!["synthetic input".into()],
        dimensions: None,
        task: None,
        sensitivity: Sensitivity::Private,
        role_binding: None,
        source: None,
        metadata: Value::Null,
    }
}
fn rerank_request() -> RerankRequest {
    RerankRequest {
        query: "synthetic query".into(),
        documents: vec!["first".into(), "second".into()],
        top_k: Some(1),
        sensitivity: Sensitivity::Private,
        role_binding: None,
        source: None,
        metadata: Value::Null,
    }
}
fn good_body(adapter: ModelAdapter) -> String {
    match adapter {
        ModelAdapter::CohereRerank => r#"{"results":[{"index":1,"relevance_score":0.9}]}"#,
        ModelAdapter::OllamaEmbedding => r#"{"embedding":[1,2]}"#,
        _ => r#"{"data":[{"index":0,"embedding":[1,2]}],"usage":{"prompt_tokens":7,"total_tokens":7}}"#,
    }.into()
}
// Return the exact request; test sockets have a deadline and accept one dispatch only.
fn fixture(
    status: u16,
    body: String,
    chunked: bool,
) -> (String, std::thread::JoinHandle<(String, Value)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/v1", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        let (headers, body_start, length) = loop {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(offset) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                let headers = String::from_utf8(bytes[..offset].to_vec()).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if bytes.len() >= offset + 4 + length {
                    break (headers, offset + 4, length);
                }
            }
        };
        let request = serde_json::from_slice(&bytes[body_start..body_start + length]).unwrap();
        let response = if chunked {
            format!(
                "HTTP/1.1 {status} Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                body.len()
            )
        } else {
            format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let _ = stream.write_all(response.as_bytes());
        (headers, request)
    });
    (url, handle)
}
async fn call(
    adapter: ModelAdapter,
    registry: &ModelRegistry,
    key: &str,
) -> Result<Value, ModelError> {
    let binding = registry
        .binding(
            &TenantId("tenant".into()),
            &ProviderPrincipalId("provider".into()),
        )
        .unwrap();
    if adapter == ModelAdapter::CohereRerank {
        let response = CohereRerankProvider::from_binding(&binding, key)
            .unwrap()
            .rerank(rerank_request())
            .await?;
        serde_json::to_value(response)
            .map_err(|_| ModelError::Provider(DiagnosticCode::InvalidResponse))
    } else {
        let response = CompatibleEmbeddingProvider::from_binding(&binding, key)
            .unwrap()
            .embed(embed_request())
            .await?;
        serde_json::to_value(response)
            .map_err(|_| ModelError::Provider(DiagnosticCode::InvalidResponse))
    }
}
#[tokio::test]
async fn retrieval_protocols_preserve_request_shape_and_keyless_headers() {
    for adapter in ADAPTERS {
        for key in ["", KEY] {
            let (url, server) = fixture(200, good_body(adapter), false);
            let registry = registry(adapter, &url, 4096);
            let response = call(adapter, &registry, key).await.unwrap();
            let (headers, body) = server.join().unwrap();
            if key.is_empty() {
                assert!(!headers.to_lowercase().contains("authorization:"));
            } else {
                assert!(headers.contains(&format!("Bearer {KEY}")));
                assert!(response["raw_provider_response"].is_null());
            }
            let expected = match adapter {
                ModelAdapter::CohereRerank => {
                    json!({"model":"Qwen3-Embedding-8B","query":"synthetic query","documents":["first","second"],"top_n":1})
                }
                ModelAdapter::OllamaEmbedding => {
                    json!({"model":"Qwen3-Embedding-8B","prompt":"synthetic input"})
                }
                _ => {
                    json!({"model":"Qwen3-Embedding-8B","input":["synthetic input"],"dimensions":2})
                }
            };
            assert_eq!(body, expected);
            let path = match adapter {
                ModelAdapter::CohereRerank => "rerank",
                ModelAdapter::OllamaEmbedding => "api/embeddings",
                _ => "embeddings",
            };
            assert!(headers.starts_with(&format!("POST /v1/{path} ")));
            if adapter == ModelAdapter::CohereRerank {
                assert_eq!(response["hits"][0]["index"], 1);
            } else {
                assert_eq!(response["dimensions"], 2);
                assert_eq!(response["vectors"], json!([[1., 2.]]));
            }
        }
    }
}
#[tokio::test]
async fn retrieval_refuses_oversized_length_and_chunked_responses() {
    for adapter in ADAPTERS {
        for chunked in [false, true] {
            let (url, server) = fixture(200, "x".repeat(65), chunked);
            let result = call(adapter, &registry(adapter, &url, 64), KEY).await;
            server.join().unwrap();
            assert!(matches!(
                result,
                Err(ModelError::Provider(
                    DiagnosticCode::ProviderResponseLimitExceeded
                ))
            ));
        }
    }
}
#[tokio::test]
async fn retrieval_malformed_vectors_and_hits_are_refused_without_filtering() {
    for (adapter, bodies) in [
        (
            ModelAdapter::OpenAiEmbedding,
            vec![
                "{}",
                r#"{"data":[]}"#,
                r#"{"data":[{"index":1,"embedding":[1,2]}]}"#,
                r#"{"data":[{"index":0,"embedding":[1]}]}"#,
                r#"{"data":[{"index":0,"embedding":[1e40,2]}]}"#,
            ],
        ),
        (
            ModelAdapter::OllamaEmbedding,
            vec![
                "{}",
                r#"{"embedding":[]}"#,
                r#"{"embedding":[1]}"#,
                r#"{"embedding":[1e40,2]}"#,
            ],
        ),
        (
            ModelAdapter::CohereRerank,
            vec![
                "{}",
                r#"{"results":[]}"#,
                r#"{"results":[{"index":2,"relevance_score":0.5}]}"#,
                r#"{"results":[{"index":0}]}"#,
                r#"{"results":[{"index":0,"relevance_score":1e40}]}"#,
            ],
        ),
    ] {
        for body in bodies {
            let (url, server) = fixture(200, body.into(), false);
            let result = call(adapter, &registry(adapter, &url, 4096), KEY).await;
            server.join().unwrap();
            assert!(
                matches!(result, Err(ModelError::Provider(_))),
                "{adapter:?}: {result:?}"
            );
        }
    }
}
#[tokio::test]
async fn retrieval_errors_and_success_echoes_are_redacted() {
    for adapter in ADAPTERS {
        for (status, body) in [
            (401, KEY.into()),
            (
                200,
                format!("{{\"ignored\":\"{KEY}\",{}", &good_body(adapter)[1..]),
            ),
            (200, KEY.into()),
        ] {
            let (url, server) = fixture(status, body, false);
            let error = call(adapter, &registry(adapter, &url, 4096), KEY)
                .await
                .unwrap_err();
            server.join().unwrap();
            assert!(!format!("{error:?} {error}").contains(KEY));
            if status == 401 {
                assert!(matches!(error, ModelError::Auth(_)));
            } else {
                assert!(matches!(error, ModelError::Provider(_)));
            }
        }
    }
}
#[tokio::test]
async fn openai_embeddings_order_batch_indices_and_honor_reduced_dimensions_and_task() {
    let (url, server) = fixture(
        200,
        r#"{"data":[{"index":1,"embedding":[2]},{"index":0,"embedding":[1]}]}"#.into(),
        false,
    );
    let registry = registry(ModelAdapter::OpenAiEmbedding, &url, 4096);
    let binding = registry
        .binding(
            &TenantId("tenant".into()),
            &ProviderPrincipalId("provider".into()),
        )
        .unwrap();
    let mut request = embed_request();
    request.inputs.push("second".into());
    request.dimensions = Some(1);
    request.task = Some("query".into());
    let response = CompatibleEmbeddingProvider::from_binding(&binding, KEY)
        .unwrap()
        .embed(request)
        .await
        .unwrap();
    assert_eq!(response.vectors, vec![vec![1.], vec![2.]]);
    assert_eq!(response.dimensions, 1);
    let (_, body) = server.join().unwrap();
    assert_eq!(body["dimensions"], 1);
    assert_eq!(body["input_type"], "query");
}
#[test]
fn retrieval_request_limits_and_unsupported_options_refuse_before_transport() {
    for adapter in [ModelAdapter::OpenAiEmbedding, ModelAdapter::OllamaEmbedding] {
        let settings = TransportSettings {
            dimensions: Some(1024),
            embedding_full_dimensions: Some(1024),
            ..Default::default()
        };
        let mut request = embed_request();
        let (body, dimensions) = wire::compatible_embedding_body(
            adapter,
            "Qwen3-Embedding-8B",
            &settings,
            &request,
            4096,
        )
        .unwrap();
        assert_eq!(dimensions, 1024);
        assert!(
            wire::compatible_embedding_body(
                adapter,
                "Qwen3-Embedding-8B",
                &settings,
                &request,
                body.len() - 1
            )
            .is_err()
        );
        for dimensions in [0, 1025] {
            request.dimensions = Some(dimensions);
            assert!(
                wire::compatible_embedding_body(adapter, "model", &settings, &request, 4096)
                    .is_err()
            );
        }
        if adapter == ModelAdapter::OllamaEmbedding {
            request.dimensions = None;
            request.task = Some("query".into());
            assert!(
                wire::compatible_embedding_body(adapter, "model", &settings, &request, 4096)
                    .is_err()
            );
            request.task = None;
            request.inputs.push("second".into());
            assert!(
                wire::compatible_embedding_body(adapter, "model", &settings, &request, 4096)
                    .is_err()
            );
        }
    }
    let mut settings = TransportSettings {
        rerank_candidates: Some(2),
        rerank_input_bytes: Some(64),
        ..Default::default()
    };
    let mut request = rerank_request();
    let (body, _) = wire::cohere_rerank_body("model", &settings, &request, 4096).unwrap();
    assert!(wire::cohere_rerank_body("model", &settings, &request, body.len() - 1).is_err());
    settings.rerank_candidates = Some(1);
    assert!(wire::cohere_rerank_body("model", &settings, &request, 4096).is_err());
    settings.rerank_candidates = Some(2);
    settings.rerank_input_bytes = Some(1);
    assert!(wire::cohere_rerank_body("model", &settings, &request, 4096).is_err());
    settings.rerank_input_bytes = Some(64);
    request.top_k = Some(0);
    assert!(wire::cohere_rerank_body("model", &settings, &request, 4096).is_err());
}

#[tokio::test]
async fn retrieval_duplicate_indices_refuse_and_rerank_scores_sort() {
    for (adapter, body, valid) in [
        (
            ModelAdapter::OpenAiEmbedding,
            r#"{"data":[{"index":0,"embedding":[1,2]},{"index":0,"embedding":[3,4]}]}"#,
            false,
        ),
        (
            ModelAdapter::CohereRerank,
            r#"{"results":[{"index":0,"relevance_score":0.1},{"index":0,"relevance_score":0.9}]}"#,
            false,
        ),
        (
            ModelAdapter::CohereRerank,
            r#"{"results":[{"index":0,"relevance_score":0.1},{"index":1,"relevance_score":0.9}]}"#,
            true,
        ),
    ] {
        let (url, server) = fixture(200, body.into(), false);
        let registry = registry(adapter, &url, 4096);
        let binding = registry
            .binding(
                &TenantId("tenant".into()),
                &ProviderPrincipalId("provider".into()),
            )
            .unwrap();
        if adapter == ModelAdapter::OpenAiEmbedding {
            let mut request = embed_request();
            request.inputs.push("second".into());
            assert!(
                CompatibleEmbeddingProvider::from_binding(&binding, KEY)
                    .unwrap()
                    .embed(request)
                    .await
                    .is_err()
            );
        } else {
            let mut request = rerank_request();
            request.top_k = Some(2);
            let result = CohereRerankProvider::from_binding(&binding, KEY)
                .unwrap()
                .rerank(request)
                .await;
            if valid {
                assert_eq!(result.unwrap().hits[0].index, 1);
            } else {
                assert!(result.is_err());
            }
        }
        server.join().unwrap();
    }
}

#[test]
fn retrieval_registry_refuses_missing_zero_and_cross_adapter_settings() {
    for adapter in ADAPTERS {
        let valid = registry(adapter, "http://localhost/v1", 4096)
            .config()
            .clone();
        let field = if adapter == ModelAdapter::CohereRerank {
            "rerank_candidates"
        } else {
            "embedding_full_dimensions"
        };
        for value in [Value::Null, json!(0)] {
            let mut config = serde_json::to_value(&valid).unwrap();
            config["bindings"][0]["settings"][field] = value;
            assert!(ModelRegistry::from_json(&serde_json::to_vec(&config).unwrap()).is_err());
        }
        let mut config = serde_json::to_value(&valid).unwrap();
        config["bindings"][0]["settings"]["thinking"] = json!("enabled");
        assert!(ModelRegistry::from_json(&serde_json::to_vec(&config).unwrap()).is_err());
    }
}
