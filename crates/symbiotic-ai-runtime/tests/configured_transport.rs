//! Configured HTTP boundaries, with synthetic credentials and loopback servers.
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
};
use symbiotic_ai_runtime::{
    ChatProvider, ChatRequest, ConfiguredProvider, InMemoryReceiptSink, ModelError,
    ModelQueueConfig, Runtime, RuntimeConfig, model,
};
use symbiotic_core::{ProviderPrincipalId, TenantId};
use symbiotic_trace::InMemoryTraceSink;

const KEY: &str = "synthetic-credential-echo-9271";

struct Credentials;
#[async_trait]
impl model::CredentialResolver for Credentials {
    async fn resolve_auth(
        &self,
        _: &model::ProviderAuthMode,
    ) -> Result<model::ResolvedAuth, ModelError> {
        Ok(model::ResolvedAuth::ApiKey(KEY.into()))
    }
}

fn fixture(
    status: u16,
    body: String,
    location: Option<String>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
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
                if bytes.len() >= offset + 4 + length {
                    break;
                }
            }
        }
        let location = location.map_or(String::new(), |url| format!("Location: {url}\r\n"));
        write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    (url, server)
}

async fn configured(
    endpoint: &str,
    state: &std::path::Path,
    classifier: bool,
) -> (
    ConfiguredProvider,
    Arc<InMemoryReceiptSink>,
    Arc<InMemoryTraceSink>,
) {
    let mut config: Value =
        serde_json::from_slice(include_bytes!("../../../examples/model-registry.json")).unwrap();
    config["accounts"] = json!([{"id": "policy", "policy": ModelQueueConfig {
        logical_retry_attempts: 1, retry_attempts: 1, request_timeout_seconds: Some(2), ..ModelQueueConfig::default()
    }}]);
    if classifier {
        config["models"][0]["adapter"] = json!("jev_classifier");
        config["models"][0]["operations"] = json!(["classify"]);
        config["models"][0]["identity"]["operation"] = json!("classify");
    }
    config["bindings"] = json!([{
        "identity": {"tenant": "tenant", "provider": "provider", "revision": "1", "account": "account"},
        "model": "example-chat", "endpoint": endpoint, "secret_ref": "synthetic",
        "account_policy": "policy", "account_sharing_key": null,
        "limits": {"max_request_bytes": 65536, "max_response_bytes": 65536, "max_output_tokens": if classifier { None } else { Some(128) }},
        "settings": {"thinking": null, "reasoning_effort": null, "dimensions": null, "served_model": null}
    }]);
    let receipts = Arc::new(InMemoryReceiptSink::default());
    let traces = Arc::new(InMemoryTraceSink::default());
    let runtime = Runtime::open(RuntimeConfig {
        state_dir: Some(state.to_path_buf()),
        registry: Some(Arc::new(
            model::ModelRegistry::from_json(&serde_json::to_vec(&config).unwrap()).unwrap(),
        )),
        receipt_sink: Some(receipts.clone()),
        trace_sink: Some(traces.clone()),
        ..RuntimeConfig::default()
    })
    .unwrap();
    let provider = runtime
        .configured_provider(
            &TenantId("tenant".into()),
            &ProviderPrincipalId("provider".into()),
            &Credentials,
        )
        .await
        .unwrap();
    (provider, receipts, traces)
}

async fn call(provider: &ConfiguredProvider) -> Result<(), ModelError> {
    match provider {
        ConfiguredProvider::Chat(provider) => provider
            .chat(ChatRequest {
                messages: vec![model::ChatMessage {
                    role: "user".into(),
                    content: "synthetic prompt".into(),
                }],
                max_output_tokens: Some(32),
                temperature: None,
                response_format: None,
                sensitivity: symbiotic_core::Sensitivity::Shareable,
                role_binding: None,
                source: None,
                metadata: Value::Null,
            })
            .await
            .map(|_| ()),
        ConfiguredProvider::Classifier(provider) => {
            use model::ClassifierProvider;
            provider
                .classify(model::ClassifyRequest::new(
                    serde_json::Map::new(),
                    vec![model::ClassifierQuestion::noul(
                        "answer", "yes?", None, None,
                    )],
                ))
                .await
                .map(|_| ())
        }
        _ => panic!("unexpected adapter"),
    }
}

fn assert_no_secret_files(dir: &std::path::Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_secret_files(&path);
        } else {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(KEY.len()).any(|part| part == KEY.as_bytes()),
                "credential in {path:?}"
            );
        }
    }
}

#[tokio::test]
async fn configured_401_echo_is_sanitized_before_runtime_bookkeeping() {
    for classifier in [false, true] {
        let (url, server) = fixture(401, format!("unauthorized key={KEY}"), None);
        let state = tempfile::tempdir().unwrap();
        let (provider, receipts, traces) =
            configured(&url, &state.path().join("state"), classifier).await;
        let err = call(&provider).await.unwrap_err();
        server.join().unwrap();
        assert!(matches!(err, ModelError::Auth(_)), "{err:?}");
        assert!(!format!("{err:?}").contains(KEY));
        assert!(
            !serde_json::to_string(&receipts.receipts())
                .unwrap()
                .contains(KEY)
        );
        assert!(
            !serde_json::to_string(&traces.records())
                .unwrap()
                .contains(KEY)
        );
        assert_no_secret_files(state.path());
    }
}

#[tokio::test]
async fn configured_success_body_echo_is_refused_before_runtime_bookkeeping() {
    let escaped = KEY
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect::<String>();
    for (classifier, body) in [
        (
            false,
            json!({"choices": [{"message": {"content": KEY}}]}).to_string(),
        ),
        (
            false,
            json!({"id": KEY, "choices": [{"message": {"content": "OK"}}]}).to_string(),
        ),
        (
            false,
            format!(
                "{{\"ignored\":\"{escaped}\",\"choices\":[{{\"message\":{{\"content\":\"OK\"}}}}]}}"
            ),
        ),
        (
            true,
            json!({"model": "example-model", "answers": {"answer": 0.5}, "ignored": KEY})
                .to_string(),
        ),
    ] {
        let (url, server) = fixture(200, body, None);
        let state = tempfile::tempdir().unwrap();
        let (provider, receipts, traces) =
            configured(&url, &state.path().join("state"), classifier).await;
        let result = call(&provider).await;
        server.join().unwrap();
        assert!(matches!(result, Err(ModelError::Provider(_))), "{result:?}");
        assert!(!format!("{result:?}").contains(KEY));
        assert!(
            !serde_json::to_string(&receipts.receipts())
                .unwrap()
                .contains(KEY)
        );
        assert!(
            !serde_json::to_string(&traces.records())
                .unwrap()
                .contains(KEY)
        );
        assert_no_secret_files(state.path());
    }
}

#[tokio::test]
async fn configured_redirects_are_refused_without_contacting_the_target() {
    for classifier in [false, true] {
        for status in [307, 308] {
            let target = TcpListener::bind("127.0.0.1:0").unwrap();
            target.set_nonblocking(true).unwrap();
            let (url, server) = fixture(
                status,
                String::new(),
                Some(format!("http://{}/other", target.local_addr().unwrap())),
            );
            let state = tempfile::tempdir().unwrap();
            let (provider, _, _) = configured(&url, &state.path().join("state"), classifier).await;
            let err = call(&provider).await.unwrap_err();
            server.join().unwrap();
            assert!(
                matches!(err, ModelError::Provider(ref message) if message.contains("redirect")),
                "{err:?}"
            );
            assert_eq!(
                target.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
}
