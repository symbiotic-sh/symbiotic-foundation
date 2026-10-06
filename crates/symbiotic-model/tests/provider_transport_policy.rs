use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use symbiotic_model::{
    ChatMessage, ChatProvider, ChatRequest, ClassifierProvider, ClassifierQuestion,
    ClassifyRequest, JevClassifierProvider, ModelError, OpenAiCompatibleChatProvider,
};

fn chat_request() -> ChatRequest {
    ChatRequest {
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "synthetic prompt".into(),
        }],
        max_output_tokens: Some(16),
        temperature: None,
        response_format: None,
        role_binding: None,
        source: None,
        metadata: serde_json::Value::Null,
    }
}

fn classify_request() -> ClassifyRequest {
    ClassifyRequest::new(
        serde_json::Map::new(),
        vec![ClassifierQuestion::noul(
            "goal",
            "Is it a goal?",
            None,
            None,
        )],
    )
}

// A bounded loopback fixture also accepts arbitrary bytes for malformed UTF-8 tests.
fn serve(body: Vec<u8>, stop: Arc<AtomicBool>) -> (String, std::thread::JoinHandle<usize>) {
    serve_response(200, None, body, stop)
}

fn serve_response(
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
    stop: Arc<AtomicBool>,
) -> (String, std::thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = 0;
        while !stop.load(Ordering::Acquire) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            // Accepted sockets inherit the nonblocking listener mode on macOS.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            let (offset, length) = loop {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..offset]).unwrap();
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
            requests += 1;
            write!(
                stream,
                "HTTP/1.1 {status} Fixture\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                location.as_ref().map(|url| format!("Location: {url}\r\n")).unwrap_or_default(),
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
        requests
    });
    (url, handle)
}

#[test]
fn built_in_clients_ignore_ambient_proxies() {
    const CHILD: &str = "SYMBIOTIC_PROXY_TEST_ADAPTER";
    if let Ok(adapter) = std::env::var(CHILD) {
        // Environment changes belong to this subprocess, never the concurrent test runner.
        let url = std::env::var("SYMBIOTIC_PROXY_TEST_ENDPOINT").unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                if adapter == "raw_classifier" {
                    let response =
                        JevClassifierProvider::new("fixture", "fixture", url, "synthetic-key")
                            .with_request_limit(65536)
                            .with_response_limit(65536)
                            .classify(classify_request())
                            .await
                            .unwrap();
                    assert_eq!(
                        response.trace.metadata["provider"]["response_id"],
                        "response-direct"
                    );
                } else {
                    let mut provider = OpenAiCompatibleChatProvider::new(
                        "fixture",
                        "fixture",
                        url,
                        "synthetic-key",
                    )
                    .with_request_limit(65536)
                    .with_response_limit(65536);
                    if adapter == "configured" {
                        provider = provider.with_timeout(3).unwrap();
                    }
                    assert_eq!(provider.chat(chat_request()).await.unwrap().text, "direct");
                }
            });
        return;
    }

    let mut failures = Vec::new();
    for adapter in ["configured", "raw_chat", "raw_classifier"] {
        let stop = Arc::new(AtomicBool::new(false));
        let body = |id| {
            // The response id must not repeat the answer text, or identity screening drops it.
            serde_json::to_vec(&serde_json::json!({
                "id": format!("response-{id}"), "model": "fixture",
                "choices": [{"message": {"content": id}}],
                "answers": {"goal": {"type": "noul", "noul": 0.25}}
            }))
            .unwrap()
        };
        let (endpoint, destination) = serve(body("direct"), stop.clone());
        let (proxy, proxy_server) = serve(body("proxy"), stop.clone());
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "built_in_clients_ignore_ambient_proxies",
                "--nocapture",
                "--test-threads=4",
            ])
            .env(CHILD, adapter)
            .env("SYMBIOTIC_PROXY_TEST_ENDPOINT", endpoint)
            .env("HTTP_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .env("https_proxy", &proxy)
            .env("ALL_PROXY", &proxy)
            .env("all_proxy", &proxy)
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .output()
            .unwrap();
        stop.store(true, Ordering::Release);
        let direct_requests = destination.join().unwrap();
        let proxied_requests = proxy_server.join().unwrap();
        if proxied_requests != 0 || direct_requests != 1 || !output.status.success() {
            failures.push(format!(
                "{adapter}: {proxied_requests} proxied, {direct_requests} direct requests; {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn jev_refuses_invalid_utf8_in_a_success_body() {
    for secret in ["", "synthetic-key"] {
        let mut body = br#"{"id":"invalid-#"#.to_vec();
        body.push(0xff);
        body.extend_from_slice(
            br#"","model":"fixture","answers":{"goal":{"type":"noul","noul":0.25}}}"#,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let (endpoint, server) = serve(body, stop.clone());
        let result = JevClassifierProvider::new("fixture", "fixture", endpoint, secret)
            .with_timeout(3)
            .unwrap()
            .with_request_limit(65536)
            .with_response_limit(65536)
            .classify(classify_request())
            .await;
        stop.store(true, Ordering::Release);
        assert_eq!(server.join().unwrap(), 1);
        let error = result.expect_err("invalid UTF-8 must not become a successful classification");
        let expected = symbiotic_core::DiagnosticCode::ProviderResponseIsNotValidUtf8;
        assert!(matches!(error, ModelError::Provider(message) if message == expected));
    }
}

#[tokio::test]
async fn built_in_clients_refuse_redirects_without_contacting_the_target() {
    for secret in ["", "synthetic-key"] {
        for configured in [false, true] {
            for classifier in [false, true] {
                for status in [307, 308] {
                    let target = TcpListener::bind("127.0.0.1:0").unwrap();
                    target.set_nonblocking(true).unwrap();
                    let stop = Arc::new(AtomicBool::new(false));
                    let (endpoint, server) = serve_response(
                        status,
                        Some(format!("http://{}/other", target.local_addr().unwrap())),
                        Vec::new(),
                        stop.clone(),
                    );
                    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        if classifier {
                            let mut provider =
                                JevClassifierProvider::new("fixture", "fixture", endpoint, secret)
                                    .with_request_limit(65536)
                                    .with_response_limit(65536);
                            if configured {
                                provider = provider.with_timeout(3).unwrap();
                            }
                            provider.classify(classify_request()).await.map(|_| ())
                        } else {
                            let mut provider = OpenAiCompatibleChatProvider::new(
                                "fixture", "fixture", endpoint, secret,
                            )
                            .with_request_limit(65536)
                            .with_response_limit(65536);
                            if configured {
                                provider = provider.with_timeout(3).unwrap();
                            }
                            provider.chat(chat_request()).await.map(|_| ())
                        }
                    })
                    .await;
                    stop.store(true, Ordering::Release);
                    assert_eq!(server.join().unwrap(), 1);
                    let result = result.expect("provider redirect refusal must finish promptly");
                    let expected = symbiotic_core::DiagnosticCode::ProviderRedirectRefused;
                    assert!(
                        matches!(result, Err(ModelError::Provider(message)) if message == expected)
                    );
                    assert_eq!(
                        target.accept().unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                }
            }
        }
    }
}

#[test]
fn regression_raw_endpoints_refuse_credentials_before_descriptor_publication() {
    use symbiotic_model::ModelProvider;
    for endpoint in [
        "https://synthetic-user:synthetic-password@example.com/v1",
        "https://example.com/v1?api_key=synthetic-query-key",
        "https://example.com/v1#synthetic-fragment",
        "file:///synthetic-path",
    ] {
        let chat = OpenAiCompatibleChatProvider::new("fixture", "fixture", endpoint, "")
            .with_request_limit(65536)
            .with_response_limit(65536);
        let classifier = JevClassifierProvider::new("fixture", "fixture", endpoint, "")
            .with_request_limit(65536)
            .with_response_limit(65536);
        for provider in [
            &chat as &dyn ModelProvider,
            &classifier as &dyn ModelProvider,
        ] {
            assert!(provider.validate_configuration().is_err(), "{endpoint}");
            assert!(!format!("{:?}", provider.descriptor()).contains("synthetic-"));
            assert!(
                !serde_json::to_string(provider.descriptor())
                    .unwrap()
                    .contains("synthetic-")
            );
        }
    }
}
