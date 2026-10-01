#![cfg(unix)]
use base64::{Engine, engine::general_purpose};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use symbiotic_credential_process::{
    CredentialProcess, ProcessConfig, RouteConfig, RouteProvider, secrets::SecretSource, server,
};
use symbiotic_egress::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const SECRET: &str = "synthetic-WP14-credential-\"/+?=é-canary";
const KEY: &[u8] = b"synthetic-admission-key-at-least-32-bytes";

struct Fixture {
    dir: tempfile::TempDir,
    config: ProcessConfig,
    calls: Arc<AtomicUsize>,
}
impl Fixture {
    async fn new(status: u16, output: String, delay: Duration) -> Self {
        Self::with_cost(status, output, delay, r#""0.00001234567890123456789""#).await
    }
    async fn with_cost(
        status: u16,
        output: String,
        delay: Duration,
        cost_json: &'static str,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, value) in [("provider", SECRET.as_bytes()), ("admission", KEY)] {
            let path = dir.path().join(name);
            std::fs::write(&path, value).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let output = output.clone();
                let count = count.clone();
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    loop {
                        let mut chunk = [0u8; 4096];
                        let read = stream.read(&mut chunk).await.unwrap();
                        if read == 0 {
                            return;
                        }
                        data.extend_from_slice(&chunk[..read]);
                        if let Some(header_end) =
                            data.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let headers = String::from_utf8_lossy(&data[..header_end]);
                            let len = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .and_then(|len| len.parse::<usize>().ok())
                                })
                                .unwrap();
                            if data.len() >= header_end + 4 + len {
                                // Credential injection occurs solely in the HTTP header.
                                assert!(headers.contains(&format!("Bearer {SECRET}")));
                                assert!(
                                    !String::from_utf8_lossy(&data[header_end + 4..])
                                        .contains("synthetic-WP14-credential")
                                );
                                break;
                            }
                        }
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    let body = if status == 200 {
                        // Insert the raw JSON literal so the test's own serde_json
                        // feature set cannot round a numeric cost before transmission.
                        format!(
                            r#"{{"choices":[{{"message":{{"content":{}}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":7,"completion_tokens":3,"cost":{cost_json}}}}}"#,
                            serde_json::to_string(&output).unwrap()
                        )
                    } else {
                        output
                    };
                    let response = format!(
                        "HTTP/1.1 {status} test\r\nContent-Type: application/json\r\nLocation: /not-approved\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let config = ProcessConfig {
            version: PROTOCOL_VERSION,
            state_dir: dir.path().join("state"),
            socket_path: dir.path().join("egress.sock"),
            admission_key: SecretSource::OwnerOnlyFile {
                path: dir.path().join("admission"),
            },
            max_secret_bytes: 4096,
            max_frame_bytes: 262144,
            max_connections: 8,
            io_timeout_seconds: 2,
            routes: vec![RouteConfig {
                tenant: "tenant".into(),
                route: "chat".into(),
                secret_ref: "provider-key".into(),
                secret: SecretSource::OwnerOnlyFile {
                    path: dir.path().join("provider"),
                },
                destination: format!("http://{address}/v1"),
                model: "test-model".into(),
                provider: RouteProvider::OpenAiChat {
                    operator: "test".into(),
                },
                allow_loopback_http: true,
                max_input_bytes: 32768,
                max_response_bytes: 32768,
                max_field_bytes: 1024,
                max_output_tokens: 100,
                max_in_flight: 4,
                requests_per_minute: None,
                input_units_per_minute: None,
                timeout_seconds: 1,
            }],
        };
        Self { dir, config, calls }
    }
    fn process(&self) -> CredentialProcess {
        CredentialProcess::open(self.config.clone()).unwrap()
    }
    fn attempt(
        &self,
        invocation: &str,
        ordinal: u32,
        sequence: u64,
    ) -> (SignedAttempt, ProviderPayload) {
        let payload = ProviderPayload::Chat(ChatRequest {
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "private test input".into(),
            }],
            max_output_tokens: Some(10),
            temperature: None,
            response_format: None,
            sensitivity: Sensitivity::Private,
            role_binding: None,
            source: None,
            metadata: serde_json::Value::Null,
        });
        let attempt = DurableAttempt {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            invocation_id: invocation.into(),
            attempt_ordinal: ordinal,
            record_sequence: sequence,
            recorded_at: 100,
            expires_at: 101,
            recovery_expires_at: 4_000_000_000,
            caller_binding: "caller".into(),
            route: "chat".into(),
            destination: self.config.routes[0].destination.clone(),
            model: "test-model".into(),
            method: "POST".into(),
            secret_ref: "provider-key".into(),
            manifest_ref: "manifest".into(),
            input_manifest_digest: "a".repeat(64),
            input_digest: payload.digest().unwrap(),
            markings: vec![],
            max_attempts: 3,
            reserved_budget: ReservedBudget {
                unit: "provider_requests".into(),
                amount: 1,
                invocation_limit: 3,
            },
        };
        (
            AdmissionKey::new(KEY.to_vec())
                .unwrap()
                .sign_attempt(attempt)
                .unwrap(),
            payload,
        )
    }
}
async fn exchange(process: &CredentialProcess, operation: Operation) -> Result<Reply, EgressError> {
    process
        .handle(Request {
            version: PROTOCOL_VERSION,
            operation,
        })
        .await
        .result
}
async fn permit(process: &CredentialProcess, admission: &SignedAttempt) -> DispatchPermit {
    match exchange(process, Operation::IssuePermit(admission.clone()))
        .await
        .unwrap()
    {
        Reply::Permit(grant) => grant.permit,
        _ => panic!("wrong reply"),
    }
}
fn inject(admission: SignedAttempt, payload: ProviderPayload, permit: DispatchPermit) -> Operation {
    Operation::InjectProviderCredential(Box::new(InjectProviderCredential {
        operation_version: PROTOCOL_VERSION,
        admission,
        permit,
        payload,
    }))
}
fn dispatched(reply: Reply) -> DispatchResult {
    match reply {
        Reply::Dispatched(result) => result,
        _ => panic!("wrong reply"),
    }
}
async fn revoke(process: &CredentialProcess, sequence: u64) {
    let signed = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_revocation(RouteRevocation {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            route: "chat".into(),
            record_sequence: sequence,
        })
        .unwrap();
    assert!(matches!(
        exchange(process, Operation::RevokeRoute(signed))
            .await
            .unwrap(),
        Reply::Revoked
    ));
}

#[tokio::test]
async fn permit_replay_refused_concurrently_and_after_restart() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("replay", 1, 10);
    let permit = permit(&process, &admission).await;
    let request = inject(admission.clone(), payload, permit);
    let (first, second) = tokio::join!(
        exchange(&process, request.clone()),
        exchange(&process, request.clone())
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(
        matches!(first, Err(EgressError::PermitRefused))
            || matches!(second, Err(EgressError::PermitRefused))
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    drop(process);
    let process = fixture.process();
    assert!(matches!(
        exchange(&process, request).await,
        Err(EgressError::PermitRefused)
    ));
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(admission)).await,
        Ok(Reply::Permit(PermitGrant {
            status: AttemptStatus::Completed { .. },
            ..
        }))
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn revocation_orders_by_durable_record_not_barrier_completion_or_later_expiry() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    revoke(&process, 11).await;
    let (early, payload) = fixture.attempt("early", 1, 10);
    let granted = permit(&process, &early).await;
    let result = dispatched(
        exchange(&process, inject(early, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    let (late, _) = fixture.attempt("late", 1, 12);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(late)).await,
        Err(EgressError::RouteRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    drop(process);
    let process = fixture.process();
    let (late, _) = fixture.attempt("late-restart", 1, 12);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(late)).await,
        Err(EgressError::RouteRefused)
    ));
}

#[tokio::test]
async fn revocation_between_issue_and_inject_refuses_unconsumed_later_records() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let mut process = fixture.process();
    let (early, early_payload) = fixture.attempt("early", 1, 10);
    let early_permit = permit(&process, &early).await;
    let mut refused = Vec::new();
    for sequence in [12, 11] {
        let (admission, payload) = fixture.attempt(&format!("late-{sequence}"), 1, sequence);
        let granted = permit(&process, &admission).await;
        refused.push((admission, payload, granted));
    }
    revoke(&process, 11).await;
    for restart in [false, true] {
        if restart {
            drop(process);
            process = fixture.process();
        }
        for (admission, payload, granted) in &refused {
            assert!(matches!(
                exchange(
                    &process,
                    inject(admission.clone(), payload.clone(), granted.clone())
                )
                .await,
                Err(EgressError::RouteRefused)
            ));
            assert!(matches!(
                status(&process, admission).await,
                AttemptStatus::Permitted
            ));
            assert!(matches!(
                exchange(&process, Operation::Receipt(admission.clone())).await,
                Ok(Reply::Receipt(None))
            ));
            let reattached = permit(&process, admission).await;
            assert_eq!(reattached.token, granted.token);
            assert_eq!(reattached.attempt_digest, granted.attempt_digest);
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    }
    let result = dispatched(
        exchange(&process, inject(early, early_payload, early_permit))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn wrong_input_or_attempt_cannot_spend_a_permit() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("binding", 1, 10);
    let granted = permit(&process, &admission).await;
    let mut changed = payload.clone();
    if let ProviderPayload::Chat(request) = &mut changed {
        request.messages[0].content = "changed".into();
    }
    assert!(matches!(
        exchange(
            &process,
            inject(admission.clone(), changed, granted.clone())
        )
        .await,
        Err(EgressError::InvalidRequest)
    ));
    let (other, other_payload) = fixture.attempt("other", 1, 10);
    assert!(matches!(
        exchange(&process, inject(other, other_payload, granted.clone())).await,
        Err(EgressError::PermitRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        dispatched(
            exchange(&process, inject(admission, payload, granted))
                .await
                .unwrap()
        )
        .receipt
        .status,
        DispatchStatus::Succeeded
    );
}

#[tokio::test]
async fn unsigned_or_expired_at_record_authority_never_gets_a_permit() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (mut admission, _) = fixture.attempt("tamper", 1, 10);
    admission.attempt.route = "forged".into();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(admission)).await,
        Err(EgressError::Unauthorized)
    ));
    let (mut admission, _) = fixture.attempt("expired", 1, 10);
    admission.attempt.recorded_at = admission.attempt.expires_at;
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(admission)).await,
        Err(EgressError::InvalidRequest)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retry_is_a_new_attempt_same_invocation_without_response_cache() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let key_path = fixture.dir.path().join("provider");
    std::fs::remove_file(&key_path).unwrap();
    let (first, payload) = fixture.attempt("retry", 1, 1);
    let granted = permit(&process, &first).await;
    let failed = dispatched(
        exchange(&process, inject(first, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(failed.receipt.status, DispatchStatus::CredentialUnavailable);
    assert_eq!(failed.error, Some(EgressError::CredentialUnavailable));
    std::fs::write(&key_path, SECRET).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // The retry and a different invocation have byte-identical provider input.
    // Both must dispatch; no result cache may answer the second invocation.
    for (invocation, ordinal, sequence) in [("retry", 2, 2), ("other-invocation", 1, 3)] {
        let (admission, payload) = fixture.attempt(invocation, ordinal, sequence);
        let granted = permit(&process, &admission).await;
        let result = dispatched(
            exchange(&process, inject(admission, payload, granted))
                .await
                .unwrap(),
        );
        assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
        assert_eq!(result.receipt.usage.input_tokens, Some(7));
        assert_eq!(result.receipt.usage.output_tokens, Some(3));
        assert!(result.receipt_persisted);
    }
    let (completed, _) = fixture.attempt("retry", 3, 4);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(completed)).await,
        Err(EgressError::InvocationComplete)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    assert!(!fixture.config.state_dir.join("responses").exists());
    for entry in std::fs::read_dir(&fixture.config.state_dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for canary in [SECRET.as_bytes(), b"private test input"] {
            assert!(!bytes.windows(canary.len()).any(|window| window == canary));
        }
    }
}

#[tokio::test]
async fn unknown_charge_stays_reserved_and_prevents_blind_retry_after_restart() {
    let fixture = Fixture::new(200, "late answer".into(), Duration::from_secs(2)).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("timeout", 1, 1);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission.clone(), payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::ProviderFailed);
    assert_eq!(result.error, Some(EgressError::Transport));
    assert_eq!(
        result.receipt.charge,
        ChargeReport::Unknown {
            reserved: admission.attempt.reserved_budget.clone()
        }
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    drop(process);
    let process = fixture.process();
    let receipt = exchange(&process, Operation::Receipt(admission))
        .await
        .unwrap();
    assert!(matches!(
        receipt,
        Reply::Receipt(Some(DispatchReceipt {
            charge: ChargeReport::Unknown { .. },
            ..
        }))
    ));
    let (retry, _) = fixture.attempt("timeout", 2, 2);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(retry)).await,
        Err(EgressError::ReconciliationRequired)
    ));
}

#[tokio::test]
async fn caller_cancellation_does_not_cancel_started_dispatch() {
    let fixture = Fixture::new(200, "answer".into(), Duration::from_millis(80)).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("cancel", 1, 1);
    let granted = permit(&process, &admission).await;
    let cloned = process.clone();
    let operation = inject(admission.clone(), payload, granted);
    let task = tokio::spawn(async move { exchange(&cloned, operation).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if matches!(
                exchange(&process, Operation::Receipt(admission.clone()))
                    .await
                    .unwrap(),
                Reply::Receipt(Some(DispatchReceipt {
                    status: DispatchStatus::Succeeded,
                    ..
                }))
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn credentials_and_declared_encodings_never_return_in_success_or_error() {
    let mut encodings = vec![
        SECRET.to_owned(),
        serde_json::to_string(SECRET)
            .unwrap()
            .trim_matches('"')
            .to_owned(),
    ];
    for upper in [false, true] {
        encodings.push(
            SECRET
                .bytes()
                .map(|b| {
                    if upper {
                        format!("%{b:02X}")
                    } else {
                        format!("%{b:02x}")
                    }
                })
                .collect(),
        );
    }
    for engine in [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ] {
        encodings.push(engine.encode(SECRET));
    }
    for status in [200, 400] {
        for encoded in &encodings {
            let fixture = Fixture::new(status, format!("echo {encoded}"), Duration::ZERO).await;
            let process = fixture.process();
            let (admission, payload) = fixture.attempt("isolation", 1, 1);
            let granted = permit(&process, &admission).await;
            let result = dispatched(
                exchange(&process, inject(admission, payload, granted))
                    .await
                    .unwrap(),
            );
            let serialized = serde_json::to_string(&result).unwrap();
            assert_eq!(result.receipt.status, DispatchStatus::ProviderFailed);
            assert_eq!(result.error, Some(EgressError::Transport));
            assert!(result.output.is_none());
            for encoding in &encodings {
                assert!(!serialized.contains(encoding));
            }
            assert!(!format!("{result:?}").contains("synthetic-WP14-credential"));
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn owner_only_socket_roundtrip_and_oversized_frame_refusal() {
    use symbiotic_egress::socket::UnixEgressClient;
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let listener = server::bind(&process).unwrap();
    assert_eq!(
        std::fs::metadata(&fixture.config.socket_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let task = tokio::spawn(server::serve(process, listener));
    let client = UnixEgressClient {
        path: fixture.config.socket_path.clone(),
        max_frame_bytes: fixture.config.max_frame_bytes,
        timeout: Duration::from_secs(3),
    };
    let (admission, payload) = fixture.attempt("socket", 1, 1);
    let response = client
        .exchange(Request {
            version: PROTOCOL_VERSION,
            operation: Operation::IssuePermit(admission.clone()),
        })
        .await
        .unwrap();
    let Reply::Permit(granted) = response.result.unwrap() else {
        panic!("wrong reply")
    };
    let response = client
        .exchange(Request {
            version: PROTOCOL_VERSION,
            operation: inject(admission, payload, granted.permit),
        })
        .await
        .unwrap();
    assert_eq!(
        dispatched(response.result.unwrap()).receipt.status,
        DispatchStatus::Succeeded
    );
    let mut stream = tokio::net::UnixStream::connect(&fixture.config.socket_path)
        .await
        .unwrap();
    stream
        .write_u32(fixture.config.max_frame_bytes + 1)
        .await
        .unwrap();
    let response: Response = socket::read_frame(&mut stream, fixture.config.max_frame_bytes)
        .await
        .unwrap();
    assert!(matches!(response.result, Err(EgressError::LimitExceeded)));
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn missing_secret_is_a_known_zero_charge_and_strict_money_budget_is_refused() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    std::fs::remove_file(fixture.dir.path().join("provider")).unwrap();
    let (admission, payload) = fixture.attempt("missing", 1, 1);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::CredentialUnavailable);
    assert_eq!(
        result.receipt.charge,
        ChargeReport::Measured {
            unit: "provider_requests".into(),
            amount: 0
        }
    );
    let (mut admission, _) = fixture.attempt("money", 1, 1);
    admission.attempt.reserved_budget.unit = "micro_usd".into();
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(admission)).await,
        Err(EgressError::BudgetRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn redirects_and_oversized_provider_responses_fail_without_a_second_call() {
    for (status, body) in [(302, "redirect".to_owned()), (200, "x".repeat(40000))] {
        let fixture = Fixture::new(status, body, Duration::ZERO).await;
        let process = fixture.process();
        let (admission, payload) = fixture.attempt("bounded", 1, 1);
        let granted = permit(&process, &admission).await;
        let result = dispatched(
            exchange(&process, inject(admission, payload, granted))
                .await
                .unwrap(),
        );
        assert_eq!(result.receipt.status, DispatchStatus::ProviderFailed);
        assert_eq!(result.error, Some(EgressError::Transport));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert!(result.output.is_none());
    }
}

#[tokio::test]
async fn immutable_invocation_limits_and_destination_cannot_change_on_retry() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("immutable", 1, 1);
    let granted = permit(&process, &admission).await;
    exchange(&process, inject(admission, payload, granted))
        .await
        .unwrap();
    let (mut retry, _) = fixture.attempt("immutable", 2, 2);
    retry.attempt.input_manifest_digest = "b".repeat(64);
    let retry = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(retry.attempt)
        .unwrap();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(retry)).await,
        Err(EgressError::InvalidRequest)
    ));
    let (mut changed, _) = fixture.attempt("destination", 1, 1);
    changed.attempt.destination = "https://unapproved.invalid".into();
    let changed = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(changed.attempt)
        .unwrap();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(changed)).await,
        Err(EgressError::RouteRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<std::sync::Mutex<String>>);
impl tracing::field::Visit for CapturedLogs {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = writeln!(self.0.lock().unwrap(), "{}={value:?}", field.name());
    }
}
impl tracing::Subscriber for CapturedLogs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        attrs.record(&mut self.clone());
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut self.clone());
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut self.clone());
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn provider_credential_errors_never_reach_runtime_logs() {
    let logs = CapturedLogs::default();
    tracing::subscriber::set_global_default(logs.clone()).unwrap();
    let fixture = Fixture::new(500, format!("backend failure: {SECRET}"), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("logs", 1, 1);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission, payload, granted))
            .await
            .unwrap(),
    );
    tracing::info!(status = ?result.receipt.status, "safe completion evidence");
    let captured = logs.0.lock().unwrap();
    assert!(captured.contains("safe completion evidence"));
    assert!(!captured.contains("synthetic-WP14-credential"));
    assert!(!captured.contains(&general_purpose::STANDARD.encode(SECRET)));
}

#[tokio::test]
async fn executable_recovery_lost_permit_and_completion_replies() {
    executable_dispatch(None, None).await;
}

#[tokio::test]
async fn executable_preserves_numeric_provider_cost_after_restart() {
    // Run this package alone (also a separate CI step): workspace tests unify
    // serde_json dev features that the production executable does not inherit.
    executable_dispatch(None, Some("0.1234567890123456789")).await;
}

#[tokio::test]
async fn ambient_proxies_cannot_receive_credentials_or_private_inputs() {
    let proxy = Fixture::new(200, "process answer".into(), Duration::ZERO).await;
    executable_dispatch(Some(&proxy.config.routes[0].destination), None).await;
    assert_eq!(proxy.calls.load(Ordering::SeqCst), 0);
}

async fn executable_dispatch(proxy: Option<&str>, numeric_cost: Option<&'static str>) {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    async fn ready_status(
        child: &mut Child,
        client: &socket::UnixEgressClient,
        signed_id: &SignedAttemptId,
    ) -> AttemptStatus {
        // The socket path can appear before the server is accepting.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(child.0.try_wait().unwrap().is_none());
                match client.attempt_status(signed_id.clone()).await {
                    Ok(status) => break status,
                    Err(EgressError::Transport) => {}
                    Err(error) => panic!("startup status failed: {error:?}"),
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
    let fixture = Fixture::with_cost(
        200,
        "process answer".into(),
        Duration::ZERO,
        numeric_cost.unwrap_or(r#""0.00001234567890123456789""#),
    )
    .await;
    let config_path = fixture.dir.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&fixture.config).unwrap()).unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut command =
        std::process::Command::new(env!("CARGO_BIN_EXE_symbiotic-credential-process"));
    // Isolate environment changes in the child; parallel tests retain their environment.
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
    if let Some(proxy) = proxy {
        for name in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            command.env(name, proxy);
        }
        command.env("NO_PROXY", "").env("no_proxy", "");
    }
    let mut child = Child(
        command
            .arg(&config_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let client = socket::UnixEgressClient {
        path: fixture.config.socket_path.clone(),
        max_frame_bytes: fixture.config.max_frame_bytes,
        timeout: Duration::from_secs(3),
    };
    let (admission, payload) = fixture.attempt("executable", 1, 1);
    let signed_id = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt_id(admission.attempt.attempt_id())
        .unwrap();
    assert!(matches!(
        ready_status(&mut child, &client, &signed_id).await,
        AttemptStatus::NotIssued
    ));
    // Never read the permit reply. Observe its commit via a separate connection
    // before dropping it, so this proves loss after commit rather than before accept.
    let lost_permit_reply =
        send_without_reading(&client, Operation::IssuePermit(admission.clone())).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if matches!(
                client.attempt_status(signed_id.clone()).await.unwrap(),
                AttemptStatus::Permitted
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(lost_permit_reply);
    let Reply::Permit(granted) = client
        .exchange(Request {
            version: PROTOCOL_VERSION,
            operation: Operation::IssuePermit(admission.clone()),
        })
        .await
        .unwrap()
        .result
        .unwrap()
    else {
        panic!("wrong reply")
    };
    assert!(matches!(granted.status, AttemptStatus::Permitted));
    // Lose the completion reply as well. No second injection is needed to settle.
    let lost_completion_reply =
        send_without_reading(&client, inject(admission, payload, granted.permit)).await;
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let AttemptStatus::Completed { result } =
                client.attempt_status(signed_id.clone()).await.unwrap()
            {
                break result;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(lost_completion_reply);
    assert!(result.receipt_persisted);
    assert_eq!(result.receipt.usage.input_tokens, Some(7));
    assert_eq!(result.receipt.usage.output_tokens, Some(3));
    assert_eq!(
        result.receipt.usage.reported_cost_usd.as_deref(),
        Some(numeric_cost.unwrap_or("0.00001234567890123456789"))
    );
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    assert!(
        matches!(&result.output, Some(ProviderOutput::Chat { text }) if text == "process answer")
    );
    drop(child);
    std::fs::remove_file(&fixture.config.socket_path).unwrap();
    let mut child = Child(command.spawn().unwrap());
    let recovered = ready_status(&mut child, &client, &signed_id).await;
    let AttemptStatus::Completed { result: recovered } = recovered else {
        panic!("missing result after executable restart");
    };
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(recovered).unwrap()
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn embeddings_share_attempt_binding_and_credential_boundary() {
    let mut fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    fixture.config.routes[0].provider = RouteProvider::GeminiEmbedding { dimensions: 8 };
    fixture.config.routes[0].destination =
        "https://generativelanguage.googleapis.com/v1beta".into();
    fixture.config.routes[0].model = "gemini-embedding-001".into();
    let process = fixture.process();
    std::fs::remove_file(fixture.dir.path().join("provider")).unwrap();
    let (mut admission, _) = fixture.attempt("embedding", 1, 1);
    let payload = ProviderPayload::Embedding(EmbeddingRequest {
        inputs: vec!["incoming input without a stored revision".into()],
        dimensions: Some(8),
        task: None,
        sensitivity: Sensitivity::Private,
        role_binding: None,
        source: None,
        metadata: serde_json::Value::Null,
    });
    admission.attempt.model = fixture.config.routes[0].model.clone();
    admission.attempt.input_digest = payload.digest().unwrap();
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    let granted = permit(&process, &admission).await;
    let mut changed = payload.clone();
    if let ProviderPayload::Embedding(request) = &mut changed {
        request.inputs[0] = "substituted".into();
    }
    assert!(matches!(
        exchange(
            &process,
            inject(admission.clone(), changed, granted.clone())
        )
        .await,
        Err(EgressError::InvalidRequest)
    ));
    let result = dispatched(
        exchange(&process, inject(admission, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::CredentialUnavailable);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn known_zero_charge_releases_reservation_for_next_attempt() {
    let fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    let process = fixture.process();
    std::fs::remove_file(fixture.dir.path().join("provider")).unwrap();
    for ordinal in 1..=2 {
        let (mut admission, payload) = fixture.attempt("zero-charge", ordinal, u64::from(ordinal));
        admission.attempt.reserved_budget.invocation_limit = 1;
        let admission = AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_attempt(admission.attempt)
            .unwrap();
        let granted = permit(&process, &admission).await;
        let result = dispatched(
            exchange(&process, inject(admission, payload, granted))
                .await
                .unwrap(),
        );
        assert_eq!(
            result.receipt.charge,
            ChargeReport::Measured {
                unit: "provider_requests".into(),
                amount: 0
            }
        );
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expanded_gemini_wire_payload_is_refused_before_consumption() {
    expanded_wire_payload_is_refused(true).await;
}

#[tokio::test]
async fn expanded_chat_wire_payload_is_refused_before_consumption() {
    expanded_wire_payload_is_refused(false).await;
}

async fn expanded_wire_payload_is_refused(embedding: bool) {
    let mut fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    fixture.config.routes[0].max_input_bytes = 1024;
    let payload = if embedding {
        fixture.config.routes[0].provider = RouteProvider::GeminiEmbedding { dimensions: 8 };
        fixture.config.routes[0].destination =
            "https://generativelanguage.googleapis.com/v1beta".into();
        fixture.config.routes[0].model = "gemini-embedding-001".into();
        ProviderPayload::Embedding(EmbeddingRequest {
            inputs: vec!["x".into(); 128],
            dimensions: Some(8),
            task: None,
            sensitivity: Sensitivity::Private,
            role_binding: None,
            source: None,
            metadata: serde_json::Value::Null,
        })
    } else {
        // The configured model is absent from the typed payload but present on the wire.
        fixture.config.routes[0].model = "m".repeat(1024);
        fixture.attempt("wire-limit", 1, 1).1
    };
    assert!(serde_json::to_vec(&payload).unwrap().len() < 1024);
    let process = fixture.process();
    // A regression must stop before loading this missing secret, and cannot reach Google.
    std::fs::remove_file(fixture.dir.path().join("provider")).unwrap();
    let (mut admission, _) = fixture.attempt("wire-limit", 1, 1);
    admission.attempt.model = fixture.config.routes[0].model.clone();
    admission.attempt.input_digest = payload.digest().unwrap();
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    let granted = permit(&process, &admission).await;
    let result = exchange(&process, inject(admission.clone(), payload, granted)).await;
    assert!(
        matches!(result, Err(EgressError::LimitExceeded)),
        "oversized wire body accepted (embedding={embedding})"
    );
    assert!(matches!(
        exchange(&process, Operation::Receipt(admission)).await,
        Ok(Reply::Receipt(None))
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn conflicting_shared_route_limits_are_refused_at_startup() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    for field in ["concurrency", "requests", "input"] {
        let mut config = fixture.config.clone();
        let mut second = config.routes[0].clone();
        second.route = "second-route".into();
        second.tenant = "other-tenant".into();
        match field {
            "concurrency" => second.max_in_flight += 1,
            "requests" => second.requests_per_minute = Some(60),
            _ => second.input_units_per_minute = Some(1000),
        }
        config.routes.push(second);
        assert!(matches!(
            CredentialProcess::open(config),
            Err(EgressError::InvalidRequest)
        ));
    }
    let mut config = fixture.config.clone();
    let mut second = config.routes[0].clone();
    second.route = "same-limits".into();
    config.routes.push(second);
    assert!(CredentialProcess::open(config).is_ok());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failure_before_dispatch_returns_safe_error_and_releases_reservation() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let db = rusqlite::Connection::open(fixture.config.state_dir.join("queue.sqlite")).unwrap();
    // Inject a real queue write failure after permit consumption, before HTTP.
    db.execute_batch(
        "CREATE TRIGGER refuse_queue BEFORE INSERT ON queue_items
        BEGIN SELECT RAISE(FAIL, 'synthetic queue unavailable'); END;",
    )
    .unwrap();
    let (first, payload) = fixture.attempt("pre-dispatch", 1, 1);
    let granted = permit(&process, &first).await;
    let result = dispatched(
        exchange(&process, inject(first.clone(), payload, granted))
            .await
            .unwrap(),
    );
    let wire = serde_json::to_value(&result).unwrap();
    assert_eq!(wire["error"], "state_unavailable");
    let decoded: DispatchResult = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded.error, Some(EgressError::StateUnavailable));
    assert!(!wire.to_string().contains(SECRET));
    assert!(result.output.is_none());
    assert!(result.receipt_persisted);
    assert_eq!(
        result.receipt.charge,
        ChargeReport::Measured {
            unit: "provider_requests".into(),
            amount: 0
        }
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    drop(process);
    db.execute_batch("DROP TRIGGER refuse_queue").unwrap();
    let process = fixture.process();
    let stored = exchange(&process, Operation::Receipt(first)).await.unwrap();
    assert!(matches!(
        stored,
        Reply::Receipt(Some(DispatchReceipt {
            charge: ChargeReport::Measured { amount: 0, .. },
            ..
        }))
    ));
    let (retry, payload) = fixture.attempt("pre-dispatch", 2, 2);
    let granted = permit(&process, &retry).await;
    let result = dispatched(
        exchange(&process, inject(retry, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn recovery_lost_permit_reply_reattaches_after_restart() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("lost-permit", 1, 10);
    let committed = permit(&process, &admission).await;
    drop(process);
    let process = fixture.process();
    let recovered = permit(&process, &admission).await;
    assert_eq!(committed.token, recovered.token);
    assert_eq!(committed.attempt_digest, recovered.attempt_digest);
    let result = dispatched(
        exchange(&process, inject(admission, payload, recovered))
            .await
            .unwrap(),
    );
    assert!(result.error.is_none());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

async fn send_without_reading(
    client: &socket::UnixEgressClient,
    operation: Operation,
) -> tokio::net::UnixStream {
    let mut stream = tokio::net::UnixStream::connect(&client.path).await.unwrap();
    socket::write_frame(
        &mut stream,
        &Request {
            version: PROTOCOL_VERSION,
            operation,
        },
        client.max_frame_bytes,
    )
    .await
    .unwrap();
    stream
}

async fn status(process: &CredentialProcess, admission: &SignedAttempt) -> AttemptStatus {
    let id = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt_id(admission.attempt.attempt_id())
        .unwrap();
    match exchange(process, Operation::AttemptStatus(id))
        .await
        .unwrap()
    {
        Reply::AttemptStatus(status) => status,
        _ => panic!("wrong reply"),
    }
}

#[tokio::test]
async fn recovery_lost_completion_reply_survives_restart_with_output_and_usage() {
    let fixture = Fixture::new(200, "retained answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("lost-completion", 1, 10);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(
            &process,
            inject(admission.clone(), payload, granted.clone()),
        )
        .await
        .unwrap(),
    );
    assert!(result.receipt_persisted);
    assert_eq!(
        serde_json::to_value(&result.receipt.usage).unwrap()["reported_cost_usd"],
        "0.00001234567890123456789"
    );
    assert_eq!(result.receipt.usage.cost_micro_usd, None);
    assert!(matches!(
        result.receipt.charge,
        ChargeReport::Measured { amount: 1, .. }
    ));
    drop(process);
    let process = fixture.process();
    let AttemptStatus::Completed { result: recovered } = status(&process, &admission).await else {
        panic!("missing result");
    };
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(recovered).unwrap()
    );
    let Reply::Permit(reattached) = exchange(&process, Operation::IssuePermit(admission))
        .await
        .unwrap()
    else {
        panic!("missing permit");
    };
    assert_eq!(reattached.permit.token, granted.token);
    assert!(matches!(reattached.status, AttemptStatus::Completed { .. }));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn recovery_same_identity_with_different_signed_digest_is_refused() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, _) = fixture.attempt("digest-mismatch", 1, 10);
    permit(&process, &admission).await;
    let key = AdmissionKey::new(KEY.to_vec()).unwrap();
    for field in 0..3 {
        let mut changed = admission.attempt.clone();
        match field {
            0 => changed.record_sequence += 1,
            1 => changed.input_digest = "c".repeat(64),
            _ => changed.recovery_expires_at += 1,
        }
        assert!(matches!(
            exchange(
                &process,
                Operation::IssuePermit(key.sign_attempt(changed).unwrap())
            )
            .await,
            Err(EgressError::InvalidRequest)
        ));
    }
    let mut signed_id = key.sign_attempt_id(admission.attempt.attempt_id()).unwrap();
    signed_id.attempt_id.tenant = "other".into();
    assert!(matches!(
        exchange(&process, Operation::AttemptStatus(signed_id)).await,
        Err(EgressError::Unauthorized)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn recovery_failed_status_preserves_safe_error_and_charge() {
    let fixture = Fixture::new(500, SECRET.into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("failed-status", 1, 10);
    let granted = permit(&process, &admission).await;
    exchange(&process, inject(admission.clone(), payload, granted))
        .await
        .unwrap();
    let AttemptStatus::Failed { result } = status(&process, &admission).await else {
        panic!("missing failure");
    };
    assert!(result.error.is_some());
    assert!(result.output.is_none());
    assert!(matches!(
        result.receipt.charge,
        ChargeReport::Unknown { .. }
    ));
    assert!(!serde_json::to_string(&result).unwrap().contains(SECRET));
}

#[tokio::test]
async fn recovery_expired_status_does_not_retain_late_completion() {
    let fixture = Fixture::new(200, "expired answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (mut admission, payload) = fixture.attempt("expired-status", 1, 10);
    admission.attempt.recovery_expires_at = 102; // Declared window already elapsed.
    admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission.clone(), payload, granted))
            .await
            .unwrap(),
    );
    assert!(result.receipt_persisted);
    assert!(matches!(
        status(&process, &admission).await,
        AttemptStatus::Expired
    ));
    drop(process);
    let process = fixture.process();
    assert!(matches!(
        status(&process, &admission).await,
        AttemptStatus::Expired
    ));
    assert!(matches!(
        exchange(&process, Operation::Receipt(admission.clone()))
            .await
            .unwrap(),
        Reply::Receipt(Some(_))
    ));
    let Reply::Permit(grant) = exchange(&process, Operation::IssuePermit(admission))
        .await
        .unwrap()
    else {
        panic!("missing permit");
    };
    assert!(matches!(grant.status, AttemptStatus::Expired));
    let db = rusqlite::Connection::open(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
    )
    .unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM egress_permits WHERE result IS NOT NULL",
            [],
            |row| row.get::<_, u64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn recovery_idle_server_purges_completed_results_at_deadline() {
    let fixture = Fixture::new(200, "short-lived answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, payload) = fixture.attempt("idle-expiry", 1, 10);
    let granted = permit(&process, &admission).await;
    exchange(&process, inject(admission.clone(), payload, granted))
        .await
        .unwrap();
    assert!(matches!(
        status(&process, &admission).await,
        AttemptStatus::Completed { .. }
    ));
    let listener = server::bind(&process).unwrap();
    let task = tokio::spawn(server::serve(process.clone(), listener));
    let db = rusqlite::Connection::open(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
    )
    .unwrap();
    // Advance the stored deadline in this fixture so slow debug builds cannot
    // expire the answer before the test observes completion. The registry test
    // separately checks the exact signed deadline boundary with an injected time.
    db.execute("UPDATE egress_permits SET recovery_expires_at=0", [])
        .unwrap();
    // No further IPC/handle requests: the daemon must expire results while idle.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let retained: u64 = db
                .query_row(
                    "SELECT count(*) FROM egress_permits WHERE result IS NOT NULL",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            if retained == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        status(&process, &admission).await,
        AttemptStatus::Expired
    ));
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn recovery_concurrent_permit_requests_share_one_capability() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process();
    let (admission, _) = fixture.attempt("concurrent-issue", 1, 10);
    let (first, second) = tokio::join!(permit(&process, &admission), permit(&process, &admission));
    assert_eq!(first.token, second.token);
    assert_eq!(first.attempt_digest, second.attempt_digest);
    assert!(matches!(
        status(&process, &admission).await,
        AttemptStatus::Permitted
    ));
    let request = Request {
        version: 1,
        operation: Operation::IssuePermit(admission),
    };
    assert!(matches!(
        process.handle(request).await.result,
        Err(EgressError::Version)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn recovery_disconnected_peer_does_not_stop_socket_server() {
    let fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    let process = fixture.process();
    let listener = server::bind(&process).unwrap();
    // Disconnect before accept/peer authentication, as can happen with a lost reply.
    let stream = tokio::net::UnixStream::connect(&fixture.config.socket_path)
        .await
        .unwrap();
    drop(stream);
    let task = tokio::spawn(server::serve(process, listener));
    tokio::task::yield_now().await;
    assert!(
        !task.is_finished(),
        "one disconnected peer stopped the server: {:?}",
        task.await
    );
    task.abort();
    let _ = task.await;
}
