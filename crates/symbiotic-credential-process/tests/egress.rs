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
    CredentialProcess, InProcessEgressClient, ProcessConfig, RouteConfig, RouteProvider,
    secrets::{SecretSource, initialize_resolver_panic_hook},
    server,
};
use symbiotic_egress::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const SECRET: &str = "synthetic-WP14-credential-\"/+?=é-canary";
const KEY: &[u8] = b"synthetic-admission-key-at-least-32-bytes";

fn initialize_panic_reporting() {
    static INITIALIZE: std::sync::Once = std::sync::Once::new();
    INITIALIZE.call_once(|| initialize_resolver_panic_hook(std::panic::take_hook()));
}

// Paths are read when the tests run, not compiled in: a compiled-in path makes this test build
// specific to one checkout, so no other worktree can reuse it from the build cache.
fn credential_process() -> std::path::PathBuf {
    std::env::var_os("CARGO_BIN_EXE_symbiotic-credential-process")
        .expect("cargo test sets CARGO_BIN_EXE_symbiotic-credential-process")
        .into()
}

#[cfg(target_os = "macos")]
fn manifest_dir() -> std::path::PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("cargo test sets CARGO_MANIFEST_DIR")
        .into()
}

#[tokio::test]
async fn configuration_refuses_removed_secret_backend_before_startup() {
    let fixture = Fixture::new(200, "ok".into(), Duration::ZERO).await;
    for admission in [true, false] {
        let mut config = serde_json::to_value(&fixture.config).unwrap();
        let source = serde_json::json!({
            "backend": "macos_keychain",
            "service": "synthetic-service",
            "account": "synthetic-account"
        });
        if admission {
            config["admission_key"] = source;
        } else {
            config["routes"][0]["secret"] = source;
        }
        let error = serde_json::from_value::<ProcessConfig>(config.clone())
            .err()
            .expect("removed secret backend must be refused during deserialization");
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("unknown variant `macos_keychain`"));
        assert!(diagnostic.contains("`none`"));
        assert!(diagnostic.contains("`owner_only_file`"));

        let path = fixture.dir.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let output = std::process::Command::new(credential_process())
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "invalid configuration: supported secret backends are `none` and `owner_only_file`"
        );
        assert!(!fixture.config.state_dir.exists());
        assert!(!fixture.config.socket_path.exists());
    }
}

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
        Self::with_http_response(status, output, delay, cost_json, false, false).await
    }
    async fn with_http_response(
        status: u16,
        output: String,
        delay: Duration,
        cost_json: &'static str,
        raw_response: bool,
        keyless: bool,
    ) -> Self {
        Self::with_response_gate(
            status,
            output,
            delay,
            cost_json,
            raw_response,
            keyless,
            None,
        )
        .await
    }
    async fn with_response_gate(
        status: u16,
        output: String,
        delay: Duration,
        cost_json: &'static str,
        raw_response: bool,
        keyless: bool,
        response_gate: Option<Arc<tokio::sync::Semaphore>>,
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
                let response_gate = response_gate.clone();
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
                                if keyless {
                                    assert!(
                                        !headers.to_ascii_lowercase().contains("authorization:")
                                    );
                                } else if headers.starts_with("POST /v1/messages ") {
                                    assert!(headers.contains(&format!("x-api-key: {SECRET}")));
                                    assert!(headers.contains("anthropic-version: 2023-06-01"));
                                } else {
                                    assert!(headers.contains(&format!("Bearer {SECRET}")));
                                }
                                assert!(
                                    !String::from_utf8_lossy(&data[header_end + 4..])
                                        .contains("synthetic-WP14-credential")
                                );
                                break;
                            }
                        }
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    if let Some(gate) = response_gate {
                        gate.acquire().await.unwrap().forget();
                    }
                    tokio::time::sleep(delay).await;
                    let body = if status == 200 && !raw_response {
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
            clock_rollback_warning_tolerance_seconds: 5,
            jobs: Default::default(),
            job_runner: Default::default(),
            routes: vec![RouteConfig {
                tenant: "tenant".into(),
                account: "account".into(),
                account_sharing_key: None,
                provider_request_limit: None,
                max_attempts: 3,
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
    async fn process(&self) -> CredentialProcess {
        let process = CredentialProcess::open(self.config.clone()).unwrap();
        // Initial publication is explicit; restart cannot roll back a newer revision.
        match exchange(&process, publish_revision(1)).await {
            Ok(Reply::GrantRevisionPublished) | Err(EgressError::RouteRefused) => (),
            _ => panic!("initial revision publication failed"),
        }
        process
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
            expires_at: unix_seconds() + 3600,
            recovery_expires_at: 4_000_000_000,
            caller_binding: "caller".into(),
            route: "chat".into(),
            destination: self.config.routes[0].destination.clone(),
            model: "test-model".into(),
            method: "POST".into(),
            secret_ref: self.config.routes[0].secret_ref.clone(),
            manifest_ref: "manifest".into(),
            input_manifest_digest: "a".repeat(64),
            input_digest: payload.digest().unwrap(),
            grant_revision: 1,
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
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn exchange_wire(
    process: &CredentialProcess,
    operation: Operation,
) -> Result<Reply, EgressError> {
    let bytes = serde_json::to_vec(&Request {
        version: PROTOCOL_VERSION,
        operation,
    })
    .unwrap();
    let response = InProcessEgressClient::new(process.clone())
        .exchange(serde_json::from_slice(&bytes).unwrap())
        .await?;
    serde_json::from_slice::<Response>(&serde_json::to_vec(&response).unwrap())
        .unwrap()
        .result
}

#[tokio::test]
async fn authority_deadline_passed_between_check_and_acceptance_allows_reauthorization() {
    for restart in [false, true] {
        let mut fixture = Fixture::new(200, "reauthorized answer".into(), Duration::ZERO).await;
        fixture.config.routes[0].max_attempts = 1;
        fixture.config.routes[0].provider_request_limit = Some(1);
        let mut process = fixture.process().await;
        let key = AdmissionKey::new(KEY.to_vec()).unwrap();
        let (first, payload) = fixture.attempt("authority-deadline", 1, 10);
        let mut first = first.attempt;
        first.recorded_at = unix_seconds();
        first.expires_at = first.recorded_at + 2;
        let first = key.sign_attempt(first).unwrap();
        let granted = permit(&process, &first).await;
        assert!(unix_seconds() < first.attempt.expires_at);
        // Serialized after the consumer's successful check, but delayed until
        // Foundation's clock has reached the exclusive authority deadline.
        let bytes = serde_json::to_vec(&Request {
            version: PROTOCOL_VERSION,
            operation: inject(first.clone(), payload.clone(), granted.clone()),
        })
        .unwrap();
        while unix_seconds() < first.attempt.expires_at {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let response = InProcessEgressClient::new(process.clone())
            .exchange(serde_json::from_slice(&bytes).unwrap())
            .await
            .unwrap();
        let response: Response =
            serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();
        assert!(matches!(
            response.result,
            Err(EgressError::AuthorityExpired)
        ));
        assert!(matches!(
            status(&process, &first).await,
            AttemptStatus::Invalidated
        ));
        assert!(matches!(
            exchange(&process, Operation::Receipt(signed_id(&first))).await,
            Ok(Reply::Receipt(None))
        ));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        assert_eq!(ledger_totals(&fixture), (0, 0));
        let db = rusqlite::Connection::open(
            fixture
                .config
                .state_dir
                .join(symbiotic_ai_runtime::QUEUE_DATABASE),
        )
        .unwrap();
        assert_eq!(
            db.query_row(
                "SELECT consumed, accepted_attempts FROM egress_permits",
                [],
                |r| Ok((r.get::<_, bool>(0)?, r.get::<_, u32>(1)?))
            )
            .unwrap(),
            (false, 0)
        );
        drop(db);
        if restart {
            drop(process);
            process = fixture.process().await;
        }
        let reattached = permit(&process, &first).await;
        assert_eq!(reattached.token, granted.token);
        assert!(matches!(
            exchange_wire(&process, inject(first.clone(), payload.clone(), reattached)).await,
            Err(EgressError::AuthorityExpired)
        ));
        let mut second = first.attempt.clone();
        second.recorded_at = unix_seconds();
        second.expires_at = second.recorded_at + 3600;
        // A newly signed deadline cannot mutate an existing attempt identity.
        assert!(matches!(
            exchange_wire(
                &process,
                Operation::IssuePermit(key.sign_attempt(second.clone()).unwrap().into())
            )
            .await,
            Err(EgressError::InvalidRequest)
        ));
        second.attempt_ordinal += 1;
        second.record_sequence += 1;
        let second = key.sign_attempt(second).unwrap();
        let second_permit = permit(&process, &second).await;
        let result = dispatched(
            exchange_wire(&process, inject(second.clone(), payload, second_permit))
                .await
                .unwrap(),
        );
        assert_eq!(result.receipt.attempt_id, second.attempt.attempt_id());
        assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(ledger_totals(&fixture), (1, 1));
    }
}

#[tokio::test]
async fn accepted_handoff_completes_and_recovers_after_authority_deadline() {
    let mut fixture = Fixture::new(200, "accepted answer".into(), Duration::from_secs(2)).await;
    fixture.config.routes[0].timeout_seconds = 4;
    let process = fixture.process().await;
    let (mut admission, payload) = fixture.attempt("accepted-deadline", 1, 10);
    admission.attempt.recorded_at = unix_seconds();
    admission.attempt.expires_at = admission.attempt.recorded_at + 2;
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange_wire(
            &process,
            inject(admission.clone(), payload.clone(), granted.clone()),
        )
        .await
        .unwrap(),
    );
    assert!(unix_seconds() >= admission.attempt.expires_at);
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    assert_eq!(result.receipt.spend_state, SpendState::Settled);
    drop(process);
    let process = fixture.process().await;
    let AttemptStatus::Completed { result: recovered } = status(&process, &admission).await else {
        panic!("accepted result was withdrawn after authority expiry");
    };
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::to_value(recovered).unwrap()
    );
    assert!(matches!(
        exchange_wire(&process, inject(admission, payload, granted)).await,
        Err(EgressError::PermitRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger_totals(&fixture), (1, 1));
}

async fn exchange(process: &CredentialProcess, operation: Operation) -> Result<Reply, EgressError> {
    exchange_client(&InProcessEgressClient::new(process.clone()), operation).await
}

async fn exchange_client(
    client: &dyn EgressClient,
    operation: Operation,
) -> Result<Reply, EgressError> {
    client
        .exchange(Request {
            version: PROTOCOL_VERSION,
            operation,
        })
        .await?
        .result
}
async fn permit(process: &CredentialProcess, admission: &SignedAttempt) -> DispatchPermit {
    match exchange(process, Operation::IssuePermit(admission.clone().into()))
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
fn signed_id(admission: &SignedAttempt) -> SignedAttemptId {
    AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt_id(admission.attempt.attempt_id())
        .unwrap()
}
fn publish_revision(revision: u64) -> Operation {
    Operation::PublishGrantRevision(
        AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_grant_revision(GrantRevision {
                tenant: "tenant".into(),
                incarnation: "incarnation".into(),
                revision,
            })
            .unwrap(),
    )
}
async fn revoke(process: &CredentialProcess, revision: u64) {
    assert!(matches!(
        exchange(process, publish_revision(revision)).await.unwrap(),
        Reply::GrantRevisionPublished
    ));
}

#[tokio::test]
async fn permit_replay_refused_concurrently_and_after_restart() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
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
    let process = fixture.process().await;
    assert!(matches!(
        exchange(&process, request).await,
        Err(EgressError::PermitRefused)
    ));
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(admission.into())).await,
        Ok(Reply::Permit(PermitGrant {
            status: AttemptStatus::Completed { .. },
            ..
        }))
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn grant_updates_refuse_old_admissions_and_cannot_roll_back_after_restart() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    revoke(&process, 11).await;
    let (old, _) = fixture.attempt("old", 1, 10);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(old.into())).await,
        Err(EgressError::RouteRefused)
    ));
    assert!(matches!(
        exchange(&process, publish_revision(10)).await,
        Err(EgressError::RouteRefused)
    ));
    let (mut current, payload) = fixture.attempt("current", 1, 12);
    current.attempt.grant_revision = 11;
    current = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(current.attempt)
        .unwrap();
    let granted = permit(&process, &current).await;
    let result = dispatched(
        exchange(&process, inject(current, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    drop(process);
    let process = fixture.process().await;
    let (old, _) = fixture.attempt("old-restart", 1, 12);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(old.into())).await,
        Err(EgressError::RouteRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn grant_revocation_between_admission_and_dispatch_refuses_all_pending_admissions() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let mut process = fixture.process().await;
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
            process = fixture.process().await;
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
                AttemptStatus::Invalidated
            ));
            assert!(matches!(
                exchange(&process, Operation::Receipt(signed_id(admission))).await,
                Ok(Reply::Receipt(None))
            ));
            let reattached = permit(&process, admission).await;
            assert_eq!(reattached.token, granted.token);
            assert_eq!(reattached.attempt_digest, granted.attempt_digest);
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    }
    assert!(matches!(
        exchange(&process, inject(early, early_payload, early_permit)).await,
        Err(EgressError::RouteRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalidated_permit_allows_reauthorized_handoff_at_max_attempts_one() {
    for restart in [false, true] {
        let mut fixture = Fixture::new(200, "reauthorized answer".into(), Duration::ZERO).await;
        fixture.config.routes[0].max_attempts = 1;
        let mut process = fixture.process().await;
        let (first, payload) = fixture.attempt("reauthorized", 1, 10);
        let first_permit = permit(&process, &first).await;
        revoke(&process, 2).await;
        assert!(matches!(
            status(&process, &first).await,
            AttemptStatus::Invalidated
        ));
        assert!(matches!(
            exchange(
                &process,
                inject(first.clone(), payload.clone(), first_permit.clone())
            )
            .await,
            Err(EgressError::RouteRefused)
        ));
        assert_eq!(ledger_totals(&fixture), (0, 0));
        if restart {
            drop(process);
            process = fixture.process().await;
        }
        let key = AdmissionKey::new(KEY.to_vec()).unwrap();
        let mut second = first.attempt.clone();
        second.grant_revision = 2;
        // Reauthorization cannot mutate an existing attempt identity.
        assert!(matches!(
            exchange(
                &process,
                Operation::IssuePermit(key.sign_attempt(second.clone()).unwrap().into())
            )
            .await,
            Err(EgressError::InvalidRequest)
        ));
        second.attempt_ordinal = 2;
        second.record_sequence = 11;
        let second = key.sign_attempt(second).unwrap();
        let second_permit = permit(&process, &second).await;
        assert_ne!(second_permit.token, first_permit.token);
        assert!(matches!(
            status(&process, &first).await,
            AttemptStatus::Invalidated
        ));
        assert!(matches!(
            exchange(&process, Operation::Receipt(signed_id(&first))).await,
            Ok(Reply::Receipt(None))
        ));
        let reattached = permit(&process, &first).await;
        assert_eq!(reattached.token, first_permit.token);
        assert!(matches!(
            exchange(&process, inject(first, payload.clone(), reattached)).await,
            Err(EgressError::RouteRefused)
        ));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        let result = dispatched(
            exchange(&process, inject(second.clone(), payload, second_permit))
                .await
                .unwrap(),
        );
        assert_eq!(result.receipt.attempt_id, second.attempt.attempt_id());
        assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(ledger_totals(&fixture), (1, 1));
    }
}

#[tokio::test]
async fn invalidated_permits_preserve_accepted_attempt_allowance_after_restart() {
    let mut fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    fixture.config.routes[0].max_attempts = 2;
    fixture.config.routes[0].secret = SecretSource::OwnerOnlyFile {
        path: fixture.dir.path().join("missing-provider"),
    };
    let mut process = fixture.process().await;
    let key = AdmissionKey::new(KEY.to_vec()).unwrap();
    for (ordinal, revision, consume) in [(1, 1, true), (2, 1, false), (3, 2, false), (4, 3, true)] {
        let (mut admission, payload) = fixture.attempt("allowance", ordinal, u64::from(ordinal));
        admission.attempt.grant_revision = revision;
        let admission = key.sign_attempt(admission.attempt).unwrap();
        let granted = permit(&process, &admission).await;
        if consume {
            let result = dispatched(
                exchange(&process, inject(admission, payload, granted))
                    .await
                    .unwrap(),
            );
            assert_eq!(result.receipt.spend_state, SpendState::Released);
        } else {
            revoke(&process, revision + 1).await;
            assert!(matches!(
                exchange(&process, inject(admission, payload, granted)).await,
                Err(EgressError::RouteRefused)
            ));
        }
        drop(process);
        process = fixture.process().await;
    }
    let (mut excess, _) = fixture.attempt("allowance", 5, 5);
    excess.attempt.grant_revision = 3;
    let excess = key.sign_attempt(excess.attempt).unwrap();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(excess.into())).await,
        Err(EgressError::BudgetRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger_totals(&fixture), (0, 2));
}

#[tokio::test]
async fn wrong_input_or_attempt_cannot_spend_a_permit() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
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
    let process = fixture.process().await;
    let (mut admission, _) = fixture.attempt("tamper", 1, 10);
    admission.attempt.route = "forged".into();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(admission.into())).await,
        Err(EgressError::Unauthorized)
    ));
    let (mut admission, _) = fixture.attempt("expired", 1, 10);
    admission.attempt.recorded_at = admission.attempt.expires_at;
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(admission.into())).await,
        Err(EgressError::InvalidRequest)
    ));
    let (admission, _) = fixture.attempt("deadline-bounds", 1, 10);
    for expires_at in [unix_seconds(), i64::MAX as u64 + 1] {
        let mut attempt = admission.attempt.clone();
        attempt.expires_at = expires_at;
        let signed = AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_attempt(attempt)
            .unwrap();
        let expected = if expires_at > i64::MAX as u64 {
            EgressError::InvalidRequest
        } else {
            EgressError::AuthorityExpired
        };
        assert!(
            matches!(exchange(&process, Operation::IssuePermit(signed.into())).await, Err(error) if error == expected)
        );
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retry_is_a_new_attempt_same_invocation_without_response_cache() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
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
        exchange(&process, Operation::IssuePermit(completed.into())).await,
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
    let process = fixture.process().await;
    let (admission, payload) = fixture.attempt("timeout", 1, 1);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission.clone(), payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::ProviderFailed);
    assert_eq!(result.error, Some(EgressError::Transport));
    assert_eq!(result.receipt.spend_state, SpendState::Unknown);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger_totals(&fixture), (1, 1));
    drop(process);
    let process = fixture.process().await;
    let receipt = exchange(&process, Operation::Receipt(signed_id(&admission)))
        .await
        .unwrap();
    assert!(matches!(
        receipt,
        Reply::Receipt(Some(DispatchReceipt {
            spend_state: SpendState::Unknown,
            ..
        }))
    ));
    let (retry, _) = fixture.attempt("timeout", 2, 2);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(retry.into())).await,
        Err(EgressError::ReconciliationRequired)
    ));
}

#[tokio::test]
async fn caller_cancellation_does_not_cancel_started_dispatch() {
    let fixture = Fixture::new(200, "answer".into(), Duration::from_millis(80)).await;
    let process = fixture.process().await;
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
                exchange(&process, Operation::Receipt(signed_id(&admission)))
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
            let process = fixture.process().await;
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
    let process = fixture.process().await;
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
            operation: Operation::IssuePermit(admission.clone().into()),
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
async fn missing_secret_releases_foundation_reservation() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    std::fs::remove_file(fixture.dir.path().join("provider")).unwrap();
    let (admission, payload) = fixture.attempt("missing", 1, 1);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::CredentialUnavailable);
    assert_eq!(result.receipt.spend_state, SpendState::Released);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn redirects_and_oversized_provider_responses_fail_without_a_second_call() {
    for (status, body) in [(302, "redirect".to_owned()), (200, "x".repeat(40000))] {
        let fixture = Fixture::new(status, body, Duration::ZERO).await;
        let process = fixture.process().await;
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
async fn immutable_invocation_inputs_and_destination_cannot_change_on_retry() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
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
        exchange(&process, Operation::IssuePermit(retry.into())).await,
        Err(EgressError::InvalidRequest)
    ));
    let (mut changed, _) = fixture.attempt("destination", 1, 1);
    changed.attempt.destination = "https://unapproved.invalid".into();
    let changed = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(changed.attempt)
        .unwrap();
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(changed.into())).await,
        Err(EgressError::RouteRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[derive(Clone, Default)]
struct CapturedLogs(
    Arc<std::sync::Mutex<String>>,
    Option<Arc<dyn Fn() + Send + Sync>>,
);
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
        if event.metadata().fields().field("ahead_seconds").is_some()
            && let Some(on_warning) = &self.1
        {
            assert_eq!(*event.metadata().level(), tracing::Level::WARN);
            on_warning();
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn provider_credential_errors_never_reach_runtime_logs() {
    let logs = CapturedLogs::default();
    tracing::subscriber::set_global_default(logs.clone()).unwrap();
    let fixture = Fixture::new(500, format!("backend failure: {SECRET}"), Duration::ZERO).await;
    let process = fixture.process().await;
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
    executable_dispatch(None, None, None).await;
}

#[tokio::test]
async fn executable_preserves_numeric_provider_cost_after_restart() {
    // Run this package alone (also a separate CI step): workspace tests unify
    // serde_json dev features that the production executable does not inherit.
    executable_dispatch(None, Some("0.1234567890123456789"), None).await;
}

#[tokio::test]
async fn ambient_proxies_cannot_receive_credentials_or_private_inputs() {
    let proxy = Fixture::new(200, "process answer".into(), Duration::ZERO).await;
    executable_dispatch(Some(&proxy.config.routes[0].destination), None, None).await;
    assert_eq!(proxy.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn signed_attempt_time_ahead_beyond_tolerance_warns_and_accepts() {
    signed_attempt_time_warning(3600, 5, true).await;
}

#[tokio::test]
async fn signed_attempt_time_within_tolerance_accepts_without_warning() {
    signed_attempt_time_warning(5, 5, false).await;
}

#[tokio::test]
async fn signed_attempt_time_uses_configured_warning_tolerance() {
    signed_attempt_time_warning(3600, 7200, false).await;
}

async fn signed_attempt_time_warning(
    ahead_seconds: u64,
    tolerance_seconds: u64,
    should_warn: bool,
) {
    use tracing::instrument::WithSubscriber;

    let mut fixture = Fixture::new(200, "process answer".into(), Duration::ZERO).await;
    fixture.config.clock_rollback_warning_tolerance_seconds = tolerance_seconds;
    let process = fixture.process().await;
    let reentrant_process = process.clone();
    let logs = CapturedLogs(
        Arc::default(),
        Some(Arc::new(move || {
            // A subscriber can reenter the process. Delivery must hold no registry lock.
            let process = reentrant_process.clone();
            let (send, receive) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = send.send(process.purge_expired_results());
            });
            assert_eq!(
                receive.recv_timeout(Duration::from_secs(1)).unwrap(),
                Ok(())
            );
        })),
    );
    let (mut admission, payload) = fixture.attempt("clock-warning", 1, 1);
    admission.attempt.recorded_at = unix_seconds() + ahead_seconds;
    admission.attempt.expires_at = admission.attempt.recorded_at + 3600;
    admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    // These handler logging/reentrancy checks use a scoped subscriber, which
    // Tokio does not inherit in the in-process client's detached task.
    let handle = |operation| {
        let process = &process;
        async move {
            process
                .handle(Request {
                    version: PROTOCOL_VERSION,
                    operation,
                })
                .await
                .result
                .unwrap()
        }
    };
    async {
        let Reply::Permit(granted) = handle(Operation::IssuePermit(admission.clone().into())).await
        else {
            panic!("missing permit")
        };
        let Reply::Permit(replayed) =
            handle(Operation::IssuePermit(admission.clone().into())).await
        else {
            panic!("missing replayed permit")
        };
        assert!(replayed.permit.token == granted.permit.token);
        assert_eq!(
            replayed.permit.attempt_digest,
            granted.permit.attempt_digest
        );
        let result = dispatched(handle(inject(admission, payload, granted.permit)).await);
        assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
        assert!(result.receipt_persisted);
    }
    .with_subscriber(logs.clone())
    .await;
    let captured = logs.0.lock().unwrap();
    // Fresh issuance, replayed issuance, and accepted dispatch all report.
    assert_eq!(
        captured
            .matches("event=\"signed_attempt_time_ahead\"")
            .count(),
        if should_warn { 3 } else { 0 }
    );
    if should_warn {
        assert_eq!(captured.matches("recorded_at=").count(), 3);
        assert_eq!(captured.matches("foundation_now=").count(), 3);
        assert_eq!(captured.matches("ahead_seconds=").count(), 3);
        assert_eq!(
            captured
                .matches(&format!("tolerance_seconds={tolerance_seconds}\n"))
                .count(),
            3
        );
        let lines = captured.lines().collect::<Vec<_>>();
        let (warnings, remainder) = lines.as_chunks::<5>();
        assert!(remainder.is_empty());
        for warning in warnings {
            let value = |name: &str| {
                warning
                    .iter()
                    .find_map(|line| line.strip_prefix(&format!("{name}=")))
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            };
            assert_eq!(
                value("ahead_seconds"),
                value("recorded_at") - value("foundation_now")
            );
            assert!(value("ahead_seconds") > tolerance_seconds);
        }
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn signed_attempt_time_open_log_sink_reports_executable_warnings() {
    let logs = executable_dispatch(None, None, Some((3600, 5, false))).await;
    // Fresh issuance, replayed issuance, and accepted dispatch each warn on stderr.
    assert_eq!(logs.matches("WARN").count(), 3);
    assert_eq!(
        logs.matches("event=\"signed_attempt_time_ahead\"").count(),
        3
    );
    for field in [
        "recorded_at=",
        "foundation_now=",
        "ahead_seconds=",
        "tolerance_seconds=5",
    ] {
        assert_eq!(logs.matches(field).count(), 3);
    }
    assert!(!logs.contains(SECRET));
    assert!(!logs.contains(&general_purpose::STANDARD.encode(SECRET)));
}

#[tokio::test]
async fn signed_attempt_time_closed_log_sink_preserves_permit_and_dispatch() {
    executable_dispatch(None, None, Some((3600, 5, true))).await;
}

#[tokio::test]
async fn signed_attempt_time_warning_tolerance_defaults_to_five_seconds() {
    let fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    let mut value = serde_json::to_value(&fixture.config).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("clock_rollback_warning_tolerance_seconds");
    let config: ProcessConfig = serde_json::from_value(value).unwrap();
    assert_eq!(config.clock_rollback_warning_tolerance_seconds, 5);
}

async fn executable_dispatch(
    proxy: Option<&str>,
    numeric_cost: Option<&'static str>,
    clock_case: Option<(u64, u64, bool)>,
) -> String {
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
    let mut fixture = Fixture::with_cost(
        200,
        "process answer".into(),
        Duration::ZERO,
        numeric_cost.unwrap_or(r#""0.00001234567890123456789""#),
    )
    .await;
    if let Some((_, tolerance_seconds, _)) = clock_case {
        fixture.config.clock_rollback_warning_tolerance_seconds = tolerance_seconds;
    }
    let config_path = fixture.dir.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&fixture.config).unwrap()).unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut command = std::process::Command::new(credential_process());
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
    if matches!(clock_case, Some((_, _, true))) {
        // Closing the reader makes stderr writes fail with BrokenPipe.
        drop(child.0.stderr.take());
    }
    let client = socket::UnixEgressClient {
        path: fixture.config.socket_path.clone(),
        max_frame_bytes: fixture.config.max_frame_bytes,
        timeout: Duration::from_secs(3),
    };
    let (mut admission, payload) = fixture.attempt("executable", 1, 1);
    if let Some((ahead_seconds, _, _)) = clock_case {
        admission.attempt.recorded_at = unix_seconds() + ahead_seconds;
        admission.attempt.expires_at = admission.attempt.recorded_at + 3600;
        admission = AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_attempt(admission.attempt)
            .unwrap();
    }
    let signed_id = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt_id(admission.attempt.attempt_id())
        .unwrap();
    assert!(matches!(
        ready_status(&mut child, &client, &signed_id).await,
        AttemptStatus::NotIssued
    ));
    assert!(matches!(
        client
            .exchange(Request {
                version: PROTOCOL_VERSION,
                operation: publish_revision(1),
            })
            .await
            .unwrap()
            .result
            .unwrap(),
        Reply::GrantRevisionPublished
    ));
    // Never read the permit reply. Observe its commit via a separate connection
    // before dropping it, so this proves loss after commit rather than before accept.
    let lost_permit_reply =
        send_without_reading(&client, Operation::IssuePermit(admission.clone().into())).await;
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
            operation: Operation::IssuePermit(admission.clone().into()),
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
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let mut logs = String::new();
    if let Some(mut stderr) = child.0.stderr.take() {
        use std::io::Read;
        stderr.read_to_string(&mut logs).unwrap();
    }
    drop(child);
    // SIGKILL leaves the socket behind: restart must remove it under the state lock.
    assert!(fixture.config.socket_path.exists());
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
    logs
}

#[tokio::test]
async fn embeddings_share_attempt_binding_and_credential_boundary() {
    let mut fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    fixture.config.routes[0].provider = RouteProvider::GeminiEmbedding { dimensions: 8 };
    fixture.config.routes[0].destination =
        "https://generativelanguage.googleapis.com/v1beta".into();
    fixture.config.routes[0].model = "gemini-embedding-001".into();
    let process = fixture.process().await;
    std::fs::remove_file(fixture.dir.path().join("provider")).unwrap();
    let (mut admission, _) = fixture.attempt("embedding", 1, 1);
    let payload = ProviderPayload::Embedding(EmbeddingRequest {
        inputs: vec!["incoming input without a stored revision".into()],
        dimensions: Some(8),
        task: None,
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
    let process = fixture.process().await;
    std::fs::remove_file(fixture.dir.path().join("provider")).unwrap();
    for ordinal in 1..=3 {
        let (admission, payload) = fixture.attempt("zero-charge", ordinal, u64::from(ordinal));
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
        assert_eq!(result.receipt.spend_state, SpendState::Released);
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let (fourth, _) = fixture.attempt("zero-charge", 4, 4);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(fourth.into())).await,
        Err(EgressError::BudgetRefused)
    ));
    assert_eq!(ledger_totals(&fixture), (0, 3));
}

#[tokio::test]
async fn expanded_gemini_wire_payload_is_refused_before_consumption() {
    expanded_wire_payload_is_refused(0).await;
}

#[tokio::test]
async fn expanded_chat_wire_payload_is_refused_before_consumption() {
    expanded_wire_payload_is_refused(1).await;
}

async fn expanded_wire_payload_is_refused(adapter: u8) {
    let mut fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    fixture.config.routes[0].max_input_bytes = 1024;
    let payload = if adapter == 0 {
        fixture.config.routes[0].provider = RouteProvider::GeminiEmbedding { dimensions: 8 };
        fixture.config.routes[0].destination =
            "https://generativelanguage.googleapis.com/v1beta".into();
        fixture.config.routes[0].model = "gemini-embedding-001".into();
        ProviderPayload::Embedding(EmbeddingRequest {
            inputs: vec!["x".into(); 128],
            dimensions: Some(8),
            task: None,
            role_binding: None,
            source: None,
            metadata: serde_json::Value::Null,
        })
    } else {
        if adapter == 2 {
            fixture.config.routes[0].provider = RouteProvider::AnthropicChat {
                operator: "anthropic".into(),
                thinking: Some(symbiotic_ai_runtime::model::ThinkingMode::Enabled),
            };
        }
        // The configured model is absent from the typed payload but present on the wire.
        fixture.config.routes[0].model = "m".repeat(1024);
        fixture.attempt("wire-limit", 1, 1).1
    };
    assert!(serde_json::to_vec(&payload).unwrap().len() < 1024);
    let process = fixture.process().await;
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
        "oversized wire body accepted (adapter={adapter})"
    );
    assert!(matches!(
        exchange(&process, Operation::Receipt(signed_id(&admission))).await,
        Ok(Reply::Receipt(None))
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn zero_request_pacing_is_refused_at_route_validation() {
    let mut fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    fixture.config.routes[0].requests_per_minute = Some(0);
    assert!(matches!(
        CredentialProcess::open(fixture.config.clone()),
        Err(EgressError::InvalidRequest)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture.config.routes[0].requests_per_minute = None;
    assert!(CredentialProcess::open(fixture.config).is_ok());
}

#[tokio::test]
async fn zero_input_pacing_is_refused_at_route_validation() {
    let mut fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    fixture.config.routes[0].input_units_per_minute = Some(0);
    assert!(matches!(
        CredentialProcess::open(fixture.config.clone()),
        Err(EgressError::InvalidRequest)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture.config.routes[0].input_units_per_minute = None;
    assert!(CredentialProcess::open(fixture.config).is_ok());
}

#[tokio::test]
async fn runtime_bookkeeping_failure_retains_paid_output_and_safe_diagnostic() {
    let fixture = Fixture::new(200, "paid answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let db = rusqlite::Connection::open(fixture.config.state_dir.join("queue.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER refuse_completion BEFORE UPDATE OF status ON queue_items
        WHEN NEW.status = 'succeeded'
        BEGIN SELECT RAISE(FAIL, 'private bookkeeping failure'); END;",
    )
    .unwrap();
    let (admission, payload) = fixture.attempt("completion-failure", 1, 1);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission.clone(), payload, granted))
            .await
            .unwrap(),
    );
    let wire = serde_json::to_value(&result).unwrap();
    assert_eq!(
        wire["diagnostics"],
        serde_json::json!(["queue_complete_failed"])
    );
    assert!(!wire.to_string().contains("private bookkeeping failure"));
    assert!(!wire.to_string().contains(SECRET));
    assert_eq!(result.error, None);
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    assert!(result.receipt_persisted);
    assert!(matches!(result.output, Some(ProviderOutput::Chat { text }) if text == "paid answer"));
    assert_eq!(result.receipt.usage.input_tokens, Some(7));
    assert_eq!(result.receipt.usage.output_tokens, Some(3));
    assert_eq!(result.receipt.spend_state, SpendState::Settled);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    drop(process);
    let process = fixture.process().await;
    let AttemptStatus::Completed { result } = status(&process, &admission).await else {
        panic!("missing completed result");
    };
    assert_eq!(serde_json::to_value(result).unwrap(), wire);
}

#[tokio::test]
async fn conflicting_shared_route_limits_are_refused_at_startup() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    for field in ["concurrency", "requests", "input"] {
        let mut config = fixture.config.clone();
        config.routes[0].account_sharing_key =
            Some(symbiotic_ai_runtime::AccountSharingKey::new("shared"));
        let mut second = config.routes[0].clone();
        second.route = "second-route".into();
        second.tenant = "other-tenant".into();
        match field {
            "concurrency" => second.max_in_flight += 1,
            "requests" => second.requests_per_minute = Some(60),
            _ => second.input_units_per_minute = Some(1000),
        }
        config.routes.push(second);
        let opened = CredentialProcess::open(config);
        assert!(
            matches!(&opened, Err(EgressError::InvalidRequest)),
            "{field}: unexpected startup result {:?}",
            opened.err()
        );
    }
    let mut config = fixture.config.clone();
    let mut second = config.routes[0].clone();
    second.route = "same-limits".into();
    config.routes.push(second);
    assert!(CredentialProcess::open(config).is_ok());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn conflicting_shared_route_limits_are_validated_before_state_in_every_order() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let unopened = fixture.dir.path().join("unopened-state");
    let blocked = fixture.dir.path().join("state-is-a-file");
    std::fs::write(&blocked, b"untouched").unwrap();

    // Exhaust all 24 permutations of four routes, including two unrelated
    // account groups that must not hide the conflicting pair.
    let mut orders = vec![Vec::new()];
    for index in 0..4 {
        orders = orders
            .into_iter()
            .flat_map(|order| {
                (0..=order.len()).map(move |position| {
                    let mut next = order.clone();
                    next.insert(position, index);
                    next
                })
            })
            .collect();
    }
    assert_eq!(orders.len(), 24);
    for explicitly_shared in [false, true] {
        for field in ["concurrency", "requests", "input"] {
            // Cover both unrestricted-versus-paced and two distinct paced limits.
            for already_paced in [false, true] {
                let mut first = fixture.config.routes[0].clone();
                if explicitly_shared {
                    first.account_sharing_key =
                        Some(symbiotic_ai_runtime::AccountSharingKey::new("shared"));
                }
                if already_paced {
                    first.requests_per_minute = Some(30);
                    first.input_units_per_minute = Some(500);
                }
                let mut second = first.clone();
                second.route = "conflicting-route".into();
                if explicitly_shared {
                    second.tenant = "other-tenant".into();
                    second.account = "other-account".into();
                }
                match field {
                    "concurrency" => second.max_in_flight += 1,
                    "requests" => second.requests_per_minute = Some(60),
                    _ => second.input_units_per_minute = Some(1000),
                }
                let mut independent = first.clone();
                independent.route = "independent-route".into();
                independent.account = "independent-account".into();
                independent.account_sharing_key = None;
                let mut other_pool = first.clone();
                other_pool.route = "other-pool-route".into();
                other_pool.account_sharing_key =
                    Some(symbiotic_ai_runtime::AccountSharingKey::new("other-pool"));
                let routes = [first, second, independent, other_pool];
                for order in &orders {
                    // Rebuilding the registry also varies its HashMaps' random seeds.
                    for state_dir in [&fixture.config.state_dir, &unopened, &blocked] {
                        let mut config = fixture.config.clone();
                        config.routes = order.iter().map(|&i| routes[i].clone()).collect();
                        config.state_dir = state_dir.clone();
                        let opened = CredentialProcess::open(config);
                        assert!(
                            matches!(&opened, Err(EgressError::InvalidRequest)),
                            "{field}, shared={explicitly_shared}, paced={already_paced}, \
                             order={order:?}, state={state_dir:?}: {:?}",
                            opened.err()
                        );
                        assert!(!unopened.exists(), "invalid routes created state");
                        assert_eq!(std::fs::read(&blocked).unwrap(), b"untouched");
                    }
                }
            }
        }
    }
    // Valid configuration still reports actual lock/IO failures as state errors.
    assert!(matches!(
        CredentialProcess::open(fixture.config.clone()),
        Err(EgressError::StateUnavailable)
    ));
    let mut config = fixture.config.clone();
    config.state_dir = blocked;
    assert!(matches!(
        CredentialProcess::open(config),
        Err(EgressError::StateUnavailable)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    drop(process);
}

#[tokio::test]
async fn failure_before_dispatch_returns_safe_error_and_releases_reservation() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
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
    assert_eq!(result.receipt.spend_state, SpendState::Released);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    drop(process);
    db.execute_batch("DROP TRIGGER refuse_queue").unwrap();
    let process = fixture.process().await;
    let stored = exchange(&process, Operation::Receipt(signed_id(&first)))
        .await
        .unwrap();
    assert!(matches!(
        stored,
        Reply::Receipt(Some(DispatchReceipt {
            spend_state: SpendState::Released,
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
    let process = fixture.process().await;
    let (admission, payload) = fixture.attempt("lost-permit", 1, 10);
    let committed = permit(&process, &admission).await;
    drop(process);
    let process = fixture.process().await;
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
    let process = fixture.process().await;
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
    assert!(matches!(result.receipt.spend_state, SpendState::Settled));
    drop(process);
    let process = fixture.process().await;
    let AttemptStatus::Completed { result: recovered } = status(&process, &admission).await else {
        panic!("missing result");
    };
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(recovered).unwrap()
    );
    let Reply::Permit(reattached) = exchange(&process, Operation::IssuePermit(admission.into()))
        .await
        .unwrap()
    else {
        panic!("missing permit");
    };
    assert_eq!(reattached.permit.token, granted.token);
    assert!(matches!(reattached.status, AttemptStatus::Completed { .. }));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger_totals(&fixture), (1, 1));
}

#[tokio::test]
async fn recovery_same_identity_with_different_signed_digest_is_refused() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let (admission, _) = fixture.attempt("digest-mismatch", 1, 10);
    permit(&process, &admission).await;
    let key = AdmissionKey::new(KEY.to_vec()).unwrap();
    for field in 0..4 {
        let mut changed = admission.attempt.clone();
        match field {
            0 => changed.record_sequence += 1,
            1 => changed.input_digest = "c".repeat(64),
            2 => changed.recovery_expires_at += 1,
            _ => changed.expires_at += 1,
        }
        assert!(matches!(
            exchange(
                &process,
                Operation::IssuePermit(key.sign_attempt(changed).unwrap().into())
            )
            .await,
            Err(EgressError::InvalidRequest)
        ));
    }
    let mut signed_id = key.sign_attempt_id(admission.attempt.attempt_id()).unwrap();
    signed_id.attempt_id.tenant = "other".into();
    assert!(matches!(
        exchange(&process, Operation::AttemptStatus(signed_id.clone())).await,
        Err(EgressError::Unauthorized)
    ));
    assert!(matches!(
        exchange(&process, Operation::Receipt(signed_id)).await,
        Err(EgressError::Unauthorized)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn recovery_failed_status_preserves_safe_error_and_charge() {
    let fixture = Fixture::new(500, SECRET.into(), Duration::ZERO).await;
    let process = fixture.process().await;
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
    assert!(matches!(result.receipt.spend_state, SpendState::Unknown));
    assert!(!serde_json::to_string(&result).unwrap().contains(SECRET));
}

#[tokio::test]
async fn recovery_expired_status_does_not_retain_late_completion() {
    let fixture = Fixture::new(200, "expired answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
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
    let process = fixture.process().await;
    assert!(matches!(
        status(&process, &admission).await,
        AttemptStatus::Expired
    ));
    assert!(matches!(
        exchange(&process, Operation::Receipt(signed_id(&admission)))
            .await
            .unwrap(),
        Reply::Receipt(Some(_))
    ));
    let Reply::Permit(grant) = exchange(&process, Operation::IssuePermit(admission.into()))
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
    let process = fixture.process().await;
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
    let process = fixture.process().await;
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
        operation: Operation::IssuePermit(admission.into()),
    };
    assert!(matches!(
        InProcessEgressClient::new(process.clone())
            .exchange(request)
            .await
            .unwrap()
            .result,
        Err(EgressError::Version)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn recovery_disconnected_peer_does_not_stop_socket_server() {
    let fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    let process = fixture.process().await;
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

#[tokio::test]
async fn independent_tenant_routes_accept_different_account_policies() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let mut config = fixture.config.clone();
    let mut second = config.routes[0].clone();
    second.tenant = "other-tenant".into();
    second.max_in_flight = 1;
    second.requests_per_minute = Some(60);
    config.routes.push(second);
    assert!(CredentialProcess::open(config).is_ok());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

fn ledger_totals(fixture: &Fixture) -> (u64, u64) {
    let conn = rusqlite::Connection::open(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
    )
    .unwrap();
    (
        conn.query_row(
            "SELECT coalesce(sum(used), 0) FROM spend_accounts",
            [],
            |r| r.get(0),
        )
        .unwrap(),
        conn.query_row("SELECT count(*) FROM spend_receipts", [], |r| r.get(0))
            .unwrap(),
    )
}

#[tokio::test]
async fn spend_concurrent_dispatches_on_one_account_share_one_durable_budget() {
    let mut fixture = Fixture::new(200, "answer".into(), Duration::from_millis(30)).await;
    fixture.config.routes[0].provider_request_limit = Some(1);
    let process = fixture.process().await;
    let (a, pa) = fixture.attempt("first-account-call", 1, 1);
    let (b, pb) = fixture.attempt("second-account-call", 1, 2);
    let ap = permit(&process, &a).await;
    let bp = permit(&process, &b).await;
    let (ra, rb) = tokio::join!(
        exchange(&process, inject(a, pa, ap)),
        exchange(&process, inject(b, pb, bp))
    );
    assert_eq!([&ra, &rb].iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        [&ra, &rb]
            .iter()
            .filter(|r| matches!(r, Err(EgressError::BudgetRefused)))
            .count(),
        1
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger_totals(&fixture), (1, 1));
}

#[tokio::test]
async fn retrieval_dispatch_supports_keyless_permits_and_one_provider_request() {
    use symbiotic_ai_runtime::model::{ModelAdapter, RerankRequest};
    for adapter in [
        ModelAdapter::OpenAiEmbedding,
        ModelAdapter::OllamaEmbedding,
        ModelAdapter::CohereRerank,
    ] {
        for keyless in [false, true] {
            for measured_usage in [false, true] {
                let rerank = adapter == ModelAdapter::CohereRerank;
                let body = match adapter {
                    ModelAdapter::CohereRerank => {
                        r#"{"results":[{"index":0,"relevance_score":0.8}]}"#
                    }
                    ModelAdapter::OllamaEmbedding => r#"{"embedding":[1,2]}"#,
                    _ => r#"{"data":[{"index":0,"embedding":[1,2]}]}"#,
                };
                let mut body: serde_json::Value = serde_json::from_str(body).unwrap();
                if measured_usage {
                    body["usage"] = serde_json::json!({"cost": "0.001"});
                }
                let mut fixture = Fixture::with_http_response(
                    200,
                    body.to_string(),
                    Duration::ZERO,
                    "null",
                    true,
                    keyless,
                )
                .await;
                let route = &mut fixture.config.routes[0];
                route.provider_request_limit = Some(1);
                if keyless {
                    route.secret = SecretSource::None;
                    route.secret_ref.clear();
                }
                route.provider = if rerank {
                    RouteProvider::CohereRerank {
                        operator: "test".into(),
                        rerank_input_bytes: 64,
                        rerank_candidates: 2,
                        rerank_context_tokens: 16,
                        rerank_query_tokens: 8,
                    }
                } else {
                    RouteProvider::CompatibleEmbedding {
                        adapter,
                        operator: "test".into(),
                        dimensions: 2,
                        embedding_full_dimensions: 1024,
                        embedding_input_tokens: 16,
                    }
                };
                if !rerank {
                    let mut collision = fixture.config.clone();
                    let mut other = collision.routes[0].clone();
                    other.route = "other".into();
                    if let RouteProvider::CompatibleEmbedding { adapter, .. } = &mut other.provider
                    {
                        *adapter = if *adapter == ModelAdapter::OpenAiEmbedding {
                            ModelAdapter::OllamaEmbedding
                        } else {
                            ModelAdapter::OpenAiEmbedding
                        };
                    }
                    collision.routes.push(other);
                    assert!(CredentialProcess::open(collision).is_err());
                }
                let process = fixture.process().await;
                let (admission, _) = fixture.attempt("retrieval", 1, 10);
                let payload = if rerank {
                    ProviderPayload::Rerank(RerankRequest {
                        query: "query".into(),
                        documents: vec!["candidate".into()],
                        top_k: Some(1),
                        role_binding: None,
                        source: None,
                        metadata: serde_json::Value::Null,
                    })
                } else {
                    ProviderPayload::Embedding(EmbeddingRequest {
                        inputs: vec!["input".into()],
                        dimensions: Some(2),
                        task: None,
                        role_binding: None,
                        source: None,
                        metadata: serde_json::Value::Null,
                    })
                };
                let mut attempt = admission.attempt;
                {
                    let mut oversized = payload.clone();
                    match &mut oversized {
                        ProviderPayload::Rerank(request) => request.documents[0] = "x".repeat(17),
                        ProviderPayload::Embedding(request) => request.inputs[0] = "x".repeat(17),
                        _ => unreachable!(),
                    }
                    let (oversized_admission, _) =
                        fixture.attempt("retrieval-over-capacity", 1, 10);
                    let mut oversized_attempt = oversized_admission.attempt;
                    oversized_attempt.input_digest = oversized.digest().unwrap();
                    let oversized_admission = AdmissionKey::new(KEY.to_vec())
                        .unwrap()
                        .sign_attempt(oversized_attempt)
                        .unwrap();
                    let oversized_permit = permit(&process, &oversized_admission).await;
                    assert!(matches!(
                        exchange(
                            &process,
                            inject(oversized_admission.clone(), oversized, oversized_permit)
                        )
                        .await,
                        Err(EgressError::LimitExceeded)
                    ));
                    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
                    assert_eq!(ledger_totals(&fixture), (0, 0));
                    assert!(matches!(
                        status(&process, &oversized_admission).await,
                        AttemptStatus::Permitted
                    ));
                }
                attempt.input_digest = payload.digest().unwrap();
                let admission = AdmissionKey::new(KEY.to_vec())
                    .unwrap()
                    .sign_attempt(attempt)
                    .unwrap();
                let token = permit(&process, &admission).await;
                let operation = inject(admission.clone(), payload.clone(), token);
                let result = dispatched(exchange(&process, operation.clone()).await.unwrap());
                assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
                assert_eq!(
                    result.receipt.spend_state,
                    if measured_usage {
                        SpendState::Settled
                    } else {
                        SpendState::Unknown
                    }
                );
                assert!(result.error.is_none());
                assert!(result.output.is_some());
                assert!(result.receipt_persisted);
                let encoded = serde_json::to_string(&result).unwrap();
                serde_json::from_str::<DispatchResult>(&encoded).unwrap_or_else(|error| {
                    panic!(
                        "{adapter:?}, keyless={keyless}, measured_usage={measured_usage}: {error}"
                    )
                });
                assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
                assert!(exchange(&process, operation).await.is_err());
                assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
                assert_eq!(ledger_totals(&fixture), (1, 1));
                let ledger = symbiotic_ai_runtime::spend::SqliteSpendLedger::open(
                    &fixture
                        .config
                        .state_dir
                        .join(symbiotic_ai_runtime::QUEUE_DATABASE),
                )
                .unwrap();
                use symbiotic_ai_runtime::model::SpendLedger;
                let canonical = ledger.receipt(&result.receipt.reference).unwrap().unwrap();
                assert_eq!(
                    canonical.state,
                    if measured_usage {
                        symbiotic_ai_runtime::SpendState::Settled
                    } else {
                        symbiotic_ai_runtime::SpendState::Unknown
                    }
                );
                let mut next_attempt = admission.attempt.clone();
                next_attempt.invocation_id = "retrieval-next".into();
                let next = AdmissionKey::new(KEY.to_vec())
                    .unwrap()
                    .sign_attempt(next_attempt)
                    .unwrap();
                let next_permit = permit(&process, &next).await;
                assert!(matches!(
                    exchange(&process, inject(next, payload, next_permit)).await,
                    Err(EgressError::BudgetRefused)
                ));
                assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
                assert_eq!(ledger_totals(&fixture), (1, 1));
                drop(process);
                let reopened = fixture.process().await;
                let AttemptStatus::Completed { result: recovered } =
                    status(&reopened, &admission).await
                else {
                    panic!("retrieval completion missing after restart");
                };
                assert_eq!(
                    serde_json::to_value(&result).unwrap(),
                    serde_json::to_value(recovered).unwrap()
                );
                assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
                assert!(!serde_json::to_string(&result).unwrap().contains(SECRET));
            }
        }
    }
}

#[tokio::test]
async fn grant_revocation_preserves_accepted_handoff_and_accounting() {
    let fixture = Fixture::new(200, "accepted answer".into(), Duration::from_millis(250)).await;
    let process = fixture.process().await;
    let (admission, payload) = fixture.attempt("accepted-before-revocation", 1, 10);
    let granted = permit(&process, &admission).await;
    let operation = inject(admission.clone(), payload, granted);
    let worker = process.clone();
    let task = tokio::spawn(async move { dispatched(exchange(&worker, operation).await.unwrap()) });
    let retained = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let AttemptStatus::Dispatched { receipt } = status(&process, &admission).await {
                break receipt;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(retained.attempt_id, admission.attempt.attempt_id());
    assert_eq!(retained.spend_state, SpendState::Unknown);
    revoke(&process, 11).await;
    let result = task.await.unwrap();
    assert_eq!(result.receipt.reference, retained.reference);
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    assert_eq!(result.receipt.spend_state, SpendState::Settled);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger_totals(&fixture), (1, 1));
    drop(process);
    let process = fixture.process().await;
    let AttemptStatus::Completed { result: recovered } = status(&process, &admission).await else {
        panic!("accepted handoff lost after revision change");
    };
    assert_eq!(recovered.receipt.reference, retained.reference);
    let Reply::Receipt(Some(receipt)) =
        exchange(&process, Operation::Receipt(signed_id(&admission)))
            .await
            .unwrap()
    else {
        panic!("accepted receipt lost");
    };
    assert_eq!(receipt.reference, retained.reference);
    assert_eq!(receipt.spend_state, SpendState::Settled);
    assert_eq!(ledger_totals(&fixture), (1, 1));
}

#[tokio::test]
async fn grant_revision_requires_authenticated_initial_publication() {
    let fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    let process = CredentialProcess::open(fixture.config.clone()).unwrap();
    let (admission, _) = fixture.attempt("no-publication", 1, 10);
    assert!(matches!(
        exchange(&process, Operation::IssuePermit(admission.clone().into())).await,
        Err(EgressError::RouteRefused)
    ));
    let Operation::PublishGrantRevision(mut signed) = publish_revision(1) else {
        unreachable!()
    };
    signed.grant.revision = 2;
    assert!(matches!(
        exchange(&process, Operation::PublishGrantRevision(signed)).await,
        Err(EgressError::Unauthorized)
    ));
    revoke(&process, 1).await;
    revoke(&process, 1).await;
    permit(&process, &admission).await;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger_totals(&fixture), (0, 0));
}

#[tokio::test]
async fn failed_settlement_keeps_typed_receipt_unknown_and_preserves_paid_output() {
    let fixture = Fixture::new(200, "paid answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let (admission, payload) = fixture.attempt("failed-settlement", 1, 10);
    let permit = permit(&process, &admission).await;
    let conn = rusqlite::Connection::open(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
    )
    .unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_completion BEFORE UPDATE OF finished ON egress_permits
        BEGIN SELECT RAISE(ABORT, 'synthetic completion failure'); END;",
    )
    .unwrap();
    let operation = inject(admission.clone(), payload, permit);
    let result = dispatched(exchange(&process, operation.clone()).await.unwrap());
    assert!(result.output.is_some());
    assert_eq!(result.receipt.usage.input_tokens, Some(7));
    assert!(!result.receipt_persisted);
    assert_eq!(result.receipt.spend_state, SpendState::Unknown);
    assert_eq!(ledger_totals(&fixture), (1, 1));
    let reference = result.receipt.reference;
    drop(conn);
    drop(process);
    let process = fixture.process().await;
    let AttemptStatus::Dispatched { receipt } = status(&process, &admission).await else {
        panic!("failed settlement lost its accepted receipt");
    };
    assert_eq!(receipt.reference, reference);
    assert_eq!(receipt.spend_state, SpendState::Unknown);
    assert!(matches!(
        exchange(&process, operation).await,
        Err(EgressError::PermitRefused)
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger_totals(&fixture), (1, 1));
}

#[tokio::test]
async fn frame_config_refuses_identity_fields_that_cannot_fit_with_the_response() {
    let mut fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let response_bytes = fixture.config.routes[0].max_response_bytes;
    let largest_field = (fixture.config.max_frame_bytes as usize - 4096 - 4 * response_bytes) / 18;
    fixture.config.routes[0].max_field_bytes = largest_field;
    let process = CredentialProcess::open(fixture.config.clone()).unwrap();
    drop(process);
    for field_bytes in [
        largest_field + 1,
        fixture.config.max_frame_bytes as usize,
        usize::MAX,
    ] {
        fixture.config.routes[0].max_field_bytes = field_bytes;
        let error = CredentialProcess::open(fixture.config.clone())
            .err()
            .expect("oversized route must be refused");
        for setting in ["max_frame_bytes", "max_field_bytes", "max_response_bytes"] {
            assert!(
                error.to_string().contains(setting),
                "missing {setting}: {error}"
            );
        }
    }
    fixture.config.routes[0].max_field_bytes = 1;
    fixture.config.routes[0].max_response_bytes = 1;
    fixture.config.routes[0].max_input_bytes = 1;
    for frame_bytes in [4096, 4117] {
        fixture.config.max_frame_bytes = frame_bytes;
        let error = CredentialProcess::open(fixture.config.clone())
            .err()
            .expect("frame must fit envelope and one field");
        assert!(error.to_string().contains("max_frame_bytes"));
    }
    fixture.config.max_frame_bytes = 4118;
    CredentialProcess::open(fixture.config.clone()).unwrap();
}

#[tokio::test]
async fn supervision_socket_recovery_preserves_live_owner_and_non_socket_paths() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let listener = server::bind(&process).unwrap();
    assert!(
        server::bind(&process).is_err(),
        "a clone must not unlink its own live listener"
    );
    assert!(matches!(
        CredentialProcess::open(fixture.config.clone()),
        Err(EgressError::StateUnavailable)
    ));
    let mut other_config = fixture.config.clone();
    other_config.state_dir = fixture.dir.path().join("other-state");
    let other = CredentialProcess::open(other_config).unwrap();
    assert!(
        server::bind(&other).is_err(),
        "another state lock must not authorize unlinking an active listener"
    );
    drop(other);
    let task = tokio::spawn(server::serve(process, listener));
    let client = socket::UnixEgressClient {
        path: fixture.config.socket_path.clone(),
        max_frame_bytes: fixture.config.max_frame_bytes,
        timeout: Duration::from_secs(2),
    };
    let (admission, _) = fixture.attempt("readiness", 1, 1);
    let id = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt_id(admission.attempt.attempt_id())
        .unwrap();
    assert!(matches!(
        client.attempt_status(id).await.unwrap(),
        AttemptStatus::NotIssued
    ));
    task.abort();
    let _ = task.await;
    let process = CredentialProcess::open(fixture.config.clone()).unwrap();
    std::fs::remove_file(&fixture.config.socket_path).unwrap();
    std::fs::write(&fixture.config.socket_path, b"keep").unwrap();
    assert!(server::bind(&process).is_err());
    assert_eq!(std::fs::read(&fixture.config.socket_path).unwrap(), b"keep");
    std::fs::remove_file(&fixture.config.socket_path).unwrap();
    std::os::unix::fs::symlink(
        fixture.dir.path().join("admission"),
        &fixture.config.socket_path,
    )
    .unwrap();
    assert!(server::bind(&process).is_err());
    assert!(
        std::fs::symlink_metadata(&fixture.config.socket_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

fn supervision_policy() -> symbiotic_supervise::Policy {
    symbiotic_supervise::Policy {
        version: 1,
        max_restarts: 2,
        crash_window_ms: 10_000,
        backoff_ms: 10,
        stop_grace_ms: 100,
        poll_ms: 5,
    }
}

#[test]
fn supervised_credential_parent_entrypoint() {
    let Some(config) = std::env::var_os("CREDENTIAL_PARENT_CONFIG") else {
        return;
    };
    let pid_path = std::env::var_os("CREDENTIAL_CHILD_PID").unwrap();
    let supervisor = symbiotic_supervise::Supervisor::start(
        move || {
            let mut command = std::process::Command::new(credential_process());
            command.arg("--child").arg(&config);
            command
        },
        supervision_policy(),
    )
    .unwrap();
    let symbiotic_supervise::Event::Started(pid) = supervisor.next_event().unwrap() else {
        panic!("expected child");
    };
    std::fs::write(pid_path, pid.to_string()).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[tokio::test]
async fn supervision_credential_child_exits_when_app_is_killed() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let config = fixture.dir.path().join("config.json");
    std::fs::write(&config, serde_json::to_vec(&fixture.config).unwrap()).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pid_path = fixture.dir.path().join("child.pid");
    let mut parent = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "supervised_credential_parent_entrypoint",
                "--nocapture",
            ])
            .env("CREDENTIAL_PARENT_CONFIG", &config)
            .env("CREDENTIAL_CHILD_PID", &pid_path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = socket::UnixEgressClient {
        path: fixture.config.socket_path.clone(),
        max_frame_bytes: fixture.config.max_frame_bytes,
        timeout: Duration::from_secs(2),
    };
    let (attempt, _) = fixture.attempt("child-ready", 1, 1);
    let id = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt_id(attempt.attempt.attempt_id())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client.attempt_status(id.clone()).await {
                Ok(AttemptStatus::NotIssued) => break,
                Err(EgressError::Transport) => tokio::time::sleep(Duration::from_millis(5)).await,
                _ => panic!("readiness refused"),
            }
        }
    })
    .await
    .unwrap();
    let pid: u32 = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
    parent.0.kill().unwrap();
    parent.0.wait().unwrap();
    // Lock release, rather than PID disappearance, also works with Linux orphan zombies.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(process) = CredentialProcess::open(fixture.config.clone()) {
                assert!(server::bind(&process).is_ok());
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    // SAFETY: signal 0 checks only; on Linux the exited child may await PID 1's reap.
    #[cfg(not(target_os = "linux"))]
    assert_ne!(unsafe { libc::kill(pid as i32, 0) }, 0);
    #[cfg(target_os = "linux")]
    let _ = pid;
}

#[test]
fn supervision_child_mode_requires_parent_pipe_before_configuration() {
    let output = std::process::Command::new(credential_process())
        .args(["--child", "/nonexistent-config"])
        .env_remove("SYMBIOTIC_PARENT_FD")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        EgressError::StateUnavailable.to_string()
    );
}

#[tokio::test]
async fn supervised_engine_entrypoint() {
    let Some(dir) = std::env::var_os("SUPERVISED_ENGINE_DIR") else {
        return;
    };
    symbiotic_supervise::watch_parent(|| Ok(())).unwrap();
    let dir = std::path::PathBuf::from(dir);
    let id: SignedAttemptId =
        serde_json::from_slice(&std::fs::read(dir.join("status.json")).unwrap()).unwrap();
    let client = socket::UnixEgressClient {
        path: dir.join("egress.sock"),
        max_frame_bytes: 262144,
        timeout: Duration::from_secs(2),
    };
    std::fs::write(dir.join("engine.ready"), "ready").unwrap();
    loop {
        match client.attempt_status(id.clone()).await.unwrap() {
            AttemptStatus::Completed { result } => {
                std::fs::write(
                    dir.join("engine.result.pending"),
                    serde_json::to_vec(&result).unwrap(),
                )
                .unwrap();
                std::fs::rename(dir.join("engine.result.pending"), dir.join("engine.result"))
                    .unwrap();
                std::future::pending::<()>().await;
            }
            AttemptStatus::NotIssued
            | AttemptStatus::Permitted
            | AttemptStatus::Dispatched { .. } => {}
            _ => panic!("unexpected engine recovery state"),
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn supervision_engine_restart_consumes_saved_completion_without_second_payment() {
    let response_gate = Arc::new(tokio::sync::Semaphore::new(0));
    let fixture = Fixture::with_response_gate(
        200,
        "saved completion".into(),
        Duration::ZERO,
        r#""0.00001234567890123456789""#,
        false,
        false,
        Some(response_gate.clone()),
    )
    .await;
    let process = fixture.process().await;
    let listener = server::bind(&process).unwrap();
    let task = tokio::spawn(server::serve(process, listener));
    let client = socket::UnixEgressClient {
        path: fixture.config.socket_path.clone(),
        max_frame_bytes: fixture.config.max_frame_bytes,
        timeout: Duration::from_secs(2),
    };
    let (admission, payload) = fixture.attempt("engine-restart", 1, 1);
    let id = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt_id(admission.attempt.attempt_id())
        .unwrap();
    std::fs::write(
        fixture.dir.path().join("status.json"),
        serde_json::to_vec(&id).unwrap(),
    )
    .unwrap();
    let dir = fixture.dir.path().to_owned();
    let supervisor = symbiotic_supervise::Supervisor::start(
        move || {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "supervised_engine_entrypoint", "--nocapture"])
                .env("SUPERVISED_ENGINE_DIR", &dir)
                .stdout(std::process::Stdio::null());
            command
        },
        supervision_policy(),
    )
    .unwrap();
    let symbiotic_supervise::Event::Started(first_pid) = supervisor.next_event().unwrap() else {
        panic!("missing engine");
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fixture.dir.path().join("engine.ready").exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let response = client
        .exchange(Request {
            version: PROTOCOL_VERSION,
            operation: Operation::IssuePermit(admission.clone().into()),
        })
        .await
        .unwrap();
    let Reply::Permit(grant) = response.result.unwrap() else {
        panic!("missing permit");
    };
    let dispatch_client = client.clone();
    let dispatch = tokio::spawn(async move {
        dispatch_client
            .exchange(Request {
                version: PROTOCOL_VERSION,
                operation: inject(admission, payload, grant.permit),
            })
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        !dispatch.is_finished(),
        "engine crash must occur during the paid call"
    );
    // SAFETY: the supervisor still owns this child; SIGKILL models a native engine fault.
    assert_eq!(unsafe { libc::kill(first_pid as i32, libc::SIGKILL) }, 0);
    assert!(matches!(
        supervisor.next_event().unwrap(),
        symbiotic_supervise::Event::Exited(_)
    ));
    assert!(
        !fixture.dir.path().join("engine.result").exists(),
        "first engine cannot consume a gated response"
    );
    assert!(
        !dispatch.is_finished(),
        "paid call must remain pending until the first engine is reaped"
    );
    response_gate.add_permits(1);
    let symbiotic_supervise::Event::Started(second_pid) = supervisor.next_event().unwrap() else {
        panic!("engine not restarted");
    };
    assert_ne!(first_pid, second_pid);
    let result = dispatched(dispatch.await.unwrap().result.unwrap());
    assert!(
        matches!(&result.output, Some(ProviderOutput::Chat { text }) if text == "saved completion")
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fixture.dir.path().join("engine.result").exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let recovered: DispatchResult =
        serde_json::from_slice(&std::fs::read(fixture.dir.path().join("engine.result")).unwrap())
            .unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::to_value(recovered).unwrap()
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    supervisor.stop().unwrap();
    task.abort();
    let _ = task.await;
}

#[test]
fn protection_refusal_embedded_entrypoint() {
    if let Some(path) = std::env::var_os("PROTECTED_READ_PROBE") {
        std::fs::read(path).unwrap();
        return;
    }
    let Ok(config) = std::env::var("REFUSED_PROCESS_CONFIG") else {
        return;
    };
    let config: ProcessConfig = serde_json::from_str(&config).unwrap();
    assert!(matches!(
        CredentialProcess::open(config),
        Err(EgressError::StateUnavailable)
    ));
}

#[cfg(target_os = "linux")]
fn refuse_protection(command: &mut std::process::Command, syscall: libc::c_long) {
    use std::os::unix::process::CommandExt;
    // SAFETY: pre_exec performs only prctl on preallocated BPF data.
    unsafe {
        command.pre_exec(move || {
            let filter = [
                libc::sock_filter {
                    code: 0x20,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: 0x15,
                    jt: 0,
                    jf: 1,
                    k: syscall as u32,
                },
                libc::sock_filter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                },
                libc::sock_filter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut _,
            };
            if libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
                || libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                    &program,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn protection_refusal_aborts_embedded_and_executable_startup_before_protected_reads() {
    let fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    let config_path = fixture.dir.path().join("config.json");
    let config_json = serde_json::to_string(&fixture.config).unwrap();
    std::fs::write(&config_path, &config_json).unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    #[cfg(target_os = "macos")]
    let library = {
        let library = fixture.dir.path().join("refuse-protection.dylib");
        let compiler = std::env::var("CC").expect("configured compiler cache");
        let mut compiler = compiler.split_whitespace();
        let output = std::process::Command::new(compiler.next().unwrap())
            .args(compiler)
            .args(["-O2", "-dynamiclib"])
            .arg(manifest_dir().join("tests/refuse_protection.c"))
            .arg("-o")
            .arg(&library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        library
    };
    #[cfg(target_os = "macos")]
    let protected_root = fixture.dir.path().canonicalize().unwrap();
    #[cfg(target_os = "macos")]
    {
        // Positive control: the observer must record an actual protected read.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "protection_refusal_embedded_entrypoint",
                "--nocapture",
            ])
            .env("PROTECTED_READ_PROBE", &config_path)
            .env("DYLD_INSERT_LIBRARIES", &library)
            .env("PROTECTED_READ_ROOT", &protected_root)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("protected read"));
    }
    #[cfg(target_os = "linux")]
    let refusals = [libc::SYS_prctl, libc::SYS_prlimit64];
    #[cfg(target_os = "macos")]
    let refusals = [library.as_path()];
    for refusal in refusals {
        for embedded in [true, false] {
            let mut command = if embedded {
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                command
                    .args([
                        "--exact",
                        "protection_refusal_embedded_entrypoint",
                        "--nocapture",
                    ])
                    .env("REFUSED_PROCESS_CONFIG", &config_json);
                command
            } else {
                let mut command = std::process::Command::new(credential_process());
                command.arg(&config_path);
                command
            };
            #[cfg(target_os = "linux")]
            refuse_protection(&mut command, refusal);
            #[cfg(target_os = "linux")]
            let monitor = {
                use std::os::fd::{FromRawFd, OwnedFd};
                // Watch only protected files; startup may read ordinary runtime libraries.
                let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
                assert!(fd >= 0);
                let monitor = unsafe { OwnedFd::from_raw_fd(fd) };
                for path in [
                    &config_path,
                    &fixture.dir.path().join("admission"),
                    &fixture.dir.path().join("provider"),
                ] {
                    use std::os::unix::ffi::OsStrExt;
                    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert!(
                        unsafe {
                            libc::inotify_add_watch(
                                fd,
                                path.as_ptr(),
                                libc::IN_OPEN | libc::IN_ACCESS,
                            )
                        } >= 0
                    );
                }
                monitor
            };
            #[cfg(target_os = "macos")]
            {
                command
                    .env("DYLD_INSERT_LIBRARIES", refusal)
                    .env("PROTECTED_READ_ROOT", &protected_root);
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.success(),
                embedded,
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if !embedded {
                assert_eq!(
                    String::from_utf8_lossy(&output.stderr).trim(),
                    EgressError::StateUnavailable.to_string()
                );
            }
            assert!(
                !fixture.config.state_dir.exists(),
                "refusal must precede state and secret access"
            );
            assert!(!String::from_utf8_lossy(&output.stderr).contains("protected read"));
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                let mut events = [0_u8; 4096];
                assert_eq!(
                    unsafe {
                        libc::read(
                            monitor.as_raw_fd(),
                            events.as_mut_ptr().cast(),
                            events.len(),
                        )
                    },
                    -1
                );
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "protected files must remain unopened"
                );
            }
        }
    }
}

#[tokio::test]
async fn anthropic_route_dispatches_only_through_the_credential_permit_and_recovers() {
    for thinking in [
        None,
        Some(symbiotic_ai_runtime::model::ThinkingMode::Enabled),
        Some(symbiotic_ai_runtime::model::ThinkingMode::Disabled),
    ] {
        for stop_reason in ["end_turn", "model_context_window_exceeded"] {
            let mut fixture = Fixture::with_http_response(200,
            serde_json::json!({"content":[{"type":"text","text":"answer"}],"stop_reason":stop_reason,
                "usage":{"input_tokens":7,"output_tokens":348,"output_tokens_details":{"thinking_tokens":312},"cost_usd":"0.000000125"}}).to_string(),
            Duration::ZERO, "0", true, false).await;
            fixture.config.routes[0].provider = RouteProvider::AnthropicChat {
                operator: "anthropic".into(),
                thinking,
            };
            let process = fixture.process().await;
            let (admission, payload) = fixture.attempt("anthropic", 1, 1);
            let granted = permit(&process, &admission).await;
            let result = dispatched(
                exchange(&process, inject(admission.clone(), payload, granted))
                    .await
                    .unwrap(),
            );
            assert!(
                matches!(&result.output, Some(ProviderOutput::Chat {text}) if text == "answer")
            );
            assert_eq!(result.receipt.usage.input_tokens, Some(7));
            assert_eq!(result.receipt.usage.output_tokens, Some(348));
            assert_eq!(result.receipt.usage.reasoning_tokens, Some(312));
            assert_eq!(
                result.receipt.usage.reported_cost_usd.as_deref(),
                Some("0.000000125")
            );
            assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
            assert_eq!(result.receipt.spend_state, SpendState::Settled);
            assert!(result.receipt_persisted);
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
            drop(process);
            let process = fixture.process().await;
            let AttemptStatus::Completed { result: recovered } = status(&process, &admission).await
            else {
                panic!("missing recovered answer");
            };
            assert_eq!(
                recovered.receipt.usage.reported_cost_usd.as_deref(),
                Some("0.000000125")
            );
            assert_eq!(
                serde_json::to_value(&result).unwrap(),
                serde_json::to_value(recovered).unwrap()
            );
            assert!(
                matches!(exchange(&process, Operation::Receipt(signed_id(&admission))).await,
            Ok(Reply::Receipt(Some(receipt))) if receipt.usage.reasoning_tokens == Some(312) && receipt.usage.output_tokens == Some(348) && receipt.usage.reported_cost_usd.as_deref() == Some("0.000000125") && receipt.spend_state == SpendState::Settled)
            );
            let recovered = exchange(&process, Operation::IssuePermit(admission.into()))
                .await
                .unwrap();
            assert!(matches!(
                recovered,
                Reply::Permit(PermitGrant {
                    status: AttemptStatus::Completed { .. },
                    ..
                })
            ));
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn expanded_anthropic_wire_payload_is_refused_before_consumption() {
    expanded_wire_payload_is_refused(2).await;
}

#[tokio::test]
async fn anthropic_enabled_thinking_temperature_is_refused_before_consumption() {
    anthropic_invalid_conversation_is_refused(
        false,
        Some(0.0),
        Some(symbiotic_ai_runtime::model::ThinkingMode::Enabled),
    )
    .await;
}

#[tokio::test]
async fn anthropic_assistant_prefill_is_refused_before_consumption() {
    anthropic_invalid_conversation_is_refused(
        true,
        None,
        Some(symbiotic_ai_runtime::model::ThinkingMode::Enabled),
    )
    .await;
}

#[tokio::test]
async fn anthropic_invalid_temperatures_are_refused_before_consumption() {
    for thinking in [
        None,
        Some(symbiotic_ai_runtime::model::ThinkingMode::Disabled),
    ] {
        for temperature in [-0.1, 1.5, f32::NAN, f32::NEG_INFINITY, f32::INFINITY] {
            anthropic_invalid_conversation_is_refused(false, Some(temperature), thinking).await;
        }
    }
}

#[tokio::test]
async fn in_process_nonfinite_temperatures_cannot_alias_an_admitted_request() {
    let mut fixture = Fixture::with_http_response(
        200,
        serde_json::json!({
            "content": [{"type": "text", "text": "answer"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 7, "output_tokens": 1}
        })
        .to_string(),
        Duration::ZERO,
        "0",
        true,
        false,
    )
    .await;
    fixture.config.routes[0].provider = RouteProvider::AnthropicChat {
        operator: "anthropic".into(),
        thinking: None,
    };
    let process = fixture.process().await;
    let client = InProcessEgressClient::new(process.clone());
    let (admission, payload) = fixture.attempt("nonfinite-temperature", 1, 1);
    let granted = permit(&process, &admission).await;
    for temperature in [f32::NAN, f32::NEG_INFINITY, f32::INFINITY] {
        let mut invalid_payload = payload.clone();
        let ProviderPayload::Chat(chat) = &mut invalid_payload else {
            panic!("chat expected")
        };
        chat.temperature = Some(temperature);
        // JSON maps nonfinite floats to null, so the digest alone cannot
        // distinguish these invalid inputs from the admitted absent temperature.
        assert_eq!(invalid_payload.digest().unwrap(), payload.digest().unwrap());
        assert!(matches!(
            exchange_client(
                &client,
                inject(admission.clone(), invalid_payload, granted.clone()),
            )
            .await,
            Err(EgressError::InvalidRequest)
        ));
        assert!(matches!(
            status(&process, &admission).await,
            AttemptStatus::Permitted
        ));
        assert!(matches!(
            exchange(&process, Operation::Receipt(signed_id(&admission))).await,
            Ok(Reply::Receipt(None))
        ));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        assert_eq!(ledger_totals(&fixture), (0, 0));
    }
    let result = dispatched(
        exchange_client(&client, inject(admission, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    assert!(matches!(result.output, Some(ProviderOutput::Chat { text }) if text == "answer"));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger_totals(&fixture), (1, 1));
}

async fn anthropic_invalid_conversation_is_refused(
    prefill: bool,
    temperature: Option<f32>,
    thinking: Option<symbiotic_ai_runtime::model::ThinkingMode>,
) {
    let mut fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    fixture.config.routes[0].provider = RouteProvider::AnthropicChat {
        operator: "anthropic".into(),
        thinking,
    };
    fixture.config.routes[0].secret = SecretSource::OwnerOnlyFile {
        path: fixture.dir.path().join("missing-provider"),
    };
    let process = fixture.process().await;
    let (mut admission, mut payload) = fixture.attempt("invalid-anthropic", 1, 1);
    let ProviderPayload::Chat(request) = &mut payload else {
        panic!("chat expected")
    };
    if prefill {
        request.messages.push(ChatMessage {
            role: "assistant".into(),
            content: "Answer:".into(),
        });
    }
    request.temperature = temperature;
    admission.attempt.input_digest = payload.digest().unwrap();
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(admission.attempt)
        .unwrap();
    let granted = permit(&process, &admission).await;
    assert!(matches!(
        exchange(&process, inject(admission.clone(), payload, granted)).await,
        Err(EgressError::InvalidRequest)
    ));
    assert!(matches!(
        exchange(&process, Operation::Receipt(signed_id(&admission))).await,
        Ok(Reply::Receipt(None))
    ));
    assert!(matches!(
        status(&process, &admission).await,
        AttemptStatus::Permitted
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger_totals(&fixture), (0, 0));
}

#[tokio::test]
async fn both_clients_refuse_deeply_nested_requests_before_permit_consumption() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let listener = server::bind(&process).unwrap();
    let task = tokio::spawn(server::serve(process.clone(), listener));
    let socket_client = socket::UnixEgressClient {
        path: fixture.config.socket_path.clone(),
        max_frame_bytes: fixture.config.max_frame_bytes,
        timeout: Duration::from_secs(3),
    };
    let in_process_client = InProcessEgressClient::new(process.clone());
    let (admission, mut payload) = fixture.attempt("nested-metadata", 1, 1);
    let ProviderPayload::Chat(chat) = &mut payload else {
        panic!("wrong payload")
    };
    let mut metadata = serde_json::json!(0);
    for _ in 0..200 {
        metadata = serde_json::Value::Array(vec![metadata]);
    }
    chat.metadata = metadata;
    assert!(
        serde_json::to_vec(&payload).unwrap().len() <= fixture.config.routes[0].max_input_bytes
    );
    let mut attempt = admission.attempt;
    attempt.input_digest = payload.digest().unwrap();
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(attempt)
        .unwrap();
    let granted = permit(&process, &admission).await;
    let request = Request {
        version: PROTOCOL_VERSION,
        operation: inject(admission.clone(), payload, granted.clone()),
    };
    encode_frame(&request, fixture.config.max_frame_bytes).unwrap();
    let db = rusqlite::Connection::open(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
    )
    .unwrap();
    for client in [
        &socket_client as &dyn EgressClient,
        &in_process_client as &dyn EgressClient,
    ] {
        let response = client.exchange(request.clone()).await.unwrap();
        assert_eq!(response.version, PROTOCOL_VERSION);
        assert!(matches!(response.result, Err(EgressError::InvalidRequest)));
        assert!(matches!(
            status(&process, &admission).await,
            AttemptStatus::Permitted
        ));
        assert_eq!(
            db.query_row(
                "SELECT consumed, accepted_attempts FROM egress_permits WHERE token=?1",
                [&granted.token],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, u32>(1)?))
            )
            .unwrap(),
            (false, 0)
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        assert_eq!(ledger_totals(&fixture), (0, 0));
    }
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn in_process_oversized_requests_are_refused_before_handler_execution() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let client = InProcessEgressClient::new(process.clone());
    let tenant = "t".repeat(fixture.config.max_frame_bytes as usize + 1);
    let key = AdmissionKey::new(KEY.to_vec()).unwrap();
    let oversized_grant = key
        .sign_grant_revision(GrantRevision {
            tenant: tenant.clone(),
            incarnation: "incarnation".into(),
            revision: 1,
        })
        .unwrap();
    assert!(matches!(
        exchange_client(&client, Operation::PublishGrantRevision(oversized_grant)).await,
        Err(EgressError::LimitExceeded)
    ));
    // A rejected publication must not have reached the canonical grant registry.
    let db = rusqlite::Connection::open(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
    )
    .unwrap();
    let published: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM egress_grant_revisions WHERE grant_key=?1)",
            [digest(&(tenant, "incarnation")).unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!published);
    let (admission, mut payload) = fixture.attempt("oversized-frame", 1, 1);
    let ProviderPayload::Chat(chat) = &mut payload else {
        panic!("wrong payload")
    };
    chat.messages[0].content = "x".repeat(fixture.config.max_frame_bytes as usize + 1);
    let mut attempt = admission.attempt;
    attempt.input_digest = payload.digest().unwrap();
    let admission = key.sign_attempt(attempt).unwrap();
    let granted = permit(&process, &admission).await;
    assert!(matches!(
        exchange_client(&client, inject(admission.clone(), payload, granted)).await,
        Err(EgressError::LimitExceeded)
    ));
    assert!(matches!(
        status(&process, &admission).await,
        AttemptStatus::Permitted
    ));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger_totals(&fixture), (0, 0));
}

#[tokio::test]
async fn in_process_oversized_recovered_response_is_refused_without_losing_the_answer() {
    let answer = "a".repeat(20 * 1024);
    let fixture = Fixture::new(200, answer.clone(), Duration::ZERO).await;
    let process = fixture.process().await;
    let (admission, payload) = fixture.attempt("large-recovery", 1, 1);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission.clone(), payload, granted))
            .await
            .unwrap(),
    );
    assert!(result.receipt_persisted);
    assert!(matches!(&result.output, Some(ProviderOutput::Chat { text }) if text == &answer));
    drop(process);

    let mut smaller = fixture.config.clone();
    smaller.max_frame_bytes = 8192;
    smaller.routes[0].max_field_bytes = 64;
    smaller.routes[0].max_response_bytes = 256;
    smaller.routes[0].max_input_bytes = 4096;
    let client = InProcessEgressClient::new(CredentialProcess::open(smaller).unwrap());
    for operation in [
        Operation::AttemptStatus(signed_id(&admission)),
        Operation::IssuePermit(admission.clone().into()),
    ] {
        let response = client
            .exchange(Request {
                version: PROTOCOL_VERSION,
                operation,
            })
            .await
            .unwrap();
        assert_eq!(response.version, PROTOCOL_VERSION);
        assert!(matches!(response.result, Err(EgressError::LimitExceeded)));
    }
    drop(client);

    let client = InProcessEgressClient::new(fixture.process().await);
    let AttemptStatus::Completed { result: recovered } =
        client.attempt_status(signed_id(&admission)).await.unwrap()
    else {
        panic!("missing stored answer")
    };
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::to_value(recovered).unwrap()
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger_totals(&fixture), (1, 1));
}

#[tokio::test]
async fn in_process_exchange_survives_a_dropped_caller_and_recovers_without_resending() {
    use std::{future::Future, task::Poll};
    use symbiotic_credential_process::InProcessEgressClient;

    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let mut fixture = Fixture::with_response_gate(
        200,
        "thread answer".into(),
        Duration::ZERO,
        "0",
        false,
        true,
        Some(gate.clone()),
    )
    .await;
    fixture.config.routes[0].secret = SecretSource::None;
    fixture.config.routes[0].secret_ref.clear();
    let process = fixture.process().await;
    let client = InProcessEgressClient::new(process.clone());
    let (admission, payload) = fixture.attempt("thread-cancel", 1, 1);
    let response = client
        .exchange(Request {
            version: PROTOCOL_VERSION,
            operation: Operation::IssuePermit(admission.clone().into()),
        })
        .await
        .unwrap();
    let Reply::Permit(grant) = response.result.unwrap() else {
        panic!("missing permit")
    };
    let mut caller = Box::pin(client.exchange(Request {
        version: PROTOCOL_VERSION,
        operation: inject(admission.clone(), payload, grant.permit),
    }));
    // Poll once on this single-thread runtime, then drop before the spawned
    // Foundation handler can run. The exchange must still reach acceptance.
    let polled = std::future::poll_fn(|cx| Poll::Ready(caller.as_mut().poll(cx))).await;
    assert!(polled.is_pending());
    // No runtime yield has occurred: acceptance must not have run in the caller.
    let consumed: bool = rusqlite::Connection::open_with_flags(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT consumed FROM egress_permits WHERE attempt_digest=?1",
        [digest(&admission.attempt).unwrap()],
        |row| row.get(0),
    )
    .unwrap();
    assert!(
        !consumed,
        "acceptance ran on the caller instead of the Foundation task"
    );
    drop(caller);
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    gate.add_permits(1);
    let id = signed_id(&admission);
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client.attempt_status(id.clone()).await.unwrap() {
                AttemptStatus::Completed { result } => break result,
                AttemptStatus::Dispatched { .. } => tokio::task::yield_now().await,
                _ => panic!("unexpected recovery status"),
            }
        }
    })
    .await
    .unwrap();
    assert!(
        matches!(&result.output, Some(ProviderOutput::Chat { text }) if text == "thread answer")
    );
    assert!(result.receipt_persisted);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    drop(client);
    drop(process);
    let reopened = InProcessEgressClient::new(fixture.process().await);
    let AttemptStatus::Completed { result: recovered } = reopened.attempt_status(id).await.unwrap()
    else {
        panic!("missing recovered answer")
    };
    assert_eq!(result.receipt.reference, recovered.receipt.reference);
    assert!(
        matches!(recovered.output, Some(ProviderOutput::Chat { text }) if text == "thread answer")
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn resolver_is_lazy_and_provider_uses_its_key_in_thread_mode() {
    initialize_panic_reporting();
    let mut fixture = Fixture::new(200, "resolver answer".into(), Duration::ZERO).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    fixture.config.routes[0].secret = SecretSource::Resolver {
        name: "named-provider-key".into(),
        resolve: Arc::new(move |name| {
            assert_eq!(name, "named-provider-key");
            // The regression in secrets checks refusal before OS protection.
            count.fetch_add(1, Ordering::SeqCst);
            Ok(symbiotic_ai_runtime::model::SecretValue::new(
                SECRET.as_bytes().to_vec(),
            ))
        }),
    };
    let process = fixture.process().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (admission, payload) = fixture.attempt("resolver", 1, 1);
    let granted = permit(&process, &admission).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let result = dispatched(
        exchange(&process, inject(admission, payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.receipt.status, DispatchStatus::Succeeded);
    assert!(
        matches!(result.output, Some(ProviderOutput::Chat { text }) if text == "resolver answer")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn resolver_debug_redacts_captured_key_without_invoking_callback() {
    let key = symbiotic_ai_runtime::model::SecretValue::new(SECRET.as_bytes().to_vec());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let source = SecretSource::Resolver {
        name: "provider-key".into(),
        resolve: Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(key.clone())
        }),
    };
    let diagnostic = format!("{source:?}");
    assert!(diagnostic.contains("Resolver { .. }"));
    assert!(!diagnostic.contains("synthetic-WP14-credential"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn resolver_error_is_redacted_and_never_reaches_provider() {
    initialize_panic_reporting();
    let mut fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    fixture.config.routes[0].secret = SecretSource::Resolver {
        name: "provider-key".into(),
        resolve: Arc::new(|_| Err(std::io::Error::other(SECRET).into())),
    };
    let process = fixture.process().await;
    let (admission, payload) = fixture.attempt("resolver-error", 1, 1);
    let granted = permit(&process, &admission).await;
    let result = dispatched(
        exchange(&process, inject(admission.clone(), payload, granted))
            .await
            .unwrap(),
    );
    assert_eq!(result.error, Some(EgressError::CredentialUnavailable));
    assert_eq!(result.receipt.status, DispatchStatus::CredentialUnavailable);
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("synthetic-WP14-credential")
    );
    assert!(!format!("{result:?}").contains("synthetic-WP14-credential"));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let AttemptStatus::Failed { result: recovered } = status(&process, &admission).await else {
        panic!("expected retained redacted failure");
    };
    assert_eq!(recovered.error, Some(EgressError::CredentialUnavailable));
    assert!(
        !serde_json::to_string(&recovered)
            .unwrap()
            .contains("synthetic-WP14-credential")
    );
}

#[tokio::test]
async fn resolver_panic_child() {
    fn lookup() -> std::io::Result<symbiotic_ai_runtime::model::SecretValue<Vec<u8>>> {
        Err(std::io::Error::other(SECRET))
    }

    let Some(mode) = std::env::var_os("RESOLVER_PANIC_TEST") else {
        return;
    };
    // Use Rust's default reporter, rather than the test harness's hook.
    drop(std::panic::take_hook());
    initialize_resolver_panic_hook(std::panic::take_hook());
    let mut fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    let worker = mode == "worker";
    let source = SecretSource::Resolver {
        name: "provider-key".into(),
        resolve: Arc::new(move |_| {
            if worker {
                return std::thread::spawn(|| lookup().expect("worker lookup failed"))
                    .join()
                    .map_err(|_| std::io::Error::other("lookup worker panicked").into());
            }
            Ok(lookup().expect("lookup failed"))
        }),
    };
    if mode == "admission" {
        fixture.config.admission_key = source;
        assert!(matches!(
            CredentialProcess::open(fixture.config.clone()),
            Err(EgressError::CredentialUnavailable)
        ));
    } else {
        assert!(mode == "provider" || mode == "worker" || mode == "reporter");
        if mode == "reporter" {
            fixture.config.admission_key = SecretSource::Resolver {
                name: "admission-key".into(),
                resolve: Arc::new(|_| {
                    Ok(symbiotic_ai_runtime::model::SecretValue::new(KEY.to_vec()))
                }),
            };
        }
        fixture.config.routes[0].secret = source;
        let process = fixture.process().await;
        if mode == "reporter" {
            // App reporter initialization follows a successful admission-key lookup.
            initialize_resolver_panic_hook(|info| eprintln!("app reporter: {info}"));
        }
        let (admission, payload) = fixture.attempt("resolver-panic", 1, 1);
        let granted = permit(&process, &admission).await;
        let result = dispatched(
            exchange(&process, inject(admission.clone(), payload, granted))
                .await
                .unwrap(),
        );
        assert_eq!(result.error, Some(EgressError::CredentialUnavailable));
        assert_eq!(result.receipt.status, DispatchStatus::CredentialUnavailable);
        assert_eq!(result.receipt.spend_state, SpendState::Released);
        assert!(result.output.is_none());
        assert!(!serde_json::to_string(&result).unwrap().contains(SECRET));
        let AttemptStatus::Failed { result: recovered } = status(&process, &admission).await else {
            panic!("expected retained redacted failure");
        };
        assert_eq!(recovered.error, Some(EgressError::CredentialUnavailable));
        assert!(!serde_json::to_string(&recovered).unwrap().contains(SECRET));
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    // Unrelated panics must retain ordinary reporting after resolution too.
    assert!(std::panic::catch_unwind(|| panic!("unrelated panic after resolution")).is_err());
}

fn assert_resolver_panic_is_redacted(mode: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "resolver_panic_child", "--nocapture"])
        .env("RESOLVER_PANIC_TEST", mode)
        .env("RUST_BACKTRACE", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("synthetic-WP14-credential"));
    assert!(output.status.success(), "{stderr}");
    assert_eq!(stderr.matches("credential resolver panicked").count(), 1);
    assert!(stderr.contains("unrelated panic after resolution"));
    if mode == "reporter" {
        assert!(stderr.contains("app reporter:"));
    }
}

#[test]
fn resolver_panics_are_redacted_at_startup() {
    assert_resolver_panic_is_redacted("admission");
}

#[test]
fn resolver_panics_are_redacted_at_dispatch() {
    assert_resolver_panic_is_redacted("provider");
}

#[test]
fn resolver_panics_are_redacted_after_reporter_initialization() {
    assert_resolver_panic_is_redacted("reporter");
}

#[test]
fn resolver_worker_panics_are_redacted() {
    assert_resolver_panic_is_redacted("worker");
}

#[tokio::test]
async fn resolver_configuration_is_refused_in_child_mode_without_invoking_callback() {
    let fixture = Fixture::new(200, "unused".into(), Duration::ZERO).await;
    fixture.config.validate_child_process().unwrap();
    for admission in [true, false] {
        let mut config = fixture.config.clone();
        let source = SecretSource::Resolver {
            name: "provider-key".into(),
            resolve: Arc::new(|_| panic!("child configuration must never resolve a key")),
        };
        if admission {
            config.admission_key = source;
        } else {
            config.routes[0].secret = source;
        }
        assert_eq!(
            config.validate_child_process(),
            Err(EgressError::ResolverRequiresThreadMode)
        );
        assert!(serde_json::to_vec(&config).is_err());
    }
    let mut json = serde_json::to_value(&fixture.config).unwrap();
    json["routes"][0]["secret"] =
        serde_json::json!({"backend": "resolver", "name": "provider-key"});
    assert!(serde_json::from_value::<ProcessConfig>(json).is_err());
}

fn jobs_scope() -> JobScope {
    JobScope {
        tenant: "tenant".into(),
        incarnation: "incarnation".into(),
        queue: "derivation".into(),
    }
}
async fn job_call(
    client: &impl EgressClient,
    command: JobsCommand,
) -> Result<JobsReply, JobsClientError> {
    struct BorrowedClient<'a, C>(&'a C);
    #[async_trait::async_trait]
    impl<C: EgressClient> EgressClient for BorrowedClient<'_, C> {
        async fn exchange(&self, request: Request) -> Result<Response, EgressError> {
            self.0.exchange(request).await
        }
    }
    JobsClient::new(
        BorrowedClient(client),
        jobs_scope(),
        AdmissionKey::new(KEY.to_vec()).unwrap(),
    )
    .request(command)
    .await
}
fn queued(fixture: &Fixture, key: &str) -> EnqueueJob {
    let (admission, payload) = fixture.attempt(key, 1, 1);
    EnqueueJob {
        group: Some("task".into()),
        owners: vec!["input-owner".into()],
        admission,
        payload,
    }
}
async fn enqueue_id(client: &impl EgressClient, input: EnqueueJob) -> JobId {
    let JobsReply::Enqueued(items) = job_call(client, JobsCommand::EnqueueJobs(vec![input]))
        .await
        .unwrap()
    else {
        panic!("enqueue reply")
    };
    match &items[0] {
        Enqueued::Inserted(id) | Enqueued::Joined(id) => id.clone(),
        _ => panic!("already done"),
    }
}
async fn wait_job(client: &impl EgressClient, job: &JobId, state: JobState) -> Box<JobRecord> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let JobsReply::Status(row) = job_call(client, JobsCommand::JobStatus(job.clone()))
                .await
                .unwrap()
            else {
                panic!("status")
            };
            assert!(row.payload.is_none() && row.admission.is_none() && row.output.is_none());
            if row.state == state {
                return row;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn jobs_six_operations_round_trip_on_both_transports_and_join_by_key() {
    for socket_mode in [false, true] {
        let fixture = Fixture::new(200, "job answer".into(), Duration::ZERO).await;
        let process = fixture.process().await;
        let server_task;
        let client: Box<dyn EgressClient> = if socket_mode {
            let listener = server::bind(&process).unwrap();
            server_task = Some(tokio::spawn(server::serve(process.clone(), listener)));
            Box::new(socket::UnixEgressClient {
                path: fixture.config.socket_path.clone(),
                max_frame_bytes: fixture.config.max_frame_bytes,
                timeout: Duration::from_secs(3),
            })
        } else {
            server_task = None;
            Box::new(InProcessEgressClient::new(process.clone()))
        };
        // Trait objects are wrapped by a concrete forwarding adapter for shared helpers.
        struct Client(Box<dyn EgressClient>);
        #[async_trait::async_trait]
        impl EgressClient for Client {
            async fn exchange(&self, request: Request) -> Result<Response, EgressError> {
                self.0.exchange(request).await
            }
        }
        let client = Client(client);
        let mut input = queued(&fixture, "six");
        if let ProviderPayload::Chat(request) = &mut input.payload {
            request.source = Some("private-source".into());
            request.role_binding = Some("private-role".into());
            request.metadata = serde_json::json!({"private": "private-payload-metadata"});
        }
        input.admission.attempt.input_digest = input.payload.digest().unwrap();
        input.admission = AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_attempt(input.admission.attempt)
            .unwrap();
        let id = enqueue_id(&client, input.clone()).await;
        assert_eq!(enqueue_id(&client, input.clone()).await, id);
        let mut conflicting = input;
        conflicting.admission.attempt.manifest_ref = "changed-manifest".into();
        conflicting.admission = AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_attempt(conflicting.admission.attempt)
            .unwrap();
        assert!(matches!(
            job_call(&client, JobsCommand::EnqueueJobs(vec![conflicting])).await,
            Err(JobsClientError::Job(JobError::KeyConflict))
        ));
        wait_job(&client, &id, JobState::Succeeded).await;
        assert!(matches!(
            job_call(
                &client,
                JobsCommand::Completions {
                    limit: 1,
                    max_bytes: 40,
                    wait_seconds: 0
                }
            )
            .await,
            Err(JobsClientError::Job(JobError::CompletionTooLarge { .. }))
        ));
        assert_eq!(
            wait_job(&client, &id, JobState::Succeeded)
                .await
                .delivery_generation,
            0
        );
        let JobsReply::Completions(page) = job_call(
            &client,
            JobsCommand::Completions {
                limit: 8,
                max_bytes: 65536,
                wait_seconds: 0,
            },
        )
        .await
        .unwrap() else {
            panic!("completions")
        };
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].output.as_ref().unwrap()["text"], "job answer");
        let encoded = serde_json::to_string(&page.items[0].output).unwrap();
        for private in ["private-source", "private-role", "private-payload-metadata"] {
            assert!(!encoded.contains(private));
        }
        let token = page.items[0].delivery.token.clone();
        assert!(
            matches!(job_call(&client, JobsCommand::AckJobs(vec![(token.clone(), Disposition::Accepted)])).await.unwrap(), JobsReply::Acked(ref results) if results == &[AckResult::Acked(Disposition::Accepted)])
        );
        assert!(
            matches!(job_call(&client, JobsCommand::AckJobs(vec![(token, Disposition::Discarded)])).await.unwrap(), JobsReply::Acked(ref results) if results == &[AckResult::AlreadyAcked(Disposition::Accepted)])
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        // Expired authority is stored and noticed, never silently dropped.
        let mut waiting = queued(&fixture, "cancel-awaiting");
        waiting.admission.attempt.expires_at = unix_seconds();
        waiting.admission = AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_attempt(waiting.admission.attempt)
            .unwrap();
        let mut successor = waiting.admission.attempt.clone();
        successor.attempt_ordinal = 2;
        successor.record_sequence = 2;
        let successor = AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_attempt(successor)
            .unwrap();
        let waiting = enqueue_id(&client, waiting).await;
        wait_job(&client, &waiting, JobState::AwaitingAdmission).await;
        assert!(matches!(
            job_call(
                &client,
                JobsCommand::AdmitJob {
                    job: waiting.clone(),
                    admission: Box::new(successor)
                }
            )
            .await
            .unwrap(),
            JobsReply::Admitted
        ));
        wait_job(&client, &waiting, JobState::AwaitingAdmission).await;
        assert!(matches!(
            job_call(
                &client,
                JobsCommand::CancelJobs(Selector::Group("task".into()))
            )
            .await
            .unwrap(),
            JobsReply::Cancelled(1)
        ));
        wait_job(&client, &waiting, JobState::Cancelled).await;
        if let Some(task) = server_task {
            task.abort();
        }
    }
}

#[tokio::test]
async fn jobs_recheck_grants_after_account_wait_and_readmit_without_renewing_ceiling() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let mut fixture = Fixture::with_response_gate(
        200,
        "answer".into(),
        Duration::ZERO,
        "null",
        false,
        false,
        Some(gate.clone()),
    )
    .await;
    fixture.config.routes[0].max_in_flight = 1;
    fixture.config.routes[0].max_attempts = 1;
    fixture.config.routes[0].timeout_seconds = 5;
    let process = fixture.process().await;
    let client = InProcessEgressClient::new(process.clone());
    let first = enqueue_id(&client, queued(&fixture, "first")).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture.calls.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let waiting = queued(&fixture, "waiting");
    let second = enqueue_id(&client, waiting.clone()).await;
    revoke(&process, 2).await;
    gate.add_permits(1);
    wait_job(&client, &first, JobState::Succeeded).await;
    let row = wait_job(&client, &second, JobState::AwaitingAdmission).await;
    assert_eq!(row.generation, 0);
    assert!(row.receipt.is_none());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    // A final and a notice coexist: finals are delivered first and notices cannot be acked.
    let JobsReply::Completions(page) = job_call(
        &client,
        JobsCommand::Completions {
            limit: 1,
            max_bytes: 65536,
            wait_seconds: 0,
        },
    )
    .await
    .unwrap() else {
        panic!("page")
    };
    assert_eq!(page.items.len(), 1);
    assert!(page.notices.is_empty());
    let JobsReply::Completions(page) = job_call(
        &client,
        JobsCommand::Completions {
            limit: 1,
            max_bytes: 65536,
            wait_seconds: 0,
        },
    )
    .await
    .unwrap() else {
        panic!("notice")
    };
    assert_eq!(page.notices[0].id, second);
    assert!(matches!(
        job_call(
            &client,
            JobsCommand::AckJobs(vec![(
                DeliveryToken {
                    job: second.clone(),
                    generation: 1
                },
                Disposition::Accepted
            )])
        )
        .await,
        Err(JobsClientError::Job(JobError::NotFinal))
    ));
    let mut successor = waiting.admission.attempt;
    successor.grant_revision = 2;
    successor.attempt_ordinal = 2;
    successor.record_sequence = 2;
    successor.recorded_at = unix_seconds();
    successor.expires_at = successor.recorded_at + 3600;
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(successor)
        .unwrap();
    assert!(matches!(
        job_call(
            &client,
            JobsCommand::AdmitJob {
                job: second.clone(),
                admission: Box::new(admission)
            }
        )
        .await
        .unwrap(),
        JobsReply::Admitted
    ));
    gate.add_permits(1);
    let row = wait_job(&client, &second, JobState::Succeeded).await;
    assert_eq!(row.generation, 1);
    assert_eq!(row.max_attempts, 1);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn jobs_expired_recovery_keeps_waiting_input_and_settles_without_output() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let client = InProcessEgressClient::new(process);
    let mut input = queued(&fixture, "expired-recovery");
    input.admission.attempt.recovery_expires_at = unix_seconds() - 1;
    input.admission.attempt.expires_at = unix_seconds();
    input.admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(input.admission.attempt)
        .unwrap();
    let id = enqueue_id(&client, input.clone()).await;
    wait_job(&client, &id, JobState::AwaitingAdmission).await;
    let mut successor = input.admission.attempt;
    successor.attempt_ordinal = 2;
    successor.record_sequence = 2;
    // Renew authority after recovery expiry; recovery never controls execution.
    successor.recorded_at = unix_seconds();
    successor.expires_at = unix_seconds() + 3600;
    let admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(successor)
        .unwrap();
    job_call(
        &client,
        JobsCommand::AdmitJob {
            job: id.clone(),
            admission: Box::new(admission),
        },
    )
    .await
    .unwrap();
    let row = wait_job(&client, &id, JobState::Succeeded).await;
    assert!(row.result_expired && row.receipt.is_some());
    let JobsReply::Completions(page) = job_call(
        &client,
        JobsCommand::Completions {
            limit: 1,
            max_bytes: 65536,
            wait_seconds: 0,
        },
    )
    .await
    .unwrap() else {
        panic!("completion")
    };
    assert!(page.items[0].output.is_none());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn jobs_scope_and_mac_are_checked_before_any_control_operation() {
    let fixture = Fixture::new(200, "answer".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let client = InProcessEgressClient::new(process);
    let mut input = queued(&fixture, "foreign");
    input.admission.attempt.expires_at = unix_seconds();
    input.admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(input.admission.attempt)
        .unwrap();
    let id = enqueue_id(&client, input.clone()).await;
    wait_job(&client, &id, JobState::AwaitingAdmission).await;
    for field in ["tenant", "incarnation", "queue"] {
        let mut foreign = id.clone();
        match field {
            "tenant" => foreign.scope.tenant = "other".into(),
            "incarnation" => foreign.scope.incarnation = "other".into(),
            _ => foreign.scope.queue = "other".into(),
        }
        for command in [
            JobsCommand::JobStatus(foreign.clone()),
            JobsCommand::CancelJobs(Selector::Ids(vec![foreign.clone()])),
            JobsCommand::AckJobs(vec![(
                DeliveryToken {
                    job: foreign.clone(),
                    generation: 1,
                },
                Disposition::Accepted,
            )]),
            JobsCommand::AdmitJob {
                job: foreign,
                admission: Box::new(input.admission.clone()),
            },
        ] {
            assert!(matches!(
                job_call(&client, command).await,
                Err(JobsClientError::Egress(EgressError::Unauthorized))
            ));
        }
    }
    let mut signed = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_jobs(JobsRequest {
            scope: jobs_scope(),
            command: JobsCommand::JobStatus(id.clone()),
        })
        .unwrap();
    signed.request.scope.incarnation = "tampered".into();
    assert!(matches!(
        client
            .exchange(Request {
                version: PROTOCOL_VERSION,
                operation: signed.operation()
            })
            .await
            .unwrap()
            .result,
        Err(EgressError::Unauthorized)
    ));
    wait_job(&client, &id, JobState::AwaitingAdmission).await;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn jobs_kill_after_dispatch_recovers_uncertain_without_resending() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut fixture = Fixture::new(200, "late answer".into(), Duration::from_secs(10)).await;
    fixture.config.jobs.claim_lease_seconds = 1;
    fixture.config.routes[0].timeout_seconds = 30;
    let config = fixture.dir.path().join("jobs-config.json");
    std::fs::write(&config, serde_json::to_vec(&fixture.config).unwrap()).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut command = std::process::Command::new(credential_process());
    command
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env_remove(name);
    }
    let mut child = Child(command.spawn().unwrap());
    let client = socket::UnixEgressClient {
        path: fixture.config.socket_path.clone(),
        max_frame_bytes: fixture.config.max_frame_bytes,
        timeout: Duration::from_secs(3),
    };
    async fn ready(child: &mut Child, client: &socket::UnixEgressClient) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(child.0.try_wait().unwrap().is_none());
                match client
                    .exchange(Request {
                        version: PROTOCOL_VERSION,
                        operation: publish_revision(1),
                    })
                    .await
                {
                    Ok(response) => {
                        response.result.unwrap();
                        break;
                    }
                    Err(EgressError::Transport) => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    other => panic!("startup failed: {}", other.is_err()),
                }
            }
        })
        .await
        .unwrap();
    }
    ready(&mut child, &client).await;
    let input = queued(&fixture, "crashed");
    let id = enqueue_id(&client, input.clone()).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.calls.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    drop(child);
    // Lease expiry triggers ledger-first recovery; the paid answer never committed.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut child = Child(command.spawn().unwrap());
    ready(&mut child, &client).await;
    assert_eq!(enqueue_id(&client, input).await, id);
    let row = wait_job(&client, &id, JobState::Uncertain).await;
    assert_eq!(row.generation, 1);
    assert!(row.receipt.is_some());
    // A successor cannot turn uncertain accounting into another paid dispatch.
    let (admission, _) = fixture.attempt("crashed", 2, 2);
    assert!(matches!(
        job_call(
            &client,
            JobsCommand::AdmitJob {
                job: id.clone(),
                admission: Box::new(admission)
            }
        )
        .await,
        Err(JobsClientError::Job(JobError::InvalidRequest))
    ));
    wait_job(&client, &id, JobState::Uncertain).await;
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn jobs_cancel_sent_call_keeps_answer_and_ack_discards_only_recovery() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let fixture = Fixture::with_response_gate(
        200,
        "sent answer".into(),
        Duration::ZERO,
        "null",
        false,
        false,
        Some(gate.clone()),
    )
    .await;
    let process = fixture.process().await;
    let client = InProcessEgressClient::new(process);
    let id = enqueue_id(&client, queued(&fixture, "sent-cancel")).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture.calls.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    job_call(
        &client,
        JobsCommand::CancelJobs(Selector::Ids(vec![id.clone()])),
    )
    .await
    .unwrap();
    gate.add_permits(1);
    let row = wait_job(&client, &id, JobState::Cancelled).await;
    let reference = row.receipt.unwrap();
    let JobsReply::Completions(page) = job_call(
        &client,
        JobsCommand::Completions {
            limit: 1,
            max_bytes: 65536,
            wait_seconds: 0,
        },
    )
    .await
    .unwrap() else {
        panic!("completion")
    };
    assert_eq!(
        page.items[0].output.as_ref().unwrap()["text"],
        "sent answer"
    );
    job_call(
        &client,
        JobsCommand::AckJobs(vec![(
            page.items[0].delivery.token.clone(),
            Disposition::Discarded,
        )]),
    )
    .await
    .unwrap();
    let conn = rusqlite::Connection::open(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
    )
    .unwrap();
    let (state, usage, recovery): (String, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT state,usage,recovery FROM spend_receipts WHERE reference=?1",
            [reference],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(state, "settled");
    assert!(usage.is_some() && recovery.is_none());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn jobs_only_local_credential_failures_are_known_zero_charge() {
    for missing_secret in [false, true] {
        let fixture = Fixture::new(401, "refused".into(), Duration::ZERO).await;
        if missing_secret {
            std::fs::remove_file(fixture.dir.path().join("provider")).unwrap();
        }
        let process = fixture.process().await;
        let client = InProcessEgressClient::new(process);
        let id = enqueue_id(&client, queued(&fixture, "credential-failure")).await;
        let state = if missing_secret {
            JobState::Failed
        } else {
            JobState::Uncertain
        };
        let row = wait_job(&client, &id, state).await;
        let conn = rusqlite::Connection::open(
            fixture
                .config
                .state_dir
                .join(symbiotic_ai_runtime::QUEUE_DATABASE),
        )
        .unwrap();
        let accounting: String = conn
            .query_row(
                "SELECT state FROM spend_receipts WHERE reference=?1",
                [row.receipt.unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            accounting,
            if missing_secret {
                "released"
            } else {
                "unknown"
            }
        );
        assert_eq!(
            fixture.calls.load(Ordering::SeqCst),
            usize::from(!missing_secret)
        );
        if !missing_secret {
            let (admission, _) = fixture.attempt("credential-failure", 2, 2);
            assert!(matches!(
                job_call(
                    &client,
                    JobsCommand::AdmitJob {
                        job: id,
                        admission: Box::new(admission)
                    }
                )
                .await,
                Err(JobsClientError::Job(JobError::InvalidRequest))
            ));
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        }
    }
}

async fn reopen_jobs(fixture: &Fixture) -> CredentialProcess {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match CredentialProcess::open(fixture.config.clone()) {
                Ok(process) => return process,
                Err(EgressError::StateUnavailable) => tokio::task::yield_now().await,
                Err(error) => panic!("reopen failed: {error:?}"),
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn jobs_stored_operations_survive_execution_config_changes_and_misses_do_not_attach() {
    let mut fixture = Fixture::new(200, "saved answer".into(), Duration::ZERO).await;
    let client = InProcessEgressClient::new(fixture.process().await);
    let id = enqueue_id(&client, queued(&fixture, "saved")).await;
    wait_job(&client, &id, JobState::Succeeded).await;
    let mut waiting = queued(&fixture, "waiting");
    waiting.admission.attempt.expires_at = unix_seconds();
    waiting.admission = AdmissionKey::new(KEY.to_vec())
        .unwrap()
        .sign_attempt(waiting.admission.attempt)
        .unwrap();
    let waiting = enqueue_id(&client, waiting).await;
    wait_job(&client, &waiting, JobState::AwaitingAdmission).await;
    drop(client);
    fixture.config.routes[0].timeout_seconds += 1;
    fixture.config.routes[0].max_in_flight += 1;
    let client = InProcessEgressClient::new(reopen_jobs(&fixture).await);
    wait_job(&client, &id, JobState::Succeeded).await;
    // Renewal stores unfinished work, but the changed execution binding refuses
    // attachment. That refusal must not gate metadata or saved completions.
    let (admission, _) = fixture.attempt("waiting", 2, 2);
    assert!(matches!(
        job_call(
            &client,
            JobsCommand::AdmitJob {
                job: waiting.clone(),
                admission: Box::new(admission)
            }
        )
        .await,
        Err(JobsClientError::Egress(EgressError::StateUnavailable))
    ));
    wait_job(&client, &waiting, JobState::Pending).await;

    let JobsReply::Completions(page) = job_call(
        &client,
        JobsCommand::Completions {
            limit: 1,
            max_bytes: 65536,
            wait_seconds: 0,
        },
    )
    .await
    .unwrap() else {
        panic!("completions")
    };
    assert_eq!(
        page.items[0].output.as_ref().unwrap()["text"],
        "saved answer"
    );
    job_call(
        &client,
        JobsCommand::AckJobs(vec![(
            page.items[0].delivery.token.clone(),
            Disposition::Accepted,
        )]),
    )
    .await
    .unwrap();
    job_call(
        &client,
        JobsCommand::CancelJobs(Selector::Ids(vec![waiting.clone()])),
    )
    .await
    .unwrap();
    wait_job(&client, &waiting, JobState::Cancelled).await;
    for n in 0..4 {
        let mut scope = jobs_scope();
        scope.queue = format!("missing-{n}");
        let jobs = JobsClient::new(
            client.clone(),
            scope.clone(),
            AdmissionKey::new(KEY.to_vec()).unwrap(),
        );
        let missing = JobId {
            scope,
            id: "missing".into(),
        };
        assert!(matches!(
            jobs.request(JobsCommand::JobStatus(missing.clone())).await,
            Err(JobsClientError::Job(JobError::NotFound))
        ));
        let (admission, _) = fixture.attempt("missing", 2, 2);
        assert!(matches!(
            jobs.request(JobsCommand::AdmitJob {
                job: missing,
                admission: Box::new(admission)
            })
            .await,
            Err(JobsClientError::Job(JobError::NotFound))
        ));
        jobs.request(JobsCommand::Completions {
            limit: 1,
            max_bytes: 65536,
            wait_seconds: 0,
        })
        .await
        .unwrap();
    }
    let conn = rusqlite::Connection::open(
        fixture
            .config
            .state_dir
            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
    )
    .unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM model_job_bindings", [], |r| r
            .get::<_, usize>(0))
            .unwrap(),
        1
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn jobs_refuse_signed_attempt_already_dispatched_directly_after_restart() {
    let fixture = Fixture::new(200, "paid once".into(), Duration::ZERO).await;
    let process = fixture.process().await;
    let input = queued(&fixture, "shared-attempt");
    let permit = permit(&process, &input.admission).await;
    assert!(
        dispatched(
            exchange(
                &process,
                inject(input.admission.clone(), input.payload.clone(), permit)
            )
            .await
            .unwrap()
        )
        .output
        .is_some()
    );
    drop(process);
    let client = InProcessEgressClient::new(reopen_jobs(&fixture).await);
    let id = enqueue_id(&client, input).await;
    let row = wait_job(&client, &id, JobState::Refused).await;
    assert_eq!(
        row.diagnostic,
        Some(symbiotic_ai_runtime::model::DiagnosticCode::InvocationCompleted)
    );
    assert!(row.receipt.is_none());
    assert_eq!(row.generation, 0);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn jobs_keyless_completions_discard_raw_json_for_every_response_type() {
    use symbiotic_ai_runtime::model::{ModelAdapter, RerankRequest};
    for kind in ["chat", "embedding", "rerank"] {
        let body = match kind {
            "chat" => serde_json::json!({"choices":[{"message":{"content":"selected answer"}}]}),
            "embedding" => serde_json::json!({"data":[{"index":0,"embedding":[1,2]}]}),
            _ => serde_json::json!({"results":[{"index":0,"relevance_score":0.8}]}),
        };
        let mut body = body;
        body["debug"] = serde_json::json!({"internal_prompt":"private-provider-debug"});
        let mut fixture =
            Fixture::with_http_response(200, body.to_string(), Duration::ZERO, "null", true, true)
                .await;
        fixture.config.routes[0].secret = SecretSource::None;
        fixture.config.routes[0].secret_ref.clear();
        if kind == "embedding" {
            fixture.config.routes[0].provider = RouteProvider::CompatibleEmbedding {
                adapter: ModelAdapter::OpenAiEmbedding,
                operator: "test".into(),
                dimensions: 2,
                embedding_full_dimensions: 1024,
                embedding_input_tokens: 16,
            };
        } else if kind == "rerank" {
            fixture.config.routes[0].provider = RouteProvider::CohereRerank {
                operator: "test".into(),
                rerank_input_bytes: 64,
                rerank_candidates: 2,
                rerank_context_tokens: 16,
                rerank_query_tokens: 8,
            };
        }
        let mut input = queued(&fixture, kind);
        if kind == "embedding" {
            input.payload = ProviderPayload::Embedding(EmbeddingRequest {
                inputs: vec!["input".into()],
                dimensions: Some(2),
                task: None,
                role_binding: None,
                source: None,
                metadata: serde_json::Value::Null,
            });
        } else if kind == "rerank" {
            input.payload = ProviderPayload::Rerank(RerankRequest {
                query: "query".into(),
                documents: vec!["candidate".into()],
                top_k: Some(1),
                role_binding: None,
                source: None,
                metadata: serde_json::Value::Null,
            });
        }
        input.admission.attempt.input_digest = input.payload.digest().unwrap();
        input.admission = AdmissionKey::new(KEY.to_vec())
            .unwrap()
            .sign_attempt(input.admission.attempt)
            .unwrap();
        let client = InProcessEgressClient::new(fixture.process().await);
        let id = enqueue_id(&client, input).await;
        wait_job(&client, &id, JobState::Succeeded).await;
        let JobsReply::Completions(page) = job_call(
            &client,
            JobsCommand::Completions {
                limit: 1,
                max_bytes: 65536,
                wait_seconds: 0,
            },
        )
        .await
        .unwrap() else {
            panic!("completions")
        };
        let output = page.items[0].output.as_ref().unwrap();
        assert!(
            output["raw_provider_response"].is_null(),
            "raw response escaped for {kind}"
        );
        assert!(!output.to_string().contains("private-provider-debug"));
        match kind {
            "chat" => assert_eq!(output["text"], "selected answer"),
            "embedding" => assert_eq!(output["vectors"], serde_json::json!([[1.0, 2.0]])),
            _ => assert_eq!(output["hits"][0]["index"], 0),
        }
        let conn = rusqlite::Connection::open(
            fixture
                .config
                .state_dir
                .join(symbiotic_ai_runtime::QUEUE_DATABASE),
        )
        .unwrap();
        let recovery: String = conn
            .query_row(
                "SELECT recovery FROM spend_receipts WHERE recovery IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!recovery.contains("private-provider-debug"));
    }
}

#[tokio::test]
async fn jobs_and_direct_dispatch_share_atomic_signed_attempt_acceptance() {
    for concurrent in [false, true] {
        let fixture = Fixture::new(200, "one dispatch".into(), Duration::ZERO).await;
        let process = fixture.process().await;
        let client = InProcessEgressClient::new(process.clone());
        let input = queued(&fixture, "atomic-attempt");
        // Issuance alone does not accept a dispatch; either path may consume it.
        let permit = permit(&process, &input.admission).await;
        let operation = inject(
            input.admission.clone(),
            input.payload.clone(),
            permit.clone(),
        );
        let id = if concurrent {
            let (id, direct) = tokio::join!(
                enqueue_id(&client, input.clone()),
                exchange(&process, operation)
            );
            assert!(matches!(
                direct,
                Ok(Reply::Dispatched(_)) | Err(EgressError::PermitRefused)
            ));
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let JobsReply::Status(row) =
                        job_call(&client, JobsCommand::JobStatus(id.clone()))
                            .await
                            .unwrap()
                    else {
                        panic!("status")
                    };
                    if matches!(row.state, JobState::Succeeded | JobState::Refused) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            id
        } else {
            let id = enqueue_id(&client, input.clone()).await;
            wait_job(&client, &id, JobState::Succeeded).await;
            assert!(matches!(
                exchange(&process, operation).await,
                Err(EgressError::PermitRefused)
            ));
            id
        };
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        drop(client);
        drop(process);
        let process = reopen_jobs(&fixture).await;
        assert!(matches!(
            exchange(&process, inject(input.admission, input.payload, permit)).await,
            Err(EgressError::PermitRefused)
        ));
        let client = InProcessEgressClient::new(process);
        let JobsReply::Status(row) = job_call(&client, JobsCommand::JobStatus(id)).await.unwrap()
        else {
            panic!("status")
        };
        assert!(matches!(row.state, JobState::Succeeded | JobState::Refused));
        let conn = rusqlite::Connection::open(
            fixture
                .config
                .state_dir
                .join(symbiotic_ai_runtime::QUEUE_DATABASE),
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM spend_receipts", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM egress_permits WHERE consumed=1",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    }
}
