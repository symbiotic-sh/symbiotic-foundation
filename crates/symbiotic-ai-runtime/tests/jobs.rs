//! PR 3 acceptance cases against the real ledger/job transactions.
use async_trait::async_trait;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use symbiotic_ai_runtime::{
    jobs::{ModelJobs, model_job_payload},
    model::{ChatMessage, ModelCapability, ProviderAuthMode, ProviderClass},
    *,
};
use symbiotic_core::{ModelIdentity, TraceId};
use symbiotic_queue::{
    jobs::*,
    runner::{JobRunner, RunnerConfig},
};
use symbiotic_trace::{InvocationOutcome, ModelInvocationTrace, UsageTrace};
use tokio::sync::Notify;

#[derive(Clone)]
struct Provider {
    descriptor: ProviderDescriptor,
    calls: Arc<AtomicUsize>,
    started: Arc<Notify>,
    finish: Option<Arc<Notify>>,
    failures: usize,
    known_zero: bool,
}
impl Provider {
    fn new() -> Self {
        Self {
            descriptor: ProviderDescriptor {
                identity: ModelIdentity::new("chat", "test", "jobs"),
                provider_class: ProviderClass::Cloud,
                capabilities: vec![ModelCapability::Chat],
                auth_mode: ProviderAuthMode::None,
                metadata: serde_json::json!({}),
            },
            calls: Arc::new(AtomicUsize::new(0)),
            started: Arc::new(Notify::new()),
            finish: None,
            failures: 0,
            known_zero: false,
        }
    }
}
impl ModelProvider for Provider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }
    fn failure_charge(&self, _: &ModelError) -> model::FailureCharge {
        if self.known_zero {
            model::FailureCharge::KnownZero
        } else {
            model::FailureCharge::Unknown
        }
    }
}
#[async_trait]
impl ChatProvider for Provider {
    async fn chat(&self, _: ChatRequest) -> Result<ChatResponse, ModelError> {
        let ordinal = self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        if let Ok(path) = std::env::var("FDN_Q3_CRASH_MARKER") {
            std::fs::write(path, b"dispatched").unwrap();
        }
        if let Some(finish) = &self.finish {
            finish.notified().await;
        }
        if ordinal < self.failures {
            return Err(ModelError::Unavailable(
                symbiotic_core::DiagnosticCode::HttpUnavailable,
            ));
        }
        Ok(ChatResponse {
            text: "paid answer".into(),
            finish_reason: Some("stop".into()),
            raw_provider_response: None,
            trace: ModelInvocationTrace {
                trace_id: TraceId::new(),
                queue_item_id: None,
                model: self.descriptor.identity.clone(),
                role_binding: None,
                source: None,
                request_hash: String::new(),
                response_hash: None,
                cache: Default::default(),
                usage: UsageTrace {
                    input_tokens: Some(3),
                    ..Default::default()
                },
                timing: Default::default(),
                outcome: InvocationOutcome::Succeeded,
                error_class: None,
                audit_refs: Vec::new(),
                metadata: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            },
        })
    }
}
fn binding(p: Provider) -> ModelBinding<Provider> {
    ModelBinding::new(p)
        .with_identity(BindingIdentity::new("tenant", "provider", "1", "account"))
        .with_policy(ModelQueueConfig {
            max_in_flight: 1,
            retry_base_delay_ms: 1,
            retry_jitter_seconds: 0,
            ..Default::default()
        })
}
fn request() -> ChatRequest {
    ChatRequest {
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "input".into(),
        }],
        max_output_tokens: Some(2),
        temperature: None,
        response_format: None,
        role_binding: None,
        source: None,
        metadata: serde_json::json!({}),
    }
}
fn runtime(path: &std::path::Path) -> Runtime {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    Runtime::open(RuntimeConfig {
        state_dir: Some(path.into()),
        ..Default::default()
    })
    .unwrap()
}
fn jobs(r: &Runtime, config: JobConfig) -> ModelJobs {
    r.model_jobs(
        JobScope {
            tenant: "tenant".into(),
            incarnation: "1".into(),
            queue: "model".into(),
        },
        config,
    )
    .unwrap()
}
fn spec(key: &str, p: &Provider) -> JobSpec {
    JobSpec {
        key: key.into(),
        group: Some("batch".into()),
        owners: vec!["owner-a".into(), "owner-b".into()],
        kind: "chat".into(),
        execution: Execution::Model,
        payload: model_job_payload(&binding(p.clone()), &request()).unwrap(),
        limits: JobLimits { max_attempts: 1 },
        recovery_until: None,
    }
}
async fn enqueue(j: &ModelJobs, s: JobSpec) -> JobId {
    let JobResponse::Enqueued(rows) = j.request(JobRequest::Enqueue(vec![s])).await.unwrap() else {
        panic!()
    };
    let Enqueued::Inserted(id) = &rows[0] else {
        panic!()
    };
    id.clone()
}
async fn row(j: &ModelJobs, id: &JobId) -> JobRecord {
    let JobResponse::Job(Some(row)) = j.request(JobRequest::Get(id.clone())).await.unwrap() else {
        panic!()
    };
    *row
}
async fn wait_state(j: &ModelJobs, id: &JobId, expected: JobState) -> JobRecord {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let row = row(j, id).await;
            if row.state == expected {
                return row;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}
async fn start(j: &ModelJobs, p: Provider) -> JobRunner {
    j.start_chat(
        binding(p),
        RunnerConfig {
            heartbeat_interval_ms: Some(10),
            poll_interval_ms: 5,
            ..Default::default()
        },
        "chat".into(),
    )
    .await
    .unwrap()
}
fn sql(dir: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(dir.join(QUEUE_DATABASE)).unwrap()
}
fn copies(dir: &std::path::Path) -> usize {
    sql(dir)
        .query_row(
            "SELECT count(*) FROM spend_receipts WHERE recovery IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test]
async fn case_1_paid_commit_and_separate_direct_answer_recover_together() {
    let dir = tempfile::tempdir().unwrap();
    let p = Provider::new();
    {
        let r = runtime(dir.path());
        r.execute_chat(binding(p.clone()), "direct", request())
            .await
            .unwrap();
    }
    let r = runtime(dir.path());
    let j = jobs(&r, JobConfig::default());
    let id = enqueue(&j, spec("direct", &p)).await;
    let runner = start(&j, p.clone()).await;
    wait_state(&j, &id, JobState::Succeeded).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    runner.shutdown().await.unwrap();
    assert_eq!(
        j.completions(1, 10000).await.unwrap()[0]
            .output
            .as_ref()
            .unwrap()["text"],
        "paid answer"
    );
    drop(j);
    drop(r);
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    assert_eq!(row(&j, &id).await.state, JobState::Succeeded);
    assert_eq!(copies(dir.path()), 1);
}

#[tokio::test]
async fn case_2_account_concurrency_one_completes_without_second_slot() {
    let dir = tempfile::tempdir().unwrap();
    let r = runtime(dir.path());
    let j = jobs(&r, JobConfig::default());
    let p = Provider::new();
    let id = enqueue(&j, spec("single-slot", &p)).await;
    let runner = start(&j, p.clone()).await;
    let result = wait_state(&j, &id, JobState::Succeeded).await;
    assert!(result.output.is_none());
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    assert_eq!(copies(dir.path()), 1);
    let delivery = j.completions(1, 10000).await.unwrap().remove(0);
    assert!(delivery.output.is_some());
    j.request(JobRequest::Ack(vec![(
        delivery.delivery.token,
        Disposition::Accepted,
    )]))
    .await
    .unwrap();
    assert_eq!(copies(dir.path()), 0);
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn case_6_restart_backlog_pages_respect_population_and_completion_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let r = runtime(dir.path());
    let config = JobConfig {
        max_live_jobs: 2,
        max_page: 1,
        maintenance_batch: 1,
        ..Default::default()
    };
    let j = jobs(&r, config.clone());
    let p = Provider::new();
    let first = enqueue(&j, spec("one", &p)).await;
    let second = enqueue(&j, spec("two", &p)).await;
    assert!(matches!(
        j.request(JobRequest::Enqueue(vec![spec("three", &p)]))
            .await,
        Err(JobError::QueueFull)
    ));
    drop(j);
    drop(r);
    let j = jobs(&runtime(dir.path()), config);
    let runner = start(&j, p.clone()).await;
    wait_state(&j, &first, JobState::Succeeded).await;
    wait_state(&j, &second, JobState::Succeeded).await;
    assert!(matches!(
        j.completions(1, 100).await,
        Err(JobError::CompletionTooLarge { .. })
    ));
    assert_eq!(row(&j, &first).await.delivery_generation, 0);
    let page = j.completions(1, 10000).await.unwrap();
    assert!(serde_json::to_vec(&page).unwrap().len() <= 10000);
    j.request(JobRequest::Ack(vec![(
        page[0].delivery.token.clone(),
        Disposition::Discarded,
    )]))
    .await
    .unwrap();
    let third = enqueue(&j, spec("three", &p)).await;
    wait_state(&j, &third, JobState::Succeeded).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 3);
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn case_8_pending_past_recovery_until_runs_without_saved_output() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let p = Provider::new();
    let mut s = spec("expired", &p);
    s.recovery_until = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    let id = enqueue(&j, s).await;
    j.request(JobRequest::Maintain).await.unwrap();
    assert!(row(&j, &id).await.payload.is_some());
    let runner = start(&j, p).await;
    let final_row = wait_state(&j, &id, JobState::Succeeded).await;
    assert!(final_row.result_expired);
    assert_eq!(copies(dir.path()), 0);
    assert!(j.completions(1, 10000).await.unwrap()[0].output.is_none());
    let reference = SpendReceiptRef::new(final_row.receipt.unwrap()).unwrap();
    assert_eq!(
        j_runtime_receipt(dir.path(), &reference).state,
        SpendState::Settled
    );
    runner.shutdown().await.unwrap();
}
fn j_runtime_receipt(dir: &std::path::Path, reference: &SpendReceiptRef) -> SpendReceipt {
    spend::SqliteSpendLedger::open(&dir.join(QUEUE_DATABASE))
        .unwrap()
        .receipt(reference)
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn case_12_purge_any_owner_in_flight_settles_without_output_or_copy() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let mut p = Provider::new();
    p.finish = Some(Arc::new(Notify::new()));
    let id = enqueue(&j, spec("purged", &p)).await;
    let runner = start(&j, p.clone()).await;
    p.started.notified().await;
    j.request(JobRequest::PurgeOwner("owner-b".into()))
        .await
        .unwrap();
    p.finish.as_ref().unwrap().notify_one();
    let result = wait_state(&j, &id, JobState::Purged).await;
    assert!(result.payload.is_none() && result.output.is_none());
    assert_eq!(copies(dir.path()), 0);
    assert_eq!(
        j_runtime_receipt(
            dir.path(),
            &SpendReceiptRef::new(result.receipt.unwrap()).unwrap()
        )
        .state,
        SpendState::Settled
    );
    runner.shutdown().await.unwrap();
}

async fn killed_app(test: &str) {
    if let Ok(path) = std::env::var("FDN_Q3_CRASH_DIR") {
        let j = jobs(&runtime(std::path::Path::new(&path)), JobConfig::default());
        let mut p = Provider::new();
        p.finish = Some(Arc::new(Notify::new()));
        enqueue(&j, spec("crash", &p)).await;
        let _runner = start(&j, p).await;
        std::future::pending::<()>().await;
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // A completed job and the interrupted call coexist across whole-app death.
    let committed = {
        let j = jobs(&runtime(dir.path()), JobConfig::default());
        let p = Provider::new();
        let id = enqueue(&j, spec("committed", &p)).await;
        let runner = start(&j, p).await;
        wait_state(&j, &id, JobState::Succeeded).await;
        runner.shutdown().await.unwrap();
        id
    };
    let marker = dir.path().join("dispatch");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("FDN_Q3_CRASH_DIR", dir.path())
        .env("FDN_Q3_CRASH_MARKER", &marker)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !marker.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    sql(dir.path())
        .execute(
            "UPDATE jobs SET lease_until=0, recovery_until=0 WHERE key='crash'",
            [],
        )
        .unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let p = Provider::new();
    let runner = start(&j, p.clone()).await;
    let JobResponse::Diagnostics(page) = j
        .request(JobRequest::Diagnostics {
            group: "batch".into(),
            after: None,
            limit: 10,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    // The recovery loop converts the expired claim; inspect its stable ID via SQL.
    let id: String = sql(dir.path())
        .query_row("SELECT id FROM jobs WHERE key='crash'", [], |r| r.get(0))
        .unwrap();
    let id = JobId {
        scope: JobScope {
            tenant: "tenant".into(),
            incarnation: "1".into(),
            queue: "model".into(),
        },
        id,
    };
    let result = wait_state(&j, &id, JobState::Uncertain).await;
    assert!(result.payload.is_some());
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        j_runtime_receipt(
            dir.path(),
            &SpendReceiptRef::new(result.receipt.unwrap()).unwrap()
        )
        .state,
        SpendState::Unknown
    );
    assert!(page.items.len() <= 10);
    assert_eq!(row(&j, &committed).await.state, JobState::Succeeded);
    assert!(j.completions(1, 10000).await.unwrap()[0].output.is_some());
    j.request(JobRequest::PurgeOwner("owner-a".into()))
        .await
        .unwrap();
    let purged = row(&j, &id).await;
    assert_eq!(purged.state, JobState::Uncertain);
    assert!(purged.payload.is_none());
    runner.shutdown().await.unwrap();
}
#[tokio::test]
async fn case_13_killed_after_dispatch_before_commit_is_uncertain_never_retried() {
    killed_app("case_13_killed_after_dispatch_before_commit_is_uncertain_never_retried").await;
}
#[tokio::test]
async fn case_26_whole_app_crash_without_child_mode_recovers_paid_state() {
    killed_app("case_26_whole_app_crash_without_child_mode_recovers_paid_state").await;
}

#[test]
fn case_22_incompatible_queue_schema_refuses_open_without_changes() {
    let dir = tempfile::tempdir().unwrap();
    drop(runtime(dir.path()));
    let conn = sql(dir.path());
    conn.pragma_update(None, "user_version", 999).unwrap();
    assert!(
        Runtime::open(RuntimeConfig {
            state_dir: Some(dir.path().into()),
            ..Default::default()
        })
        .is_err()
    );
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        999
    );
}

#[tokio::test]
async fn d11_cancel_sent_call_keeps_answer_and_never_retries() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let mut p = Provider::new();
    p.finish = Some(Arc::new(Notify::new()));
    let id = enqueue(&j, spec("cancel", &p)).await;
    let runner = start(&j, p.clone()).await;
    p.started.notified().await;
    j.request(JobRequest::Cancel(Selector::Ids(vec![id.clone()])))
        .await
        .unwrap();
    p.finish.as_ref().unwrap().notify_one();
    wait_state(&j, &id, JobState::Cancelled).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    assert!(j.completions(1, 10000).await.unwrap()[0].output.is_some());
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn paid_result_and_job_completion_roll_back_together() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let p = Provider::new();
    let id = enqueue(&j, spec("rollback", &p)).await;
    sql(dir.path()).execute_batch("CREATE TRIGGER refuse_job_result BEFORE UPDATE OF state ON jobs WHEN NEW.state='\"Succeeded\"' BEGIN SELECT RAISE(ABORT,'synthetic'); END;").unwrap();
    let runner = start(&j, p.clone()).await;
    assert!(runner.wait().await.is_err());
    assert_eq!(row(&j, &id).await.state, JobState::Running);
    assert_eq!(copies(dir.path()), 0);
    let receipt = j_runtime_receipt(
        dir.path(),
        &SpendReceiptRef::new(row(&j, &id).await.receipt.unwrap()).unwrap(),
    );
    assert!(receipt.output.is_none());
    assert_eq!(receipt.state, SpendState::Unknown);
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn claim_and_reservation_roll_back_together() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let p = Provider::new();
    let id = enqueue(&j, spec("reserve-fails", &p)).await;
    sql(dir.path()).execute_batch("CREATE TRIGGER refuse_reservation BEFORE INSERT ON spend_receipts BEGIN SELECT RAISE(ABORT,'synthetic'); END;").unwrap();
    let runner = start(&j, p.clone()).await;
    assert!(runner.wait().await.is_err());
    let row = row(&j, &id).await;
    assert_eq!((row.state, row.generation), (JobState::Pending, 0));
    assert!(row.receipt.is_none());
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn purge_pending_job_discards_separately_committed_direct_answer() {
    let dir = tempfile::tempdir().unwrap();
    let r = runtime(dir.path());
    let p = Provider::new();
    r.execute_chat(binding(p.clone()), "direct-purge", request())
        .await
        .unwrap();
    let j = jobs(&r, JobConfig::default());
    let id = enqueue(&j, spec("direct-purge", &p)).await;
    j.request(JobRequest::PurgeOwner("owner-a".into()))
        .await
        .unwrap();
    assert_eq!(row(&j, &id).await.state, JobState::Purged);
    assert_eq!(copies(dir.path()), 0);
}

#[tokio::test]
async fn paid_delivery_byte_preflight_defers_last_without_leasing_or_loading_it() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let p = Provider::new();
    let first = enqueue(&j, spec("first", &p)).await;
    let second = enqueue(&j, spec("second", &p)).await;
    let runner = start(&j, p).await;
    wait_state(&j, &first, JobState::Succeeded).await;
    wait_state(&j, &second, JobState::Succeeded).await;
    let one = j.completions(1, 10000).await.unwrap();
    let max_bytes = serde_json::to_vec(&one).unwrap().len() + 20;
    sql(dir.path())
        .execute(
            "UPDATE jobs SET delivery_until=NULL,delivery_generation=0",
            [],
        )
        .unwrap();
    let page = j.completions(2, max_bytes).await.unwrap();
    assert_eq!(page.len(), 1);
    assert!(serde_json::to_vec(&page).unwrap().len() <= max_bytes);
    let remaining = if page[0].delivery.completion.id == first {
        second
    } else {
        first
    };
    assert_eq!(row(&j, &remaining).await.delivery_generation, 0);
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn known_zero_retry_uses_frozen_job_ceiling_and_settles_each_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let mut p = Provider::new();
    p.failures = 1;
    p.known_zero = true;
    let mut s = spec("retry", &p);
    s.limits.max_attempts = 2;
    let id = enqueue(&j, s).await;
    let runner = start(&j, p.clone()).await;
    wait_state(&j, &id, JobState::Succeeded).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        sql(dir.path())
            .query_row(
                "SELECT count(*) FROM spend_receipts WHERE state='released'",
                [],
                |r| r.get::<_, usize>(0)
            )
            .unwrap(),
        1
    );
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancelled_sent_failure_keeps_unknown_accounting_and_never_retries() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let mut p = Provider::new();
    p.failures = 10;
    p.finish = Some(Arc::new(Notify::new()));
    let mut s = spec("cancel-failure", &p);
    s.limits.max_attempts = 3;
    let id = enqueue(&j, s).await;
    let runner = start(&j, p.clone()).await;
    p.started.notified().await;
    j.request(JobRequest::Cancel(Selector::Ids(vec![id.clone()])))
        .await
        .unwrap();
    p.finish.as_ref().unwrap().notify_one();
    let cancelled = wait_state(&j, &id, JobState::Cancelled).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        j_runtime_receipt(
            dir.path(),
            &SpendReceiptRef::new(cancelled.receipt.unwrap()).unwrap()
        )
        .state,
        SpendState::Unknown
    );
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn exhausted_account_refuses_job_visibly_without_dispatch_or_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let p = Provider::new();
    let id = enqueue(&j, spec("no-allowance", &p)).await;
    let mut b = binding(p.clone());
    b.policy.as_mut().unwrap().provider_request_limit = Some(0);
    let runner = j
        .start_chat(b, RunnerConfig::default(), "chat".into())
        .await
        .unwrap();
    let refused = wait_state(&j, &id, JobState::Refused).await;
    assert_eq!(
        refused.diagnostic,
        Some(symbiotic_core::DiagnosticCode::SpendBudgetExhausted)
    );
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        sql(dir.path())
            .query_row("SELECT count(*) FROM spend_receipts", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        0
    );
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn ledger_first_committed_answer_recovers_before_new_rate_admission() {
    let dir = tempfile::tempdir().unwrap();
    let p = Provider::new();
    {
        let r = runtime(dir.path());
        r.execute_chat(binding(p.clone()), "rate-recovery", request())
            .await
            .unwrap();
    }
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let id = enqueue(&j, spec("rate-recovery", &p)).await;
    let mut b = binding(p.clone());
    b.policy.as_mut().unwrap().input_units_per_minute = Some(1);
    let runner = j
        .start_chat(b, RunnerConfig::default(), "chat".into())
        .await
        .unwrap();
    wait_state(&j, &id, JobState::Succeeded).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn consumer_cannot_write_model_completion_or_supplant_ledger_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let p = Provider::new();
    let id = enqueue(&j, spec("owned", &p)).await;
    assert!(matches!(
        j.request(JobRequest::Complete {
            job: id.clone(),
            generation: 1,
            state: JobState::Succeeded,
            origin: ResultOrigin::Paid,
            output: None,
            receipt: Some("foreign-receipt".into()),
            diagnostic: None
        })
        .await,
        Err(JobError::InvalidRequest)
    ));
    assert_eq!(row(&j, &id).await.state, JobState::Pending);
}

#[tokio::test]
async fn direct_discard_leaves_accounting_and_reports_unavailable_job_answer() {
    let dir = tempfile::tempdir().unwrap();
    let r = runtime(dir.path());
    let j = jobs(&r, JobConfig::default());
    let p = Provider::new();
    let id = enqueue(&j, spec("discard-direct", &p)).await;
    let runner = start(&j, p.clone()).await;
    wait_state(&j, &id, JobState::Succeeded).await;
    r.discard_invocation_output(
        binding(p).identity.as_ref().unwrap(),
        None,
        "discard-direct",
    )
    .unwrap();
    let page = j.completions(1, 10000).await.unwrap();
    assert!(page[0].output.is_none());
    assert!(page[0].delivery.completion.result_expired);
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn job_limit_cannot_expand_the_execution_owners_provider_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let mut p = Provider::new();
    p.failures = 10;
    p.known_zero = true;
    let mut s = spec("frozen-policy", &p);
    s.limits.max_attempts = 3;
    let id = enqueue(&j, s).await;
    let mut b = binding(p.clone());
    b.policy.as_mut().unwrap().logical_retry_attempts = 1;
    let runner = j
        .start_chat(b, RunnerConfig::default(), "chat".into())
        .await
        .unwrap();
    wait_state(&j, &id, JobState::Refused).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    runner.shutdown().await.unwrap();
}

#[tokio::test]
async fn model_job_failure_reaches_the_existing_trace_sink() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(symbiotic_trace::InMemoryTraceSink::default());
    drop(runtime(dir.path()));
    let r = Runtime::open(RuntimeConfig {
        state_dir: Some(dir.path().into()),
        trace_sink: Some(sink.clone()),
        ..Default::default()
    })
    .unwrap();
    let j = jobs(&r, JobConfig::default());
    let mut p = Provider::new();
    p.failures = 1;
    let id = enqueue(&j, spec("traced-failure", &p)).await;
    let runner = start(&j, p).await;
    wait_state(&j, &id, JobState::Uncertain).await;
    runner.shutdown().await.unwrap();
    assert!(
        sink.records()
            .iter()
            .any(|trace| trace.outcome == InvocationOutcome::Failed)
    );
}

#[tokio::test]
async fn pre_dispatch_heartbeat_failure_releases_accounting_without_transport() {
    let dir = tempfile::tempdir().unwrap();
    let j = jobs(&runtime(dir.path()), JobConfig::default());
    let p = Provider::new();
    let id = enqueue(&j, spec("heartbeat-refused", &p)).await;
    sql(dir.path()).execute_batch("CREATE TRIGGER refuse_dispatch_heartbeat BEFORE UPDATE OF lease_until ON jobs WHEN NEW.state='\"Running\"' AND OLD.receipt=NEW.receipt AND EXISTS(SELECT 1 FROM spend_receipts WHERE reference=NEW.receipt AND state='unknown') BEGIN SELECT RAISE(ABORT,'synthetic'); END;").unwrap();
    let runner = start(&j, p.clone()).await;
    assert!(runner.wait().await.is_err());
    let released = row(&j, &id).await;
    assert_eq!(released.state, JobState::Refused);
    let receipt = j_runtime_receipt(
        dir.path(),
        &SpendReceiptRef::new(released.receipt.unwrap()).unwrap(),
    );
    assert_eq!(receipt.state, SpendState::Released);
    assert!(receipt.pre_dispatch_released);
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}
