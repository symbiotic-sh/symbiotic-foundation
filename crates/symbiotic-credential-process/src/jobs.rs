//! Signed jobs extend the canonical model runner and its claim transaction.
use crate::{
    CredentialProcess, Inner, RouteConfig, RouteProvider, provider,
    secrets::{Secret, SecretSource},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusqlite::Transaction;
use std::sync::{Arc, Weak};
use symbiotic_ai_runtime::{
    jobs::{ModelJobAdmission, ModelJobs, model_job_payload},
    model, *,
};
use symbiotic_egress::*;
use symbiotic_queue::{
    jobs::{Execution, JobLimits, JobRequest, JobResponse, JobSpec, encoded_bytes},
    runner::JobRunner,
};

struct Admission {
    process: Weak<Inner>,
    _lock: Arc<crate::ProcessLock>,
}
fn invalid(_: impl std::fmt::Display) -> JobError {
    JobError::InvalidRequest
}
fn storage(_: impl std::fmt::Display) -> JobError {
    JobError::Storage
}
fn decode(bytes: Option<&[u8]>) -> Result<SignedAttempt, JobError> {
    serde_json::from_slice(bytes.ok_or(JobError::InvalidRequest)?).map_err(invalid)
}
impl Admission {
    fn process(&self) -> Result<CredentialProcess, JobError> {
        Ok(CredentialProcess {
            inner: self.process.upgrade().ok_or(JobError::Unavailable)?,
        })
    }
}
impl ModelJobAdmission for Admission {
    fn enqueue(&self, spec: &JobSpec) -> Result<(), JobError> {
        let process = self.process()?;
        let signed = decode(spec.admission.as_deref())?;
        process.inner.key.verify_attempt(&signed).map_err(invalid)?;
        let route = process.validate_attempt(&signed.attempt).map_err(invalid)?;
        if signed.attempt.invocation_id != spec.key
            || signed.attempt.route != spec.kind
            || route.max_attempts != spec.limits.max_attempts
        {
            return Err(JobError::InvalidRequest);
        }
        Ok(())
    }
    fn admit(&self, row: &JobRecord, bytes: &[u8]) -> Result<bool, JobError> {
        let process = self.process()?;
        let signed = decode(Some(bytes))?;
        process.inner.key.verify_attempt(&signed).map_err(invalid)?;
        process.validate_attempt(&signed.attempt).map_err(invalid)?;
        let old = decode(row.admission.as_deref())?;
        if signed.attempt == old.attempt {
            return Ok(false);
        }
        if crate::invocation_binding(&signed.attempt).map_err(invalid)?
            != crate::invocation_binding(&old.attempt).map_err(invalid)?
            || signed.attempt.attempt_ordinal <= old.attempt.attempt_ordinal
            || signed.attempt.record_sequence <= old.attempt.record_sequence
        {
            return Err(JobError::KeyConflict);
        }
        Ok(true)
    }
    fn accept(
        &self,
        tx: &Transaction<'_>,
        row: &JobRecord,
        reservation: &SpendReservation,
    ) -> Result<(), JobError> {
        let process = self.process()?;
        let signed = decode(row.admission.as_deref())?;
        let route = process.validate_attempt(&signed.attempt).map_err(invalid)?;
        crate::registry::Registry::accept_job_in(
            tx,
            &signed.attempt,
            &reservation.reference,
            route.max_attempts,
        )
        .map_err(|error| match error {
            EgressError::StateUnavailable => JobError::Storage,
            EgressError::AuthorityExpired => JobError::AuthorityExpired,
            EgressError::BudgetRefused => {
                JobError::Execution(model::DiagnosticCode::AttemptBudgetExhausted)
            }
            EgressError::PermitRefused
            | EgressError::ReconciliationRequired
            | EgressError::InvocationComplete => {
                JobError::Execution(model::DiagnosticCode::InvocationCompleted)
            }
            EgressError::InvalidProviderJson => JobError::InvalidRequest,
            other => invalid(other),
        })
    }
    fn before_send(
        &self,
        tx: &Transaction<'_>,
        row: &JobRecord,
        credential_fingerprint: Option<String>,
    ) -> Result<(), JobError> {
        let process = self.process()?;
        let signed = decode(row.admission.as_deref())?;
        let route = process.validate_attempt(&signed.attempt).map_err(invalid)?;
        let key = crate::request_key(route, &signed.attempt.input_digest, credential_fingerprint)
            .map_err(storage)?;
        crate::registry::Registry::admit_request_in(
            tx,
            &digest(&signed.attempt).map_err(storage)?,
            key,
            None,
        )
        .map(|_| ())
        .map_err(|error| match error {
            EgressError::ReconciliationRequired => {
                JobError::Execution(model::DiagnosticCode::SpendReconciliationRequired)
            }
            other => storage(other),
        })
    }
    fn finish(&self, tx: &Transaction<'_>, row: &JobRecord) -> Result<(), JobError> {
        crate::registry::Registry::complete_job_in(
            tx,
            row.receipt.as_deref().ok_or(JobError::Storage)?,
        )
        .map_err(storage)
    }
    fn claim(
        &self,
        tx: &Transaction<'_>,
        row: &JobRecord,
        now: DateTime<Utc>,
    ) -> Result<bool, JobError> {
        let process = self.process()?;
        let signed = decode(row.admission.as_deref())?;
        process.inner.key.verify_attempt(&signed).map_err(invalid)?;
        let route = process.validate_attempt(&signed.attempt).map_err(invalid)?;
        // Configuration rotation may refuse the frozen route; it never rebinds the payload.
        if u64::from(route.max_attempts) < row.generation.saturating_add(1) {
            return Err(JobError::InvalidRequest);
        }
        match crate::registry::Registry::check_revision(tx, &signed.attempt) {
            Ok(()) => {
                Ok(now.timestamp() >= 0 && (now.timestamp() as u64) < signed.attempt.expires_at)
            }
            Err(EgressError::RouteRefused) => Ok(false),
            Err(error) => Err(storage(error)),
        }
    }
}

// Resolve a secret only after the shared model runner has claimed and reserved.
// A route prototype carries configuration/credential-boundary metadata, never a key.
#[derive(Clone)]
struct JobProvider {
    runtime: Runtime,
    route: RouteConfig,
    max_secret_bytes: usize,
    prototype: Arc<dyn ModelProvider>,
    prepared: Option<PreparedAdapter>,
}
#[derive(Clone)]
enum PreparedAdapter {
    Chat(Arc<dyn ChatProvider>),
    Embedding(Arc<dyn EmbeddingProvider>),
    Rerank(Arc<dyn RerankProvider>),
    Classifier(Arc<dyn ClassifierProvider>),
}
// Only local resolution produces this authentication/configuration failure.
// Remote authentication rejection is not evidence of zero charge.
fn credential_unavailable(_: impl std::fmt::Debug) -> ModelError {
    ModelError::Auth(model::DiagnosticCode::InvalidConfiguration)
}
impl JobProvider {
    async fn secret(&self) -> Result<Secret, ModelError> {
        let source = self.route.secret.clone();
        let max = self.max_secret_bytes;
        tokio::task::spawn_blocking(move || match source {
            SecretSource::None => Ok(Secret::keyless()),
            source => Secret::from_bytes(source.load(max)?),
        })
        .await
        .map_err(credential_unavailable)?
        .map_err(credential_unavailable)
    }
}
#[async_trait]
impl ModelProvider for JobProvider {
    async fn prepare_call(&self) -> Result<Self, ModelError> {
        let secret = self.secret().await?;
        let invalid = |_| ModelError::InvalidRequest(model::DiagnosticCode::InvalidConfiguration);
        let prepared = match self.route.provider {
            RouteProvider::OpenAiChat { .. } | RouteProvider::AnthropicChat { .. } => {
                PreparedAdapter::Chat(
                    provider::chat_adapter(&self.route, secret.value()).map_err(invalid)?,
                )
            }
            RouteProvider::GeminiEmbedding { .. } | RouteProvider::CompatibleEmbedding { .. } => {
                PreparedAdapter::Embedding(
                    provider::embedding_adapter(&self.runtime, &self.route, secret.value())
                        .map_err(invalid)?,
                )
            }
            RouteProvider::JevClassifier { .. } => PreparedAdapter::Classifier(
                provider::classifier_adapter(&self.route, secret.value()).map_err(invalid)?,
            ),
            RouteProvider::CohereRerank { .. } => PreparedAdapter::Rerank(
                provider::rerank_adapter(&self.runtime, &self.route, secret.value())
                    .map_err(invalid)?,
            ),
        };
        Ok(Self {
            prepared: Some(prepared),
            ..self.clone()
        })
    }
    fn descriptor(&self) -> &ProviderDescriptor {
        self.prototype.descriptor()
    }
    fn validate_configuration(&self) -> Result<(), ModelError> {
        self.prototype.validate_configuration()
    }
    fn credential_fingerprint(&self) -> Option<String> {
        match &self.prepared {
            Some(PreparedAdapter::Chat(adapter)) => adapter.credential_fingerprint(),
            Some(PreparedAdapter::Embedding(adapter)) => adapter.credential_fingerprint(),
            Some(PreparedAdapter::Rerank(adapter)) => adapter.credential_fingerprint(),
            Some(PreparedAdapter::Classifier(adapter)) => adapter.credential_fingerprint(),
            None => None,
        }
    }
    fn credential_boundary(&self) -> Option<&model::CredentialBoundary> {
        self.prototype.credential_boundary()
    }
    fn failure_charge(&self, error: &ModelError) -> model::FailureCharge {
        if matches!(
            error,
            ModelError::Auth(model::DiagnosticCode::InvalidConfiguration)
        ) {
            model::FailureCharge::KnownZero
        } else {
            self.prototype.failure_charge(error)
        }
    }
}
#[async_trait]
impl ChatProvider for JobProvider {
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
        let Some(PreparedAdapter::Chat(adapter)) = &self.prepared else {
            return Err(ModelError::InvalidRequest(
                model::DiagnosticCode::InvalidConfiguration,
            ));
        };
        let mut response = adapter.chat(request).await?;
        response.raw_provider_response = None;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}
#[async_trait]
impl ClassifierProvider for JobProvider {
    async fn classify(&self, request: ClassifyRequest) -> Result<ClassifyResponse, ModelError> {
        let Some(PreparedAdapter::Classifier(adapter)) = &self.prepared else {
            return Err(ModelError::InvalidRequest(
                model::DiagnosticCode::InvalidConfiguration,
            ));
        };
        let mut response = adapter.classify(request).await?;
        response.raw_provider_response = None;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}
#[async_trait]
impl EmbeddingProvider for JobProvider {
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, ModelError> {
        let Some(PreparedAdapter::Embedding(adapter)) = &self.prepared else {
            return Err(ModelError::InvalidRequest(
                model::DiagnosticCode::InvalidConfiguration,
            ));
        };
        let mut response = adapter.embed(request).await?;
        response.raw_provider_response = None;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}
#[async_trait]
impl RerankProvider for JobProvider {
    async fn rerank(&self, request: RerankRequest) -> Result<RerankResponse, ModelError> {
        let Some(PreparedAdapter::Rerank(adapter)) = &self.prepared else {
            return Err(ModelError::InvalidRequest(
                model::DiagnosticCode::InvalidConfiguration,
            ));
        };
        let mut response = adapter.rerank(request).await?;
        response.raw_provider_response = None;
        response.trace.metadata = serde_json::Value::Null;
        Ok(response)
    }
}
impl CredentialProcess {
    fn model_jobs(&self, scope: JobScope) -> Result<ModelJobs, JobError> {
        self.inner
            .runtime
            .model_jobs(scope, self.inner.config.jobs.clone())
            .map(|jobs| {
                jobs.with_admission(Arc::new(Admission {
                    process: Arc::downgrade(&self.inner),
                    _lock: self.inner._process_lock.clone(),
                }))
            })
    }
    fn job_provider(&self, route: &RouteConfig) -> Result<JobProvider, EgressError> {
        let runtime = &self.inner.runtime;
        let prototype: Arc<dyn ModelProvider> = match route.provider {
            RouteProvider::OpenAiChat { .. } | RouteProvider::AnthropicChat { .. } => {
                provider::chat_adapter(route, "")?
            }
            RouteProvider::GeminiEmbedding { .. } | RouteProvider::CompatibleEmbedding { .. } => {
                provider::embedding_adapter(runtime, route, "")?
            }
            RouteProvider::JevClassifier { .. } => provider::classifier_adapter(route, "")?,
            RouteProvider::CohereRerank { .. } => provider::rerank_adapter(runtime, route, "")?,
        };
        Ok(JobProvider {
            runtime: runtime.clone(),
            route: route.clone(),
            max_secret_bytes: self.inner.config.max_secret_bytes,
            prototype,
            prepared: None,
        })
    }
    async fn start_jobs(
        &self,
        scope: &JobScope,
        jobs: &ModelJobs,
        kind: Option<&str>,
    ) -> Result<(), EgressError> {
        let mut runners = self.inner.job_runners.lock().await;
        for route in self
            .inner
            .routes
            .values()
            .filter(|r| r.tenant == scope.tenant && kind.is_none_or(|kind| kind == r.route))
        {
            let key = serde_json::to_string(&(scope, &route.route))
                .map_err(|_| EgressError::InvalidRequest)?;
            Self::check_job_runner(&mut runners, &key).await?;
            if !jobs
                .needs_execution(route.route.clone())
                .await
                .map_err(|_| EgressError::StateUnavailable)?
            {
                continue;
            }
            if runners.contains_key(&key) {
                continue;
            }
            let binding =
                provider::route_binding(&self.inner.runtime, route, self.job_provider(route)?)?
                    .with_response_cache(ResponseCacheMode::Off);
            // Sleeping observation must not retain admission's process lock.
            // Execution tasks keep their signed jobs owner until they drain.
            let observation = self
                .inner
                .runtime
                .model_jobs(scope.clone(), self.inner.config.jobs.clone())
                .map_err(|_| EgressError::StateUnavailable)?;
            let config = self.inner.config.job_runner.clone();
            let poll = std::time::Duration::from_millis(config.poll_interval_ms);
            let runner = match route.provider {
                RouteProvider::OpenAiChat { .. } | RouteProvider::AnthropicChat { .. } => {
                    jobs.start_chat(binding, config, route.route.clone()).await
                }
                RouteProvider::GeminiEmbedding { .. }
                | RouteProvider::CompatibleEmbedding { .. } => {
                    jobs.start_embedding(binding, config, route.route.clone())
                        .await
                }
                RouteProvider::JevClassifier { .. } => {
                    jobs.start_classifier(binding, config, route.route.clone())
                        .await
                }
                RouteProvider::CohereRerank { .. } => {
                    jobs.start_rerank(binding, config, route.route.clone())
                        .await
                }
            }
            .map_err(|_| EgressError::StateUnavailable)?;
            runners.insert(key.clone(), Some(runner));
            let process = Arc::downgrade(&self.inner);
            let jobs = observation;
            let kind = route.route.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(poll).await;
                    let Some(process) = process.upgrade() else {
                        return;
                    };
                    let mut runners = process.job_runners.lock().await;
                    if Self::check_job_runner(&mut runners, &key).await.is_err()
                        || !runners.contains_key(&key)
                    {
                        return;
                    }
                    // Keep the attachment lock from the canonical lookup through
                    // shutdown/removal. Enqueue's start_jobs either keeps this
                    // runner for new work or starts one after retirement.
                    let needed = jobs.needs_execution(kind.clone()).await;
                    if matches!(needed, Ok(true)) {
                        continue;
                    }
                    if let Some(runner) = runners.insert(key.clone(), None).flatten() {
                        // Successful shutdown is the drained result. Failure
                        // keeps the marker so subsequent operations report it.
                        if runner.shutdown().await.is_ok() && needed.is_ok() {
                            runners.remove(&key);
                        }
                    }
                    return;
                }
            });
        }
        Ok(())
    }
    async fn check_job_runner(
        runners: &mut std::collections::HashMap<String, Option<JobRunner>>,
        key: &str,
    ) -> Result<(), EgressError> {
        if let Some(runner) = runners.get(key)
            && runner.as_ref().is_none_or(JobRunner::is_finished)
        {
            if let Some(runner) = runners.insert(key.into(), None).flatten() {
                runner
                    .wait()
                    .await
                    .map_err(|_| EgressError::StateUnavailable)?;
            }
            return Err(EgressError::StateUnavailable);
        }
        Ok(())
    }
    async fn check_job_runners(&self, scope: &JobScope) -> Result<(), EgressError> {
        let mut runners = self.inner.job_runners.lock().await;
        for route in self
            .inner
            .routes
            .values()
            .filter(|route| route.tenant == scope.tenant)
        {
            let key = serde_json::to_string(&(scope, &route.route))
                .map_err(|_| EgressError::InvalidRequest)?;
            Self::check_job_runner(&mut runners, &key).await?;
        }
        Ok(())
    }
    pub(crate) async fn jobs_operation(
        &self,
        signed: SignedJobsRequest,
    ) -> Result<Reply, EgressError> {
        self.inner.key.verify_jobs(&signed)?;
        let JobsRequest { scope, command } = signed.request;
        if [&scope.tenant, &scope.incarnation, &scope.queue]
            .iter()
            .any(|v| {
                v.is_empty()
                    || v.len()
                        > self
                            .inner
                            .config
                            .routes
                            .iter()
                            .map(|r| r.max_field_bytes)
                            .max()
                            .unwrap_or(0)
            })
            || !self.inner.routes.values().any(|r| r.tenant == scope.tenant)
        {
            return Err(EgressError::Unauthorized);
        }
        // Reject foreign IDs before disclosure, attachment or any mutation.
        let scoped = |id: &JobId| {
            if id.scope == scope {
                Ok(())
            } else {
                Err(EgressError::Unauthorized)
            }
        };
        match &command {
            JobsCommand::AdmitJob { job, admission } => {
                scoped(job)?;
                if admission.attempt.tenant != scope.tenant
                    || admission.attempt.incarnation != scope.incarnation
                    || admission.attempt.job_queue.as_deref() != Some(scope.queue.as_str())
                {
                    return Err(EgressError::Unauthorized);
                }
            }
            JobsCommand::AckJobs(items) => {
                for (token, _) in items {
                    scoped(&token.job)?;
                }
            }
            JobsCommand::CancelJobs(Selector::Ids(ids)) => {
                for id in ids {
                    scoped(id)?;
                }
            }
            JobsCommand::JobStatus(job) => scoped(job)?,
            JobsCommand::EnqueueJobs(items) => {
                for item in items {
                    if item.admission.attempt.tenant != scope.tenant
                        || item.admission.attempt.incarnation != scope.incarnation
                        || item.admission.attempt.job_queue.as_deref() != Some(scope.queue.as_str())
                    {
                        return Err(EgressError::Unauthorized);
                    }
                }
            }
            _ => {}
        }
        self.check_job_runners(&scope).await?;
        let jobs = match self.model_jobs(scope.clone()) {
            Ok(jobs) => jobs,
            Err(error) => return Ok(Reply::Jobs(Err(error))),
        };
        // Own the entire commit-to-attachment sequence. Dropping a direct
        // caller's future cannot cancel attachment after a blocking commit.
        let process = self.clone();
        tokio::spawn(async move { process.run_jobs_operation(scope, jobs, command).await })
            .await
            .map_err(|_| EgressError::Transport)?
    }
    async fn run_jobs_operation(
        &self,
        scope: JobScope,
        jobs: ModelJobs,
        command: JobsCommand,
    ) -> Result<Reply, EgressError> {
        let admitted = match &command {
            JobsCommand::AdmitJob { job, .. } => Some(job.clone()),
            _ => None,
        };
        let result = self.run_jobs_command(&scope, &jobs, command).await;
        let mut execution = Vec::new();
        if let Ok(reply) = &result {
            match reply {
                JobsReply::Enqueued(items) => {
                    for item in items {
                        if let Enqueued::Inserted(id) | Enqueued::Joined(id) = item {
                            execution.push(id.clone());
                        }
                    }
                }
                JobsReply::Admitted => execution.extend(admitted),
                _ => {}
            }
        }
        for id in execution {
            if let JobResponse::Job(Some(row)) = jobs
                .request(JobRequest::Status(id))
                .await
                .map_err(|_| EgressError::StateUnavailable)?
                && matches!(
                    row.state,
                    JobState::Pending | JobState::Running | JobState::Uncertain
                )
            {
                self.start_jobs(&scope, &jobs, Some(&row.kind)).await?;
            }
        }
        Ok(Reply::Jobs(result))
    }
    async fn run_jobs_command(
        &self,
        scope: &JobScope,
        jobs: &ModelJobs,
        command: JobsCommand,
    ) -> Result<JobsReply, JobError> {
        let purging = matches!(&command, JobsCommand::PurgeOwner(_));
        let request = match command {
            JobsCommand::EnqueueJobs(items) => {
                if items.len() > self.inner.config.jobs.max_batch {
                    return Err(JobError::InvalidRequest);
                }
                let mut specs = Vec::with_capacity(items.len());
                for mut item in items {
                    self.inner
                        .key
                        .verify_attempt(&item.admission)
                        .map_err(invalid)?;
                    let attempt = &item.admission.attempt;
                    let route = self.validate_attempt(attempt).map_err(invalid)?;
                    crate::validate_payload(route, &item.payload).map_err(invalid)?;
                    if item.payload.digest().map_err(invalid)? != attempt.input_digest {
                        return Err(JobError::KeyConflict);
                    }
                    provider::prepare_payload(
                        &mut item.payload,
                        &jobs.invocation_key(&attempt.invocation_id)?,
                    );
                    let binding = provider::route_binding(
                        &self.inner.runtime,
                        route,
                        self.job_provider(route).map_err(invalid)?,
                    )
                    .map_err(invalid)?;
                    let payload = match &item.payload {
                        ProviderPayload::Chat(request) => model_job_payload(&binding, request)?,
                        ProviderPayload::Embedding(request) => {
                            model_job_payload(&binding, request)?
                        }
                        ProviderPayload::Rerank(request) => model_job_payload(&binding, request)?,
                        ProviderPayload::Classify(request) => model_job_payload(&binding, request)?,
                    };
                    // Bind immutable caller/manifest/provider fields to key-conflict checks,
                    // while excluding renewable authority and attempt ordinals.
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&payload).map_err(invalid)?;
                    value["egress_binding"] = serde_json::Value::String(
                        crate::invocation_binding(attempt).map_err(invalid)?,
                    );
                    specs.push(JobSpec {
                        key: attempt.invocation_id.clone(),
                        kind: attempt.route.clone(),
                        group: item.group,
                        owners: item.owners,
                        execution: Execution::Model,
                        payload: serde_json::to_vec(&value).map_err(storage)?,
                        admission: Some(serde_json::to_vec(&item.admission).map_err(storage)?),
                        limits: JobLimits {
                            max_attempts: route.max_attempts,
                        },
                        recovery_until: Some(
                            DateTime::from_timestamp(attempt.recovery_expires_at as i64, 0)
                                .ok_or(JobError::InvalidRequest)?,
                        ),
                    });
                }
                JobRequest::Enqueue(specs)
            }
            JobsCommand::AdmitJob { job, admission } => JobRequest::Admit {
                job,
                admission: serde_json::to_vec(&admission).map_err(storage)?,
            },
            JobsCommand::AckJobs(acks) => JobRequest::Ack(acks),
            JobsCommand::CancelJobs(target) => JobRequest::Cancel(target),
            JobsCommand::PurgeOwner(owner) => JobRequest::PurgeOwner(owner),
            JobsCommand::JobStatus(job) => JobRequest::Status(job),
            JobsCommand::Completions {
                limit,
                max_bytes,
                wait_seconds,
            } => {
                let empty = JobsCompletions {
                    items: Vec::new(),
                    notices: Vec::new(),
                };
                let body_bytes = encoded_bytes(&empty)?;
                let frame_bytes = encode_frame(
                    &Response {
                        version: PROTOCOL_VERSION,
                        result: Ok(Reply::Jobs(Ok(JobsReply::Completions(empty)))),
                    },
                    self.inner.config.max_frame_bytes,
                )
                .map_err(invalid)?
                .len();
                let envelope_bytes = frame_bytes
                    .checked_sub(body_bytes)
                    .ok_or(JobError::Storage)?;
                if wait_seconds > self.inner.config.io_timeout_seconds
                    || max_bytes
                        > (self.inner.config.max_frame_bytes as usize)
                            .saturating_sub(envelope_bytes)
                {
                    return Err(JobError::InvalidRequest);
                }
                let until = tokio::time::Instant::now()
                    .checked_add(std::time::Duration::from_secs(wait_seconds))
                    .ok_or(JobError::InvalidRequest)?;
                let overhead = body_bytes - 2;
                loop {
                    let delivery_bytes = max_bytes
                        .checked_sub(overhead)
                        .filter(|n| *n >= 2)
                        .ok_or(JobError::InvalidRequest)?;
                    let items = jobs
                        .completions(limit, delivery_bytes)
                        .await
                        .map_err(|error| match error {
                            JobError::CompletionTooLarge { job, bytes } => {
                                JobError::CompletionTooLarge {
                                    job,
                                    bytes: bytes + overhead,
                                }
                            }
                            other => other,
                        })?
                        .into_iter()
                        .map(|item| JobDelivery {
                            delivery: item.delivery,
                            output: item.output,
                        })
                        .collect::<Vec<_>>();
                    let mut page = JobsCompletions {
                        items,
                        notices: Vec::new(),
                    };
                    let mut used = encoded_bytes(&page)?;
                    if used > max_bytes {
                        return Err(JobError::InvalidRequest);
                    }
                    if page.items.len() < limit {
                        let JobResponse::Diagnostics(notices) = jobs
                            .request(JobRequest::AdmissionNotices {
                                limit: limit - page.items.len(),
                            })
                            .await?
                        else {
                            return Err(JobError::Storage);
                        };
                        for notice in notices.items {
                            let size =
                                encoded_bytes(&notice)? + usize::from(!page.notices.is_empty());
                            if used + size > max_bytes {
                                if page.items.is_empty() && page.notices.is_empty() {
                                    return Err(JobError::CompletionTooLarge {
                                        job: notice.id,
                                        bytes: used + size,
                                    });
                                }
                                break;
                            }
                            used += size;
                            page.notices.push(notice);
                        }
                    }
                    if page.items.is_empty() && page.notices.is_empty() {
                        self.start_jobs(scope, jobs, None)
                            .await
                            .map_err(|_| JobError::Unavailable)?;
                    }
                    if !page.items.is_empty()
                        || !page.notices.is_empty()
                        || tokio::time::Instant::now() >= until
                    {
                        return Ok(JobsReply::Completions(page));
                    }
                    tokio::time::sleep(
                        std::time::Duration::from_millis(
                            self.inner.config.job_runner.poll_interval_ms,
                        )
                        .min(until.saturating_duration_since(tokio::time::Instant::now())),
                    )
                    .await;
                }
            }
        };
        match jobs.request(request).await? {
            JobResponse::Enqueued(items) => Ok(JobsReply::Enqueued(items)),
            JobResponse::Acks(items) => Ok(JobsReply::Acked(items)),
            JobResponse::Changed(count) if purging => Ok(JobsReply::Purged(count)),
            JobResponse::Changed(count) => Ok(JobsReply::Cancelled(count)),
            JobResponse::Done => Ok(JobsReply::Admitted),
            JobResponse::Job(Some(mut row)) => {
                row.payload = None;
                row.admission = None;
                row.output = None;
                Ok(JobsReply::Status(row))
            }
            JobResponse::Job(None) => Err(JobError::NotFound),
            _ => Err(JobError::InvalidRequest),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use symbiotic_queue::jobs::{Enqueued, JobConfig, JobState};

    struct RetirementFixture {
        process: CredentialProcess,
        jobs: ModelJobs,
        scope: JobScope,
        key: String,
        server: tokio::task::JoinHandle<()>,
        _dir: Arc<tempfile::TempDir>,
    }

    impl Drop for RetirementFixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl RetirementFixture {
        async fn new() -> Self {
            Self::with_poll(1).await
        }

        async fn with_poll(poll_interval_ms: u64) -> Self {
            use std::os::unix::fs::PermissionsExt;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let dir = tempfile::tempdir().unwrap();
            let admission = dir.path().join("admission");
            std::fs::write(&admission, [0u8; 32]).unwrap();
            std::fs::set_permissions(&admission, std::fs::Permissions::from_mode(0o600)).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    tokio::time::timeout(std::time::Duration::from_secs(60), async {
                        let mut request = Vec::new();
                        loop {
                            let mut bytes = [0; 4096];
                            let count = stream.read(&mut bytes).await.unwrap();
                            assert_ne!(count, 0);
                            request.extend_from_slice(&bytes[..count]);
                            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                                let headers = String::from_utf8_lossy(&request[..end]);
                                let len: usize = headers.lines().find_map(|line| {
                                    line.to_ascii_lowercase().strip_prefix("content-length: ")?.parse().ok()
                                }).unwrap();
                                if request.len() >= end + 4 + len { break; }
                            }
                        }
                        let body = r#"{"choices":[{"message":{"content":"answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
                        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        stream.write_all(response.as_bytes()).await.unwrap();
                    }).await.unwrap();
                }
            });
            let config = serde_json::from_value(serde_json::json!({
                "version": PROTOCOL_VERSION, "state_dir": dir.path().join("state"),
                "socket_path": dir.path().join("unused.sock"),
                "admission_key": {"backend": "owner_only_file", "path": admission},
                "max_secret_bytes": 4096, "max_frame_bytes": 262144,
                "max_connections": 8, "io_timeout_seconds": 2,
                "job_runner": {"version": 1, "worker_count": 1, "poll_interval_ms": poll_interval_ms,
                    "heartbeat_interval_ms": null, "maintenance_interval_ms": 60000},
                "routes": [{"tenant": "tenant", "account": "account", "account_sharing_key": null,
                    "max_attempts": 1, "route": "chat", "secret_ref": "", "secret": {"backend": "none"},
                    "destination": format!("http://{address}/v1"), "model": "test-model",
                    "provider": {"kind": "open_ai_chat", "operator": "test"},
                    "allow_loopback_http": true, "max_field_bytes": 1024, "max_output_tokens": 10,
                    "max_input_bytes": 32768, "max_response_bytes": 32768,
                    "max_in_flight": 1, "requests_per_minute": null, "input_units_per_minute": null,
                    "timeout_seconds": 1}]
            })).unwrap();
            let process = CredentialProcess::open(config).unwrap();
            let scope = JobScope {
                tenant: "tenant".into(),
                incarnation: "incarnation".into(),
                queue: "jobs".into(),
            };
            // Trusted embedded jobs avoid signed-admission setup; the actual route
            // runner, store, retirement watcher and attachment lock are unchanged.
            let jobs = process
                .inner
                .runtime
                .model_jobs(scope.clone(), JobConfig::default())
                .unwrap();
            let key = serde_json::to_string(&(&scope, "chat")).unwrap();
            Self {
                process,
                jobs,
                scope,
                key,
                server,
                _dir: Arc::new(dir),
            }
        }

        async fn enqueue(&self, key: &str) -> JobId {
            let route = &self.process.inner.config.routes[0];
            let binding = provider::route_binding(
                &self.process.inner.runtime,
                route,
                self.process.job_provider(route).unwrap(),
            )
            .unwrap();
            let request = ChatRequest {
                messages: vec![model::ChatMessage {
                    role: "user".into(),
                    content: "input".into(),
                }],
                max_output_tokens: Some(10),
                temperature: None,
                response_format: None,
                role_binding: None,
                source: None,
                metadata: serde_json::Value::Null,
            };
            let spec = JobSpec {
                key: key.into(),
                group: None,
                owners: vec![],
                kind: "chat".into(),
                execution: Execution::Model,
                payload: model_job_payload(&binding, &request).unwrap(),
                admission: None,
                limits: JobLimits { max_attempts: 1 },
                recovery_until: None,
            };
            let JobResponse::Enqueued(items) = self
                .jobs
                .request(JobRequest::Enqueue(vec![spec]))
                .await
                .unwrap()
            else {
                panic!("enqueue")
            };
            let Enqueued::Inserted(id) = &items[0] else {
                panic!("inserted")
            };
            id.clone()
        }

        fn signed_enqueue(&self, key: &str) -> Request {
            let route = &self.process.inner.config.routes[0];
            let payload = ProviderPayload::Chat(ChatRequest {
                messages: vec![model::ChatMessage {
                    role: "user".into(),
                    content: "input".into(),
                }],
                max_output_tokens: Some(10),
                temperature: None,
                response_format: None,
                role_binding: None,
                source: None,
                metadata: serde_json::Value::Null,
            });
            let now = Utc::now().timestamp() as u64;
            let admission = self
                .process
                .inner
                .key
                .sign_attempt(DurableAttempt {
                    tenant: self.scope.tenant.clone(),
                    incarnation: self.scope.incarnation.clone(),
                    invocation_id: key.into(),
                    job_queue: Some(self.scope.queue.clone()),
                    attempt_ordinal: 1,
                    record_sequence: 1,
                    recorded_at: now,
                    expires_at: now + 3600,
                    recovery_expires_at: now + 3600,
                    caller_binding: "caller".into(),
                    route: route.route.clone(),
                    destination: route.destination.clone(),
                    model: route.model.clone(),
                    method: "POST".into(),
                    secret_ref: route.secret_ref.clone(),
                    manifest_ref: "manifest".into(),
                    input_manifest_digest: "a".repeat(64),
                    input_digest: payload.digest().unwrap(),
                    grant_revision: 1,
                })
                .unwrap();
            self.process
                .inner
                .registry
                .lock()
                .unwrap()
                .publish_revision(&GrantRevision {
                    tenant: self.scope.tenant.clone(),
                    incarnation: self.scope.incarnation.clone(),
                    revision: 1,
                })
                .unwrap();
            let signed = self
                .process
                .inner
                .key
                .sign_jobs(JobsRequest {
                    scope: self.scope.clone(),
                    command: JobsCommand::EnqueueJobs(vec![EnqueueJob {
                        admission,
                        payload,
                        group: None,
                        owners: vec![],
                    }]),
                })
                .unwrap();
            Request {
                version: PROTOCOL_VERSION,
                operation: signed.operation(),
            }
        }

        fn committed_id(&self, key: &str) -> Option<JobId> {
            use rusqlite::OptionalExtension;
            let conn = rusqlite::Connection::open(
                self.process
                    .inner
                    .config
                    .state_dir
                    .join(symbiotic_ai_runtime::QUEUE_DATABASE),
            )
            .unwrap();
            let id = conn
                .query_row("SELECT id FROM jobs WHERE key=?1", [key], |row| row.get(0))
                .optional()
                .unwrap()?;
            Some(JobId {
                scope: self.scope.clone(),
                id,
            })
        }

        async fn succeeded(&self, id: &JobId) {
            loop {
                let JobResponse::Job(Some(row)) = self
                    .jobs
                    .request(JobRequest::Status(id.clone()))
                    .await
                    .unwrap()
                else {
                    panic!("status")
                };
                if row.state == JobState::Succeeded {
                    return;
                }
                assert!(row.state.unfinished(), "job failed: {:?}", row.state);
                tokio::task::yield_now().await;
            }
        }

        async fn drain_barrier(
            &self,
            fail: bool,
        ) -> (
            Arc<tokio::sync::Semaphore>,
            Arc<AtomicUsize>,
            Arc<tokio::sync::Notify>,
        ) {
            let first = self.enqueue("first").await;
            self.process
                .start_jobs(&self.scope, &self.jobs, Some("chat"))
                .await
                .unwrap();
            let mut runners = self.process.inner.job_runners.lock().await;
            self.succeeded(&first).await;
            // Hold the real attachment lock so the real watcher cannot retire
            // before a deterministic shutdown barrier is installed.
            runners
                .remove(&self.key)
                .flatten()
                .unwrap()
                .shutdown()
                .await
                .unwrap();
            let draining = Arc::new(tokio::sync::Semaphore::new(0));
            let release = Arc::new(tokio::sync::Semaphore::new(0));
            let polls = Arc::new(AtomicUsize::new(0));
            let tick = Arc::new(tokio::sync::Notify::new());
            let runner = JobRunner::start_owned(
                1,
                {
                    let polls = polls.clone();
                    let tick = tick.clone();
                    move |mut stop| {
                        let polls = polls.clone();
                        let tick = tick.clone();
                        async move {
                            loop {
                                if *stop.borrow() {
                                    return Ok(());
                                }
                                polls.fetch_add(1, Ordering::SeqCst);
                                tokio::select! { _ = stop.changed() => {}, _ = tick.notified() => {} }
                            }
                        }
                    }
                },
                {
                    let draining = draining.clone();
                    let release = release.clone();
                    move |mut stop| async move {
                        while !*stop.borrow_and_update() {
                            stop.changed().await.unwrap();
                        }
                        draining.add_permits(1);
                        release.acquire().await.unwrap().forget();
                        if fail {
                            Err(symbiotic_queue::runner::RunnerError::Store(
                                JobError::Storage,
                            ))
                        } else {
                            Ok(())
                        }
                    }
                },
            );
            runners.insert(self.key.clone(), Some(runner));
            while polls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            drop(runners);
            draining.acquire().await.unwrap().forget();
            (release, polls, tick)
        }
    }

    #[tokio::test]
    async fn drained_scope_removes_runner_and_stops_polling() {
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let fixture = RetirementFixture::new().await;
            let (release, polls, tick) = fixture.drain_barrier(false).await;
            release.add_permits(1);
            loop {
                if fixture.process.inner.job_runners.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let before = polls.load(Ordering::SeqCst);
            tick.notify_one();
            fixture
                .process
                .check_job_runners(&fixture.scope)
                .await
                .unwrap();
            assert_eq!(
                polls.load(Ordering::SeqCst),
                before,
                "joined workers cannot poll again"
            );
            eprintln!(
                "drained scope: attachment removed; worker and maintenance joined; polls={before}"
            );
        })
        .await
        .expect("60 s drain hang guard");
    }

    #[tokio::test]
    async fn enqueue_racing_drain_starts_runner_and_completes_job() {
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let fixture = RetirementFixture::new().await;
            let (release, _, _) = fixture.drain_barrier(false).await;
            // Canonical enqueue commits while retirement holds the attachment
            // lock and awaits maintenance. start_jobs must wait, then replace it.
            let next = fixture.enqueue("next").await;
            assert!(fixture.process.inner.job_runners.try_lock().is_err());
            let process = fixture.process.clone();
            let jobs = fixture.jobs.clone();
            let scope = fixture.scope.clone();
            let start =
                tokio::spawn(async move { process.start_jobs(&scope, &jobs, Some("chat")).await });
            release.add_permits(1);
            start.await.unwrap().unwrap();
            fixture.succeeded(&next).await;
            eprintln!("enqueue during retirement: replacement runner completed the job");
        })
        .await
        .expect("60 s enqueue/drain hang guard");
    }

    #[tokio::test]
    async fn drained_scope_preserves_real_runner_failure() {
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let fixture = RetirementFixture::new().await;
            let (release, _, _) = fixture.drain_barrier(true).await;
            release.add_permits(1);
            let runners = fixture.process.inner.job_runners.lock().await;
            assert!(
                runners.get(&fixture.key).unwrap().is_none(),
                "maintenance failure must leave the failure marker"
            );
            drop(runners);
            for _ in 0..2 {
                assert!(matches!(
                    fixture.process.check_job_runners(&fixture.scope).await,
                    Err(EgressError::StateUnavailable)
                ));
            }
            assert!(matches!(
                fixture
                    .process
                    .start_jobs(&fixture.scope, &fixture.jobs, Some("chat"))
                    .await,
                Err(EgressError::StateUnavailable)
            ));
            eprintln!("drained scope: real maintenance failure remains StateUnavailable");
        })
        .await
        .expect("60 s failure visibility hang guard");
    }

    #[tokio::test]
    async fn cancelled_direct_enqueue_still_attaches_and_executes() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let fixture = RetirementFixture::new().await;
            let request = fixture.signed_enqueue("cancelled-caller");
            let mut handler = Box::pin(fixture.process.handle(request));
            // One poll passes the uncontended attachment check and starts the
            // blocking enqueue (or its owned task), before returning Pending.
            std::future::poll_fn(|cx| {
                assert!(handler.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            let runners = fixture.process.inner.job_runners.lock().await;
            let id = loop {
                if let Some(id) = fixture.committed_id("cancelled-caller") {
                    break id;
                }
                tokio::task::yield_now().await;
            };
            // The canonical row committed while runner attachment is blocked.
            drop(handler);
            drop(runners);
            fixture.succeeded(&id).await;
            eprintln!("cancelled direct enqueue: committed job attached and succeeded");
        })
        .await
        .expect("5 s cancelled enqueue regression bound");
    }

    #[tokio::test]
    async fn stopped_signed_workers_allow_reopen_before_retirement_poll() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let fixture = RetirementFixture::with_poll(60_000).await;
            let request = fixture.signed_enqueue("reopen");
            let response = fixture.process.handle(request).await;
            assert!(matches!(
                response.result,
                Ok(Reply::Jobs(Ok(JobsReply::Enqueued(_))))
            ));
            let id = fixture.committed_id("reopen").unwrap();
            fixture.succeeded(&id).await;
            let config = fixture.process.inner.config.clone();
            let _dir = fixture._dir.clone();
            let process = fixture.process.clone();
            let jobs = fixture.jobs.clone();
            drop(fixture);
            drop(jobs);
            drop(process);
            // Reopen waits only for execution tasks to observe stop and drain,
            // never for the 60-second retirement observer's next poll.
            loop {
                match CredentialProcess::open(config.clone()) {
                    Ok(reopened) => {
                        drop(reopened);
                        break;
                    }
                    Err(EgressError::StateUnavailable) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected reopen error: {error:?}"),
                }
            }
            eprintln!("signed workers stopped: reopened before the 60 s observer poll");
        })
        .await
        .expect("5 s signed worker reopen regression bound");
    }

    #[derive(Clone)]
    struct CountedChat {
        prototype: Arc<dyn ModelProvider>,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl ModelProvider for CountedChat {
        fn descriptor(&self) -> &ProviderDescriptor {
            self.prototype.descriptor()
        }
        fn credential_boundary(&self) -> Option<&model::CredentialBoundary> {
            self.prototype.credential_boundary()
        }
    }
    #[async_trait]
    impl ChatProvider for CountedChat {
        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, ModelError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            model::StaticChatProvider::new("answer").chat(request).await
        }
    }

    #[tokio::test]
    async fn signed_jobs_refuse_unfinished_requests_and_retire_unknown_completions() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let admission_path = dir.path().join("admission");
            std::fs::write(&admission_path, [0u8; 32]).unwrap();
            std::fs::set_permissions(&admission_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let route: RouteConfig = serde_json::from_value(serde_json::json!({
                "tenant": "tenant", "account": "account", "account_sharing_key": null,
                "max_attempts": 3, "request_budget": {"attempts": 3, "renewal_seconds": null},
                "route": "chat", "secret_ref": "", "secret": {"backend": "none"},
                "destination": "https://example.com/v1", "model": "test-model",
                "provider": {"kind": "open_ai_chat", "operator": "test"},
                "allow_loopback_http": false, "max_field_bytes": 1024, "max_output_tokens": 100,
                "max_in_flight": 4, "requests_per_minute": null, "input_units_per_minute": null,
                "timeout_seconds": 1
            }))
            .unwrap();
            let config = crate::ProcessConfig {
                version: PROTOCOL_VERSION,
                state_dir: dir.path().join("state"),
                socket_path: dir.path().join("unused.sock"),
                admission_key: SecretSource::OwnerOnlyFile {
                    path: admission_path,
                },
                max_secret_bytes: 4096,
                max_frame_bytes: 8 * model::DEFAULT_MAX_RESPONSE_BYTES as u32,
                max_connections: 8,
                io_timeout_seconds: 2,
                clock_rollback_warning_tolerance_seconds: 5,
                jobs: JobConfig::default(),
                job_runner: Default::default(),
                routes: vec![route.clone()],
            };
            let process = CredentialProcess::open(config.clone()).unwrap();
            let request = ChatRequest {
                messages: vec![model::ChatMessage {
                    role: "user".into(),
                    content: "input".into(),
                }],
                max_output_tokens: Some(10),
                temperature: None,
                response_format: None,
                role_binding: None,
                source: None,
                metadata: serde_json::Value::Null,
            };
            let now = chrono::Utc::now().timestamp() as u64;
            let mut attempt = DurableAttempt {
                tenant: "tenant".into(),
                incarnation: "incarnation".into(),
                invocation_id: "unfinished".into(),
                job_queue: None,
                attempt_ordinal: 1,
                record_sequence: 1,
                recorded_at: now,
                expires_at: now + 3600,
                recovery_expires_at: now + 3600,
                caller_binding: "caller".into(),
                route: "chat".into(),
                destination: route.destination.clone(),
                model: route.model.clone(),
                method: "POST".into(),
                secret_ref: "".into(),
                manifest_ref: "manifest".into(),
                input_manifest_digest: "a".repeat(64),
                input_digest: ProviderPayload::Chat(request.clone()).digest().unwrap(),
                grant_revision: 1,
            };
            let original = {
                let mut registry = process.inner.registry.lock().unwrap();
                registry
                    .publish_revision(&GrantRevision {
                        tenant: "tenant".into(),
                        incarnation: "incarnation".into(),
                        revision: 1,
                    })
                    .unwrap();
                let permit = registry.issue(&attempt, 3).unwrap().permit;
                let handoff = model::AcceptedSpendHandoff {
                    reservation: crate::spend_reservation(&attempt, &route).unwrap(),
                    input_identity: "input".into(),
                };
                let receipt = registry.consume(&attempt, &permit, &handoff, 3).unwrap();
                registry
                    .admit_request(
                        &receipt.attempt_digest,
                        model::configuration_revision(&(
                            &route.tenant,
                            &route.route,
                            None::<String>,
                            &attempt.input_digest,
                        ))
                        .unwrap()
                        .0,
                        route.request_budget.as_ref(),
                    )
                    .unwrap();
                receipt
            };
            drop(process);
            let process = CredentialProcess::open(config).unwrap();
            let scope = JobScope {
                tenant: "tenant".into(),
                incarnation: "incarnation".into(),
                queue: "jobs".into(),
            };
            let jobs = process.model_jobs(scope.clone()).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = CountedChat {
                prototype: process.job_provider(&route).unwrap().prototype,
                calls: calls.clone(),
            };
            let binding = provider::route_binding(&process.inner.runtime, &route, counted)
                .unwrap()
                .with_response_cache(ResponseCacheMode::Off);
            let runner = jobs
                .start_chat(binding.clone(), Default::default(), "chat".into())
                .await
                .unwrap();
            attempt.job_queue = Some(scope.queue);
            for (key, expected) in [
                ("refused", JobState::Failed),
                ("resolved", JobState::Succeeded),
                ("completed", JobState::Succeeded),
            ] {
                attempt.invocation_id = key.into();
                let signed = process.inner.key.sign_attempt(attempt.clone()).unwrap();
                let spec = JobSpec {
                    key: key.into(),
                    group: None,
                    owners: vec![],
                    kind: "chat".into(),
                    execution: Execution::Model,
                    payload: model_job_payload(&binding, &request).unwrap(),
                    admission: Some(serde_json::to_vec(&signed).unwrap()),
                    limits: JobLimits { max_attempts: 3 },
                    recovery_until: None,
                };
                let JobResponse::Enqueued(items) =
                    jobs.request(JobRequest::Enqueue(vec![spec])).await.unwrap()
                else {
                    panic!("enqueue")
                };
                let Enqueued::Inserted(id) = &items[0] else {
                    panic!("inserted")
                };
                let row = loop {
                    let JobResponse::Job(Some(row)) =
                        jobs.request(JobRequest::Get(id.clone())).await.unwrap()
                    else {
                        panic!("job")
                    };
                    if !row.state.unfinished() {
                        break row;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                };
                assert_eq!(row.state, expected);
                if key == "refused" {
                    assert_eq!(
                        row.diagnostic,
                        Some(model::DiagnosticCode::SpendReconciliationRequired)
                    );
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                    assert_eq!(
                        process
                            .inner
                            .registry
                            .lock()
                            .unwrap()
                            .receipt(&original.attempt_id)
                            .unwrap()
                            .unwrap()
                            .spend_state,
                        SpendState::Unknown
                    );
                    let ledger = symbiotic_ai_runtime::spend::SqliteSpendLedger::open(
                        &process
                            .inner
                            .config
                            .state_dir
                            .join(symbiotic_ai_runtime::QUEUE_DATABASE),
                    )
                    .unwrap();
                    let refused_ref =
                        SpendReceiptRef::new(row.receipt.as_deref().unwrap()).unwrap();
                    assert_eq!(
                        model::SpendLedger::receipt(&ledger, &refused_ref)
                            .unwrap()
                            .unwrap()
                            .state,
                        SpendState::Released
                    );
                    model::SpendLedger::finish(
                        &ledger,
                        &original.reference,
                        SpendState::Released,
                        None,
                        None,
                        None,
                    )
                    .unwrap();
                }
            }
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            let conn = rusqlite::Connection::open(
                process
                    .inner
                    .config
                    .state_dir
                    .join(symbiotic_ai_runtime::QUEUE_DATABASE),
            )
            .unwrap();
            let debits: u32 = conn
                .query_row(
                    "SELECT failed_sends FROM egress_request_failures",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(debits, 1, "signed jobs preserve their per-job allowance");
            runner.shutdown().await.unwrap();
        })
        .await
        .expect("bounded signed job request guard and completion");
    }
}
