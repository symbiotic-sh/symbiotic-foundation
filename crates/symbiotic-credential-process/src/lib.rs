//! Credential-owning WP14 daemon. Memory depends on `symbiotic-egress`, not this crate.
//! Credentials are resolved only after a single-use permit is durably consumed.

#[cfg(unix)]
mod process_security;
#[cfg(unix)]
pub use process_security::protect_process;

mod in_process;
pub use in_process::InProcessEgressClient;

mod provider;
mod registry;
pub mod secrets;
#[cfg(unix)]
pub mod server;

use registry::Registry;
use secrets::{Secret, SecretSource};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use symbiotic_ai_runtime::{Runtime, RuntimeConfig};
use symbiotic_egress::*;

/// Supported pinned provider transports.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteProvider {
    /// Existing OpenAI-compatible chat adapter.
    OpenAiChat { operator: String },
    /// Anthropic Messages with explicit thinking mode.
    AnthropicChat {
        /// Provider identity.
        operator: String,
        /// Enabled maps to adaptive thinking; Disabled is explicit; None omits it.
        thinking: Option<symbiotic_ai_runtime::model::ThinkingMode>,
    },
    /// Existing Gemini embedding adapter, pinned to Google's service.
    GeminiEmbedding { dimensions: usize },
    /// Compatible embedding protocol and explicit dimensions, resolved by the registry.
    CompatibleEmbedding {
        /// OpenAI batch or Ollama single-input protocol.
        adapter: symbiotic_ai_runtime::model::ModelAdapter,
        /// Provider identity; never inferred from endpoint/model text.
        operator: String,
        /// Default output dimensions.
        dimensions: usize,
        /// Full-vector ceiling for reduced-dimension requests.
        embedding_full_dimensions: usize,
        /// Usable input token capacity after provider/model special/task tokens.
        embedding_input_tokens: usize,
    },
    /// Cohere-compatible rerank protocol with hard candidate/input bounds.
    CohereRerank {
        /// Provider identity.
        operator: String,
        /// Maximum sum of query and candidate UTF-8 bytes.
        rerank_input_bytes: usize,
        /// Maximum candidate count.
        rerank_candidates: usize,
        /// Usable query/document token capacity after provider/model overhead.
        rerank_context_tokens: usize,
        /// Provider/model query token capacity.
        rerank_query_tokens: usize,
    },
}

/// Route configured by the credential-process owner. No defaults for safety limits.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Tenant namespace.
    pub tenant: String,
    /// Concrete account identity, scoped to this tenant unless explicitly shared.
    pub account: String,
    /// Explicit account quota sharing across routes or tenants.
    pub account_sharing_key: Option<symbiotic_ai_runtime::AccountSharingKey>,
    /// Absolute durable request allowance for this account; no monetary ceiling.
    #[serde(default)]
    pub provider_request_limit: Option<u64>,
    /// Foundation-owned finite accepted-handoff allowance per invocation.
    pub max_attempts: u32,
    /// Provider route identifier.
    pub route: String,
    /// Opaque reference scoped to this tenant; empty only for `secret.backend: none`.
    pub secret_ref: String,
    /// Actual backend location, or explicit `none` for keyless execution.
    pub secret: SecretSource,
    /// Pinned base URL; userinfo, query, fragments and redirects are refused.
    pub destination: String,
    /// Exact provider model.
    pub model: String,
    /// Concrete transport.
    pub provider: RouteProvider,
    /// Permit loopback HTTP for local models/tests; otherwise HTTPS is required.
    pub allow_loopback_http: bool,
    /// Maximum complete encoded provider payload.
    pub max_input_bytes: usize,
    /// Maximum provider HTTP response body.
    pub max_response_bytes: usize,
    /// Maximum metadata/identity field bytes in an attempt.
    pub max_field_bytes: usize,
    /// Maximum chat output tokens; requests must also specify their own bound.
    pub max_output_tokens: u32,
    /// Existing runtime model concurrency limit.
    pub max_in_flight: usize,
    /// Existing runtime request pacing, explicitly set or null.
    pub requests_per_minute: Option<u32>,
    /// Existing runtime input pacing, explicitly set or null.
    pub input_units_per_minute: Option<u64>,
    /// Provider timeout, finite and nonzero.
    pub timeout_seconds: u64,
}

/// Versioned deployment configuration; only locations/references, no credential values.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    /// Must equal protocol version 3.
    pub version: u16,
    /// Owner-only runtime directory (queue plus permit replay metadata).
    pub state_dir: PathBuf,
    /// Socket inside an existing owner-only directory.
    pub socket_path: PathBuf,
    /// Admission MAC key source, separate from provider credentials.
    pub admission_key: SecretSource,
    /// Finite upper bound on each secret, including the admission key.
    pub max_secret_bytes: usize,
    /// Bound on each socket frame before allocation.
    pub max_frame_bytes: u32,
    /// Maximum concurrent socket handlers; this is not a model scheduler.
    pub max_connections: usize,
    /// Time allowed for reading/writing a socket frame.
    pub io_timeout_seconds: u64,
    /// Reporting-only tolerance for signed attempt time ahead of this clock.
    /// In seconds; defaults to five. Does not change admission or authority checks.
    #[serde(default = "default_clock_rollback_warning_tolerance_seconds")]
    pub clock_rollback_warning_tolerance_seconds: u64,
    /// Approved routes; no caller-supplied destinations or secret paths.
    pub routes: Vec<RouteConfig>,
}

fn default_clock_rollback_warning_tolerance_seconds() -> u64 {
    5
}

// Fixed receipt/status/permit envelope allowance, excluding escaped identity
// strings and the existing fourfold provider-response allowance.
const REPLY_ENVELOPE_BYTES: usize = 4096;

struct Inner {
    config: ProcessConfig,
    key: AdmissionKey,
    routes: HashMap<(String, String), RouteConfig>,
    registry: Mutex<Registry>,
    runtime: Runtime,
    _process_lock: ProcessLock,
}

/// Cloneable process handle. Started dispatch work survives dropped caller futures.
#[derive(Clone)]
pub struct CredentialProcess {
    inner: Arc<Inner>,
}

impl CredentialProcess {
    /// Open bounded, protected state and configured local secret backends.
    /// Embedded callers must also call [`protect_process`] before reading configuration.
    pub fn open(config: ProcessConfig) -> Result<Self, EgressError> {
        #[cfg(unix)]
        protect_process().map_err(|_| EgressError::StateUnavailable)?;
        if config.version != PROTOCOL_VERSION {
            return Err(EgressError::Version);
        }
        // Even the smallest route needs three one-byte identities and a
        // one-byte response in addition to the fixed envelope allowance.
        if (config.max_frame_bytes as usize) < REPLY_ENVELOPE_BYTES + 3 * 6 + 4 {
            return Err(EgressError::InvalidFrameConfiguration);
        }
        if config.max_secret_bytes < 32
            || config.max_connections == 0
            || config.io_timeout_seconds == 0
            || config.routes.is_empty()
        {
            return Err(EgressError::InvalidRequest);
        }
        // Validate every route and shared account policy before touching state.
        // A lock or IO failure must not mask invalid deployment configuration.
        let mut routes = HashMap::new();
        for route in &config.routes {
            validate_route(route, config.max_frame_bytes)?;
            if routes
                .insert((route.tenant.clone(), route.route.clone()), route.clone())
                .is_some()
            {
                return Err(EgressError::InvalidRequest);
            }
        }
        let configured_registry = Arc::new(provider::configured_registry(&config.routes)?);
        symbiotic_ai_runtime::model::private_fs::ensure_private_dir(&config.state_dir)
            .map_err(|_| EgressError::StateUnavailable)?;
        let process_lock = lock_process(&config.state_dir)?;
        let key = AdmissionKey::new(config.admission_key.load(config.max_secret_bytes)?.to_vec())?;
        let runtime = Runtime::open(RuntimeConfig {
            registry: Some(configured_registry),
            state_dir: Some(config.state_dir.clone()),
            ..RuntimeConfig::default()
        })
        .map_err(|_| EgressError::StateUnavailable)?;
        for route in &config.routes {
            provider::validate_binding(&runtime, route)?;
        }
        // Replay and ledger acceptance share the runtime operational database.
        let registry =
            Registry::open(&config.state_dir.join(symbiotic_ai_runtime::QUEUE_DATABASE))?;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                key,
                routes,
                registry: Mutex::new(registry),
                runtime,
                _process_lock: process_lock,
            }),
        })
    }

    /// Deployment settings without credential values.
    pub fn config(&self) -> &ProcessConfig {
        &self.inner.config
    }

    /// Handle the shared protocol in process (the socket server calls this method).
    pub async fn handle(&self, request: Request) -> Response {
        let result = if request.version != PROTOCOL_VERSION {
            Err(EgressError::Version)
        } else {
            self.operation(request.operation).await
        };
        Response {
            version: PROTOCOL_VERSION,
            result,
        }
    }

    async fn operation(&self, operation: Operation) -> Result<Reply, EgressError> {
        self.purge_expired_results()?;
        match operation {
            Operation::IssuePermit(signed) => {
                self.inner.key.verify_attempt(&signed)?;
                let foundation_now = registry::now()?;
                // Release the registry mutex before invoking a tracing subscriber.
                let existing = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .existing(&signed.attempt)?;
                if let Some(grant) = existing {
                    self.warn_if_attempt_time_ahead(signed.attempt.recorded_at, foundation_now);
                    return Ok(Reply::Permit(grant));
                }
                let max_attempts = self.validate_attempt(&signed.attempt)?.max_attempts;
                let permit = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .issue(&signed.attempt, max_attempts)?;
                self.warn_if_attempt_time_ahead(signed.attempt.recorded_at, foundation_now);
                Ok(Reply::Permit(permit))
            }
            Operation::AttemptStatus(signed) => {
                self.inner.key.verify_attempt_id(&signed)?;
                let status = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .attempt_status(&signed.attempt_id, registry::now()?)?;
                Ok(Reply::AttemptStatus(status))
            }
            Operation::PublishGrantRevision(signed) => {
                self.inner.key.verify_grant_revision(&signed)?;
                let grant = &signed.grant;
                if grant.tenant.is_empty()
                    || grant.incarnation.is_empty()
                    || grant.revision == 0
                    || grant.revision > i64::MAX as u64
                {
                    return Err(EgressError::InvalidRequest);
                }
                self.inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .publish_revision(grant)?;
                Ok(Reply::GrantRevisionPublished)
            }
            Operation::Receipt(signed) => {
                self.inner.key.verify_attempt_id(&signed)?;
                let receipt = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .receipt(&signed.attempt_id)?;
                Ok(Reply::Receipt(receipt))
            }
            Operation::InjectProviderCredential(request) => {
                if request.operation_version != PROTOCOL_VERSION {
                    return Err(EgressError::Version);
                }
                self.inner.key.verify_attempt(&request.admission)?;
                let foundation_now = registry::now()?;
                let route = self.validate_attempt(&request.admission.attempt)?.clone();
                validate_payload(&route, &request.payload)?;
                if request.payload.digest()? != request.admission.attempt.input_digest {
                    return Err(EgressError::InvalidRequest);
                }
                let mut payload = request.payload;
                provider::prepare_payload(&mut payload, &digest(&request.admission.attempt)?);
                let handoff =
                    provider::accepted_handoff(&request.admission.attempt, &route, &payload)?;
                let receipt = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .consume(
                        &request.admission.attempt,
                        &request.permit,
                        &handoff,
                        route.max_attempts,
                    )?;
                // Spawning occurs immediately after consumption with no await in
                // between. Client cancellation cannot leave a consumed-but-cancelled
                // live task; a process crash leaves the durable unknown receipt.
                let process = self.clone();
                let task = tokio::spawn(async move {
                    process.dispatch(route, payload, receipt, handoff).await
                });
                self.warn_if_attempt_time_ahead(
                    request.admission.attempt.recorded_at,
                    foundation_now,
                );
                task.await
                    .map_err(|_| EgressError::Transport)
                    .map(Reply::Dispatched)
            }
        }
    }

    fn warn_if_attempt_time_ahead(&self, recorded_at: u64, foundation_now: u64) {
        let ahead_seconds = recorded_at.saturating_sub(foundation_now);
        let tolerance_seconds = self.inner.config.clock_rollback_warning_tolerance_seconds;
        if ahead_seconds > tolerance_seconds {
            tracing::warn!(
                event = "signed_attempt_time_ahead",
                recorded_at,
                foundation_now,
                ahead_seconds,
                tolerance_seconds,
            );
        }
    }

    /// Remove at most 64 expired recovery results, selected by the deadline index.
    /// Socket serving runs this every second even when idle.
    /// Embedded hosts must also call it periodically while idle; all operations purge first.
    pub fn purge_expired_results(&self) -> Result<(), EgressError> {
        self.inner
            .registry
            .lock()
            .map_err(|_| EgressError::StateUnavailable)?
            .purge_expired(registry::now()?)
    }

    fn validate_attempt(&self, a: &DurableAttempt) -> Result<&RouteConfig, EgressError> {
        let route = self
            .inner
            .routes
            .get(&(a.tenant.clone(), a.route.clone()))
            .ok_or(EgressError::RouteRefused)?;
        let fields = [
            &a.tenant,
            &a.incarnation,
            &a.invocation_id,
            &a.caller_binding,
            &a.route,
            &a.destination,
            &a.model,
            &a.method,
            &a.manifest_ref,
        ];
        if fields
            .iter()
            .any(|field| field.is_empty() || field.len() > route.max_field_bytes)
            || a.secret_ref.len() > route.max_field_bytes
            || a.attempt_ordinal == 0
            || a.grant_revision == 0
            || a.grant_revision > i64::MAX as u64
            || a.record_sequence == 0
            || a.record_sequence > i64::MAX as u64
            || a.recorded_at >= a.expires_at
            || a.expires_at > i64::MAX as u64
            || a.recovery_expires_at <= a.recorded_at
            || a.recovery_expires_at > i64::MAX as u64
            || !is_digest(&a.input_digest)
            || !is_digest(&a.input_manifest_digest)
        {
            return Err(EgressError::InvalidRequest);
        }
        if a.destination != route.destination
            || a.model != route.model
            || a.method != "POST"
            || a.secret_ref != route.secret_ref
        {
            return Err(EgressError::RouteRefused);
        }
        Ok(route)
    }

    async fn dispatch(
        &self,
        route: RouteConfig,
        payload: ProviderPayload,
        mut receipt: DispatchReceipt,
        handoff: symbiotic_ai_runtime::model::AcceptedSpendHandoff,
    ) -> DispatchResult {
        let source = route.secret.clone();
        let max = self.inner.config.max_secret_bytes;
        let secret = tokio::task::spawn_blocking(move || match source {
            SecretSource::None => Ok(Secret::keyless()),
            source => Secret::from_bytes(source.load(max)?),
        })
        .await;
        let mut output = None;
        let mut error = None;
        let mut diagnostics = Vec::new();
        match secret {
            Ok(Ok(secret)) => {
                match provider::execute(
                    &self.inner.runtime,
                    &route,
                    Arc::new(secret),
                    payload,
                    handoff,
                )
                .await
                {
                    Ok((answer, usage, runtime_diagnostics)) => {
                        diagnostics = runtime_diagnostics;
                        receipt.status = DispatchStatus::Succeeded;
                        receipt.usage = usage;
                        if symbiotic_ai_runtime::model::has_measured_usage(&receipt.usage) {
                            receipt.spend_state = SpendState::Settled;
                        }
                        output = Some(answer);
                    }
                    Err(failure) => {
                        error = Some(failure.code);
                        if !failure.may_have_dispatched {
                            receipt.spend_state = SpendState::Released;
                        }
                    }
                }
            }
            _ => {
                error = Some(EgressError::CredentialUnavailable);
                receipt.status = DispatchStatus::CredentialUnavailable;
                receipt.spend_state = SpendState::Released;
            }
        }
        // A paid answer is returned even if its bookkeeping write fails. The
        // previously committed Unknown remains conservative for restart/reconciliation.
        let mut result = DispatchResult {
            error,
            diagnostics,
            receipt,
            output,
            receipt_persisted: true,
        };
        result.receipt_persisted = self
            .inner
            .registry
            .lock()
            .is_ok_and(|mut registry| registry.finish(&result).is_ok());
        if !result.receipt_persisted {
            // Observed usage and output remain useful, but cannot claim a durable
            // settlement or release when the atomic completion transaction failed.
            result.receipt.spend_state = SpendState::Unknown;
        }
        result
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_route(route: &RouteConfig, max_frame: u32) -> Result<(), EgressError> {
    // Every receipt echoes three identity strings; JSON can encode each input
    // byte as six bytes (\\u00xx). Preserve the existing fourfold response
    // allowance, plus room for the fixed receipt/status/permit envelopes.
    let reply_bound = route
        .max_field_bytes
        .checked_mul(3 * 6)
        .and_then(|identity| {
            route
                .max_response_bytes
                .checked_mul(4)
                .and_then(|response| identity.checked_add(response))
        })
        .and_then(|bytes| bytes.checked_add(REPLY_ENVELOPE_BYTES));
    if reply_bound.is_none_or(|bytes| bytes > max_frame as usize) {
        return Err(EgressError::InvalidFrameConfiguration);
    }
    if route.account.trim().is_empty()
        || route.tenant.is_empty()
        || route.route.is_empty()
        || (matches!(route.secret, SecretSource::None) != route.secret_ref.is_empty())
        || route.model.is_empty()
        || route.max_field_bytes == 0
        || route.max_input_bytes == 0
        || route.max_response_bytes == 0
        || route.max_output_tokens == 0
        || route.max_in_flight == 0
        || route.requests_per_minute == Some(0)
        || route.input_units_per_minute == Some(0)
        || route.max_attempts == 0
        || route.timeout_seconds == 0
        || route.max_input_bytes > max_frame as usize / 2
    {
        return Err(EgressError::InvalidRequest);
    }
    let url = reqwest::Url::parse(&route.destination).map_err(|_| EgressError::InvalidRequest)?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || !(url.scheme() == "https"
            || route.allow_loopback_http && loopback && url.scheme() == "http")
    {
        return Err(EgressError::InvalidRequest);
    }
    match &route.provider {
        RouteProvider::GeminiEmbedding { dimensions }
            if *dimensions == 0
                || route.destination != "https://generativelanguage.googleapis.com/v1beta"
                || !route
                    .model
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) =>
        {
            Err(EgressError::InvalidRequest)
        }
        RouteProvider::OpenAiChat { operator } | RouteProvider::AnthropicChat { operator, .. }
            if operator.is_empty() =>
        {
            Err(EgressError::InvalidRequest)
        }
        _ => Ok(()),
    }
}

fn validate_payload(route: &RouteConfig, payload: &ProviderPayload) -> Result<(), EgressError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| EgressError::InvalidRequest)?;
    if bytes.len() > route.max_input_bytes {
        return Err(EgressError::LimitExceeded);
    }
    match (&route.provider, payload) {
        (RouteProvider::CompatibleEmbedding { .. }, ProviderPayload::Embedding(request)) => {
            let (adapter, _, settings) = provider::route_settings(route);
            symbiotic_ai_runtime::model::wire::compatible_embedding_body(
                adapter,
                &route.model,
                &settings,
                request,
                route.max_input_bytes,
            )
            .map(|_| ())
            .map_err(payload_error)
        }
        (RouteProvider::CohereRerank { .. }, ProviderPayload::Rerank(request)) => {
            let (_, _, settings) = provider::route_settings(route);
            symbiotic_ai_runtime::model::wire::cohere_rerank_body(
                &route.model,
                &settings,
                request,
                route.max_input_bytes,
            )
            .map(|_| ())
            .map_err(payload_error)
        }
        (
            RouteProvider::OpenAiChat { .. } | RouteProvider::AnthropicChat { .. },
            ProviderPayload::Chat(request),
        ) if !request.messages.is_empty()
            && request.messages.len() <= 128
            && request
                .messages
                .iter()
                .all(|message| message.role.len() <= route.max_field_bytes)
            && request
                .max_output_tokens
                .is_some_and(|limit| limit > 0 && limit <= route.max_output_tokens) =>
        {
            match &route.provider {
                RouteProvider::AnthropicChat { thinking, .. } => {
                    symbiotic_ai_runtime::model::wire::anthropic_chat_body(
                        &route.model,
                        request,
                        *thinking,
                        Some(route.max_input_bytes),
                    )
                }
                _ => symbiotic_ai_runtime::model::wire::openai_chat_body(
                    &route.model,
                    request,
                    None,
                    None,
                    Some(route.max_input_bytes),
                ),
            }
            .map(|_| ())
            .map_err(payload_error)
        }
        (RouteProvider::GeminiEmbedding { dimensions }, ProviderPayload::Embedding(request))
            if !request.inputs.is_empty()
                && request.inputs.len() <= 128
                && request.dimensions.is_none_or(|value| value == *dimensions) =>
        {
            symbiotic_ai_runtime::model::wire::gemini_embedding_body(
                &route.model,
                *dimensions,
                request,
                Some(route.max_input_bytes),
            )
            .map(|_| ())
            .map_err(|_| EgressError::LimitExceeded)
        }
        _ => Err(EgressError::InvalidRequest),
    }
}

fn payload_error(error: symbiotic_ai_runtime::ModelError) -> EgressError {
    if error.code() == symbiotic_ai_runtime::model::DiagnosticCode::ProviderRequestLimitExceeded {
        EgressError::LimitExceeded
    } else {
        EgressError::InvalidRequest
    }
}

struct ProcessLock(std::fs::File);

impl Drop for ProcessLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // Closing alone leaves the flock held while a concurrently spawned
            // child retains an inherited descriptor, even with O_CLOEXEC.
            // SAFETY: this guard owns the live descriptor; flock retains no pointer.
            let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn lock_process(dir: &std::path::Path) -> Result<ProcessLock, EgressError> {
    let path = dir.join("credential-process.lock");
    symbiotic_ai_runtime::model::private_fs::ensure_private_file(&path)
        .map_err(|_| EgressError::StateUnavailable)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| EgressError::StateUnavailable)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor belongs to this live File; flock retains no pointer.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(EgressError::StateUnavailable);
        }
    }
    #[cfg(not(unix))]
    return Err(EgressError::StateUnavailable);
    Ok(ProcessLock(file))
}

fn invocation_binding(a: &DurableAttempt) -> Result<String, EgressError> {
    let mut immutable = a.clone();
    immutable.attempt_ordinal = 0;
    immutable.record_sequence = 0;
    immutable.recorded_at = 0;
    // Authority is rechecked for each attempt; a renewed deadline does not
    // change the invocation's input/provider or immutable recovery binding.
    immutable.expires_at = 0;
    immutable.grant_revision = 0;
    digest(&immutable)
}

fn egress_reference(
    a: &DurableAttempt,
) -> Result<symbiotic_ai_runtime::SpendReceiptRef, EgressError> {
    symbiotic_ai_runtime::SpendReceiptRef::new(format!("egress:{}", digest(a)?))
        .map_err(|_| EgressError::LimitExceeded)
}

fn spend_reservation(
    a: &DurableAttempt,
    route: &RouteConfig,
) -> Result<symbiotic_ai_runtime::SpendReservation, EgressError> {
    Ok(symbiotic_ai_runtime::SpendReservation {
        reference: egress_reference(a)?,
        account: symbiotic_ai_runtime::account_scope(
            &symbiotic_ai_runtime::BindingIdentity::new(
                &route.tenant,
                &route.route,
                "ledger",
                &route.account,
            ),
            route.account_sharing_key.as_ref(),
        )
        .map_err(|_| EgressError::InvalidRequest)?,
        invocation: digest(&(&a.tenant, &a.incarnation, &a.invocation_id))?,
        binding: invocation_binding(a)?,
        request_limit: route.provider_request_limit,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn dropping_process_lock_releases_it_with_an_inherited_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_process(dir.path()).unwrap();
        // dup and a child inheriting the descriptor retain the same flock.
        let inherited = lock.0.try_clone().unwrap();
        assert!(matches!(
            lock_process(dir.path()),
            Err(EgressError::StateUnavailable)
        ));
        drop(lock);
        let reopened = lock_process(dir.path());
        assert!(reopened.is_ok(), "inherited descriptor retained the lock");
        drop(inherited);
        assert!(matches!(
            lock_process(dir.path()),
            Err(EgressError::StateUnavailable)
        ));
    }
}
