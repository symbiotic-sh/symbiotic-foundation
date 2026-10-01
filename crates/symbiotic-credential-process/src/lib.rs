//! Credential-owning WP14 daemon. Memory depends on `symbiotic-egress`, not this crate.
//! Credentials are resolved only after a single-use permit is durably consumed.

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
    /// Existing Gemini embedding adapter, pinned to Google's service.
    GeminiEmbedding { dimensions: usize },
}

/// Route configured by the credential-process owner. No defaults for safety limits.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Tenant namespace.
    pub tenant: String,
    /// Route identifier.
    pub route: String,
    /// Opaque reference scoped to this tenant.
    pub secret_ref: String,
    /// Actual backend location, invisible to Memory.
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
    /// Must equal protocol version 2.
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
    /// Approved routes; no caller-supplied destinations or secret paths.
    pub routes: Vec<RouteConfig>,
}

struct Inner {
    config: ProcessConfig,
    key: AdmissionKey,
    routes: HashMap<(String, String), RouteConfig>,
    registry: Mutex<Registry>,
    runtime: Runtime,
    _process_lock: std::fs::File,
}

/// Cloneable process handle. Started dispatch work survives dropped caller futures.
#[derive(Clone)]
pub struct CredentialProcess {
    inner: Arc<Inner>,
}

impl CredentialProcess {
    /// Open bounded, protected state and configured local secret backends.
    pub fn open(config: ProcessConfig) -> Result<Self, EgressError> {
        if config.version != PROTOCOL_VERSION {
            return Err(EgressError::Version);
        }
        if config.max_secret_bytes < 32
            || config.max_frame_bytes < 4096
            || config.max_connections == 0
            || config.io_timeout_seconds == 0
            || config.routes.is_empty()
        {
            return Err(EgressError::InvalidRequest);
        }
        symbiotic_ai_runtime::model::private_fs::ensure_private_dir(&config.state_dir)
            .map_err(|_| EgressError::StateUnavailable)?;
        let process_lock = lock_process(&config.state_dir)?;
        let key = AdmissionKey::new(config.admission_key.load(config.max_secret_bytes)?.to_vec())?;
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
        let runtime = Runtime::open(RuntimeConfig {
            state_dir: Some(config.state_dir.clone()),
            ..RuntimeConfig::default()
        })
        .map_err(|_| EgressError::StateUnavailable)?;
        for route in &config.routes {
            provider::validate_binding(&runtime, route)?;
        }
        // Extend the existing runtime database with replay protection, not a new
        // execution ledger or scheduling queue. Memory remains the accounting owner.
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
                if let Some(grant) = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .existing(&signed.attempt)?
                {
                    return Ok(Reply::Permit(grant));
                }
                self.validate_attempt(&signed.attempt)?;
                let permit = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .issue(&signed.attempt)?;
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
            Operation::RevokeRoute(signed) => {
                self.inner.key.verify_revocation(&signed)?;
                if signed.revocation.record_sequence == 0
                    || signed.revocation.record_sequence > i64::MAX as u64
                {
                    return Err(EgressError::InvalidRequest);
                }
                self.inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .revoke(&signed.revocation)?;
                Ok(Reply::Revoked)
            }
            Operation::Receipt(signed) => {
                self.inner.key.verify_attempt(&signed)?;
                let receipt = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .receipt(&signed.attempt)?;
                Ok(Reply::Receipt(receipt))
            }
            Operation::InjectProviderCredential(request) => {
                if request.operation_version != PROTOCOL_VERSION {
                    return Err(EgressError::Version);
                }
                self.inner.key.verify_attempt(&request.admission)?;
                let route = self.validate_attempt(&request.admission.attempt)?.clone();
                validate_payload(&route, &request.payload)?;
                if request.payload.digest()? != request.admission.attempt.input_digest {
                    return Err(EgressError::InvalidRequest);
                }
                let receipt = self
                    .inner
                    .registry
                    .lock()
                    .map_err(|_| EgressError::StateUnavailable)?
                    .consume(&request.admission.attempt, &request.permit)?;
                // Spawning occurs immediately after consumption with no await in
                // between. Client cancellation cannot leave a consumed-but-cancelled
                // live task; a process crash leaves the durable unknown receipt.
                let process = self.clone();
                let task =
                    tokio::spawn(
                        async move { process.dispatch(route, request.payload, receipt).await },
                    );
                task.await
                    .map_err(|_| EgressError::Transport)
                    .map(Reply::Dispatched)
            }
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
            &a.secret_ref,
            &a.manifest_ref,
        ];
        if fields
            .iter()
            .any(|field| field.is_empty() || field.len() > route.max_field_bytes)
            || a.markings.len() > 128
            || a.markings.iter().any(|marking| {
                marking.is_empty()
                    || marking.len() > route.max_field_bytes
                    || marking == "unclassified"
            })
            || a.attempt_ordinal == 0
            || a.max_attempts == 0
            || a.attempt_ordinal > a.max_attempts
            || a.record_sequence == 0
            || a.record_sequence > i64::MAX as u64
            || a.recorded_at >= a.expires_at
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
        if a.reserved_budget.unit != "provider_requests"
            || a.reserved_budget.amount != 1
            || a.reserved_budget.invocation_limit == 0
        {
            return Err(EgressError::BudgetRefused);
        }
        Ok(route)
    }

    async fn dispatch(
        &self,
        route: RouteConfig,
        payload: ProviderPayload,
        mut receipt: DispatchReceipt,
    ) -> DispatchResult {
        let source = route.secret.clone();
        let max = self.inner.config.max_secret_bytes;
        let secret =
            tokio::task::spawn_blocking(move || Secret::from_bytes(source.load(max)?)).await;
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
                    &receipt.attempt_digest,
                )
                .await
                {
                    Ok((answer, usage, runtime_diagnostics)) => {
                        diagnostics = runtime_diagnostics;
                        receipt.status = DispatchStatus::Succeeded;
                        receipt.usage = usage;
                        receipt.charge = ChargeReport::Measured {
                            unit: "provider_requests".into(),
                            amount: 1,
                        };
                        output = Some(answer);
                    }
                    Err(failure) => {
                        error = Some(failure.code);
                        if !failure.may_have_dispatched {
                            receipt.charge = ChargeReport::Measured {
                                unit: "provider_requests".into(),
                                amount: 0,
                            };
                        }
                    }
                }
            }
            _ => {
                error = Some(EgressError::CredentialUnavailable);
                receipt.status = DispatchStatus::CredentialUnavailable;
                receipt.charge = ChargeReport::Measured {
                    unit: "provider_requests".into(),
                    amount: 0,
                };
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
    if route.tenant.is_empty()
        || route.route.is_empty()
        || route.secret_ref.is_empty()
        || route.model.is_empty()
        || route.max_field_bytes == 0
        || route.max_input_bytes == 0
        || route.max_response_bytes == 0
        || route.max_output_tokens == 0
        || route.max_in_flight == 0
        || route.requests_per_minute == Some(0)
        || route.input_units_per_minute == Some(0)
        || route.timeout_seconds == 0
        || route.max_response_bytes > max_frame as usize / 4
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
        RouteProvider::OpenAiChat { operator } if operator.is_empty() => {
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
        (RouteProvider::OpenAiChat { .. }, ProviderPayload::Chat(request))
            if !request.messages.is_empty()
                && request.messages.len() <= 128
                && request
                    .messages
                    .iter()
                    .all(|message| message.role.len() <= route.max_field_bytes)
                && request
                    .max_output_tokens
                    .is_some_and(|limit| limit > 0 && limit <= route.max_output_tokens) =>
        {
            symbiotic_ai_runtime::model::wire::openai_chat_body(
                &route.model,
                request,
                None,
                None,
                Some(route.max_input_bytes),
            )
            .map(|_| ())
            .map_err(|_| EgressError::LimitExceeded)
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

fn lock_process(dir: &std::path::Path) -> Result<std::fs::File, EgressError> {
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
    Ok(file)
}
