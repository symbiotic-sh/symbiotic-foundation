//! WP14 v1: Memory attests durable admission; Foundation owns credentials and dispatch.
//! A signer must never sign an attempt until its K durability barrier has succeeded.

pub use symbiotic_core::Sensitivity;
pub use symbiotic_model::{ChatMessage, ChatRequest, EmbeddingRequest};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(unix)]
pub mod socket;

/// Current wire and operation version. Unknown versions fail closed.
pub const PROTOCOL_VERSION: u16 = 1;

/// Static, safe-to-log errors. Never carry transport/provider bodies or credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum EgressError {
    /// Unsupported protocol/operation version.
    #[error("unsupported egress version")]
    Version,
    /// Invalid fields, digest or immutable invocation binding.
    #[error("invalid egress request")]
    InvalidRequest,
    /// Admission authentication failed.
    #[error("invalid admission authentication")]
    Unauthorized,
    /// The route is unavailable or revoked for this attempt.
    #[error("route refused")]
    RouteRefused,
    /// Permit absent, mismatched, or already consumed.
    #[error("permit refused or already used")]
    PermitRefused,
    /// A new attempt cannot reuse an unsettled uncertain dispatch.
    #[error("previous attempt requires reconciliation")]
    ReconciliationRequired,
    /// A successful invocation cannot acquire another dispatch attempt.
    #[error("invocation already completed")]
    InvocationComplete,
    /// Limits or enforceable reservation missing.
    #[error("egress budget refused")]
    BudgetRefused,
    /// Credential backend unavailable or incorrectly protected.
    #[error("credential unavailable")]
    CredentialUnavailable,
    /// Durable state failed; no new handoff is permitted.
    #[error("egress state unavailable")]
    StateUnavailable,
    /// Frame or provider output exceeds configured limits.
    #[error("egress message exceeds configured limit")]
    LimitExceeded,
    /// Protocol transport failed. A dispatch may already have incurred a charge.
    #[error("egress transport unavailable; dispatch charge may be unknown")]
    Transport,
}

/// Trusted upper reservation. V1 supports provider requests, not inferred money.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedBudget {
    /// Explicit unit; v1 dispatch supports `provider_requests` only.
    pub unit: String,
    /// Upper bound for this attempt; one request for the v1 adapters.
    pub amount: u64,
    /// Invocation total, reserved atomically by Memory across attempts.
    pub invocation_limit: u64,
}

/// Exact Memory K record, signed only after successful durability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableAttempt {
    /// Tenant namespace.
    pub tenant: String,
    /// Restore incarnation; never reuse across restore.
    pub incarnation: String,
    /// Logical invocation, stable across retries.
    pub invocation_id: String,
    /// One-based attempt ordinal, strictly increasing.
    pub attempt_ordinal: u32,
    /// Position of this attempt in Memory K's serialization order.
    pub record_sequence: u64,
    /// Trusted time at serialization, Unix seconds.
    pub recorded_at: u64,
    /// Authority expiry checked at serialization, exclusive Unix seconds.
    pub expires_at: u64,
    /// Verified caller binding.
    pub caller_binding: String,
    /// Approved route identifier.
    pub route: String,
    /// Exact configured destination (base URL for chat; service URL for Gemini).
    pub destination: String,
    /// Exact provider model.
    pub model: String,
    /// Pinned HTTP method (`POST`).
    pub method: String,
    /// Tenant-scoped opaque secret reference; not a file path.
    pub secret_ref: String,
    /// Input manifest reference.
    pub manifest_ref: String,
    /// Lowercase SHA-256 of Memory's manifest bytes.
    pub input_manifest_digest: String,
    /// Lowercase SHA-256 from [`ProviderPayload::digest`].
    pub input_digest: String,
    /// Verified processing markings; empty is valid under unconfigured markings.
    pub markings: Vec<String>,
    /// Configured total attempts for this invocation.
    pub max_attempts: u32,
    /// Trusted reservation already recorded by Memory.
    pub reserved_budget: ReservedBudget,
}

/// One supported provider call; neither variant contains credentials or URLs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "request", rename_all = "snake_case")]
pub enum ProviderPayload {
    /// Chat through a configured OpenAI-compatible route.
    Chat(symbiotic_model::ChatRequest),
    /// Embeddings through a configured Gemini route.
    Embedding(symbiotic_model::EmbeddingRequest),
}

impl ProviderPayload {
    /// Digest the exact version-1 typed JSON representation; Memory uses this helper.
    pub fn digest(&self) -> Result<String, EgressError> {
        digest(self)
    }
}

/// Authenticated durable record. Signatures do not contain provider credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAttempt {
    /// Complete immutable admission record.
    pub attempt: DurableAttempt,
    /// HMAC-SHA256 over domain-separated typed JSON, lowercase hex.
    pub authentication: String,
}

/// Route restriction from Memory's serialization order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRevocation {
    /// Tenant namespace.
    pub tenant: String,
    /// Restore incarnation.
    pub incarnation: String,
    /// Restricted route.
    pub route: String,
    /// K position of the route removal.
    pub record_sequence: u64,
}

/// Authenticated route restriction.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevocation {
    /// Restriction record.
    pub revocation: RouteRevocation,
    /// Domain-separated HMAC-SHA256.
    pub authentication: String,
}

/// Admission MAC key, distinct from provider secrets. Non-Debug, non-Serialize.
/// Memory holds a signing copy; Foundation holds a verification copy.
pub struct AdmissionKey(Zeroizing<Vec<u8>>);

impl AdmissionKey {
    /// Construct from at least 32 bytes supplied by protected local configuration.
    pub fn new(bytes: Vec<u8>) -> Result<Self, EgressError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() < 32 {
            return Err(EgressError::Unauthorized);
        }
        Ok(Self(bytes))
    }

    /// Attest an attempt after the Memory durability barrier (never before).
    pub fn sign_attempt(&self, attempt: DurableAttempt) -> Result<SignedAttempt, EgressError> {
        let authentication = self.sign(b"symbiotic-egress/v1/attempt\0", &attempt)?;
        Ok(SignedAttempt {
            attempt,
            authentication,
        })
    }

    /// Authenticate a serialized route removal.
    pub fn sign_revocation(
        &self,
        revocation: RouteRevocation,
    ) -> Result<SignedRevocation, EgressError> {
        let authentication = self.sign(b"symbiotic-egress/v1/revocation\0", &revocation)?;
        Ok(SignedRevocation {
            revocation,
            authentication,
        })
    }

    /// Verify a durable admission attestation in constant time.
    pub fn verify_attempt(&self, signed: &SignedAttempt) -> Result<(), EgressError> {
        self.verify(
            b"symbiotic-egress/v1/attempt\0",
            &signed.attempt,
            &signed.authentication,
        )
    }

    /// Verify a route restriction in constant time.
    pub fn verify_revocation(&self, signed: &SignedRevocation) -> Result<(), EgressError> {
        self.verify(
            b"symbiotic-egress/v1/revocation\0",
            &signed.revocation,
            &signed.authentication,
        )
    }

    fn mac(&self, domain: &[u8], value: &impl Serialize) -> Result<Hmac<Sha256>, EgressError> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| EgressError::Unauthorized)?;
        mac.update(domain);
        mac.update(&serde_json::to_vec(value).map_err(|_| EgressError::InvalidRequest)?);
        Ok(mac)
    }

    fn sign(&self, domain: &[u8], value: &impl Serialize) -> Result<String, EgressError> {
        Ok(hex::encode(
            self.mac(domain, value)?.finalize().into_bytes(),
        ))
    }

    fn verify(&self, domain: &[u8], value: &impl Serialize, tag: &str) -> Result<(), EgressError> {
        let tag = hex::decode(tag).map_err(|_| EgressError::Unauthorized)?;
        self.mac(domain, value)?
            .verify_slice(&tag)
            .map_err(|_| EgressError::Unauthorized)
    }
}

/// SHA-256 of typed JSON. Use the shared types, never independently serialize a map.
pub fn digest(value: &impl Serialize) -> Result<String, EgressError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| EgressError::InvalidRequest)?,
    )))
}

/// Opaque single-use capability; deliberately has no Debug implementation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchPermit {
    /// Cryptographically random permit identifier.
    pub token: String,
    /// SHA-256 of the exact durable attempt record.
    pub attempt_digest: String,
}

/// The sole credential operation; values never cross this interface.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectProviderCredential {
    /// Must equal [`PROTOCOL_VERSION`].
    pub operation_version: u16,
    /// Signed durable attempt, including route, method, secret ref and input binding.
    pub admission: SignedAttempt,
    /// Permit issued for this exact record.
    pub permit: DispatchPermit,
    /// Bounded provider payload whose digest matches the record.
    pub payload: ProviderPayload,
}

/// Bounded normalized provider output, with no raw response/trace metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderOutput {
    /// Model text.
    Chat { text: String },
    /// Embedding vectors.
    Embedding {
        vectors: Vec<Vec<f32>>,
        dimensions: usize,
    },
}

/// Charge settlement. Unknown means retain the entire reservation until reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChargeReport {
    /// Confirmed measured charge in the declared units.
    Measured { unit: String, amount: u64 },
    /// May have reached the provider; never release/reuse this reservation automatically.
    Unknown { reserved: ReservedBudget },
}

/// Outcome of one attempted dispatch, safe to log (no provider error strings).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchStatus {
    /// Successful provider answer.
    Succeeded,
    /// Provider failed; outcome/charge may be uncertain.
    ProviderFailed,
    /// No call made because credential loading failed.
    CredentialUnavailable,
}

/// Receipt without reusable cached response state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchReceipt {
    /// Exact attempt binding.
    pub attempt_digest: String,
    /// Typed completion state.
    pub status: DispatchStatus,
    /// Reported token/media/cost measurements, never inferred prices.
    pub usage: symbiotic_trace::UsageTrace,
    /// Reservation settlement instruction.
    pub charge: ChargeReport,
}

/// Typed response to credential injection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchResult {
    /// Static failure code alongside accounting; absent only on success.
    pub error: Option<EgressError>,
    /// False if the receipt write failed; restart still reports the earlier unknown charge.
    pub receipt_persisted: bool,
    /// Status and accounting.
    pub receipt: DispatchReceipt,
    /// Present only on success; never persisted as a cache by Foundation.
    pub output: Option<ProviderOutput>,
}

/// Versioned request envelope. One frame/request/response per socket connection.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Protocol version.
    pub version: u16,
    /// Operation.
    pub operation: Operation,
}

/// Protocol operations; no operation reads or returns a secret value.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", content = "body", rename_all = "snake_case")]
pub enum Operation {
    /// Verify durable admission and issue its single-use permit.
    IssuePermit(SignedAttempt),
    /// Inject credential and execute exactly one attempt.
    InjectProviderCredential(Box<InjectProviderCredential>),
    /// Publish a route restriction.
    RevokeRoute(SignedRevocation),
    /// Query a consumed attempt's accounting; never replay its output.
    Receipt(SignedAttempt),
}

/// Versioned response envelope.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Protocol version.
    pub version: u16,
    /// Operation result or static safe error.
    pub result: Result<Reply, EgressError>,
}

/// Successful reply variants.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "reply", content = "body", rename_all = "snake_case")]
pub enum Reply {
    /// Newly issued capability.
    Permit(DispatchPermit),
    /// Provider answer and usage.
    Dispatched(DispatchResult),
    /// Revocation recorded.
    Revoked,
    /// Accounting only; absent while no handoff has occurred.
    Receipt(Option<DispatchReceipt>),
}

/// Memory's only egress dependency: use the socket implementation or a test double.
#[async_trait]
pub trait EgressClient: Send + Sync {
    /// Submit one versioned operation. Transport failures after dispatch are unknown charges.
    async fn exchange(&self, request: Request) -> Result<Response, EgressError>;
}
