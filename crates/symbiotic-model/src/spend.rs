//! Canonical execution accounting, independent of optional trace sinks.
use crate::{DiagnosticCode, ModelError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use symbiotic_trace::UsageTrace;

/// Opaque Foundation receipt identity for consumer provenance and status lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendReceiptRef(pub String);

/// Per-execution receipt pointer; accounting remains in the canonical ledger.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct ExecutionAttemptContext(std::sync::Arc<std::sync::Mutex<Option<SpendReceiptRef>>>);
impl ExecutionAttemptContext {
    /// The exact accepted or recovered receipt observed by this execution.
    pub fn reference(&self) -> Result<Option<SpendReceiptRef>, ModelError> {
        self.0
            .lock()
            .map(|reference| reference.clone())
            .map_err(|_| storage())
    }
    #[cfg(feature = "queue")]
    pub(crate) fn clear(&self) -> Result<(), ModelError> {
        *self.0.lock().map_err(|_| storage())? = None;
        Ok(())
    }
    #[cfg(feature = "queue")]
    pub(crate) fn capture(&self, reference: &SpendReceiptRef) -> Result<(), ModelError> {
        *self.0.lock().map_err(|_| storage())? = Some(reference.clone());
        Ok(())
    }
}

/// Enforceable request accounting, separate from monetary observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendState {
    /// Accepted, possibly dispatched: its request remains reserved.
    Unknown,
    /// Evidence establishes that no charge was incurred.
    Released,
    /// Successful request with measured provider usage.
    Settled,
}

/// Durable reservation identity. One request is reserved per accepted attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendReservation {
    pub reference: SpendReceiptRef,
    pub account: String,
    pub invocation: String,
    /// Immutable input/provider-binding digest for the logical invocation.
    /// Explicit runtime invocations also bind their original total attempt ceiling.
    /// Individual attempt identity belongs to `reference`.
    pub binding: String,
    /// Absolute account request allowance; no time window or monetary ceiling.
    pub request_limit: Option<u64>,
}

/// A single-use accepted attempt, bound to its account, input and runtime binding.
/// The ledger stores this identity before accepting the trusted handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedSpendHandoff {
    /// Accepted account, logical invocation and exact attempt identity.
    pub reservation: SpendReservation,
    /// Hash of the operation, provider binding and exact queued request.
    pub input_identity: String,
}

/// Scope a caller's invocation to its exact tenant/provider/configuration binding.
pub fn execution_invocation_identity(
    binding: &symbiotic_core::BindingIdentity,
    invocation: &str,
) -> Result<String, ModelError> {
    crate::configuration_revision(&(binding, invocation)).map(|revision| revision.0)
}

/// Exact queued input identity, including operation and provider binding.
pub fn handoff_input_identity(
    kind: &str,
    binding: Option<&symbiotic_core::BindingIdentity>,
    request_hash: &str,
) -> Result<String, ModelError> {
    crate::configuration_revision(&(kind, binding, request_hash)).map(|revision| revision.0)
}

/// Authoritative receipt. Missing usage retains Unknown even with successful output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendReceipt {
    pub reservation: SpendReservation,
    pub state: SpendState,
    /// Confirmed release before transport: this queue claim used no provider attempt.
    /// Ordinary Released accounting, including known-zero provider failures, still did.
    #[serde(default)]
    pub pre_dispatch_released: bool,
    pub usage: Option<UsageTrace>,
    /// Same-attempt runtime result, or credential completion evidence; egress
    /// output bytes stay in its authenticated, deadline-bounded recovery store.
    pub output: Option<Value>,
}

impl SpendReceipt {
    /// Content-free success evidence, preserved after recovery payload deletion.
    pub fn completion_evidence() -> Value {
        serde_json::json!({"output_received": true})
    }

    /// Same-attempt runtime payload, excluding content-free completion evidence.
    pub fn recovery_output(&self) -> Option<&Value> {
        self.output
            .as_ref()
            .filter(|output| **output != Self::completion_evidence())
    }
}

/// Accounting boundary used by every queued operation and credential handoff.
/// A successful reserve returns true only for a newly accepted attempt.
pub trait SpendLedger: Send + Sync {
    /// Enforce an optional invocation attempt ceiling atomically with reservation.
    fn reserve(
        &self,
        reservation: &SpendReservation,
        attempt_limit: Option<u32>,
    ) -> Result<bool, ModelError>;
    /// Count canonical provider attempts, excluding confirmed pre-dispatch releases.
    /// A reference prefix scopes implicit calls to their current queue item.
    fn attempts(
        &self,
        account: &str,
        invocation: &str,
        reference_prefix: Option<&str>,
    ) -> Result<u32, ModelError>;
    /// Atomically release a reservation and record that transport never started.
    /// Must not reclassify a provider attempt already settled or reconciled.
    fn release_before_dispatch(&self, reference: &SpendReceiptRef) -> Result<(), ModelError>;
    /// Atomically validate and consume dispatch ownership for an accepted handoff.
    /// Reuse, identity mismatch and non-unknown accounting are refused.
    fn acquire_handoff(
        &self,
        handoff: &AcceptedSpendHandoff,
        account: &str,
        input_identity: &str,
        owner: &str,
    ) -> Result<(), ModelError>;
    fn receipt(&self, reference: &SpendReceiptRef) -> Result<Option<SpendReceipt>, ModelError>;
    /// Latest accepted attempt for this account/invocation, including Released accounting.
    fn invocation(
        &self,
        account: &str,
        invocation: &str,
    ) -> Result<Option<SpendReceipt>, ModelError>;
    /// Discard recovery for an authenticated account/invocation, preserving completion.
    fn discard_output(&self, account: &str, invocation: &str) -> Result<bool, ModelError>;
    /// Delete matching runtime recovery payloads while preserving accounting evidence.
    fn purge_outputs(
        &self,
        matches: &dyn Fn(&Value) -> Result<bool, ModelError>,
    ) -> Result<usize, ModelError>;
    fn finish(
        &self,
        reference: &SpendReceiptRef,
        state: SpendState,
        usage: Option<UsageTrace>,
        output: Option<Value>,
    ) -> Result<(), ModelError>;
}

pub(crate) fn storage() -> ModelError {
    ModelError::Queue(DiagnosticCode::SpendLedgerUnavailable)
}
#[cfg(feature = "queue")]
pub(crate) fn reconciliation() -> ModelError {
    ModelError::Queue(DiagnosticCode::SpendReconciliationRequired)
}

/// Refuse dispatch when no durable operational store was supplied.
#[doc(hidden)]
pub struct UnavailableSpendLedger;
impl SpendLedger for UnavailableSpendLedger {
    fn reserve(&self, _: &SpendReservation, _: Option<u32>) -> Result<bool, ModelError> {
        Err(storage())
    }
    fn attempts(&self, _: &str, _: &str, _: Option<&str>) -> Result<u32, ModelError> {
        Err(storage())
    }
    fn release_before_dispatch(&self, _: &SpendReceiptRef) -> Result<(), ModelError> {
        Err(storage())
    }
    fn acquire_handoff(
        &self,
        _: &AcceptedSpendHandoff,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(), ModelError> {
        Err(storage())
    }
    fn receipt(&self, _: &SpendReceiptRef) -> Result<Option<SpendReceipt>, ModelError> {
        Err(storage())
    }
    fn invocation(&self, _: &str, _: &str) -> Result<Option<SpendReceipt>, ModelError> {
        Err(storage())
    }
    fn discard_output(&self, _: &str, _: &str) -> Result<bool, ModelError> {
        Err(storage())
    }
    fn purge_outputs(
        &self,
        _: &dyn Fn(&Value) -> Result<bool, ModelError>,
    ) -> Result<usize, ModelError> {
        Err(storage())
    }
    fn finish(
        &self,
        _: &SpendReceiptRef,
        _: SpendState,
        _: Option<UsageTrace>,
        _: Option<Value>,
    ) -> Result<(), ModelError> {
        Err(storage())
    }
}

/// Whether usage was actually reported; absent fields never stand for zero.
pub fn has_measured_usage(u: &UsageTrace) -> bool {
    u.input_tokens.is_some()
        || u.output_tokens.is_some()
        || u.reasoning_tokens.is_some()
        || u.media_units.is_some()
        || u.cost_micro_usd.is_some()
        || u.reported_cost_usd.is_some()
}
