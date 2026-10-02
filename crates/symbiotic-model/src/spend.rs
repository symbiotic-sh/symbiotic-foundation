//! Canonical execution accounting, independent of optional trace sinks.
use crate::{DiagnosticCode, ModelError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use symbiotic_trace::UsageTrace;

/// Opaque Foundation receipt identity for consumer provenance and status lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendReceiptRef(pub String);

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
    /// Exact binding/input identity; reattachment must match it.
    pub binding: String,
    /// Absolute account request allowance; no time window or monetary ceiling.
    pub request_limit: Option<u64>,
}

/// Authoritative receipt. Missing usage retains Unknown even with successful output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendReceipt {
    pub reservation: SpendReservation,
    pub state: SpendState,
    pub usage: Option<UsageTrace>,
    /// Same-attempt runtime result, or credential completion evidence; egress
    /// output bytes stay in its authenticated, deadline-bounded recovery store.
    pub output: Option<Value>,
}

/// Accounting boundary used by every queued operation and credential handoff.
/// A successful reserve returns true only for a newly accepted attempt.
pub trait SpendLedger: Send + Sync {
    fn reserve(&self, reservation: &SpendReservation) -> Result<bool, ModelError>;
    fn receipt(&self, reference: &SpendReceiptRef) -> Result<Option<SpendReceipt>, ModelError>;
    fn invocation(
        &self,
        account: &str,
        invocation: &str,
    ) -> Result<Option<SpendReceipt>, ModelError>;
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
pub(crate) fn reconciliation() -> ModelError {
    ModelError::Queue(DiagnosticCode::SpendReconciliationRequired)
}

/// Refuse dispatch when no durable operational store was supplied.
#[doc(hidden)]
pub struct UnavailableSpendLedger;
impl SpendLedger for UnavailableSpendLedger {
    fn reserve(&self, _: &SpendReservation) -> Result<bool, ModelError> {
        Err(storage())
    }
    fn receipt(&self, _: &SpendReceiptRef) -> Result<Option<SpendReceipt>, ModelError> {
        Err(storage())
    }
    fn invocation(&self, _: &str, _: &str) -> Result<Option<SpendReceipt>, ModelError> {
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
