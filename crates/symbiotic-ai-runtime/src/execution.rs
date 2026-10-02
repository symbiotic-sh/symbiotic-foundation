//! Explicit invocation execution and durable recovery, independent of telemetry.
use crate::{
    AccountSharingKey, BindingIdentity, ChatProvider, ChatRequest, ChatResponse,
    ClassifierProvider, ClassifyRequest, ClassifyResponse, EmbeddingProvider, EmbeddingRequest,
    EmbeddingResponse, ModelBinding, ModelError, RerankProvider, RerankRequest, RerankResponse,
    Runtime, SpendReceipt, SpendReceiptRef, SpendState, account_scope,
};
use symbiotic_core::DiagnosticCode;

/// Durable status of one accepted provider attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAttemptStatus {
    /// Canonical receipt identity, accepted by receipt lookup and reconciliation.
    pub reference: SpendReceiptRef,
    /// Accounting state; an unknown charge must be reconciled before resubmission.
    pub state: SpendState,
    /// Whether Foundation durably holds the successful same-attempt output.
    pub output_available: bool,
}

impl From<SpendReceipt> for ExecutionAttemptStatus {
    fn from(receipt: SpendReceipt) -> Self {
        Self {
            reference: receipt.reservation.reference,
            state: receipt.state,
            output_available: receipt.output.is_some(),
        }
    }
}

/// Successful execution with durable attempt status, without requiring a sink.
#[derive(Debug)]
pub struct ExecutionResult<T> {
    /// Typed provider output.
    pub output: T,
    /// The accepted or recovered attempt selected by this execution, when any.
    /// A lookup failure remains visible while preserving the paid output.
    pub attempt: Result<Option<ExecutionAttemptStatus>, ModelError>,
}

/// Execution failure with durable attempt status, without requiring a sink.
#[derive(Debug)]
pub struct ExecutionError {
    /// Original closed provider/runtime error.
    pub source: ModelError,
    /// Accepted attempt and its receipt, or no accepted attempt for pre-dispatch
    /// refusal. A status storage failure is separate from the execution failure.
    pub attempt: Result<Option<ExecutionAttemptStatus>, ModelError>,
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for ExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

macro_rules! execute {
    ($name:ident, $bind:ident, $call:ident, $trait:ident, $request:ty, $response:ty, $doc:literal) => {
        #[doc = $doc]
        pub async fn $name<P>(
            &self,
            binding: ModelBinding<P>,
            invocation: impl Into<String>,
            request: $request,
        ) -> Result<ExecutionResult<$response>, ExecutionError>
        where
            P: $trait + Clone + 'static,
        {
            let invocation = invocation.into();
            binding
                .identity
                .clone()
                .filter(BindingIdentity::is_valid)
                .ok_or(ExecutionError {
                    source: ModelError::InvalidRequest(DiagnosticCode::BindingIdentityIsRequired),
                    attempt: Ok(None),
                })?;
            if invocation.trim().is_empty() {
                return Err(ExecutionError {
                    source: ModelError::InvalidRequest(DiagnosticCode::InvalidConfiguration),
                    attempt: Ok(None),
                });
            }
            let attempt_context = crate::model::ExecutionAttemptContext::default();
            let result = match self.$bind(
                binding
                    .with_invocation(invocation.clone())
                    .with_attempt_context(attempt_context.clone()),
            ) {
                Ok(provider) => provider.$call(request).await,
                Err(error) => Err(error),
            };
            self.execution_result(attempt_context, result).await
        }
    };
}

impl Runtime {
    /// Discover an accepted attempt by its explicit logical invocation after a
    /// lost reply or process restart. Identity and sharing must match the binding
    /// used for execution. The host supplies authenticated account authority.
    pub fn invocation_status(
        &self,
        identity: &BindingIdentity,
        sharing: Option<&AccountSharingKey>,
        invocation: &str,
    ) -> Result<Option<ExecutionAttemptStatus>, ModelError> {
        if !identity.is_valid() || invocation.trim().is_empty() {
            return Err(ModelError::InvalidRequest(
                DiagnosticCode::InvalidConfiguration,
            ));
        }
        let account = account_scope(identity, sharing)?;
        let invocation = crate::model::execution_invocation_identity(identity, invocation)?;
        self.inner
            .spend
            .invocation(&account, &invocation)
            .map(|receipt| receipt.map(ExecutionAttemptStatus::from))
    }

    execute!(
        execute_chat,
        chat,
        chat,
        ChatProvider,
        ChatRequest,
        ChatResponse,
        "Execute chat with an explicit invocation and return its durable recovery status."
    );
    execute!(
        execute_embedding,
        embedding,
        embed,
        EmbeddingProvider,
        EmbeddingRequest,
        EmbeddingResponse,
        "Execute embedding with an explicit invocation and return its durable recovery status."
    );
    execute!(
        execute_rerank,
        rerank,
        rerank,
        RerankProvider,
        RerankRequest,
        RerankResponse,
        "Execute reranking with an explicit invocation and return its durable recovery status."
    );
    execute!(
        execute_classifier,
        classifier,
        classify,
        ClassifierProvider,
        ClassifyRequest,
        ClassifyResponse,
        "Execute classification with an explicit invocation and return its durable recovery status."
    );

    async fn execution_result<T>(
        &self,
        context: crate::model::ExecutionAttemptContext,
        result: Result<T, ModelError>,
    ) -> Result<ExecutionResult<T>, ExecutionError> {
        let runtime = self.clone();
        let attempt = match tokio::task::spawn_blocking(move || match context.reference()? {
            Some(reference) => runtime
                .spend_receipt(&reference)
                .map(|r| r.map(ExecutionAttemptStatus::from)),
            None => Ok(None),
        })
        .await
        {
            Ok(attempt) => attempt,
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(_) => Err(ModelError::Queue(DiagnosticCode::SpendLedgerUnavailable)),
        };
        match result {
            Ok(output) => Ok(ExecutionResult { output, attempt }),
            Err(source) => Err(ExecutionError { source, attempt }),
        }
    }
}
