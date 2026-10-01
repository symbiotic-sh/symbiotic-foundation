//! Tiny shared vocabulary for foundation crates.
//!
//! Keep this crate deliberately small. It should contain stable identifiers and
//! policy labels that generic crates need to agree on, not product behavior.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(pub String);

impl TraceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueId(pub String);

impl QueueId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueItemId(pub String);

impl QueueItemId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for QueueItemId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Operation(pub String);

impl Operation {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleBinding(pub String);

impl RoleBinding {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvocationSource(pub String);

impl InvocationSource {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTier {
    Fast,
    Balanced,
    Deep,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Operator(pub String);

impl Operator {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelName(pub String);

impl ModelName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelIdentity {
    pub operation: Operation,
    pub operator: Operator,
    pub model: ModelName,
}

impl ModelIdentity {
    pub fn new(
        operation: impl Into<String>,
        operator: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            operation: Operation::new(operation),
            operator: Operator::new(operator),
            model: ModelName::new(model),
        }
    }

    pub fn queue_id(&self) -> QueueId {
        QueueId(format!(
            "{}:{}:{}",
            self.operation.0, self.operator.0, self.model.0
        ))
    }
}

/// Tenant namespace of a configured provider.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);
/// Provider principal whose data grants are owned by Memory.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderPrincipalId(pub String);
/// Opaque configuration generation; changing it invalidates result reuse.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigurationRevision(pub String);
/// Concrete provider account, distinct from the model name or secret value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);
/// Required identity of a runtime binding. Contains references, never secrets.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BindingIdentity {
    pub tenant: TenantId,
    pub provider: ProviderPrincipalId,
    pub revision: ConfigurationRevision,
    pub account: AccountId,
}
impl BindingIdentity {
    pub fn new(
        tenant: impl Into<String>,
        provider: impl Into<String>,
        revision: impl Into<String>,
        account: impl Into<String>,
    ) -> Self {
        Self {
            tenant: TenantId(tenant.into()),
            provider: ProviderPrincipalId(provider.into()),
            revision: ConfigurationRevision(revision.into()),
            account: AccountId(account.into()),
        }
    }
    pub fn is_valid(&self) -> bool {
        [
            &self.tenant.0,
            &self.provider.0,
            &self.revision.0,
            &self.account.0,
        ]
        .iter()
        .all(|s| !s.trim().is_empty())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Shareable,
    Private,
    Restricted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_identity_derives_shared_queue_id() {
        let identity = ModelIdentity::new("chat", "deepseek", "deepseek-v4-pro");

        assert_eq!(identity.queue_id().0, "chat:deepseek:deepseek-v4-pro");
    }
}
