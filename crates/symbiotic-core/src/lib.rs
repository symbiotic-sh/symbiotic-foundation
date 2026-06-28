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
