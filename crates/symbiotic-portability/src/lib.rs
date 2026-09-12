//! External interchange helpers. No Memory, business storage, authorization or
//! mutation runtime is a dependency. Preserve original bytes before parsing.
mod model;
mod table;
mod validate;
pub use model::*;
pub use table::*;
pub use validate::*;

/// Bounded parsing/resource limits selected by the host.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_records: usize,
    pub max_artifacts: usize,
    pub max_artifact_bytes: u64,
    pub max_table_cells: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 8 * 1024 * 1024,
            max_records: 10_000,
            max_artifacts: 10_000,
            max_artifact_bytes: 64 * 1024 * 1024,
            max_table_cells: 100_000,
        }
    }
}
/// Sanitized structural errors; caller input is never interpolated into messages.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unsupported contract version")]
    UnsupportedVersion,
    #[error("invalid wire value")]
    InvalidValue,
    #[error("duplicate identity or field")]
    DuplicateIdentity,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("artifact bytes do not match declared identity")]
    ArtifactMismatch,
    #[error("artifact unavailable")]
    ArtifactUnavailable,
    #[error("configured resource limit exceeded")]
    LimitExceeded,
}
