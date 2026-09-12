//! Wire values for data-portability/1. Product payloads remain application-owned.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

/// Access labels; empty audiences have no recipients in this interchange schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub space: String,
    pub audience: Vec<String>,
    pub sensitivity: Sensitivity,
}

/// Ordered disclosure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Shareable,
    Private,
    Restricted,
}

/// Fully qualified application record identity; never a path or display name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordKey {
    pub application: String,
    pub space: String,
    pub record_type: String,
    pub record_id: String,
}

/// Exact evidence version, or explicitly unversioned provenance.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub application: String,
    pub space: String,
    pub record_type: String,
    pub record_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub revision: Option<String>,
}

/// Evidence and correction lineage are distinct.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub producer: String,
    #[serde(deserialize_with = "required_nullable")]
    pub producer_record_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub captured_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub locator: Option<String>,
    pub derived_from: Vec<EvidenceRef>,
    #[serde(deserialize_with = "required_nullable")]
    pub supersedes: Option<EvidenceRef>,
}

/// Semantic authority independent of storage API names.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    ApplicationRecord,
    Source,
    DerivedClaim,
}

/// The attachment's interpretation, scope and provenance belong to its binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub binding_id: String,
    pub artifact_id: String,
    pub role: ArtifactRole,
    pub scope: Scope,
    pub asserted_media_type: String,
    #[serde(deserialize_with = "required_nullable")]
    pub display_filename: Option<String>,
    pub provenance: Provenance,
}

/// Why these bytes are attached.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    CapturedOriginal,
    ApplicationSerialization,
    Attachment,
    Derivative,
}

/// Byte location; external IDs must not contain access credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactTarget {
    BundleFile {
        path: String,
    },
    External {
        resource_id: String,
        #[serde(deserialize_with = "required_nullable")]
        version_id: Option<String>,
    },
    Unavailable {
        reason: String,
    },
}

/// Declared preservation evidence, not a future availability guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preservation {
    IncludedVerified,
    ExternalVerified,
    ReferenceOnly,
    Unavailable,
}

/// Exact byte identity independent of filenames/media interpretation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub artifact_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub byte_length: Option<u64>,
    pub target: ArtifactTarget,
    pub preservation: Preservation,
}

/// One typed record. The owner validates the payload against its versioned schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRecord {
    pub application: String,
    pub space: String,
    pub record_type: String,
    pub record_id: String,
    pub record_schema_version: u64,
    pub authority: Authority,
    #[serde(deserialize_with = "required_nullable")]
    pub revision: Option<String>,
    pub scope: Scope,
    pub payload: Map<String, Value>,
    pub provenance: Provenance,
    pub artifact_bindings: Vec<Binding>,
}
impl PortableRecord {
    /// Return the qualified identity without interpreting its labels.
    pub fn key(&self) -> RecordKey {
        RecordKey {
            application: self.application.clone(),
            space: self.space.clone(),
            record_type: self.record_type.clone(),
            record_id: self.record_id.clone(),
        }
    }
}

/// Declared external representation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Json,
    Markdown,
    Csv,
    Docx,
    Xlsx,
    Pdf,
    Original,
}
/// Export fidelity.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportMode {
    Typed,
    Presentation,
    ExactBytes,
    None,
}
/// Import meaning.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportMode {
    Typed,
    Mapped,
    Extract,
    PreserveOnly,
    None,
}
/// Application mutation capability (this library never executes mutations).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditMode {
    Preview,
    Apply,
    None,
}
/// A product profile's explicit supported formats and losses.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub format: Format,
    pub profile: String,
    pub export: ExportMode,
    pub import: ImportMode,
    pub edit: EditMode,
    pub editable_fields: Vec<String>,
    pub losses: Vec<String>,
}
/// Exporting tool identity, distinct from application record authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub application: String,
    pub version: String,
}
/// Enumeration consistency claim, supplied and qualified by the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnumerationKind {
    Selection,
    LiveTraversal,
    Snapshot,
}
/// Completeness is relative to the declared selection/profile only.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enumeration {
    pub kind: EnumerationKind,
    pub complete: bool,
    pub selection: String,
    #[serde(deserialize_with = "required_nullable")]
    pub snapshot_revision: Option<String>,
    pub excluded_record_types: Vec<String>,
}
/// A bounded portable selection. Decoding validates structure, never authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub contract: String,
    pub profile: String,
    pub bundle_id: String,
    pub producer: Producer,
    pub exported_at: String,
    pub scope: Scope,
    pub enumeration: Enumeration,
    pub capabilities: Vec<Capability>,
    pub records: Vec<PortableRecord>,
    pub artifacts: Vec<Artifact>,
}

/// Explicit change intent. Omission never means deletion or clearing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Create {
        application: String,
        space: String,
        record_type: String,
        record_id: String,
        base_revision: (),
        value: Map<String, Value>,
    },
    Update {
        application: String,
        space: String,
        record_type: String,
        record_id: String,
        base_revision: String,
        set: Map<String, Value>,
        clear: Vec<String>,
    },
    Delete {
        application: String,
        space: String,
        record_type: String,
        record_id: String,
        base_revision: String,
        reason: String,
    },
}
impl Change {
    /// Return the qualified target identity.
    pub fn key(&self) -> RecordKey {
        match self {
            Self::Create {
                application,
                space,
                record_type,
                record_id,
                ..
            }
            | Self::Update {
                application,
                space,
                record_type,
                record_id,
                ..
            }
            | Self::Delete {
                application,
                space,
                record_type,
                record_id,
                ..
            } => RecordKey {
                application: application.clone(),
                space: space.clone(),
                record_type: record_type.clone(),
                record_id: record_id.clone(),
            },
        }
    }
}
/// Validating a plan does not execute it, authorize it or establish concurrency.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePlan {
    pub contract: String,
    pub profile: String,
    pub operation_id: String,
    pub bundle_id: String,
    pub scope: Scope,
    pub changes: Vec<Change>,
}
