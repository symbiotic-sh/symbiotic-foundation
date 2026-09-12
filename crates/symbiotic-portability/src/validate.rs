use crate::*;
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Component, Path},
};

struct UniqueJson;
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Check;
        impl<'de> Visitor<'de> for Check {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate fields")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<UniqueJson, A::Error> {
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate field"));
                    }
                    map.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<UniqueJson, A::Error> {
                while seq.next_element::<UniqueJson>()?.is_some() {}
                Ok(UniqueJson)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_unit<E: de::Error>(self) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
        }
        d.deserialize_any(Check)
    }
}
fn decode<T: de::DeserializeOwned>(bytes: &[u8], limits: Limits) -> Result<T, Error> {
    if bytes.len() > limits.max_input_bytes {
        return Err(Error::LimitExceeded);
    }
    serde_json::from_slice::<UniqueJson>(bytes).map_err(|_| Error::InvalidValue)?;
    serde_json::from_slice(bytes).map_err(|_| Error::InvalidValue)
}
fn nonempty(value: &str) -> Result<(), Error> {
    if value.trim().is_empty() || value.contains('\0') {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}
fn unique(values: &[String]) -> Result<(), Error> {
    let mut found = BTreeSet::new();
    for v in values {
        nonempty(v)?;
        if !found.insert(v) {
            return Err(Error::DuplicateIdentity);
        }
    }
    Ok(())
}
fn scope(s: &Scope) -> Result<(), Error> {
    nonempty(&s.space)?;
    unique(&s.audience)
}
/// Check structural containment only. Authenticated host policy is still required.
pub fn validate_scope(child: &Scope, parent: &Scope) -> Result<(), Error> {
    scope(child)?;
    scope(parent)?;
    if child.space != parent.space
        || child.sensitivity < parent.sensitivity
        || child.audience.iter().any(|v| !parent.audience.contains(v))
    {
        Err(Error::ScopeMismatch)
    } else {
        Ok(())
    }
}

/// Bind a validated selection to the application's trusted destination. This
/// prevents metadata from choosing a different application or widening scope;
/// the host must still authorize each record and binding with its current policy.
pub fn validate_destination(
    bundle: &Bundle,
    application: &str,
    allowed: &Scope,
) -> Result<(), Error> {
    nonempty(application)?;
    validate_scope(&bundle.scope, allowed)?;
    if bundle
        .records
        .iter()
        .any(|record| record.application != application)
    {
        return Err(Error::ScopeMismatch);
    }
    Ok(())
}

/// Bind plan targets to an authenticated destination before domain validation.
pub fn validate_plan_destination(
    plan: &ChangePlan,
    application: &str,
    allowed: &Scope,
) -> Result<(), Error> {
    nonempty(application)?;
    validate_scope(&plan.scope, allowed)?;
    if plan
        .changes
        .iter()
        .any(|change| change.key().application != application)
    {
        return Err(Error::ScopeMismatch);
    }
    Ok(())
}
fn key(k: &RecordKey) -> Result<(), Error> {
    for v in [&k.application, &k.space, &k.record_type, &k.record_id] {
        nonempty(v)?;
    }
    Ok(())
}
fn timestamp(value: &str) -> Result<(), Error> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| Error::InvalidValue)
}
fn provenance(p: &Provenance) -> Result<(), Error> {
    nonempty(&p.producer)?;
    if let Some(t) = &p.captured_at {
        timestamp(t)?;
    }
    for e in p.derived_from.iter().chain(p.supersedes.iter()) {
        key(&RecordKey {
            application: e.application.clone(),
            space: e.space.clone(),
            record_type: e.record_type.clone(),
            record_id: e.record_id.clone(),
        })?;
        if let Some(r) = &e.revision {
            nonempty(r)?;
        }
    }
    if p.supersedes.as_ref().is_some_and(|e| e.revision.is_none()) {
        return Err(Error::InvalidValue);
    }
    Ok(())
}
/// Decode and validate a selection. Included files still require byte verification.
pub fn decode_bundle(bytes: &[u8], limits: Limits) -> Result<Bundle, Error> {
    let bundle: Bundle = decode(bytes, limits)?;
    validate_bundle(&bundle, limits)?;
    Ok(bundle)
}
/// Validate programmatically constructed records with the same wire invariants.
pub fn validate_bundle(b: &Bundle, limits: Limits) -> Result<(), Error> {
    if b.contract != "data-portability/1" {
        return Err(Error::UnsupportedVersion);
    }
    for v in [
        &b.profile,
        &b.bundle_id,
        &b.producer.application,
        &b.producer.version,
        &b.enumeration.selection,
    ] {
        nonempty(v)?;
    }
    scope(&b.scope)?;
    timestamp(&b.exported_at)?;
    if b.records.len() > limits.max_records || b.artifacts.len() > limits.max_artifacts {
        return Err(Error::LimitExceeded);
    }
    if (b.enumeration.kind == EnumerationKind::Snapshot)
        != b.enumeration.snapshot_revision.is_some()
    {
        return Err(Error::InvalidValue);
    }
    if let Some(r) = &b.enumeration.snapshot_revision {
        nonempty(r)?;
    }
    unique(&b.enumeration.excluded_record_types)?;
    let mut artifacts = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for a in &b.artifacts {
        nonempty(&a.artifact_id)?;
        if !artifacts.insert(&a.artifact_id) {
            return Err(Error::DuplicateIdentity);
        }
        validate_artifact(a, limits)?;
        if let ArtifactTarget::BundleFile { path } = &a.target
            && !paths.insert(path)
        {
            return Err(Error::DuplicateIdentity);
        }
    }
    let mut identities = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    for r in &b.records {
        key(&r.key())?;
        if !identities.insert(r.key()) {
            return Err(Error::DuplicateIdentity);
        }
        if r.space != r.scope.space {
            return Err(Error::ScopeMismatch);
        }
        validate_scope(&r.scope, &b.scope)?;
        if r.record_schema_version == 0 || r.record_schema_version > 9_007_199_254_740_991 {
            return Err(Error::InvalidValue);
        }
        if let Some(v) = &r.revision {
            nonempty(v)?;
        }
        provenance(&r.provenance)?;
        for a in &r.artifact_bindings {
            nonempty(&a.binding_id)?;
            nonempty(&a.asserted_media_type)?;
            if !bindings.insert(&a.binding_id) {
                return Err(Error::DuplicateIdentity);
            }
            if !artifacts.contains(&a.artifact_id) {
                return Err(Error::ArtifactUnavailable);
            }
            validate_scope(&a.scope, &r.scope)?;
            provenance(&a.provenance)?;
        }
    }
    for c in &b.capabilities {
        nonempty(&c.profile)?;
        unique(&c.editable_fields)?;
    }
    Ok(())
}
/// Decode explicit mutation intent. Host schema, authority, current revisions and
/// operation idempotency must all be checked before the application writes.
pub fn decode_change_plan(bytes: &[u8], limits: Limits) -> Result<ChangePlan, Error> {
    let p: ChangePlan = decode(bytes, limits)?;
    if p.contract != "data-portability/1" {
        return Err(Error::UnsupportedVersion);
    }
    for v in [&p.profile, &p.bundle_id, &p.operation_id] {
        nonempty(v)?;
    }
    scope(&p.scope)?;
    if p.changes.len() > limits.max_records {
        return Err(Error::LimitExceeded);
    }
    let mut seen = BTreeSet::new();
    for c in &p.changes {
        let k = c.key();
        key(&k)?;
        if k.space != p.scope.space {
            return Err(Error::ScopeMismatch);
        }
        if !seen.insert(k) {
            return Err(Error::DuplicateIdentity);
        }
        match c {
            Change::Update {
                base_revision,
                set,
                clear,
                ..
            } => {
                nonempty(base_revision)?;
                unique(clear)?;
                if clear.iter().any(|k| set.contains_key(k)) {
                    return Err(Error::InvalidValue);
                }
            }
            Change::Delete {
                base_revision,
                reason,
                ..
            } => {
                nonempty(base_revision)?;
                nonempty(reason)?;
            }
            Change::Create { .. } => {}
        }
    }
    Ok(p)
}
fn validate_artifact(a: &Artifact, limits: Limits) -> Result<(), Error> {
    if a.sha256.as_ref().is_some_and(|s| {
        s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err(Error::InvalidValue);
    }
    if a.byte_length.is_some_and(|n| n > 9_007_199_254_740_991) {
        return Err(Error::InvalidValue);
    }
    if a.byte_length.is_some_and(|n| n > limits.max_artifact_bytes) {
        return Err(Error::LimitExceeded);
    }
    let exact = a.sha256.is_some() && a.byte_length.is_some();
    if a.sha256.is_some() != a.byte_length.is_some() {
        return Err(Error::InvalidValue);
    }
    match (&a.target, a.preservation) {
        (ArtifactTarget::BundleFile { path }, Preservation::IncludedVerified) if exact => {
            validate_path(path)
        }
        (
            ArtifactTarget::External {
                resource_id,
                version_id: Some(version),
            },
            Preservation::ExternalVerified,
        ) if exact => {
            nonempty(resource_id)?;
            nonempty(version)
        }
        (ArtifactTarget::External { resource_id, .. }, Preservation::ReferenceOnly) => {
            nonempty(resource_id)
        }
        (ArtifactTarget::Unavailable { reason }, Preservation::Unavailable) => nonempty(reason),
        _ => Err(Error::InvalidValue),
    }
}
fn validate_path(path: &str) -> Result<(), Error> {
    nonempty(path)?;
    if path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|v| v.is_empty() || v == "." || v == "..")
    {
        Err(Error::InvalidValue)
    } else {
        Ok(())
    }
}
/// Verify an included file under a trusted, quiescent bundle directory. Reject
/// symlinks in every path component. Hosts must exclude concurrent path mutation
/// while opening imported bundles; this API is not an extraction sandbox.
pub fn verify_bundle_file(root: &Path, a: &Artifact, limits: Limits) -> Result<(), Error> {
    validate_artifact(a, limits)?;
    let ArtifactTarget::BundleFile { path } = &a.target else {
        return Err(Error::ArtifactUnavailable);
    };
    let mut current = root.to_path_buf();
    if std::fs::symlink_metadata(&current)
        .map_err(|_| Error::ArtifactUnavailable)?
        .file_type()
        .is_symlink()
    {
        return Err(Error::ArtifactUnavailable);
    }
    for c in Path::new(path).components() {
        let Component::Normal(c) = c else {
            return Err(Error::InvalidValue);
        };
        current.push(c);
        if std::fs::symlink_metadata(&current)
            .map_err(|_| Error::ArtifactUnavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::ArtifactUnavailable);
        }
    }
    let file = std::fs::File::open(current).map_err(|_| Error::ArtifactUnavailable)?;
    if !file
        .metadata()
        .map_err(|_| Error::ArtifactUnavailable)?
        .is_file()
    {
        return Err(Error::ArtifactUnavailable);
    }
    verify_artifact_bytes(file, a, limits)
}
/// Hash exact bytes using bounded streaming; no text, media or record conversion.
pub fn verify_artifact_bytes(reader: impl Read, a: &Artifact, limits: Limits) -> Result<(), Error> {
    validate_artifact(a, limits)?;
    let (Some(expected), Some(length)) = (&a.sha256, a.byte_length) else {
        return Err(Error::ArtifactUnavailable);
    };
    let mut input = reader.take(length.saturating_add(1));
    let mut total = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 16384];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| Error::ArtifactUnavailable)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hash.update(&buffer[..n]);
    }
    if total != length || hex::encode(hash.finalize()) != *expected {
        Err(Error::ArtifactMismatch)
    } else {
        Ok(())
    }
}
