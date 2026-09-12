use serde_json::{Value, json};
use symbiotic_portability::*;
fn bundle() -> Value {
    let scope = json!({"space":"synthetic","audience":["user:operator"],"sensitivity":"private"});
    let provenance = json!({"producer":"operator","producer_record_id":null,"captured_at":null,"locator":null,"derived_from":[],"supersedes":null});
    json!({"contract":"data-portability/1","profile":"synthetic.v1","bundle_id":"b1","producer":{"application":"exporter","version":"1"},"exported_at":"2026-09-13T00:00:00Z","scope":scope,"enumeration":{"kind":"selection","complete":true,"selection":"one","snapshot_revision":null,"excluded_record_types":[]},"capabilities":[],"records":[{"application":"app","space":"synthetic","record_type":"person","record_id":"p1","record_schema_version":1,"authority":"application_record","revision":"r1","scope":scope,"payload":{"name":"Ada","nested":{"unknown":[null,true,"保留"]}},"provenance":provenance,"artifact_bindings":[]}],"artifacts":[]})
}
fn decode(v: Value) -> Result<Bundle, Error> {
    decode_bundle(&serde_json::to_vec(&v).unwrap(), Limits::default())
}
#[test]
fn typed_json_roundtrip_preserves_unknown_payload_and_number_lexemes() {
    let mut b = bundle();
    b["records"][0]["payload"]["precise"] =
        serde_json::from_str("123456789012345678901234567890.0123456789").unwrap();
    let original = b.clone();
    let parsed = decode(b).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), original);
}
#[test]
fn unknown_envelope_missing_required_null_and_duplicate_payload_fields_fail() {
    let mut b = bundle();
    b["ignored"] = json!(true);
    assert!(decode(b).is_err());
    let mut b = bundle();
    b["records"][0]["provenance"]
        .as_object_mut()
        .unwrap()
        .remove("supersedes");
    assert!(decode(b).is_err());
    let text = serde_json::to_string(&bundle())
        .unwrap()
        .replace("\"name\":\"Ada\"", "\"name\":\"Ada\",\"name\":\"other\"");
    assert!(decode_bundle(text.as_bytes(), Limits::default()).is_err());
}
#[test]
fn qualified_identity_and_scope_containment_prevent_collisions_and_broadening() {
    let mut b = bundle();
    let r = b["records"][0].clone();
    b["records"].as_array_mut().unwrap().push(r);
    assert_eq!(decode(b.clone()).unwrap_err(), Error::DuplicateIdentity);
    b["records"][1]["application"] = json!("other-app");
    assert!(decode(b).is_ok());
    for (field, value) in [
        ("space", json!("other")),
        ("sensitivity", json!("public")),
        ("audience", json!(["user:other"])),
    ] {
        let mut b = bundle();
        b["records"][0]["scope"][field] = value;
        assert_eq!(decode(b).unwrap_err(), Error::ScopeMismatch);
    }
}
#[test]
fn correction_requires_pinned_revision_and_snapshot_requires_token() {
    let mut b = bundle();
    b["records"][0]["provenance"]["supersedes"] = json!({"application":"app","space":"synthetic","record_type":"source","record_id":"s1","revision":null});
    assert!(decode(b).is_err());
    let mut b = bundle();
    b["enumeration"]["kind"] = json!("snapshot");
    assert!(decode(b).is_err());
}
#[test]
fn plan_requires_revision_and_disjoint_explicit_clear() {
    let mut p = json!({"contract":"data-portability/1","profile":"synthetic.v1","bundle_id":"b1","operation_id":"op1","scope":bundle()["scope"],"changes":[{"application":"app","space":"synthetic","record_type":"person","record_id":"p1","action":"update","base_revision":"r1","set":{"name":null},"clear":[]}]});
    assert!(decode_change_plan(&serde_json::to_vec(&p).unwrap(), Limits::default()).is_ok());
    p["changes"][0]["clear"] = json!(["name"]);
    assert!(decode_change_plan(&serde_json::to_vec(&p).unwrap(), Limits::default()).is_err());
    p["changes"][0]["clear"] = json!([]);
    p["changes"][0]["base_revision"] = Value::Null;
    assert!(decode_change_plan(&serde_json::to_vec(&p).unwrap(), Limits::default()).is_err());
}
fn artifact(bytes: &[u8]) -> Artifact {
    use sha2::{Digest, Sha256};
    Artifact {
        artifact_id: "a1".into(),
        sha256: Some(hex::encode(Sha256::digest(bytes))),
        byte_length: Some(bytes.len() as u64),
        target: ArtifactTarget::BundleFile {
            path: "original.bin".into(),
        },
        preservation: Preservation::IncludedVerified,
    }
}
#[test]
fn binary_verification_checks_exact_bytes_limits_missing_files_and_paths() {
    let bytes = [0, 255, 128, 13, 10];
    let mut a = artifact(&bytes);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("original.bin"), bytes).unwrap();
    verify_bundle_file(dir.path(), &a, Limits::default()).unwrap();
    assert_eq!(
        verify_artifact_bytes(&bytes[..4], &a, Limits::default()),
        Err(Error::ArtifactMismatch)
    );
    assert_eq!(
        verify_artifact_bytes(
            &bytes[..],
            &a,
            Limits {
                max_artifact_bytes: 4,
                ..Limits::default()
            }
        ),
        Err(Error::LimitExceeded)
    );
    a.target = ArtifactTarget::BundleFile {
        path: "../original.bin".into(),
    };
    assert_eq!(
        verify_bundle_file(dir.path(), &a, Limits::default()),
        Err(Error::InvalidValue)
    );
    a.target = ArtifactTarget::BundleFile {
        path: "missing.bin".into(),
    };
    assert_eq!(
        verify_bundle_file(dir.path(), &a, Limits::default()),
        Err(Error::ArtifactUnavailable)
    );
}
#[cfg(unix)]
#[test]
fn symlink_artifacts_are_never_followed() {
    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(external.path(), dir.path().join("original.bin")).unwrap();
    assert_eq!(
        verify_bundle_file(dir.path(), &artifact(&[]), Limits::default()),
        Err(Error::ArtifactUnavailable)
    );
}
#[test]
fn csv_quotes_unicode_multiline_and_exposes_formula_presentation_loss() {
    let t = Table {
        columns: vec!["name".into(), "note".into()],
        rows: vec![
            vec!["Ada, \"例\"".into(), "line1\nline2".into()],
            vec!["=1+1".into(), "@SUM(A1)".into()],
        ],
    };
    let view = render_csv(&t, Limits::default()).unwrap();
    assert_eq!(view.losses.len(), 1);
    let parsed = parse_csv(&view.bytes, Limits::default()).unwrap();
    assert_eq!(parsed.rows[0], t.rows[0]);
    assert_eq!(parsed.rows[1][0], "'=1+1");
    assert_eq!(
        parse_csv(b"a,a\nx,y\n", Limits::default()),
        Err(Error::DuplicateIdentity)
    );
    assert!(parse_csv(b"a,b\nx\n", Limits::default()).is_err());
    assert!(
        parse_csv(
            b"a,b\nx,y\n",
            Limits {
                max_table_cells: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
    let md = render_markdown(&t, Limits::default()).unwrap();
    assert!(
        String::from_utf8(md.bytes)
            .unwrap()
            .contains("line1<br>line2")
    );
    assert!(!md.losses.is_empty());
}
#[test]
fn oversize_json_is_rejected_before_deserializing() {
    assert_eq!(
        decode_bundle(
            b"{}",
            Limits {
                max_input_bytes: 1,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        Error::LimitExceeded
    );
}
