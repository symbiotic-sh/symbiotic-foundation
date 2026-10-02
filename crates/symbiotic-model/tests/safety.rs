//! Response-cache maintenance never follows a symlink or touches another
//! user's files, and the queued classifier keeps its credential's
//! fingerprint.
#![cfg(feature = "queue")]

use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use symbiotic_model::{
    CacheEntry, DirResponseCache, JevClassifierProvider, ModelProvider, ModelQueueConfig,
    QueuedClassifierProvider, ResponseCache, api_key_fingerprint,
};
use symbiotic_queue::MemoryQueue;

/// A directory, outside any cache, holding one response-like JSON file.
fn bystander() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("precious.json");
    std::fs::write(&file, json!({"trace": {"source": "a"}}).to_string()).unwrap();
    (dir, file)
}

fn assert_refused<T: std::fmt::Debug>(result: Result<T, symbiotic_model::ModelError>, file: &Path) {
    let err = result.expect_err("a symlinked cache is refused");
    assert!(matches!(
        err,
        symbiotic_model::ModelError::Cache(symbiotic_core::DiagnosticCode::CachePathRefused)
    ));
    assert!(file.exists(), "a file behind the symlink was deleted");
}

#[cfg(unix)]
#[test]
fn prune_and_purge_refuse_a_symlinked_cache_root() {
    let (target, file) = bystander();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cache");
    std::os::unix::fs::symlink(target.path(), &root).unwrap();
    let cache = DirResponseCache::new(&root);
    assert_refused(cache.prune(None, Some(0)), &file);
    assert_refused(cache.purge(|_| true), &file);
    let request = json!({});
    let entry = CacheEntry {
        kind: "chat",
        scope: None,
        request_hash: "precious",
        request: &request,
    };
    assert_refused(cache.load(&entry), &file);
    assert_refused(cache.store(&entry, &request), &file);
}

#[cfg(unix)]
#[test]
fn prune_and_purge_refuse_a_symlink_inside_the_cache() {
    let (target, file) = bystander();
    let dir = tempfile::tempdir().unwrap();
    let cache = DirResponseCache::new(dir.path().join("cache"));
    let request = json!({});
    cache
        .store(
            &CacheEntry {
                kind: "chat",
                scope: None,
                request_hash: "own",
                request: &request,
            },
            &json!({"trace": {"source": "a"}}),
        )
        .unwrap();
    std::os::unix::fs::symlink(target.path(), dir.path().join("cache/embedding")).unwrap();
    assert_refused(cache.prune(None, Some(0)), &file);
    assert_refused(cache.purge(|_| true), &file);
    let entry = CacheEntry {
        kind: "embedding",
        scope: None,
        request_hash: "precious",
        request: &request,
    };
    assert_refused(cache.load(&entry), &file);
    assert_refused(cache.store(&entry, &request), &file);
    assert!(
        dir.path().join("cache/chat/own.json").exists(),
        "a refused sweep deletes nothing"
    );
}

#[cfg(unix)]
#[test]
fn load_store_prune_and_purge_refuse_a_symlinked_cache_file() {
    let (_target, file) = bystander();
    let dir = tempfile::tempdir().unwrap();
    let cache = DirResponseCache::new(dir.path().join("cache"));
    let request = json!({});
    let entry = CacheEntry {
        kind: "chat",
        scope: None,
        request_hash: "own",
        request: &request,
    };
    cache.store(&entry, &request).unwrap();
    let link = cache.root().join("chat/own.json");
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert_refused(cache.load(&entry), &file);
    assert_refused(cache.store(&entry, &request), &file);
    assert_refused(cache.prune(None, Some(0)), &file);
    assert_refused(cache.purge(|_| true), &file);
}

#[test]
fn the_queued_classifier_keeps_its_credential_fingerprint() {
    let key = "sk-classifier-0123456789";
    let queued = QueuedClassifierProvider::new(
        JevClassifierProvider::new("op", "model", "http://127.0.0.1:9", key),
        Arc::new(MemoryQueue::new()),
        "worker",
        ModelQueueConfig::default(),
    );
    assert_eq!(queued.credential_fingerprint(), api_key_fingerprint(key));
    assert!(queued.credential_fingerprint().is_some());
}

#[test]
fn purge_reports_malformed_binding_and_model_instead_of_silently_keeping_entries() {
    for trace in [
        json!({"metadata":{"binding":{"tenant":42}}}),
        json!({"model":{"operation":42}}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let cache = DirResponseCache::new(dir.path().join("cache"));
        let request = json!({});
        cache
            .store(
                &CacheEntry {
                    kind: "chat",
                    scope: None,
                    request_hash: "invalid",
                    request: &request,
                },
                &json!({"trace": trace}),
            )
            .unwrap();
        let result = cache.purge(|_| false);
        assert!(matches!(result, Err(symbiotic_model::ModelError::Cache(_))));
        assert!(dir.path().join("cache/chat/invalid.json").exists());
    }
}
