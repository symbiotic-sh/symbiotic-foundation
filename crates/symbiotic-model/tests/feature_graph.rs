//! Dependency-graph contract of the `queue` feature.
//!
//! Without default features, `symbiotic-model` is the provider contracts and
//! HTTP providers alone, so a host can use them without linking SQLite. The
//! default build keeps the queue runtime. Both are checked on the resolved
//! graph of this workspace's lockfile (`cargo tree --locked --offline`).

use std::process::Command;

fn normal_dependencies(extra: &[&str]) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let output = Command::new(cargo)
        .args([
            "tree",
            "--manifest-path",
            manifest,
            "--package",
            "symbiotic-model",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p} {f}",
            "--locked",
            "--offline",
        ])
        .args(extra)
        .output()
        .expect("run cargo tree");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("cargo tree output is UTF-8")
}

fn has_package(graph: &str, name: &str) -> bool {
    graph
        .lines()
        .any(|line| line.split_whitespace().next() == Some(name))
}

#[test]
fn without_default_features_the_model_contract_links_no_sqlite() {
    let graph = normal_dependencies(&["--no-default-features"]);

    assert!(!has_package(&graph, "rusqlite"), "{graph}");
    assert!(!has_package(&graph, "libsqlite3-sys"), "{graph}");
    // Traces still name the queue event contracts, never the SQLite backend.
    assert!(
        graph
            .lines()
            .filter(|line| line.starts_with("symbiotic-queue "))
            .all(|line| !line.contains("sqlite")),
        "{graph}"
    );
}

#[test]
fn default_features_keep_the_queue_runtime() {
    let graph = normal_dependencies(&[]);

    assert!(
        graph
            .lines()
            .any(|line| line.starts_with("symbiotic-model ") && line.contains("queue")),
        "{graph}"
    );
    assert!(has_package(&graph, "symbiotic-queue"), "{graph}");
}
