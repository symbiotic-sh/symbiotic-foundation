//! Dependency-graph contract of the provider crates.
//!
//! The queue contracts and the model contracts never pull in SQLite: the SQLite
//! queue backend is the separate `symbiotic-queue-sqlite` crate, so feature
//! unification with other crates in the same build cannot bring it in. Without
//! default features, `symbiotic-model` also leaves out its queue runtime. Only
//! the SQLite backend and `symbiotic-ai-runtime`, which persists through it,
//! link SQLite. The checks read the resolved graphs of this workspace's lockfile
//! (`cargo tree --locked --offline`).

use std::process::Command;

fn normal_dependencies(package: &str, extra: &[&str]) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let output = Command::new(cargo)
        .args([
            "tree",
            "--manifest-path",
            manifest,
            "--package",
            package,
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}|{f}",
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

/// The features enabled on `name` (the `{f}` column after `|`).
fn features(graph: &str, name: &str) -> Vec<String> {
    graph
        .lines()
        .filter(|line| line.split_whitespace().next() == Some(name))
        .flat_map(|line| {
            line.rsplit_once('|')
                .map(|(_, features)| features.to_string())
        })
        .flat_map(|features| {
            features
                .split(',')
                .map(str::trim)
                .filter(|feature| !feature.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn assert_no_sqlite(graph: &str) {
    for name in ["rusqlite", "libsqlite3-sys", "symbiotic-queue-sqlite"] {
        assert!(!has_package(graph, name), "{name} in:\n{graph}");
    }
}

#[test]
fn queue_contracts_never_link_sqlite() {
    assert_no_sqlite(&normal_dependencies("symbiotic-queue", &[]));
    assert_no_sqlite(&normal_dependencies("symbiotic-trace", &[]));
}

#[test]
fn model_contract_links_no_sqlite_with_or_without_the_queue_runtime() {
    let lean = normal_dependencies("symbiotic-model", &["--no-default-features"]);
    assert_no_sqlite(&lean);
    assert!(
        !features(&lean, "symbiotic-model").contains(&"queue".to_string()),
        "{lean}"
    );

    let default = normal_dependencies("symbiotic-model", &[]);
    assert_no_sqlite(&default);
    assert!(
        features(&default, "symbiotic-model").contains(&"queue".to_string()),
        "{default}"
    );
}

#[test]
fn sqlite_backend_is_its_own_crate() {
    let graph = normal_dependencies("symbiotic-queue-sqlite", &[]);
    assert!(has_package(&graph, "rusqlite"), "{graph}");
    assert!(has_package(&graph, "symbiotic-queue"), "{graph}");
}

#[test]
fn only_the_ai_runtime_and_the_sqlite_backend_link_sqlite() {
    let runtime = normal_dependencies("symbiotic-ai-runtime", &[]);
    assert!(has_package(&runtime, "rusqlite"), "{runtime}");
    assert!(has_package(&runtime, "symbiotic-queue-sqlite"), "{runtime}");
    for crate_name in ["symbiotic-core", "symbiotic-portability"] {
        assert_no_sqlite(&normal_dependencies(crate_name, &[]));
    }
}
