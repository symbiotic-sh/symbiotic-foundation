#!/usr/bin/env bash
# Archive committed source, never build output or arbitrary Rust rlibs.
set -euo pipefail
output=${1:?usage: source-artifact.sh OUTPUT_DIRECTORY}
mkdir -p "$output"
revision=$(git rev-parse HEAD)
archive="foundation-source-${revision}.tar.gz"
git archive --format=tar --prefix="symbiotic-foundation-${revision}/" HEAD \
  Cargo.toml Cargo.lock rust-toolchain.toml crates README.md docs scripts .github | \
  gzip -n > "$output/$archive"
(
  cd "$output"
  shasum -a 256 "$archive" > SHA256SUMS
)
jq -n --arg revision "$revision" --arg archive "$archive" \
  --arg sha256 "$(cut -d ' ' -f1 "$output/SHA256SUMS")" \
  '{schema: 1, revision: $revision, archive: $archive, sha256: $sha256,
    kind: "cargo-workspace-source", rust_binary_abi: false,
    consumer: "Verify SHA256SUMS, extract the workspace, and let Cargo build for the consumer toolchain, target, features and dependency graph."}' \
  > "$output/manifest.json"
