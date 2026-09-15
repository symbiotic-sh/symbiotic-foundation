#!/usr/bin/env bash
set -euo pipefail
mkdir -p .debug-session/ci
rustc -Vv > .debug-session/ci/rustc.txt
cargo -V > .debug-session/ci/cargo.txt
start=$SECONDS
cargo build --locked --release --workspace --all-targets --all-features \
  --message-format=json-render-diagnostics | tee .debug-session/ci/build.jsonl
elapsed=$((SECONDS - start))
# compiler-artifact.fresh is Cargo's observed reuse decision, not a cache-key guess.
jq -s --argjson elapsed "$elapsed" \
  --arg cache_hit "${CACHE_HIT:-unavailable}" \
  --arg native_digest "${NATIVE_DIGEST:-unavailable}" \
  --arg revision "$(git rev-parse HEAD)" \
  --arg target "${CARGO_BUILD_TARGET:-host}" \
  --arg run_id "${GITHUB_RUN_ID:-local}" \
  --arg run_attempt "${GITHUB_RUN_ATTEMPT:-local}" '
  [.[] | select(.reason == "compiler-artifact")] as $artifacts |
  {revision: $revision, target: $target, profile: "release", features: "all",
   run_id: $run_id, run_attempt: $run_attempt, cache_hit: $cache_hit,
   native_digest: $native_digest, elapsed_seconds: $elapsed,
   fresh: ([$artifacts[] | select(.fresh)] | length),
   compiled: ([$artifacts[] | select(.fresh == false)] | length),
   artifacts: [$artifacts[] | {package_id, target: .target.name, fresh}]}
' .debug-session/ci/build.jsonl > .debug-session/ci/build-summary.json
cat .debug-session/ci/build-summary.json
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  jq -r '"Cargo build: \(.fresh) fresh artifacts, \(.compiled) compiled artifacts; \(.elapsed_seconds)s; exact cache hit: \(.cache_hit)."' \
    .debug-session/ci/build-summary.json >> "$GITHUB_STEP_SUMMARY"
fi
