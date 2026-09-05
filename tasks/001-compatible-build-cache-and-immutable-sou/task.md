---
id: 001
title: Compatible build cache and immutable source artifacts
status: active
owner: foundation
priority: P2
depends_on:
lane: .github/workflows/ci.yml, scripts/, rust-toolchain.toml, docs/architecture/build-artifacts.md, crates/symbiotic-model/src/lib.rs, crates/symbiotic-queue/src/lib.rs
design:
pr: https://github.com/symbiotic-sh/symbiotic-foundation/pull/1
created: 2026-09-05T05:19:45Z
updated: 2026-09-05T05:19:46Z
---

## Scope

## Acceptance criteria

## Decisions
<!-- settled choices + rejected alternatives, with why -->

Foundation-only lane, isolated at `.worktrees/build-cache`, branch
`task/001-build-cache/foundation`, based on `814060c`. Owner is Codex task
`01a07001-6d57-7be0-9158-5ec5ee08ac75`; parent task
`01a06c3b-8267-7ba2-b676-2a6511271b0a` coordinates Memory and local build slots.

Acceptance: correct cache boundaries; unchanged dependency compilation avoided
in observed warm run; correctness gates retained; immutable source archive with
digest and explicit consumer contract; reviewable branch/PR and durable evidence.

Decisions: source-only distribution, no universal Rust rlibs, no crates.io release.
Memory already uses full Foundation Git pins. No existing Foundation CI was found
locally or via hosted API. Introduce one Linux job bounded to 30 minutes. No
consumer changes, purchases, external model calls, or merges.

Validation envelope: one cold and one warm hosted run, diagnose before retries;
local static checks and archive verification only unless parent grants build slot.
Hypothesis: warm compatible dependency artifacts are Fresh while workspace crates
may rebuild; inspect Cargo JSON counts and native digest before timing claims.
Initial static check: `cargo +1.93.0 fmt --all --check` passed. No heavy local
builds have been run. Hosted run IDs and results will be recorded in handoffs.

## Diagnosed cold failure and recovery

First hosted run 33947031417 at candidate 0aef7b6 built all 152 compilation
units cold (0 Fresh) in 80 seconds. The new warnings-denied gate exposed baseline
nested-if lints in queue. No cache or source archive was published; build evidence
was correctly retained. Parent explicitly approved an exclusive local preflight
slot followed by one corrected cold and one warm recovery run.

Local preflight exposed three additional nested conditions and two large private
helper signatures in model. Equivalent let chains and private QueueContext /
RetryRequest structs fix them without suppressions or public API changes. Clippy
passes; existing full workspace release tests validate queue/retry/cache behavior.
Raw logs and session IDs are under .debug-session/validation-session.md.

Local preflight completed: fmt, warnings-denied release clippy and all 40 tests
passed (1 core, 20 model, 14 queue, 5 trace; none ignored), plus doc-tests. Session
59941 exited 0; heavy local slot handed directly to Symbiotic lane per parent.
