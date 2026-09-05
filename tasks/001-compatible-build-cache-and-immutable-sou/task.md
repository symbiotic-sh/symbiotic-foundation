---
id: 001
title: Compatible build cache and immutable source artifacts
status: active
owner: foundation
priority: P2
depends_on:
lane:
design:
pr:
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
