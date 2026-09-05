---
id: 001
title: Compatible build cache and immutable source artifacts
status: review
owner: foundation
priority: P2
depends_on:
lane: .github/workflows/ci.yml, scripts/, rust-toolchain.toml, docs/architecture/build-artifacts.md, crates/symbiotic-model/src/lib.rs, crates/symbiotic-queue/src/lib.rs
design:
pr: https://github.com/symbiotic-sh/symbiotic-foundation/pull/1
created: 2026-09-05T05:19:45Z
updated: 2026-09-05T05:50:20Z
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

## Retry fixture isolation

Corrected hosted cold 33947361391 built 152 units in 79s and passed clippy, but
`queued_chat_provider_waiter_shares_logical_retry_envelope` hit its 5s timeout.
The failure reproduces locally using the already-built model test executable:
`logical_retry --test-threads=1 --nocapture` => 2 pass, 1 timeout, 9.22s.
Parallel and two-thread focused runs passed, revealing order-sensitive shared
state. The preceding test leaves process-global model cooldown under the same
identity even though test queues are independent. The fixture-only repair gives
independent retry tests distinct model identities while duplicate clones retain
the same key, and keeps all assertions and the original timeout.

Parent approved one final corrected cold plus one warm after local validation;
another unrelated hosted failure must stop retries. Waiting for Symbiotic's
exclusive build slot before recompiling the test fixture repair. No hosted
source archive or warm cache proof exists yet. Raw evidence is in .debug-session.

Fixture isolation validated in local session 31786: exact serial reproduction
now 3/3 pass (8.42s overall; original waiter timeout remains 5s). Full 40 tests,
clippy -D warnings and fmt pass. Local slot released. Proceeding only with parent’s
final approved cold/warm pair; any unrelated failure is a reported blocker.

## Final evidence

Final run33947992655 cold and warm both pass. Cold152 compiled/0 Fresh/78s;
warm8 compiled/144 Fresh/11s, exact cache hit and identical native digest/source
revision. Both40-test gates green. Source artifact9963966062 and proof9963966279
published; downloaded checksums and extracted workspace layout verified. Cold and
warm source bytes identical. Full report: docs/reports/2026-09-05-build-cache-proof.md.
No remaining implementation blocker; PR#1 remains unmerged for review. Final
commit is evidence-only with CI skipped; executable candidate2132e85 is unchanged.
