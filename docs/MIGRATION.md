# Migration Plan

This repo starts as a clean foundation. Existing Symbiotic code is migrated by
adapters, not by big-bang replacement.

## Phase 0 — Contracts

Status: implemented.

- Define crate boundaries.
- Define core queue/model/trace traits.
- Keep current Symbiotic runtime untouched.
- Use compile checks and small trait tests only.

## Phase 1 — Queue Prototype

Build a first-party SQLite queue backend behind `symbiotic-queue`.

Status: implemented and covered by unit tests, including multi-connection
idempotency/claim behavior, lease-owner enforcement, expired-lease rejection,
expired-lease reclaim, event persistence, retry/dead-letter, and reopen/resume.

Required behavior:

- atomic enqueue with idempotency key;
- atomic claim with lease owner and lease expiry;
- per-queue `max_in_flight` enforced by the host scheduler;
- heartbeat;
- complete;
- fail with retry or dead-letter;
- reclaim expired leases;
- append queue events.

Reference material:

- current runtime `symbiotic-queue`;
- Apalis SQLite backend;
- taskmill lifecycle events;
- qoxide reserve/complete/fail shape.

## Phase 2 — Model Runtime Prototype

Build a minimal provider runtime around foundation contracts.

Status: partially implemented.

First adapters:

- hash/test embedding provider;
- OpenAI-compatible chat provider;
- Codex CLI/session provider;
- Gemini embedding provider or `genai` substrate adapter.

Hard requirements:

- every call returns or emits `ModelInvocationTrace`;
- every adapter classifies auth/rate-limit/budget/timeout separately;
- provider output includes usage and cache fields when available;
- raw provider responses are optional and redaction-aware.

Implemented now: hash/test embedding, static test chat, OpenAI-compatible chat,
Gemini embedding, exact response cache, queue-bound wrappers, prompt-cache
telemetry fields where adapters expose them, and retry classification.

Missing before product-wide use: Codex CLI/session adapter, optional `genai`
adapter, stronger adapter-specific HTTP error classification, cost calculation,
and host-owned credential resolution for concrete HTTP adapters.

## Phase 3 — Trace Sinks

Implement sinks as adapters, not as dependencies:

Status: partially implemented.

| sink | target |
| --- | --- |
| usage meter | cost/budget records |
| audit sink | forensic LLM I/O log |
| Archive trace sink | memory/evolution capture source |
| benchmark sink | experiment artifacts |
| external sink | OpenTelemetry or warehouse export |

Memory accepts host-supplied trace documents. Memory does not scrape providers.

Implemented now: JSONL sink, in-memory sink, fail-fast fanout, best-effort
wrapper, queue-event JSONL/in-memory sinks, and a `symbiotic-queue` event-sink
adapter. Missing: first-class usage/audit/Archive/benchmark sink adapters.

## Phase 4 — Symbiotic Runtime Bridge

Add bridge crates or modules inside the product runtime:

- wrap existing daemon provider registry behind `symbiotic-model`;
- map existing `UsageRecord` into `ModelInvocationTrace`;
- map existing queue jobs into `symbiotic-queue`;
- keep the existing product behavior green while routing one non-critical flow
  through the new foundation.

Candidate first flow: benchmark harness or provider preflight, not the daemon's
main agent loop.

## Phase 5 — Symbiotic Memory Bridge

Move standalone memory off local queue/provider copies:

Status: in progress.

- replace local `ChatProvider` and `EmbeddingProvider` traits with foundation
  traits or thin adapters;
- replace local provider queue with host-supplied queue/model runtime;
- add `capture_model_trace` or accept an Archive trace document from the host;
- preserve benchmark reproducibility.

Implemented now: memory CLI HTTP providers can use foundation model queues,
workflow LongMemEval row execution uses a foundation SQLite queue, provider and
queue trace sinks can be attached from the benchmark runner, external score
artifacts can be recorded into manifests, answer-only reruns can reuse complete
vaults, and original source artifacts are preserved under each vault. Remaining:
remove the memory-local provider trait/queue copies or reduce them to thin
compatibility adapters and replace local benchmark stage orchestration with
durable per-stage work items.

## Phase 6 — Extraction Decision

Only after the interfaces survive real runtime and memory use:

- publish crates;
- split implementations into feature crates if useful;
- consider renaming `symbiotic-model` to `symbiotic-providers` if that is the
  stronger public name;
- decide whether `symbiotic-auth` deserves its own crate.

## Explicit Rollback

Until Phase 4, this repository is additive. Rollback is deleting the dependency
from experimental adapters. The existing Symbiotic runtime remains the source of
truth for production behavior.
