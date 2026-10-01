---
status: implemented
issue: 8
---

# 8 — AI runtime facade

Shipped behaviour: [architecture/ai-runtime.md](../architecture/ai-runtime.md).
The operator approved this design on 2026-09-28 (issue #8). This page keeps the
decisions and the alternatives they replaced.

The current [Foundation boundary contract](../architecture/boundary.md) supersedes
this record's model-only limit grouping, legacy-cache retention and host tariff
ownership. The decisions below preserve the original facade rationale; current
provider/account isolation, spend and bounds follow the boundary contract.

## Problem

Queued provider calls were implemented three times across Foundation's
consumers: Foundation's `Queued*` providers, a consumer-local provider-queue
stack, and a consumer-local durable journal. Fixes reached one copy at a time.
Consumers forked because Foundation offered only a SQLite backend and lacked
behaviour one of them depended on. The Stage-4 gate asks for zero duplicate
rate-limiter/rerank/queue implementations.

## Decisions

1. **The AI layer is a stateful black box.** Hosts open a `Runtime` and get
   ready providers. Queueing, retries, limits, cooldowns, attempt budgets, the
   cache, traces, receipts and persistence are internal.
   - *Rejected:* shipping more backends and wrappers for consumers to wire
     themselves. That is how the copies diverged: each consumer re-assembled
     the pieces and then re-implemented the missing ones.
2. **Persistence is a runtime choice, not a consumer build.** A `state_dir`
   selects the existing SQLite backend. None selects the in-memory backend.
   - *Rejected:* a new file-journal backend. The audit found that no backend
     can resume an in-flight call (queue items hold only a request hash), so
     a durable queue buys restart-persistent budgets, cooldowns and
     deduplication. SQLite already provides those.
   - *Rejected:* making persistence a Cargo feature, which would reintroduce
     per-consumer wiring.
3. **A separate crate, `symbiotic-ai-runtime`, is the only SQLite-linking
   crate besides the backend.** `symbiotic-model` and `symbiotic-queue` stay
   storage-free, as #7 established. A host that bans embedded databases in its
   own code can allow exactly this boundary.
   - *Rejected:* `symbiotic_model::Runtime`, which would put SQLite into every
     model-contract build.
4. **Limits are per model, shared by every binding — superseded.** Current grouping follows
   [explicit tenant/account sharing](../architecture/boundary.md#tenant-provider-bindings-and-data-access).
   The original implementation used a FIFO
   semaphore per `queue_id`, with the backend cap as the cross-process
   backstop. Conflicting shared limits are an error, not first-wins.
   - *Rejected:* the backend cap alone, whose 25 ms claim polling is unfair and
     busy at high fan-in.
   - *Rejected:* a process-global default admission, which couples unrelated
     runtimes and tests.
5. **The cache is a seam — legacy-reader requirement superseded.** Current storage follows
   [current-format storage](../architecture/boundary.md#storage-and-credentials).
   The original `ResponseCache` seam received the serialized request so hosts could
   keep reading legacy layouts. The runtime's own cache is scoped by provider descriptor.
   - *Rejected:* migrating legacy caches, which is impossible for keys that are
     one-way hashes of inputs.
   - *Rejected:* the old per-kind shared directory, where two models could
     answer for each other.
6. **Receipts, not host-side ledgers — host tariff ownership superseded.** Accounting follows
   [Foundation's canonical spend ledger](../architecture/boundary.md#spend-ledger-and-budgets).
   Per-attempt `QueueReceipt`s carry
   usage, provider receipt metadata, units and waits. The original design had hosts
   price them with their own tariffs.
7. **Retry knobs over forks.** A base delay (sub-second allowed), an opt-in to
   retry provider errors, and rate burst cover the behaviour a consumer's copy
   had. The defaults are unchanged.
   Retry knobs do not establish safe admission: uncertain attempts must follow
   [Foundation recovery](../architecture/boundary.md#spend-ledger-and-budgets).
   Current timeout retries remain a gap assigned to audit PRs 5/6.
8. **Repeating a finished request without a cached answer runs it again.**
   Before, this returned a cache error. Queue records coordinate calls; they do
   not hold answers.
9. **Retention.** A persistent runtime retires state older than seven days at
   open and every 10,000 finished calls.
   - *Rejected:* unbounded tables in long-running daemons.
