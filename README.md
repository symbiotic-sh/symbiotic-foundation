# Symbiotic Foundation

Reusable Rust contracts for durable AI work:

- `symbiotic-ai-runtime` — **the entry point for model calls.** Open one
  `Runtime` (persistent with a state directory, in memory without) and get
  ready chat, embedding, rerank and classifier providers. Queueing, retries,
  limits, cooldowns, attempt budgets, caching, traces, usage receipts and
  persistence are internal. See [docs/architecture/ai-runtime.md](docs/architecture/ai-runtime.md).
- `symbiotic-core` — tiny shared vocabulary and identifiers.
- `symbiotic-queue` — durable execution queue traits and state vocabulary,
  plus the in-process `MemoryQueue` backend and a backend conformance suite; no
  storage dependency.
- `symbiotic-queue-sqlite` — the local SQLite backend (`SqliteQueue`) for those
  traits.
- `symbiotic-model` — provider-neutral model/operator runtime traits: chat,
  embedding, rerank and classification (typed questions answered with
  probabilities, served by TypeSafe System One or any chat model). The
  queue-bound `Queued*` wrappers are its default `queue` feature;
  `default-features = false` gives the contracts and HTTP providers without the
  queue runtime. Neither configuration links SQLite. Hosts use the queued
  providers through `symbiotic-ai-runtime`; building them directly is
  unsupported.
- `symbiotic-trace` — normalized invocation traces and pluggable sinks.
- `symbiotic-portability` — external record interchange validation and explicit
  CSV/Markdown presentations; no Memory or application mutation dependency.

This repository is contract-first. It intentionally does not own Symbiotic memory, Archive,
Gatekeeper, Vault, Matrix transport, or agent role evolution. Product runtimes compose these crates
and decide policy.

## Why This Exists

The current Symbiotic runtime and memory experiments proved the shape, but the code grew around
urgent benchmark and product needs. This workspace rebuilds the generic layer directly:

```text
symbiotic-memory  -> foundation traits
symbiotic-runtime -> foundation implementations + policy
foundation        -> no dependency on memory/runtime
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/MIGRATION.md](docs/MIGRATION.md).
