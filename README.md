# Symbiotic Foundation

Reusable Rust contracts for durable AI work:

- `symbiotic-core` — tiny shared vocabulary and identifiers.
- `symbiotic-queue` — durable execution queue traits and state vocabulary.
- `symbiotic-model` — provider-neutral model/operator runtime traits.
- `symbiotic-trace` — normalized invocation traces and pluggable sinks.

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
