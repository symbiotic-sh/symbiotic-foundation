# AI runtime

`symbiotic-ai-runtime` is the one way hosts run model calls. A host opens a
`Runtime` and gets ready providers back. Everything between the call and the
provider stays inside the runtime: queueing, retries and backoff, rate and
concurrency limits, cooldowns, attempt budgets, the response cache, traces,
usage receipts and persistence.

Design record: [docs/design/8-ai-runtime.md](../design/8-ai-runtime.md)
(issue #8).

## Use

```rust
use symbiotic_ai_runtime::{ModelBinding, Runtime, RuntimeConfig};

let runtime = Runtime::open(RuntimeConfig {
    state_dir: Some(data_dir.join("ai-runtime")), // None: in memory
    ..RuntimeConfig::default()
})?;
let chat = runtime.chat(ModelBinding::new(raw_chat))?;          // Arc<dyn ChatProvider>
let embed = runtime.embedding(ModelBinding::new(raw_embedder))?; // Arc<dyn EmbeddingProvider>
let rerank = runtime.rerank(ModelBinding::new(raw_reranker))?;   // Arc<dyn RerankProvider>
let classify = runtime.classifier(ModelBinding::new(raw))?;      // Arc<dyn ClassifierProvider>
```

A binding's `provider` is the raw transport: one of `symbiotic_model`'s HTTP
providers, or a host type implementing the provider trait
(`Arc<dyn ChatProvider>` and the other trait objects work too). Open the
runtime once per process or data root and share its clones. Every clone uses
the same state.

`ModelBinding` options:

| Field | Default | Meaning |
|---|---|---|
| `policy` | Catalog default for the model (`default_model_queue_config`), else `ModelQueueConfig::default()` | Concurrency, rate limits, retries, timeout |
| `response_cache` | `Default` | `Default`: the runtime's own cache when persistent, no cache in memory. `Off`: every call reaches the provider. `Custom(cache)`: a host `ResponseCache` |
| `receipt_sink` / `trace_sink` | The runtime's sinks | Per-binding override |

## Persistence

| | `state_dir: None` | `state_dir: Some(dir)` |
|---|---|---|
| Queue backend | `MemoryQueue` (in-process, bounded terminal history) | `SqliteQueue` at `dir/queue.sqlite` |
| Cooldowns, attempt budgets, deduplication | End with the process | Survive restarts |
| Response cache (`Default` mode) | None | `dir/responses/<descriptor hash>/<kind>[/<scope>]/<request hash>.json` |

A missing `state_dir` is created with mode `0700` and the database with mode
`0600` (SQLite gives its journal files the database's mode). An existing
directory's mode is left alone.

Queue records hold the request hash, never the request. A crash therefore
cannot resume an in-flight call from the queue: the host re-issues its work,
and the cache and attempt budget make the re-issue cheap and bounded. For
example, a request that exhausted its attempts before a restart fails again
afterwards without another provider call.

**Retention.** At open, and after every 10,000 finished calls, a persistent
runtime retires state older than `RuntimeConfig::retention` (seven days by
default):

- calls orphaned by a crash are marked dead;
- finished calls' queue records are deleted, along with queue events.

Cached responses are kept.

Measured on one laptop with a 15 ms loopback provider, cap 64, 3,000 calls on
one thread: in memory 3,600 calls/s (the cap's ceiling), persistent
1,750 calls/s.

## Shared limits

Every provider handed out for one model (`queue_id`, e.g. `chat:deepseek:deepseek-v4-pro`)
shares:

- one concurrency cap. Callers wait FIFO for a slot (`ModelAdmission`), and the
  backend enforces the same cap;
- one requests-per-minute bucket and one input-units bucket (text length ÷ 4;
  one request charge per call or batch);
- one cooldown after rate-limit, unavailable or timeout errors.

Bindings of one model must agree on `max_in_flight`, `requests_per_minute`,
`input_units_per_minute` and `rate_burst_seconds`. A binding that disagrees
fails with `ModelError::InvalidRequest`. Retry and timeout settings may differ
per binding.

## Policy knobs

`ModelQueueConfig` fields:

- `rate_burst_seconds` (default `0`): seconds of rate budget available as an
  initial burst. `0` paces from the first request. `60` admits one minute's
  budget at once, as per-minute metering allows.
- `retry_base_delay_ms` (default `1000`): the first retry delay. It doubles per
  attempt up to 32x, capped at 30 s (or at the base, if that is longer), plus
  up to `retry_jitter_seconds` of deterministic jitter. The total is at most
  two minutes, and sub-second delays are honoured.
- `retry_provider_errors` (default `false`): also retry `ModelError::Provider`
  failures. Unavailable, rate-limited and timed-out calls always retry. Provider
  errors never start a cooldown.
- `request_debug_dir`: write each serialized request to
  `{dir}/{kind}[/{scope}]/{request_hash}.json` before it is queued. For
  debugging only: requests can contain sensitive text.
- `logical_retry_attempts` / `retry_attempts`: the request's total attempt
  budget and the attempts per queue item. They are unchanged.

## Receipts

A `QueueReceiptSink` gets one `QueueReceipt` per step of a call:

- `Queued` (attempt 0);
- `Running`, with the queue and throttle waits;
- `Succeeded`, with usage, cache counts, the provider's receipt metadata and
  provider time;
- `Failed`, with the error, before any retry;
- `CacheHit`, which repeats the original usage and receipt and makes no
  provider call.

Cost estimation stays with the host's tariff: the receipt carries the token
counts it needs. `QueueReceipt::redacted` replaces error text for logs that
must not keep response bodies.

## Response-cache compatibility

`ResponseCache` is the seam for a cache the runtime did not write. `load`
receives the request kind, scope, request hash and the serialized request, so
a host can compute its historical key, for example a hash of the raw prompt
text, and return the stored response converted to the provider's response
type. Returning `Ok(None)` falls through to a provider call. A host keeps an
existing cache readable this way, and no re-run is needed.

The runtime does not migrate foreign caches. A layout keyed by a one-way hash
of inputs cannot be re-keyed without those inputs, so a host that must not pay
twice keeps its reader as a `Custom` cache.

## Backends and conformance

`symbiotic-queue` ships `MemoryQueue`, the in-process backend with no storage
dependency. Its `conformance` feature exposes `queue_backend_conformance!`: 18
checks of the `QueueBackend` contract. Both `MemoryQueue` and `SqliteQueue` run
them in CI:

- deduplication dispositions;
- default attempts and schedule;
- per-queue idempotency;
- claim order and future items;
- `max_in_flight` for `claim` and `claim_item`;
- claim races;
- lease-owner and running checks;
- heartbeat;
- retry to dead;
- retry delay;
- expired-lease reclaim;
- cooldown monotonicity;
- unknown items.

A new backend passes the same macro.

## Lower-level types

`symbiotic-model`'s `Queued*` providers, `ModelAdmission`, and constructing
queue backends for them stay public only because this crate composes them.
Consumers that build them directly are unsupported: behaviour such as shared
admission, cache scoping and retention is only guaranteed through the runtime.
`symbiotic_ai_runtime::model` re-exports the provider contracts and HTTP
providers for building raw transports.

Only `symbiotic-ai-runtime` and `symbiotic-queue-sqlite` link SQLite.
`crates/symbiotic-model/tests/feature_graph.rs` checks that `symbiotic-core`,
`symbiotic-queue`, `symbiotic-trace`, `symbiotic-model` and
`symbiotic-portability` do not.
