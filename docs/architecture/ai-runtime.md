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
| `queue_id` | The model's own queue (`operation:operator:model`) | Queue whose limits and cooldown the binding shares: isolate a role, or pool models |
| `policy` | Catalog default for the model (`default_model_queue_config`), else `ModelQueueConfig::default()` | Concurrency, rate limits, retries, timeout |
| `response_cache` | `Default` | `Default`: the runtime's own cache when persistent, no cache in memory. `Off`: every call reaches the provider. `Custom(cache)`: a host `ResponseCache` |
| `receipt_sink` / `trace_sink` | The runtime's sinks | Per-binding override |

## Persistence

| | `state_dir: None` | `state_dir: Some(dir)` |
|---|---|---|
| Queue backend | `MemoryQueue` (in-process, bounded terminal history) | `SqliteQueue` at `dir/queue.sqlite` |
| Cooldowns, attempt budgets, deduplication | End with the process | Survive restarts |
| Response cache (`Default` mode) | None | `dir/responses/<descriptor hash>/<kind>[/<scope>]/<request hash>.json` |

**Private state.** Cached responses and queue state can hold private text,
so the state directory and everything in it are owner-only:

- A missing `state_dir` is created `0700`, with any missing parents.
- An existing `state_dir` must be a directory owned by the current user,
  not a symlink, and closed to group and others. Otherwise `Runtime::open`
  fails with a message naming the path, for example
  `is open to group or others; make it owner-only (chmod 700)`.
- Inside it, the runtime creates directories `0700` and files `0600`: the
  database (SQLite gives its journal files the database's mode) and cache
  entries, written through a temporary file and a rename.
- A symlink, or a component owned by another user, anywhere under
  `responses/` or at the database files, is refused. It is never followed.
  At open, components that an earlier version wrote with wider permissions
  are tightened to `0700`/`0600`, so existing state keeps working.

Queue records hold the request hash, never the request. A crash therefore
cannot resume an in-flight call from the queue: the host re-issues its work,
and the cache and attempt budget make the re-issue cheap and bounded. For
example, a request that exhausted its attempts before a restart fails again
afterwards without another provider call.

**Retention.** At open, and after every 10,000 finished calls, a persistent
runtime retires state older than `RuntimeConfig::retention` (seven days by
default):

- calls orphaned by a crash are marked dead;
- finished calls' queue records are deleted, along with queue events;
- cached responses older than `RuntimeConfig::response_max_age` (30 days by
  default) are deleted, then the oldest ones until the rest fit in
  `response_max_bytes` (1 GiB by default). `None` disables either limit.

An expired response also misses on read, before any sweep removes it.
Periodic sweeps run on the blocking pool. A failed sweep is logged as a
`tracing` warning and retried at the next interval; it never fails a call.
A sweep or purge checks the whole cache tree before it deletes anything.
If the root or any component in it is a symlink or belongs to another user,
it refuses and removes nothing, so it can never reach outside the cache.

**Purge.** `Runtime::purge_responses(|cached| ...)` removes the cached
responses whose recorded owner matches. It is the hook for erasure: when a
source or tenant is erased, the host purges its responses. Each entry is
matched by what its response's trace records: the request's `source` and
`role_binding`, and the model (`CachedResponse`). A host that needs erasure
by tenant or source puts that identity in the request's `source` or
`role_binding`. The purge reads every entry once, so it suits erasure, not a
hot path.

Measured on one laptop with a 15 ms loopback provider, cap 64, 3,000 calls on
one thread: in memory 3,600 calls/s (the cap's ceiling), persistent
1,750 calls/s.

## Calls in flight

Once an attempt claims its queue item, the runtime owns it, not the caller.
The attempt runs as a task of its own, and the caller awaits its handle.
Dropping the caller's future (a job timeout, `tokio::time::timeout` around
`chat()`) therefore does not cancel the provider call. The attempt:

- finishes the provider call, bounded by `request_timeout_seconds`;
- records its receipts and trace, and stores the response in the cache when
  one applies;
- completes the item, or fails it with its error class and retry deadline;
- keeps its model slot until then, so an abandoned call still counts against
  `max_in_flight`.

An identical caller waiting on the item, or a later identical request, gets
the result through deduplication and the cache. Without a cache, it runs the
request again once the item has finished, as for any finished request.

The attempt renews its lease every third of `lease_seconds`, from its claim
until the item is completed or failed. That covers the provider call and
every receipt, trace, cache and cooldown write before the release, so a slow
sink cannot let the lease expire and hand the item to another caller. The
renewal is part of the attempt's own future, so it ends with the attempt and
cannot outlive it. It also stops once a renewal fails because the lease was
lost. Every exit of an attempt releases the lease, including a failed trace,
cache or cooldown write.

Renewal shares a task with the attempt, so nothing in the attempt may block
its thread. A `ResponseCache` is synchronous and may do file I/O, so every
cache read and write, the serialization of the stored response and the
`request_debug_dir` capture run on tokio's blocking pool. A slow disk
therefore delays only the call that is waiting for it.

There is no cancellation API. A provider that panics propagates the panic to
the waiting caller; its lease is not renewed and expires after
`lease_seconds`, as after a crash.

## Shared limits

Every provider handed out for one queue shares the limits below. By default a
queue is one model (`queue_id`, e.g. `chat:deepseek:deepseek-v4-pro`); a
binding's `queue_id` moves it to another queue. The providers of a queue
share:

- one concurrency cap. Callers wait FIFO for a slot (`ModelAdmission`), and the
  backend enforces the same cap;
- one requests-per-minute bucket and one input-units bucket (text length ÷ 4;
  one request charge per call or batch);
- one cooldown after rate-limit, unavailable or timeout errors.

Only a provider attempt spends rate budget. Before its claim, a caller waits,
with its item still pending, until the buckets hold enough for one attempt.
It holds the queue's rate gate from that check through the claim, and the
attempt charges the buckets once its claim succeeds, immediately before the
provider call. A caller whose item is not claimable spends nothing: one
waiting on an identical call in flight, or one waiting out a retry backoff.
Each attempt, including each retry, is charged once, and pacing stays exact
because no two callers can be cleared for the same budget.
A caller waiting for budget gives up its model slot and sleeps in slices of
at most 250 ms. Between slices it looks at its item and the cache, so a
duplicate whose answer has arrived returns at once and spends nothing.

Pooling shares limits only. Deduplication, attempt budgets and results stay
per provider: the idempotency key is the queue, the provider descriptor and
the request hash.

The key also includes the provider's credential generation,
`ModelProvider::credential_fingerprint`. The HTTP providers derive it from
their API key with `api_key_fingerprint`, a domain-separated SHA-256 of the
key. Rotating a key therefore starts a fresh attempt budget: a request
exhausted by a bad key is tried again with the new one. The fingerprint is
one-way, and only a hash of it enters the queue's idempotency key. Neither
the key nor the fingerprint is written to traces, receipts or queue
payloads. A host provider without a credential returns `None`, and its
budgets are keyed as before.

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
  two minutes. The backend stores the exact retry deadline
  (`QueueBackend::fail_with`), so no caller of the request retries earlier,
  and sub-second delays hold.
- `retry_provider_errors` (default `false`): also retry `ModelError::Provider`
  failures. Unavailable, rate-limited and timed-out calls always retry. Provider
  errors never start a cooldown.
- `request_debug_dir`: write each serialized request to
  `{dir}/{kind}[/{scope}]/{request_hash}.json` before it is queued. For
  debugging only: requests can contain sensitive text.
- `logical_retry_attempts` / `retry_attempts`: the request's total provider
  attempts across every retry layer, and the attempts per queue item. The
  logical budget is a cap: an item runs at most
  `min(retry_attempts, logical_retry_attempts)` attempts, so
  `logical_retry_attempts = 1` makes exactly one provider call. When the
  budget runs out, the error keeps the class of the last failure and says
  `exhausted after n/m`. The class is stored on the queue item
  (`last_error_class`), so a later call or a restarted runtime reports the
  same class.
- A lease that expires on an item's last allowed attempt, for example
  because the process crashed mid-call, ends the item as dead. A restarted
  runtime does not make another paid attempt.

- `budget_renewal_seconds` (default `None`): once a request has exhausted
  its budget, later calls for the same request fail without a provider call
  while the queue remembers it. On a persistent runtime that includes calls
  after a restart. `Some(n)` gives a new call a fresh budget after `n` seconds;
  `Some(0)` gives every call its own budget, for hosts that schedule their own
  retries. Renewing (and continuing a retry chain) replaces the dead item
  only while it is still the newest for the request
  (`QueueBackend::enqueue_replacing`), so a delayed caller cannot start a
  budget over one another caller renewed in the meantime.

A classify request that fails validation returns `InvalidRequest` before it
takes a queue slot.

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

## Side effects never change an outcome

Once the provider has answered, the call has been paid for, and the runtime
returns the answer. The writes that follow are best-effort: the response
cache, the trace, and the queue item's completion. The cache is an
optimisation, never a condition for returning a paid result. When one of
these writes fails:

- the response is returned, and its `Succeeded` usage receipt is recorded
  once;
- the failure is listed in the response trace's `metadata` under
  `RUNTIME_DIAGNOSTICS` (`"runtime_diagnostics"`), as
  `{"kind": ..., "error": ...}` entries, and the receipt's `metadata` carries
  the same list. The kinds are `response_cache_write_failed`,
  `trace_write_failed` and `queue_complete_failed`;
- it is logged as a `tracing` warning.

The same holds elsewhere. A cache hit whose trace write fails is still
returned, with the diagnostic. A failed call keeps its own error when its
failure trace or its cooldown cannot be written; those failures are logged,
and the retry proceeds as scheduled.

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
dependency. Its `conformance` feature exposes `queue_backend_conformance!`: 21
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
- expired-lease reclaim, with an expired final attempt ending dead;
- `fail_with` recording the error class and the exact retry deadline;
- `enqueue_replacing` superseding only the current newest item, atomically;
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

Only `symbiotic-ai-runtime`, `symbiotic-queue-sqlite` and the WP14
`symbiotic-credential-process` implementation link SQLite. The credential process
extends the runtime database with permit replay protection and uses the same runtime
with response caching disabled; see [model egress](model-egress.md).
`crates/symbiotic-model/tests/feature_graph.rs` checks that `symbiotic-core`,
`symbiotic-queue`, `symbiotic-trace`, `symbiotic-model` and
`symbiotic-portability` do not.
