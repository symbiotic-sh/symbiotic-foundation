# AI runtime

`symbiotic-ai-runtime` is the one way hosts run model calls. A host opens a
`Runtime` and gets ready providers back. Everything between the call and the
provider stays inside the runtime: queueing, retries and backoff, rate and
concurrency limits, cooldowns, attempt budgets, the response cache, traces,
usage receipts and persistence.

The [Foundation boundary contract](boundary.md) is authoritative for ownership,
provider-principal authorization, spend, storage and supported modes. This page
records current runtime behavior. Typed tenant/provider/configuration binding scopes execution and result reuse.
Canonical spend accounting and admission/maintenance bounds remain implementation work; this API alone supplies none of Memory's data
authorization checks. The error-class retry gaps listed under
[policy knobs](#policy-knobs) remain implementation work under the
[spend contract](boundary.md#spend-ledger-and-budgets).

Design record: [docs/design/8-ai-runtime.md](../design/8-ai-runtime.md)
(issue #8).

## Use

```rust
use symbiotic_ai_runtime::{ModelBinding, ModelQueueConfig, Runtime, RuntimeConfig};

let runtime = Runtime::open(RuntimeConfig {
    state_dir: Some(data_dir.join("ai-runtime")), // None: in memory
    ..RuntimeConfig::default()
})?;
let policy = ModelQueueConfig::default(); // explicit, conservative policy for this account
let identity = symbiotic_ai_runtime::BindingIdentity::new("tenant-a", "chat", "revision-1", "account-a");
let chat = runtime.chat(ModelBinding::new(raw_chat).with_identity(identity.clone()).with_policy(policy.clone()))?;          // Arc<dyn ChatProvider>
let embed = runtime.embedding(ModelBinding::new(raw_embedder).with_identity(identity.clone()).with_policy(policy.clone()))?; // Arc<dyn EmbeddingProvider>
let rerank = runtime.rerank(ModelBinding::new(raw_reranker).with_identity(identity.clone()).with_policy(policy.clone()))?;   // Arc<dyn RerankProvider>
let classify = runtime.classifier(ModelBinding::new(raw).with_identity(identity).with_policy(policy))?;      // Arc<dyn ClassifierProvider>
```

This example shows current runtime assembly, not complete authorized credential
dispatch. Credential-bearing transports stay inside Foundation; consumer adoption
follows [boundary.md](boundary.md#ownership).

A binding's `provider` is the raw transport: one of `symbiotic_model`'s HTTP
providers, or a host type implementing the provider trait
(`Arc<dyn ChatProvider>` and the other trait objects work too). Open the
runtime once per process or data root and share its clones. Every clone uses
the same state.

`ModelBinding` options:

| Field | Default | Meaning |
|---|---|---|
| `identity` | Required | Tenant, provider principal, configuration revision and concrete account |
| `account_sharing_key` | None | Tenant/account execution state; an explicit key pools accounts across bindings or tenants |
| `policy` | Required explicit policy, or the configured registry account | Concurrency, rate limits, retries, timeout |
| `response_cache` | `Default` | `Default`: the runtime's own cache when persistent, no cache in memory. `Off`: every call reaches the provider. `Custom(cache)`: a host `ResponseCache` |
| `receipt_sink` / `trace_sink` | The runtime's sinks | Per-binding override |

## Configured registry

`ModelRegistry::from_json` validates the entire current-version configuration before
serving. Pass `Arc<ModelRegistry>` in `RuntimeConfig::registry`, then call
`Runtime::configured_provider(tenant, principal, credential_resolver)`. It returns
an installed chat, Gemini/OpenAI/Ollama embedding, Cohere rerank or Jev classifier adapter. Keyless bindings do
not call the credential resolver. Unknown tenants/principals and configuration,
transport or policy overrides are refused.

| Family | Required configuration |
|---|---|
| `models` | Unique ID and aliases, canonical model identity, installed adapter, supported operation, advisory capabilities; prices require provenance/date |
| `bindings` | Typed tenant/provider/revision/account identity, model ID or alias, endpoint, optional secret reference, account policy, explicit sharing key or null, finite request/response bytes and chat output tokens, effective settings |
| `accounts` | Named explicit execution policy: concurrency, timeout, attempts and optional pacing; no model-name fallback |

The [example catalogue](../../examples/model-registry.json) contains one synthetic
model with an alias and **no bindings or accounts**. It enables no provider.
Aliases use the canonical model on the wire and resolve the same capabilities.
Unsupported advertised operations/settings, ambiguous aliases, unusable limits,
endpoint credentials and conflicting shared-account policies refuse startup.
Credential-process deployment routes compile into this same validated registry;
they retain their existing permit protocol and single-attempt policy.

Every supported HTTP adapter requires finite nonzero encoded request and response
byte limits for success bodies, including chunked bodies. Non-success HTTP bodies
are discarded without decoding or retaining their bytes; the status determines the
error class, including for invalid UTF-8 bodies. Chat also requires a
finite output-token bound; requests above a configured bound are refused. Gemini
requires the exact configured dimension for every returned vector. Its adapter
refuses task options and conflicting per-request dimensions before dispatch.
Compatible embeddings require explicit `dimensions` and `embedding_full_dimensions`.
For Memory's Qwen3-Embedding-8B profile, configure both as 1,024; reduced dimensions
are configurable per binding or OpenAI-compatible request, within the full ceiling.
OpenAI/OpenRouter uses `/embeddings` with `input`, `dimensions` and optional `input_type`
from request `task`; it restores batch input order and validates every vector.
Ollama uses `/api/embeddings` with `prompt`; batch, task and dimension overrides
are refused before HTTP. Foundation never splits one invocation into multiple calls.
Cohere/OpenRouter uses `/rerank` with `query`, `documents` and `top_n`. Required
`rerank_input_bytes` (sum of query/candidate UTF-8 bytes) and `rerank_candidates`
are hard admission limits, separate from encoded request/response bytes. Invalid,
duplicate or non-finite hits refuse the whole response; valid hits are sorted by score.
These adapters use the same queue, credential boundary and receipt/accounting hook.
No provider binding, model default, separate scheduler or spend ledger is added.
Provider credentials and derived secret buffers use the shared non-Debug,
non-serializable `SecretValue` zeroizing container; `ResolvedAuth` is also non-Debug.

Without a registry, raw Foundation bindings require an explicit execution policy.
`default_model_queue_config` and `default_model_capabilities` are removed; consumers
must configure accounts rather than infer limits from a model/operator name.
Sensitivity remains a typed request/trace field pending protocol cleanup, but has
no selection, cache or dispatch authority. Memory owns provider grants.

## Errors and credential boundary

`ModelError`, `QueueError` and `TraceError` carry closed `DiagnosticCode` values
(or a typed unsupported capability), never free-form strings. Adapter validation,
provider decoding, cache, storage and restored failures cannot attach provider or
credential text to an error. Diagnostics and logs retain static codes only. The
credential owner still checks successful raw and normalized outputs before results
reach runtime bookkeeping, and discards raw provider JSON.

## Persistence

| | `state_dir: None` | `state_dir: Some(dir)` |
|---|---|---|
| Queue backend | `MemoryQueue` (in-process, bounded terminal history) | `SqliteQueue` at `dir/queue.sqlite` |
| Cooldowns, attempt budgets, deduplication | End with the process | Survive restarts |
| Response cache (`Default` mode) | None | `dir/responses/<kind>/<binding and transport hash>/<request hash>.json` |

**Private state.** Cached responses and queue state can hold private text,
so the state directory and everything in it are owner-only:

- A missing `state_dir` is created `0700`, with any missing parents.
- An existing `state_dir` must be a directory owned by the current user,
  not a symlink, and closed to group and others. Otherwise `Runtime::open`
  fails with a static queue diagnostic. State paths and underlying filesystem
  error text are never copied into runtime errors.
- Inside it, the runtime creates directories `0700` and files `0600`: the
  database (SQLite gives its journal files the database's mode) and cache
  entries, written through a temporary file and a rename.
- A symlink, or a component owned by another user, anywhere under
  `responses/` or at the database files, is refused. It is never followed.
  The current implementation also tightens existing component permissions at open.
  This does not establish a legacy-format compatibility requirement; state format
  and unresolved-attempt handling follow
  [boundary.md](boundary.md#storage-and-credentials).

Queue records hold the request hash, never the request. A crash therefore
cannot resume an in-flight call from the queue. Recovery requirements follow the
[spend contract](boundary.md#spend-ledger-and-budgets). The current credential backend
provides [same-attempt recovery](model-egress.md#same-attempt-recovery-v2); the general
runtime still requires that recovery integration. The cache and
attempt budget are execution primitives, not spend reconciliation. For example,
a request that exhausted its attempts before a restart fails again
afterwards without another provider call.

**Current retention settings.** At open, and after every 10,000 finished calls, a persistent
runtime retires state older than `RuntimeConfig::retention` (seven days by
default):

- calls orphaned by a crash are marked dead;
- finished calls' queue records are deleted, along with queue events;
- cached responses older than `RuntimeConfig::response_max_age` (30 days by
  default) are deleted, then the oldest ones until the rest fit in
  `response_max_bytes` (1 GiB by default). `None` disables either limit.

An expired response also misses on read, before any sweep removes it.
These are sweep-based soft cache limits, not hard byte admission bounds. Pending
count/bytes and per-batch/idle work remain unbounded by these settings; see
[boundary.md](boundary.md#bounds-as-labelled-settings).
Periodic sweeps run on the blocking pool. A failed sweep is logged as a
`tracing` warning and retried at the next interval; it never fails a call.
This is a visibility gap: retention can stop without a caller-visible error.
Visible maintenance failure reporting remains implementation work alongside the
soft limits and unbounded maintenance noted above.
A sweep or purge checks the whole cache tree before it deletes anything.
If the root or any component in it is a symlink or belongs to another user,
it refuses and removes nothing, so it can never reach outside the cache.

**Purge.** `Runtime::purge_responses(|cached| ...)` removes the cached
responses whose recorded owner matches. It is the hook for erasure: when a
source or tenant is erased, the host purges its responses. Each entry is
matched by what its response's trace records: the request's `source` and
`role_binding`, model, and typed binding identity (`CachedResponse::binding`).
Tenant erasure matches `binding.tenant`, independently of free-text source labels. The purge reads every entry once, so it suits erasure, not a
hot path.

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

## Current shared limits

Execution state belongs to the runtime. By default queues and rate state are
keyed by typed tenant and concrete account; all models on that account share its
policy. An explicit `AccountSharingKey` pools execution across bindings or tenants.
Independent runtimes have separate in-process rate state. Persistent cooldowns
belong to their queue backend, so deliberately sharing a state directory shares
that durable account state. Poisoned rate/admission locks and closed gates return
visible `ModelError::Queue` errors; they never bypass pacing. Accounts share:

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
per provider: the idempotency key is the queue, the tenant/provider/revision/account identity, effective provider descriptor,
credential generation and request hash. Endpoint, thinking and effort settings enter
the descriptor; custom providers must describe their effective configuration.

The key also includes the provider's credential generation,
`ModelProvider::credential_fingerprint`. The HTTP providers derive it from
their API key with `api_key_fingerprint`, a domain-separated SHA-256 of the
key. Rotating a key therefore starts a fresh attempt budget: a request
exhausted by a bad key is tried again with the new one. The fingerprint is
one-way, and only a hash of it enters the queue's idempotency key. Neither
the key nor the fingerprint is written to traces, receipts or queue
payloads. A host provider without a credential returns `None`, and its
budgets are keyed as before. This fresh queue budget does not establish charge
certainty for an earlier attempt or authorize resubmitting an unknown charge;
admission and recovery follow the
[spend contract](boundary.md#spend-ledger-and-budgets). That integration remains
a known implementation gap.

Raw bindings without a registry must agree on `max_in_flight`, `requests_per_minute`,
`input_units_per_minute` and `rate_burst_seconds`. A binding that disagrees
fails with `ModelError::InvalidRequest`. Retry and timeout settings may differ
per raw binding. Registry bindings of one account use an identical configured
execution policy, including timeout and retries.

## Policy knobs

Retry admission and recovery follow the
[spend contract](boundary.md#spend-ledger-and-budgets). The current `is_retryable`
policy retries `ModelError::Timeout`, `ModelError::Unavailable` (5xx, including 529)
and `ModelError::RateLimited` (429) without checking charge certainty. Opt-in
`retry_provider_errors` adds `ModelError::Provider` to that policy. All four classes
are known gaps across the shared queued chat, embedding, rerank and classification
paths and remain implementation work.

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
  failures. `ModelQueueConfig::default()`
  allows three attempts when explicitly chosen; registry account policies specify
  their own finite total attempts. These settings expose the error-class
  retry gaps listed above. Provider errors
  never start a cooldown.
- `request_debug_dir`: write each serialized request to
  `{dir}/{kind}[/{scope}]/{request_hash}.json` before it is queued. For
  development builds only (`debug_assertions`): requests can contain sensitive
  text. Production builds refuse a policy containing this setting at bind time.
- `logical_retry_attempts` / `retry_attempts`: the request's total provider
  attempts across every retry layer, and the attempts per queue item. The
  logical budget is a cap: an item runs at most
  `min(retry_attempts, logical_retry_attempts)` attempts, so
  `logical_retry_attempts = 1` makes exactly one provider call. When the
  budget runs out, the error keeps the class of the last failure and says
  `attempt budget exhausted`. Queue items store only a typed diagnostic code
  (`last_error`) and typed class (`last_error_class`), so a later call or a
  restarted runtime rebuilds the same class without stored text.
- A lease that expires on an item's last allowed attempt, for example
  because the process crashed mid-call, ends the item as dead. A restarted
  runtime does not make another paid attempt from that item. On a non-final
  attempt, both queue backends instead mark the item failed and allow another
  claim without checking the earlier attempt's charge certainty. This is another
  recovery gap under the
  [spend contract](boundary.md#spend-ledger-and-budgets).

- `budget_renewal_seconds` (default `None`): once a request has exhausted
  its budget, later calls for the same request fail without a provider call
  while the queue remembers it. On a persistent runtime that includes calls
  after a restart. `Some(n)` gives a new call a fresh budget after `n` seconds;
  `Some(0)` gives every call its own budget. These are current queue mechanics;
  renewal does not prove zero charge or authorize resending an uncertain attempt.
  Retry admission and recovery must follow
  [boundary.md](boundary.md#spend-ledger-and-budgets); that alignment remains an
  implementation gap.
  Renewing (and continuing a retry chain) replaces the dead item
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

These usage receipts support telemetry and cost reporting. They are not the
canonical spend ledger or an enforceable monetary reservation. Accounting ownership
and budget guarantees are specified in
[boundary.md](boundary.md#spend-ledger-and-budgets). Receipt errors carry only
static diagnostic codes; they cannot contain provider response text.

## Current post-provider writes

The behavior below describes runtime cache/trace/queue writes. Foundation ledger
reservation, settlement and unknown-charge recovery are durable obligations under
[boundary.md](boundary.md#spend-ledger-and-budgets), not optional telemetry.

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
returned, with the diagnostic. A failed failure-trace write is logged. A failed cooldown write returns a
queue error and persists a stopped item, because execution without its account
limiter is not allowed. Stopped items cannot be claimed, continued as logical retry
chains or renewed by `budget_renewal_seconds`; identical waiters and later calls
return the recorded refusal while the queue retains the item. Failures without a
retry deadline also stop the item. Retryable failures with a deadline become failed
or dead according to their attempt budget. This does not establish safe retry
admission; the current policy's charge-certainty gap is described above.

## Custom response caches

`ResponseCache` is the seam for an alternate cache. `load` receives request kind,
scope, request hash and the serialized request; `Ok(None)` falls through to a
provider call. Custom caches must respect the result-identity and data-lifecycle
contract in [boundary.md](boundary.md#tenant-provider-bindings-and-data-access) and its
[storage rules](boundary.md#storage-and-credentials).

## Backends and conformance

`symbiotic-queue` ships `MemoryQueue`, the in-process backend with no storage
dependency. Its `conformance` feature exposes `queue_backend_conformance!`: 22
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

A new backend passes the same macro. SQLite creates only the current schema;
queue files require schema version 2 and the current queue table layouts.
Other layouts are refused without migration. Unknown stored failure codes/classes
are refused with a static error. Terminal items without a recorded error class
return a queue error, without inferring a
class from provider text.

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
