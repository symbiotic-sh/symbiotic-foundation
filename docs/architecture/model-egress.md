# Credential-owned model egress (WP14)

The [Foundation boundary contract](boundary.md) is authoritative for provider
principals, grant-revision dispatch ordering, spend ownership and supported modes.
This page describes the local credential backend and version-4 API implementing
Foundation-owned spend and ordered caller/provider grant-revision acceptance.

Memory consumes **`symbiotic-egress` 0.2.0** (Rust path `symbiotic_egress`).
The executable and implementation crate are **`symbiotic-credential-process` 0.2.0**
(`symbiotic_credential_process`). They reuse the Foundation runtime and its
operational database; there is no second provider scheduler or spend owner.

## Shared schema and Memory integration

The schema is defined in `crates/symbiotic-egress/src/lib.rs` and `jobs_client.rs`.
`PROTOCOL_VERSION = 4`. The credential operation also requires
`InjectProviderCredential.operation_version = 4`.

| Current type / API | Meaning |
| --- | --- |
| `EgressClient::exchange(Request) -> Result<Response, EgressError>` | Async, object-safe seam for Memory and its test doubles |
| `socket::UnixEgressClient` | Local socket implementation, configured path, frame bound and timeout |
| `Request { version, operation }` | Operations are `IssuePermit(Box<SignedAttempt>)`, `InjectProviderCredential(Box<InjectProviderCredential>)`, `PublishGrantRevision(SignedGrantRevision)`, `Receipt(SignedAttemptId)`, `AttemptStatus(SignedAttemptId)` |
| `Response { version, result }` | Result is `Result<Reply, EgressError>`; error codes contain no arbitrary provider strings |
| `Reply` | `Permit(PermitGrant)`, `Dispatched(DispatchResult)`, `GrantRevisionPublished`, `Receipt(Option<DispatchReceipt>)`, `AttemptStatus(AttemptStatus)` |
| `DurableAttempt` | Exact record binding described below |
| `AdmissionKey` | Non-Debug/non-Serialize, zeroized HMAC key; `sign_attempt`, `verify_attempt`, `sign_attempt_id`, `verify_attempt_id`, `sign_grant_revision`, `verify_grant_revision` |
| `ProviderPayload` | `Chat(ChatRequest)`, `Embedding(EmbeddingRequest)`, `Rerank(RerankRequest)` or `Classify(ClassifyRequest)`; use its `digest()` helper, never a separately implemented serialization |
| `DispatchPermit { token, attempt_digest }` | Opaque random capability, accepted exactly once, including across process restarts |
| `InjectProviderCredential` | `operation_version`, `admission`, `permit`, `payload` |
| `DispatchResult` | `receipt`, optional typed `output`, optional static `error: EgressError`, typed `diagnostics: Vec<DispatchDiagnostic>`, `receipt_persisted` |
| `DispatchReceipt` | `attempt_digest`, `AttemptId`, typed `SpendReceiptRef`, `DispatchStatus`, provider-reported `UsageTrace`, read-only `SpendState` |
| `ProviderOutput` | Chat text with optional typed finish reason, embedding vectors/dimensions, rerank hits or typed classifier answers; no raw provider response, raw error, credentials or trace metadata |

`DurableAttempt` and related wire types are defined in
[`crates/symbiotic-egress/src/lib.rs`](../../crates/symbiotic-egress/src/lib.rs).
Use those definitions for current version-4 serialization; this page does not
provide a replacement wire schema. `input_digest` hashes the exact typed
`ProviderPayload` JSON via its `digest()` helper. `input_manifest_digest` binds
Memory's manifest bytes; Foundation verifies the binding, not the manifest's
policy contents. Secret references are tenant scoped, not file paths.

All protocol timestamps are absolute Unix seconds (UTC), never milliseconds.
`recorded_at` is the serialization time. The required signed/digested `expires_at`
is the exclusive authority deadline, greater than `recorded_at` and at most
`i64::MAX`. Memory sets it to cover the earliest applicable expiry of caller or
provider input authority, including their authorization dependencies. Foundation
checks its own clock at acceptance as described below. This is a per-attempt
deadline; a newly authorized attempt may renew it without changing the invocation's
input/provider binding. The separate recovery deadline remains immutable across retries.

The replacement integration order is specified once in
[boundary.md](boundary.md#grant-revision-and-dispatch-ordering). The admission MAC
key is distinct from provider credentials and authenticates trusted admission;
it is not end-user authentication. Integration responsibilities are defined in
the [ownership contract](boundary.md#ownership).

The current `EgressClient` test seam supports unknown-charge results. It re-exports
the payload construction types; consumers do not import the credential-process
implementation.

## Signed model jobs (Memory FQ4)

`JobsClient<C>` offers `enqueue`, `admit`, `completions`, `ack`, `cancel` and
`status` on either `InProcessEgressClient` or `UnixEgressClient`. The corresponding
wire operations are `EnqueueJobs`, `AdmitJob`, `Completions`, `AckJobs`, `CancelJobs`
and `JobStatus`. Each carries a `SignedJobsRequest`; the MAC covers the complete
`JobsRequest { scope, command }` under `symbiotic-egress/v4/jobs\0`. The outer
operation must match the signed command. Foreign job/token scopes are refused
before lookup or mutation. Replies use `Reply::Jobs(Result<JobsReply, JobError>)`.
No claim, heartbeat, checkpoint, worker completion or settlement operation is exposed.

An `EnqueueJob` contains a group, owners, a signed durable attempt and its exact
`ProviderPayload`. The signed invocation ID is the job key within
`JobScope { tenant, incarnation, queue }`. The frozen model binding, caller/manifest
binding and request participate in the payload's conflict digest. Group and
owners use the canonical job metadata; enqueue replays retain the original metadata.
Replaying enqueue joins the existing key, including after restart; it never
refreshes an admission or the route's frozen attempt ceiling. The signed job uses
that ceiling for reservation; the direct-egress one-send retry setting does not
reduce it. Each further claim still requires successor authority. `AdmitJob` updates
only the current signed authority, requiring the same immutable invocation binding
and increasing attempt ordinal and record sequence. An exact replay is idempotent.

Jobs use the existing model runner, account limiter and spend-ledger connection.
The account slot is acquired before the IMMEDIATE transaction that rechecks the
published grant revision and exclusive authority deadline, claims the job, reads
its waiting payload and reserves accounting. An invalidated admission moves an
unsent job to `AwaitingAdmission`, consumes no attempt or allowance, and retains
its input independently of recovery expiry. The shared egress payload preparation strips caller trace metadata and role labels
and uses the stable scoped invocation key for attribution. Provider secrets are resolved only
inside the claimed execution. No second scheduler, result copy or spend owner exists.
Local credential-resolution failures report authentication/configuration failure and
release the reservation without HTTP. Remote authentication rejection is not trusted
zero-charge evidence: its accounting and job remain uncertain.
Cancel before claim finalizes waiting work; cancel after claim arrives with the
lease heartbeat. Sent version-1 calls finish under their configured timeout.

`Completions { limit, max_bytes, wait_seconds }` long-polls up to
`io_timeout_seconds`; socket clients must configure a longer exchange timeout.
The byte bound covers the complete `JobsCompletions` body and must fit within
`max_frame_bytes` after subtracting the response envelope derived from the shared
wire serializer. Final deliveries
precede admission notices. A notice contains an ID/state/code and no delivery
fence; acknowledging an unfinished job returns `NotFinal`. An individually
oversized completion returns `CompletionTooLarge` before taking a delivery lease.
`JobStatus` reads one job's metadata without loading input, admission or output.
Group summaries and diagnostics are outside this six-operation subset.

`ProcessConfig.jobs` and `.job_runner` use the existing versioned `JobConfig` and
`RunnerConfig` defaults. Admission bytes count against pending utilization and
follow the same confirmation, cancellation and erasure deletion rules as input.
Queue schema 17 adds the current admission column and `AwaitingAdmission` to the
existing bounded live-row indexes; older formats are refused without migration.
Workers attach to an authenticated scope on its first job request (also after
restart). Dropped consumer futures leave Foundation-owned execution running.
The process state lock remains held until its runners drain. Worker failures
are reported by subsequent job requests and a failed attachment stays refused.
Ledger-first recovery preserves `Uncertain` after a kill during dispatch and never
resends it; final output is retained only by the ledger's existing recovery owner.

The acceptance tests are `jobs_*` in
`crates/symbiotic-credential-process/tests/egress.rs`: both transports, keyed joins,
revocation during account waits, successor authority after recovery expiry,
foreign scopes/MAC tampering, and executable kill/restart without resending.
`jobs_only_local_credential_failures_are_known_zero_charge` covers local resolution
versus remote rejection; `admission_bytes_share_maintenance_budget` in the SQLite
job tests covers admission deletion under the existing maintenance byte budget.

## Same-attempt recovery (v4)

V4 replaces earlier versions without aliases or fallback. Both request and credential-operation
versions, configuration version and HMAC domains are 4; the egress registry schema stamp is 6 and queue schema is 17.
Opening a registry with a different stamp fails with `Version`; no migration or reset is
performed. Operators must reconcile any old live attempts before provisioning fresh state;
never delete active replay history.
The crate package version remains 0.2.0 on this unreleased branch.

The exact public API is:

```rust
DurableAttempt::attempt_id(&self) -> AttemptId
AdmissionKey::sign_attempt_id(&self, AttemptId) -> Result<SignedAttemptId, EgressError>
EgressClient::attempt_status(&self, SignedAttemptId) -> Result<AttemptStatus, EgressError> // async
```

`AttemptId { tenant, incarnation, invocation_id, attempt_ordinal }` is the durable
identity. Status requests use `Operation::AttemptStatus(SignedAttemptId { attempt_id,
authentication })`, authenticated over `b"symbiotic-egress/v4/attempt-status\0"` plus
its typed identity JSON. The reply is `Reply::AttemptStatus(AttemptStatus)`. Knowing an
identity alone does not authorize lookup; Memory signs it only for its trusted recovery
path and applies its own caller/output disclosure checks before releasing recovered output.

`IssuePermit(Box<SignedAttempt>)` returns `Reply::Permit(PermitGrant { permit, status })`.
For the same identity and exact authenticated attempt digest, the permit token and digest
are unchanged, including after restart, consumption, completion, revocation, or expiry.
A different signed record for the same identity returns `InvalidRequest`. Reattachment
runs before current route configuration/admission checks; it grants no second dispatch.
`InjectProviderCredential` still consumes a capability exactly once. Concurrent issue
requests converge on one permit, and concurrent injections admit at most one handoff.

`AttemptStatus` is tagged by `state` in snake case:

| State | Fields / meaning |
| --- | --- |
| `NotIssued` | No permit for this identity; lookup does not issue one |
| `Permitted` | Unconsumed permit under the published revision with unexpired authority |
| `Invalidated` | Unconsumed permit superseded by publication or authority expiry; see [revocation rules](#revocation-replay-and-unknown-charges) |
| `Dispatched { receipt }` | Consumed, with no durable completion; receipt retains unknown reservation |
| `Completed { result }` | `DispatchResult` with typed `ProviderOutput`, measured usage/charge, no error |
| `Failed { result }` | `DispatchResult` with static `EgressError`, no output, and known-zero or unknown charge |
| `Expired` | Terminal result recovery deadline elapsed; `Receipt` still returns accounting |

The required signed `DurableAttempt.recovery_expires_at` is an exclusive absolute Unix
second deadline, greater than the first attempt's `recorded_at` and at most `i64::MAX`.
A successor may be recorded after recovery expiry: its authority deadline still
controls execution, while the original recovery deadline still prevents storing output. It is immutable
across invocation retries, distinct from authority `expires_at`, and chosen by Memory
for its recovery window. Terminal results are unavailable at or after that deadline.
Completion after the deadline persists accounting but never stores recovery output.
Expiry neither permits a new dispatch nor deletes accounting or replay tombstones.
Pending permits and uncertain dispatched attempts retain their authority/execution
state independently of the recovery deadline.

Expired result rows are cleared incrementally at startup, before operations, and every
second during socket serving, even when idle or connection slots are occupied. Each call
clears at most 64 results selected by the partial deadline index, regardless of the
expired backlog. Status lookup enforces the deadline even before physical cleanup.
Embedded users must periodically call `CredentialProcess::purge_expired_results()` while idle. Cleanup failure
returns `StateUnavailable`; the daemon fails visibly. SQLite secure-delete is enabled;
this is logical retention, not a forensic erasure guarantee for WAL files, backups, or
filesystem snapshots. These recovery records are protected by filesystem permissions,
not encrypted at rest. Users of this local backend must keep the state directory
owner-only; these requirements do not prescribe a universal deployment topology.

## Wire format

One request/response per Unix connection. Each frame is a **big-endian u32 byte length**
followed by UTF-8 JSON. Zero/oversized frames are refused before body allocation.
There is no line framing, compression, stream multiplexing or raw HTTP forwarding.
Unknown protocol/operation versions refuse dispatch.

Enums use snake-case tags. `Operation` has `operation` / `body` fields; `ProviderPayload`
has `kind` / `request`; `Reply` has `reply` / `body`. Rust's `Result` is serialized as
`{"Ok": ...}` or `{"Err": "error_code"}`. For example a refusal is:

```json
{"version":4,"result":{"Err":"permit_refused"}}
```

`IssuePermit` requests have the outer form:

```json
{"version":4,"operation":{"operation":"issue_permit","body":{"attempt":{},"authentication":"..."}}}
```

The empty object above stands for **all** `DurableAttempt` fields, not a valid request.
Use the shared Rust types, which reject absent required fields.
`SignedAttempt.authentication` is HMAC-SHA256 over
`b"symbiotic-egress/v4/attempt\0" || serde_json::to_vec(attempt)`.
Revision publications use `b"symbiotic-egress/v4/grant-revision\0"` and the `GrantRevision` value.
The `AdmissionKey` helpers define serialization and constant-time verification.

## Revocation, replay and unknown charges

The required grant-revision ordering is in
[boundary.md](boundary.md#grant-revision-and-dispatch-ordering).
`PublishGrantRevision` authenticates a `GrantRevision { tenant, incarnation, revision }`.
The tenant/incarnation revision covers both caller and provider authorization,
including memberships and every input dependency. This backend uses one tenant-wide
revision: a change invalidates all pending admissions in that incarnation, and
Memory must reauthorize both principals before submitting a new admission.
The initial positive revision must be published before any new admission.
There is no implicit revision or timestamp fallback.

Memory's trusted integration serializes its grant changes and admission checks
through publication. Publication acknowledgement is the effective grant-change
point; until acknowledged, Memory keeps the change pending and does not expose it
as effective. It must not sign admissions from an older check under a newer revision.
An asynchronous notification after an effective Memory change does not satisfy
this contract. Memory adoption implements this integration.

Publication durably advances the revision and refuses rollback; an exact replay
is idempotent. Permit issuance checks the published revision but reserves nothing.
Dispatch acceptance rechecks exact equality in the same immediate transaction as
permit consumption and ledger reservation. Inside that transaction, after acquiring
the writer lock and before consuming or reserving, Foundation samples its own clock
and requires `now < expires_at`. That transaction is the acceptance point and is
serialized with publication. A delayed attempt at or past its exclusive deadline
returns `EgressError::AuthorityExpired` (wire code `authority_expired`), with no
permit consumption, reservation, receipt or charge. New permit issuance also refuses
expired authority; exact reattachment still returns the existing capability and status.

A permit invalidated by a grant-revision change or authority expiry before handoff has status
`Invalidated`: it is not a charge, does not occupy the invocation and does not consume
`max_attempts`. Its capability remains refused, even if its K record preceded the change.
After Memory reauthorizes both principals, the next admission under the published revision
is a new handoff for the same invocation, with the following ordinal and a higher record
sequence and a currently valid signed deadline; it cannot mutate an existing signed attempt.
Ordinals may have gaps when durable attempts were never issued, including expiry before
issuance; issued ordinals and record sequences must still strictly increase.
Issuing a successor permanently invalidates an unconsumed predecessor. Acceptance refuses
that predecessor and status remains `Invalidated` even if Foundation's clock rolls back.
Ordinary expiry needs no revision publication, so reauthorization after expiry can
use the same published revision. For example, ordinal 1 issued
under revision 10 and invalidated by revision 11 permits a newly signed ordinal 2 under
revision 11 even with `max_attempts = 1`. Accepted handoffs retain execution, accounting,
status and receipt recovery after publication or authority expiry; any retry must
match the current revision and carry its newly checked authority deadline.

The existing runtime `queue.sqlite` is extended with `egress_permits` and
`egress_grant_revisions` replay-protection tables. They store hashes, ordinal/sequence,
grant-revision bindings, authority deadlines, accepted-handoff counts, consumption status,
recoverable permit tokens and accounting receipts. Pending status is projected from the
stored permit revision, the durably published revision, indexed successor existence
and Foundation's clock, so publication and authority expiry need no permit-history scan. V3 also stores
safe typed results until the signed recovery deadline, never prompts or provider credentials.
The owner-only database and same-UID authenticated IPC protect these recovery values.
SQLite FULL synchronization (including macOS fullfsync) makes consumption precede
handoff. A process lock prevents two credential processes using one state directory.
These tables do not schedule jobs. The existing runtime remains the only model
queue/scheduler. Permit consumption reserves through the canonical Foundation ledger in the same
transaction; completion updates the ledger and recovery result atomically. Route
`provider_request_limit` configures an absolute account request allowance, distinct
from pacing or monetary observations. Each receipt carries its accepted `AttemptId` and typed `SpendReceiptRef`.
`SpendState` and usage are observations projected from the canonical ledger;
Memory retains the reference and cannot reserve, release or settle through this protocol.

Before handoff the consumed permit has durable `SpendState::Unknown` and its
Foundation-owned one-request reservation. Timeout, uncertain provider failure or crash leaves it reserved.
`Receipt(SignedAttemptId)` returns accounting only, never a cached output; it returns
`None` when no consumption record exists. Capability reuse follows the revocation rules above.
A lost issue-permit reply is recovered by replaying the exact signed `IssuePermit`:
it returns the same capability and current state without allocating another attempt.
A lost dispatch reply is recovered with `AttemptStatus`; never resend a consumed permit.
There is no exactly-once external execution claim. A process crash before durable
completion leaves `Dispatched` with unknown accounting, requiring reconciliation or
a visible stop.

A received success with measured usage reports `SpendState::Settled` and available measured
input/output/reasoning/media/cost fields. Missing usage remains `None`; it is never
invented. `UsageTrace.reported_cost_usd` preserves validated provider-reported USD cost
as an exact decimal string, including sub-micro-dollar precision, in immediate receipts
and recovered results. It is separate from integer `cost_micro_usd`; the process neither
rounds it nor estimates prices, and does not establish a monetary ceiling.
Every failed dispatch returns a static credential-free `error` alongside
its receipt (`None` on success). Credential-loading and setup/queue failures before
transport handoff report `SpendState::Released` and release that reservation for a
subsequent admitted attempt, while the attempt-count limit still applies. Once the
raw transport starts, failures conservatively retain the unknown reservation.
Admission checks only the latest attempt using the invocation/ordinal index. For a
consumed predecessor, its receipt's canonical ledger state must be Released;
an unconsumed predecessor follows the revocation rule above. Success is terminal,
and other charges require reconciliation. The latest row carries the cumulative accepted
handoff count, incremented only with atomic consumption/reservation and copied to the next
row; earlier history needs no aggregate scan.
If the atomic final result/receipt write fails, the paid output still returns with
`receipt_persisted = false` and `SpendState::Unknown`; restart retains the earlier reservation and
`Dispatched` state. Receipt reconciliation and references follow the
[spend contract](boundary.md#spend-ledger-and-budgets). A paid output is not
evidence that canonical settlement was durably recorded.
Runtime queue-completion, trace-write and response-cache-write failures return the
static `queue_complete_failed`, `trace_write_failed` and `response_cache_write_failed`
diagnostics alongside the paid output and accounting state, even when the separate
registry write succeeds. Raw runtime diagnostic strings are never forwarded.

Memory supplies no budget unit, reservation, invocation spend limit, attempt
allowance or settlement instruction. The route owner configures a finite positive
`max_attempts` and an optional absolute account `provider_request_limit`.
Foundation reserves one provider request per accepted attempt and applies `max_attempts`
to accepted handoffs, rather than raw ordinals. After an accepted handoff, a logical invocation
is terminal on success; uncertain attempts stop retries, and only a known-zero
failure permits a new attempt within Foundation's allowance. HTTP protocol retries,
redirects and ambient proxies are disabled; runtime retry budgets are one.
No monetary reservation is supported or hard dollar ceiling promised; see
[the spend contract](boundary.md#spend-ledger-and-budgets).

## Deployment and credentials

This section applies to the supported Unix same-UID local backend. It is one
option within the [mode contract](boundary.md#supported-modes-and-trusted-channels).
Keyless routes use `secret: {"backend":"none"}` and an empty `secret_ref` in
configuration and admission. No credential is loaded or Authorization header sent.
The admission MAC key still requires a real secret source.

There are three sources: `none`, an owner-only file, and an app-supplied resolver.
Thread-mode apps pass `SecretSource::Resolver` through `ProcessConfig`.
The callback resolves a named key into zeroizing bytes. Foundation calls it only
after process protection is active. Provider keys are resolved lazily after permit
consumption. Resolver failures become `CredentialUnavailable`; their text is discarded.
Resolver configs cannot be serialized. `ProcessConfig::validate_child_process()`
refuses them with `ResolverRequiresThreadMode`; no callback crosses into a child.
In thread mode, the credential boundary protects against accidents, not same-process code.

Run `symbiotic-credential-process /absolute/path/config.json`. The JSON configuration
must be an owner-only regular file. Before reading configuration or secrets, the executable
sets both core resource limits to zero and, on Linux, clears dumpability with
`PR_SET_DUMPABLE` (piped core collectors ignore the resource limit). Either failure
refuses startup. Hosts embedding the library must establish equivalent process protection. Socket and runtime directories must be owner-only; socket peers must match the
process UID. A failed peer-credential lookup refuses only that connection, so a
client disconnect cannot terminate the recovery service. No credential is passed in argv, an environment fallback, protocol reply,
provider prompt, routine log or raw diagnostic. This local IPC boundary trusts the
same-user deployment; it is not an OS sandbox against a compromised same-UID process.

`ProcessConfig` version 4 requires `state_dir`, `socket_path`, `admission_key`,
`max_secret_bytes`, `max_frame_bytes`, `max_connections`, `io_timeout_seconds`, `routes`.
Each route names a concrete `account`; `account_sharing_key` is null for tenant/account
isolation, or explicitly pools execution across routes or tenants. Shared bindings
must agree on account limits. Each route requires all `RouteConfig` fields documented in the Rust type, including
finite field/input/response/token/concurrency/timeout settings. The escaped identity
field bounds, response allowance and reply envelope must fit `max_frame_bytes`
together; invalid bounds name `max_frame_bytes`, `max_field_bytes` and
`max_response_bytes`, and an oversized reply returns `LimitExceeded`.
These are configured
limits, not measured capacity; their labels and qualification follow
[boundary.md](boundary.md#bounds-as-labelled-settings). Startup registers every
route with the runtime. Concurrency, rate buckets and cooldowns are grouped by
`(tenant, account)` when `account_sharing_key` is null; matching model routes in
independent tenant accounts remain isolated. The same non-null sharing key
explicitly pools execution limits across routes, models and tenants. Bindings
in one group must agree on concurrency and pacing limits or startup is refused.
Route and registry validation runs before creating state, acquiring the process
lock, loading the admission key or opening the runtime. Frame-bound conflicts
return `InvalidFrameConfiguration`; other configuration conflicts return
`InvalidRequest`; actual state/IO failures return `StateUnavailable`.
Dropping the last process handle explicitly releases its lock so descriptors
inherited by concurrently spawned children cannot delay a subsequent reopen.
Unknown config fields
are refused. `requests_per_minute` and `input_units_per_minute` must be positive
when present; null leaves pacing unrestricted.

Child-process admission keys and authenticated provider routes use:

```json
{"backend":"owner_only_file","path":"/private/egress/provider-key"}
```

Keyless provider routes use:

```json
{"backend":"none"}
```

The `none` source is only for keyless provider routes, never admission keys.
Unknown secret backends are refused during configuration deserialization.
File values are exact UTF-8 bytes, with no automatic trimming. Files must be owned by
the process UID, be regular, have no group/other permission bits, and not be symlinks.
No remote secret backend or credential creation/rotation is performed.
Secret buffers and adapter key storage zeroize on drop.

Configured providers include `open_ai_chat { operator, thinking, reasoning_effort }`,
`anthropic_chat { operator, thinking }`, `jev_classifier { operator }`,
`gemini_embedding { dimensions }`, `compatible_embedding { adapter, operator,
dimensions, embedding_full_dimensions, embedding_input_tokens }` (adapter `open_ai_embedding` or
`ollama_embedding`), and `cohere_rerank { operator, rerank_input_bytes,
rerank_candidates, rerank_context_tokens, rerank_query_tokens }`. The token budgets
are the deployed model's usable query/document context after special/template tokens
and its query capacity. The shared adapter conservatively bounds UTF-8 bytes against
these token capacities and sends `max_tokens_per_doc` explicitly; see
[the admission contract](ai-runtime.md#configured-registry). They compile into the same validated registry as embedded
calls. Compatible transports use the configured base URL and preserve one HTTP
request per permit; Ollama batching is refused. Chat uses its configured base URL; Gemini is pinned
to `https://generativelanguage.googleapis.com/v1beta` and safe model-name characters.
HTTPS is required except explicitly enabled loopback HTTP. Userinfo, URL queries,
fragments, caller-controlled hosts and redirects are refused. The credential process ignores
ambient HTTP/HTTPS/ALL proxy settings so only the configured destination receives secrets.

OpenAI-compatible `thinking` is optional (`enabled` or `disabled`) and sends
`{"thinking":{"type":"enabled"}}` or `{"thinking":{"type":"disabled"}}` only
when configured. Optional typed `reasoning_effort` (`low`, `medium`, `high`) sends
that string only when configured; combining it with disabled thinking is refused.
Rabbithole's deployed DeepSeek profile uses enabled thinking and low effort. These
settings participate in the existing route configuration revision and use the same
encoder for admission byte checks and HTTP transmission.

Direct dispatch `DispatchResult` chat output includes
`finish_reason: Option<FinishReason>`. OpenAI `stop` and
Anthropic `end_turn`/`stop_sequence` map to `stop`; OpenAI `length` and Anthropic
`max_tokens`/`model_context_window_exceeded` map to `length`; other reported values
map to `other`. An absent provider reason remains absent. Token-limited text remains
available with its finish reason and accounting receipt, including recovery.
Arbitrary provider reason strings are excluded from direct dispatch output.
Anthropic tool, pause and refusal outcomes remain visible errors under the existing
Messages adapter contract; their partial text is never returned as a supported chat answer.

`ProviderPayload::Classify(ClassifyRequest)` uses the existing Jev System One
adapter at `POST {destination}/systemone`. The state is a JSON object containing
application data; questions are typed Noul, Choice or Score values. No arbitrary
HTTP body or provider options pass through. Question and option vector order is
the provider presentation order; returned answers preserve question order. The
route model is also the expected served model. Direct dispatch returns only the
validated `ClassifierAnswer` vector; raw response, provider metadata and local
trace labels are excluded. Applications own classification meaning and thresholds.

Job completions retain the sanitized canonical runtime response, as described by
`JobDelivery::output`: chat retains the provider's finish-reason string, and
classification includes `served_model` and `trace` alongside `answers`. Raw
provider responses and provider trace metadata are removed; runtime bookkeeping
remains in the trace. The direct dispatch normalization and answers-only
guarantees do not apply to job completions.

Classification uses the same signed payload digest, grant revision acceptance,
exclusive authority deadline, permit consumption, account reservation and recovery
path as chat. Admission and transmission share the Jev encoder and question/token
checks. One permit authorizes one HTTP send; reattachment or recovery never resends
it. A crash after sending and before durable completion retains unknown spend and
refuses replay. Existing model jobs also execute classification through their shared
runner. No new database, index, queue, cache or scheduler is introduced.

The `rabbithole_*` integration tests in
`crates/symbiotic-credential-process/tests/egress.rs` cover settings omission and
exact request bodies, finish reasons and recovered output, typed Jev answers and
once-only accounting, pre-consumption validation, and executable kill/reopen
without a second provider request.

`max_input_bytes` bounds both the typed payload and the complete encoded HTTP body,
including model names, repeated Gemini batch wrappers and JSON escaping. The same capped
provider encoder runs before permit consumption/secret loading and at transmission;
the adapters send its resulting bytes without re-serializing them. Oversized admission
returns `LimitExceeded` without consuming the permit.

The shared adapter-result boundary (`secrets::credential_boundary` in
`symbiotic-model`) wraps every credential-bearing HTTP adapter's complete result,
including typed decoding and answer validation, before runtime bookkeeping.
Queued calls also require the credential owner's opaque guard before any result
writes; raw adapters and chat-backed classification use that same boundary.
Injected credential-bearing adapters without a Foundation-owned guard are refused.
On
success it refuses credential echoes in raw JSON and typed output: exact bytes,
JSON-escaped UTF-8, numeric re-spellings (including `arbitrary_precision` numbers),
percent-encoded UTF-8 (upper/lower hex), standard Base64 and URL-safe Base64
(padded/unpadded). It discards raw provider JSON after checking it. On failure it
preserves typed error classes with static messages, so provider text never reaches
receipts, traces, queue storage or the response cache. All adapter clients are
Foundation-owned, disable redirects and HTTP retries, and ignore ambient proxies;
public client injection is unavailable.
The shared Gemini adapter rejects non-finite embedding components in single and
batch responses with a static provider failure; dispatch retains an unknown charge.
Other transformations are outside that finite guarantee. Persistent response caching,
request debug capture and raw trace metadata forwarding are disabled. Provider-side
cache isolation remains a provider-configuration/deployment responsibility; the broker does not
claim control over a remote provider's private prefix-cache implementation.

The process refuses an existing socket path instead of unlinking another listener.
After a crash, the owner verifies the old process is stopped before removing its stale
socket. Preserve the state directory to preserve single-use and accounting history.

## Evidence boundary

Targeted synthetic loopback tests exercise credential injection, all declared encodings,
response/error/log isolation, durable replay, grant-revision publication and acceptance, unknown charges,
cancellation, same-attempt attachment after lost permit/completion IPC replies, restart
recovery, digest mismatch refusal, exclusive result expiry, no cache, new-attempt retry,
pinned destinations, redirects, response/frame
limits, file protection, unsupported secret backend refusal and real executable IPC. These fixtures
are not a live-provider qualification or physical power-loss certification. The tests cover this backend's revision ordering and ledger accounting; Memory must
implement the trusted publication integration and its data authorization checks.
Memory input-authorization and guarded-commit verification belongs to Memory.
