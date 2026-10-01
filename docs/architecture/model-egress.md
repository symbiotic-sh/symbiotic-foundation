# Credential-owned model egress (WP14)

The [Foundation boundary contract](boundary.md) is authoritative for provider
principals, grant-revision dispatch ordering, spend ownership and supported modes.
This page describes the current local credential backend and version-2 API;
it does not claim those APIs already satisfy the replacement contract.

Memory consumes **`symbiotic-egress` 0.2.0** (Rust path `symbiotic_egress`).
The executable and implementation crate are **`symbiotic-credential-process` 0.2.0**
(`symbiotic_credential_process`). The implementation reuses the Foundation runtime
and its operational database; it has no second provider scheduler.

**Implementation gaps:** the current schema still carries obsolete policy fields
and a caller-supplied reservation, compares record sequences on route keys rather than
the [caller-and-provider grant-revision ordering](boundary.md#grant-revision-and-dispatch-ordering),
still rejects a marking equal to `unclassified`, and lacks complete tenant/provider/configuration
identity and the canonical Foundation spend ledger. Replacement protocol and
accounting work must follow [boundary.md](boundary.md), not preserve these semantics.

## Shared schema and Memory integration

The schema is defined once in `crates/symbiotic-egress/src/lib.rs`.
`PROTOCOL_VERSION = 2`. The credential operation also requires
`InjectProviderCredential.operation_version = 2`.

| Current type / API | Meaning |
| --- | --- |
| `EgressClient::exchange(Request) -> Result<Response, EgressError>` | Async, object-safe seam for Memory and its test doubles |
| `socket::UnixEgressClient` | Local socket implementation, configured path, frame bound and timeout |
| `Request { version, operation }` | Operations are `IssuePermit(SignedAttempt)`, `InjectProviderCredential(Box<InjectProviderCredential>)`, `RevokeRoute(SignedRevocation)`, `Receipt(SignedAttempt)`, `AttemptStatus(SignedAttemptId)` |
| `Response { version, result }` | Result is `Result<Reply, EgressError>`; error codes contain no arbitrary provider strings |
| `Reply` | `Permit(PermitGrant)`, `Dispatched(DispatchResult)`, `Revoked`, `Receipt(Option<DispatchReceipt>)`, `AttemptStatus(AttemptStatus)` |
| `DurableAttempt` | Exact record binding described below |
| `AdmissionKey` | Non-Debug/non-Serialize, zeroized HMAC key; `sign_attempt`, `verify_attempt`, `sign_attempt_id`, `verify_attempt_id`, `sign_revocation`, `verify_revocation` |
| `ProviderPayload` | `Chat(ChatRequest)` or `Embedding(EmbeddingRequest)`; use its `digest()` helper, never a separately implemented serialization |
| `DispatchPermit { token, attempt_digest }` | Opaque random capability, accepted exactly once, including across process restarts |
| `InjectProviderCredential` | `operation_version`, `admission`, `permit`, `payload` |
| `DispatchResult` | `receipt`, optional typed `output`, optional static `error: EgressError`, typed `diagnostics: Vec<DispatchDiagnostic>`, `receipt_persisted` |
| `DispatchReceipt` | `attempt_digest`, `DispatchStatus`, provider-reported `UsageTrace`, `ChargeReport` |
| `ProviderOutput` | Chat text or embedding vectors/dimensions; no raw provider response, raw error, credentials or trace metadata |

`DurableAttempt` and related wire types are defined in
[`crates/symbiotic-egress/src/lib.rs`](../../crates/symbiotic-egress/src/lib.rs).
Use those definitions for current version-2 serialization; this page does not
provide a replacement wire schema. `input_digest` hashes the exact typed
`ProviderPayload` JSON via its `digest()` helper. `input_manifest_digest` binds
Memory's manifest bytes; Foundation verifies the binding, not the manifest's
policy contents. Secret references are tenant scoped, not file paths.

The replacement integration order is specified once in
[boundary.md](boundary.md#grant-revision-and-dispatch-ordering). The admission MAC
key is distinct from provider credentials and authenticates trusted admission;
it is not end-user authentication. Integration responsibilities are defined in
the [ownership contract](boundary.md#ownership).

The current `EgressClient` test seam supports unknown-charge results. It re-exports
the payload construction types; consumers do not import the credential-process
implementation.

## Same-attempt recovery (v2)

V2 replaces v1 without aliases or fallback. Both request and credential-operation
versions, configuration version, and HMAC domains are 2. Opening a v1 egress registry
fails with `Version`; no migration or reset is performed. Operators must reconcile any
old live attempts before provisioning fresh v2 state; never delete active replay history.
The crate package version remains 0.2.0 on this unreleased branch.

The exact public API is:

```rust
DurableAttempt::attempt_id(&self) -> AttemptId
AdmissionKey::sign_attempt_id(&self, AttemptId) -> Result<SignedAttemptId, EgressError>
EgressClient::attempt_status(&self, SignedAttemptId) -> Result<AttemptStatus, EgressError> // async
```

`AttemptId { tenant, incarnation, invocation_id, attempt_ordinal }` is the durable
identity. Status requests use `Operation::AttemptStatus(SignedAttemptId { attempt_id,
authentication })`, authenticated over `b"symbiotic-egress/v2/attempt-status\0"` plus
its typed identity JSON. The reply is `Reply::AttemptStatus(AttemptStatus)`. Knowing an
identity alone does not authorize lookup; Memory signs it only for its trusted recovery
path and applies its own caller/output disclosure checks before releasing recovered output.

`IssuePermit(SignedAttempt)` returns `Reply::Permit(PermitGrant { permit, status })`.
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
| `Permitted` | Committed permit has not been consumed |
| `Dispatched { receipt }` | Consumed, with no durable completion; receipt retains unknown reservation |
| `Completed { result }` | `DispatchResult` with typed `ProviderOutput`, measured usage/charge, no error |
| `Failed { result }` | `DispatchResult` with static `EgressError`, no output, and known-zero or unknown charge |
| `Expired` | Terminal result recovery deadline elapsed; `Receipt` still returns accounting |

The required signed `DurableAttempt.recovery_expires_at` is an exclusive absolute Unix
second deadline, greater than `recorded_at` and at most `i64::MAX`. It is immutable
across invocation retries, distinct from authority `expires_at`, and chosen by Memory
for its recovery window. Terminal results are unavailable at or after that deadline.
Completion after the deadline persists accounting but never stores recovery output.
Expiry neither permits a new dispatch nor deletes accounting or replay tombstones.
Permitted and uncertain dispatched attempts keep their state after the deadline.

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
{"version":2,"result":{"Err":"permit_refused"}}
```

`IssuePermit` requests have the outer form:

```json
{"version":2,"operation":{"operation":"issue_permit","body":{"attempt":{},"authentication":"..."}}}
```

The empty object above stands for **all** `DurableAttempt` fields, not a valid request.
Use the shared Rust types, which reject absent required fields.
`SignedAttempt.authentication` is HMAC-SHA256 over
`b"symbiotic-egress/v2/attempt\0" || serde_json::to_vec(attempt)`.
Revocations use `b"symbiotic-egress/v2/revocation\0"` and the `RouteRevocation` value.
The `AdmissionKey` helpers define serialization and constant-time verification.

## Revocation, replay and unknown charges

The required grant-revision ordering is in
[boundary.md](boundary.md#grant-revision-and-dispatch-ordering). The current v2
`RouteRevocation`/`RevokeRoute` API and registry compare `record_sequence` on each
route key, retaining the earliest revoked sequence;
this is an implementation gap, not the authorization contract for new adoption.
Already accepted handoffs and their accounting remain recoverable.

The existing runtime `queue.sqlite` is extended with `egress_permits` and
`egress_revocations` replay-protection tables. They store hashes, ordinal/sequence,
consumption status, recoverable permit tokens and accounting receipts. V2 also stores
safe typed results until the signed recovery deadline, never prompts or provider credentials.
The owner-only database and same-UID authenticated IPC protect these recovery values.
SQLite FULL synchronization (including macOS fullfsync) makes consumption precede
handoff. A process lock prevents two credential processes using one state directory.
These tables do not schedule jobs. The existing runtime remains the only model
queue/scheduler. They supply replay and charge-recovery primitives; the canonical
Foundation spend ledger remains implementation work under
[boundary.md](boundary.md#spend-ledger-and-budgets).

Before handoff the consumed permit has a durable `ChargeReport::Unknown` carrying the
full reservation. Timeout, uncertain provider failure or crash leaves it reserved.
`Receipt` returns accounting only, never a cached output. An absent receipt means no
consumption record exists, not permission to reuse an already refused permit.
A lost issue-permit reply is recovered by replaying the exact signed `IssuePermit`:
it returns the same capability and current state without allocating another attempt.
A lost dispatch reply is recovered with `AttemptStatus`; never resend a consumed permit.
There is no exactly-once external execution claim. A process crash before durable
completion leaves `Dispatched` with unknown accounting, requiring reconciliation or
a visible stop.

A received success reports measured provider requests (one) and available measured
input/output/reasoning/media/cost fields. Missing usage remains `None`; it is never
invented. `UsageTrace.reported_cost_usd` preserves validated provider-reported USD cost
as an exact decimal string, including sub-micro-dollar precision, in immediate receipts
and recovered results. It is separate from integer `cost_micro_usd`; the process neither
rounds it nor estimates prices, and `ChargeReport` still measures provider requests.
Every failed dispatch returns a static credential-free `error` alongside
its receipt (`None` on success). Credential-loading and setup/queue failures before
transport handoff report known zero requests and release that reservation for a
subsequent admitted attempt, while the attempt-count limit still applies. Once the
raw transport starts, failures conservatively retain the unknown reservation.
Retry admission checks only the latest receipt using the invocation/ordinal index:
it must be a measured zero-charge failure in the reserved unit. Success is terminal,
and other charges require reconciliation, so earlier history needs no aggregate scan.
If the atomic final result/receipt write fails, the paid output still returns with
`receipt_persisted = false`; restart retains the earlier unknown reservation and
`Dispatched` state. Receipt reconciliation and references follow the
[spend contract](boundary.md#spend-ledger-and-budgets). A paid output is not
evidence that canonical settlement was durably recorded.
Runtime queue-completion, trace-write and response-cache-write failures return the
static `queue_complete_failed`, `trace_write_failed` and `response_cache_write_failed`
diagnostics alongside the paid output and measured charge, even when the separate
registry write succeeds. Raw runtime diagnostic strings are never forwarded.

V2 accepts only `ReservedBudget.unit = "provider_requests"`, `amount = 1`, with a finite
invocation limit and `max_attempts`. The adapters enforce one HTTP request per permit:
HTTP protocol retries, redirects and ambient proxies are disabled; runtime retry budgets are one.
Monetary units are refused with `BudgetRefused`. Budget guarantees and the
distinction between request bounds and money are specified in
[boundary.md](boundary.md#spend-ledger-and-budgets).

## Deployment and credentials

This section applies to the supported Unix same-UID local backend. It is one
option within the [mode contract](boundary.md#supported-modes-and-trusted-channels).
The current backend requires secret sources even for loopback bindings; keyless
binding support remains implementation work.

Run `symbiotic-credential-process /absolute/path/config.json`. The JSON configuration
must be an owner-only regular file. Before reading configuration or secrets, the executable
sets both core resource limits to zero and, on Linux, clears dumpability with
`PR_SET_DUMPABLE` (piped core collectors ignore the resource limit). Either failure
refuses startup. Hosts embedding the library must establish equivalent process protection. Socket and runtime directories must be owner-only; socket peers must match the
process UID. A failed peer-credential lookup refuses only that connection, so a
client disconnect cannot terminate the recovery service. No credential is passed in argv, an environment fallback, protocol reply,
provider prompt, routine log or raw diagnostic. This local IPC boundary trusts the
same-user deployment; it is not an OS sandbox against a compromised same-UID process.

`ProcessConfig` version 2 requires `state_dir`, `socket_path`, `admission_key`,
`max_secret_bytes`, `max_frame_bytes`, `max_connections`, `io_timeout_seconds`, `routes`.
Each route names a concrete `account`; `account_sharing_key` is null for tenant/account
isolation, or explicitly pools execution across routes or tenants. Shared bindings
must agree on account limits. Each route requires all `RouteConfig` fields documented in the Rust type, including
finite field/input/response/token/concurrency/timeout settings. These are configured
limits, not measured capacity; their labels and qualification follow
[boundary.md](boundary.md#bounds-as-labelled-settings). Startup registers every
route with the runtime and refuses conflicting concurrency or pacing limits for a
shared model queue, including routes in different tenants. When those limits agree,
the current backend pools those tenants' rate buckets and cooldowns. This is the
accidental sharing forbidden by the
[boundary contract](boundary.md#tenant-provider-bindings-and-data-access), not the
target configuration; explicit tenant/account isolation remains implementation work.
Unknown config fields
are refused. `requests_per_minute` and `input_units_per_minute` must be positive
when present; null leaves pacing unrestricted.

Both admission and provider sources use one of:

```json
{"backend":"owner_only_file","path":"/private/egress/provider-key"}
```

```json
{"backend":"macos_keychain","service":"foundation-egress","account":"tenant/provider-key"}
```

File values are exact UTF-8 bytes, with no automatic trimming. Files must be owned by
the process UID, be regular, have no group/other permission bits, and not be symlinks.
Keychain reads use Security.framework's generic-password API; non-macOS keychain
configuration fails closed. No command-line keychain tool, remote backend or credential
creation/rotation is performed. Secret buffers and adapter key storage zeroize on drop.

Configured providers are `open_ai_chat { operator }` and
`gemini_embedding { dimensions }`. Chat uses its configured base URL; Gemini is pinned
to `https://generativelanguage.googleapis.com/v1beta` and safe model-name characters.
HTTPS is required except explicitly enabled loopback HTTP. Userinfo, URL queries,
fragments, caller-controlled hosts and redirects are refused. The credential process ignores
ambient HTTP/HTTPS/ALL proxy settings so only the configured destination receives secrets.

`max_input_bytes` bounds both the typed payload and the complete encoded HTTP body,
including model names, repeated Gemini batch wrappers and JSON escaping. The same capped
provider encoder runs before permit consumption/secret loading and at transmission;
the adapters send its resulting bytes without re-serializing them. Oversized admission
returns `LimitExceeded` without consuming the permit.

The safe provider wrapper rejects a response containing the injected credential in
any declared representation: exact bytes, JSON-escaped UTF-8, percent-encoded UTF-8
(upper/lower hex), standard Base64 and URL-safe Base64 (padded/unpadded). It scans string
values before forwarding and discards raw errors before the runtime can log them.
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
response/error/log isolation, durable replay, current record-sequence revocation on route keys, unknown charges,
cancellation, same-attempt attachment after lost permit/completion IPC replies, restart
recovery, digest mismatch refusal, exclusive result expiry, no cache, new-attempt retry,
pinned destinations, redirects, response/frame
limits, file protection and real executable IPC. The macOS keychain API is compiled;
no real user credential or keychain item is read or created by tests. These fixtures
are not a live-provider qualification or physical power-loss certification. They
do not establish the grant-revision ordering or Foundation spend-ledger contract.
Memory input-authorization and guarded-commit verification belongs to Memory.
