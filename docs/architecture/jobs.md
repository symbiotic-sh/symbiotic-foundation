# Generic job store version 1 (proposal)

Following the lead's queue design §13, version 1 provides atomic batch enqueue
with scoped keys, deduplication and key conflicts; claims with leases and
claim-generation fencing; completions with delivery leases and fenced Accepted
or Discarded confirmation; job/group cancellation; owner-tag erasure with a
sticky purged flag; pending/result bounds; bounded maintenance; transaction
participation; per-job lookup/status and paged Failed/Uncertain diagnostics.
Payloads and handler results are opaque bytes (`Vec<u8>` in memory, SQLite
`BLOB`), preserved exactly. Paid answers remain exclusively in the spend ledger;
the store retains only their receipt reference and reconciliation state.

Later: admission attempts/notices → PR 4 (Memory egress); checkpoints → Warden adoption PR; cache-origin results → the caching consumer PR; priority/background share → the shared-scheduler consumer PR; group summaries/resumable rebuild → Memory adoption PR (D5b Q3).

The store uses `JobConfig` version 1 in both backends. Every default below is
**PROVISIONAL**; R9-D2 settles final values. Apps supply versioned configuration.

| Setting | Provisional default | Reason |
|---|---:|---|
| `max_pending_items` | 1,024 | Bound unfinished work while allowing a bulk submission. |
| `max_pending_bytes` | 16 MiB | Bound retained raw input bytes plus encoded metadata before writes. |
| `max_batch` | 64 | Bound atomic enqueue and confirmation requests. |
| `max_page` | 64 | Bound claim, delivery and diagnostic selections. |
| `max_page_bytes` | 1 MiB | Bound serialized candidate and completion arrays. |
| `max_result_bytes` | 16 MiB | Refuse larger raw handler results before commit. |
| `maintenance_bytes_per_pass` | 16 MiB | Bound raw payload/result bytes erased per expiry pass. |
| `claim_lease_seconds` | 30 seconds | Permit timely handler recovery after a lost worker. |
| `delivery_lease_seconds` | 30 seconds | Reduce overlap while retaining at-least-once delivery. |
| `max_leased_completions` | 256 (4 × default maximum page size) | Bound skipped live leases in delivery cursor order. |
| `maintenance_batch` | 64 | Bound each expiry pass and each atomic erasure/cancel chunk. |
| `retention_seconds` | 7 days | Allow consumer recovery when no explicit result deadline is provided. |

Enqueue and claim use `(created_at, id)` order. Final delivery uses
`(finished_at, id)`; diagnostics, owner erasure and group cancellation use
ascending IDs with exclusive cursors. SQL timestamps are INTEGER Unix
milliseconds within chrono's representable range; both backends quantize
ordinary clock precision to milliseconds and reject leap seconds or overflowing
deadlines before commit.

Pending utilization is derived from unfinished canonical rows: raw payload
length plus the encoded metadata tuple `(scope, key, group, owners, kind,
execution, max_attempts)`. No pending-byte counter is stored.

Expiry processes jobs in `(recovery_until, id)` order, up to `maintenance_batch`
and `maintenance_bytes_per_pass`. The byte budget counts raw payload and result
copies erased by the pass. A nonempty pass always erases at least one job: a job
larger than the budget is erased alone. Subsequent jobs are deferred if they
would exceed the remaining budget; a pass stops when its budget is reached.
Unfinished jobs never expire solely because their recovery deadline passed.

Following the lead's queue design §12, unconfirmed finals have a partial delivery
index; a per-scope live-lease cap bounds examined candidates by page plus cap.
`CompletionPage.lease_cap_reached` reports delivery backpressure. Failed/Uncertain
diagnostics use a partial index. Owner membership is derived from canonical job
owners in an indexed table; erasure drains bounded chunks within one atomic
transaction. Memory keeps corresponding rebuildable lookup/order indexes and
an operation-local undo journal of touched rows.

Completion selection reads stored encoded result lengths and delivery metadata
before loading saved answers. The existing length column counts the serialized
byte-array representation for exact page preflight, while the result limit and
maintenance budget count raw bytes. Diagnostics and expiry maintenance use
content-free projections; expiry deletes copies directly. Encoded lengths and
all indexes are rebuildable from canonical rows. The unreleased SQLite schema
version is 13; older layouts are refused without migration.
