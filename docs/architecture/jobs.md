# Generic job store policy (proposal)

The store uses `JobConfig` version 1 in both backends. Every default below is
**PROVISIONAL**; R9-D2 settles final values. Apps supply versioned configuration.

| Setting | Provisional default | Reason |
|---|---:|---|
| `max_pending_items` | 1,024 | Bound unfinished work while allowing a bulk submission. |
| `max_pending_bytes` | 16 MiB | Bound retained input, metadata and checkpoint bytes before writes. |
| `max_batch` | 64 | Bound atomic enqueue and confirmation requests. |
| `max_page` | 64 | Bound claim, delivery and diagnostic selections. |
| `max_page_bytes` | 1 MiB | Bound serialized candidate and completion arrays. |
| `max_result_bytes` | 16 MiB | Refuse larger encoded cache/handler results before commit. |
| `maintenance_bytes_per_pass` | 16 MiB (**PROVISIONAL**) | Bound encoded recovery-copy and result bytes erased per expiry pass. |
| `max_checkpoint_bytes` | 64 KiB | Bound handler progress retained with unfinished jobs. |
| `claim_lease_seconds` | 30 seconds | Permit timely handler recovery after a lost worker. |
| `delivery_lease_seconds` | 30 seconds | Reduce overlap while retaining at-least-once delivery. |
| `max_leased_completions` | 256 (4 × default maximum page size) | Bound skipped live leases in delivery cursor order. |
| `maintenance_batch` | 64 | Bound each expiry or summary-rebuild pass and each atomic erasure/cancel chunk. |
| `retention_seconds` | 7 days | Allow consumer recovery when no explicit result deadline is provided. |
| `priority` | `BackgroundShare { minimum_slots: 1 }` | Give bulk work progress while interactive work is waiting. |

Enqueue and claim use `(created_at, id)` order. Final delivery uses
`(finished_at, id)` before admission notices; diagnostics, owner erasure, group
cancellation and summary rebuilding use ascending IDs with exclusive cursors.
SQL timestamps are INTEGER Unix milliseconds within chrono's representable range;
both backends quantize ordinary clock precision to milliseconds and reject leap
seconds or overflowing deadlines before commit.

Expiry processes jobs in `(recovery_until, id)` order, up to `maintenance_batch`
and `maintenance_bytes_per_pass`. The byte budget counts the encoded payload,
checkpoint, admission and result copies erased by the pass, derived from the
canonical rows. A nonempty pass always erases at least one job: a job larger than
the budget is erased alone in its pass. Subsequent jobs are deferred if they
would exceed the remaining budget; a pass stops when its budget is reached.
The 16 MiB byte-budget default is **PROVISIONAL**.

Following the lead's queue design §12, unconfirmed finals have a partial delivery
index; a per-scope live-lease cap bounds examined candidates by page plus cap.
`CompletionPage.lease_cap_reached` reports delivery backpressure. Failed/Uncertain
diagnostics and admission notices use separate partial indexes, each selecting at
most one page before their ID-ordered merge. Owner membership is derived from
canonical job owners in an indexed table; erasure drains bounded chunks within
one atomic transaction. Memory keeps corresponding rebuildable lookup/order
indexes and an operation-local undo journal of touched rows and summaries.

Summary rebuilding processes one `maintenance_batch` per `RebuildSummary`
request. Its summary row stores `rebuilding` and `rebuild_after`; status hides
partial counts until rebuilding completes. Transitions update counts only for
rows already incorporated by the cursor. Callers continue rebuild requests until
`rebuilding` is false. Counts and all indexes remain rebuildable from job rows.
Completion selection reads stored encoded result lengths and delivery metadata
before loading any saved answers. Diagnostics, summary rebuild and expiry
maintenance use content-free projections; expiry deletes copies directly.
The encoded lengths are derived on every canonical write and are rebuildable.
The unreleased SQLite schema version is 12; older layouts are refused without
migration.
