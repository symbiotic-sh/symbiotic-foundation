# Spend ledger: slower-review finding dispositions

Fix scope: only blocking findings from `fdnledger-slow-b21031c/generalist-b.md`
that are distinct from `fdnledger-r2-review/generalist-a.md`, both reviewed at
`b21031c96c4d7aee1e090f182f2f8b5da4098b00`. This work stays on the local
`fdnledger-slowfix-b21031c` branch; the lead owns integration and external writes.

| Finding | Disposition | Confirmation and fix |
| --- | --- | --- |
| Slower Blocking 1: reserve errors permanently stop an unspent request | **Fixed** | A pre-commit storage failure leaves no receipt, but the queue stored Stopped and refused subsequent identical calls. Both backend regressions failed before the fix. A later call now reconsiders the stopped claim once the ledger is available, without subtracting from its provider-attempt allowance. |
| Slower Blocking 2: lease loss before transport consumes the last attempt | **Fixed** | Both backend regressions failed after actual lease expiry, and the heartbeat regressions failed at a one-attempt limit. The shared abort helper releases spend and persists a queue failure when it still owns the lease. Atomic ledger evidence preserves the unused attempt even when expired ownership prevents that queue write and reclaim marks the item Dead. |

No slower blocking finding overlaps a faster blocking finding; neither slower
blocking finding was dismissed as not holding. The slower non-blocking
invocation-lookup scan follow-up is the same defect as **faster Blocking 3**:
the latest-receipt query cannot use the partial active-invocation index. It is
left to the other fixer. Faster Blocking 1 and 2 also remain in that fixer's scope.
The reports' non-blocking retention and allowance questions remain outside this fix.

The repeated retry-accounting class is fixed through a shared mechanism rather
than another diagnostic-code subtraction. `QueuedCall::provider_attempts` counts
canonical receipts for the item's claims: absent receipts and confirmed
pre-dispatch releases cost zero; Unknown, Settled and ordinary Released receipts
still count. `SpendLedger::release_before_dispatch` commits the release, allowance
refund and `pre_dispatch_released` evidence in one transaction. A known-zero
provider rejection therefore still consumes an attempt, and ordinary settlement
or reconciliation cannot later be relabeled as a pre-dispatch abort.

The crate-wide pattern search covered pre-transport releases, queue failure exits,
and logical attempt sums. Both ownership checks, rate-grant charging failure and
attempt-context capture failure use the shared abort helper. Stopped-item
followers use the same reconsideration logic as later identical calls; dead-item
continuation uses the same receipt-based count. Accepted credential handoffs keep
their existing single-use ownership and accounting behavior.

Queue format is now **5**, adding `pre_dispatch_released` with a conservative
false default. Version 4 is refused under the existing current-format-only
contract; no migration is added. When integrating the other fix, retain both this
column and its complete invocation-lookup index. Architecture documentation and
schema-refusal coverage are updated with the format.

Verification used the debug profile, Rust **1.98.1**, `CARGO_BUILD_JOBS=4` and
`RUST_TEST_THREADS=4`; every test invocation passed `--test-threads=4`. CI owns
the complete matrix on Rust 1.93.0. No full suite was run locally.

Before implementation, the two targeted regression commands below produced
**0 passed / 6 failed** and **0 passed / 2 failed**, respectively, against the
unchanged production code. They exposed permanent SpendLedgerUnavailable stops
and AttemptBudgetExhausted after zero provider calls:

```sh
export CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4
cargo test --locked -p symbiotic-model --test queue_parity preserves_the_last_provider_attempt -- --test-threads=4
cargo test --locked -p symbiotic-model --test queue_parity lease_loss_during_reservation_refuses_dispatch -- --test-threads=4
```

The final candidate passes formatting and lint:

```sh
cargo fmt --all -- --check
cargo clippy --locked -p symbiotic-model -p symbiotic-ai-runtime -p symbiotic-queue-sqlite -p symbiotic-credential-process --all-targets -- -D warnings
```

| Final targeted check | Passed / failed |
| --- | --- |
| Model queue parity: new regressions, reconciliation, budget exhaustion and cooldown failures | 26 / 0 |
| Runtime spend ledger: settlement, concurrent budgets, restart evidence and atomic rollback | 6 / 0 |
| Runtime accepted-handoff ownership and spend API guards | 7 / 0 |
| Model logical retry and poisoned-rate guards | 4 / 0 |
| SQLite initialization, rollback and unsupported-format guards | 4 / 0 |
| Credential permit identity and concurrent account-budget guards | 2 / 0 |

Total: **49 passed / 0 failed** on the final candidate. The credential Cargo
invocation initially failed both fixtures at `TcpListener::bind("127.0.0.1:0")`
with the sandbox's PermissionDenied, before exercising product code. The same
compiled binary passed both selected tests after approval to bind its local
synthetic-provider socket outside the sandbox; it contacts no external service.

Exact test commands (with the resource environment above):

```sh
cargo test --locked -p symbiotic-model --test queue_parity -- --test-threads=4 reconciliation_ restored_account_allowance uncertain_charge_cooldown a_failed_cooldown known_zero_retries an_exhausted_budget preserves_the_last_provider_attempt lease_loss_during_reservation a_reclaimed_unknown_attempt
cargo test --locked -p symbiotic-ai-runtime --test spend -- --test-threads=4
cargo test --locked -p symbiotic-ai-runtime --lib --test runtime -- --test-threads=4 spend_ spend::tests::
cargo test --locked -p symbiotic-model --lib -- --test-threads=4 queued_chat_provider_reenqueues_dead_item_until_logical_retry_limit queued_chat_provider_stops_at_logical_retry_limit queued_chat_provider_waiter_shares_logical_retry_envelope poisoned_rate_state_refuses_checks_and_charging
cargo test --locked -p symbiotic-queue-sqlite --lib -- --test-threads=4 schema_ unversioned_existing
cargo test --locked -p symbiotic-credential-process --test egress -- --test-threads=4 spend_concurrent_dispatches_on_one_account_share_one_durable_budget wrong_input_or_attempt_cannot_spend_a_permit
target/debug/deps/egress-399a1b731c3c7d6b --test-threads=4 spend_concurrent_dispatches_on_one_account_share_one_durable_budget wrong_input_or_attempt_cannot_spend_a_permit
```

No pushes, PR/issue changes, comments, reviews, labels, status changes or other
external writes were performed. The lead's next step is to integrate this local
commit with the other fixer's changes, then run CI and the next review.
