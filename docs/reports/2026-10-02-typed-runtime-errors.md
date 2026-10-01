# Typed runtime errors — review round 3 resolution

Credential leakage through errors was still possible at adapter validation and
queue restoration after three review rounds. This change replaces error text
with a closed type contract on branch `25-runtime-correctness`.

## Delivered behavior

- `ModelError`, `QueueError` and `TraceError` carry only `DiagnosticCode` values
  or a typed unsupported capability. Every constructor was updated; provider,
  adapter, configuration and stored-state text cannot be error payloads.
- Queue failures, items, events and runtime receipt errors carry typed codes;
  queue failure classes are typed too. Side-effect warning/bookkeeping functions
  accept only a diagnostic code and log its static identifier.
- SQLite stores only canonical code/class identifiers. Queue schema version 2
  and current table layouts are required. Older layouts, wrong versions and
  unknown stored codes/classes are refused without migrations or text echoes.
  Stopped and exhausted items rebuild their class from typed state; exhaustion
  uses a static `attempt_budget_exhausted` diagnostic.
- Non-success HTTP bodies are discarded without decoding or retaining their
  text. Status determines auth, budget, timeout, rate-limit and unavailable
  classes. Strict UTF-8, body limits and JSON decoding apply to success bodies.
- The shared credential owner continues screening raw and normalized successful
  outputs and discarding raw provider JSON. Error sanitization and receipt
  redaction, plus tests solely exercising them, were deleted.

Regressions cover a key echoed in a 401 body, credential-adapter validation,
restored stopped and exhausted dead items, corrupted stored text, and `0xFF`
bodies for 401, 402 and 429. Compile-fail examples prove validation and queue
failures cannot accept strings. Existing successful-output echo regressions
remain, including numeric normalization and adapter composition.

## Verification

Rust 1.93.0, debug profile except the explicitly required production test:

```sh
cargo +1.93.0 fmt --all -- --check
cargo +1.93.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.93.0 clippy --locked -p symbiotic-model --no-default-features --all-targets -- -D warnings
```

All gates passed. Targeted tests used `cargo +1.93.0 test --locked` with these
arguments; local logs are `.tmp/gate-*.log` and `.tmp/final-clippy*.log`.

| Package | Arguments | Passing tests |
| --- | --- | ---: |
| symbiotic-model | `--lib` | 78 |
| symbiotic-model | `--test openai_transport` | 13 |
| symbiotic-model | `--test provider_transport_policy` | 3 |
| symbiotic-model | `--test queue_parity` | 56 initially; the corrected receipt assertion passed its exact rerun, covering all 57 cases |
| symbiotic-model | `--test queue_parity retry_base_delay_allows_sub_second_backoff_and_receipts_record_the_failure -- --exact` | 1 |
| symbiotic-model | `--test queue_parity a_failed_` (final typed logging) | 12 |
| symbiotic-model | `--no-default-features --lib` | 45 |
| symbiotic-model | `--doc` | 8 |
| symbiotic-ai-runtime | `--test configured_transport --test runtime` | 11 + 40 |
| symbiotic-queue-sqlite | `--lib --test conformance` | 19 + 22 |
| symbiotic-queue | `--features conformance --test conformance` | 22 |
| symbiotic-queue | `--doc` | 1 |
| symbiotic-trace | `--lib` | 5 |
| symbiotic-credential-process | `--lib provider::tests` | 1 |
| symbiotic-credential-process | `--test egress credential` | 4 |
| symbiotic-credential-process | `--test egress executable_preserves_numeric_provider_cost_after_restart -- --exact` | 1 |
| symbiotic-ai-runtime | `--release --test runtime production_request_debug_dir_is_refused_at_bind_time -- --exact` | 1 |

Initial test failures were assertions expecting removed free-form diagnostics;
the underlying refusal, class, retry, receipt and persistence checks remain.
The injected adapter test helper was corrected to copy the complete typed error,
so the restoration regression covers auth as well as transient failures.
No workspace-wide test matrix, CI result or independent reviewer approval is
claimed.

## Lead handoff

Completed: the four requested construction, persistence, success-screening and
HTTP-status requirements, their regressions, and the local gates. No local
execution blocker remains. Pending: the lead's review and external publication.
There were no pushes, PR changes, comments, reviews, labels, status changes or
other external-service writes.

Proposed update for the lead to post:

> Credential error leakage is prevented by construction: model, queue and trace
> errors accept only typed static codes. Persisted queue failures contain only
> codes/classes; schema version 2 refuses older layouts without migration.
> Successful outputs still cross the credential boundary, and invalid UTF-8
> error bodies retain HTTP status classes. Validation, 401 echo, stopped/dead
> replay and 0xFF 429 regressions pass, along with Rust 1.93.0 formatting,
> workspace/no-default-features Clippy and the targeted gates recorded here.
