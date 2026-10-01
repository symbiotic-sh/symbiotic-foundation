# Runtime correctness review fixes — 2026-10-02

The requested credential-result and HTTP-client mechanisms are implemented and
locally verified on `25-runtime-correctness`. Findings were checked against the
starting head, `bc55c6a`, before repair. This is a local implementation handoff,
not an independent review or a claim that all Foundation boundary gaps are closed.

Inputs: `fdna-r2-review/generalist-a.md` and
`fdna-slow-3d18394/generalist-b.md`, from the supplied review directories.
The lead owns all external publication and review actions. No external writes
were performed.

## Delivered mechanisms

`symbiotic-model::secrets::credential_boundary` checks complete adapter results,
after typed decoding and validation. Successful results are inspected for
credential echoes in raw JSON and final typed fields, including numeric
re-spellings, escaped strings, percent encoding and standard/URL-safe Base64.
Raw provider JSON is then discarded. Errors retain their typed class with static
messages. Chat, Gemini single/batch embedding and Jev use this function directly.
Chat-backed classification forwards to the same credential owner after its own
parsing and probability normalization.

Queued execution and cache loads invoke that owner's opaque credential guard
before result bookkeeping. Wrappers forward the guard without exposing the secret or allowing a policy override.
An injected adapter declaring credentials but lacking a boundary is refused.
Cache decoding errors also cross the boundary before returning.

Every production adapter client comes from one private builder with
`redirect(Policy::none())`, `no_proxy()` and `retry(never())`. Public
`with_client` injection is removed for all three HTTP adapters. Registry and
credential-process construction use `with_timeout`, which constructs an owned
client with the same policy. Gemini fixture endpoint substitution is private and
compiled only for unit tests. Compile-fail regressions prohibit public client
injection for chat, Gemini and Jev.

The execution order is:

1. Resolve and retain the credential inside Foundation; construct the owned client.
2. Bound and dispatch the request; refuse redirects and strictly decode success JSON.
3. Decode typed output and validate answers; pass the complete result through the
   credential boundary, inspecting success values and sanitizing errors.
4. Require the owner guard on fresh and cached results before receipts, traces,
   queue result writes or response-cache writes.

## Findings checked against the starting head

| Finding | Starting-head disposition and final result |
| --- | --- |
| R2 blocking 1: normalized Jev validation errors and typed decoding errors | Confirmed. A regression reproduced `1.234e8` becoming `123400000` in an exported validation error. The shared final-result boundary now covers both error paths. |
| Other instance: chat-backed classification | Confirmed by a separate failing regression. Its error normalization and successful probability normalization now pass through the same boundary. |
| R2 blocking 2: injected clients can follow redirects | Confirmed by the unrestricted public API. Injection is removed, and compile-fail tests cover every adapter. Runtime tests cover same-origin 307 and cross-host 302/307/308; target listeners receive no connection. |
| Slow blocking 1: configured client follows redirects and uses ambient proxies | Partially fixed already: the default builder refused redirects on `bc55c6a`. Ambient proxies and client injection remained. The sole builder now disables redirects, proxies and HTTP retries for every construction path. |
| Slow blocking 2: configured 401/200 credential echoes and raw result retention | Ordinary 401 and decoded string echoes were already checked. Later decoding/validation errors remained unchecked, and successful raw JSON was retained. All stages now share the final boundary; regressions inspect returned errors, receipts, traces, SQLite files and cache files. |
| Slow blocking 3: cache lacks request-hash binding | Already fixed. `load_cached` checks both result scope and request hash before reuse. Runtime cache regressions pass. Credential checks now also cover cache values and decoding failures before cache-hit bookkeeping. |
| Slow blocking 4: Jev accepts invalid UTF-8 success bodies | The reported acceptance no longer held: `provider_response_json` already used strict `serde_json::from_slice`. The remaining lossy trace-body conversion is replaced with `String::from_utf8`; a 0xFF success-body regression returns `ModelError::Provider`. |
| Slow blocking 5: tenant/account pooling documentation | Already fixed. The page describes isolated `(tenant, account)` state and explicit sharing keys, matching runtime grouping. |
| R2 prior check-back: stopped cooldown failures, nested unknown identity fields, chat settings, local hash-embedding endpoint | Already fixed. Queue parity/conformance, binding/settings and local-embedding regressions remain green. Both nested identity structs deny unknown fields. |
| R2 documentation: safe-wrapper attribution and 21-check count | Confirmed stale. `model-egress.md` names the shared boundary and final-result checks; `ai-runtime.md` names 22 conformance checks. Both backends run all 22. |

## Late follow-ups and observations

| Finding | Disposition |
| --- | --- |
| Production request-debug refusal absent from debug-only CI | Confirmed. CI now has a targeted release-profile invocation of the existing refusal test. That invocation passed locally. |
| `ResponseCache` docs require reading legacy layouts | Confirmed. The docs require the current response format and complete identity. |
| Classifier pacing uses `unwrap_or_default` after serialization | The fallback remained; the concrete question type has no demonstrated failing serializer. Budget estimation now returns `Result` and propagates an encoding error before queueing or dispatch. |
| Empty reasoning effort silently discarded | Already fixed. The setter preserves the value and shared validation refuses empty/whitespace effort. Raw and registry binding parity tests pass. |
| Purge silently ignores malformed binding metadata | Confirmed. Present malformed binding metadata now returns `ModelError::Cache`. The equivalent silent model-metadata parsing is fixed too; malformed entries are retained with a visible error. |
| SQLite migrates a queue missing `last_error_class`; terminal errors infer class from text | Confirmed. New schemas include the column; older schemas are refused before schema writes. Missing terminal classes return a static queue error. Regressions prove no column or auxiliary-table migration and no text-based inference. |
| Descriptor `secret_ref: "runtime"` | Still a non-secret placeholder, not the result/cache identity. Identity includes the binding, effective configuration and one-way credential fingerprint. This observation is not a credential-leak defect. |
| Credential-process Gemini operator is `"gemini"` | Still the operator defined by its route schema, which has no operator field. The generated registry uses that same identity. This observation does not show a correctness failure. |
| Earlier reviewer did not run targeted tests | Historical review limitation. This handoff includes observed local test results. |

The charge-certainty retry and crash-recovery gaps documented in
[the boundary contract](../architecture/boundary.md#spend-ledger-and-budgets)
remain existing implementation work under work item 25. Disabling hidden HTTP
retries and refusing stopped items do not close those broader ledger/admission
gaps. This change does not claim otherwise.

## Verification

All commands use toolchain `1.93.0`, the locked dependency set, and the debug
profile except the explicit production-refusal test. Final format and both
Clippy gates passed with warnings denied:

```sh
cargo +1.93.0 fmt --all -- --check
cargo +1.93.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.93.0 clippy -p symbiotic-model --no-default-features --all-targets --locked -- -D warnings
```

The following test targets passed. Each row expands to
`cargo +1.93.0 test --locked -p <package> <arguments>`; counts are per invocation
and overlap where filters select the same tests.

| Package | Arguments | Passed |
| --- | --- | ---: |
| symbiotic-ai-runtime | `--test configured_transport` | 10 |
| symbiotic-ai-runtime | `--test runtime injected_credential_results_without_a_boundary_are_refused_before_bookkeeping` | 1 |
| symbiotic-ai-runtime | `--test runtime cache` / `--test runtime binding` | 6 / 6 |
| symbiotic-ai-runtime | `--test runtime purging_a_source_removes_only_its_responses` | 1 |
| symbiotic-model | `--lib credential_transport_tests` / `--lib secrets::tests` | 3 / 5 |
| symbiotic-model | `--lib classify::tests` / `--lib gemini_` | 31 / 9 |
| symbiotic-model | `--lib every_error_class_survives_a_dead_item_and_exhaustion` | 1 |
| symbiotic-model | `--test openai_transport` / `--test safety` / `--test queue_parity` | 13 / 4 / 57 |
| symbiotic-model | `--doc` | 7 |
| symbiotic-model | `--no-default-features --lib credential_transport_tests` / `--no-default-features --lib secrets::tests` | 3 / 5 |
| symbiotic-model | `--no-default-features --lib classify::tests` / `--no-default-features --test openai_transport` | 27 / 13 |
| symbiotic-queue-sqlite | `--lib` / `--lib previous_queue_schema_is_refused_without_migration` | 17 / 1 |
| symbiotic-queue-sqlite | `--test conformance` | 22 |
| symbiotic-queue | `--features conformance --test conformance` | 22 |
| symbiotic-credential-process | `--test egress credential` / `--test egress redirect` / `--test egress ambient_proxies` | 4 / 1 / 1 |
| symbiotic-credential-process | `--test egress executable_preserves_numeric_provider_cost_after_restart -- --exact` | 1 |

The production-profile check also passed:

```sh
cargo +1.93.0 test --release --locked -p symbiotic-ai-runtime --test runtime production_request_debug_dir_is_refused_at_bind_time -- --exact
```

Gate stdout and command records are retained locally under
`.tmp/runtime-correctness/`; final incremental checks are also recorded in the
session transcript. No workspace-wide test matrix or external CI run is
claimed. The requested targeted gates, regressions and conformance checks passed.

## Lead handoff and proposed external update

Completed: A–D, the additional matching composition/cache paths, and the concrete
late findings above. Pending: the lead's review/publication actions. No local
execution blocker remains for this patch. Decisions: one result policy and one
owned client factory replace per-path checks and unrestricted client injection;
older development queue schemas are refused rather than migrated.

Proposed update for the lead to post: “Consolidated credential protection at the
complete adapter-result boundary and made HTTP clients Foundation-owned. Added
regressions for 401/200 echoes, numeric normalization, decoding/validation errors,
chat-backed classification, injected providers, cache reuse, redirects, proxies
and invalid UTF-8. Rust 1.93.0 format, workspace/no-default-features Clippy and
targeted tests passed; both queue backends passed 22 conformance checks. Older
findings were reconciled against the current head as recorded in the local
report. The separately documented charge-certainty/recovery work remains.”
