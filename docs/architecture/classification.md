# Classification seam

Products keep asking models narrow questions about a small piece of state:
"is this message a multi-step goal?", "which of these categories fits this
document, or none?", "how urgent is this ticket?". Asking a chat model and
parsing a word out of its reply is slow (reasoning models think before a
one-word answer) and brittle: the reply may not parse, or may name a label
that was never offered (`finance.incoming_invoice` for a fixed category list).
There was no provider-neutral way to ask typed questions and get probabilities
back, so each product would build its own.

`symbiotic-model` now owns that seam beside chat, embedding and rerank:
`ModelCapability::Classify`, the `ClassifierProvider` trait, request and
response types, a queue wrapper, and three providers. Thresholds and decisions
stay with the caller. The [boundary contract](boundary.md#ownership) governs
product classification meaning, explicit Memory-run registered tasks and provider
data authorization. This page describes the current classification API.

## Current API shape

The excerpt shows the task and response shape; it is not a complete struct
literal. Obsolete policy fields still in the Rust types are pending removal under
the [boundary contract](boundary.md#tenant-provider-bindings-and-data-access).

```rust
#[async_trait]
pub trait ClassifierProvider: ModelProvider {
    async fn classify(&self, request: ClassifyRequest) -> Result<ClassifyResponse, ModelError>;
}

pub struct ClassifyRequest {
    pub state: serde_json::Map<String, Value>, // the content classified
    pub questions: Vec<ClassifierQuestion>,    // answered independently, in order
    pub state_description: Option<String>,     // prompt opening for chat-backed providers
    pub role_binding: Option<String>,
    pub source: Option<String>,
    pub metadata: Value,
}

pub struct ClassifierQuestion { pub id: String, pub instructions: String, pub kind: QuestionKind }

pub enum QuestionKind {                         // System One primitives
    Noul { when_true: Option<String>, when_false: Option<String> },
    Choice { options: Vec<ChoiceOption> },      // ChoiceOption { id, criterion }, ordered
    Score { levels: Vec<String> },              // lowest first
}

pub struct ClassifyResponse {
    pub answers: Vec<ClassifierAnswer>,         // { question_id, value }, request order
    pub served_model: String,
    pub trace: ModelInvocationTrace,            // usage tokens, timing.provider_ms, receipts
    pub raw_provider_response: Option<Value>,
}

pub enum AnswerValue {
    Noul { probability: f64 },
    Choice { chosen: String, probabilities: Vec<OptionProbability>, confidence: Option<f64> },
    Score { value: f64, probabilities: Vec<f64>, confidence: Option<f64> },
}
```

`ClassifyRequest::validate` rejects an empty question list, empty or repeated
question ids, a Choice without options or with repeated option ids, and a
Score with fewer than two levels (`ModelError::InvalidRequest`).

Every provider returns answers that satisfy one contract, checked by a shared
validator before a response is returned: a Noul probability in `[0, 1]`; a
Choice with exactly the requested option ids in order, probabilities in
`[0, 1]` summing to 1, `chosen` among the most probable options, and
confidence (when present) in `[0, 1]`; a Score with one probability per
level summing to 1 and `value` equal to the probability-weighted level.

Decision helpers evaluate caller thresholds only: `noul_at_least(id, t)`
(inclusive) and `decide_choice(id, abstain_option, min_probability)`, which
selects the most probable option other than an abstain option such as `none`
when it reaches the minimum and is more probable than the abstain option.
Exact ties go to the answer's `chosen` option, so without an abstain option
`decide_choice` always agrees with `chosen`.

`QueuedClassifierProvider` (default `queue` feature) runs classification
through the same `run_queued` path as `QueuedChatProvider`,
`QueuedEmbeddingProvider` and `QueuedRerankProvider`: idempotent enqueue,
model cap, rate buckets, cooldowns, retry classification, exact response cache,
and one trace per call. Its cache
entries live under `{cache}/classify/{descriptor hash}/`, so classifiers with
different identities or expected served models never share an entry. The
other wrappers keep the historical `{cache}/{kind}/{request hash}` path, which
does not include the model: two chat models sharing that lower-level cache
directory can read each other's answers. Runtime-owned caches add descriptor
scoping, but complete tenant/configuration result identity remains cleanup work
required by [boundary.md](boundary.md#tenant-provider-bindings-and-data-access).

## Providers

| Provider | Identity | Class | Transport |
|---|---|---|---|
| `JevClassifierProvider` | `classify:<operator>:<model>` | Cloud | `POST {base}/systemone`, bearer key |
| `ChatClassifierProvider` | `classify:<chat operator>:<chat model>` | the chat provider's | one JSON-mode `ChatRequest` |
| `StaticClassifierProvider` | `classify:static:static-classifier-v1` | Local | scripted answers (tests) |

**`JevClassifierProvider`** speaks TypeSafe's System One API:
`{"model", "state", "questions"}` in, typed answers out.
`JevClassifierProvider::typesafe(key)` targets `https://api.typesafe.ai/v1`
with the pinned `jev-1.13.0`; `new(operator, model, base_url, key)` targets any
host of the same API, and `from_resolver` obtains the key through the host's
`CredentialResolver` (a bearer token or API key). These current constructors
are transport APIs; credential ownership and consumer adoption follow
[boundary.md](boundary.md#storage-and-credentials). Before sending it refuses
Jev 1.13's documented limits: 255 Choice options, 10 Score levels, 32,000
tokens for the state plus the longest question, 64,000 for the request.
Tokens are estimated as one per UTF-8 byte of JSON plus a 512-token template
reserve, which never under-counts and refuses states above roughly 30 KB. The
response must name the expected served model (by default the requested one;
`with_served_model` accepts a gateway's snapshot name), because thresholds are
tuned on one version. HTTP statuses use the crate's classification: 408/504
time out, 429 is rate limited, 5xx (including TypeSafe's 529 Overloaded) is
unavailable. The current queue policy treats all three as retryable without proving
zero charge; this is the [runtime retry gap](ai-runtime.md#policy-knobs).
Opt-in `retry_provider_errors` also retries
`ModelError::Provider` without checking charge certainty under the same gap.
Retry admission follows the [spend contract](boundary.md#spend-ledger-and-budgets).
Answers that do not match the questions
are `ModelError::Provider`: a missing or extra answer, a wrong kind, a choice
outside the options or not among the most probable, a distribution that sums
more than 0.02 from 1 (it is then rescaled), confidence outside `[0, 1]`, or a
score outside the level range or more than half a level from its
probability-weighted level (`value` is that weighted level). Jev rounds
probabilities to two decimals, so a displayed tie can hide its real ranking;
`chosen` keeps Jev's pick among the tied options. The response is read field
by field from the parsed JSON rather than through a tagged serde enum, so
numbers such as `0.1200` parse under serde_json's `arbitrary_precision`,
which `symbiotic-portability` enables in workspace builds.

**`ChatClassifierProvider`** wraps any `Arc<dyn ChatProvider>`. The system
prompt opens with "You answer *n* independent questions about
*state_description*", renders each question (choice: options with criteria;
noul: what yes and no mean; score: numbered levels) and the exact reply shape,
e.g. `{"route": {"quick": <p>, "goal": <p>}, "goal": <p>}`; the user turn is
the state as JSON; the request asks for `json_object` at temperature 0. The
reply must be exactly that object: every question answered, no other keys,
numbers in `[0, 1]`, Choice and Score keys exactly the requested ids. A label
outside the offered ids therefore cannot be returned; it fails the call and
the caller decides the fallback. Choice and Score probabilities are normalised
to sum to 1, and `chosen` is the most probable id. Provider class is descriptive;
authorization follows [boundary.md](boundary.md#tenant-provider-bindings-and-data-access).
Consumers obtain classifiers through `Runtime::classifier`; queue wrappers and
chat-provider composition stay inside Foundation.

## Defaults and pricing

`default_model_queue_config("classify:typesafe:jev-1.13.0")`: 32 in flight,
1,200 requests/min and 15M input units/min (TypeSafe's account limits of
1,200 requests/min and 250,000 tokens/s, checked 2026-09-28 and adjusted
dynamically by TypeSafe), 30 s timeout, 3 attempts with 2 s jitter.

`default_model_capabilities` catalogues the same identity with a 64k context,
structured output, `CostClass::Budget`, and the new advisory
`ModelCapabilities::pricing`: `ModelPricing { input_micro_usd_per_million_tokens:
42_000, output_micro_usd_per_million_tokens: 0 }` ($0.042 per million input
tokens, output free). `ModelPricing::cost_micro_usd(input, output)` estimates a
call; a provider-reported cost, when present, stays in trace metadata as
`reported_cost_usd`. Accounting and monetary guarantees follow the
[spend contract](boundary.md#spend-ledger-and-budgets).

## Gateways

OpenRouter serves the same API at `https://openrouter.ai/api/v1/systemone`
(checked 2026-09-28 against its API reference and model endpoints): model
`typesafe/jev-1.13` with an OpenRouter key, answering with a dated snapshot as
the served model (`typesafe/jev-1.13-20260917` in its example). That route is
configuration only:

```rust
JevClassifierProvider::new("openrouter", "typesafe/jev-1.13", "https://openrouter.ai/api/v1", key)
    .with_served_model("typesafe/jev-1.13-20260917")
```

The catalogue lists `classify:openrouter:typesafe/jev-1.13` at the same token
price, and its queue policy falls back to the generic OpenRouter entry.
OpenRouter bills through purchased credits, which carry its purchase fee, so
the direct TypeSafe key is cheaper when a deployment has it. Whether the
OpenRouter snapshot answers exactly like `jev-1.13.0` has not been measured.

## Verification

Tests use a loopback HTTP server and scripted chat providers; they need no
provider account or paid call. `symbiotic-model`'s tests enable serde_json's
`arbitrary_precision` as the workspace does, and literal response bodies keep
provider number spellings. They cover the System One body and question order,
bearer auth, answer parsing for all three kinds, non-canonical numbers,
inconsistent distributions, choices, scores and confidence, displayed ties,
served-model checks, limit refusals before sending, status classification, the
chat prompt and strict reply validation (including an out-of-vocabulary
option), the queue wrapper's cache scoping, traces and retry, and the
catalogue entries.
