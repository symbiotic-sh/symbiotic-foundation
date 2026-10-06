# Shared OpenAI-compatible chat transport

RabbitHole needs thinking/effort settings and complete usage metadata while using
Memory's supported provider boundary. The existing Foundation adapter lacks those
settings; Memory currently has a second HTTP encoder and decoder. That prevents
one shared implementation from retaining response metadata consistently.

The shared Foundation adapter encodes OpenAI-compatible requests, executes HTTP
and decodes responses. Builder-level thinking and reasoning effort preserve
`ChatRequest` source compatibility. Transport and execution policy follow the Foundation
[boundary contract](boundary.md#ownership); budgets follow its
[spend contract](boundary.md#spend-ledger-and-budgets).

Normalized traces retain numeric usage, provider response ID, served model,
creation time, and provider-reported decimal USD cost when present. Requested
model identity stays separate. Missing cache counters are not a cache miss;
contradictory counters remain unknown. Hidden reasoning text never enters trace
metadata. The shared adapter-result boundary discards raw provider JSON before
runtime bookkeeping, including for keyless calls.

Memory keeps its public chat trait and builders, plus its established reasoning
return field. Its usage record gains optional provider metadata with serde defaults.
Existing Rust usage literals can use `..Default::default()`. Memory's supported
metadata-only queue wrapper uses one attempt, no response cache or prompt debug
capture, and omits free-form provider error bodies. Host snapshot replay remains
an application concern. The queue event file is best-effort
telemetry, not a billing or before-dispatch accounting barrier.

Verification uses synthetic loopback responses and workspace tests; it requires
no provider account, paid calls, production changes, or user applications.
