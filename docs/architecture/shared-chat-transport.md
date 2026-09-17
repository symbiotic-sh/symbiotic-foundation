# Shared OpenAI-compatible chat transport

RabbitHole needs thinking/effort settings and complete usage metadata while using
Memory's supported provider boundary. The existing Foundation adapter lacks those
settings; Memory currently has a second HTTP encoder and decoder. That prevents
one shared implementation from retaining response metadata consistently.

Foundation owns OpenAI-compatible wire encoding, HTTP execution and response
decoding. Builder-level thinking and reasoning effort preserve `ChatRequest`
source compatibility. Memory injects its existing configured reqwest client so
pooling, timeouts and transport policy do not silently change. Foundation's
reqwest dependency therefore aligns with Memory's 0.13 client type.

Normalized traces retain numeric usage, provider response ID, served model,
creation time, and provider-reported decimal USD cost when present. Requested
model identity stays separate. Missing cache counters are not a cache miss;
contradictory counters remain unknown. Hidden reasoning text never enters trace
metadata. Raw responses remain an explicit return value, not a trace sink.

Memory keeps its public chat trait and builders, plus its established reasoning
return field. Its usage record gains optional provider metadata with serde defaults.
Existing Rust usage literals can use `..Default::default()`. Memory's supported
metadata-only queue wrapper uses one attempt, no response cache or prompt debug
capture, and omits free-form provider error bodies. Host snapshot replay and
independent budget guards remain host-owned. The queue event file is best-effort
telemetry, not a billing or before-dispatch accounting barrier.

Verification uses synthetic loopback responses and workspace tests; it requires
no provider account, paid calls, production changes, or user applications.
