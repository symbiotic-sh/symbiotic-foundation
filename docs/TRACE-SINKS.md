# Trace Sinks

Model and queue invocations produce data that is useful for many systems, but
the foundation must not choose a single storage target.

## Principle

```text
provider/queue layer emits
host runtime routes
storage systems consume
```

Memory, audit, usage, and evolution are consumers, not owners of the provider
runtime.

## Normalized Event

The central event is `ModelInvocationTrace`:

- `trace_id`
- optional `queue_item_id`
- `model` identity
- `role_binding`, such as `memory.distill` or `agent.plan`
- `source`, such as `recall`, `intake`, `benchmark`, or `cli`
- `sensitivity`
- request and response hashes
- cache status
- token/media/cost usage
- timing
- outcome and error class
- audit references
- free-form metadata

## Required Sinks

| sink | responsibility |
| --- | --- |
| `UsageMeterSink` | cost, budgets, cache-hit accounting |
| `AuditSink` | forensic prompt/response references according to audit level |
| `AgentMonitorSink` | agent fitness, process-engineer queries |
| `ArchiveTraceSink` | raw capture source for memory/evolution |
| `BenchmarkSink` | experiment runs and regression analysis |
| `ExternalTelemetrySink` | OpenTelemetry or warehouse export |

## Memory Boundary

Memory should expose a trace capture input, but should not subscribe directly to
model providers. The runtime decides which traces deserve memory capture.

This prevents:

- duplicate usage accounting;
- hidden provider side effects;
- memory-owned credential handling;
- benchmark harnesses accidentally changing production scheduling.

## Learning Uses

Traces support:

- repeated prompt failure detection;
- model parse-failure rates;
- cache-hit effectiveness;
- high-cost low-value calls;
- provider latency/retry tuning;
- role-to-model routing improvements;
- Process Engineer recommendations;
- future training/export pipelines.
