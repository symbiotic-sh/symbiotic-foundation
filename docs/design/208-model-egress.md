---
status: implemented
---
# WP14 credential dispatch

Implemented locally for symbiotic-sh/symbiotic-memory#208 from the operator-authorized
Memory design 137 revision 8 §§7.2 and 12. The current schema, integration order,
security boundary, deployment and evidence are in
[model egress architecture](../architecture/model-egress.md).

The [Foundation boundary contract](../architecture/boundary.md#ownership) supersedes
the original design's Memory-owned canonical accounting. Revocation follows the
[caller-and-provider grant-revision ordering](../architecture/boundary.md#grant-revision-and-dispatch-ordering),
superseding the original §7.2 route-sequence example. The current implementation's
record-sequence revocation on route keys remains a gap documented in
[model egress](../architecture/model-egress.md#revocation-replay-and-unknown-charges).
No additional model scheduler or persistent response cache was added.

The [v2 recovery protocol](../architecture/model-egress.md#same-attempt-recovery-v2)
supports same-attempt attachment and status lookup after lost replies. It replaces
v1 without aliases. Memory client adoption is tracked by
[symbiotic-memory#208](https://github.com/symbiotic-sh/symbiotic-memory/issues/208).
