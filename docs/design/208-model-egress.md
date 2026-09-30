---
status: implemented
---
# WP14 credential dispatch

Implemented locally for symbiotic-sh/symbiotic-memory#208 from the operator-authorized
Memory design 137 revision 8 §§7.2 and 12. The current schema, integration order,
security boundary, deployment and evidence are in
[model egress architecture](../architecture/model-egress.md).

Foundation owns the credential process and single-use dispatch; Memory owns K admission,
durability and canonical accounting. The authoritative §7.2 record-order example governs
revocation: attempt@10 can receive its permit after removal@11 once durable; attempt@12
is refused. No additional model scheduler or persistent response cache was added.

Publication and Memory adoption remain with the lead under memory#208; this work makes
no external writes and does not claim a merged or deployed release.
