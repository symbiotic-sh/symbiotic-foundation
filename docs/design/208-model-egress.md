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

The round-3 Foundation attachment finding is addressed by the v2 recovery contract in
that architecture document: idempotent permit issuance by durable attempt identity and
signed-record digest, authenticated status/result retrieval, and a signed absolute
recovery deadline. This operator-authorized protocol replaces v1 without aliases;
Memory pinning and client adoption remain with the lead.
