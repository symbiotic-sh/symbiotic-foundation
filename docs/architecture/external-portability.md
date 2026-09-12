# External record interchange

The independent `symbiotic-portability` crate owns the external wire boundary for
scoped typed records. It implements Memory's proposed data-portability/1 envelope
without importing Memory or creating another source database. Applications retain
schema, authorization, concurrency, audit and business-store authority.

The accepted implementation scope in foundation issue2 is bounded JSON decoding,
qualified identity and scope validation, explicit change plans, exact byte hash
verification, CSV mapping input and CSV/Markdown presentation output. See the
[crate API guide](../../crates/symbiotic-portability/README.md) for caller duties,
limits and format fidelity. Parsing cannot certify a host's snapshot declaration,
external retention, record revision, access policy or completed mutation.

Rejected alternatives: a Memory codec module would violate engine ownership;
putting schemas into symbiotic-core would expand its tiny vocabulary; mandatory
Markdown conversion loses record types and binary fidelity; a generic plugin
registry has no established requirement. The existing foundation workspace is the
shared library home, but this crate is independent from its runtime/provider
crates. Existing product DOCX/XLSX/PDF parsers remain external and report losses.

Changes to the wire contract require coordinated schema/version qualification;
product-specific profiles can publish explicit semantic mappings without changing
their wire shapes to the common envelope.
