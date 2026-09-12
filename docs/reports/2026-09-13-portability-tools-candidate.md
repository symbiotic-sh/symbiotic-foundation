# Shared external format candidate — 2026-09-13

## Objective

Foundation issue2 owns the external shared tooling requested alongside Memory
issue49 and consumer portability work. The new independent symbiotic-portability
crate implements the data-portability/1 structural boundary from Memory PR83
`ee7a3c1`; it is not a business-store migration, mutation executor or backup.

## Completed and evidence

Rust1.93.0 release tests passed all 9 synthetic contract cases, and crate/all-target
Clippy passed with warnings denied. Formatting and git diff whitespace checks
passed. Tests cover typed JSON/numeric precision preservation, unknown/duplicate
fields and required null fields, qualified identity/scope, source correction
lineage, snapshot tokens, explicit change/revision plans, exact non-UTF8 bytes,
missing/mismatched/oversize/path/symlink artifacts, quoted Unicode multiline CSV,
formula presentation losses and Markdown rendering. No providers or live data.

## Pending

Review the work-branch PR and consumer-owned exact pins/mappings. SmartOffice
received the concrete worktree/API for its execution service. Rabbithole retains
its existing strict application JSON edit profile and presentation-only Markdown/
CSV. Existing DOCX/XLSX/PDF product parsers retain mapping/extraction responsibility
and must preserve original bytes and report unsupported features; this crate does
not claim it supplies those parsers or reversible document conversion.

## Blockers

No local implementation blocker. Main merge requires project/operator authority;
publication is a reviewable release candidate, not a merge or deployment.

## Decisions and rejected alternatives

Foundation is the existing shared library home. Core vocabulary, Memory's native
store and consumer business policy stay untouched. Strict envelope structural
validation is separate from authenticated destination binding and host record
authorization. Source bytes and application typed values are separate fidelity
claims. Rejected: mandatory Markdown/Node/Knap, universal document conversion,
Memory codecs, generic plugin registries and speculative database transactions.
