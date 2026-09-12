# Portability review corrections — 2026-09-13

Foundation PR3 review identified three concrete validation improvements: audience
subset lookup now uses a set, collection counts are checked without allocating
typed entries before deserialization, and external resource/version IDs reject URL
userinfo/query/access forms through an explicit opaque-ID grammar. The Markdown
presentation return was expanded for readability; Rust1.93 rustfmt already accepted
the original expression, so the formatting comment did not reproduce as a failed
gate. No API signature changed.

The revised candidate passes all 10 synthetic release tests and crate/all-target
Clippy with warnings denied on Rust1.93.0, plus formatting and whitespace checks.
The added regression checks the count limit before malformed typed entries,
credential-bearing external IDs, and authenticated destination mismatch.
This supersedes the earlier 9-test count. Consumer pins must select the revised
work-branch head. Main remains unmerged; no provider or live data was used.
