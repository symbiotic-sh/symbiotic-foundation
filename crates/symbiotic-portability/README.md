# External record portability

`symbiotic-portability` implements structural validation of `data-portability/1`
from Memory contract PR83 at `ee7a3c1`, independently of the Memory engine. It has
no Memory, database, provider, Knap or Node dependency. It does not apply changes.

```rust
use symbiotic_portability::{decode_bundle, validate_destination, Limits, Scope, Sensitivity};
fn inspect(bytes: &[u8]) -> Result<(), symbiotic_portability::Error> {
    let bundle = decode_bundle(bytes, Limits::default())?;
    let destination = Scope {
        space: "workspace".into(), audience: vec!["user:operator".into()],
        sensitivity: Sensitivity::Private,
    };
    validate_destination(&bundle, "owning-application", &destination)?;
    // Authorize each record/binding using current host policy, validate payloads
    // using the named application schema, then verify included artifact bytes.
    Ok(())
}
```

`decode_change_plan` and `validate_plan_destination` validate explicit plan intent.
The application owns field allowlists, required fields, current revision checks,
operation retries, auditing and the guarded writer. A successful decode proves
none of those execution guarantees. Nullable wire fields are required, with null
meaning unavailable; missing and null payload fields remain distinct. Duplicate
JSON keys and unknown envelope fields fail. Unknown fields inside product payloads
are preserved, including arbitrary-precision JSON numbers through serde_json's
`arbitrary_precision` feature. Serialization preserves typed values and numeric
lexemes, not whitespace/key ordering of the original document: retain original
bytes and their digest separately.

`verify_artifact_bytes` hashes a bounded reader; `verify_bundle_file` also checks
relative path containment and rejects symlinks. File verification requires a
trusted, quiescent directory (not concurrently rewritten or replaced by another
process). It is not a ZIP extraction sandbox. External verified declarations
describe prior verification only; fresh resolution must still check bytes and
host authorization. This library never fetches external references.

`Table { columns, rows }` carries strings without inferring record identity/types.
`parse_csv` is an explicit mapped-import input. `render_csv` and `render_markdown`
return `Presentation { bytes, losses }`; neither is a controlled editable schema.
CSV formula-like cells receive a reported apostrophe prefix for spreadsheet use.
Markdown cells are escaped; no Markdown parser or reversible conversion is claimed.

For DOCX/XLSX/PDF, preserve original bytes first. Existing external parsers (for
example SmartOffice's calamine worksheet mapping and PDF/document extraction)
remain format-specific: map selected sheets/paragraphs/text into the owning schema
and declare formulas, layout, annotations, macros or other unsupported features
as losses. No generic bundle decoder turns extracted text into lossless document
records. Those parsers and their product mappings are separately qualified in the
consumer; this crate does not advertise document extraction or editable document
round trips.

Scope here is an explicit interchange restriction: empty audience means no
recipients. Memory's empty-audience space-default semantics require an explicit
host mapping; never copy empty arrays and assume equivalent access. Limits apply
before JSON/CSV parsing and during byte verification. Product limits may be lower.

Validation: `cargo test --release --locked -p symbiotic-portability` and
`cargo clippy --release --locked -p symbiotic-portability --all-targets -- -D warnings`.
