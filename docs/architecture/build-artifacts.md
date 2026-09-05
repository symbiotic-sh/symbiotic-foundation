# Build reuse and source artifacts

Foundation is a Cargo source dependency. Consumers pin the full Git revision in
Cargo.toml and commit their own lockfile. Memory currently pins
`814060cd3c31b976234c171608196293c1fed4eb`; changing producer CI does not require
changing that dependency or the crate version.

## Compatibility boundary

CI pins Rust 1.93.0 and builds release, all targets and all features, on
x86_64-unknown-linux-gnu. The compiled dependency cache is scoped by Rust's
compiler identity, runner OS/architecture, explicit target/profile/features,
Cargo manifests and lockfile, Cargo configuration, workflow/proof scripts,
compiler/linker flags, and a digest of the hosted image version and installed
native packages/compiler/linker/libc. Native SQLite and ring builds therefore
cannot cross a changed native environment. This strict policy trades cache
availability after image updates for native ABI safety.

The pinned rust-cache action restores Cargo registry/git sources and compiled
**dependency** artifacts. It intentionally removes workspace build outputs when
saving. Cargo still validates each fingerprint; a restored cache is not permission
to skip any correctness gate. Formatter, clippy with warnings denied, and all
workspace tests run on every job. Pull request cache scope cannot overwrite the
default branch's trusted cache. There are no secrets or write-scoped tokens.

A consumer must cache its own Cargo dependency graph under equivalent boundaries.
Foundation's target directory is not a reusable binary dependency for Memory or
Runtime: feature unification, profile, compiler, target, dependency versions and
native ABI can differ. Do not copy `.rlib` files or claim a stable Rust binary ABI.

## Published source contract

Each successful CI job uploads `foundation-source-<revision>-<attempt>` containing:

- `foundation-source-<revision>.tar.gz`: committed Cargo workspace sources,
  manifests, lockfile, pinned toolchain, documentation and build scripts;
- `SHA256SUMS`: SHA-256 of the gzip archive;
- `manifest.json`: exact revision, digest, filename and consumer contract.

The archive uses `git archive` and gzip without a timestamp; the same revision
produces identical bytes. Verify the digest against the artifact from the trusted
successful run, run `shasum -a 256 -c SHA256SUMS`, and extract. Use the full workspace
layout if consuming crates by path; internal path dependencies remain relative.
Normal Git consumers keep their full `rev` pins. The archive is an alternate
source distribution, not a crates.io release or a vendored offline dependency set.
Registry downloads may still be required. No published package names or versions
are changed. CI source artifacts expire after 90 days; durable consumers use the
Git revision and can regenerate the archive with `scripts/source-artifact.sh`.
GitHub's upload artifact digest describes its outer ZIP, separately from SHA256SUMS.

## Evidence contract and bounded validation

`foundation-build-proof-<revision>-<attempt>` retains Cargo JSON messages, exact
compiler identity, native environment and `build-summary.json` for 30 days.
The summary records actual `compiler-artifact.fresh` decisions, compiled counts,
elapsed build seconds, revision, target, profile/features, cache hit and run IDs.
Counts are compilation units, not unique package names. Source checkout/runner
setup and test time are outside the measured build step.

Validate with one cold run and one rerun of the same workflow revision on the
same runner image. Expected cold: cache miss and compiled dependency artifacts.
Expected warm: cache hit and fresh unchanged dependencies; workspace crates may
compile again by design. Compare the per-package artifacts and native digests,
not just elapsed times. A two-run timing difference is descriptive, not a
statistically established speedup. If either fails, diagnose before any retry.
The new single job has a 30-minute timeout and no build matrix. No local heavy
build runs concurrently with another stack lane.
