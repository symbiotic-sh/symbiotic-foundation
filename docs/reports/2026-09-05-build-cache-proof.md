# Foundation build cache and source artifact proof

PR: https://github.com/symbiotic-sh/symbiotic-foundation/pull/1
Branch: `task/001-build-cache/foundation` (unmerged).
Executable candidate: `2132e85d5a139f8615b333d118716880154b308f`.
CI tested its PR merge revision `ee45a29616273aaf2f0a52278e9a9180ab604b5a`.
The final evidence-only commit changes documentation/task records, not executable
code or workflow configuration, and skips CI to preserve the bounded run envelope.

## Observed reuse

Run: https://github.com/symbiotic-sh/symbiotic-foundation/actions/runs/33947992655

| Observation | Cold attempt 1 | Warm attempt 2 |
| --- | ---: | ---: |
| Exact cache hit | false | true |
| Cargo compiled units | 152 | 8 |
| Cargo Fresh units | 0 | 144 |
| Measured release build seconds | 78 | 11 |
| Whole job seconds | 116 | 42 |
| Workspace tests passing | 40 | 40 |

Both runs passed formatting, clippy with warnings denied, all 40 tests and
doc-tests. Counts come from Cargo JSON `compiler-artifact.fresh`, not inferred
from cache configuration. The full compilation-unit multisets (package, target,
profile, features) match between runs. All registry dependency units are Fresh
in the warm run. The eight compiled units are each of the four workspace crates'
library and test targets; rust-cache deliberately excludes these from saved
outputs. Thus 144 compilation units avoided compilation. A single cold/warm pair
is descriptive evidence, not a statistical speedup claim or cross-consumer proof.

Compatibility was identical: Rust 1.93.0, target x86_64-unknown-linux-gnu, release,
all features, committed lockfile/manifests/configuration and native environment
SHA-256 `d0391a6019ffe6bad7eb4b5a3b5ce5ae666a7d3eb5c7092be06d81affdb94623`.
Cache ID `7354005223`, scope `refs/pull/1/merge`, size 168631068 bytes.
Its key is:

```
foundation-v1-release-all-features-x86_64-unknown-linux-gnu-d0391a6019ffe6bad7eb4b5a3b5ce5ae666a7d3eb5c7092be06d81affdb94623-e9561b1727385a1f227c57427d14be0c70ea5443ad99c1fabecb8565cdef23a7-verify-Linux-x64-2b40554e-182814c8
```

## Published artifacts and verified consumer contract

[Warm source artifact](https://github.com/symbiotic-sh/symbiotic-foundation/actions/runs/33947992655/artifacts/9963966062)
contains the source tarball, `SHA256SUMS` and `manifest.json`.
Tarball: `foundation-source-ee45a29616273aaf2f0a52278e9a9180ab604b5a.tar.gz`.
Tarball SHA-256:
`59226cb9eeef1a9b0e7c0c9d6758b13ff7ff1f52304c22cfdede365e1fda7fff`.
GitHub outer source ZIP digest:
`9c24b66d8a09066c9a4dae5e373e12b78926eccc8677e49f185c5dd7aeb8a7ea`.

[Warm build proof](https://github.com/symbiotic-sh/symbiotic-foundation/actions/runs/33947992655/artifacts/9963966279)
contains Cargo JSON, summary and compiler/native identities. GitHub ZIP digest:
`9224aac636c073ae69b3a12bda1dfa4f944fbb320c120c261d8299b1106ce1bf`.

Downloaded source checksum verification passed. Cold and warm tarballs compare
byte-for-byte equal. Extracted workspace `cargo metadata --offline --locked
--no-deps` resolves all four crates and their relative paths. This validates the
packaged source layout; it does not claim an offline vendored dependency set.
Sources are retained for 90 days, build proof for 30 days. Local downloaded
cold/warm artifacts, complete logs and manifests remain under the isolated
worktree's `.debug-session/` (not tracked due to size/derived status).

Consumers retain full Git `rev` pins or verify and extract the entire source
workspace. Cargo compiles that source inside the consumer's own compatible
compiler/target/profile/features/dependency/native ABI boundary. Memory's existing
`814060cd3c31b976234c171608196293c1fed4eb` pin remains valid. No consumer repository,
crate API/version, crates.io release or universal Rust rlib ABI was introduced.
The producer cache is scoped to this repository/PR, not exported as a binary
library for other repositories. See ../architecture/build-artifacts.md.

## Gate repairs and bounded recovery

The repository had no pre-existing CI. The first cold run `33947031417` built
successfully but exposed existing nested-if clippy lints. Local preflight also
found two private helper signatures with too many arguments. Equivalent let chains
and private input structs fix these without lint suppressions or public API changes.

The corrected cold `33947361391` passed build/clippy but exposed the existing
retry fixture timeout. Independent tests shared a model identity and therefore
process-wide cooldown state despite using separate in-memory queues. Existing
binary `logical_retry --test-threads=1 --nocapture` reproduced the exact timeout:
2 pass, 1 fail, 9.22s. Parallel and two-thread focused runs passed. Distinct
identities for independent fixtures fixed the exact serial reproduction (3 pass,
8.42s), retaining duplicate waiters' same identity, every assertion and the 5s
waiter timeout. Full local 40-test suite, clippy and fmt then passed.

Parent authorized each diagnosed recovery before launch. Actual hosted use was
two failed diagnostic cold runs followed by one successful cold and one warm;
each job was bounded to 30 minutes. No failure was ignored; unsuccessful gates
withheld source publication and cache saving. Local builds used an exclusive
coordinated slot and two Cargo jobs. No purchases, paid model calls, runner
provisioning, additional benchmarks or main merges occurred.

No implementation blocker remains. PR review/merge is pending; cross-repository
consumer cache changes belong to the parent-coordinated lanes.
