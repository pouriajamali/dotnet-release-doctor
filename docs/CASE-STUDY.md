# Decisions with bounded evidence

| Decision | Evidence in tests/ReleaseDoctor.Tests/Program.cs | Limit |
| --- | --- | --- |
| Never start target code | Real separately built x64 FDD tripwire, unchanged hashes, absent entry sentinel; actual consumer CLI checks | Not malware-sandbox proof; only trusted benign fixtures |
| Classify AnyCPU separately from I386 native | Separately compiled no-RID AnyCpuGolden plus real x64 Tripwire and numeric32-bit flag mutations | Not all CLI/host/ABI formats |
| Avoid host-compatibility claims | Disable roll-forward, two frameworks, expected-version with separate build metadata | Reads declarations; does not resolve runtime policy |
| Duplicate JSON cannot silently win | Root/nested duplicate fields, deps duplicates, bounded arrays/bytes | Unknown non-contract metadata is not authenticated |
| Nested entries use their paired metadata | app/Sample.dll regression compares its paired deps asset Sample.dll | Not a full dependency resolver |
| A manifest cannot exempt arbitrary files | Exact self-exemption, missing/extra/hash, unsafe/duplicate/case-colliding/self-reference/wrong-size paths | Unsigned inventory agreement is not provenance |
| Late changes override earlier checks | Changes before config read, before recheck and late added file | No hostile-filesystem race guarantee |
| Child exit0 alone is insufficient | Missing/truncated/extra/duplicate/version/incomplete/oversized receipts and real hang/flood/exit17 children | Test probes are excluded from consumer archives |
| Avoid FIFO/open and path surprises | Linux FIFO/statx, actual symlinks, walk/depth/aggregate/per-file caps, report nesting/collision/write failure | Linux-only cases and local Windows privilege skips stay visible |
| A header is not a runnable executable | Handwritten PE/ELF header goldens, x86/ARM/big-endian/malformed examples | Header goldens intentionally are not executable programs |

Initial failed test evidence is retained in delivery notes. The first harness
launched its test host without dispatching the production worker. A subsequent
Linux run exposed an incorrect assumption that a RID-published tool assembly was
always AnyCPU, plus a string-based mutation that had not changed the protocol.
The test host now dispatches the exact production worker entry, the AnyCPU golden
is a separately compiled no-RID project, and each mutation must differ from its
valid receipt. Actual consumer-package CLI tests additionally use the shipped apphost.
These harness corrections do not establish application startup or performance.

Independent review also reproduced root-directory containment, final-newline
regex anchoring and nested-entry resolution defects before publication. Root
containment now preserves the root separator, patterns use absolute anchors and
explicit control rejection, and the nested entry uses its paired deps directory.
Lexical root/child/reverse/sibling tests never walk a real filesystem root;
control, line-separator and BOM characters are tried at every component/version
position. A mutated informational-version blob also cannot pass or leak its value.
The initial packaging adapter's wrong assets-directory path is retained as a failed
build log and corrected before candidate packaging. No failed candidate is released.

The public Execution lab's fixed release archives supply a separate real FDD
inventory/config/header compatibility example, inspected without running them.
Their release hashes and exact commands belong to the delivery receipt; no private
application or customer dataset is an input. No benchmark was performed or claimed.

## Wave5 M1: local report consumption example

The source-only [consumer](../examples/consume_report.py) checks a captured process
exit and a bounded v1 JSON report together. Explicit `--require` policy fails
closed for unselected checks while preserving the original inspector result.
See the [guide and counterexample](REPORT-CONSUMPTION.md) and seven focused
[regressions](../tests/test_report_consumer.py). Inspector C# code, packaging,
manifest/header/metadata semantics and frozen release assets are unchanged.
Local validation includes a separate real Tripwire sentinel/hash observation;
CI was not run per owner instruction. No startup/runtime/security claim follows.

Observed on the owned Ubuntu 24.04 x64 WSL job: 7 focused tests and 3 inspection
cases passed; 4 CLI decision cases returned the expected exits. The capped job
used CPU quota 2, memory max 4 GiB, tasks max 64 and memory swap max 0. The local
validation phase took about 14 seconds, peaked at 104,529,920 bytes cgroup memory
and 16 tasks; no OOM event was observed. The owned unit/cgroup terminated and the
exact-owner canonical lease was released. These observations are not a benchmark
or a claim about other hosts. An initial source-identity lookup failed before
tests because the Windows Git worktree link is not a Linux path; the bounded
corrected run checked the same candidate's explicit SHA/file hashes instead.

## .NET10 servicing validation

Runtime/source identity: `9254ccfeb36ef24ccea845d02aff000b0cd8795a`, signed tag
`v0.1.0-preview.2`, SDK10.0.404 and bundled runtime10.0.15. This is a servicing
update within .NET10 LTS, with no new target/packaging matrix or runtime-resolution
logic. The Python M1 consumer is unchanged.

| Actual local validation | Result |
| --- | --- |
| Windows26H2 x64 native regression | 83 passed, 0 failed, 3 explicit skips (local symlink privilege and Linux-only FIFO) |
| Ubuntu24.04 x64 regression coverage | 85 original successes plus the sole corrected FIFO case; all86 cases covered |
| Extracted, actual consumer archive | 14 checks per OS |
| Independent M1 Tripwire integration | 3 cases per OS; sentinel absent and input hashes unchanged |

The first Linux suite's nonzero exit is retained: its FIFO fixture could not be
created on DrvFs. Only that setup-dependent case was corrected to a real FIFO on
the Linux filesystem; its `NON_REGULAR_FILE`/exit1 expectation passed. The85
healthy cases, successful restore/build and SDK qualification were not rerun.
The first SCD restore also exposed a missing offline ASP.NET runtime pack; the
existing exact official cache was reused and its actual NuGet signature verified.
Windows SDK restore additionally used its existing transitive WindowsDesktop
runtime pack. Neither adds a product FrameworkReference or supported target type.
An aggregation pathmap error was fixed before signing; no healthy package was
rebuilt for that correction.

Each native phase used the single canonical lane and actual owned kernel limits:
at most2CPU,4GiB,64 processes/tasks; Linux memory swap max0. Source/SDK bytes and
host/PID were bound to the actual job. Every owned phase terminated and released
only its exact lease. The successful Linux continuation observed395,309,056 bytes
memory peak and39 tasks; the Windows native job observed194,715,648 bytes job
memory peak. These are observations of this workload, not benchmarks or universal
resource bounds for other hosts.

Windows26H2 is an experimental observed compatibility host, not a vendor-supported
OS qualification. Linux is the observed Ubuntu24.04/glibc x64 host. Existing
matching-OS archive guards and the no-target-execution boundary remain intact.
CI was NOT_RUN per owner instruction; the exact runtime commit had zero Actions
runs in the final readback. Commits and the annotated tag retain `[skip ci]`.
The old preview.1 tag, assets and signatures remain unchanged. Frozen binaries
and source identify the runtime commit above; later documentation commits do not
rebuild or replace those assets.
