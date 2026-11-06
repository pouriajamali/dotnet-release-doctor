# Decisions with bounded evidence

| Decision | Evidence in tests/ReleaseDoctor.Tests/Program.cs | Limit |
| --- | --- | --- |
| Never start target code | Real separately built x64 FDD tripwire, unchanged hashes, absent entry sentinel; actual consumer CLI checks | Not malware-sandbox proof; only trusted benign fixtures |
| Classify AnyCPU separately from I386 native | Separately compiled no-RID AnyCpuGolden plus real x64 Tripwire and numeric32-bit flag mutations | Not all CLI/host/ABI formats |
| Avoid host-compatibility claims | Disable roll-forward, two frameworks, expected-version with separate build metadata | Reads declarations; does not resolve runtime policy |
| Duplicate JSON cannot silently win | Root/nested duplicate fields, deps duplicates, bounded arrays/bytes | Unknown non-contract metadata is not authenticated |
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

The public Execution lab's fixed release archives supply a separate real FDD
inventory/config/header compatibility example, inspected without running them.
Their release hashes and exact commands belong to the delivery receipt; no private
application or customer dataset is an input. No benchmark was performed or claimed.
