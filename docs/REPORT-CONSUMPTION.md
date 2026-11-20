# Consume an existing static report locally

The source-only [Python example](../examples/consume_report.py) projects Doctor's
v1 `summary.json` into a small JSON decision without starting Doctor, opening the
target or resolving dependencies. It needs Python 3.12 or later, standard library
only. It is distributed with source, separately from the frozen
[v0.1.0-preview.2 consumer bundles](https://github.com/pouriajamali/dotnet-release-doctor/releases/tag/v0.1.0-preview.2).
No SDK, new inspector build, workflow or service is needed to consume a report.

Save the **actual** Doctor exit immediately. With a trusted-origin extracted FDD
fixture and a fresh report directory, in PowerShell:

```powershell
.\doctor.exe inspect "extracted app" "new report" --entry App.dll --rid win-x64
$doctorExit = $LASTEXITCODE
python examples/consume_report.py "new report/summary.json" --doctor-exit $doctorExit
$decisionExit = $LASTEXITCODE
# In an automation script: exit $decisionExit
```

The equivalent shell capture is `doctor_exit=$?` immediately after `./doctor
inspect ...`, then `python3 examples/consume_report.py "new report/summary.json"
--doctor-exit "$doctor_exit"`. Run the command on one line; do not lose the exit
by piping through another command or add `|| true`. Use a fresh report directory
for each inspection. This consumer cannot detect a substituted/stale report whose
contents and supplied exit happen to agree; provenance and freshness remain the
caller's responsibility. Use local regular report files from a trusted workflow.

| Decision exit | Meaning |
| --- | --- |
| 0 | Consistent complete selected static pass; optional checks may be `not_checked` |
| 2 | Consistent completed static failure, with the inspector reason retained |
| 1 | Incomplete/unsupported report, unreadable/malformed/missing report, exit disagreement, or unmet explicit consumer policy |

The projection retains all six checks, original `reason`, inspector outcome/exit
and the five fixed assurance disclaimers. `RID_UNSUPPORTED` and
`SELF_CONTAINED_UNSUPPORTED` remain incomplete, not evidence of corrupt input.
Unknown schema, duplicate properties, contradictory success, missing/reordered
checks, an altered assurance or more than 64 KiB of report data cannot yield exit0.
The projection is a small consumption example, not full validation of every
informational field, a signature verifier or a hostile-filesystem sandbox.

## Counterexample: selected pass is not an inventory pass

A successful run without `--manifest` has `inventory: not_checked / NOT_SELECTED`.
The basic consumer correctly returns 0 while preserving that status. If your
local policy requires an inventory check, request it explicitly:

```powershell
python examples/consume_report.py "new report/summary.json" --doctor-exit $doctorExit --require inventory
```

This returns 1 with `REQUIRED_CHECK_NOT_PASSED`, `inspectorExit: 0`, and
`unmetRequiredChecks: ["inventory"]`. It does not rewrite the original static
pass. Rerun inspection with an authenticated-origin package and its separately
selected manifest to obtain a new assessment if needed; an agreeing manifest
still does not authenticate the package. `--require expected-version` similarly
requires a selected version check. Do not use the consumer to turn missing
optional checks into green checks.

A genuine expected-version mismatch remains exit2. An unsupported self-contained
target remains incomplete/exit1 with dependent checks `not_checked`. Missing JSON
after a report-write error remains exit1 even if an old text report says PASS.

## Evidence and scope

Run `python -m unittest discover -s tests -p test_report_consumer.py -v` from source.
For a separate integration with an existing trusted Doctor and the published-from-source
Tripwire test fixture (never run the target), use a new work directory:

```sh
python3 tests/check_report_consumer_integration.py --doctor /absolute/path/to/doctor --fixture /absolute/path/to/tripwire --work /absolute/path/to/new-work
```

The example's focused regressions cover selected pass, explicit policy rejection,
completed failure, unsupported input, invalid receipts and captured-exit mismatch.
The Wave5 local integration also used the existing published Linux Doctor on a
synthetic Windows x64 Tripwire FDD fixture, a version-mismatch counterexample and
an unsupported runtimeconfig. It checked the target sentinel remained absent and
the input file hashes stayed unchanged. This uses the existing supported
cross-platform static inspection contract, not a new platform matrix.

No inspector code, manifest adapter, entry/header reader, metadata contract,
package version, historical signature or frozen release asset changes in this M1.
CI was not run per owner instruction. Local evidence is not GitHub CI evidence.

Microsoft's [publishing modes](https://learn.microsoft.com/en-us/dotnet/core/deploying/)
explain why FDD declarations differ from runtime availability. Python's
[JSON documentation](https://docs.python.org/3/library/json.html) documents
`object_pairs_hook` and recommends bounding input size; the example rejects
duplicates rather than accepting the decoder's default last-value behavior.
Static PASS establishes neither startup nor runtime resolution, security or a
sandbox. The report remains UNVERIFIED / NOT_CHECKED / NOT_EXECUTED /
NOT_PROVEN / NOT_ASSESSED.
