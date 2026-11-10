# .NET Release Doctor

Inspect an extracted **framework-dependent** .NET application directory without
starting its entry assembly, apphost or scripts. Get declared framework versions,
observed architecture/RID inconsistencies and an optional file-inventory comparison
as JSON and a plain text report. This is a static check, not a runtime installer
or a verdict that an application is safe or will start.

Preview channel: **v0.1.0-preview.1**. [Downloads](https://github.com/pouriajamali/dotnet-release-doctor/releases/tag/v0.1.0-preview.1)
and [signature verification](PROVENANCE.md). A missing release or checksum signature
is an incomplete publication; do not bypass verification.

## Start with the synthetic demo

Extract the complete bundle and keep its files together. The doctor itself is
self-contained; no installed .NET SDK/runtime is required. Native OS libraries
still apply; this is not a clean-OS installation guarantee.

Windows x64:

```powershell
.\doctor.exe --version
.\doctor.exe demo "demo output"
```

Ubuntu 24.04/glibc x64:

```sh
./doctor --version
./doctor demo "demo output"
```

Use a new output directory. Five generated metadata fixtures show a valid static
assessment, missing runtime metadata, duplicate JSON, a wrong declared RID and an
unlisted file. `DEMO PASS` / exit0 means all five **expected** outcomes matched;
it does not mean all inputs passed. The fixtures are for static checks, not proof
of application startup. No target is launched. Open each `report.txt` alongside its
complete `summary.json`.

## Inspect your own build

Use only trusted-origin packages: your own builds or public releases authenticated
through a separate trusted procedure. An arbitrary folder plus its own unsigned
manifest is not authenticated. Microsoft warns that
[PEReader is not designed for untrusted input](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.portableexecutable.pereader?view=net-10.0).
A child deadline limits an observed inspection hang; it does not provide a sandbox
for malicious PE files.

```powershell
.\doctor.exe inspect "extracted app" "new report" --entry App.dll --rid win-x64
.\doctor.exe inspect "extracted app" "another report" --entry App.dll --rid win-x64 --manifest BUILD-MANIFEST.json --expected-version 0.5.2-preview.1
```

On Linux use `./doctor` and `--rid linux-x64` for a Linux target. The selected RID
describes the **target**, not the computer running Doctor: cross-platform static
inspection is allowed. Source checkout users can replace `doctor` with
`dotnet run --project src/ReleaseDoctor -c Release --` using SDK10.0.403.

| Exit | Meaning |
| --- | --- |
| 0 | Supported selected static checks passed; unselected checks remain `not_checked` |
| 2 | A completed static check failed; later dependent checks are `not_checked` |
| 1 | Incomplete, unsupported, I/O, child/protocol/deadline or report-write failure |

Always read `complete`, `outcome` and the reason. Input provenance is **UNVERIFIED**,
installed runtime **NOT_CHECKED**, target startup **NOT_EXECUTED**, dependency
resolution **NOT_PROVEN** and safety **NOT_ASSESSED**, including on exit0.
Report files are not a power-loss-atomic pair; missing/invalid JSON is not success.

## Supported checks and limits

- Extracted directories only. Windows x64 / Ubuntu24.04 glibc x64 FDD targets;
  self-contained targets, single-file, NativeAOT, ARM, musl/macOS and custom hosts
  are unsupported, not declared corrupt. The doctor's own self-contained package
  is distinct from the target packages it can assess.
- Bounded runtimeconfig/deps JSON, duplicate-property rejection and declared
  Microsoft.NETCore.App / Microsoft.AspNetCore.App framework versions and
  roll-forward policy. These are declarations; Doctor does not implement host
  framework resolution, inspect installed runtimes or prove prerequisites are met.
  Missing `.deps.json` is unsupported by this tool, not proof a .NET host cannot run.
- Entry assembly metadata and informational release/build version, read without
  `Assembly.Load`. Separate AnyCPU, x64, 32BITREQUIRED and 32BITPREFERRED cases;
  the latter is unsupported here. No target code, apphost, initializer or script runs.
- Declared deps RID and observed native PE/ELF headers. This is a bounded header
  check, not complete executable/ABI validation or a P/Invoke dependency resolver.
  PE images with a CLI directory are treated as managed candidates; only the
  selected entry's managed metadata is validated. Other assembly metadata and
  API compatibility are outside scope.
- Optional inventory: root-level exact selected manifest name; unique relative
  `files` entries with `path`, `bytes`, lowercase SHA256, optional `version`/`rid`.
  Only that manifest is excluded from its own inventory; it must not list itself.
  No wildcard exemptions. This small adapter accepts the public Execution lab's
  inventory shape but does not authenticate its other build/provenance fields.
  No selected manifest means `not_checked`; agreement is not authenticity.
- Up to512 walked entries, including directories;256MiB total,64MiB per file;
  path384 characters, component96,16 components/depth; JSON4MiB/depth16,
  up to1,024 properties/array elements per container, bounded strings/diagnostics.
  Actual reads/walks are capped; stat sizes alone are insufficient. Files are hashed
  again and observed changes force incomplete. Disk operations have no universal
  hard deadline and hostile-filesystem races are unsupported.
- Observed links/reparse points, case collisions, unsafe/control-character names,
  source/report nesting, existing reports, network-style paths and non-regular files
  are refused. Linux uses the public statx ABI to reject FIFO/device/socket types
  before opening; inability to inspect a type is incomplete. Remote mounts are
  unsupported and not universally detectable. No target files are changed.
- Owned metadata child, ten-second parent deadline, concurrent stdout16KiB /
  stderr4KiB drains and strict complete/versioned receipt. Crash, stderr, overflow,
  nonzero exit, missing/invalid receipt or deadline cannot yield PASS. This is
  process control, not a malicious-input or native-memory security boundary.

## Reproduce the tests

Use fresh artifact directories. On Windows PowerShell:

```powershell
$rid = 'win-x64'
dotnet publish tests/Tripwire -c Release -r $rid --self-contained false -o artifacts/tripwire
dotnet publish tests/AnyCpuGolden -c Release --self-contained false -o artifacts/anycpu
dotnet restore tests/ReleaseDoctor.Tests --locked-mode
dotnet run --project tests/ReleaseDoctor.Tests -c Release --no-restore -- --work artifacts/tests --fixture artifacts/tripwire --fixture-rid $rid --anycpu artifacts/anycpu/AnyCpuGolden.dll
```

On Ubuntu use the same commands with `rid='linux-x64'` in the shell and `$rid` in
the arguments. Do not execute the test target: its benign entry writes a sentinel
if launched. Tests confirm Doctor leaves that sentinel absent and preserves target
hashes. Test probes/targets are excluded from consumer bundles. Windows without
local symlink privilege reports explicit skips; the FIFO test is Linux-only.
The [Windows/Ubuntu workflow](https://github.com/pouriajamali/dotnet-release-doctor/actions/workflows/verify.yml)
also builds and executes each actual extracted consumer archive on its matching OS.

See [contracts](docs/CONTRACT.md), [decision/test map](docs/CASE-STUDY.md) and
[contribution guide](CONTRIBUTING.md). No speed, customer, production, revenue or
security certification claim is made.

## Existing tools and attribution

[ApiCompat/package validation](https://learn.microsoft.com/en-us/dotnet/fundamentals/apicompat/package-validation/overview)
checks library API compatibility;
[NuGet verify](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-nuget-verify)
verifies NuGet signatures/content hashes;
[Microsoft sbom-tool](https://github.com/microsoft/sbom-tool) provides SBOM workflows.
Doctor replaces none of them. Its bounded difference is an extracted FDD
application's offline declarations, entry/header diagnostics and optional inventory.

Independent synthetic tool created with AI assistance for Pouria Jamali,
November2026. Original source uses [MIT](LICENSE); upstream runtime licenses and
notices remain in each bundle. The public MIT portfolio transport/packaging and
provenance guide are reused with attribution in [NOTICE](NOTICE.md). No private,
shared, employer or customer source/contracts/data are included. No hosted service,
deployment, trading, account connection, package installation or repair is provided.

[CI resource policy](docs/CI-POLICY.md): documentation-only changes get real lightweight document/pipeline checks; source, tag and manual runs retain native validation. Published runtime tags and release assets remain unchanged.

## Source readability

The current source expands compact C# layout for review. The published preview links identify its frozen runtime release. Formatting preserves complete syntax, token text and values, comments and directives; it does not introduce a runtime behavior or performance claim.

To reproduce a published package, use its exact original runtime source: [v0.1.0-preview.1 source](https://github.com/pouriajamali/dotnet-release-doctor/tree/33d1c733c1a2d8bd940f42809536d42cb284477e) (`33d1c733c1a2d8bd940f42809536d42cb284477e`). Later `main` layout is reviewed separately from those frozen release commits.
