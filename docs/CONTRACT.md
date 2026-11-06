# Static inspection contract v1

The selected target is a trusted-origin extracted FDD directory, never an archive
to unpack or an executable to run. A separately authenticated public package can
be input, but this tool itself does not authenticate its origin. Consult
[PEReader's trusted-input boundary](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.portableexecutable.pereader?view=net-10.0).

Check order: runtime-config, deps, entry-metadata, native-headers, expected-version,
inventory. A failed prerequisite leaves later checks not_checked. Optional checks
not selected are visibly NOT_SELECTED; they do not become green authenticity.
Any observed late snapshot change overrides earlier results to incomplete/exit1.
Fresh JSON is published after the text report; forced loss can leave partial files.

Entry is an exact relative `.dll` path. Matching `.runtimeconfig.json` and
`.deps.json` are required by this inspector. Their absence does not mean a host
cannot start an application. Runtime JSON supports framework or frameworks, not
both or includedFrameworks; only NETCore.App and AspNetCore.App declarations,
bounded stable numeric versions, and documented rollForward values are supported.
Declared applyPatches is shown without evaluation; legacy rollForwardOnNoCandidateFx
is unsupported rather than silently described as a default policy.
No resolution policy, installed-host fallback or full TFM/API consistency proof.
Deps requires its declared runtime target and a runtime asset matching entry.
Portable target names and selected win-x64/linux-x64 declarations are supported.

The owned worker reads only entry metadata using PEReader/MetadataReader, never
Assembly.Load or target execution. IL-only PE32/I386 without 32-bit flags is
AnyCPU; IL-only PE32+/AMD64 is x64. Requires32Bit fails selected x64 scope;
Prefers32Bit and mixed/other machines are unsupported. Informational version is
bounded ASCII release/build metadata, not an authenticated identity. Optional
expected-version compares release parts, separately retaining build metadata.

Worker receipt is exactly schema, complete, outcome, code, architecture,
releaseVersion, buildMetadata. Schema1, complete=true and consistent allowlisted
codes/values are required. Duplicate/extra/missing fields, arbitrary status,
truncation, exit0 without receipt and excess output are incomplete. Parent deadline
10seconds; stdout16KiB/stderr4KiB drain concurrently. Termination/drain handling has
separate bounds; I/O and native memory are not a comprehensive sandbox.

Native header reads inspect at most4KiB. PE offset above3KiB is unsupported;
PE32+/AMD64 is the selected native Windows shape, ELF64/little-endian/EM_X86_64
the selected Linux shape. These are header checks, not full file validation.
CLI-directory PE candidates are not counted as native; only entry metadata is
validated. No complete other-assembly/PInvoke/ABI/libc/dependency/startup proof.

Selected manifest is an exact root-level relative filename. `files` is an array
of unique case-insensitive paths with nonnegative integer bytes and lowercase
64-hex SHA256. Actual paths must match exact casing; reject traversal, alternate
streams, controls, duplicates, self-reference, missing/unlisted entries and hash
or size disagreement. Only the exact selected filename is excluded. Optional
version/RID must agree; other metadata fields do not grant authenticity.

Resource bounds and filenames are listed in README. Source hashes/metadata and
entry inventory are rechecked. Read-only inspection may update filesystem access
times; it does not modify file contents. No hostile-filesystem protection or
universal remote-mount detection. On supported Linux, statx TYPE is checked before
opening a regular file. A missing type facility is incomplete.

Reports disclose only bounded validated declarations, static codes and counts,
not target absolute paths, raw exceptions, arbitrary config values or row data.
UNVERIFIED / NOT_CHECKED / NOT_EXECUTED / NOT_PROVEN / NOT_ASSESSED remain explicit
on a successful static assessment. No network lookup, download, install or repair.

Primary background: [runtimeconfig specification](https://github.com/dotnet/sdk/blob/main/documentation/specs/runtime-configuration-file.md),
[framework selection](https://learn.microsoft.com/en-us/dotnet/core/versions/selection),
[CorFlags](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.portableexecutable.corflags?view=net-10.0),
[Linux statx UAPI](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/stat.h).
