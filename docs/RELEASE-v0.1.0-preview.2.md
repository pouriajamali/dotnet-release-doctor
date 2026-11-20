# v0.1.0-preview.2 — .NET 10 LTS servicing

Preview release. Complete publication requires both native archives, the source
archive and signed SHA256SUMS. The existing preview.1 assets/tags/signatures remain
unchanged and can still be verified through their original checksum signature.

- Retain net10.0 LTS. Upgrade the pinned source SDK from 10.0.403 to 10.0.404
  and the bundled runtime from 10.0.14 to 10.0.15, the official 2026-11-10
  security servicing release. Avoid an unnecessary .NET 11 product migration.
- Derive packaging runtime version and runtime notices from Directory.Build.props
  so the archive cannot silently retain the old hard-coded runtime pack.
- Update only tool version and synthetic declaration/version expectations. The
  inspection/check order, JSON v1, exit0/2/1, not_checked and unsupported semantics,
  inventory/header/metadata constraints, --require companion and no-target-execution
  boundary remain intact. NativeAOT/single-file and additional target platforms
  remain unsupported.
- Native matching-OS regression, actual extracted package checks, M1 sentinel
  integration, checksum/signature and download validation are release gates.
  CI is NOT_RUN per owner instruction; it is not replaced with a fictional CI PASS.

The local Windows host reports 26H2/build26300. Microsoft's current .NET10
supported-OS table lists Windows11 versions through26H1. The existing package pipeline requires matching native Windows/Linux OS and
x64, rather than vendor certification of a particular Windows version. A local
Windows26H2 execution, when successful, is reported only as experimental observed
compatibility with owned Job Object limits; it is not vendor-supported OS
admission or another project's qualification. Linux validation uses the actual
owned Ubuntu24.04 x64 job with kernel limits. Cross-publishing a Windows local
candidate on Linux is not matching-OS validation or a public Windows release.

Official references: [.NET10 release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json),
[10.0.15 notes](https://github.com/dotnet/core/blob/main/release-notes/10.0/10.0.15/10.0.15.md),
[supported OS](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md).
Static PASS is not proof of startup, framework resolution, safety or a sandbox.
