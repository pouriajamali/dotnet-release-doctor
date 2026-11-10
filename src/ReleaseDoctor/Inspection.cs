using System.Text;
using System.Text.Json;

namespace ReleaseDoctor;
internal sealed class TestHooks
{
    internal Action<Snapshot>? AfterSnapshot { get; init; }
    internal Action? BeforeRecheck { get; init; }
    internal Action<string>? BeforeReport { get; init; }
    internal Func<Task<TransportResult>>? Worker { get; init; }
}

internal static class Inspection
{
    public static async Task<Report> Run(string source, string destination, string entry, string rid, string? manifest = null, string? expected = null, TestHooks? hooks = null)
    {
        Report report = new()
        {
            Checks = Contract.CheckIds.Select(id => new Check(id, "not_checked", "PREREQUISITE_NOT_MET")).ToList()
        };
        string output = "", token = Guid.NewGuid().ToString("N"), current = "";
        bool owned = false;
        void Set(string id, string status, string code) => report.Checks[Array.IndexOf(Contract.CheckIds, id)] = new(id, status, code);
        try
        {
            if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
                throw new Problem("HOST_UNSUPPORTED");
            if (rid is not ("win-x64" or "linux-x64"))
                throw new Problem("RID_UNSUPPORTED");
            report.Rid = rid;
            Contract.Relative(entry);
            if (!entry.EndsWith(".dll", StringComparison.Ordinal))
                throw new Problem("ENTRY_UNSUPPORTED");
            if (expected != null)
                expected = Contract.ReleasePart(expected);
            string input = Snapshot.Normalize(source);
            output = Snapshot.Normalize(destination);
            if (Snapshot.Nested(output, input) || Snapshot.Nested(input, output))
                throw new Problem("INPUT_REPORT_COLLISION");
            if (Directory.Exists(output) || File.Exists(output))
                throw new Problem("OUTPUT_EXISTS");
            Directory.CreateDirectory(output);
            Snapshot.NoLinks(output);
            using (var marker = new FileStream(Path.Combine(output, ".doctor-owned"), FileMode.CreateNew, FileAccess.Write))
                marker.Write(Contract.Utf8(token));
            owned = true;
            Snapshot snapshot = Snapshot.Capture(input);
            report.Files = snapshot.Files.Count;
            report.Bytes = snapshot.Bytes;
            hooks?.AfterSnapshot?.Invoke(snapshot);
            try
            {
                if (!snapshot.Files.ContainsKey(entry))
                    throw new Problem("ENTRY_UNAVAILABLE");
                current = "runtime-config";
                report.Frameworks = StaticChecks.Runtime(snapshot.ReadSmall(Path.ChangeExtension(entry, "runtimeconfig.json")));
                Set(current, "pass", "FRAMEWORK_DECLARATIONS_READ");
                current = "deps";
                StaticChecks.Deps(snapshot.ReadSmall(Path.ChangeExtension(entry, "deps.json")), entry, rid);
                Set(current, "pass", "DECLARED_TARGET_CHECKED");
                current = "entry-metadata";
                TransportResult result = hooks?.Worker != null ? await hooks.Worker() : await Transport.RunAsync(Transport.OwnWorker(Path.Combine(input, entry), output, token));
                if (result.Problem.Length > 0)
                    throw new Problem(result.Problem);
                if (result.ExitCode != 0)
                    throw new Problem("WORKER_FAILED");
                MetadataResult metadata = Metadata.Parse(result.Stdout);
                report.ManagedArchitecture = metadata.Architecture;
                if (metadata.Outcome != "pass")
                    throw new Problem(metadata.Code, metadata.Outcome == "fail");
                report.ReleaseVersion = metadata.ReleaseVersion;
                report.BuildMetadata = metadata.BuildMetadata;
                Set(current, "pass", metadata.Code);
                current = "native-headers";
                report.ObservedNativeHeaders = StaticChecks.NativeHeaders(snapshot, rid);
                Set(current, "pass", "OBSERVED_HEADERS_CHECKED");
                current = "expected-version";
                if (expected == null)
                    Set(current, "not_checked", "NOT_SELECTED");
                else
                {
                    if (metadata.ReleaseVersion != expected)
                        throw new Problem("EXPECTED_VERSION_MISMATCH", true);
                    Set(current, "pass", "RELEASE_PART_MATCHES");
                }

                current = "inventory";
                if (manifest == null)
                    Set(current, "not_checked", "NOT_SELECTED");
                else
                {
                    StaticChecks.Inventory(snapshot, manifest, metadata.ReleaseVersion, rid);
                    Set(current, "pass", "INVENTORY_AGREES_NOT_AUTHENTICATED");
                }

                report.Complete = true;
                report.Outcome = "pass";
                report.ExitCode = 0;
                report.Reason = "SELECTED_STATIC_CHECKS_PASSED";
            }
            catch (Problem p)
            {
                if (current.Length > 0)
                    Set(current, p.Failure ? "fail" : "not_checked", p.Code);
                report.Complete = p.Failure;
                report.Outcome = p.Failure ? "fail" : "incomplete";
                report.ExitCode = p.Failure ? 2 : 1;
                report.Reason = p.Code;
            }

            hooks?.BeforeRecheck?.Invoke();
            snapshot.Recheck();
        }
        catch (Problem p)
        {
            report.Complete = false;
            report.Outcome = "incomplete";
            report.ExitCode = 1;
            report.Reason = p.Code;
        }
        catch (Exception e)when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            report.Complete = false;
            report.Outcome = "incomplete";
            report.ExitCode = 1;
            report.Reason = "IO_OR_PROCESS_FAILURE";
        }

        if (owned)
        {
            try
            {
                hooks?.BeforeReport?.Invoke(output);
                Snapshot.NoLinks(output);
                if (File.ReadAllText(Path.Combine(output, ".doctor-owned")) != token)
                    throw new Problem("OUTPUT_OWNERSHIP_CHANGED");
                string plain = ".NET Release Doctor — selected static checks only\n" + $"Outcome: {report.Outcome}; complete: {report.Complete}; exit: {report.ExitCode}; code: {report.Reason}\n" + "Input provenance: UNVERIFIED; installed runtime: NOT_CHECKED; target startup: NOT_EXECUTED; safety: NOT_ASSESSED\n" + string.Join("\n", report.Frameworks.Select(f => $"Declared framework: {f.Name}; declared version: {f.DeclaredVersion}; roll-forward: {f.RollForward} (not resolved)")) + "\n" + string.Join("\n", report.Checks.Select(c => $"{c.Id}: {c.Status} / {c.Code}")) + "\n";
                static void Fresh(string path, string content)
                {
                    using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write);
                    stream.Write(Encoding.UTF8.GetBytes(content));
                }

                Fresh(Path.Combine(output, "report.txt.pending"), plain);
                Fresh(Path.Combine(output, "summary.json.pending"), JsonSerializer.Serialize(report, Contract.Json) + "\n");
                File.Move(Path.Combine(output, "report.txt.pending"), Path.Combine(output, "report.txt"));
                File.Move(Path.Combine(output, "summary.json.pending"), Path.Combine(output, "summary.json"));
            }
            catch (Exception e)when (e is IOException or UnauthorizedAccessException or Problem)
            {
                report.Complete = false;
                report.Outcome = "incomplete";
                report.ExitCode = 1;
                report.Reason = "REPORT_WRITE_FAILED";
            }
        }

        return report;
    }
}
