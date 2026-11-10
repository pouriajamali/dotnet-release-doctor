using System.Security.Cryptography;
using System.Text.Json;

namespace ReleaseDoctor;
internal static class Demo
{
    internal static void Fixture(string folder, string assembly, string rid = "win-x64")
    {
        Directory.CreateDirectory(folder);
        File.Copy(assembly, Path.Combine(folder, "Sample.dll"), false);
        File.WriteAllText(Path.Combine(folder, "Sample.runtimeconfig.json"), "{\"runtimeOptions\":{\"tfm\":\"net10.0\",\"framework\":{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.14\"}}}");
        string target = ".NETCoreApp,Version=v10.0/" + rid;
        File.WriteAllText(Path.Combine(folder, "Sample.deps.json"), JsonSerializer.Serialize(new { runtimeTarget = new { name = target }, targets = new Dictionary<string, object> { { target, new Dictionary<string, object> { { "sample/0.1.0", new { runtime = new Dictionary<string, object> { { "Sample.dll", new { } } } } } } } }, libraries = new Dictionary<string, object> { { "sample/0.1.0", new { type = "project", serviceable = false } } } }));
    }

    internal static void Manifest(string folder)
    {
        var files = Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories).Select(p => new { path = Path.GetRelativePath(folder, p).Replace('\\', '/'), bytes = new FileInfo(p).Length, sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))).ToLowerInvariant() }).ToArray();
        File.WriteAllText(Path.Combine(folder, "BUILD-MANIFEST.json"), JsonSerializer.Serialize(new { files }, Contract.Json));
    }

    public static async Task<int> Run(string destination)
    {
        string root = Snapshot.Normalize(destination);
        if (Directory.Exists(root) || File.Exists(root))
            throw new Problem("OUTPUT_EXISTS");
        Directory.CreateDirectory(root);
        using (var marker = new FileStream(Path.Combine(root, ".doctor-demo-owned"), FileMode.CreateNew, FileAccess.Write))
            marker.Write(Contract.Utf8("synthetic-demo-v1"));
        string rid = OperatingSystem.IsWindows() ? "win-x64" : "linux-x64";
        bool all = true;
        foreach (var(name, expected)in new[]
        {
            ("valid", 0),
            ("missing-config", 1),
            ("duplicate-json", 2),
            ("wrong-rid", 2),
            ("changed-inventory", 2)
        }

        )
        {
            string input = Path.Combine(root, name);
            Fixture(input, typeof(Demo).Assembly.Location, rid);
            if (name == "missing-config")
                File.Delete(Path.Combine(input, "Sample.runtimeconfig.json")); // Only this fresh owned synthetic fixture.
            if (name == "duplicate-json")
                File.WriteAllText(Path.Combine(input, "Sample.runtimeconfig.json"), "{\"runtimeOptions\":{},\"runtimeOptions\":{}}");
            if (name == "wrong-rid")
                File.WriteAllText(Path.Combine(input, "Sample.deps.json"), File.ReadAllText(Path.Combine(input, "Sample.deps.json")).Replace(rid, rid == "win-x64" ? "linux-x64" : "win-x64"));
            Manifest(input);
            if (name == "changed-inventory")
                File.WriteAllText(Path.Combine(input, "extra.txt"), "Synthetic extra file, not private data.");
            Report report = await Inspection.Run(input, Path.Combine(root, name + " report"), "Sample.dll", rid, "BUILD-MANIFEST.json");
            bool pass = report.ExitCode == expected;
            all &= pass;
            Console.WriteLine($"{name}: exit{report.ExitCode}; expected{expected}; {(pass ? "matched" : "MISMATCH")}");
        }

        Console.WriteLine(all ? "DEMO PASS (expected successful and unsuccessful static assessments matched)" : "DEMO FAILED");
        return all ? 0 : 1;
    }
}
