using System.Text.Json;

namespace ReleaseDoctor;
internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "--version")
            {
                Console.WriteLine(".NET Release Doctor 0.1.0-preview.1");
                return 0;
            }

            if (args.Length == 4 && args[0] == "--metadata-worker")
            {
                string entry = Snapshot.Normalize(args[1]), report = Snapshot.Normalize(args[2]), token = args[3];
                string marker = Path.Combine(report, ".doctor-owned");
                if (token.Length != 32 || Environment.GetEnvironmentVariable("DOCTOR_INTERNAL_TOKEN") != token || new FileInfo(marker).Length != 32 || File.ReadAllText(marker) != token)
                    return 1;
                Console.WriteLine(JsonSerializer.Serialize(Metadata.Read(entry), Contract.Json));
                return 0;
            }

            if (args.Length == 2 && args[0] == "demo")
                return await Demo.Run(args[1]);
            if (args.Length < 7 || args[0] != "inspect" || (args.Length - 3) % 2 != 0)
                throw new Problem("CLI_INVALID");
            Dictionary<string, string> options = new(StringComparer.Ordinal);
            for (int i = 3; i < args.Length; i += 2)
                if (args[i] is not ("--entry" or "--rid" or "--manifest" or "--expected-version") || !options.TryAdd(args[i], args[i + 1]))
                    throw new Problem("CLI_INVALID");
            if (!options.TryGetValue("--entry", out var entryName) || !options.TryGetValue("--rid", out var rid))
                throw new Problem("CLI_INVALID");
            Report result = await Inspection.Run(args[1], args[2], entryName, rid, options.GetValueOrDefault("--manifest"), options.GetValueOrDefault("--expected-version"));
            Console.WriteLine(JsonSerializer.Serialize(result, Contract.Json));
            return result.ExitCode;
        }
        catch (Problem p)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { complete = false, outcome = "incomplete", exitCode = 1, reason = p.Code }, Contract.Json));
            return 1;
        }
        catch (Exception e)when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or InvalidOperationException)
        {
            Console.WriteLine("{\"complete\":false,\"outcome\":\"incomplete\",\"exitCode\":1,\"reason\":\"IO_OR_CONFIGURATION_FAILURE\"}");
            return 1;
        }
    }
}
