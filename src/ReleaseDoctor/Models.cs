using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ReleaseDoctor;
internal sealed class Problem(string code, bool failure = false) : Exception(code)
{
    public string Code { get; } = code;
    public bool Failure { get; } = failure;
}

internal sealed record Check(string Id, string Status, string Code);
internal sealed record FrameworkRequirement(string Name, string DeclaredVersion, string RollForward);
internal sealed class Report
{
    public string Schema { get; set; } = "release-doctor-report-v1";
    public string ToolVersion { get; set; } = "0.1.0-preview.1";
    public string Rid { get; set; } = "";
    public bool Complete { get; set; }
    public string Outcome { get; set; } = "incomplete";
    public int ExitCode { get; set; } = 1;
    public string Reason { get; set; } = "NOT_COMPLETED";
    public List<Check> Checks { get; set; } = [];
    public List<FrameworkRequirement> Frameworks { get; set; } = [];
    public string ManagedArchitecture { get; set; } = "NOT_CHECKED";
    public string ReleaseVersion { get; set; } = "NOT_CHECKED";
    public string BuildMetadata { get; set; } = "NOT_CHECKED";
    public int ObservedNativeHeaders { get; set; }
    public int Files { get; set; }
    public long Bytes { get; set; }
    public string InputProvenance { get; set; } = "UNVERIFIED";
    public string InstalledRuntime { get; set; } = "NOT_CHECKED";
    public string Startup { get; set; } = "NOT_EXECUTED";
    public string DependencyResolution { get; set; } = "NOT_PROVEN";
    public string Safety { get; set; } = "NOT_ASSESSED";
}

internal static partial class Contract
{
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
    public static readonly string[] CheckIds = ["runtime-config", "deps", "entry-metadata", "native-headers", "expected-version", "inventory"];
    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9._ -]*\z")]
    private static partial Regex ComponentPattern();
    [GeneratedRegex(@"\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z")]
    private static partial Regex VersionPattern();
    public static string Relative(string path)
    {
        if (path.Length is 0 or > 384 || path.Any(char.IsControl) || path.Contains('\\') || path.Contains(':') || path.StartsWith('/') || path.Split('/').Length > 16)
            throw new Problem("PATH_UNSUPPORTED");
        foreach (string part in path.Split('/'))
            if (part.Length is 0 or > 96 || part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.') || !ComponentPattern().IsMatch(part))
                throw new Problem("PATH_UNSUPPORTED");
        return path;
    }

    public static string Version(string value)
    {
        if (value.Length > 128 || value.Any(char.IsControl) || !VersionPattern().IsMatch(value))
            throw new Problem("VERSION_UNSUPPORTED");
        return value;
    }

    public static string ReleasePart(string value) => Version(value).Split('+')[0];
    public static JsonDocument ParseJson(byte[] bytes)
    {
        if (bytes.Length > 4 * 1024 * 1024)
            throw new Problem("JSON_LIMIT");
        try
        {
            JsonDocument d = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            try
            {
                Validate(d.RootElement);
                return d;
            }
            catch
            {
                d.Dispose();
                throw;
            }
        }
        catch (JsonException)
        {
            throw new Problem("JSON_INVALID", true);
        }
    }

    private static void Validate(JsonElement e)
    {
        if (e.ValueKind == JsonValueKind.Object)
        {
            HashSet<string> names = new(StringComparer.Ordinal);
            int count = 0;
            foreach (var p in e.EnumerateObject())
            {
                if (++count > 1024 || p.Name.Length > 384)
                    throw new Problem("JSON_LIMIT");
                if (!names.Add(p.Name))
                    throw new Problem("JSON_DUPLICATE_PROPERTY", true);
                Validate(p.Value);
            }
        }
        else if (e.ValueKind == JsonValueKind.Array)
        {
            if (e.GetArrayLength() > 1024)
                throw new Problem("JSON_LIMIT");
            foreach (var item in e.EnumerateArray())
                Validate(item);
        }
        else if (e.ValueKind == JsonValueKind.String && e.GetString()!.Length > 4096)
            throw new Problem("JSON_LIMIT");
    }

    public static JsonElement Object(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.Object)
            throw new Problem("JSON_SHAPE", true);
        return e;
    }

    public static JsonElement Required(JsonElement e, string name)
    {
        Object(e);
        if (!e.TryGetProperty(name, out var v))
            throw new Problem("JSON_FIELD_MISSING", true);
        return v;
    }

    public static string Text(JsonElement e)
    {
        if (e.ValueKind != JsonValueKind.String)
            throw new Problem("JSON_SHAPE", true);
        return e.GetString()!;
    }

    public static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);
}
