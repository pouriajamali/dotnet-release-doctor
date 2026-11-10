using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;

namespace ReleaseDoctor;
internal sealed record MetadataResult(int Schema, bool Complete, string Outcome, string Code, string Architecture, string ReleaseVersion, string BuildMetadata);
internal static class Metadata
{
    private static MetadataResult Invalid(string code, bool unsupported = false, string architecture = "NOT_CHECKED") => new(1, true, unsupported ? "unsupported" : "fail", code, architecture, "NOT_CHECKED", "NOT_CHECKED");
    public static MetadataResult Read(string entry)
    {
        try
        {
            Snapshot.NoLinks(entry);
            Snapshot.RequireRegular(entry);
            using FileStream stream = new(entry, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > Snapshot.FileLimit)
                return Invalid("ENTRY_LIMIT", true);
            using PEReader pe = new(stream);
            var cor = pe.PEHeaders.CorHeader;
            if (!pe.HasMetadata || cor == null)
                return Invalid("ENTRY_NOT_MANAGED_UNSUPPORTED", true);
            if (!pe.GetMetadataReader().IsAssembly)
                return Invalid("ENTRY_MODULE_UNSUPPORTED", true);
            if ((cor.Flags & CorFlags.ILOnly) == 0 || (cor.Flags & CorFlags.NativeEntryPoint) != 0)
                return Invalid("MIXED_MODE_UNSUPPORTED", true);
            if ((cor.Flags & CorFlags.Requires32Bit) != 0)
                return Invalid("ENTRY_32BIT_REQUIRED", false, "32bit-required");
            if ((cor.Flags & CorFlags.Prefers32Bit) != 0)
                return Invalid("ENTRY_32BIT_PREFERRED", true, "32bit-preferred");
            string architecture = pe.PEHeaders.CoffHeader.Machine switch
            {
                Machine.I386 when pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32 => "anycpu",
                Machine.Amd64 when pe.PEHeaders.PEHeader?.Magic == PEMagic.PE32Plus => "x64",
                _ => "unsupported"
            };
            if (architecture == "unsupported")
                return Invalid("ENTRY_MACHINE_UNSUPPORTED", true);
            MetadataReader reader = pe.GetMetadataReader();
            string? info = null;
            foreach (var handle in reader.GetAssemblyDefinition().GetCustomAttributes())
            {
                var attribute = reader.GetCustomAttribute(handle);
                if (attribute.Constructor.Kind != HandleKind.MemberReference)
                    continue;
                var member = reader.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
                if (member.Parent.Kind != HandleKind.TypeReference)
                    continue;
                var type = reader.GetTypeReference((TypeReferenceHandle)member.Parent);
                if (reader.GetString(type.Namespace) != "System.Reflection" || reader.GetString(type.Name) != "AssemblyInformationalVersionAttribute")
                    continue;
                if (info != null)
                    return Invalid("ENTRY_VERSION_AMBIGUOUS");
                var blob = reader.GetBlobReader(attribute.Value);
                if (blob.ReadUInt16() != 1)
                    return Invalid("ENTRY_VERSION_INVALID");
                info = blob.ReadSerializedString();
                if (info == null || blob.ReadUInt16() != 0 || blob.RemainingBytes != 0)
                    return Invalid("ENTRY_VERSION_INVALID");
            }

            if (info == null)
                return Invalid("ENTRY_VERSION_UNAVAILABLE", true);
            Contract.Version(info);
            string[] parts = info.Split('+');
            return new(1, true, "pass", "ENTRY_METADATA_READ", architecture, parts[0], parts.Length == 2 ? parts[1] : "");
        }
        catch (Problem p)
        {
            return Invalid(p.Code, true);
        }
        catch (Exception e)when (e is BadImageFormatException or InvalidOperationException or ArgumentOutOfRangeException)
        {
            return Invalid("ENTRY_METADATA_INVALID");
        }
    }

    public static MetadataResult Parse(byte[] bytes)
    {
        if (bytes.Length > 16 * 1024)
            throw new Problem("WORKER_PROTOCOL");
        try
        {
            using var d = Contract.ParseJson(bytes);
            var root = Contract.Object(d.RootElement);
            string[] fields = ["schema", "complete", "outcome", "code", "architecture", "releaseVersion", "buildMetadata"];
            if (!root.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(fields))
                throw new Problem("WORKER_PROTOCOL");
            if (Contract.Required(root, "schema").GetInt32() != 1 || Contract.Required(root, "complete").ValueKind != JsonValueKind.True)
                throw new Problem("WORKER_PROTOCOL");
            string outcome = Contract.Text(Contract.Required(root, "outcome")), code = Contract.Text(Contract.Required(root, "code")), arch = Contract.Text(Contract.Required(root, "architecture")), version = Contract.Text(Contract.Required(root, "releaseVersion")), build = Contract.Text(Contract.Required(root, "buildMetadata"));
            if (code == "ENTRY_METADATA_READ")
            {
                if (outcome != "pass" || arch is not ("anycpu" or "x64") || Contract.ReleasePart(version) != version || version.Contains('+') || build.Length > 128 || (build.Length > 0 && Contract.Version("1.0.0+" + build).Split('+').Length != 2))
                    throw new Problem("WORKER_PROTOCOL");
            }
            else
            {
                var expected = code switch
                {
                    "ENTRY_32BIT_REQUIRED" => ("fail", "32bit-required"),
                    "ENTRY_32BIT_PREFERRED" => ("unsupported", "32bit-preferred"),
                    "ENTRY_METADATA_INVALID" or "ENTRY_VERSION_AMBIGUOUS" or "ENTRY_VERSION_INVALID" => ("fail", "NOT_CHECKED"),
                    "ENTRY_LIMIT" or "ENTRY_NOT_MANAGED_UNSUPPORTED" or "ENTRY_MODULE_UNSUPPORTED" or "MIXED_MODE_UNSUPPORTED" or "ENTRY_MACHINE_UNSUPPORTED" or "ENTRY_VERSION_UNAVAILABLE" or "VERSION_UNSUPPORTED" or "LINK_UNSUPPORTED" or "NON_REGULAR_FILE" or "FILE_TYPE_UNAVAILABLE" => ("unsupported", "NOT_CHECKED"),
                    _ => ("invalid", "invalid")};
                if (outcome != expected.Item1 || arch != expected.Item2 || version != "NOT_CHECKED" || build != "NOT_CHECKED")
                    throw new Problem("WORKER_PROTOCOL");
            }

            return new(1, true, outcome, code, arch, version, build);
        }
        catch (Exception e)when (e is Problem or JsonException or InvalidOperationException or FormatException or OverflowException)
        {
            throw new Problem("WORKER_PROTOCOL");
        }
    }
}
