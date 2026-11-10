using System.Buffers.Binary;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ReleaseDoctor;
internal static class StaticChecks
{
    public static List<FrameworkRequirement> Runtime(byte[] bytes)
    {
        using var d = Contract.ParseJson(bytes);
        var options = Contract.Object(Contract.Required(d.RootElement, "runtimeOptions"));
        if (options.TryGetProperty("includedFrameworks", out _))
            throw new Problem("SELF_CONTAINED_UNSUPPORTED");
        bool one = options.TryGetProperty("framework", out var framework), many = options.TryGetProperty("frameworks", out var frameworks);
        if (one == many)
            throw new Problem("FRAMEWORK_DECLARATION_UNSUPPORTED");
        string policy = "host-default (not resolved)";
        if (options.TryGetProperty("rollForwardOnNoCandidateFx", out _))
            throw new Problem("LEGACY_ROLL_FORWARD_UNSUPPORTED");
        if (options.TryGetProperty("rollForward", out var roll))
        {
            policy = Contract.Text(roll);
            if (policy is not ("Disable" or "LatestPatch" or "Minor" or "LatestMinor" or "Major" or "LatestMajor"))
                throw new Problem("ROLL_FORWARD_UNSUPPORTED");
        }

        if (options.TryGetProperty("applyPatches", out var patches))
        {
            if (patches.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new Problem("JSON_SHAPE", true);
            policy += "; applyPatches=" + (patches.GetBoolean() ? "true" : "false");
        }

        List<JsonElement> entries = [];
        if (one)
            entries.Add(Contract.Object(framework));
        else
        {
            if (frameworks.ValueKind != JsonValueKind.Array || frameworks.GetArrayLength()is 0 or > 8)
                throw new Problem("FRAMEWORK_DECLARATION_UNSUPPORTED");
            entries.AddRange(frameworks.EnumerateArray());
        }

        List<FrameworkRequirement> result = [];
        HashSet<string> names = new(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            string name = Contract.Text(Contract.Required(entry, "name")), version = Contract.Text(Contract.Required(entry, "version"));
            if (name is not ("Microsoft.NETCore.App" or "Microsoft.AspNetCore.App"))
                throw new Problem("CUSTOM_FRAMEWORK_UNSUPPORTED");
            if (!names.Add(name))
                throw new Problem("DUPLICATE_FRAMEWORK", true);
            if (!Regex.IsMatch(version, @"\A[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}\z") || !Version.TryParse(version, out _))
                throw new Problem("FRAMEWORK_VERSION_UNSUPPORTED");
            result.Add(new(name, version, policy));
        }

        if (!names.Contains("Microsoft.NETCore.App"))
            throw new Problem("CORE_FRAMEWORK_REQUIRED");
        return result;
    }

    public static void Deps(byte[] bytes, string entry, string rid)
    {
        using var d = Contract.ParseJson(bytes);
        var root = Contract.Object(d.RootElement);
        string name = Contract.Text(Contract.Required(Contract.Required(root, "runtimeTarget"), "name"));
        if (!Regex.IsMatch(name, @"\A\.NETCoreApp,Version=v[0-9]{1,3}\.[0-9]{1,3}(?:/(?:win-x64|linux-x64))?\z"))
            throw new Problem("DEPS_TARGET_UNSUPPORTED");
        if (name.Contains('/') && name.Split('/')[1] != rid)
            throw new Problem("DEPS_RID_MISMATCH", true);
        var targets = Contract.Object(Contract.Required(root, "targets"));
        if (!targets.TryGetProperty(name, out var target))
            throw new Problem("DEPS_TARGET_MISSING", true);
        Contract.Object(target);
        Contract.Object(Contract.Required(root, "libraries"));
        bool found = false;
        foreach (var library in target.EnumerateObject())
        {
            Contract.Object(library.Value);
            if (library.Value.TryGetProperty("runtime", out var runtime))
            {
                Contract.Object(runtime);
                foreach (var asset in runtime.EnumerateObject())
                    if (asset.Name == Path.GetFileName(entry))
                        found = true; // Runtime asset is relative to its paired deps directory.
            }
        }

        if (!found)
            throw new Problem("ENTRY_RUNTIME_ASSET_MISSING", true);
    }

    public static int NativeHeaders(Snapshot snapshot, string rid)
    {
        int native = 0;
        foreach (var file in snapshot.Files.Values)
        {
            // Small fixed header inspection only; full bytes have separately been hashed.
            string full = Path.Combine(snapshot.Root, file.Path);
            Snapshot.NoLinks(full);
            Snapshot.RequireRegular(full);
            byte[] b = new byte[(int)Math.Min(file.Bytes, 4096)];
            using (var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read))
                stream.ReadExactly(b);
            if (b.Length >= 2 && b[0] == 'M' && b[1] == 'Z')
            {
                if (b.Length < 64)
                    throw new Problem("PE_HEADER_INVALID", true);
                int offset = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(60));
                if (offset < 64 || offset > 3072)
                    throw new Problem("PE_HEADER_UNSUPPORTED");
                if (offset + 24 > b.Length || !b.AsSpan(offset, 4).SequenceEqual("PE\0\0"u8))
                    throw new Problem("PE_HEADER_INVALID", true);
                ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(offset + 4));
                int optional = offset + 24;
                ushort size = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(offset + 20));
                if (size < 2 || optional + size > b.Length)
                    throw new Problem("PE_HEADER_INVALID", true);
                ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(optional));
                int numberOffset = magic == 0x10b ? 92 : magic == 0x20b ? 108 : -1;
                if (numberOffset < 0 || size < numberOffset + 4)
                    throw new Problem("PE_HEADER_INVALID", true);
                uint count = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(optional + numberOffset));
                bool managed = false;
                if (count > 14)
                {
                    int cor = optional + numberOffset + 4 + 14 * 8;
                    if (cor + 8 > optional + size)
                        throw new Problem("PE_HEADER_INVALID", true);
                    managed = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(cor)) != 0;
                }

                if (managed)
                    continue; // Only entry managed metadata is validated by the owned worker.
                native++;
                if (rid != "win-x64" || machine != 0x8664 || magic != 0x20b)
                    throw new Problem("NATIVE_RID_MISMATCH", true);
            }
            else if (b.Length >= 4 && b.AsSpan(0, 4).SequenceEqual("\u007fELF"u8))
            {
                if (b.Length < 64 || b[4] is not (1 or 2) || b[5] is not (1 or 2) || b[6] != 1)
                    throw new Problem("ELF_HEADER_INVALID", true);
                ushort U16(int offset) => b[5] == 1 ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(offset)) : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(offset));
                uint version = b[5] == 1 ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(20)) : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(20));
                if (U16(16)is not (2 or 3) || version != 1 || U16(b[4] == 2 ? 52 : 40) != (b[4] == 2 ? 64 : 52))
                    throw new Problem("ELF_HEADER_INVALID", true);
                ushort machine = U16(18);
                native++;
                if (rid != "linux-x64" || b[4] != 2 || b[5] != 1 || machine != 62)
                    throw new Problem("NATIVE_RID_MISMATCH", true);
            }
        }

        return native;
    }

    public static void Inventory(Snapshot snapshot, string selected, string expectedVersion, string rid)
    {
        if (selected.Contains('/'))
            throw new Problem("MANIFEST_NAME_UNSUPPORTED");
        Contract.Relative(selected);
        using var d = Contract.ParseJson(snapshot.ReadSmall(selected));
        var root = Contract.Object(d.RootElement);
        if (root.TryGetProperty("version", out var version) && Contract.ReleasePart(Contract.Text(version)) != expectedVersion)
            throw new Problem("MANIFEST_VERSION_MISMATCH", true);
        if (root.TryGetProperty("rid", out var declared) && Contract.Text(declared) != rid)
            throw new Problem("MANIFEST_RID_MISMATCH", true);
        var files = Contract.Required(root, "files");
        if (files.ValueKind != JsonValueKind.Array || files.GetArrayLength() > 512)
            throw new Problem("MANIFEST_SHAPE", true);
        HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> exact = new(StringComparer.Ordinal);
        foreach (var item in files.EnumerateArray())
        {
            string path = Contract.Relative(Contract.Text(Contract.Required(item, "path")));
            if (!paths.Add(path))
                throw new Problem("MANIFEST_DUPLICATE_PATH", true);
            if (path == selected)
                throw new Problem("MANIFEST_SELF_REFERENCE", true);
            string hash = Contract.Text(Contract.Required(item, "sha256"));
            var size = Contract.Required(item, "bytes");
            if (size.ValueKind != JsonValueKind.Number || !size.TryGetInt64(out long count) || count < 0 || !Regex.IsMatch(hash, @"\A[0-9a-f]{64}\z"))
                throw new Problem("MANIFEST_SHAPE", true);
            if (!snapshot.Files.TryGetValue(path, out var actual) || actual.Bytes != count || actual.Sha256 != hash)
                throw new Problem("INVENTORY_MISMATCH", true);
            exact.Add(path);
        }

        if (!exact.SetEquals(snapshot.Files.Keys.Where(p => p != selected)))
            throw new Problem("INVENTORY_MISMATCH", true);
    }
}
