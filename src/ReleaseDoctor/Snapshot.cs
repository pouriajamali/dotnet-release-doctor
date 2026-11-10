using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ReleaseDoctor;
internal sealed record FileEntry(string Path, long Bytes, string Sha256, long ModifiedTicks);
internal sealed class Snapshot
{
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(0)]
        public uint Mask;
        [FieldOffset(28)]
        public ushort Mode;
    }

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int LinuxStatx(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out Statx result);
    internal static void RequireRegular(string path)
    {
        if (!OperatingSystem.IsLinux())
            return;
        // Linux's stable statx ABI: request type, do not follow a final symlink.
        // Ubuntu24.04/glibc x64 only; unavailable type inspection is incomplete.
        if (LinuxStatx(-100, path, 0x100, 1, out var result) != 0 || (result.Mask & 1) == 0)
            throw new Problem("FILE_TYPE_UNAVAILABLE");
        if ((result.Mode & 0xf000) != 0x8000)
            throw new Problem("NON_REGULAR_FILE");
    }

    public const long FileLimit = 64L * 1024 * 1024, TotalLimit = 256L * 1024 * 1024;
    public const int EntryLimit = 512;
    public required string Root { get; init; }
    public Dictionary<string, FileEntry> Files { get; } = new(StringComparer.Ordinal);
    public long Bytes { get; private set; }

    public static string Normalize(string path)
    {
        string full = Path.GetFullPath(path);
        if (path.StartsWith("//") || path.StartsWith(@"\\") || full.StartsWith(@"\\"))
            throw new Problem("NETWORK_PATH_UNSUPPORTED");
        if (OperatingSystem.IsWindows() && new DriveInfo(Path.GetPathRoot(full)!).DriveType == DriveType.Network)
            throw new Problem("NETWORK_PATH_UNSUPPORTED");
        NoLinks(full);
        return Path.TrimEndingDirectorySeparator(full);
    }

    public static void NoLinks(string path)
    {
        string? p = Path.GetFullPath(path);
        while (p != null)
        {
            FileSystemInfo f = Directory.Exists(p) ? new DirectoryInfo(p) : new FileInfo(p);
            if (f.LinkTarget != null || (f.Exists && (f.Attributes & FileAttributes.ReparsePoint) != 0))
                throw new Problem("LINK_UNSUPPORTED");
            p = Path.GetDirectoryName(p);
        }
    }

    public static bool Nested(string a, string b)
    {
        a = Path.TrimEndingDirectorySeparator(a);
        b = Path.TrimEndingDirectorySeparator(b);
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        string prefix = Path.EndsInDirectorySeparator(b) ? b : b + Path.DirectorySeparatorChar;
        return a.Equals(b, comparison) || a.StartsWith(prefix, comparison);
    }

    public static Snapshot Capture(string root)
    {
        NoLinks(root);
        if (!Directory.Exists(root))
            throw new Problem("INPUT_DIRECTORY_REQUIRED");
        Snapshot result = new()
        {
            Root = root
        };
        HashSet<string> collision = new(StringComparer.OrdinalIgnoreCase);
        int entries = 0;
        void Walk(string directory, int depth)
        {
            if (depth > 16)
                throw new Problem("DEPTH_LIMIT");
            foreach (string path in Directory.EnumerateFileSystemEntries(directory))
            {
                if (++entries > EntryLimit)
                    throw new Problem("ENTRY_LIMIT");
                NoLinks(path);
                string relative = Contract.Relative(Path.GetRelativePath(root, path).Replace('\\', '/'));
                if (!collision.Add(relative))
                    throw new Problem("CASE_COLLISION");
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Walk(path, depth + 1);
                    continue;
                }

                if ((attributes & (FileAttributes.Device | FileAttributes.ReparsePoint)) != 0)
                    throw new Problem("NON_REGULAR_FILE");
                var file = ReadFile(path, relative, TotalLimit - result.Bytes);
                result.Bytes += file.Bytes;
                result.Files.Add(relative, file);
            }
        }

        Walk(root, 0);
        if (result.Files.Count == 0)
            throw new Problem("EMPTY_DIRECTORY");
        return result;
    }

    private static FileEntry ReadFile(string full, string relative, long remaining)
    {
        NoLinks(full);
        RequireRegular(full);
        FileInfo before = new(full);
        long length = before.Length, ticks = before.LastWriteTimeUtc.Ticks;
        if (length > FileLimit || length > remaining)
            throw new Problem("BYTE_LIMIT");
        using FileStream stream = new(full, FileMode.Open, FileAccess.Read, FileShare.Read);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[65536];
        long total = 0;
        int n;
        while ((n = stream.Read(buffer)) > 0)
        {
            total += n;
            if (total > FileLimit || total > remaining)
                throw new Problem("BYTE_LIMIT");
            hash.AppendData(buffer, 0, n);
        }

        FileInfo after = new(full);
        NoLinks(full);
        if (total != length || after.Length != length || after.LastWriteTimeUtc.Ticks != ticks)
            throw new Problem("INPUT_CHANGED");
        return new(relative, total, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(), ticks);
    }

    public byte[] ReadSmall(string relative, int cap = 4 * 1024 * 1024)
    {
        if (!Files.TryGetValue(relative, out var expected))
            throw new Problem("REQUIRED_METADATA_UNAVAILABLE");
        if (expected.Bytes > cap)
            throw new Problem("JSON_LIMIT");
        string path = Path.Combine(Root, relative);
        NoLinks(path);
        RequireRegular(path);
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using MemoryStream memory = new();
        byte[] b = new byte[65536];
        int n;
        while ((n = stream.Read(b)) > 0)
        {
            if (memory.Length + n > cap)
                throw new Problem("JSON_LIMIT");
            memory.Write(b, 0, n);
        }

        byte[] bytes = memory.ToArray();
        NoLinks(path);
        if (bytes.LongLength != expected.Bytes || Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() != expected.Sha256)
            throw new Problem("INPUT_CHANGED");
        return bytes;
    }

    public void Recheck()
    {
        Snapshot after = Capture(Root);
        if (after.Files.Count != Files.Count || after.Bytes != Bytes || Files.Any(p => !after.Files.TryGetValue(p.Key, out var f) || f != p.Value))
            throw new Problem("INPUT_CHANGED");
    }
}
