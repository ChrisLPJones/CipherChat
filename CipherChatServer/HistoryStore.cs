using System.Security.Cryptography;
using System.Text;

namespace CipherChatServer;

// One retained message: the opaque client ciphertext, never decrypted here.
public readonly record struct HistoryRecord(long Id, long UnixMillis, string Payload);

// Opt-in per-channel message history on disk. The server stores only the opaque payloads the clients
// produced (AES-256-GCM under keys the server never has), so "encrypted at rest" holds by construction.
// File per channel: <dir>/<hex SHA-256(tag)>.log, lines "<id> <unixMillis> <payload>", append-only,
// trimmed by rewrite-to-temp + rename. The raw tag is never used as a path or logged. All members are
// thread-safe (one lock); callers must pass grammar-validated tags (checked again here).
public sealed class HistoryStore
{
    private readonly string directory;
    private readonly int max;
    private readonly int slack;
    private readonly object sync = new();
    // tag hash -> (head id, record count on disk); filled lazily, only for channels that have a file
    private readonly Dictionary<string, Meta> meta = [];

    private sealed class Meta { public long Head; public int Count; }

    private static readonly UnixFileMode FileMode600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly UnixFileMode DirMode700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    public HistoryStore(string directory, int maxPerChannel)
    {
        if (string.IsNullOrWhiteSpace(directory)) throw new ArgumentException("A history directory is required.", nameof(directory));
        if (maxPerChannel < 1) throw new ArgumentOutOfRangeException(nameof(maxPerChannel));
        this.directory = Path.GetFullPath(directory);
        max = maxPerChannel;
        // Hysteresis: trim only when 10% over the cap so a full channel does not rewrite its file on every message.
        // Reads never serve more than the cap.
        slack = Math.Max(1, maxPerChannel / 10);
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(this.directory);
        else Directory.CreateDirectory(this.directory, DirMode700);
    }

    // The file name for a tag: hex SHA-256 of the (validated) tag, never the tag itself.
    public static string FileNameFor(string tag)
    {
        if (!ServerFrame.IsTag(tag)) throw new ArgumentException("Not a valid channel tag.", nameof(tag));
        return Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(tag))).ToLowerInvariant() + ".log";
    }

    private string PathFor(string tag) => Path.Combine(directory, FileNameFor(tag));

    // Highest id ever stored for the channel (0 if none). Lets ids continue after a restart or an empty-channel drop.
    public long Head(string tag)
    {
        lock (sync) return GetMeta(tag, create: false)?.Head ?? 0;
    }

    // Appends one record. The caller assigns the id (must be greater than the current head).
    public void Append(string tag, long id, long unixMillis, string payload)
    {
        if (!ServerFrame.IsBase64(payload, ProtocolLimits.MinPayloadChars, ProtocolLimits.MaxPayloadChars))
            throw new ArgumentException("Not a valid payload.", nameof(payload));
        lock (sync)
        {
            string path = PathFor(tag);
            Meta m = GetMeta(tag, create: true);
            if (id <= m.Head) throw new ArgumentException("Ids must increase.", nameof(id));

            byte[] line = Encoding.ASCII.GetBytes($"{id} {unixMillis} {payload}\n");
            using (FileStream fs = Open(path, FileMode.Append))
            {
                fs.Write(line, 0, line.Length);
                fs.Flush(true);
            }
            m.Head = id;
            m.Count++;

            if (m.Count > max + slack)
            {
                List<HistoryRecord> all = LoadFile(path, out _);
                Rewrite(path, all.Skip(Math.Max(0, all.Count - max)).ToList());
                m.Count = Math.Min(all.Count, max);
            }
        }
    }

    // The last `count` records with id > afterId, oldest first (never more than the retention cap).
    public List<HistoryRecord> Read(string tag, long afterId, int count)
    {
        lock (sync)
        {
            string path = PathFor(tag);
            if (!File.Exists(path)) return [];
            List<HistoryRecord> all = LoadFile(path, out _);
            var after = all.Where(r => r.Id > afterId).ToList();
            int take = Math.Min(Math.Min(count, max), after.Count);
            return after.GetRange(after.Count - take, take);
        }
    }

    // Caller holds sync. Returns cached meta, loading (and repairing) the file on first use.
    private Meta GetMeta(string tag, bool create)
    {
        string hash = FileNameFor(tag);
        if (meta.TryGetValue(hash, out Meta m)) return m;
        string path = Path.Combine(directory, hash);
        if (!File.Exists(path))
        {
            if (!create) return null;
            return meta[hash] = new Meta();
        }
        List<HistoryRecord> records = LoadFile(path, out bool damaged);
        if (damaged) Rewrite(path, records); // drop corrupt/truncated lines so appends start on a clean line
        m = new Meta { Head = records.Count == 0 ? 0 : records[^1].Id, Count = records.Count };
        meta[hash] = m;
        return m;
    }

    // Parses a file leniently: invalid lines (bad grammar, over-long, non-increasing id, a final line
    // without newline) are skipped. Never buffers more than one bounded line at a time.
    private static List<HistoryRecord> LoadFile(string path, out bool damaged)
    {
        damaged = false;
        var result = new List<HistoryRecord>();
        long lastId = 0;
        // Longest valid line: id (18) + space + millis (18) + space + payload
        int maxLine = 18 + 1 + 18 + 1 + ProtocolLimits.MaxPayloadChars;

        using FileStream fs = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new BufferedStream(fs, 64 * 1024);
        var sb = new StringBuilder();
        bool overflow = false;
        int b;
        while ((b = reader.ReadByte()) >= 0)
        {
            if (b == '\n')
            {
                if (overflow || !TryParseLine(sb.ToString(), lastId, out HistoryRecord rec)) damaged = true;
                else { result.Add(rec); lastId = rec.Id; }
                sb.Clear();
                overflow = false;
                continue;
            }
            if (overflow) continue;
            if (sb.Length >= maxLine) { overflow = true; sb.Clear(); continue; }
            sb.Append((char)b);
        }
        if (sb.Length > 0 || overflow) damaged = true; // truncated last line (no newline): ignored
        return result;
    }

    private static bool TryParseLine(string line, long lastId, out HistoryRecord rec)
    {
        rec = default;
        string[] t = line.Split(' ');
        if (t.Length != 3) return false;
        if (!ServerFrame.TryParseId(t[0], out long id) || id <= lastId) return false;
        if (!ServerFrame.TryParseId(t[1], out long ms)) return false;
        if (!ServerFrame.IsBase64(t[2], ProtocolLimits.MinPayloadChars, ProtocolLimits.MaxPayloadChars)) return false;
        rec = new HistoryRecord(id, ms, t[2]);
        return true;
    }

    // Caller holds sync. Replaces the file atomically with exactly these records.
    private static void Rewrite(string path, List<HistoryRecord> records)
    {
        string temp = path + ".tmp";
        using (FileStream fs = Open(temp, FileMode.Create))
        {
            foreach (HistoryRecord r in records)
            {
                byte[] line = Encoding.ASCII.GetBytes($"{r.Id} {r.UnixMillis} {r.Payload}\n");
                fs.Write(line, 0, line.Length);
            }
            fs.Flush(true);
        }
        File.Move(temp, path, overwrite: true);
    }

    private static FileStream Open(string path, FileMode mode)
    {
        var options = new FileStreamOptions { Mode = mode, Access = FileAccess.Write, Share = FileShare.Read };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = FileMode600;
        return new FileStream(path, options);
    }
}
