using System.Globalization;

namespace CipherChatServer;

// user -> identity public key, kept for good. File: <dataDir>/accounts.txt, one line per account:
// "<user> <pubBase64> <unixSeconds>". Strict parse on load (a bad file stops the server instead of
// silently dropping accounts). Appended and flushed; directory 0700, file 0600. Without a directory
// accounts live in memory only (tests and dev).
public sealed class AccountStore
{
    private static readonly UnixFileMode DirMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private static readonly UnixFileMode FileMode_ = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly object gate = new();
    private readonly Dictionary<string, string> accounts = new();
    private readonly string path;

    public bool Persistent => path != null;

    public AccountStore(string dataDirectory)
    {
        if (dataDirectory == null) return;
        if (!Directory.Exists(dataDirectory))
        {
            if (OperatingSystem.IsWindows()) Directory.CreateDirectory(dataDirectory);
            else Directory.CreateDirectory(dataDirectory, DirMode);
        }
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(dataDirectory, DirMode);
        path = Path.Combine(dataDirectory, "accounts.txt");
        if (!File.Exists(path)) return;
        foreach (string line in File.ReadAllLines(path))
        {
            string[] t = line.Split(' ');
            if (t.Length != 3 || !ServerFrame.IsUser(t[0]) || !ServerFrame.IsBase64Bytes(t[1], AuthVerifier.PublicKeyBytes)
                || t[2].Length is < 1 or > 18 || !t[2].All(char.IsAsciiDigit)
                || !AuthVerifier.IsValidPublicKey(Convert.FromBase64String(t[1])) || !accounts.TryAdd(t[0], t[1]))
                throw new InvalidDataException("accounts.txt is damaged.");
        }
    }

    public int Count { get { lock (gate) return accounts.Count; } }

    public bool TryGet(string user, out byte[] pub)
    {
        lock (gate)
        {
            if (accounts.TryGetValue(user, out string b64)) { pub = Convert.FromBase64String(b64); return true; }
        }
        pub = null;
        return false;
    }

    // False when the name is taken. Throws IOException when it cannot be saved (the account is then not added).
    public bool TryAdd(string user, byte[] pub, long unixSeconds)
    {
        string b64 = Convert.ToBase64String(pub);
        lock (gate)
        {
            if (accounts.ContainsKey(user)) return false;
            if (path != null) Append($"{user} {b64} {unixSeconds.ToString(CultureInfo.InvariantCulture)}\n");
            accounts[user] = b64;
            return true;
        }
    }

    private void Append(string text)
    {
        FileStreamOptions opts = new() { Mode = FileMode.Append, Access = FileAccess.Write, Share = FileShare.Read };
        if (!OperatingSystem.IsWindows()) opts.UnixCreateMode = FileMode_;
        using FileStream fs = new(path, opts);
        byte[] b = System.Text.Encoding.ASCII.GetBytes(text);
        fs.Write(b);
        fs.Flush(true);
    }
}
