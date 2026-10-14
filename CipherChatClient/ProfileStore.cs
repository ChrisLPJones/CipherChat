using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CipherChatClient;

public enum ProfileError { Exists, Missing, WrongPassphrase, Corrupt, WeakPassphrase }

public sealed class ProfileException : Exception
{
    public ProfileError Error { get; }
    public ProfileException(ProfileError error, string message) : base(message) { Error = error; }
}

public sealed class PeerRecord
{
    public string User { get; set; }
    public string Pub { get; set; }          // Base64 of the 65-byte identity key
    public long FirstSeen { get; set; }      // unix seconds
    public bool Verified { get; set; }
    public bool Blocked { get; set; }
}

// Pinned peer keys (TOFU), verification and block state. Persisted encrypted in peers.dat.
public sealed class PeerBook
{
    private readonly Dictionary<string, PeerRecord> peers = new();
    private readonly Action save;

    internal PeerBook(IEnumerable<PeerRecord> records, Action save)
    {
        foreach (PeerRecord r in records) peers[r.User] = r;
        this.save = save;
    }

    public IReadOnlyCollection<PeerRecord> All => peers.Values.ToList();
    public PeerRecord Get(string user) => peers.TryGetValue(user, out PeerRecord r) ? Copy(r) : null;

    // Pins a key for a user. An already pinned user keeps the old key unless replace is true
    // (replace resets the verified flag and keeps the block flag).
    public PeerRecord Pin(string user, byte[] pub, long nowSeconds, bool replace = false)
    {
        if (!Proto.IsUserName(user) || !IdentityKey.IsValidPublicKey(pub)) throw new ArgumentException("Invalid peer.");
        string b64 = Convert.ToBase64String(pub);
        if (peers.TryGetValue(user, out PeerRecord existing))
        {
            if (existing.Pub == b64) return Copy(existing);
            if (existing.Pub == null) { existing.Pub = b64; existing.FirstSeen = nowSeconds; save(); return Copy(existing); }
            if (!replace) throw new InvalidOperationException("The user already has a different pinned key.");
            existing.Pub = b64; existing.Verified = false; existing.FirstSeen = nowSeconds;
        }
        else peers[user] = new PeerRecord { User = user, Pub = b64, FirstSeen = nowSeconds };
        save();
        return Copy(peers[user]);
    }

    public void SetVerified(string user, bool verified) => Update(user, r => r.Verified = verified);
    public void SetBlocked(string user, bool blocked)
    {
        if (!Proto.IsUserName(user)) throw new ArgumentException("Invalid user name.");
        if (!peers.ContainsKey(user)) { peers[user] = new PeerRecord { User = user, Pub = null }; }
        Update(user, r => r.Blocked = blocked);
    }
    public bool IsBlocked(string user) => peers.TryGetValue(user, out PeerRecord r) && r.Blocked;
    public byte[] GetKey(string user) => peers.TryGetValue(user, out PeerRecord r) && r.Pub != null ? Convert.FromBase64String(r.Pub) : null;

    private void Update(string user, Action<PeerRecord> change)
    {
        if (!peers.TryGetValue(user, out PeerRecord r)) throw new KeyNotFoundException("Unknown peer.");
        change(r);
        save();
    }

    private static PeerRecord Copy(PeerRecord r) => new() { User = r.User, Pub = r.Pub, FirstSeen = r.FirstSeen, Verified = r.Verified, Blocked = r.Blocked };
}

// One unlocked profile (identity key + peer book) for a (user, server) pair.
public sealed class Profile : IDisposable
{
    public IdentityKey Identity { get; }
    public PeerBook Peers { get; }
    public string Directory { get; }
    private readonly byte[] peersKey;

    internal Profile(IdentityKey identity, PeerBook peers, string directory, byte[] peersKey)
    {
        Identity = identity; Peers = peers; Directory = directory; this.peersKey = peersKey;
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(peersKey);
        Identity.Dispose();
    }
}

// Local profile directory: <base>/profiles/<user>@<host>-<port>/ with identity.p8 (encrypted PKCS#8) and
// peers.dat (AES-256-GCM under a key derived from the identity private scalar). Directories 0700 and files
// 0600 on Unix (Windows relies on the per-user AppData ACL). No messages are ever written to disk.
public sealed class ProfileStore
{
    public const int MinPassphraseLength = 8;
    public const byte PeersVersion = 0x04;
    private const string IdentityFile = "identity.p8";
    private const string PeersFile = "peers.dat";
    private const int MaxHostChars = 100;

    private static readonly UnixFileMode DirMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private static readonly UnixFileMode FileMode_ = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public string BaseDirectory { get; }

    // baseDirectory null: CIPHERCHAT_HOME if set, otherwise ApplicationData/CipherChat.
    public ProfileStore(string baseDirectory = null)
    {
        if (string.IsNullOrEmpty(baseDirectory))
        {
            string env = Environment.GetEnvironmentVariable("CIPHERCHAT_HOME");
            baseDirectory = !string.IsNullOrEmpty(env)
                ? env
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CipherChat");
        }
        BaseDirectory = Path.GetFullPath(baseDirectory);
    }

    // Host mapped to [a-z0-9.-]; anything else becomes '_'. Bounded length.
    public static string SanitizeHost(string host)
    {
        if (string.IsNullOrEmpty(host)) return "_";
        StringBuilder sb = new();
        foreach (char c in host.ToLowerInvariant())
        {
            if (sb.Length >= MaxHostChars) break;
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
            sb.Append(ok ? c : '_');
        }
        return sb.ToString();
    }

    public static string ProfileLabel(string user, string host, int port)
    {
        if (!Proto.IsUserName(user)) throw new ArgumentException("Invalid user name.");
        if (port < 1 || port > 65535) throw new ArgumentException("Invalid port.");
        return $"{user}@{SanitizeHost(host)}-{port}";
    }

    public string ProfilePath(string user, string host, int port)
    {
        string profiles = Path.Combine(BaseDirectory, "profiles");
        string path = Path.GetFullPath(Path.Combine(profiles, ProfileLabel(user, host, port)));
        // Defence in depth: the label has no separators, but never leave the profiles directory.
        if (!path.StartsWith(profiles + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArgumentException("Invalid profile path.");
        return path;
    }

    public bool Exists(string user, string host, int port) => File.Exists(Path.Combine(ProfilePath(user, host, port), IdentityFile));

    public Profile Create(string user, string host, int port, string passphrase)
    {
        if (passphrase == null || passphrase.Length < MinPassphraseLength)
            throw new ProfileException(ProfileError.WeakPassphrase, $"The passphrase must be at least {MinPassphraseLength} characters.");
        string dir = ProfilePath(user, host, port);
        if (File.Exists(Path.Combine(dir, IdentityFile))) throw new ProfileException(ProfileError.Exists, "A profile already exists for this user and server.");
        EnsureDirectory(BaseDirectory);
        EnsureDirectory(Path.Combine(BaseDirectory, "profiles"));
        EnsureDirectory(dir);

        IdentityKey identity = IdentityKey.Generate();
        byte[] peersKey = null;
        try
        {
            WriteAtomic(Path.Combine(dir, IdentityFile), identity.ExportEncrypted(passphrase));
            peersKey = DerivePeersKey(identity);
            string label = ProfileLabel(user, host, port);
            Profile p = Build(identity, new List<PeerRecord>(), dir, label, peersKey);
            WritePeers(dir, label, peersKey, new List<PeerRecord>());
            return p;
        }
        catch
        {
            if (peersKey != null) CryptographicOperations.ZeroMemory(peersKey);
            identity.Dispose();
            throw;
        }
    }

    public Profile Unlock(string user, string host, int port, string passphrase)
    {
        string dir = ProfilePath(user, host, port);
        string idPath = Path.Combine(dir, IdentityFile);
        if (!File.Exists(idPath)) throw new ProfileException(ProfileError.Missing, "No profile exists for this user and server.");
        IdentityKey identity;
        try { identity = IdentityKey.LoadEncrypted(File.ReadAllBytes(idPath), passphrase ?? ""); }
        catch (CryptographicException) { throw new ProfileException(ProfileError.WrongPassphrase, "Wrong passphrase, or the key file is damaged."); }

        byte[] peersKey = DerivePeersKey(identity);
        try
        {
            string label = ProfileLabel(user, host, port);
            List<PeerRecord> records = ReadPeers(dir, label, peersKey);
            return Build(identity, records, dir, label, peersKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(peersKey);
            identity.Dispose();
            throw;
        }
    }

    private static Profile Build(IdentityKey identity, List<PeerRecord> records, string dir, string label, byte[] peersKey)
    {
        PeerBook book = null;
        book = new PeerBook(records, () => WritePeers(dir, label, peersKey, book.All.ToList()));
        return new Profile(identity, book, dir, peersKey);
    }

    private static byte[] DerivePeersKey(IdentityKey identity)
    {
        byte[] d = identity.ExportPrivateScalar();
        try { return HKDF.DeriveKey(HashAlgorithmName.SHA256, d, 32, Proto.Label("CipherChat-v4/local"), Proto.Label("peers")); }
        finally { CryptographicOperations.ZeroMemory(d); }
    }

    private static byte[] PeersAad(string label) => Proto.Concat(Proto.Label("CipherChat-v4/peers"), Proto.Lp(label));

    private static void WritePeers(string dir, string label, byte[] key, List<PeerRecord> records)
    {
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(records);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] file = new byte[1 + 12 + plain.Length + 16];
        file[0] = PeersVersion;
        nonce.CopyTo(file, 1);
        try
        {
            using AesGcm gcm = new(key, 16);
            gcm.Encrypt(nonce, plain, file.AsSpan(13, plain.Length), file.AsSpan(13 + plain.Length, 16), PeersAad(label));
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
        WriteAtomic(Path.Combine(dir, PeersFile), file);
    }

    private static List<PeerRecord> ReadPeers(string dir, string label, byte[] key)
    {
        string path = Path.Combine(dir, PeersFile);
        if (!File.Exists(path)) throw new ProfileException(ProfileError.Corrupt, "peers.dat is missing; refusing to start (the pinned keys would be lost).");
        byte[] file = File.ReadAllBytes(path);
        if (file.Length < 1 + 12 + 16 || file[0] != PeersVersion) throw new ProfileException(ProfileError.Corrupt, "peers.dat is damaged or has an unknown version.");
        int ctLen = file.Length - 1 - 12 - 16;
        byte[] plain = new byte[ctLen];
        try
        {
            using AesGcm gcm = new(key, 16);
            gcm.Decrypt(file.AsSpan(1, 12), file.AsSpan(13, ctLen), file.AsSpan(13 + ctLen, 16), plain, PeersAad(label));
            List<PeerRecord> records = JsonSerializer.Deserialize<List<PeerRecord>>(plain);
            if (records == null) throw new ProfileException(ProfileError.Corrupt, "peers.dat is damaged.");
            HashSet<string> seen = new();
            foreach (PeerRecord r in records)
            {
                if (r == null || !Proto.IsUserName(r.User)) throw new ProfileException(ProfileError.Corrupt, "peers.dat contains invalid entries.");
                bool keyOk = r.Pub == null || (TryDecode(r.Pub, out byte[] pub) && IdentityKey.IsValidPublicKey(pub));
                if (!keyOk || !seen.Add(r.User))
                    throw new ProfileException(ProfileError.Corrupt, "peers.dat contains invalid entries.");
            }
            return records;
        }
        catch (CryptographicException) { throw new ProfileException(ProfileError.Corrupt, "peers.dat was modified or is damaged; refusing to start."); }
        catch (JsonException) { throw new ProfileException(ProfileError.Corrupt, "peers.dat is damaged."); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private static bool TryDecode(string b64, out byte[] bytes)
    {
        bytes = null;
        try { bytes = Convert.FromBase64String(b64); return true; }
        catch (FormatException) { return false; }
    }

    private static void EnsureDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
            else Directory.CreateDirectory(path, DirMode);
        }
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, DirMode);
    }

    // Temp file (created 0600) + rename, so a crash never leaves a half-written file.
    private static void WriteAtomic(string path, byte[] content)
    {
        string tmp = path + "." + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)) + ".tmp";
        FileStreamOptions opts = new() { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) opts.UnixCreateMode = FileMode_;
        try
        {
            using (FileStream fs = new(tmp, opts))
            {
                fs.Write(content);
                fs.Flush(true);
            }
            File.Move(tmp, path, true);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, FileMode_);
        }
        catch
        {
            try { File.Delete(tmp); } catch (IOException) { }
            throw;
        }
    }
}
