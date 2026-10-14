using System.Security.Cryptography;
using System.Text;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "cipherchat-test-" + Guid.NewGuid().ToString("N"));
    public TempDir() { Directory.CreateDirectory(Path); }
    public void Dispose() { try { Directory.Delete(Path, true); } catch (IOException) { } }
}

public class ProfileStoreTests : IDisposable
{
    private readonly TempDir tmp = new();
    private ProfileStore Store => new(tmp.Path);
    private const string Pass = "correct horse";

    public void Dispose() => tmp.Dispose();

    private static byte[] PeerKey()
    {
        using IdentityKey k = IdentityKey.Generate();
        return k.PublicKey;
    }

    [Fact]
    public void CreateThenUnlock_RoundTrips_AndKeepsPeers()
    {
        byte[] bobKey = PeerKey();
        byte[] pub;
        using (Profile p = Store.Create("alice", "localhost", 3000, Pass))
        {
            pub = p.Identity.PublicKey;
            p.Peers.Pin("bob", bobKey, 1000);
            p.Peers.SetVerified("bob", true);
            p.Peers.SetBlocked("carol", true);
        }
        Assert.True(Store.Exists("alice", "localhost", 3000));
        Assert.False(Store.Exists("alice", "localhost", 3001));
        using Profile again = Store.Unlock("alice", "localhost", 3000, Pass);
        Assert.Equal(pub, again.Identity.PublicKey);
        PeerRecord bob = again.Peers.Get("bob");
        Assert.Equal((true, false, 1000L), (bob.Verified, bob.Blocked, bob.FirstSeen));
        Assert.Equal(bobKey, again.Peers.GetKey("bob"));
        Assert.True(again.Peers.IsBlocked("carol"));
        Assert.Null(again.Peers.GetKey("carol"));
        Assert.Null(again.Peers.Get("dave"));
    }

    [Fact]
    public void WrongPassphrase_AndMissingProfile_AndWeakPassphrase_AreErrors()
    {
        Store.Create("alice", "h", 1, Pass).Dispose();
        Assert.Equal(ProfileError.WrongPassphrase, Assert.Throws<ProfileException>(() => Store.Unlock("alice", "h", 1, "not the passphrase")).Error);
        Assert.Equal(ProfileError.WrongPassphrase, Assert.Throws<ProfileException>(() => Store.Unlock("alice", "h", 1, null)).Error);
        Assert.Equal(ProfileError.Missing, Assert.Throws<ProfileException>(() => Store.Unlock("bob", "h", 1, Pass)).Error);
        Assert.Equal(ProfileError.WeakPassphrase, Assert.Throws<ProfileException>(() => Store.Create("bob", "h", 1, "short")).Error);
        Assert.Equal(ProfileError.Exists, Assert.Throws<ProfileException>(() => Store.Create("alice", "h", 1, Pass)).Error);
        Assert.False(Store.Exists("bob", "h", 1));
    }

    [Fact]
    public void FileModes_AreOwnerOnly()
    {
        if (OperatingSystem.IsWindows()) return;
        using Profile p = Store.Create("alice", "h", 1, Pass);
        p.Peers.Pin("bob", PeerKey(), 5);
        UnixFileMode dir = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        UnixFileMode file = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        Assert.Equal(dir, File.GetUnixFileMode(tmp.Path));
        Assert.Equal(dir, File.GetUnixFileMode(Path.Combine(tmp.Path, "profiles")));
        Assert.Equal(dir, File.GetUnixFileMode(p.Directory));
        Assert.Equal(file, File.GetUnixFileMode(Path.Combine(p.Directory, "identity.p8")));
        Assert.Equal(file, File.GetUnixFileMode(Path.Combine(p.Directory, "peers.dat")));
        Assert.Empty(Directory.GetFiles(p.Directory, "*.tmp")); // atomic writes leave no temp files
        Assert.Equal(2, Directory.GetFiles(p.Directory).Length);
    }

    [Fact]
    public void PeersDat_TamperAndTruncationAndMissing_RefuseToStart()
    {
        using (Profile p = Store.Create("alice", "h", 1, Pass)) p.Peers.Pin("bob", PeerKey(), 5);
        string path = Path.Combine(Store.ProfilePath("alice", "h", 1), "peers.dat");
        byte[] good = File.ReadAllBytes(path);

        for (int i = 0; i < good.Length; i += 7)
        {
            byte[] bad = (byte[])good.Clone();
            bad[i] ^= 1;
            File.WriteAllBytes(path, bad);
            Assert.Equal(ProfileError.Corrupt, Assert.Throws<ProfileException>(() => Store.Unlock("alice", "h", 1, Pass)).Error);
        }
        File.WriteAllBytes(path, good[..^1]);
        Assert.Equal(ProfileError.Corrupt, Assert.Throws<ProfileException>(() => Store.Unlock("alice", "h", 1, Pass)).Error);
        File.WriteAllBytes(path, good[..10]);
        Assert.Equal(ProfileError.Corrupt, Assert.Throws<ProfileException>(() => Store.Unlock("alice", "h", 1, Pass)).Error);
        File.Delete(path);
        Assert.Equal(ProfileError.Corrupt, Assert.Throws<ProfileException>(() => Store.Unlock("alice", "h", 1, Pass)).Error);
        File.WriteAllBytes(path, good);
        Store.Unlock("alice", "h", 1, Pass).Dispose();
    }

    [Fact]
    public void PeersDat_CannotBeSwappedBetweenProfiles()
    {
        // Same identity key file copied under another label: the AAD binds the profile label.
        using (Profile p = Store.Create("alice", "h", 1, Pass)) p.Peers.Pin("bob", PeerKey(), 5);
        string src = Store.ProfilePath("alice", "h", 1);
        string dst = Store.ProfilePath("alice", "h", 2);
        Directory.CreateDirectory(dst);
        File.Copy(Path.Combine(src, "identity.p8"), Path.Combine(dst, "identity.p8"));
        File.Copy(Path.Combine(src, "peers.dat"), Path.Combine(dst, "peers.dat"));
        Assert.Equal(ProfileError.Corrupt, Assert.Throws<ProfileException>(() => Store.Unlock("alice", "h", 2, Pass)).Error);
    }

    [Fact]
    public void Files_DoNotContainPlaintextNamesOrKeys()
    {
        byte[] bobKey = PeerKey();
        using Profile p = Store.Create("alice", "h", 1, Pass);
        p.Peers.Pin("zebrafish", bobKey, 5);
        byte[] peers = File.ReadAllBytes(Path.Combine(p.Directory, "peers.dat"));
        byte[] ident = File.ReadAllBytes(Path.Combine(p.Directory, "identity.p8"));
        Assert.False(peers.AsSpan().IndexOf(Encoding.ASCII.GetBytes("zebrafish")) >= 0);
        Assert.False(peers.AsSpan().IndexOf(bobKey) >= 0);
        Assert.False(peers.AsSpan().IndexOf(Encoding.ASCII.GetBytes(Convert.ToBase64String(bobKey)[..30])) >= 0);
        byte[] d = p.Identity.ExportPrivateScalar();
        Assert.False(ident.AsSpan().IndexOf(d) >= 0);
        Assert.False(peers.AsSpan().IndexOf(d) >= 0);
    }

    [Fact]
    public void EachSave_UsesAFreshNonce()
    {
        using Profile p = Store.Create("alice", "h", 1, Pass);
        string path = Path.Combine(p.Directory, "peers.dat");
        byte[] n1 = File.ReadAllBytes(path)[1..13];
        p.Peers.SetBlocked("bob", true);
        byte[] n2 = File.ReadAllBytes(path)[1..13];
        p.Peers.SetBlocked("bob", false);
        byte[] n3 = File.ReadAllBytes(path)[1..13];
        Assert.NotEqual(n1, n2);
        Assert.NotEqual(n2, n3);
    }

    [Theory]
    [InlineData("../../etc")]
    [InlineData("..")]
    [InlineData("/etc/passwd")]
    [InlineData("a/b\\c:d")]
    [InlineData("host\0name")]
    [InlineData("EXAMPLE.org")]
    [InlineData("[::1]")]
    [InlineData("")]
    public void HostileHosts_StayInsideTheBaseDirectory(string host)
    {
        ProfileStore s = Store;
        string path = s.ProfilePath("alice", host, 3000);
        string profiles = Path.Combine(s.BaseDirectory, "profiles") + Path.DirectorySeparatorChar;
        Assert.StartsWith(profiles, path);
        Assert.DoesNotContain(Path.DirectorySeparatorChar, path.Substring(profiles.Length));
        using Profile p = s.Create("alice", host, 3000, Pass);
        Assert.StartsWith(profiles, p.Directory);
        Assert.Equal(Path.GetFullPath(p.Directory), p.Directory);
    }

    [Theory]
    [InlineData("../x")]
    [InlineData("Alice")]
    [InlineData("a b")]
    [InlineData("")]
    [InlineData("averyveryveryverylongname")]
    public void InvalidUserNames_AreRejected(string user)
    {
        Assert.Throws<ArgumentException>(() => Store.ProfilePath(user, "h", 1));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    [InlineData(-1)]
    public void InvalidPorts_AreRejected(int port)
    {
        Assert.Throws<ArgumentException>(() => Store.ProfilePath("alice", "h", port));
    }

    [Fact]
    public void ExplicitBaseDirectory_IsUsed_NotTheDefault()
    {
        ProfileStore s = new(tmp.Path);
        Assert.Equal(Path.GetFullPath(tmp.Path), s.BaseDirectory);
        string appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CipherChat");
        Assert.DoesNotContain(appData, s.ProfilePath("alice", "h", 1));
        using Profile p = s.Create("alice", "h", 1, Pass);
        Assert.StartsWith(Path.GetFullPath(tmp.Path), p.Directory);
    }

    [Fact]
    public void PeerBook_PinningRules()
    {
        byte[] k1 = PeerKey(), k2 = PeerKey();
        using Profile p = Store.Create("alice", "h", 1, Pass);
        p.Peers.Pin("bob", k1, 10);
        Assert.Equal(10, p.Peers.Pin("bob", k1, 99).FirstSeen); // same key: unchanged
        Assert.Throws<InvalidOperationException>(() => p.Peers.Pin("bob", k2, 20)); // different key needs explicit replace
        p.Peers.SetVerified("bob", true);
        PeerRecord r = p.Peers.Pin("bob", k2, 30, replace: true);
        Assert.False(r.Verified);
        Assert.Equal(k2, p.Peers.GetKey("bob"));
        byte[] off = (byte[])k1.Clone(); off[64] ^= 1;
        Assert.Throws<ArgumentException>(() => p.Peers.Pin("carol", off, 1)); // off-curve rejected on import
        Assert.Throws<ArgumentException>(() => p.Peers.Pin("Carol", k1, 1));
        p.Peers.SetBlocked("dave", true); // blocked before ever seen
        p.Peers.Pin("dave", k1, 5);
        Assert.True(p.Peers.IsBlocked("dave"));
    }
}
