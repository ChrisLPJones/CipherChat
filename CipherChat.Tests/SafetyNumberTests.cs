using System.Security.Cryptography;
using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class SafetyNumberTests
{
    // Fixed (not real) 65-byte "keys": the safety number only hashes them.
    private static byte[] FakeKey(byte seed) { byte[] k = new byte[65]; k[0] = 4; for (int i = 1; i < 65; i++) k[i] = (byte)(seed + i); return k; }

    [Fact]
    public void BothSidesSeeTheSameNumber_AndFormatIsTwoLinesOfSixGroups()
    {
        byte[] a = FakeKey(1), b = FakeKey(100);
        string x = SafetyNumber.Compute("alice", a, "bob", b);
        string y = SafetyNumber.Compute("bob", b, "alice", a);
        Assert.Equal(x, y);
        string[] lines = x.Split('\n');
        Assert.Equal(2, lines.Length);
        foreach (string line in lines)
        {
            string[] g = line.Split(' ');
            Assert.Equal(6, g.Length);
            Assert.All(g, s => Assert.Matches("^[0-9]{5}$", s));
        }
    }

    [Fact]
    public void FrozenVector_FixedInputsGiveFixedNumber()
    {
        Assert.Equal(FrozenSafetyNumber, SafetyNumber.Compute("alice", FakeKey(1), "bob", FakeKey(100)));
    }

    private const string FrozenSafetyNumber = "66136 15567 90919 07339 18728 41217\n46018 41257 61361 12429 00871 52203";

    [Fact]
    public void ChangingAnyInput_ChangesTheNumber()
    {
        byte[] a = FakeKey(1), b = FakeKey(100);
        string baseNumber = SafetyNumber.Compute("alice", a, "bob", b);
        Assert.NotEqual(baseNumber, SafetyNumber.Compute("alice", a, "bobby", b));
        Assert.NotEqual(baseNumber, SafetyNumber.Compute("alice", a, "bob", FakeKey(101)));
        byte[] a2 = (byte[])a.Clone(); a2[10] ^= 1;
        Assert.NotEqual(baseNumber, SafetyNumber.Compute("alice", a2, "bob", b));
    }
}
