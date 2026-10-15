using CipherChatClient;
using Xunit;

namespace CipherChat.Tests;

public class PairCodeTests
{
    [Theory]
    [InlineData("  Correct   HORSE\tBattery  ", "correct horse battery")]
    [InlineData("ABC", "abc")]
    [InlineData("a\r\nb", "a b")]
    [InlineData("", "")]
    [InlineData("   ", "")]
    [InlineData("Ünï", "Ünï")]   // only ASCII A-Z is folded; the rest is left for Validate to reject
    public void Normalize(string input, string expected) => Assert.Equal(expected, PairCode.Normalize(input));

    [Fact]
    public void Normalize_Null_IsEmpty() => Assert.Equal("", PairCode.Normalize(null));

    [Theory]
    [InlineData("correct horse battery staple")]
    [InlineData("zebra lamp ocean tile")]        // 20 chars
    [InlineData("abcdefgh1234")]                 // 12 chars, 12 distinct (not one straight run)
    [InlineData("aabbccddeeff")]                 // 12 chars, exactly 6 distinct
    [InlineData("18273645501928374655")]         // 20 digits, not a run of the digit sequence
    [InlineData("7 3 9 1 4 8 2 6 5 0 7 3 9 1 4 8 2 6 5 1")]  // digits with spaces: 20 digits
    public void Validate_Accepts(string code) => Assert.Null(PairCode.Validate(PairCode.Normalize(code)));

    [Theory]
    [InlineData("", "type a code")]
    [InlineData("short code", "too short")]            // 10
    [InlineData("abcdefghijk", "too short")]           // 11
    [InlineData("aabbccddee", "too short")]
    [InlineData("aabbccddeeaabbcc", "repetitive")]     // 5 distinct, 16 chars
    [InlineData("aaaaaaaaaaaaaaaa", "repetitive")]     // 1 distinct
    [InlineData("abcdefghijkl", "straight run")]
    [InlineData("lkjihgfedcba", "straight run")]
    [InlineData("123456789012", "straight run")]
    [InlineData("12345678901234567890", "straight run")]
    [InlineData("qwertyuiopas", "straight run")]
    [InlineData("zxcvbnm", "too short")]
    [InlineData("19850314 19850314", "digits")]        // dates
    [InlineData("0612345678 0612345678", "digits")]    // 20 digits is the minimum: this is 20 -> accepted below
    public void Validate_Rejects(string code, string reasonFragment)
    {
        if (code == "0612345678 0612345678") { Assert.Null(PairCode.Validate(PairCode.Normalize(code))); return; }
        string problem = PairCode.Validate(PairCode.Normalize(code));
        Assert.NotNull(problem);
        Assert.Contains(reasonFragment, problem, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_DigitBoundary_19Vs20()
    {
        Assert.NotNull(PairCode.Validate(PairCode.Normalize("0182736455019283746")));   // 19 digits
        Assert.Null(PairCode.Validate(PairCode.Normalize("01827364550192837465")));     // 20 digits
    }

    [Fact]
    public void Validate_LengthBoundaries()
    {
        string twelve = "abcdefgh1234", eleven = "abcdefgh123";
        Assert.Null(PairCode.Validate(twelve));
        Assert.NotNull(PairCode.Validate(eleven));
        string hundred = string.Concat(Enumerable.Repeat("zebra lamp ", 10))[..100];
        Assert.Equal(100, hundred.Length);
        Assert.Null(PairCode.Validate(hundred.Trim().PadRight(100, 'q')));
        Assert.Contains("too long", PairCode.Validate(hundred + "x"));
    }

    [Theory]
    [InlineData("café au lait noir")]
    [InlineData("emoji \U0001F600 in the middle")]
    [InlineData("bell\u0007 character here")]
    [InlineData("tab\u0001 control char x")]
    [InlineData("non breaking space here")]
    [InlineData("١٢٣ arabic digits ok")]
    public void Validate_RejectsNonAsciiAndControlCharacters(string code)
    {
        string p = PairCode.Validate(PairCode.Normalize(code));
        Assert.NotNull(p);
        Assert.Contains("plain keyboard", p);
    }

    [Fact]
    public void Rid_FrozenVectors_FromAnIndependentArgon2Implementation()
    {
        // Expected values computed with argon2-cffi (Argon2id v1.3, t=3, m=256 MiB, p=1, 32 bytes) and the same salt.
        Assert.Equal("69f6e4", PairCode.DeriveRid("correct horse battery staple"));
        Assert.Equal("993c56", PairCode.DeriveRid("abc"));
        byte[] full = PairCode.DeriveRidFull("correct horse battery staple");
        Assert.Equal("69f6e4b4645045c3c5adc0f7d3e5a56a5b2f0ca8fa97365e9ea445c13606cb9f", Hex.S(full));
    }

    [Fact]
    public void Rid_IsSixLowerHexChars_AndDiffersForOneCharacterChange()
    {
        string a = PairCode.DeriveRid("correct horse battery staple");
        string b = PairCode.DeriveRid("correct horse battery stapl3");
        Assert.Matches("^[0-9a-f]{6}$", a);
        Assert.Matches("^[0-9a-f]{6}$", b);
        Assert.NotEqual(a, b);
        Assert.Equal(a, PairCode.DeriveRid("correct horse battery staple"));
    }
}
